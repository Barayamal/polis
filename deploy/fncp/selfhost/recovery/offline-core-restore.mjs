#!/usr/bin/env node
import { constants } from 'node:fs';
import { lstat, mkdir, open, readFile, realpath, unlink, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createPrivateKey, createPublicKey, randomBytes, X509Certificate } from 'node:crypto';
import { digest, inspectArchive, MAX_ARCHIVE_BYTES, recoveryFailure } from './archive.mjs';
import { encryptArchive, decryptArchive } from './encryption.mjs';

import { runPrivateCommand as run } from './command-runner.mjs';
import { createPlaintextCustody } from './plaintext-custody.mjs';
const RUNTIME_FILES = [
  'api.env', 'database-ca.pem', 'database-math-password', 'database-migration-password', 'database-owner-password',
  'database-runtime-password', 'database-server.key', 'database-server.pem', 'jwt-private.pem', 'jwt-public.pem', 'math.env', 'migration.env',
];
const CA_FILES = ['local-ca.key', 'database-ca.srl', 'database-server.csr', 'database-server.ext'];
const CHECK_CLUSTER = `
test "$(id -u)" = 70
p=/var/lib/postgresql/data/pgdata
test -d "$p" && test ! -L "$p"
test ! -e "$p/postmaster.pid"
test -z "$(find "$p" ! -type f ! -type d -print -quit)"
test "$(cat "$p/PG_VERSION")" = 17
postgres --version
pg_controldata "$p"
`;
const ARCHIVE_CLUSTER = `
test "$(id -u)" = 70
test ! -e /var/lib/postgresql/data/pgdata/postmaster.pid
test -z "$(find /var/lib/postgresql/data/pgdata ! -type f ! -type d -print -quit)"
exec tar -cf - -C /var/lib/postgresql/data pgdata
`;
const RESTORE_CLUSTER = `
set -eu
umask 077
test "$(id -u)" = 70
test -d /var/lib/postgresql/data && test ! -L /var/lib/postgresql/data
test -z "$(find /var/lib/postgresql/data -mindepth 1 -maxdepth 1 -print -quit)"
tar -xpf - -C /var/lib/postgresql/data
test -s /var/lib/postgresql/data/pgdata/PG_VERSION
test ! -e /var/lib/postgresql/data/pgdata/postmaster.pid
`;

async function exists(path) {
  try { await lstat(path); return true; } catch (error) { if (error.code === 'ENOENT') return false; throw recoveryFailure(); }
}
function contained(parent, path) {
  const relation = relative(parent, path);
  return relation === '' || (!relation.startsWith('..' + '/') && relation !== '..' && !isAbsolute(relation));
}
function absolute(path) {
  if (typeof path !== 'string' || !isAbsolute(path) || resolve(path) !== path || /[\u0000-\u001f\u007f$]/u.test(path)) throw recoveryFailure();
  return path;
}
async function ownedDirectory(path, privateMode = true) {
  absolute(path); const stat = await lstat(path);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid()
    || (privateMode && (stat.mode & 0o7777) !== 0o700) || await realpath(path) !== path) throw recoveryFailure();
}
const writePrivate = (path, value) => writeFile(path, Buffer.isBuffer(value) ? value : JSON.stringify(value, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
async function ownedFile(path, maximum = 65_536, expectedMode = 0o600) {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await file.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.uid !== BigInt(process.getuid())
      || (before.mode & 0o7777n) !== BigInt(expectedMode) || before.size < 1n || before.size > BigInt(maximum)
      || await realpath(path) !== resolve(path)) throw recoveryFailure();
    const bytes = Buffer.alloc(Number(before.size)); let offset = 0;
    while (offset < bytes.length) { const read = await file.read(bytes, offset, bytes.length - offset, offset); if (!read.bytesRead) throw recoveryFailure(); offset += read.bytesRead; }
    const after = await file.stat({ bigint: true }); const named = await lstat(path, { bigint: true });
    for (const key of ['ino', 'dev', 'size', 'mtimeNs', 'ctimeNs', 'uid', 'mode', 'nlink']) if (before[key] !== after[key] || before[key] !== named[key]) throw recoveryFailure();
    return bytes;
  } finally { await file.close(); }
}


function list(value) { return value ? value.split('\n').filter(Boolean) : []; }
function clusterReady(value) {
  if (!/^postgres \(PostgreSQL\) 17\.[0-9]+(?:[^\r\n]*)$/mu.test(value)
    || !/^Database cluster state:\s+shut down\s*$/mu.test(value)) throw recoveryFailure();
  return true;
}

export async function prepareOfflineCoreRestore(options) {
  let sourceLock; let sourceLockStat; let sourceLockPath; let targetCreated = false; let phase = 'preflight';
  const plaintext = createPlaintextCustody();
  const keys = ['repositoryRoot', 'sourceConfigurationPath', 'targetConfigurationPath', 'targetDeployment', 'targetStateDirectory', 'keyDirectory'];
  if (!options || Object.getPrototypeOf(options) !== Object.prototype || Object.keys(options).sort().join(',') !== keys.sort().join(',')) throw recoveryFailure();
  const { repositoryRoot, sourceConfigurationPath, targetConfigurationPath, targetDeployment, targetStateDirectory, keyDirectory } = options;
  for (const path of [repositoryRoot, sourceConfigurationPath, targetConfigurationPath, targetStateDirectory, keyDirectory]) absolute(path);
  if (!/^fncp-[a-z0-9][a-z0-9-]{4,40}$/u.test(targetDeployment)) throw recoveryFailure();
  await ownedDirectory(repositoryRoot, false);
  const modules = await import(pathToFileURL(join(repositoryRoot, 'deploy/fncp/selfhost/configuration.mjs')).href);
  const material = await import(pathToFileURL(join(repositoryRoot, 'deploy/fncp/selfhost/material.mjs')).href);
  const lifecycle = await import(pathToFileURL(join(repositoryRoot, 'deploy/fncp/selfhost/fncpctl.mjs')).href);
  const source = await modules.loadConfiguration(sourceConfigurationPath);
  const target = modules.validateConfiguration({ ...structuredClone(source), deployment: targetDeployment, stateDirectory: targetStateDirectory });
  if (source.deployment === targetDeployment || targetConfigurationPath === sourceConfigurationPath
    || contained(source.stateDirectory, targetStateDirectory) || contained(targetStateDirectory, source.stateDirectory)
    || contained(source.stateDirectory, keyDirectory) || contained(keyDirectory, source.stateDirectory)
    || contained(targetStateDirectory, keyDirectory) || contained(keyDirectory, targetStateDirectory)
    || contained(repositoryRoot, targetStateDirectory) || contained(repositoryRoot, keyDirectory)
    || contained(repositoryRoot, targetConfigurationPath)
    || contained(source.stateDirectory, targetConfigurationPath)) throw recoveryFailure();
  await ownedDirectory(source.stateDirectory); await ownedDirectory(dirname(targetStateDirectory)); await ownedDirectory(dirname(keyDirectory));
  if (dirname(targetConfigurationPath) !== targetStateDirectory) await ownedDirectory(dirname(targetConfigurationPath));
  if (await exists(targetStateDirectory) || await exists(keyDirectory) || await exists(targetConfigurationPath)) throw recoveryFailure();
  sourceLockPath = join(source.stateDirectory, 'operation.lock');
  sourceLock = await open(sourceLockPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  sourceLockStat = await sourceLock.stat({ bigint: true });
  let docker; let helpers = 0; const ownerToken = randomBytes(24).toString('hex');
  try {
    await sourceLock.writeFile(JSON.stringify({ pid: process.pid, operation: 'offline-core-recovery', operationStartedAt: new Date().toISOString() }));
    const controller = await lifecycle.createController(source);
    const status = await controller.status();
    if (!status.services.length || status.services.some(service => service.status !== 'exited')) throw recoveryFailure();
    const sourceOwner = JSON.parse(await modules.privateRead(join(source.stateDirectory, 'owner.json')));
    const initialized = JSON.parse(await modules.privateRead(join(source.stateDirectory, 'initialized.json')));
    const imageLock = modules.validateImageLock(JSON.parse(await modules.privateRead(join(source.stateDirectory, 'images.json'))));
    const snapshot = await lifecycle.sourceSnapshot();
    if (snapshot.sourceRevision !== source.sourceRevision || snapshot.sourceFingerprint !== imageLock.sourceFingerprint
      || initialized.version !== 1 || initialized.engineId !== sourceOwner.engineId
      || initialized.configurationSha256 !== sourceOwner.configurationSha256) throw recoveryFailure();
    const sourceMaterial = await material.snapshotMaterial(source);
    docker = (args, io) => run('docker', ['--host', source.engine.host, '--config', source.engine.configDirectory, ...args], io);
    const info = JSON.parse(await docker(['info', '--format', '{{json .}}']));
    if (info.ID !== sourceOwner.engineId || info.OSType !== 'linux' || !['aarch64', 'arm64'].includes(info.Architecture)) throw recoveryFailure();
    const pgImage = imageLock.images.postgres;
    for (const id of Object.values(imageLock.images)) {
      const image = JSON.parse(await docker(['image', 'inspect', id]))[0];
      if (image.Id !== id || image.Os !== 'linux' || image.Architecture !== 'arm64'
        || image.Config.Labels?.['org.opencontainers.image.revision'] !== source.sourceRevision) throw recoveryFailure();
    }
    const sourceVolume = `${source.deployment}_postgres`; const targetVolume = `${targetDeployment}_postgres`;
    const targetNetwork = `${targetDeployment}_private`;
    const originalVolume = JSON.parse(await docker(['volume', 'inspect', sourceVolume]))[0];
    if (originalVolume.Name !== sourceVolume || originalVolume.Driver !== 'local'
      || originalVolume.Labels?.['org.barayamal.fncp.owner'] !== sourceOwner.token
      || originalVolume.Labels?.['com.docker.compose.project'] !== source.deployment) throw recoveryFailure();
    async function sourceUnused() {
      const references = list(await docker(['ps', '-aq', '--filter', `volume=${sourceVolume}`]));
      if (references.length !== 1) throw recoveryFailure();
      const row = JSON.parse(await docker(['inspect', references[0]]))[0];
      if (row.State.Running || row.Image !== pgImage || row.Config.User !== '70:70'
        || row.HostConfig.RestartPolicy?.Name !== 'no'
        || row.Config.Labels?.['com.docker.compose.service'] !== 'postgres'
        || row.Config.Labels?.['com.docker.compose.project'] !== source.deployment
        || row.Config.Labels?.['org.barayamal.fncp.owner'] !== sourceOwner.token) throw recoveryFailure();
    }
    await sourceUnused();
    if (list(await docker(['volume', 'ls', '--format', '{{.Name}}'])).includes(targetVolume)
      || list(await docker(['network', 'ls', '--format', '{{.Name}}'])).includes(targetNetwork)
      || list(await docker(['ps', '-a', '--format', '{{.Names}}'])).some(name => name.startsWith(targetDeployment + '-') || name.startsWith(targetDeployment + '_'))
      || list(await docker(['ps', '-aq', '--filter', `label=com.docker.compose.project=${targetDeployment}`])).length) throw recoveryFailure();
    for (const kind of ['volume', 'network']) if (list(await docker([kind, 'ls', '-q', '--filter', `label=com.docker.compose.project=${targetDeployment}`])).length) throw recoveryFailure();

    await mkdir(targetStateDirectory, { mode: 0o700 }); targetCreated = true;
    await mkdir(keyDirectory, { mode: 0o700 }); await mkdir(join(targetStateDirectory, 'material'), { mode: 0o700 });
    await ownedDirectory(targetStateDirectory); await ownedDirectory(keyDirectory);
    await writePrivate(targetConfigurationPath, target);
    await writePrivate(join(targetStateDirectory, 'recovery-intent.json'), { version: 1, scope: 'CLOSED_LOCAL_CORE_OFFLINE_RECOVERY',
      engineId: info.ID, sourceDeployment: source.deployment, targetDeployment, targetVolume, targetNetwork,
      ownerToken, postgresImage: pgImage, sourceConfigurationSha256: sourceOwner.configurationSha256 });

    const copied = [];
    for (const name of [...RUNTIME_FILES, ...CA_FILES]) {
      const path = join(source.stateDirectory, 'material', name); const mode = (await lstat(path)).mode & 0o7777;
      if ((name === 'local-ca.key' && mode !== 0o600) || ![0o600, 0o644].includes(mode)) throw recoveryFailure();
      const bytes = await ownedFile(path, 65_536, mode);
      await writeFile(join(targetStateDirectory, 'material', name), bytes, { mode, flag: 'wx' });
      copied.push({ name, mode, size: bytes.length, sha256: digest(bytes) });
    }
    const ca = new X509Certificate(await readFile(join(targetStateDirectory, 'material', 'database-ca.pem')));
    const caPrivate = createPrivateKey(await ownedFile(join(targetStateDirectory, 'material', 'local-ca.key')));
    if (!ca.publicKey.export({ type: 'spki', format: 'der' }).equals(createPublicKey(caPrivate).export({ type: 'spki', format: 'der' }))) throw recoveryFailure();
    const targetMaterial = await material.snapshotMaterial(target);
    if (JSON.stringify(sourceMaterial.files) !== JSON.stringify(targetMaterial.files)) throw recoveryFailure();
    const labels = ['--label', `org.barayamal.fncp.owner=${ownerToken}`, '--label', `com.docker.compose.project=${targetDeployment}`,
      '--label', 'org.barayamal.fncp.classification=closed-local-core'];

    async function helper(volume, readonly, command, io = {}) {
      await sourceUnused(); helpers++;
      const name = `${targetDeployment}-offline-helper-${helpers}`;
      const id = await docker(['create', '--name', name, '--interactive', '--network', 'none', '--read-only', '--user', '70:70',
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--pids-limit', '64', '--memory', '512m',
        '--env', 'LC_ALL=C', '--env', 'LANG=C', ...labels, '--label', 'com.docker.compose.service=offline-recovery-helper',
        '--mount', `type=volume,source=${volume},target=/var/lib/postgresql/data${readonly ? ',readonly' : ''}`,
        '--entrypoint', '/bin/sh', pgImage, '-ceu', command]);
      if (!/^[0-9a-f]{64}$/u.test(id)) throw recoveryFailure();
      await writePrivate(join(targetStateDirectory, `helper-${helpers}.json`), { id, name, image: pgImage, volume, readonly });
      async function inspectHelper() {
        const row = JSON.parse(await docker(['inspect', id]))[0];
        if (row.Id !== id || row.Image !== pgImage || row.Config.User !== '70:70'
          || row.Config.Labels?.['org.barayamal.fncp.owner'] !== ownerToken
          || row.Config.Labels?.['com.docker.compose.project'] !== targetDeployment
          || row.Config.Labels?.['com.docker.compose.service'] !== 'offline-recovery-helper'
          || row.HostConfig.NetworkMode !== 'none' || !row.HostConfig.ReadonlyRootfs || row.HostConfig.Privileged
          || !row.HostConfig.CapDrop?.includes('ALL') || Object.keys(row.HostConfig.PortBindings ?? {}).length
          || row.Mounts.length !== 1 || row.Mounts[0].Type !== 'volume' || row.Mounts[0].Name !== volume
          || row.Mounts[0].Destination !== '/var/lib/postgresql/data' || row.Mounts[0].RW !== !readonly) throw recoveryFailure();
        return row;
      }
      try {
        await inspectHelper();
        const result = await docker(['start', '--attach', '--interactive', id], io);
        const closed = await inspectHelper();
        if (closed.State.Running || closed.State.ExitCode !== 0 || closed.State.OOMKilled) throw recoveryFailure();
        return result;
      } finally {
        const row = await inspectHelper();
        if (row.State.Running) await docker(['stop', '--time', '5', id]);
        const closed = await inspectHelper(); if (closed.State.Running) throw recoveryFailure();
        await docker(['rm', id]);
      }
    }

    phase = 'archive-source';
    clusterReady(await helper(sourceVolume, true, CHECK_CLUSTER, { rejectStderr: true }));
    const sourcePlain = join(targetStateDirectory, 'source-ephemeral.tar');
    await helper(sourceVolume, true, ARCHIVE_CLUSTER, { outputPath: sourcePlain, limit: MAX_ARCHIVE_BYTES, onOutputCreated: plaintext.record });
    const sourceArchive = await inspectArchive(sourcePlain);
    const context = { version: 1, scope: 'CLOSED_LOCAL_CORE_PHYSICAL_CLUSTER_V1', sourceRevision: source.sourceRevision,
      postgresImage: pgImage, engineIdSha256: digest(info.ID), sourceConfigurationSha256: sourceOwner.configurationSha256,
      sourceMaterialSha256: digest(JSON.stringify(sourceMaterial.files)), archiveSha256: sourceArchive.archiveSha256,
      fileContentSha256: sourceArchive.fileContentSha256 };
    phase = 'encrypt-and-authenticate';
    const keyId = randomBytes(16).toString('hex'); const keyPath = join(keyDirectory, `${keyId}.key`);
    await writePrivate(keyPath, randomBytes(32));
    const encryptedPath = join(targetStateDirectory, 'postgres-snapshot.aes256gcm');
    const encryption = await encryptArchive({ plaintextPath: sourcePlain, encryptedPath, keyPath, context });
    const restoredPlain = join(targetStateDirectory, 'authenticated-ephemeral.tar');
    const authenticated = await decryptArchive({ encryptedPath, plaintextPath: restoredPlain, keyPath, expectedContext: context, onPlaintextCreated: plaintext.record });
    const decrypted = await inspectArchive(restoredPlain);
    if (!authenticated.authenticated || decrypted.archiveSha256 !== sourceArchive.archiveSha256
      || decrypted.fileContentSha256 !== sourceArchive.fileContentSha256) throw recoveryFailure();
    await writePrivate(join(targetStateDirectory, 'encrypted-snapshot.json'), { version: 1, keyId, context, ...encryption });
    await writePrivate(join(targetStateDirectory, 'source-cluster-files.json'), sourceArchive);

    phase = 'create-target-resources';
    // Recheck names immediately before creation, then independently inspect the
    // fresh owner token: volume create can return an existing named volume, and
    // that response must never count as permission to adopt it.
    if (list(await docker(['volume', 'ls', '--format', '{{.Name}}'])).includes(targetVolume)
      || list(await docker(['network', 'ls', '--format', '{{.Name}}'])).includes(targetNetwork)) throw recoveryFailure();
    await docker(['volume', 'create', '--driver', 'local', ...labels, '--label', 'com.docker.compose.volume=postgres', targetVolume]);
    const createdVolume = JSON.parse(await docker(['volume', 'inspect', targetVolume]))[0];
    if (createdVolume.Name !== targetVolume || createdVolume.Driver !== 'local'
      || createdVolume.Labels?.['org.barayamal.fncp.owner'] !== ownerToken
      || createdVolume.Labels?.['com.docker.compose.project'] !== targetDeployment) throw recoveryFailure();
    await docker(['network', 'create', '--driver', 'bridge', '--internal', ...labels, '--label', 'com.docker.compose.network=private', targetNetwork]);
    const createdNetwork = JSON.parse(await docker(['network', 'inspect', targetNetwork]))[0];
    if (createdNetwork.Name !== targetNetwork || !createdNetwork.Internal
      || createdNetwork.Labels?.['org.barayamal.fncp.owner'] !== ownerToken
      || createdNetwork.Labels?.['com.docker.compose.project'] !== targetDeployment) throw recoveryFailure();
    phase = 'restore-volume';
    await helper(targetVolume, false, RESTORE_CLUSTER, { inputPath: restoredPlain });
    clusterReady(await helper(targetVolume, true, CHECK_CLUSTER, { rejectStderr: true }));
    phase = 'verify-restored-source';
    const targetPlain = join(targetStateDirectory, 'target-verification-ephemeral.tar');
    await helper(targetVolume, true, ARCHIVE_CLUSTER, { outputPath: targetPlain, limit: MAX_ARCHIVE_BYTES, onOutputCreated: plaintext.record });
    const targetArchive = await inspectArchive(targetPlain);
    if (targetArchive.fileContentSha256 !== sourceArchive.fileContentSha256) throw recoveryFailure();
    const sourceAfterPlain = join(targetStateDirectory, 'source-recheck-ephemeral.tar');
    await helper(sourceVolume, true, ARCHIVE_CLUSTER, { outputPath: sourceAfterPlain, limit: MAX_ARCHIVE_BYTES, onOutputCreated: plaintext.record });
    const sourceAfter = await inspectArchive(sourceAfterPlain);
    if (sourceAfter.fileContentSha256 !== sourceArchive.fileContentSha256) throw recoveryFailure();
    await sourceUnused();
    if (JSON.stringify((await material.snapshotMaterial(source)).files) !== JSON.stringify(sourceMaterial.files)) throw recoveryFailure();
    for (const file of copied) if (digest(await ownedFile(join(source.stateDirectory, 'material', file.name), 65_536, file.mode)) !== file.sha256) throw recoveryFailure();

    phase = 'finalize-closed';
    const finalMaterial = await material.snapshotMaterial(target);
    const owner = { version: 1, engineId: info.ID, configurationSha256: digest(JSON.stringify(target)),
      materialSha256: digest(JSON.stringify(finalMaterial)), token: ownerToken, createdAt: new Date().toISOString() };
    await writePrivate(join(targetStateDirectory, 'images.json'), imageLock);
    await writePrivate(join(targetStateDirectory, 'source.json'), snapshot);
    await writeFile(join(targetStateDirectory, 'empty.env'), '# No ambient Compose environment\n', { mode: 0o600, flag: 'wx' });
    await writePrivate(join(targetStateDirectory, 'material-manifest.json'), finalMaterial);
    await writePrivate(join(targetStateDirectory, 'owner.json'), owner);
    await writePrivate(join(targetStateDirectory, 'compose.yml'), modules.composeConfiguration(target, imageLock, ownerToken));
    await docker(['compose', '--project-name', targetDeployment, '--project-directory', targetStateDirectory,
      '--env-file', join(targetStateDirectory, 'empty.env'), '--file', join(targetStateDirectory, 'compose.yml'), 'config', '--quiet']);
    const targetController = await lifecycle.createController(target);
    const finalStatus = await targetController.status();
    if (finalStatus.services.length !== 0) throw recoveryFailure();
    for (const [path, expected] of [[sourcePlain, sourceArchive], [restoredPlain, decrypted], [targetPlain, targetArchive], [sourceAfterPlain, sourceAfter]]) {
      if ((await inspectArchive(path)).archiveSha256 !== expected.archiveSha256) throw recoveryFailure();
    }
    await plaintext.cleanup();
    // This marker allows the ordinary controller to start. Publish it only after
    // offline bytes, ownership, material, Compose and plaintext cleanup passed.
    await writePrivate(join(targetStateDirectory, 'initialized.json'), { version: 1, engineId: info.ID,
      configurationSha256: owner.configurationSha256, initializedAt: new Date().toISOString(),
      initializationMethod: 'VERIFIED_STOPPED_PHYSICAL_CORE_RESTORE' });
    const result = { result: 'PASS', scope: 'CLOSED_LOCAL_CORE_OFFLINE_RESTORE', offlineValidated: true,
      sourceVolumeContentUnchanged: true, sourceMaterialUnchanged: true, encryptedSnapshotAuthenticated: true,
      clusterFilesMatched: sourceArchive.records.length, copiedPrivateMaterialFiles: copied.length,
      temporaryHelpersRemoved: helpers, ephemeralPlaintextRemoved: true,
      postgresStarted: false, apiStarted: false, mathStarted: false, activationGranted: false,
      applicationRestartProven: false, joinedWordPressRecoveryProven: false, productionParticipantRecoveryProven: false };
    await writePrivate(join(targetStateDirectory, 'offline-recovery-result.json'), result);
    return result;
  } catch {
    if (targetCreated) {
      try { await writePrivate(join(targetStateDirectory, 'offline-recovery-failure.json'), { result: 'FAIL', phase,
        sourceVolumeMountedReadOnly: true, targetResourcesPreservedForDiagnosis: true,
        code: 'FNCP_OFFLINE_CORE_RECOVERY_REJECTED' }); } catch { /* Preserve the original failure. */ }
    }
    throw recoveryFailure();
  } finally {
    // Normal failures must not retain a second plaintext backup beside the
    // encrypted snapshot. A cleanup failure must still release our own lock.
    try { await plaintext.cleanup(); }
    finally {
      await sourceLock?.close();
      if (sourceLockStat) {
        const current = await lstat(sourceLockPath, { bigint: true });
        if (current.ino !== sourceLockStat.ino || current.dev !== sourceLockStat.dev || current.uid !== BigInt(process.getuid())) throw recoveryFailure();
        await unlink(sourceLockPath);
      }
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const flags = ['--repository', '--source-config', '--target-config', '--deployment', '--state', '--key-directory'];
  const args = process.argv.slice(2);
  if (args.length !== 13 || args[0] !== 'prepare' || flags.some((flag, index) => args[1 + index * 2] !== flag)) {
    console.error('FNCP_OFFLINE_CORE_RECOVERY_USAGE'); process.exitCode = 1;
  } else {
    const [repositoryRoot, sourceConfigurationPath, targetConfigurationPath, targetDeployment, targetStateDirectory, keyDirectory] = flags.map((_, index) => args[2 + index * 2]);
    prepareOfflineCoreRestore({ repositoryRoot, sourceConfigurationPath, targetConfigurationPath, targetDeployment, targetStateDirectory, keyDirectory })
      .then(result => console.log(JSON.stringify(result))).catch(() => { console.error('FNCP_OFFLINE_CORE_RECOVERY_REJECTED'); process.exitCode = 1; });
  }
}
