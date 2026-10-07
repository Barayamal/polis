#!/usr/bin/env node
import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { randomBytes, randomUUID, createHash } from 'node:crypto';
import { canonical, exact, UUID } from '../production-service/contracts.mjs';
import { recoverClosedProductionAccess } from '../production-service/recovery.mjs';
import { renderProductionCompose, validateProductionConfiguration, validateProductionImageLock, imageRoles } from './compose.mjs';
import { failure, sha, volumeRoles, MAX_BYTES, privateInput, unchanged, exactly, inspectVolumeArchive, readArchiveMember, rewritePrivateVolumeArchive } from './recovery-archive.mjs';
import { packRecoveryBundle, unpackRecoveryBundle } from './recovery-bundle.mjs';
import { CORE_FILES, EXTRA_CORE_FILES, validateStoppedProductionSnapshot } from './recovery-ownership.mjs';
import { deriveJoinedTargetState, validateClosedParticipantState } from './recovery-state.mjs';
import { encryptArchive, decryptArchive } from '../selfhost/recovery/encryption.mjs';
import { createPlaintextCustody } from '../selfhost/recovery/plaintext-custody.mjs';
import { runPrivateCommand } from '../selfhost/recovery/command-runner.mjs';

const REPOSITORY = resolve(fileURLToPath(new URL('../../../', import.meta.url)));
const UID = { postgres: 70, mariadb: 999, participant_state: 1000, participant_material: 1000, wordpress_material: 33, proxy_material: 101, edge_material: 1000 };
const owners = (a, b) => a.ino === b.ino && a.dev === b.dev;
const inside = (parent, child) => { const r = relative(parent, child); return r === '' || r !== '..' && !r.startsWith('../') && !isAbsolute(r); };
const absolute = p => { if (typeof p !== 'string' || !isAbsolute(p) || resolve(p) !== p || /[\u0000-\u001f\u007f,]/u.test(p)) throw failure(); return p; };
async function directory(path) { absolute(path); const s = await fs.lstat(path); if (!s.isDirectory() || s.uid !== process.getuid() || (s.mode & 0o7777) !== 0o700 || await fs.realpath(path) !== path) throw failure(); return s; }
async function checkDirectory(path, before) { if (!owners(await directory(path), before)) throw failure(); }
async function absent(path) { try { await fs.lstat(path); } catch (e) { if (e.code === 'ENOENT') return; throw e; } throw failure(); }
const privateWrite = (path, value) => fs.writeFile(path, Buffer.isBuffer(value) ? value : Buffer.from(canonical(value) + '\n'), { flag: 'wx', mode: 0o600 });
async function privateRead(path, maximum = 262144) { const parent = await directory(dirname(path)), opened = await privateInput(path, maximum), b = Buffer.alloc(Number(opened.stat.size));
  try { await exactly(opened.file, b, 0); await unchanged(path, opened); await checkDirectory(dirname(path), parent); return b; }
  catch { b.fill(0); throw failure(); } finally { await opened.file.close(); } }
async function readJson(path) { const b = await privateRead(path); try { const s = b.toString('utf8'); if (!Buffer.from(s).equals(b)) throw failure(); return JSON.parse(s); } finally { b.fill(0); } }
async function digestFile(path, maximum = MAX_BYTES + 8192) { const opened = await privateInput(path, maximum), hash = createHash('sha256'), b = Buffer.alloc(65536); let n = 0;
  try { while (n < Number(opened.stat.size)) { const c = b.subarray(0, Math.min(b.length, Number(opened.stat.size) - n)); await exactly(opened.file, c, n); hash.update(c); n += c.length; } await unchanged(path, opened); return hash.digest('hex'); }
  finally { b.fill(0); await opened.file.close(); } }
async function lock(path) { const parent = await directory(dirname(path)), handle = await fs.open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600), stat = await handle.stat();
  const verify = async () => { await checkDirectory(dirname(path), parent); const s = await fs.lstat(path); if (!owners(s, stat) || !s.isFile() || s.nlink !== 1 || s.uid !== process.getuid() || (s.mode & 0o7777) !== 0o600) throw failure(); };
  return { verify, async release() { try { await verify(); await fs.unlink(path); } finally { await handle.close(); } } }; }
async function ephemeralFile(path, bytes, custody) { const handle = await fs.open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  try { custody.record(path, await handle.stat({ bigint: true })); await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); } }
async function engine(input) {
  exact(input, ['binary', 'host', 'configDirectory', 'id']);
  absolute(input.binary); absolute(input.configDirectory);
  if (!['/opt/homebrew/bin/docker', '/usr/local/bin/docker', '/usr/bin/docker'].includes(input.binary)
    || typeof input.host !== 'string' || !input.host.startsWith('unix://') || typeof input.id !== 'string' || !input.id || input.id.length > 128) throw failure();
  const socket = absolute(input.host.slice(7)), stat = await fs.lstat(socket), configStat = await directory(input.configDirectory);
  if (!stat.isSocket() || stat.uid !== process.getuid() || await fs.realpath(socket) !== socket) throw failure();
  const command = async (args, io) => { const current = await fs.lstat(socket); if (!owners(stat, current) || !current.isSocket() || current.uid !== process.getuid()) throw failure(); await checkDirectory(input.configDirectory, configStat);
    return runPrivateCommand(input.binary, ['--host', input.host, '--config', input.configDirectory, ...args], io); };
  const info = JSON.parse(await command(['info', '--format', '{{json .}}']));
  if (info.ID !== input.id || info.OSType !== 'linux' || !['aarch64', 'arm64'].includes(info.Architecture)) throw failure();
  return command;
}
const list = raw => raw ? raw.split('\n').filter(Boolean) : [];
/** Docker's default quiet listing truncates IDs. Ownership comparisons use the
 * full inspected identity, so refuse abbreviated, duplicate or malformed IDs. */
export function parseRecoveryContainerIds(raw) {
  if (typeof raw !== 'string') throw failure();
  if (raw === '') return [];
  const ids = raw.split('\n');
  if (ids.length > 1024 || ids.some(id => !/^[a-f0-9]{64}$/u.test(id)) || new Set(ids).size !== ids.length) throw failure();
  return ids;
}
const containerIds = async (docker, filter) => parseRecoveryContainerIds(await docker(['ps', '-aq', '--no-trunc', '--filter', filter]));
/** Docker inspect may use the canonical CAP_ prefix for the same requested
 * capability. Accept only the existing exact restore set, never extra power. */
export function assertRecoveryHelperCapabilities(capabilities, restore) {
  if (typeof restore !== 'boolean' || !Array.isArray(capabilities) || capabilities.length !== (restore ? 3 : 0)) throw failure();
  const names = capabilities.map(name => {
    if (typeof name !== 'string' || !/^(?:CAP_)?(?:CHOWN|DAC_OVERRIDE|FOWNER)$/u.test(name)) throw failure();
    return name.replace(/^CAP_/u, '');
  });
  if (new Set(names).size !== names.length || canonical(names.sort()) !== canonical(restore ? ['CHOWN', 'DAC_OVERRIDE', 'FOWNER'] : [])) throw failure();
  return true;
}
async function inspect(docker, kind, name) { const values = JSON.parse(await docker([...kind, 'inspect', name])); if (!Array.isArray(values) || values.length !== 1) throw failure(); return values[0]; }
async function images(docker, imageLock) { const result = {}; for (const role of imageRoles(imageLock.version)) result[role] = await inspect(docker, ['image'], imageLock.images[role]); return result; }
function checkedImages(found, imageLock) { for (const role of imageRoles(imageLock.version)) { const i = found[role]; if (i.Id !== imageLock.images[role] || i.Os !== 'linux' || i.Architecture !== 'arm64' || i.Config?.Labels?.['org.opencontainers.image.revision'] !== imageLock.sourceRevision) throw failure(); } }
async function coreMaterial(path) {
  const parent = await directory(path), names = (await fs.readdir(path)).sort(), files = {}, modes = { ...CORE_FILES, ...EXTRA_CORE_FILES };
  if (Object.keys(CORE_FILES).some(n => !names.includes(n)) || names.some(n => !Object.hasOwn(modes, n))) throw failure();
  for (const name of names) { const file = join(path, name), h = await fs.open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
    try { const before = await h.stat({ bigint: true }), allowed = Array.isArray(modes[name]) ? modes[name] : [modes[name]], mode = Number(before.mode & 0o7777n);
      if (!before.isFile() || before.uid !== BigInt(process.getuid()) || before.nlink !== 1n || !allowed.includes(mode) || before.size < 1n || before.size > 65536n) throw failure();
      const bytes = Buffer.alloc(Number(before.size)); try { await exactly(h, bytes, 0); await unchanged(file, { file: h, stat: before }); files[name] = { mode, data: bytes.toString('base64'), sha256: sha(bytes) }; } finally { bytes.fill(0); }
    } finally { await h.close(); } }
  await checkDirectory(path, parent); return files;
}
async function sourceSnapshot(docker, source, material, activeHelpers = new Set()) {
  const { configuration: c, imageLock, ownerToken } = source, compose = renderProductionCompose(c, imageLock, ownerToken);
  const ids = await containerIds(docker, 'label=com.docker.compose.project=' + c.deployment);
  const rows = []; for (const id of ids) rows.push(await inspect(docker, [], id));
  const volumeRows = []; for (const v of Object.values(compose.volumes)) volumeRows.push(await inspect(docker, ['volume'], v.name));
  const networkRows = []; for (const n of Object.values(compose.networks)) networkRows.push(await inspect(docker, ['network'], n.name));
  const imageRows = await images(docker, imageLock);
  validateStoppedProductionSnapshot({ configuration: c, imageLock, ownerToken, rows, images: imageRows, volumes: volumeRows, networks: networkRows, coreMaterial: material });
  const allowed = new Set(rows.map(r => r.Id));
  for (const volume of volumeRows) for (const id of await containerIds(docker, 'volume=' + volume.Name)) if (!allowed.has(id) && !activeHelpers.has(id)) throw failure();
  return { services: rows.length, images: imageRows };
}
async function freshNamespace(docker, deployment) {
  if ((await containerIds(docker, 'label=com.docker.compose.project=' + deployment)).length) throw failure();
  for (const kind of ['volume', 'network']) if (list(await docker([kind, 'ls', '-q', '--filter', 'label=com.docker.compose.project=' + deployment])).length) throw failure();
  for (const [args, predicate] of [[['volume', 'ls', '--format', '{{.Name}}'], n => n.startsWith(deployment + '_')],
    [['network', 'ls', '--format', '{{.Name}}'], n => n.startsWith(deployment + '_')], [['ps', '-a', '--format', '{{.Names}}'], n => n.startsWith(deployment + '_') || n.startsWith(deployment + '-')]])
    if (list(await docker(args)).some(predicate)) throw failure();
}

/** Ephemeral helper images/commands are fixed; only an independently checked
 * owned volume can be mounted. Root capabilities are used only to restore
 * numeric owners into an exclusively created empty target volume. */
function helpers(docker, { imageLock, ownerToken, namespace, verifySource }) {
  const active = new Set(); let sequence = 0;
  async function run({ volume, role, restore = false, inputPath, outputPath, custody, pgCheck = false }) {
    await verifySource?.(active);
    const idImage = pgCheck ? imageLock.images.postgres : imageLock.images.participant;
    const user = restore ? '0:0' : `${UID[role]}:${UID[role]}`, destination = pgCheck ? '/var/lib/postgresql/data' : '/capture';
    const command = pgCheck
      ? 'test ! -e /var/lib/postgresql/data/pgdata/postmaster.pid; test "$(cat /var/lib/postgresql/data/pgdata/PG_VERSION)" = 17; pg_controldata /var/lib/postgresql/data/pgdata'
      : restore ? 'umask 077; test -d /capture; test -z "$(find /capture -mindepth 1 -maxdepth 1 -print -quit)"; exec tar -xpf - -C /capture'
        : 'test -d /capture; test -z "$(find /capture ! -type f ! -type d -print -quit)"; exec tar -cf - -C /capture .';
    const label = 'org.barayamal.fncp.recovery-owner', name = namespace + '-cold-helper-' + (++sequence) + '-' + randomBytes(4).toString('hex');
    const args = ['create', '--pull', 'never', '--interactive', '--name', name, '--network', 'none', '--read-only', '--user', user, '--cap-drop', 'ALL',
      ...(restore ? ['--cap-add', 'CHOWN', '--cap-add', 'DAC_OVERRIDE', '--cap-add', 'FOWNER'] : []),
      '--security-opt', 'no-new-privileges:true', '--pids-limit', '64', '--memory', '512m', '--cpus', '1',
      '--label', label + '=' + ownerToken, '--label', 'org.barayamal.fncp.classification=offline-joined-recovery-helper',
      '--env', 'LANG=C', '--env', 'LC_ALL=C', '--mount', `type=volume,source=${volume},target=${destination},volume-nocopy${restore ? '' : ',readonly'}`,
      '--entrypoint', '/bin/sh', idImage, '-ceu', command];
    const id = await docker(args); if (!/^[a-f0-9]{64}$/u.test(id)) throw failure(); active.add(id);
    const verify = async () => {
      const r = await inspect(docker, [], id), h = r.HostConfig;
      if (r.Id !== id || r.Image !== idImage || r.Config.User !== user || r.Config.Labels?.[label] !== ownerToken || r.Name !== '/' + name
        || h.NetworkMode !== 'none' || !h.ReadonlyRootfs || h.Privileged || h.RestartPolicy?.Name !== 'no' || h.AutoRemove
        || canonical(h.CapDrop) !== canonical(['ALL']) || !assertRecoveryHelperCapabilities(h.CapAdd ?? [], restore)
        || canonical(h.SecurityOpt) !== canonical(['no-new-privileges:true']) || h.PidsLimit !== 64 || h.Memory !== 512 * 1024 * 1024 || h.NanoCpus !== 1e9
        || Object.keys(h.PortBindings ?? {}).length || r.Mounts.length !== 1 || r.Mounts[0].Type !== 'volume' || r.Mounts[0].Name !== volume
        || r.Mounts[0].Destination !== destination || r.Mounts[0].RW !== restore || canonical(r.Config.Entrypoint) !== canonical(['/bin/sh'])
        || canonical(r.Config.Cmd) !== canonical(['-ceu', command])) throw failure(); return r;
    };
    try {
      await verify(); await verifySource?.(active);
      const value = await docker(['start', '--attach', '--interactive', id], { ...(inputPath ? { inputPath } : {}), ...(outputPath ? { outputPath, onOutputCreated: custody.record } : {}), limit: MAX_BYTES, timeout: 120000, rejectStderr: true });
      const r = await verify(); if (r.State.Running || r.State.ExitCode !== 0 || r.State.OOMKilled) throw failure();
      if (pgCheck && !/^Database cluster state:\s+shut down\s*$/mu.test(value)) throw failure();
      await verifySource?.(active); return value;
    } finally {
      const r = await verify(); if (r.State.Running) await docker(['stop', '--time', '10', id]);
      if ((await verify()).State.Running) throw failure(); await docker(['rm', id]); active.delete(id);
    }
  }
  return { run, active };
}

async function newDirectory(path, forbidden) {
  absolute(path); if (inside(REPOSITORY, path) || forbidden.some(p => inside(p, path) || inside(path, p))) throw failure();
  await directory(dirname(path)); await absent(path); await fs.mkdir(path, { mode: 0o700 }); return directory(path);
}
function validateSource(source) { exact(source, ['configuration', 'imageLock', 'ownerToken', 'accessDescriptor']);
  exact(source.accessDescriptor, ['binding', 'bindingSha256']); exact(source.accessDescriptor.binding, ['configuration', 'provider', 'wordpress', 'activation']);
  return { ...source, configuration: validateProductionConfiguration(source.configuration), imageLock: validateProductionImageLock(source.imageLock) }; }

/** Read stopped source resources; create a complete encrypted backup. Never
 * stops, starts, rewrites or removes any source service/volume/database. */
export async function backupStoppedProduction({ jobPath }) {
  let operation, stage, stageStat, backupStat, keyStat, result, failed;
  let phase = 'read-job';
  const custody = createPlaintextCustody();
  try {
    const job = await readJson(absolute(jobPath)); exact(job, ['profile', 'engine', 'source', 'backupDirectory', 'keyDirectory']);
    if (job.profile !== 'FNCP_JOINED_BACKUP_JOB_V1') throw failure();
    const source = validateSource(job.source), c = source.configuration, roles = volumeRoles(source.imageLock.version);
    await directory(c.stateDirectory); operation = await lock(join(c.stateDirectory, 'operation.lock'));
    phase = 'source-ownership'; const docker = await engine(job.engine), material = await coreMaterial(join(c.stateDirectory, 'material'));
    const before = await sourceSnapshot(docker, source, material);
    backupStat = await newDirectory(job.backupDirectory, [c.stateDirectory, job.keyDirectory]);
    keyStat = await newDirectory(job.keyDirectory, [c.stateDirectory, job.backupDirectory]);
    stage = join(job.backupDirectory, '.backup-' + randomUUID()); await fs.mkdir(stage, { mode: 0o700 }); stageStat = await directory(stage);
    const helper = helpers(docker, { imageLock: source.imageLock, ownerToken: randomBytes(24).toString('hex'), namespace: c.deployment,
      verifySource: async active => { await operation.verify(); await checkDirectory(stage, stageStat); await sourceSnapshot(docker, source, material, active); } });
    phase = 'postgres-clean-shutdown'; await helper.run({ role: 'postgres', volume: c.deployment + '_postgres', pgCheck: true });
    const archives = {}, inventories = {};
    for (const role of roles) { phase = 'snapshot-' + role; archives[role] = join(stage, role + '.tar'); await helper.run({ role, volume: c.deployment + '_' + role, outputPath: archives[role], custody }); inventories[role] = await inspectVolumeArchive(archives[role], role); }
    // Validate the joined private state and source material before encrypting.
    phase = 'joined-state-validation'; const proof = await deriveJoinedTargetState({ archives, inventories, sourceDescriptor: source.accessDescriptor, imageLock: source.imageLock, configuration: c, coreMaterial: material, recoveryEpoch: randomUUID() });
    proof.targetManifestBytes.fill(0);
    const accessPath = join(stage, 'access.sqlite'), activationPath = join(stage, 'activation.sqlite');
    for (const [name, path] of [['access.sqlite', accessPath], ['activation.sqlite', activationPath]]) { const bytes = await readArchiveMember(archives.participant_state, inventories.participant_state, name, 16 * 1024 * 1024); try { await ephemeralFile(path, bytes, custody); } finally { bytes.fill(0); } }
    const state = validateClosedParticipantState({ accessPath, activationPath, sourceDescriptor: source.accessDescriptor, activationIdentity: proof.activationIdentity });
    // Every source volume is read again while all approved references remain
    // stopped; a concurrent content change invalidates this joined snapshot.
    phase = 'source-stability'; for (const role of roles) { const again = join(stage, role + '.again.tar'); await helper.run({ role, volume: c.deployment + '_' + role, outputPath: again, custody }); if ((await inspectVolumeArchive(again, role)).contentSha256 !== inventories[role].contentSha256) throw failure(); }
    if (canonical(await coreMaterial(join(c.stateDirectory, 'material'))) !== canonical(material)) throw failure();
    phase = 'encrypt-complete-bundle'; const plain = join(stage, 'joined.bundle'), backupId = randomUUID();
    const packed = await packRecoveryBundle({ archives, expectedInventories: inventories, metadata: { profile: 'FNCP_JOINED_BACKUP_METADATA_V1', source, coreMaterial: material, participantState: state }, targetPath: plain, onCreated: custody.record });
    const keyPath = join(job.keyDirectory, 'recovery.key'), encryptedPath = join(job.backupDirectory, 'joined.aes256gcm');
    await checkDirectory(job.keyDirectory, keyStat); const key = randomBytes(32), keySha256 = sha(key); try { await privateWrite(keyPath, key); } finally { key.fill(0); }
    // The existing authenticated framing compares exact serialized context.
    // Canonicalize insertion order before encryption and receipt persistence.
    const context = JSON.parse(canonical({ profile: 'FNCP_JOINED_COLD_BACKUP_V1', backupId, bundleSha256: packed.bundleSha256,
      sourceBindingSha256: source.accessDescriptor.bindingSha256, sourceImagesSha256: sha(canonical(source.imageLock)), sourceEngineSha256: sha(job.engine.id) }));
    await checkDirectory(job.backupDirectory, backupStat); await encryptArchive({ plaintextPath: plain, encryptedPath, keyPath, context });
    const verified = join(stage, 'verified.bundle'); await decryptArchive({ encryptedPath, plaintextPath: verified, keyPath, expectedContext: context, onPlaintextCreated: custody.record });
    if (await digestFile(verified) !== packed.bundleSha256) throw failure();
    if (await digestFile(keyPath, 32) !== keySha256) throw failure(); const cipherSha256 = await digestFile(encryptedPath);
    await privateWrite(join(job.backupDirectory, 'backup.json'), { profile: 'FNCP_JOINED_BACKUP_RECEIPT_V1', context, cipherSha256, plaintextBytes: packed.bytes });
    await operation.verify(); await sourceSnapshot(docker, source, material); await checkDirectory(job.backupDirectory, backupStat); await checkDirectory(job.keyDirectory, keyStat);
    result = Object.freeze({ profile: 'FNCP_JOINED_COLD_BACKUP_V1', completeEncryptedBackup: true, durableVolumes: roles.length,
      sourceServicesStopped: before.services, cipherSha256, plaintextBytes: packed.bytes, participantAccounts: state.accounts,
      activationReplayFloor: state.activationReplayFloor, sourceUnchanged: true, admissionGranted: false });
  } catch { failed = failure(); failed.stage = phase; }
  finally { try { if (stage) await checkDirectory(stage, stageStat); await custody.cleanup(); if (stage) await fs.rmdir(stage); } catch { failed = failure(); }
    try { await operation?.release(); } catch { failed = failure(); } }
  if (failed) throw failed; return result;
}

/** Authenticate a retained complete backup and prepare a fresh stopped target.
 * No source engine/database needs to exist for this operation. No target
 * service is started and no signature, admission or database migration occurs.
 */
export async function restoreJoinedProduction({ jobPath }) {
  let operation, stage, stageStat, result, failed; const custody = createPlaintextCustody();
  let phase = 'read-job';
  try {
    const job = await readJson(absolute(jobPath)); exact(job, ['profile', 'engine', 'backupDirectory', 'keyDirectory', 'target']);
    exact(job.target, ['deployment', 'stateDirectory', 'recoveryEpoch']); if (job.profile !== 'FNCP_JOINED_RESTORE_JOB_V1' || !UUID.test(job.target.recoveryEpoch)) throw failure();
    const backupStat = await directory(job.backupDirectory), keyStat = await directory(job.keyDirectory);
    if (inside(job.backupDirectory, job.keyDirectory) || inside(job.keyDirectory, job.backupDirectory)) throw failure();
    phase = 'backup-custody'; operation = await lock(join(job.backupDirectory, 'restore.lock')); const docker = await engine(job.engine);
    const receipt = await readJson(join(job.backupDirectory, 'backup.json')); exact(receipt, ['profile', 'context', 'cipherSha256', 'plaintextBytes']);
    exact(receipt.context, ['profile', 'backupId', 'bundleSha256', 'sourceBindingSha256', 'sourceImagesSha256', 'sourceEngineSha256']);
    if (receipt.profile !== 'FNCP_JOINED_BACKUP_RECEIPT_V1' || !Number.isSafeInteger(receipt.plaintextBytes) || receipt.plaintextBytes < 1 || receipt.plaintextBytes > MAX_BYTES) throw failure();
    if (receipt.context.profile !== 'FNCP_JOINED_COLD_BACKUP_V1' || !UUID.test(receipt.context.backupId)
      || ![receipt.cipherSha256, receipt.context.bundleSha256, receipt.context.sourceBindingSha256, receipt.context.sourceImagesSha256, receipt.context.sourceEngineSha256].every(v => typeof v === 'string' && /^[a-f0-9]{64}$/u.test(v))) throw failure();
    const encryptedPath = join(job.backupDirectory, 'joined.aes256gcm'); if (await digestFile(encryptedPath) !== receipt.cipherSha256) throw failure();
    stage = join(job.backupDirectory, '.restore-' + randomUUID()); await fs.mkdir(stage, { mode: 0o700 }); stageStat = await directory(stage);
    phase = 'authenticate-complete-bundle'; const keyPath = join(job.keyDirectory, 'recovery.key'), keySha256 = await digestFile(keyPath, 32);
    const plaintext = join(stage, 'joined.bundle'); await decryptArchive({ encryptedPath, plaintextPath: plaintext, keyPath, expectedContext: receipt.context, onPlaintextCreated: custody.record });
    if (await digestFile(plaintext) !== receipt.context.bundleSha256) throw failure();
    const bundle = await unpackRecoveryBundle({ sourcePath: plaintext, directory: stage, onCreated: custody.record }), metadata = bundle.metadata;
    exact(metadata, ['profile', 'source', 'coreMaterial', 'participantState'], ['activationBinding']); if (metadata.profile !== 'FNCP_JOINED_BACKUP_METADATA_V1') throw failure();
    const source = validateSource(metadata.source), roles = volumeRoles(source.imageLock.version);
    if (sha(canonical(source.imageLock)) !== receipt.context.sourceImagesSha256 || source.accessDescriptor.bindingSha256 !== receipt.context.sourceBindingSha256) throw failure();
    const targetConfiguration = validateProductionConfiguration({ ...structuredClone(source.configuration), deployment: job.target.deployment, stateDirectory: job.target.stateDirectory });
    if (job.target.deployment === source.configuration.deployment || inside(source.configuration.stateDirectory, job.target.stateDirectory) || inside(job.target.stateDirectory, source.configuration.stateDirectory)) throw failure();
    phase = 'target-ownership'; checkedImages(await images(docker, source.imageLock), source.imageLock); await freshNamespace(docker, job.target.deployment);
    phase = 'joined-state-validation'; const derived = await deriveJoinedTargetState({ ...bundle, sourceDescriptor: source.accessDescriptor, imageLock: source.imageLock, configuration: source.configuration, coreMaterial: metadata.coreMaterial, recoveryEpoch: job.target.recoveryEpoch });
    const accessPath = join(stage, 'access.sqlite'), activationPath = join(stage, 'activation.sqlite');
    for (const [name, path] of [['access.sqlite', accessPath], ['activation.sqlite', activationPath]]) { const bytes = await readArchiveMember(bundle.archives.participant_state, bundle.inventories.participant_state, name, 16 * 1024 * 1024); try { await ephemeralFile(path, bytes, custody); } finally { bytes.fill(0); } }
    const state = validateClosedParticipantState({ accessPath, activationPath, sourceDescriptor: source.accessDescriptor, activationIdentity: derived.activationIdentity, ...(metadata.activationBinding ? { activationBinding: metadata.activationBinding } : {}) });
    if (canonical(state) !== canonical(metadata.participantState)) throw failure();
    const resealedPath = join(stage, 'resealed.sqlite');
    phase = 'reseal-access-binding'; const resealed = recoverClosedProductionAccess({ sourcePath: accessPath, targetPath: resealedPath, sourceDescriptor: source.accessDescriptor, targetDescriptor: derived.targetDescriptor }, custody.record);
    const resealedBytes = await privateRead(resealedPath, 16 * 1024 * 1024);
    try {
      for (const [role, replacement] of [['participant_state', new Map([['access.sqlite', resealedBytes]])], ['participant_material', new Map([['service.json', derived.targetManifestBytes]])]]) {
        const path = join(stage, role + '.target.tar'); bundle.inventories[role] = await rewritePrivateVolumeArchive({ sourcePath: bundle.archives[role], targetPath: path, inventory: bundle.inventories[role], replacements: replacement, onCreated: custody.record }); bundle.archives[role] = path;
      }
    } finally { resealedBytes.fill(0); derived.targetManifestBytes.fill(0); }
    phase = 'create-fresh-target'; const targetStat = await newDirectory(job.target.stateDirectory, [job.backupDirectory, job.keyDirectory, source.configuration.stateDirectory]);
    await fs.mkdir(join(job.target.stateDirectory, 'material'), { mode: 0o700 });
    const materialDirectory = join(job.target.stateDirectory, 'material'), materialStat = await directory(materialDirectory);
    const material = metadata.coreMaterial, allowed = { ...CORE_FILES, ...EXTRA_CORE_FILES };
    if (Object.keys(CORE_FILES).some(n => !Object.hasOwn(material, n)) || Object.keys(material).some(n => !Object.hasOwn(allowed, n))) throw failure();
    for (const [name, record] of Object.entries(material)) { exact(record, ['mode', 'data', 'sha256']); const b = Buffer.from(record.data, 'base64');
      try { if (!(Array.isArray(allowed[name]) ? allowed[name] : [allowed[name]]).includes(record.mode) || b.toString('base64') !== record.data || b.length < 1 || b.length > 65536 || sha(b) !== record.sha256) throw failure();
        await checkDirectory(job.target.stateDirectory, targetStat); await checkDirectory(materialDirectory, materialStat);
        const path = join(materialDirectory, name), handle = await fs.open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
        try { const created = await handle.stat(); await handle.writeFile(b); await handle.chmod(record.mode); await handle.sync();
          if (!owners(created, await fs.lstat(path))) throw failure(); await checkDirectory(materialDirectory, materialStat);
        } finally { await handle.close(); }
      }
      finally { b.fill(0); } }
    const ownerToken = randomBytes(24).toString('hex'), compose = renderProductionCompose(targetConfiguration, source.imageLock, ownerToken);
    await privateWrite(join(job.target.stateDirectory, 'configuration.json'), targetConfiguration); await privateWrite(join(job.target.stateDirectory, 'images.json'), source.imageLock);
    await privateWrite(join(job.target.stateDirectory, 'compose.json'), compose);
    await privateWrite(join(job.target.stateDirectory, 'owner.json'), { profile: 'FNCP_JOINED_RESTORE_OWNER_V1', engineId: job.engine.id, token: ownerToken, deployment: job.target.deployment });
    await privateWrite(join(job.target.stateDirectory, 'recovery-descriptor.json'), derived.targetDescriptor);
    await freshNamespace(docker, job.target.deployment);
    for (const [role, v] of Object.entries(compose.volumes)) {
      await operation.verify(); await checkDirectory(job.target.stateDirectory, targetStat);
      const args = ['volume', 'create', '--driver', 'local', ...Object.entries({ ...v.labels, 'com.docker.compose.project': job.target.deployment, 'com.docker.compose.volume': role }).flatMap(([k, value]) => ['--label', k + '=' + value]),
        ...Object.entries(v.driver_opts ?? {}).flatMap(([k, value]) => ['--opt', k + '=' + value]), v.name];
      if (await docker(args) !== v.name) throw failure(); const actual = await inspect(docker, ['volume'], v.name);
      if (actual.Name !== v.name || actual.Driver !== 'local' || Object.entries(v.labels).some(([k, value]) => actual.Labels?.[k] !== value) || canonical(actual.Options ?? {}) !== canonical(v.driver_opts ?? {})) throw failure();
    }
    const helper = helpers(docker, { imageLock: source.imageLock, ownerToken, namespace: job.target.deployment,
      verifySource: async () => { await operation.verify(); await checkDirectory(job.target.stateDirectory, targetStat); await checkDirectory(stage, stageStat);
        for (const [role, v] of Object.entries(compose.volumes)) {
          const actual = await inspect(docker, ['volume'], v.name);
          if (actual.Name !== v.name || actual.Driver !== 'local' || Object.entries(v.labels).some(([k, value]) => actual.Labels?.[k] !== value)
            || actual.Labels?.['com.docker.compose.project'] !== job.target.deployment || actual.Labels?.['com.docker.compose.volume'] !== role
            || canonical(actual.Options ?? {}) !== canonical(v.driver_opts ?? {})) throw failure();
          for (const id of await containerIds(docker, 'volume=' + v.name)) if (!helper.active.has(id)) throw failure();
        } } });
    for (const role of roles) {
      phase = 'restore-' + role;
      await helper.run({ role, volume: compose.volumes[role].name, restore: true, inputPath: bundle.archives[role] });
      const path = join(stage, role + '.restored.tar'); await helper.run({ role, volume: compose.volumes[role].name, outputPath: path, custody });
      if ((await inspectVolumeArchive(path, role)).contentSha256 !== bundle.inventories[role].contentSha256) throw failure();
    }
    phase = 'verify-prepared-target'; await helper.run({ role: 'postgres', volume: compose.volumes.postgres.name, pgCheck: true });
    if (canonical(await coreMaterial(join(job.target.stateDirectory, 'material'))) !== canonical(material)) throw failure();
    await checkDirectory(job.backupDirectory, backupStat); await checkDirectory(job.keyDirectory, keyStat); await operation.verify();
    if (await digestFile(keyPath, 32) !== keySha256 || await digestFile(encryptedPath) !== receipt.cipherSha256) throw failure();
    result = Object.freeze({ profile: 'FNCP_JOINED_COLD_RESTORE_V1', preparedFreshTarget: true, durableVolumesRestored: roles.length, transientVolumesCreatedEmpty: 1,
      encryptedBackupSha256: receipt.cipherSha256, sourceBindingSha256: source.accessDescriptor.bindingSha256, targetBindingSha256: derived.targetDescriptor.bindingSha256,
      participantAccounts: state.accounts, activationReplayFloor: state.activationReplayFloor, accessHistoryPreserved: resealed.historiesAndClocksPreserved,
      activationLedgerCopiedVerbatim: true, nativeDatabaseBytesVerified: true, servicesStarted: 0, admissionGranted: false, nativeCrossStoreRehearsalRequired: true });
    await privateWrite(join(job.target.stateDirectory, 'recovery-prepared.json'), result);
  } catch { failed = failure(); failed.stage = phase; }
  finally { try { if (stage) await checkDirectory(stage, stageStat); await custody.cleanup(); if (stage) await fs.rmdir(stage); } catch { failed = failure(); }
    try { await operation?.release(); } catch { failed = failure(); } }
  if (failed) throw failed; return result;
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try { if (process.argv.length !== 4 || !['backup', 'restore'].includes(process.argv[2])) throw failure();
    const result = await (process.argv[2] === 'backup' ? backupStoppedProduction : restoreJoinedProduction)({ jobPath: process.argv[3] }); process.stdout.write(canonical(result) + '\n');
  } catch { process.stderr.write('Joined production recovery denied.\n'); process.exitCode = 1; }
}
