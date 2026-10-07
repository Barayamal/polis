#!/usr/bin/env node
import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import { dirname, join, relative, resolve, isAbsolute } from 'node:path';
import { pathToFileURL } from 'node:url';
import { randomBytes, randomUUID, createHash, X509Certificate } from 'node:crypto';
import { canonical, exact, UUID, SHA } from '../production-service/contracts.mjs';
import { createMaterialCustody } from '../production-service/custody.mjs';
import { holdRenewalMaterial, validateRenewalTls } from '../production-service/renewal-material.mjs';
import { renewClosedProductionCredentials } from '../production-service/renewal.mjs';
import { validateProductionConfiguration, validateProductionImageLock } from './compose.mjs';
import { MAX_BYTES, volumeRoles, privateInput, unchanged, exactly, inspectVolumeArchive, readArchiveMember, rewritePrivateVolumeArchive } from './recovery-archive.mjs';
import { packRecoveryBundle, unpackRecoveryBundle } from './recovery-bundle.mjs';
import { deriveJoinedTargetState, validateClosedParticipantState } from './recovery-state.mjs';
import { CORE_FILES, EXTRA_CORE_FILES } from './recovery-ownership.mjs';
import { encryptArchive, decryptArchive } from '../selfhost/recovery/encryption.mjs';
import { createPlaintextCustody } from '../selfhost/recovery/plaintext-custody.mjs';

const denied = () => new Error('Joined credential renewal denied.');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const equal = (a, b) => canonical(a) === canonical(b);
const same = (a, b) => a.ino === b.ino && a.dev === b.dev;
const inside = (a, b) => { const r = relative(a, b); return r === '' || r !== '..' && !r.startsWith('../') && !isAbsolute(r); };
async function directory(path) {
  if (typeof path !== 'string' || !isAbsolute(path) || resolve(path) !== path || await fs.realpath(path) !== path) throw denied();
  const stat = await fs.lstat(path);
  if (!stat.isDirectory() || stat.uid !== process.getuid() || (stat.mode & 0o7777) !== 0o700) throw denied();
  return stat;
}
async function check(path, stat) { if (!same(await directory(path), stat)) throw denied(); }
async function createDirectory(path) { await directory(dirname(path)); await fs.mkdir(path, { mode: 0o700 }); return directory(path); }
async function privateWrite(path, bytes, custody) {
  const handle = await fs.open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  try { custody?.record(path, await handle.stat({ bigint: true })); await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
}
async function read(path, maximum = 262144) {
  const parent = await directory(dirname(path)), opened = await privateInput(path, maximum), bytes = Buffer.alloc(Number(opened.stat.size));
  try { await exactly(opened.file, bytes, 0); await unchanged(path, opened); await check(dirname(path), parent); return bytes; }
  catch { bytes.fill(0); throw denied(); } finally { await opened.file.close(); }
}
function json(bytes) { const text = bytes.toString('utf8'); if (!Buffer.from(text).equals(bytes)) throw denied(); return JSON.parse(text); }
async function readJson(path) { const b = await read(path); try { return json(b); } finally { b.fill(0); } }
async function digest(path) {
  const opened = await privateInput(path, MAX_BYTES + 8192), hash = createHash('sha256'), bytes = Buffer.alloc(65536); let offset = 0;
  try { while (offset < Number(opened.stat.size)) { const chunk = bytes.subarray(0, Math.min(bytes.length, Number(opened.stat.size) - offset)); await exactly(opened.file, chunk, offset); hash.update(chunk); offset += chunk.length; }
    await unchanged(path, opened); return hash.digest('hex'); }
  finally { bytes.fill(0); await opened.file.close(); }
}
async function operationLock(path) {
  const parent = await directory(dirname(path)), handle = await fs.open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600), stat = await handle.stat();
  const verify = async () => { await check(dirname(path), parent); const s = await fs.lstat(path), held = await handle.stat();
    if (![s, held].every(x => same(x, stat) && x.isFile() && x.nlink === 1 && x.uid === process.getuid() && (x.mode & 0o7777) === 0o600)) throw denied(); };
  return { verify, async close() { try { await verify(); await fs.unlink(path); } finally { await handle.close(); } } };
}
function certificates(bytes) {
  const text = bytes.toString('utf8'), entries = text.match(/-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----/gu);
  if (!Buffer.from(text).equals(bytes) || !entries?.length || entries.length > 8 || text.replace(/-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----/gu, '').trim()) throw denied();
  return entries.map(entry => new X509Certificate(entry));
}
/** Verify the replacement trust file actually authenticates the renewed leaf.
 * No new trust anchor is added to a machine or to the system trust store. */
export function verifyRenewedPeerTrust(leafBytes, trustBytes) {
  try {
    const chain = certificates(leafBytes), anchors = certificates(trustBytes), now = Date.now();
    if (anchors.length !== 1 || new Set(anchors.map(c => sha(c.raw))).size !== anchors.length
      || anchors.some(c => !c.ca || Date.parse(c.validFrom) > now || Date.parse(c.validTo) <= now + 3600000)) throw denied();
    for (let i = 1; i < chain.length; i++) if (!chain[i].ca || !chain[i - 1].checkIssued(chain[i]) || !chain[i - 1].verify(chain[i].publicKey)) throw denied();
    const end = chain.at(-1);
    if (!anchors.some(c => end.raw.equals(c.raw) || end.checkIssued(c) && end.verify(c.publicKey))) throw denied();
    return true;
  } catch { throw denied(); }
}
function validateCore(material) {
  const allowed = { ...CORE_FILES, ...EXTRA_CORE_FILES };
  if (Object.keys(CORE_FILES).some(n => !Object.hasOwn(material, n)) || Object.keys(material).some(n => !Object.hasOwn(allowed, n))) throw denied();
  for (const [name, entry] of Object.entries(material)) {
    exact(entry, ['data', 'sha256', 'mode']); const bytes = Buffer.from(entry.data, 'base64');
    try { const modes = Array.isArray(allowed[name]) ? allowed[name] : [allowed[name]];
      if (!modes.includes(entry.mode) || bytes.length < 1 || bytes.length > 65536 || bytes.toString('base64') !== entry.data || sha(bytes) !== entry.sha256) throw denied();
    } finally { bytes.fill(0); }
  }
}
function receiptShape(receipt) {
  exact(receipt, ['profile', 'context', 'cipherSha256', 'plaintextBytes']);
  exact(receipt.context, ['profile', 'backupId', 'bundleSha256', 'sourceBindingSha256', 'sourceImagesSha256', 'sourceEngineSha256']);
  if (receipt.profile !== 'FNCP_JOINED_BACKUP_RECEIPT_V1' || receipt.context.profile !== 'FNCP_JOINED_COLD_BACKUP_V1'
    || !UUID.test(receipt.context.backupId) || ![receipt.cipherSha256, receipt.context.bundleSha256, receipt.context.sourceBindingSha256, receipt.context.sourceImagesSha256, receipt.context.sourceEngineSha256].every(x => typeof x === 'string' && SHA.test(x))
    || !Number.isSafeInteger(receipt.plaintextBytes) || receipt.plaintextBytes < 1 || receipt.plaintextBytes > MAX_BYTES) throw denied();
}

/** Offline, complete encrypted-backup transformation. The input is authenticated
 * before use; native database and activation bytes remain identical. The new
 * bundle is consumable by the existing fresh-target restore. This neither
 * starts a service nor proves provider acceptance or native cross-store health.
 */
export async function renewJoinedProductionBackup({ jobPath }) {
  const plaintext = createPlaintextCustody(), candidates = createMaterialCustody(), directories = [];
  let lock, result, failed, material, stage, stagedProof, successMarker;
  const sensitive = [];
  try {
    const job = await readJson(jobPath);
    exact(job, ['profile', 'backupDirectory', 'keyDirectory', 'candidateMaterialDirectory', 'recoveryEpoch', 'targetBackupDirectory', 'targetKeyDirectory'], ['receiverTrustFile', 'edgeUpstreamTrustFile', 'edgeCertificateFile', 'edgePrivateKeyFile']);
    if (Object.hasOwn(job, 'edgeCertificateFile') !== Object.hasOwn(job, 'edgePrivateKeyFile')) throw denied();
    if (job.profile !== 'FNCP_JOINED_RENEWAL_JOB_V1' || !UUID.test(job.recoveryEpoch)) throw denied();
    const existing = [job.backupDirectory, job.keyDirectory, job.candidateMaterialDirectory], allPaths = [...existing, job.targetBackupDirectory, job.targetKeyDirectory];
    for (let i = 0; i < allPaths.length; i++) for (let j = i + 1; j < allPaths.length; j++) if (inside(allPaths[i], allPaths[j]) || inside(allPaths[j], allPaths[i])) throw denied();
    const heldDirectories = await Promise.all(existing.map(async path => [path, await directory(path)]));
    lock = await operationLock(join(job.backupDirectory, 'renewal.lock'));
    const sourceReceipt = await readJson(join(job.backupDirectory, 'backup.json')); receiptShape(sourceReceipt);
    const encryptedPath = join(job.backupDirectory, 'joined.aes256gcm'), keyPath = join(job.keyDirectory, 'recovery.key');
    const sourceCipher = await digest(encryptedPath), sourceKey = await digest(keyPath);
    if (sourceCipher !== sourceReceipt.cipherSha256) throw denied();
    stage = join(job.backupDirectory, '.renewal-' + randomUUID()); directories.push([stage, await createDirectory(stage)]);
    const sourceBundle = join(stage, 'source.bundle');
    await decryptArchive({ encryptedPath, plaintextPath: sourceBundle, keyPath, expectedContext: sourceReceipt.context, onPlaintextCreated: plaintext.record });
    if (await digest(sourceBundle) !== sourceReceipt.context.bundleSha256) throw denied();
    const bundle = await unpackRecoveryBundle({ sourcePath: sourceBundle, directory: stage, onCreated: plaintext.record }), metadata = bundle.metadata;
    // A renewed backup must be restored and closed normally before it can be
    // renewed again; do not hide a second unactivated transition in metadata.
    exact(metadata, ['profile', 'source', 'coreMaterial', 'participantState']);
    if (metadata.profile !== 'FNCP_JOINED_BACKUP_METADATA_V1') throw denied();
    exact(metadata.source, ['configuration', 'imageLock', 'ownerToken', 'accessDescriptor']);
    const source = metadata.source, configuration = validateProductionConfiguration(source.configuration), imageLock = validateProductionImageLock(source.imageLock), roles = volumeRoles(imageLock.version);
    if (configuration.version !== imageLock.version || configuration.sourceRevision !== imageLock.sourceRevision || !/^[a-f0-9]{48}$/u.test(source.ownerToken)
      || sha(canonical(imageLock)) !== sourceReceipt.context.sourceImagesSha256 || source.accessDescriptor.bindingSha256 !== sourceReceipt.context.sourceBindingSha256) throw denied();
    validateCore(metadata.coreMaterial);
    const derived = await deriveJoinedTargetState({ ...bundle, sourceDescriptor: source.accessDescriptor, imageLock, configuration, coreMaterial: metadata.coreMaterial, recoveryEpoch: job.recoveryEpoch });
    derived.targetManifestBytes.fill(0);
    const sourceMaterial = join(stage, 'source-material'), sourceState = join(stage, 'source-state'), targetState = join(stage, 'target-state'), targetMaterial = join(stage, 'target-material');
    for (const path of [sourceMaterial, sourceState, targetState, targetMaterial]) directories.push([path, await createDirectory(path)]);
    for (const role of ['participant_material', 'participant_state']) for (const record of bundle.inventories[role].records) if (record.kind === 'file') {
      const bytes = await readArchiveMember(bundle.archives[role], bundle.inventories[role], record.path, role === 'participant_state' ? 16 * 1024 * 1024 : 262144);
      try { await privateWrite(join(role === 'participant_state' ? sourceState : sourceMaterial, record.path), bytes, plaintext); } finally { bytes.fill(0); }
    }
    const names = bundle.inventories.participant_material.records.filter(r => r.kind === 'file').map(r => r.path).sort();
    if (!equal((await fs.readdir(job.candidateMaterialDirectory)).sort(), names)) throw denied();
    const mountView = { profile: 'FNCP_ARCHIVED_MOUNT_VIEW_V1', sourceStateDirectory: sourceState, targetStateDirectory: targetState };
    const sourceConfigurationPath = join(sourceMaterial, 'service.json'), targetConfigurationPath = join(targetMaterial, 'service.json');
    material = new Map(names.map(name => [name, candidates.read(join(job.candidateMaterialDirectory, name), 262144)]));
    const targetManifest = json(material.get('service.json')), sourceManifest = await readJson(sourceConfigurationPath);
    const comparableManifest = structuredClone(targetManifest); comparableManifest.activation.recoveryEpoch = sourceManifest.activation.recoveryEpoch;
    if (imageLock.version >= 2) comparableManifest.activation.edgeMaterialSha256 = sourceManifest.activation.edgeMaterialSha256;
    if (!equal(comparableManifest, sourceManifest) || targetManifest.activation.recoveryEpoch !== job.recoveryEpoch) throw denied();
    const leaf = role => material.get(targetManifest.tls[role + 'CertFile'].slice('/run/fncp/'.length));
    const tlsChanged = role => ['CertFile', 'KeyFile'].some(suffix => {
      const name = targetManifest.tls[role + suffix].slice('/run/fncp/'.length);
      return sha(material.get(name)) !== bundle.inventories.participant_material.records.find(r => r.path === name)?.sha256;
    });
    const trustChanges = [], replacements = { participant_material: material }; let edgeTlsChanged = false;
    for (const [role, filename, supplied, tlsRole] of [
      ['wordpress_material', 'receiver-ca.pem', job.receiverTrustFile, 'receiver'],
      ...(imageLock.version >= 2 ? [['edge_material', 'upstream-ca.pem', job.edgeUpstreamTrustFile, 'participant']] : []),
    ]) {
      const original = await readArchiveMember(bundle.archives[role], bundle.inventories[role], filename);
      const replacement = supplied ? candidates.read(supplied, 65536) : Buffer.from(original); sensitive.push(replacement);
      try {
        verifyRenewedPeerTrust(leaf(tlsRole), replacement);
        if (!replacement.equals(original)) {
          if (!tlsChanged(tlsRole)) throw denied();
          replacements[role] = new Map([[filename, replacement]]); trustChanges.push(role + '/' + filename);
        }
      } finally { original.fill(0); }
    }
    if ((job.edgeUpstreamTrustFile || job.edgeCertificateFile) && imageLock.version < 2) throw denied();
    if (imageLock.version >= 2) {
      const edge = new Map();
      for (const record of bundle.inventories.edge_material.records) if (record.kind === 'file') {
        const bytes = await readArchiveMember(bundle.archives.edge_material, bundle.inventories.edge_material, record.path); edge.set(record.path, bytes); sensitive.push(bytes);
      }
      for (const [name, bytes] of replacements.edge_material ?? []) edge.set(name, bytes);
      if (job.edgeCertificateFile) {
        const certificate = candidates.read(job.edgeCertificateFile, 65536), privateKey = candidates.read(job.edgePrivateKeyFile, 32768); sensitive.push(certificate, privateKey);
        validateRenewalTls({ certificate, privateKey, origin: configuration.edge.publicOrigin });
        edgeTlsChanged = !certificate.equals(edge.get('server.pem')) || !privateKey.equals(edge.get('server-key.pem'));
        edge.set('server.pem', certificate); edge.set('server-key.pem', privateKey);
      }
      validateRenewalTls({ certificate: edge.get('server.pem'), privateKey: edge.get('server-key.pem'), origin: configuration.edge.publicOrigin });
      targetManifest.activation.edgeMaterialSha256 = sha(canonical([...edge].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([name, bytes]) => ({ name, sha256: sha(bytes) }))));
      replacements.edge_material = edge;
      material.get('service.json').fill(0); material.set('service.json', Buffer.from(canonical(targetManifest) + '\n'));
    }
    for (const [name, bytes] of material) await privateWrite(join(targetMaterial, name), bytes, plaintext);
    stagedProof = holdRenewalMaterial(sourceConfigurationPath, targetConfigurationPath, mountView);
    if (!equal(stagedProof.sourceDescriptor, source.accessDescriptor)) throw denied();
    const state = validateClosedParticipantState({ accessPath: join(sourceState, 'access.sqlite'), activationPath: join(sourceState, 'activation.sqlite'), sourceDescriptor: source.accessDescriptor, activationIdentity: stagedProof.activationIdentity });
    if (!equal(state, metadata.participantState)) throw denied();
    candidates.verify(); stagedProof.verify(); await lock.verify();
    const renewed = renewClosedProductionCredentials({ sourceConfigurationPath, targetConfigurationPath, mountView }, plaintext.record);
    const targetDescriptor = stagedProof.targetDescriptor;
    const stateBytes = await read(join(targetState, 'access.sqlite'), 16 * 1024 * 1024);
    replacements.participant_state = new Map([['access.sqlite', stateBytes]]);
    try {
      for (const [role, values] of Object.entries(replacements)) {
        const targetPath = join(stage, role + '.renewed.tar');
        bundle.inventories[role] = await rewritePrivateVolumeArchive({ sourcePath: bundle.archives[role], targetPath, inventory: bundle.inventories[role], replacements: values, onCreated: plaintext.record });
        bundle.archives[role] = targetPath;
      }
    } finally { stateBytes.fill(0); for (const [role, values] of Object.entries(replacements)) if (!['participant_material', 'participant_state'].includes(role)) for (const bytes of values.values()) bytes.fill(0); }
    const renewedMetadata = { ...metadata, source: { ...source, accessDescriptor: targetDescriptor }, activationBinding: source.accessDescriptor.binding.activation };
    const checked = validateClosedParticipantState({ accessPath: join(targetState, 'access.sqlite'), activationPath: join(targetState, 'activation.sqlite'), sourceDescriptor: targetDescriptor, activationIdentity: stagedProof.activationIdentity, activationBinding: renewedMetadata.activationBinding });
    if (!equal(checked, state)) throw denied();
    const verifyDerived = await deriveJoinedTargetState({ ...bundle, sourceDescriptor: targetDescriptor, imageLock, configuration, coreMaterial: metadata.coreMaterial, recoveryEpoch: randomUUID() });
    verifyDerived.targetManifestBytes.fill(0);
    const targetBundle = join(stage, 'target.bundle'), packed = await packRecoveryBundle({ ...bundle, expectedInventories: bundle.inventories, metadata: renewedMetadata, targetPath: targetBundle, onCreated: plaintext.record });
    const targetDirectory = await createDirectory(job.targetBackupDirectory), targetKeyDirectory = await createDirectory(job.targetKeyDirectory);
    const targetKeyPath = join(job.targetKeyDirectory, 'recovery.key'), key = randomBytes(32), targetKeyHash = sha(key);
    try { await privateWrite(targetKeyPath, key); } finally { key.fill(0); }
    const context = JSON.parse(canonical({ profile: 'FNCP_JOINED_COLD_BACKUP_V1', backupId: randomUUID(), bundleSha256: packed.bundleSha256,
      sourceBindingSha256: targetDescriptor.bindingSha256, sourceImagesSha256: sourceReceipt.context.sourceImagesSha256, sourceEngineSha256: sourceReceipt.context.sourceEngineSha256 }));
    const targetCipher = join(job.targetBackupDirectory, 'joined.aes256gcm');
    await encryptArchive({ plaintextPath: targetBundle, encryptedPath: targetCipher, keyPath: targetKeyPath, context });
    const verified = join(stage, 'verified.bundle');
    await decryptArchive({ encryptedPath: targetCipher, plaintextPath: verified, keyPath: targetKeyPath, expectedContext: context, onPlaintextCreated: plaintext.record });
    if (await digest(verified) !== packed.bundleSha256 || await digest(targetKeyPath) !== targetKeyHash) throw denied();
    for (const [path, stat] of heldDirectories) await check(path, stat);
    await check(job.targetBackupDirectory, targetDirectory); await check(job.targetKeyDirectory, targetKeyDirectory);
    await lock.verify(); candidates.verify(); stagedProof.verify();
    if (await digest(encryptedPath) !== sourceCipher || await digest(keyPath) !== sourceKey
      || !equal(await readJson(join(job.backupDirectory, 'backup.json')), sourceReceipt)) throw denied();
    const cipherSha256 = await digest(targetCipher);
    result = Object.freeze({ profile: 'FNCP_JOINED_CREDENTIAL_RENEWAL_V1', completeEncryptedCandidate: true, durableVolumes: roles.length,
      changedRoles: [...renewed.changedRoles.filter(role => role !== 'edgeMaterial'), ...(edgeTlsChanged ? ['edgeTls'] : [])], trustFilesChanged: trustChanges, participantAccounts: state.accounts, activationReplayFloor: state.activationReplayFloor,
      revokedAccounts: renewed.revokedAccounts, pendingRemovals: renewed.pendingRemovals,
      sourceBindingSha256: source.accessDescriptor.bindingSha256, targetBindingSha256: targetDescriptor.bindingSha256, cipherSha256,
      nativeDatabaseArchivesUnchanged: true, immutableMaterialPreserved: true, activationLedgerCopiedVerbatim: true, historiesAndClocksPreserved: true,
      sourceBackupUnchanged: true, imagesAndSourceUnchanged: true, freshActivationRequired: true, servicesStarted: 0, admissionGranted: false,
      nativeJoinedRestoreRequired: true, providerSecretAcceptanceVerified: false });
    await privateWrite(join(job.targetBackupDirectory, 'renewal.json'), Buffer.from(canonical(result) + '\n'));
    // backup.json is the success marker used by restore; write it last.
    successMarker = { directory: job.targetBackupDirectory, stat: targetDirectory, keyDirectory: job.targetKeyDirectory, keyStat: targetKeyDirectory,
      bytes: Buffer.from(canonical({ profile: 'FNCP_JOINED_BACKUP_RECEIPT_V1', context, cipherSha256, plaintextBytes: packed.bytes }) + '\n') };
  } catch { failed = denied(); }
  finally {
    stagedProof?.close(); candidates.close(); for (const bytes of sensitive) bytes.fill(0); if (material) for (const bytes of material.values()) bytes.fill(0);
    try { for (const [path, stat] of directories) await check(path, stat); await plaintext.cleanup(); for (const [path] of directories.reverse()) await fs.rmdir(path); } catch { failed = denied(); }
    try { await lock?.close(); } catch { failed = denied(); }
  }
  if (failed) throw failed;
  try {
    await check(successMarker.directory, successMarker.stat); await check(successMarker.keyDirectory, successMarker.keyStat);
    await privateWrite(join(successMarker.directory, 'backup.json'), successMarker.bytes);
    for (const path of [successMarker.directory, successMarker.keyDirectory]) { const handle = await fs.open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW); try { await handle.sync(); } finally { await handle.close(); } }
  } catch { throw denied(); } finally { successMarker?.bytes.fill(0); }
  return result;
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try { if (process.argv.length !== 3) throw denied(); process.stdout.write(canonical(await renewJoinedProductionBackup({ jobPath: process.argv[2] })) + '\n'); }
  catch { process.stderr.write('Joined credential renewal denied. No launch is authorized.\n'); process.exitCode = 1; }
}
