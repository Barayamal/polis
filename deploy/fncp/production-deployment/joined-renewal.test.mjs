import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { join, basename } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { canonical, sha } from '../production-service/contracts.mjs';
import { decryptArchive } from '../selfhost/recovery/encryption.mjs';
import { unpackRecoveryBundle } from './recovery-bundle.mjs';
import { readArchiveMember } from './recovery-archive.mjs';
import { validateClosedParticipantState, deriveJoinedTargetState } from './recovery-state.mjs';
import { renewJoinedProductionBackup, verifyRenewedPeerTrust } from './joined-renewal.mjs';
import { joinedRenewalFixture } from './test-support/renewal-fixture.mjs';
import { randomUUID } from 'node:crypto';

const denied = { message: 'Joined credential renewal denied.' };
for (const version of [1, 2, 3]) test(`V${version} renewal authenticates and preserves the complete stack, quotas, revocation, votes archive and activation replay floor`, async t => {
  const x = await joinedRenewalFixture(t, version), before = await fs.readFile(join(x.job.backupDirectory, 'joined.aes256gcm'));
  const result = await renewJoinedProductionBackup({ jobPath: x.jobPath });
  assert.equal(result.completeEncryptedCandidate, true); assert.equal(result.durableVolumes, version >= 2 ? 7 : 6);
  assert.equal(result.participantAccounts, 20); assert.equal(result.revokedAccounts, 7); assert.equal(result.pendingRemovals, 4);
  assert.equal(result.activationReplayFloor, 1); assert.equal(result.freshActivationRequired, true); assert.equal(result.admissionGranted, false);
  assert.deepEqual(result.changedRoles, ['oidcClientSecret', 'participantTls', 'receiverTls']);
  assert.deepEqual(result.trustFilesChanged, ['wordpress_material/receiver-ca.pem', ...(version >= 2 ? ['edge_material/upstream-ca.pem'] : [])]);
  assert.deepEqual(await fs.readFile(join(x.job.backupDirectory, 'joined.aes256gcm')), before);
  assert.deepEqual((await fs.readdir(x.job.backupDirectory)).sort(), ['backup.json', 'joined.aes256gcm']);
  const receipt = JSON.parse(await fs.readFile(join(x.job.targetBackupDirectory, 'backup.json'), 'utf8'));
  const decoded = join(x.path, 'decoded.bundle'), extracts = join(x.path, 'extracts'); await fs.mkdir(extracts, { mode: 0o700 });
  await decryptArchive({ encryptedPath: join(x.job.targetBackupDirectory, 'joined.aes256gcm'), plaintextPath: decoded, keyPath: join(x.job.targetKeyDirectory, 'recovery.key'), expectedContext: receipt.context });
  const bundle = await unpackRecoveryBundle({ sourcePath: decoded, directory: extracts });
  for (const role of ['postgres', 'mariadb', 'proxy_material']) assert.equal(bundle.inventories[role].archiveSha256, x.inventories[role].archiveSha256);
  const get = (role, name) => readArchiveMember(bundle.archives[role], bundle.inventories[role], name, 16 * 1024 * 1024);
  assert.deepEqual(await get('participant_state', 'activation.sqlite'), x.maps.participant_state.get('activation.sqlite'));
  assert.deepEqual(await get('wordpress_material', 'plugin-config.json'), x.maps.wordpress_material.get('plugin-config.json'));
  assert.deepEqual(await get('wordpress_material', 'receiver-ca.pem'), x.targetTls.receiver.ca);
  if (version >= 2) { assert.deepEqual(await get('edge_material', 'upstream-ca.pem'), x.targetTls.participant.ca); assert.deepEqual(await get('edge_material', 'server-key.pem'), x.maps.edge_material.get('server-key.pem')); }
  const targetManifest = JSON.parse(await get('participant_material', 'service.json'));
  assert.equal(targetManifest.stateDirectory, '/var/lib/fncp'); assert.equal(targetManifest.identity.clientSecretFile.startsWith('/run/fncp/'), true);
  const descriptor = bundle.metadata.source.accessDescriptor;
  assert.equal(descriptor.bindingSha256, result.targetBindingSha256);
  assert.equal(canonical(bundle.metadata.activationBinding), canonical(x.sourceDescriptor.binding.activation));
  const accessPath = await x.file('new-access.sqlite', await get('participant_state', 'access.sqlite')), activationPath = await x.file('new-activation.sqlite', await get('participant_state', 'activation.sqlite'));
  assert.deepEqual(validateClosedParticipantState({ accessPath, activationPath, sourceDescriptor: descriptor, activationIdentity: x.activationIdentity, activationBinding: bundle.metadata.activationBinding }), x.metadata.participantState);
  const sourceDb = new DatabaseSync(join(x.f.stateDirectory, 'access.sqlite'), { readOnly: true }), targetDb = new DatabaseSync(accessPath, { readOnly: true });
  try { for (const table of ['accounts', 'events', 'invitations']) assert.equal(canonical(targetDb.prepare('SELECT * FROM ' + table + ' ORDER BY 1').all()), canonical(sourceDb.prepare('SELECT * FROM ' + table + ' ORDER BY 1').all())); }
  finally { sourceDb.close(); targetDb.close(); }
  const proof = await deriveJoinedTargetState({ ...bundle, sourceDescriptor: descriptor, imageLock: x.metadata.source.imageLock, configuration: x.metadata.source.configuration, coreMaterial: x.metadata.coreMaterial, recoveryEpoch: randomUUID() }); proof.targetManifestBytes.fill(0);
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE|SECRET|acct_|fncp_|token_hash|receipt_json/u);
});

for (const [name, mutate] of [
  ['omitted WordPress receiver trust', async x => { delete x.job.receiverTrustFile; }],
  ['omitted edge upstream trust', async x => { delete x.job.edgeUpstreamTrustFile; }],
  ['wrong receiver trust', async x => { x.job.receiverTrustFile = x.job.edgeUpstreamTrustFile; }],
  ['source/image change', async x => { x.next.activation.images.api = 'sha256:' + 'e'.repeat(64); await fs.writeFile(join(x.job.candidateMaterialDirectory, 'service.json'), canonical(x.next) + '\n'); }],
  ['logical path rewriting', async x => { x.next.stateDirectory = x.path; await fs.writeFile(join(x.job.candidateMaterialDirectory, 'service.json'), canonical(x.next) + '\n'); }],
  ['extra material', async x => { await fs.writeFile(join(x.job.candidateMaterialDirectory, 'unknown'), 'private unknown', { mode: 0o600 }); }],
  ['symlink material', async x => { const path = join(x.job.candidateMaterialDirectory, basename(x.next.identity.clientSecretFile)); await fs.unlink(path); await fs.symlink(x.job.receiverTrustFile, path); }],
  ['reused epoch', async x => { x.job.recoveryEpoch = x.manifest.activation.recoveryEpoch; }],
  ['tampered backup', async x => { const p = join(x.job.backupDirectory, 'joined.aes256gcm'), b = await fs.readFile(p); b[b.length - 1] ^= 1; await fs.writeFile(p, b); }],
  ['preexisting target', async x => { await fs.mkdir(x.job.targetBackupDirectory, { mode: 0o700 }); await fs.writeFile(join(x.job.targetBackupDirectory, 'sentinel'), 'keep', { mode: 0o600 }); }],
]) test(`joined renewal refuses ${name} and leaves no success marker`, async t => {
  const x = await joinedRenewalFixture(t); await mutate(x); await x.save();
  await assert.rejects(() => renewJoinedProductionBackup({ jobPath: x.jobPath }), denied);
  assert.equal(await fs.stat(join(x.job.targetBackupDirectory, 'backup.json')).then(() => true, () => false), false);
  assert.deepEqual((await fs.readdir(x.job.backupDirectory)).sort(), ['backup.json', 'joined.aes256gcm']);
  if (name === 'preexisting target') assert.equal(await fs.readFile(join(x.job.targetBackupDirectory, 'sentinel'), 'utf8'), 'keep');
});

test('trust validator refuses unrelated authorities, malformed PEM and CA:false trust files', async t => {
  const x = await joinedRenewalFixture(t);
  assert.equal(verifyRenewedPeerTrust(x.targetTls.receiver.tls.cert, x.targetTls.receiver.ca), true);
  for (const bytes of [x.sourceTls.receiver.ca, x.targetTls.receiver.tls.cert, Buffer.from('bad'), Buffer.concat([x.targetTls.receiver.ca, Buffer.from('unexpected')])]) assert.throws(() => verifyRenewedPeerTrust(x.targetTls.receiver.tls.cert, bytes), denied);
});

test('V2 public edge TLS can renew alone and the resulting complete edge material is activation-bound', async t => {
  const x = await joinedRenewalFixture(t);
  // Use the unchanged archived participant credentials; only the edge leaf is renewed.
  for (const [name, bytes] of x.maps.participant_material) await fs.writeFile(join(x.job.candidateMaterialDirectory, name), bytes);
  const manifest = structuredClone(x.manifest); manifest.activation.recoveryEpoch = x.job.recoveryEpoch;
  await fs.writeFile(join(x.job.candidateMaterialDirectory, 'service.json'), canonical(manifest) + '\n');
  delete x.job.receiverTrustFile; delete x.job.edgeUpstreamTrustFile;
  x.job.edgeCertificateFile = await x.file('edge-new.pem', x.targetTls.participant.tls.cert);
  x.job.edgePrivateKeyFile = await x.file('edge-new-key.pem', x.targetTls.participant.tls.key); await x.save();
  const result = await renewJoinedProductionBackup({ jobPath: x.jobPath });
  assert.deepEqual(result.changedRoles, ['edgeTls']); assert.deepEqual(result.trustFilesChanged, []);
  const receipt = JSON.parse(await fs.readFile(join(x.job.targetBackupDirectory, 'backup.json'), 'utf8'));
  const decoded = join(x.path, 'edge-decoded.bundle'), extracts = join(x.path, 'edge-extracts'); await fs.mkdir(extracts, { mode: 0o700 });
  await decryptArchive({ encryptedPath: join(x.job.targetBackupDirectory, 'joined.aes256gcm'), plaintextPath: decoded, keyPath: join(x.job.targetKeyDirectory, 'recovery.key'), expectedContext: receipt.context });
  const bundle = await unpackRecoveryBundle({ sourcePath: decoded, directory: extracts });
  const target = JSON.parse(await readArchiveMember(bundle.archives.participant_material, bundle.inventories.participant_material, 'service.json'));
  const edgeHash = sha(canonical(bundle.inventories.edge_material.records.filter(r => r.kind === 'file').map(r => ({ name: r.path, sha256: r.sha256 })).sort((a, b) => a.name < b.name ? -1 : 1)));
  assert.equal(target.activation.edgeMaterialSha256, edgeHash); assert.notEqual(edgeHash, x.manifest.activation.edgeMaterialSha256);
  assert.deepEqual(await readArchiveMember(bundle.archives.edge_material, bundle.inventories.edge_material, 'server.pem'), x.targetTls.participant.tls.cert);
});

test('V2 edge TLS pair mismatch is refused before producing a successful backup', async t => {
  const x = await joinedRenewalFixture(t);
  x.job.edgeCertificateFile = await x.file('edge-new.pem', x.targetTls.participant.tls.cert);
  x.job.edgePrivateKeyFile = await x.file('edge-wrong-key.pem', x.targetTls.receiver.tls.key); await x.save();
  await assert.rejects(() => renewJoinedProductionBackup({ jobPath: x.jobPath }), denied);
  assert.equal(await fs.stat(join(x.job.targetBackupDirectory, 'backup.json')).then(() => true, () => false), false);
});
