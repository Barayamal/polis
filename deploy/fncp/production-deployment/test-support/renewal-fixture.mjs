// Synthetic complete archives only. These native DB member bytes are test
// placeholders, not a claim of a native PostgreSQL/MariaDB renewal rehearsal.
import fs from 'node:fs/promises';
import { join, basename } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes, randomUUID, createPublicKey } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { canonical, sha } from '../../production-service/contracts.mjs';
import { serviceFixture } from '../../production-service/test-support/service-fixture.mjs';
import { freshLeaf } from '../../production-edge/tls-fixture.mjs';
import { imageRoles } from '../compose.mjs';
import { volumeRoles, inspectVolumeArchive } from '../recovery-archive.mjs';
import { packRecoveryBundle } from '../recovery-bundle.mjs';
import { encryptArchive } from '../../selfhost/recovery/encryption.mjs';
import { CORE_FILES } from '../recovery-ownership.mjs';
import { validateClosedParticipantState } from '../recovery-state.mjs';

function header(name, uid, bytes = Buffer.alloc(0)) {
  const b = Buffer.alloc(512), kind = name.endsWith('/') ? '5' : '0';
  const oct = (offset, length, n) => b.write(n.toString(8).padStart(length - 1, '0') + '\0', offset, length, 'ascii');
  b.write(name, 0, 100); oct(100, 8, kind === '5' ? 0o700 : 0o600); oct(108, 8, uid); oct(116, 8, uid); oct(124, 12, bytes.length); oct(136, 12, 1);
  b.fill(32, 148, 156); b.write(kind, 156); b.write('ustar\0', 257, 6); b.write('00', 263, 2);
  b.write(b.reduce((n, byte) => n + byte, 0).toString(8).padStart(6, '0') + '\0 ', 148, 8);
  return Buffer.concat([b, bytes, Buffer.alloc((512 - bytes.length % 512) % 512)]);
}
const ownership = { postgres: 70, mariadb: 999, participant_state: 1000, participant_material: 1000, wordpress_material: 33, proxy_material: 101, edge_material: 1000 };
function archive(role, files) { return Buffer.concat([header('./', ownership[role]), ...[...files].map(([name, bytes]) => header(name, ownership[role], bytes)), Buffer.alloc(1024)]); }
export async function joinedRenewalFixture(t, version = 2) {
  const f = await serviceFixture(t), path = await fs.realpath(await fs.mkdtemp(join(tmpdir(), 'fncp-joined-renewal-'))); await fs.chmod(path, 0o700);
  t.after(() => fs.rm(path, { recursive: true, force: true }));
  const file = async (name, bytes) => { const p = join(path, name); await fs.writeFile(p, bytes, { mode: 0o600 }); return p; };
  const sourceTls = { participant: freshLeaf(), receiver: freshLeaf() }, targetTls = { participant: freshLeaf(), receiver: freshLeaf() };
  for (const role of ['participant', 'receiver']) { await fs.writeFile(f.manifest.tls[role + 'CertFile'], sourceTls[role].tls.cert); await fs.writeFile(f.manifest.tls[role + 'KeyFile'], sourceTls[role].tls.key); }
  const edgeFiles = new Map([['config.json', Buffer.from(canonical({ version: 1, profile: 'FNCP_PARTICIPANT_EDGE_CONTAINER_V1', publicOrigin: f.manifest.participant.origin, discardCookies: [] }) + '\n')], ['server.pem', sourceTls.participant.tls.cert], ['server-key.pem', sourceTls.participant.tls.key], ['upstream-ca.pem', sourceTls.participant.ca]]);
  const operatorAccess={profile:'FNCP_OPERATOR_LOOPBACK_V1',tunnelRequired:true,participant:{hostIp:'127.0.0.1',published:8443,target:8443,protocol:'tcp'},wordpress:{hostIp:'127.0.0.1',published:9443,target:8443,protocol:'tcp'}};
  if (version >= 2) f.manifest.activation.edgeMaterialSha256 = sha(canonical([...edgeFiles].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([name, bytes]) => ({ name, sha256: sha(bytes) }))));
  if(version===3)f.manifest.activation.operatorAccessSha256=sha(canonical(operatorAccess));
  f.manifest.activation.images = Object.fromEntries(imageRoles(version).map(role => [role, 'sha256:' + sha('synthetic-exact-image-' + role)])); f.save();
  const service = await f.create(); service.operator.activate(f.envelope(service)); service.operator.closeAdmission(); const sourceDescriptor = structuredClone(service.operator.recoveryDescriptor()); await service.close();
  const material = new Map(); for (const name of await fs.readdir(f.materialDirectory)) material.set(name, await fs.readFile(join(f.materialDirectory, name)));
  const manifest = structuredClone(f.manifest); manifest.stateDirectory = '/var/lib/fncp';
  for (const group of ['identity', 'activation', 'secrets', 'tls', 'trust']) for (const [name, value] of Object.entries(manifest[group])) if (name.endsWith('File')) manifest[group][name] = '/run/fncp/' + basename(value);
  material.set('service.json', Buffer.from(canonical(manifest) + '\n'));
  const fingerprints = Object.fromEntries([...material].map(([name, bytes]) => ['/run/fncp/' + name, sha(bytes)]));
  sourceDescriptor.binding.activation.configSha256 = sha(canonical({ manifest, material: fingerprints })); sourceDescriptor.bindingSha256 = sha(canonical(sourceDescriptor.binding));
  const access = new DatabaseSync(join(f.stateDirectory, 'access.sqlite'));
  try {
    access.prepare('UPDATE meta SET binding_sha=?').run(sourceDescriptor.bindingSha256);
    const at = Math.floor((Date.now() - 120000) / 1000), c = sourceDescriptor.binding.configuration;
    for (let n = 0; n < 20; n++) {
      const accountId = 'acct_' + Buffer.from(sha('synthetic-renewal-account-' + n), 'hex').toString('base64url'), xid = 'fncp_' + Buffer.from(sha('synthetic-renewal-xid-' + n), 'hex').toString('base64url');
      const registrationId = randomUUID(), receiptId = randomUUID(), receipt = { receiptId, accountId, consentVersion: c.consentVersion, adultSelfAttested: true, eligibilitySelfAttested: true, registrationConsent: true, issuedAt: at, expiresAt: at + 60 };
      access.prepare('INSERT INTO accounts(account_id,xid,registration_id,receipt_id,receipt_json) VALUES(?,?,?,?,?)').run(accountId, xid, registrationId, receiptId, canonical(receipt));
      if (n % 3 === 0) {
        const eventId = randomUUID(), event = { schemaVersion: 1, eventId, deploymentId: c.deploymentId, conversationId: c.conversationId, registrationId, accountId, version: 2, state: 'revoked', occurredAt: at }, body = canonical(event), applied = n % 2;
        access.prepare('INSERT INTO events VALUES(?,?,?,?,?,?,?)').run(eventId, accountId, 2, 'revoked', sha(body), body, applied);
        access.prepare("UPDATE accounts SET state='revoked',provider_state=?,event_version=2,event_id=? WHERE account_id=?").run(applied ? 'removed' : 'pending_remove', eventId, accountId);
      }
      access.prepare('INSERT INTO invitations VALUES(?,?,?,1)').run(sha('synthetic-consumed-token-' + n), accountId, (at + 60) * 1000);
    }
  } finally { access.close(); }
  const activation = new DatabaseSync(join(f.stateDirectory, 'activation.sqlite'));
  try { const row = activation.prepare('SELECT boot_id FROM activation_state').get(); activation.prepare('UPDATE activation_state SET binding_hash=?').run(sha(canonical({ ...sourceDescriptor.binding.activation, bootId: row.boot_id }))); } finally { activation.close(); }
  const activationIdentity = sha(canonical([manifest.deploymentId, manifest.conversationId, manifest.activation.keyId, sha(createPublicKey(await fs.readFile(f.manifest.activation.publicKeyFile)).export({ format: 'der', type: 'spki' }))]));
  const participantState = validateClosedParticipantState({ accessPath: join(f.stateDirectory, 'access.sqlite'), activationPath: join(f.stateDirectory, 'activation.sqlite'), sourceDescriptor, activationIdentity });
  const get = p => material.get(basename(p)).toString('utf8');
  const plugin = { profile: 'FNCP_PRODUCTION_WORDPRESS_V1', deploymentId: manifest.deploymentId, conversationId: manifest.conversationId,
    wordpressOrigin: manifest.wordpress.origin, eventEndpoint: manifest.receiver.origin + '/internal/wordpress/events', consentVersion: manifest.content.consentVersion,
    noticeSha256: sourceDescriptor.binding.configuration.noticeSha256, serviceRequestKey: get(manifest.secrets.wordpressRequestKeyFile), serviceResponseKey: get(manifest.secrets.wordpressResponseKeyFile), eventKey: get(manifest.secrets.wordpressEventKeyFile), caFile: '/run/fncp/wordpress/receiver-ca.pem' };
  const maps = {
    postgres: new Map(['pgdata/', 'pgdata/global/', 'pgdata/PG_VERSION', 'pgdata/global/pg_control', 'pgdata/fncp.conf', 'pgdata/fncp-initialized', 'pgdata/server.key', 'pgdata/server.crt'].map(name => [name, name.endsWith('/') ? Buffer.alloc(0) : Buffer.from(name === 'pgdata/PG_VERSION' ? '17\n' : 'Synthetic retained native PostgreSQL bytes') ])),
    mariadb: new Map([['mysql/', Buffer.alloc(0)], ['ibdata1', Buffer.from('Synthetic retained native WordPress bytes')]]),
    participant_state: new Map(await Promise.all(['access.sqlite', 'activation.sqlite'].map(async name => [name, await fs.readFile(join(f.stateDirectory, name))]))),
    participant_material: material,
    wordpress_material: new Map([['config.json', Buffer.from('{}')], ['plugin-config.json', Buffer.from(canonical(plugin))], ['server.pem', sourceTls.receiver.tls.cert], ['server-key.pem', sourceTls.receiver.tls.key], ['receiver-ca.pem', sourceTls.receiver.ca]]),
    proxy_material: new Map([['proxy-cert.pem', sourceTls.participant.tls.cert], ['proxy-key.pem', sourceTls.participant.tls.key]]),
    ...(version >= 2 ? { edge_material: edgeFiles } : {}),
  };
  const archives = {}, inventories = {};
  for (const role of volumeRoles(version)) { archives[role] = await file(role + '.tar', archive(role, maps[role])); inventories[role] = await inspectVolumeArchive(archives[role], role); }
  const api = { FNCP_GATEWAY_SHARED_SECRET: get(manifest.secrets.gatewayKeyFile), FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL: get(manifest.secrets.providerKeyFile), FNCP_GATEWAY_CONVERSATION_ID: manifest.conversationId, FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID: manifest.conversationId, FNCP_FIXED_STATEMENT_IDS: manifest.content.statementIds.join(',') };
  const coreMaterial = Object.fromEntries(Object.entries(CORE_FILES).map(([name, mode]) => { const bytes = Buffer.from(name === 'api.env' ? Object.entries(api).map(([k, v]) => k + '=' + v).join('\n') + '\n' : 'Synthetic unchanged core bytes'); return [name, { mode, data: bytes.toString('base64'), sha256: sha(bytes) }]; }));
  const configuration = { version, profile: 'FNCP_PRODUCTION_COMPOSE_V' + version, deployment: 'fncp-synthetic-renewal', platform: 'linux/arm64', stateDirectory: join(path, 'original-install'), sourceRevision: manifest.activation.sourceRevision,
    database: { name: 'polis', owner: 'polis_owner', migrationRole: 'polis_migration', runtimeRole: 'polis_runtime', mathRole: 'polis_math', host: 'postgres', port: 5432 },
    binding: { conversationId: manifest.conversationId, statementIds: manifest.content.statementIds }, identity: { issuer: manifest.identity.issuer, audience: manifest.identity.clientId, jwksUri: manifest.identity.jwksUri }, ...(version >= 2 ? { edge: { publicOrigin: manifest.participant.origin, discardCookies: [] } } : {}), ...(version===3?{operatorAccess}:{}) };
  const imageLock = { version, sourceRevision: manifest.activation.sourceRevision, sourceFingerprint: sha('synthetic-source'), images: manifest.activation.images };
  const metadata = { profile: 'FNCP_JOINED_BACKUP_METADATA_V1', source: { configuration, imageLock, ownerToken: randomBytes(24).toString('hex'), accessDescriptor: sourceDescriptor }, coreMaterial, participantState };
  const bundle = join(path, 'source.bundle'), packed = await packRecoveryBundle({ archives, expectedInventories: inventories, metadata, targetPath: bundle });
  const backupDirectory = join(path, 'backup'), keyDirectory = join(path, 'keys'), candidateMaterialDirectory = join(path, 'candidate');
  for (const d of [backupDirectory, keyDirectory, candidateMaterialDirectory]) await fs.mkdir(d, { mode: 0o700 });
  const context = JSON.parse(canonical({ profile: 'FNCP_JOINED_COLD_BACKUP_V1', backupId: randomUUID(), bundleSha256: packed.bundleSha256, sourceBindingSha256: sourceDescriptor.bindingSha256, sourceImagesSha256: sha(canonical(imageLock)), sourceEngineSha256: sha('synthetic-engine') }));
  await fs.writeFile(join(keyDirectory, 'recovery.key'), randomBytes(32), { mode: 0o600 });
  await encryptArchive({ plaintextPath: bundle, encryptedPath: join(backupDirectory, 'joined.aes256gcm'), keyPath: join(keyDirectory, 'recovery.key'), context });
  const receipt = { profile: 'FNCP_JOINED_BACKUP_RECEIPT_V1', context, cipherSha256: sha(await fs.readFile(join(backupDirectory, 'joined.aes256gcm'))), plaintextBytes: packed.bytes };
  await fs.writeFile(join(backupDirectory, 'backup.json'), canonical(receipt) + '\n', { mode: 0o600 });
  const next = structuredClone(manifest); next.activation.recoveryEpoch = randomUUID();
  for (const [name, bytes] of material) await fs.writeFile(join(candidateMaterialDirectory, name), bytes, { mode: 0o600 });
  for (const role of ['participant', 'receiver']) { await fs.writeFile(join(candidateMaterialDirectory, basename(next.tls[role + 'KeyFile'])), targetTls[role].tls.key); await fs.writeFile(join(candidateMaterialDirectory, basename(next.tls[role + 'CertFile'])), targetTls[role].tls.cert); }
  await fs.writeFile(join(candidateMaterialDirectory, 'service.json'), canonical(next) + '\n');
  await fs.writeFile(join(candidateMaterialDirectory, basename(next.identity.clientSecretFile)), 'SYNTHETIC_RENEWED_SECRET_FOR_TESTS');
  const job = { profile: 'FNCP_JOINED_RENEWAL_JOB_V1', backupDirectory, keyDirectory, candidateMaterialDirectory, recoveryEpoch: next.activation.recoveryEpoch,
    targetBackupDirectory: join(path, 'renewed-backup'), targetKeyDirectory: join(path, 'renewed-keys'), receiverTrustFile: await file('receiver-ca.pem', targetTls.receiver.ca),
    ...(version >= 2 ? { edgeUpstreamTrustFile: await file('participant-ca.pem', targetTls.participant.ca) } : {}) };
  const jobPath = await file('job.json', Buffer.from(canonical(job) + '\n'));
  return { f, path, file, job, jobPath, maps, manifest, next, sourceDescriptor, archives, inventories, metadata, sourceTls, targetTls, activationIdentity,
    save: async () => fs.writeFile(jobPath, canonical(job) + '\n') };
}
