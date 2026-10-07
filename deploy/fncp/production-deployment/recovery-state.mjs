import { createPublicKey } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { validBinding } from '../production-activation/protocol.mjs';
import { canonical, exact, sha, SHA, UUID } from '../production-service/contracts.mjs';
import { ACCESS_SCHEMA } from '../production-service/store-schema.mjs';
import { validateExistingProductionStore } from '../production-service/store-validation.mjs';
import { failure, readArchiveMember } from './recovery-archive.mjs';
import { fileEnvironment } from './recovery-ownership.mjs';

function json(bytes) {
  const text = bytes.toString('utf8'); if (!Buffer.from(text).equals(bytes)) throw failure(); return JSON.parse(text);
}
function filename(path) {
  if (typeof path !== 'string' || !/^\/run\/fncp\/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/u.test(path)) throw failure(); return path.slice('/run/fncp/'.length);
}
function body(files, path) { const value = files.get(filename(path)); if (!value) throw failure(); return value; }
function text(files, path) { const b = body(files, path), s = b.toString('utf8'); if (!Buffer.from(s).equals(b) || s.trim() !== s) throw failure(); return s; }
const equal = (a, b) => canonical(a) === canonical(b);

/** Reconstruct the normal service's exact material hash from archived bytes.
 * It permits only a new epoch; container paths, identity and every credential
 * are retained. The resulting target descriptor is independently rechecked by
 * the normal service on startup, without starting a temporary service here.
 */
export async function deriveJoinedTargetState({ archives, inventories, sourceDescriptor, imageLock, configuration, coreMaterial, recoveryEpoch }) {
  const files = new Map();
  try {
    if (!UUID.test(recoveryEpoch) || recoveryEpoch === sourceDescriptor.binding.activation.recoveryEpoch) throw failure();
    for (const r of inventories.participant_material.records) if (r.kind === 'file') files.set(r.path, await readArchiveMember(archives.participant_material, inventories.participant_material, r.path));
    const manifest = json(files.get('service.json')); exact(manifest, ['profile', 'deploymentId', 'conversationId', 'stateDirectory', 'participant', 'receiver', 'identity', 'provider', 'wordpress', 'activation', 'content', 'secrets', 'tls', 'trust']);
    if (manifest.profile !== 'FNCP_PRODUCTION_SERVICE_V1' || manifest.stateDirectory !== '/var/lib/fncp') throw failure();
    exact(manifest.identity, ['issuer', 'authorizationEndpoint', 'tokenEndpoint', 'jwksUri', 'callbackUri', 'clientId', 'tokenEndpointAuthMethod', 'signingAlgorithm', 'clientSecretFile', 'identityKeyFile'], ['caFile']);
    exact(manifest.secrets, ['gatewayKeyFile', 'providerKeyFile', 'wordpressRequestKeyFile', 'wordpressResponseKeyFile', 'wordpressEventKeyFile']);
    exact(manifest.tls, ['participantKeyFile', 'participantCertFile', 'receiverKeyFile', 'receiverCertFile']);
    exact(manifest.trust, [], ['providerCaFile', 'wordpressCaFile']);
    const edgeBinding = Object.hasOwn(manifest.activation.images ?? {}, 'edge');
    const operatorImage = Object.hasOwn(manifest.activation.images ?? {}, 'operator');
    const operatorBinding = Object.hasOwn(manifest.activation ?? {}, 'operatorAccessSha256');
    exact(manifest.activation, ['sourceRevision', 'images', 'recoveryEpoch', 'keyId', 'publicKeyFile', ...(edgeBinding ? ['edgeMaterialSha256'] : []), ...(operatorBinding ? ['operatorAccessSha256'] : [])]);
    if (edgeBinding) {
      if (![2,3].includes(configuration.version) || typeof manifest.activation.edgeMaterialSha256 !== 'string' || !SHA.test(manifest.activation.edgeMaterialSha256)) throw failure();
      const material = [];
      for (const name of ['config.json','server-key.pem','server.pem','upstream-ca.pem']) {
        const bytes = await readArchiveMember(archives.edge_material, inventories.edge_material, name);
        try { material.push({ name, sha256: sha(bytes) }); } finally { bytes.fill(0); }
      }
      if (sha(canonical(material)) !== manifest.activation.edgeMaterialSha256) throw failure();
    }
    if (operatorBinding !== operatorImage || operatorBinding !== (configuration.version === 3)
      || operatorBinding && (typeof manifest.activation.operatorAccessSha256 !== 'string' || !SHA.test(manifest.activation.operatorAccessSha256)
        || manifest.activation.operatorAccessSha256 !== sha(canonical(configuration.operatorAccess)))) throw failure();
    const paths = new Set(['/run/fncp/service.json', manifest.identity.clientSecretFile, manifest.identity.identityKeyFile,
      ...(manifest.identity.caFile ? [manifest.identity.caFile] : []), ...Object.values(manifest.secrets), ...Object.values(manifest.tls),
      ...Object.values(manifest.trust), manifest.activation.publicKeyFile]);
    const fingerprints = Object.fromEntries([...paths].map(path => [path, sha(body(files, path))]));
    if (files.size !== paths.size || sha(canonical({ manifest, material: fingerprints })) !== sourceDescriptor.binding.activation.configSha256) throw failure();
    const c = sourceDescriptor.binding.configuration, a = sourceDescriptor.binding.activation;
    if (sourceDescriptor.bindingSha256 !== sha(canonical(sourceDescriptor.binding))
      || manifest.deploymentId !== c.deploymentId || manifest.conversationId !== c.conversationId || manifest.conversationId !== configuration.binding.conversationId
      || !equal(manifest.content, { consentVersion: c.consentVersion, notice: c.notice, statementIds: c.statementIds, statements: c.statements })
      || !equal(c.statementIds, configuration.binding.statementIds) || manifest.provider.origin !== sourceDescriptor.binding.provider.origin
      || manifest.wordpress.origin !== sourceDescriptor.binding.wordpress.origin || manifest.activation.sourceRevision !== imageLock.sourceRevision
      || a.sourceRevision !== imageLock.sourceRevision || !equal(manifest.activation.images, imageLock.images) || !equal(a.images, imageLock.images)
      || a.operatorAccessSha256 !== manifest.activation.operatorAccessSha256
      || manifest.activation.recoveryEpoch !== a.recoveryEpoch) throw failure();
    const api = fileEnvironment(Buffer.from(coreMaterial['api.env'].data, 'base64'));
    if (api.FNCP_GATEWAY_SHARED_SECRET !== text(files, manifest.secrets.gatewayKeyFile)
      || api.FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL !== text(files, manifest.secrets.providerKeyFile)
      || api.FNCP_GATEWAY_CONVERSATION_ID !== c.conversationId || api.FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID !== c.conversationId
      || api.FNCP_FIXED_STATEMENT_IDS !== c.statementIds.join(',')) throw failure();
    const pluginBytes = await readArchiveMember(archives.wordpress_material, inventories.wordpress_material, 'plugin-config.json');
    try { const p = json(pluginBytes); exact(p, ['profile', 'deploymentId', 'conversationId', 'wordpressOrigin', 'eventEndpoint', 'consentVersion', 'noticeSha256', 'serviceRequestKey', 'serviceResponseKey', 'eventKey', 'caFile']);
      if (p.profile !== 'FNCP_PRODUCTION_WORDPRESS_V1' || p.deploymentId !== c.deploymentId || p.conversationId !== c.conversationId
        || p.wordpressOrigin !== manifest.wordpress.origin || p.eventEndpoint !== manifest.receiver.origin + '/internal/wordpress/events'
        || p.consentVersion !== c.consentVersion || p.noticeSha256 !== c.noticeSha256 || p.caFile !== '/run/fncp/wordpress/receiver-ca.pem'
        || p.serviceRequestKey !== text(files, manifest.secrets.wordpressRequestKeyFile) || p.serviceResponseKey !== text(files, manifest.secrets.wordpressResponseKeyFile)
        || p.eventKey !== text(files, manifest.secrets.wordpressEventKeyFile)) throw failure();
    } finally { pluginBytes.fill(0); }
    const targetManifest = structuredClone(manifest); targetManifest.activation.recoveryEpoch = recoveryEpoch;
    const targetManifestBytes = Buffer.from(canonical(targetManifest) + '\n');
    const targetFingerprints = { ...fingerprints, '/run/fncp/service.json': sha(targetManifestBytes) };
    const targetBinding = structuredClone(sourceDescriptor.binding);
    targetBinding.activation.recoveryEpoch = recoveryEpoch;
    targetBinding.activation.configSha256 = sha(canonical({ manifest: targetManifest, material: targetFingerprints }));
    const publicKey = createPublicKey(body(files, manifest.activation.publicKeyFile));
    if (publicKey.asymmetricKeyType !== 'ed25519') throw failure();
    const activationIdentity = sha(canonical([c.deploymentId, c.conversationId, manifest.activation.keyId, sha(publicKey.export({ format: 'der', type: 'spki' }))]));
    return { targetManifestBytes, targetDescriptor: { binding: targetBinding, bindingSha256: sha(canonical(targetBinding)) }, activationIdentity };
  } catch { throw failure(); } finally { for (const bytes of files.values()) bytes.fill(0); }
}

const ACTIVATION_SCHEMA = [
  'CREATE TABLE activation_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), identity TEXT NOT NULL, boot_id TEXT NOT NULL, binding_hash TEXT NOT NULL, sequence INTEGER NOT NULL CHECK(sequence>=0), active INTEGER NOT NULL CHECK(active IN (0,1)), activation_id TEXT, digest TEXT)',
  'CREATE TABLE activation_ids (id TEXT PRIMARY KEY)',
];
function sqliteShape(db) { return db.prepare('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name').all(); }
/** Validate the stopped pair without changing either database. This does not
 * validate native PostgreSQL/MariaDB rows; those require the later closed-start
 * cross-store rehearsal. Their entire physical clusters are retained verbatim.
 */
export function validateClosedParticipantState({ accessPath, activationPath, sourceDescriptor, activationIdentity, activationBinding = sourceDescriptor.binding.activation }) {
  let access, activation, expected;
  try {
    const current = sourceDescriptor.binding.activation, comparable = { ...activationBinding, configSha256: current.configSha256, recoveryEpoch: current.recoveryEpoch };
    if (!validBinding(activationBinding) || !equal(comparable, current)) throw failure();
    access = new DatabaseSync(accessPath, { readOnly: true }); activation = new DatabaseSync(activationPath, { readOnly: true });
    for (const db of [access, activation]) { db.exec('PRAGMA query_only=ON;PRAGMA trusted_schema=OFF;BEGIN;'); if (db.prepare('PRAGMA journal_mode').get().journal_mode !== 'delete' || db.prepare('PRAGMA quick_check').get().quick_check !== 'ok') throw failure(); }
    const validated = validateExistingProductionStore(access, { schema: ACCESS_SCHEMA, configuration: sourceDescriptor.binding.configuration, bindingSha: sourceDescriptor.bindingSha256 });
    if (validated.fresh || access.prepare('SELECT count(*) AS n FROM invitations WHERE used!=1').get().n
      || access.prepare('SELECT last_ms FROM meta').get().last_ms > Date.now()) throw failure();
    expected = new DatabaseSync(':memory:'); for (const sql of ACTIVATION_SCHEMA) expected.exec(sql);
    if (!equal(sqliteShape(expected), sqliteShape(activation)) || activation.prepare('PRAGMA user_version').get().user_version !== 1
      || activation.prepare('PRAGMA application_id').get().application_id !== 1179534160) throw failure();
    const rows = activation.prepare('SELECT * FROM activation_state LIMIT 2').all(), ids = activation.prepare('SELECT id FROM activation_ids LIMIT 10001').all();
    if (rows.length !== 1 || ids.length > 10000) throw failure(); const row = rows[0];
    if (row.singleton !== 1 || row.identity !== activationIdentity || row.active !== 0 || !Number.isSafeInteger(row.sequence) || row.sequence < 0
      || !SHA.test(row.boot_id) || row.binding_hash !== sha(canonical({ ...activationBinding, bootId: row.boot_id }))
      || row.activation_id !== null && !UUID.test(row.activation_id) || row.digest !== null && !SHA.test(row.digest)
      || (row.activation_id === null) !== (row.digest === null)
      || ids.some(r => !UUID.test(r.id)) || ids.length > row.sequence || row.sequence > 0 && ids.length === 0
      || row.activation_id !== null && !ids.some(r => r.id === row.activation_id)) throw failure();
    return Object.freeze({ accounts: validated.accounts, events: validated.events, invitations: validated.invitations, activationReplayFloor: row.sequence, acceptedActivationIds: ids.length, closed: true });
  } catch { throw failure(); } finally { expected?.close(); activation?.close(); access?.close(); }
}
