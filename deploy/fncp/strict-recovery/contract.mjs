/** Strict SYNTHETIC recovery planning only. No paths, sockets, keys-as-data,
 * restore writes or activation. Private snapshots must never be logged. */
import { createHash, createPublicKey, KeyObject, verify } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { validEvent } from '../local-access/wordpress-events.mjs';

export const MODE = 'STRICT_SYNTHETIC_RECOVERY_ONLY';
export const PURPOSE = 'FNCP_STRICT_CLOSED_RECOVERY_V1';
export const SIGNING_DOMAIN = Buffer.from('Barayamal\0FNCP\0StrictClosedRecovery\0v1\0');
export const MAPPING_ALGORITHM = 'HMAC-SHA256-JSON:fncp-account-v1:fncp-xid-v1';
const DENIED = Object.freeze({ ok: false, error: 'strict_recovery_denied' });
const HEX = /^[a-f0-9]{64}$/u;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const KEY_ID = /^synthetic_[a-z][a-z0-9_]{0,63}$/u;
const IMAGES = ['server', 'math', 'alpha', 'proxy', 'migration'];
const KEY_ROLES = ['identityMapping', 'activationVerification', 'wordpressEvent', 'providerGateway', 'providerAllowlist'];
const fail = () => { throw new Error('Strict synthetic recovery denied.'); };
const need = (ok) => { if (!ok) fail(); };
const sha = (value) => createHash('sha256').update(value).digest('hex');
const integer = (value) => Number.isSafeInteger(value) && value >= 0;
const exact = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));

/** Bounded canonical JSON; accessor properties, prototypes, holes, symbols and
 * private KeyObjects are refused before a caller-controlled getter can run. */
export function canonical(value) {
  let budget = 40_000;
  const visit = (item, depth) => {
    need(--budget >= 0 && depth <= 20);
    if (item === null || typeof item === 'boolean' || Number.isSafeInteger(item)) return JSON.stringify(item);
    if (typeof item === 'string') { need(item.length <= 20_000); return JSON.stringify(item); }
    need(item !== null && typeof item === 'object');
    const descriptors = Object.getOwnPropertyDescriptors(item);
    need(Reflect.ownKeys(descriptors).every((name) => typeof name === 'string' &&
      Object.hasOwn(descriptors[name], 'value') && !['__proto__', 'prototype', 'constructor'].includes(name)));
    if (Array.isArray(item)) {
      need(item.length <= 1_000 && Object.keys(descriptors).length === item.length + 1);
      return '[' + Array.from({ length: item.length }, (_, i) => {
        need(Object.hasOwn(descriptors, String(i))); return visit(descriptors[i].value, depth + 1);
      }).join(',') + ']';
    }
    need([Object.prototype, null].includes(Object.getPrototypeOf(item)));
    return '{' + Object.keys(descriptors).sort().map((key) => JSON.stringify(key) + ':' +
      visit(descriptors[key].value, depth + 1)).join(',') + '}';
  };
  return visit(value, 0);
}
const copy = (value) => JSON.parse(canonical(value));
const equal = (a, b) => need(canonical(a) === canonical(b));
const digest = (value) => sha(canonical(value));
const normalizeSql = (sql) => sql.replace(/\bIF NOT EXISTS\s+/gu, '').replace(/\s+/gu, ' ').trim().replace(/;$/u, '');

// Pinned to the present strict access and activation schemas, including SQL
// constraints. Whitespace is normalized, not column/constraint order or types.
const SQL = {
  access: {
    round: 'CREATE TABLE round (id TEXT PRIMARY KEY, open INTEGER NOT NULL DEFAULT 0)',
    fixtures: 'CREATE TABLE fixtures (id TEXT PRIMARY KEY, credential_hash TEXT NOT NULL)',
    approvals: `CREATE TABLE approvals (fixture TEXT NOT NULL REFERENCES fixtures(id),
      round TEXT NOT NULL REFERENCES round(id), xid TEXT NOT NULL UNIQUE,
      state TEXT NOT NULL CHECK(state IN ('pending','approved','revoked')),
      PRIMARY KEY(fixture,round))`,
    invitations: `CREATE TABLE invitations (token_hash TEXT PRIMARY KEY,
      fixture TEXT NOT NULL, round TEXT NOT NULL, expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0)`,
    sessions: `CREATE TABLE sessions (token_hash TEXT PRIMARY KEY,
      fixture TEXT NOT NULL, round TEXT NOT NULL, kind TEXT NOT NULL, expires INTEGER NOT NULL)`,
    identity_mappings: `CREATE TABLE identity_mappings (
      account_id TEXT PRIMARY KEY, fixture TEXT NOT NULL UNIQUE REFERENCES fixtures(id),
      round TEXT NOT NULL REFERENCES round(id), xid TEXT NOT NULL UNIQUE)`,
    wordpress_events: `CREATE TABLE wordpress_events (
      event_id TEXT PRIMARY KEY, subject TEXT NOT NULL REFERENCES fixtures(id),
      version INTEGER NOT NULL, state TEXT NOT NULL, digest TEXT NOT NULL,
      applied INTEGER NOT NULL DEFAULT 0, UNIQUE(subject,version))`,
  },
  activation: {
    activation_state: `CREATE TABLE activation_state (
      singleton INTEGER PRIMARY KEY CHECK(singleton=1), identity TEXT NOT NULL,
      boot_id TEXT NOT NULL, sequence INTEGER NOT NULL, active INTEGER NOT NULL,
      activation_id TEXT, digest TEXT)`,
    activation_ids: 'CREATE TABLE activation_ids (id TEXT PRIMARY KEY)',
  },
};
const schema = (kind) => Object.entries(SQL[kind]).sort(([a], [b]) => a.localeCompare(b)).map(([name, sql]) =>
  ({ type: 'table', name, tbl_name: name, sql: normalizeSql(sql) }));
export const SCHEMA_SHA256 = Object.freeze({ access: digest(schema('access')), activation: digest(schema('activation')) });

/** Read-only statements on a caller-owned handle. This module never opens any
 * database path; callers must supply independently verified/quiescent handles. */
export function readStrictStore(db, kind) {
  try {
    need(db instanceof DatabaseSync && ['access', 'activation'].includes(kind));
    const observed = db.prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE NOT (type='index' AND sql IS NULL AND name GLOB 'sqlite_autoindex_*') ORDER BY name").all();
    need(observed.every((row) => typeof row.sql === 'string'));
    equal(observed.map((row) => ({ ...row, sql: normalizeSql(row.sql) })), schema(kind));
    const integrity = db.prepare('PRAGMA integrity_check').all();
    need(integrity.length === 1 && integrity[0].integrity_check === 'ok' && db.prepare('PRAGMA foreign_key_check').all().length === 0);
    const tables = {};
    for (const name of Object.keys(SQL[kind]).sort()) {
      const count = db.prepare(`SELECT count(*) AS n FROM ${name}`).get().n;
      need(integer(count) && count <= (['invitations', 'activation_ids'].includes(name) ? 1_000 : name === 'wordpress_events' ? 220 : name === 'sessions' ? 0 : 20));
      tables[name] = db.prepare(`SELECT * FROM ${name} ORDER BY 1`).all().map((row) => ({ ...row }));
    }
    return copy({ schemaSha256: SCHEMA_SHA256[kind], integrity: 'ok', foreignKeyViolations: 0, tables });
  } catch { fail(); }
}

function binding(value) {
  need(exact(value, ['deploymentId', 'conversationId', 'recoveryEpoch', 'bootId', 'configSha256', 'seedSha256', 'images', 'scope']));
  need(KEY_ID.test(value.deploymentId ?? '') && /^[0-9][A-Za-z0-9_-]{5,99}$/u.test(value.conversationId ?? '') &&
    UUID.test(value.recoveryEpoch ?? '') && ['bootId', 'configSha256', 'seedSha256'].every((key) => HEX.test(value[key] ?? '')));
  need(exact(value.images, IMAGES) && IMAGES.every((key) => /^sha256:[a-f0-9]{64}$/u.test(value.images[key] ?? '')));
  equal(value.scope, { maxParticipants: 20, statementCount: 15, suggestions: false });
}
function keys(value) {
  need(exact(value, ['mappingAlgorithm', 'mappingKeyVersion', 'issuerConfigurationSha256', 'fingerprints']));
  need(value.mappingAlgorithm === MAPPING_ALGORITHM && integer(value.mappingKeyVersion) && value.mappingKeyVersion > 0 && HEX.test(value.issuerConfigurationSha256 ?? ''));
  need(exact(value.fingerprints, KEY_ROLES) && KEY_ROLES.every((role) => HEX.test(value.fingerprints[role] ?? '')));
  need(new Set(Object.values(value.fingerprints)).size === KEY_ROLES.length);
}
function store(value, kind) {
  need(exact(value, ['schemaSha256', 'integrity', 'foreignKeyViolations', 'tables']) && value.schemaSha256 === SCHEMA_SHA256[kind] &&
    value.integrity === 'ok' && value.foreignKeyViolations === 0 && exact(value.tables, Object.keys(SQL[kind])));
  need(Object.values(value.tables).every(Array.isArray));
}
function unique(rows, key) { need(new Set(rows.map((row) => row[key])).size === rows.length); }

function validateSnapshot(value, freshBoot = false) {
  need(exact(value, ['binding', 'access', 'activation', 'wordpress', 'provider', 'volatile']));
  binding(value.binding); store(value.access, 'access'); store(value.activation, 'activation');
  equal(value.volatile, { oidcPending: 0, principalCapabilities: 0, browserSessions: 0 });
  const a = value.access.tables; const conversation = value.binding.conversationId;
  equal(a.round, [{ id: conversation, open: 0 }]); need(a.sessions.length === 0);
  need(a.fixtures.length > 0 && a.fixtures.length <= 20 && a.identity_mappings.length === a.fixtures.length && a.approvals.length === a.fixtures.length);
  for (const [rows, field] of [[a.fixtures, 'id'], [a.identity_mappings, 'account_id'], [a.identity_mappings, 'fixture'],
    [a.identity_mappings, 'xid'], [a.approvals, 'fixture'], [a.approvals, 'xid'], [a.invitations, 'token_hash'], [a.wordpress_events, 'event_id']]) unique(rows, field);
  for (const row of a.fixtures) need(exact(row, ['id', 'credential_hash']) && HEX.test(row.credential_hash ?? ''));
  const byFixture = new Map();
  for (const row of a.identity_mappings) {
    need(exact(row, ['account_id', 'fixture', 'round', 'xid']) && /^acct_[A-Za-z0-9_-]{43}$/u.test(row.account_id ?? '') &&
      /^fncp_[A-Za-z0-9_-]{43}$/u.test(row.xid ?? '') && row.round === conversation &&
      row.fixture === 'synthetic_i' + sha(row.account_id).slice(0, 39) && a.fixtures.some((f) => f.id === row.fixture));
    byFixture.set(row.fixture, row);
  }
  for (const row of a.approvals) need(exact(row, ['fixture', 'round', 'xid', 'state']) && row.round === conversation &&
    row.state === 'revoked' && byFixture.get(row.fixture)?.xid === row.xid);
  need(a.invitations.length <= 1_000);
  for (const row of a.invitations) need(exact(row, ['token_hash', 'fixture', 'round', 'expires', 'used']) &&
    HEX.test(row.token_hash ?? '') && byFixture.has(row.fixture) && row.round === conversation && integer(row.expires) && row.used === 1);

  need(exact(value.wordpress, ['events']) && Array.isArray(value.wordpress.events) &&
    value.wordpress.events.length === a.wordpress_events.length && a.wordpress_events.length <= 220);
  const eventIds = new Set(); const versions = new Set(); const histories = new Map();
  for (const record of value.wordpress.events) {
    need(exact(record, ['event', 'acknowledged']) && record.acknowledged === true && validEvent(record.event));
    const e = record.event; need(byFixture.has(e.subject) && !eventIds.has(e.event_id) && !versions.has(e.subject + ':' + e.version));
    eventIds.add(e.event_id); versions.add(e.subject + ':' + e.version);
    const row = a.wordpress_events.find((item) => item.event_id === e.event_id);
    const expectedDigest = sha(JSON.stringify(['schema_version', 'event_id', 'subject', 'round_id', 'version', 'state', 'occurred_at'].map((key) => e[key])));
    need(exact(row, ['event_id', 'subject', 'version', 'state', 'digest', 'applied']));
    equal(row, { event_id: e.event_id, subject: e.subject, version: e.version, state: e.state, digest: expectedDigest, applied: 1 });
    if (!histories.has(e.subject)) histories.set(e.subject, []);
    histories.get(e.subject).push(e);
  }
  need(histories.size === byFixture.size);
  for (const events of histories.values()) {
    events.sort((x, y) => x.version - y.version);
    need(events.at(-1).state === 'revoked' && events.slice(0, -1).every((e) => e.state === 'approved'));
  }
  need(exact(value.provider, ['conversationId', 'whitelistRows', 'operations']) && value.provider.conversationId === conversation &&
    value.provider.whitelistRows === 0 && Array.isArray(value.provider.operations) && value.provider.operations.length === byFixture.size);
  unique(value.provider.operations, 'xid');
  for (const row of value.provider.operations) need(exact(row, ['xid', 'operationVersion', 'present']) && row.operationVersion === 2 && row.present === false &&
    a.identity_mappings.some((mapping) => mapping.xid === row.xid));

  const t = value.activation.tables; need(t.activation_state.length === 1 && t.activation_ids.length <= 1_000);
  const state = t.activation_state[0];
  need(exact(state, ['singleton', 'identity', 'boot_id', 'sequence', 'active', 'activation_id', 'digest']) && state.singleton === 1 &&
    state.identity === digest([value.binding.deploymentId, conversation]) && state.boot_id === value.binding.bootId && state.active === 0 && integer(state.sequence));
  unique(t.activation_ids, 'id');
  need(t.activation_ids.every((row) => exact(row, ['id']) && UUID.test(row.id ?? '')) && state.sequence >= t.activation_ids.length);
  need((state.activation_id === null && state.digest === null) ||
    (UUID.test(state.activation_id ?? '') && HEX.test(state.digest ?? '') && t.activation_ids.some((row) => row.id === state.activation_id)));
  if (freshBoot) need(state.activation_id === null && state.digest === null);
  return { mappings: byFixture.size, terminalWordPressEvents: histories.size, retainedWordPressEvents: a.wordpress_events.length,
    providerTombstones: value.provider.operations.length, retainedUsedInvitations: a.invitations.length,
    retainedActivationIds: t.activation_ids.length, sequenceFloor: state.sequence };
}

function continuity(value) {
  need(exact(value, ['source', 'restored'])); keys(value.source); keys(value.restored); equal(value.source, value.restored);
}
function target(source, targetBinding) {
  binding(targetBinding);
  need(source.binding.bootId !== targetBinding.bootId && source.binding.recoveryEpoch !== targetBinding.recoveryEpoch);
  equal({ ...source.binding, bootId: targetBinding.bootId, recoveryEpoch: targetBinding.recoveryEpoch }, targetBinding);
}

/** Public verifier-key fingerprint only; private keys are never accepted. */
export function publicKeyFingerprint(publicKey) {
  try {
    need(publicKey?.type !== 'private');
    need(publicKey instanceof KeyObject && publicKey.type === 'public' || typeof publicKey === 'string' &&
      /^-----BEGIN PUBLIC KEY-----\n[\s\S]+\n-----END PUBLIC KEY-----\n?$/u.test(publicKey));
    const key = publicKey?.type === 'public' ? publicKey : createPublicKey(publicKey);
    need(key instanceof KeyObject && key.type === 'public' && key.asymmetricKeyType === 'ed25519');
    return sha(key.export({ type: 'spki', format: 'der' }));
  } catch { fail(); }
}

/** Produces unsigned, hash-only claims for a separate synthetic signing step. */
export function prepareStrictRecoveryManifest(options) {
  try {
    const o = copy(options);
    need(exact(o, ['mode', 'recoveryId', 'keyId', 'signerFingerprint', 'issuedAt', 'expiresAt', 'source', 'targetBinding', 'keyContinuity']) && o.mode === MODE);
    need(UUID.test(o.recoveryId ?? '') && KEY_ID.test(o.keyId ?? '') && HEX.test(o.signerFingerprint ?? '') &&
      integer(o.issuedAt) && integer(o.expiresAt) && o.expiresAt > o.issuedAt && o.expiresAt - o.issuedAt <= 1_800);
    const counts = validateSnapshot(o.source); target(o.source, o.targetBinding); continuity(o.keyContinuity);
    return { schemaVersion: 1, purpose: PURPOSE, recoveryId: o.recoveryId, keyId: o.keyId, signerFingerprint: o.signerFingerprint,
      issuedAt: o.issuedAt, expiresAt: o.expiresAt, sourceBindingSha256: digest(o.source.binding), targetBindingSha256: digest(o.targetBinding),
      schemas: { ...SCHEMA_SHA256 }, keyPolicy: copy(o.keyContinuity.source), keyContinuitySha256: digest(o.keyContinuity),
      components: Object.fromEntries(['access', 'activation', 'wordpress', 'provider', 'volatile'].map((name) => [name, digest(o.source[name])])),
      counts, instruction: 'RESTORE_CLOSED_WITH_FRESH_BOOT_NO_ACTIVATION' };
  } catch { fail(); }
}

/** Verifies observations and a signed plan. Never consumes a recovery ID, opens
 * a round, returns a principal, or accepts an activation envelope. */
export function validateStrictRecovery(options) {
  try {
    need(options !== null && typeof options === 'object' && [Object.prototype, null].includes(Object.getPrototypeOf(options)));
    need(Reflect.ownKeys(options).every((name) => typeof name === 'string' && Object.hasOwn(Object.getOwnPropertyDescriptor(options, name), 'value')));
    need(exact(options, ['mode', 'envelope', 'publicKey', 'expectedRecoveryId', 'expectedKeyId', 'source', 'restored', 'targetBinding', 'keyContinuity', 'now']));
    const { publicKey, now, ...input } = options;
    need(typeof now === 'function'); const stamp = now(); need(integer(stamp)); const seconds = Math.floor(stamp / 1_000);
    const o = copy(input); need(o.mode === MODE && UUID.test(o.expectedRecoveryId ?? '') && KEY_ID.test(o.expectedKeyId ?? ''));
    const signerFingerprint = publicKeyFingerprint(publicKey);
    const key = publicKey?.type === 'public' ? publicKey : createPublicKey(publicKey);
    need(exact(o.envelope, ['payload', 'signature']) && typeof o.envelope.payload === 'string' && o.envelope.payload.length <= 16_000 &&
      /^[A-Za-z0-9_-]+$/u.test(o.envelope.payload) && /^[A-Za-z0-9_-]{86}$/u.test(o.envelope.signature ?? ''));
    const payload = Buffer.from(o.envelope.payload, 'base64url'); const signature = Buffer.from(o.envelope.signature, 'base64url');
    need(payload.toString('base64url') === o.envelope.payload && signature.toString('base64url') === o.envelope.signature &&
      verify(null, Buffer.concat([SIGNING_DOMAIN, payload]), key, signature));
    const claims = JSON.parse(payload.toString('utf8')); need(canonical(claims) === payload.toString('utf8'));
    need(claims.issuedAt <= seconds && claims.expiresAt > seconds);
    const expected = prepareStrictRecoveryManifest({ mode: MODE, recoveryId: o.expectedRecoveryId, keyId: o.expectedKeyId,
      signerFingerprint, issuedAt: claims.issuedAt, expiresAt: claims.expiresAt,
      source: o.source, targetBinding: o.targetBinding, keyContinuity: o.keyContinuity });
    equal(claims, expected);
    const counts = validateSnapshot(o.restored, true); equal(counts, claims.counts);
    equal(o.restored.binding, o.targetBinding);
    for (const name of ['access', 'wordpress', 'provider', 'volatile']) equal(o.source[name], o.restored[name]);
    const previous = o.source.activation.tables.activation_state[0];
    const current = o.restored.activation.tables.activation_state[0];
    equal(current, { ...previous, boot_id: o.targetBinding.bootId, active: 0, activation_id: null, digest: null });
    equal(o.source.activation.tables.activation_ids, o.restored.activation.tables.activation_ids);
    return Object.freeze({ ok: true, mode: MODE, action: 'KEEP_CLOSED', productionReady: false,
      priorBootInvalidated: true, newSignedActivationRequired: true, newOidcLoginRequired: true,
      oldInvitationsReusable: false, keyContinuityVerifiedAgainstProvidedFingerprints: true,
      actualMultiStoreRestorePerformed: false, requiresExternalRecoveryIdConsumption: true,
      counts: Object.freeze({ ...counts }), manifestSha256: sha(payload) });
  } catch { return DENIED; }
}
