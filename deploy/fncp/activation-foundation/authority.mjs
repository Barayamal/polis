/** Signed deployment-bound authority for a synthetic integration proof only.
 * No HTTP endpoint, production signer, hosting provider or activation is supplied.
 */
import { createHash, randomBytes, verify, createPublicKey } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { existsSync, openSync, closeSync, lstatSync } from 'node:fs';

export const PURPOSE = 'FNCP_SYNTHETIC_ACTIVATION_V1';
export const SIGNING_DOMAIN = Buffer.from('Barayamal\0FNCP\0SyntheticActivation\0v1\0');
const SHA = /^[a-f0-9]{64}$/u;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const NAME = /^synthetic_[a-z][a-z0-9_]{0,63}$/u;
const IMAGES = ['server', 'math', 'alpha', 'proxy', 'migration'];
const digest = (value) => createHash('sha256').update(value).digest('hex');
const plain = (value) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  [Object.prototype, null].includes(Object.getPrototypeOf(value));
const exact = (value, keys) => plain(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
const fail = () => { throw new Error('Synthetic activation denied.'); };

export function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (plain(value)) return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
  if (typeof value === 'string' || typeof value === 'boolean' || value === null || Number.isSafeInteger(value)) return JSON.stringify(value);
  return fail();
}

function validBinding(value, boot = false) {
  return exact(value, ['deploymentId', 'conversationId', 'recoveryEpoch', 'configSha256', 'seedSha256', 'images', 'scope', ...(boot ? ['bootId'] : [])]) &&
    typeof value.deploymentId === 'string' && NAME.test(value.deploymentId) &&
    typeof value.conversationId === 'string' && /^[0-9][A-Za-z0-9_-]{5,99}$/u.test(value.conversationId) &&
    typeof value.recoveryEpoch === 'string' && UUID.test(value.recoveryEpoch) &&
    typeof value.configSha256 === 'string' && SHA.test(value.configSha256) &&
    typeof value.seedSha256 === 'string' && SHA.test(value.seedSha256) &&
    exact(value.images, IMAGES) && IMAGES.every((key) => typeof value.images[key] === 'string' && /^sha256:[a-f0-9]{64}$/u.test(value.images[key])) &&
    exact(value.scope, ['maxParticipants', 'statementCount', 'suggestions']) &&
    value.scope.maxParticipants === 20 && value.scope.statementCount === 15 && value.scope.suggestions === false &&
    (!boot || typeof value.bootId === 'string' && SHA.test(value.bootId));
}

function validClaims(value, keyId) {
  return exact(value, ['schemaVersion', 'purpose', 'keyId', 'activationId', 'sequence', 'issuedAt', 'notBefore', 'expiresAt', 'binding']) &&
    value.schemaVersion === 1 && value.purpose === PURPOSE && value.keyId === keyId &&
    typeof value.activationId === 'string' && UUID.test(value.activationId) &&
    Number.isSafeInteger(value.sequence) && value.sequence > 0 &&
    ['issuedAt', 'notBefore', 'expiresAt'].every((key) => Number.isSafeInteger(value[key]) && value[key] >= 0) &&
    value.notBefore >= value.issuedAt && value.expiresAt > value.notBefore &&
    value.expiresAt - value.issuedAt <= 1800 && validBinding(value.binding, true);
}

function decodeEnvelope(envelope, publicKey, keyId) {
  if (!exact(envelope, ['payload', 'signature']) || typeof envelope.payload !== 'string' ||
      typeof envelope.signature !== 'string' || envelope.payload.length > 12000 ||
      !/^[A-Za-z0-9_-]+$/u.test(envelope.payload) || !/^[A-Za-z0-9_-]{86}$/u.test(envelope.signature)) fail();
  const payload = Buffer.from(envelope.payload, 'base64url');
  const signature = Buffer.from(envelope.signature, 'base64url');
  if (payload.toString('base64url') !== envelope.payload || signature.toString('base64url') !== envelope.signature ||
      !verify(null, Buffer.concat([SIGNING_DOMAIN, payload]), publicKey, signature)) fail();
  const claims = JSON.parse(payload.toString('utf8'));
  if (!validClaims(claims, keyId) || canonical(claims) !== payload.toString('utf8')) fail();
  return { claims, envelopeDigest: digest(payload) };
}

export function createActivationAuthority({ mode, binding, publicKey, keyId, ledgerPath, now = Date.now }) {
  let key; let expected;
  try {
    expected = structuredClone(binding);
    if (mode !== 'SYNTHETIC_ONLY' || !validBinding(expected) || !NAME.test(keyId ?? '') ||
        typeof ledgerPath !== 'string' || !ledgerPath || typeof now !== 'function') fail();
    // A verifier is configured with a public key only, never a runtime signing key.
    if (publicKey?.type === 'private') fail();
    if (publicKey?.type !== 'public' && (typeof publicKey !== 'string' ||
        !/^-----BEGIN PUBLIC KEY-----\n[\s\S]+\n-----END PUBLIC KEY-----\n?$/u.test(publicKey))) fail();
    key = publicKey?.type === 'public' ? publicKey : createPublicKey(publicKey);
    if (key.asymmetricKeyType !== 'ed25519') fail();
  } catch { fail(); }
  expected.bootId = randomBytes(32).toString('hex');
  const bindingHash = digest(canonical(expected));
  const identity = digest(canonical([expected.deploymentId, expected.conversationId]));
  let db; let active; let disposed = false;
  let lastObserved = now();
  let sequenceFloor = 0;
  if (!Number.isSafeInteger(lastObserved) || lastObserved < 0) fail();
  try {
    if (ledgerPath !== ':memory:') {
      if (!existsSync(ledgerPath)) closeSync(openSync(ledgerPath, 'wx', 0o600));
      const stat = lstatSync(ledgerPath);
      if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0) fail();
    }
    db = new DatabaseSync(ledgerPath);
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all().map((row) => row.name);
    if (tables.length && canonical(tables) !== canonical(['activation_ids', 'activation_state'])) fail();
    db.exec(`PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
      CREATE TABLE IF NOT EXISTS activation_state (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1), identity TEXT NOT NULL,
        boot_id TEXT NOT NULL, sequence INTEGER NOT NULL, active INTEGER NOT NULL,
        activation_id TEXT, digest TEXT);
      CREATE TABLE IF NOT EXISTS activation_ids (id TEXT PRIMARY KEY);`);
    db.exec('BEGIN IMMEDIATE');
    const old = db.prepare('SELECT * FROM activation_state WHERE singleton=1').get();
    if (old && (old.identity !== identity || !Number.isSafeInteger(old.sequence) || old.sequence < 0)) fail();
    sequenceFloor = old?.sequence ?? 0;
    if (old) db.prepare('UPDATE activation_state SET boot_id=?,active=0,activation_id=NULL,digest=NULL WHERE singleton=1').run(expected.bootId);
    else db.prepare('INSERT INTO activation_state VALUES(1,?,?,0,0,NULL,NULL)').run(identity, expected.bootId);
    db.exec('COMMIT');
  } catch {
    try { db?.exec('ROLLBACK'); } catch { /* no open transaction */ }
    db?.close(); fail();
  }

  function close() {
    active = undefined;
    if (disposed) return;
    db.prepare('UPDATE activation_state SET active=0 WHERE singleton=1 AND boot_id=?').run(expected.bootId);
  }
  function observe() {
    if (disposed) fail();
    const stamp = now();
    if (!Number.isSafeInteger(stamp) || stamp < lastObserved) { close(); fail(); }
    lastObserved = stamp;
    return Math.floor(stamp / 1000);
  }
  function assertCurrentRow() {
    const row = db.prepare('SELECT * FROM activation_state WHERE singleton=1').get();
    if (!row || row.identity !== identity || row.boot_id !== expected.bootId ||
        !Number.isSafeInteger(row.sequence) || row.sequence < sequenceFloor) { close(); fail(); }
    return row;
  }
  function assertActive() {
    try {
      const seconds = observe(); const row = assertCurrentRow();
      if (!active || row.active !== 1 || row.sequence !== active.claims.sequence ||
          row.digest !== active.envelopeDigest || row.activation_id !== active.claims.activationId ||
          seconds < active.claims.notBefore || seconds >= active.claims.expiresAt ||
          digest(canonical(active.claims.binding)) !== bindingHash) { close(); fail(); }
      return active.claims.activationId;
    } catch {
      active = undefined;
      try { close(); } catch { /* keep the in-memory denial latched even if storage failed */ }
      fail();
    }
  }
  return Object.freeze({
    binding: () => structuredClone(expected),
    nextSequence: () => { const row = assertCurrentRow(); return Math.max(sequenceFloor, row.sequence) + 1; },
    activate(envelope) {
      try {
        const seconds = observe();
        const decoded = decodeEnvelope(envelope, key, keyId); const value = decoded.claims;
        if (digest(canonical(value.binding)) !== bindingHash || value.issuedAt > seconds ||
            value.notBefore > seconds || value.expiresAt <= seconds) fail();
        db.exec('BEGIN IMMEDIATE');
        const row = assertCurrentRow();
        if (value.sequence <= Math.max(row.sequence, sequenceFloor) ||
            db.prepare('SELECT id FROM activation_ids WHERE id=?').get(value.activationId) ||
            db.prepare('SELECT count(*) AS n FROM activation_ids').get().n >= 1000) fail();
        db.prepare('INSERT INTO activation_ids VALUES(?)').run(value.activationId);
        db.prepare('UPDATE activation_state SET sequence=?,active=1,activation_id=?,digest=? WHERE singleton=1')
          .run(value.sequence, value.activationId, decoded.envelopeDigest);
        db.exec('COMMIT');
        sequenceFloor = value.sequence; active = decoded;
        return { active: true, mode: 'SYNTHETIC_ONLY', expiresAt: value.expiresAt };
      } catch {
        try { db.exec('ROLLBACK'); } catch { /* no open transaction */ }
        fail();
      }
    },
    assertActive,
    close,
    dispose() { if (!disposed) { try { close(); } finally { disposed = true; db.close(); } } },
  });
}
