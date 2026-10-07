import { createHash, randomBytes, verify, createPublicKey, KeyObject } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { openSync, closeSync, lstatSync, fstatSync, realpathSync, writeSync, readSync, fsyncSync, unlinkSync, constants } from 'node:fs';
import { dirname, basename, isAbsolute, resolve } from 'node:path';
import { activationProtocol, KEY_ID, SHA, UUID, canonical, exact, validBinding, validClaims, fail } from './protocol.mjs';

const authorities = new WeakSet();
const openedLedgers = new Set();
export const isProductionActivation = value => authorities.has(value);
const hash = value => createHash('sha256').update(value).digest('hex');
const APP_ID = 1179534160;
const TABLES = {
  activation_state: 'CREATE TABLE activation_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), identity TEXT NOT NULL, boot_id TEXT NOT NULL, binding_hash TEXT NOT NULL, sequence INTEGER NOT NULL CHECK(sequence>=0), active INTEGER NOT NULL CHECK(active IN (0,1)), activation_id TEXT, digest TEXT)',
  activation_ids: 'CREATE TABLE activation_ids (id TEXT PRIMARY KEY)',
};
const normalize = value => value.replace(/\s+/gu, ' ').trim();
function parentCustody(path) {
  if (typeof path !== 'string' || !isAbsolute(path) || resolve(path) !== path
    || !/^[A-Za-z0-9][A-Za-z0-9_.-]*\.sqlite$/u.test(basename(path))) fail();
  const parent = dirname(path), directory = lstatSync(parent);
  if (realpathSync(parent) !== parent || !directory.isDirectory() || directory.isSymbolicLink()
    || (directory.mode & 0o7777) !== 0o700 || directory.uid !== process.getuid()) fail();
}
function privateFile(file) {
  if (!file.isFile() || file.isSymbolicLink() || file.nlink !== 1 || file.uid !== process.getuid()
    || (file.mode & 0o7777) !== 0o600) fail();
}
function custody(path, create = false) {
  parentCustody(path);
  if (create) {
    try { const fd = openSync(path, constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW, 0o600); closeSync(fd); }
    catch (error) { if (error.code !== 'EEXIST') throw error; }
  }
  const file = lstatSync(path);
  privateFile(file);
  return { dev: file.dev, ino: file.ino };
}
function lockCustody(lock) {
  parentCustody(lock.ledgerPath);
  const descriptor = fstatSync(lock.fd), file = lstatSync(lock.path);
  privateFile(descriptor); privateFile(file);
  if (descriptor.dev !== lock.dev || descriptor.ino !== lock.ino || file.dev !== lock.dev || file.ino !== lock.ino
    || descriptor.size !== lock.body.length || file.size !== lock.body.length) fail();
  const bytes = Buffer.alloc(lock.body.length);
  if (readSync(lock.fd, bytes, 0, bytes.length, 0) !== bytes.length || !bytes.equals(lock.body)) fail();
}
function releaseLock(lock) {
  try { lockCustody(lock); unlinkSync(lock.path); }
  finally { closeSync(lock.fd); }
}
function acquireLock(ledgerPath, identity) {
  parentCustody(ledgerPath);
  const path = ledgerPath + '.lock';
  // Any pre-existing path refuses startup, including a lock left after a crash.
  const fd = openSync(path, constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW, 0o600);
  let file;
  try {
    file = fstatSync(fd);
    const body = Buffer.from(canonical({ schemaVersion: 1, identity, pid: process.pid, token: randomBytes(32).toString('hex') }) + '\n');
    const lock = { ledgerPath, path, fd, dev: file.dev, ino: file.ino, body };
    privateFile(file);
    if (writeSync(fd, body, 0, body.length, 0) !== body.length) fail();
    fsyncSync(fd); lockCustody(lock); return lock;
  } catch {
    // An incomplete acquisition owns only its newly created inode, never a replacement.
    try { const current = lstatSync(path); if (file && current.dev === file.dev && current.ino === file.ino && current.nlink === 1) unlinkSync(path); } catch { /* Preserve foreign state. */ }
    closeSync(fd); fail();
  }
}
function publicVerifier(value) {
  if (value instanceof KeyObject) {
    if (value.type !== 'public' || value.asymmetricKeyType !== 'ed25519') fail();
    return createPublicKey({ key: value.export({ format: 'der', type: 'spki' }), format: 'der', type: 'spki' });
  }
  if (typeof value !== 'string' || value.length > 4096 || !/^-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+\n-----END PUBLIC KEY-----\n?$/u.test(value)) fail();
  const key = createPublicKey(value); if (key.asymmetricKeyType !== 'ed25519') fail(); return key;
}

/** Public-key-only verifier. It never imports the offline signing helper. */
export function createProductionActivation(options) {
  let key, expected, ledgerPath, now, keyId, db, inode, lock, ledgerReserved = false;
  let active, disposed = false, faulted = false, sequenceFloor = 0, lastObserved;
  try {
    if (!exact(options, ['binding', 'publicKey', 'keyId', 'ledgerPath'], ['now'])
      || !validBinding(options.binding) || typeof options.keyId !== 'string' || !KEY_ID.test(options.keyId)) fail();
    key = publicVerifier(options.publicKey); expected = structuredClone(options.binding);
    ({ ledgerPath, keyId } = options); now = options.now ?? Date.now;
    if (typeof now !== 'function') fail();
    lastObserved = now(); if (!Number.isSafeInteger(lastObserved) || lastObserved < 0) fail();
    const identity = hash(canonical([expected.deploymentId, expected.conversationId, keyId,
      hash(key.export({ format: 'der', type: 'spki' }))]));
    parentCustody(ledgerPath);
    if (openedLedgers.has(ledgerPath)) fail(); openedLedgers.add(ledgerPath); ledgerReserved = true;
    lock = acquireLock(ledgerPath, identity);
    inode = custody(ledgerPath, true);
    expected.bootId = randomBytes(32).toString('hex');
    const bindingHash = hash(canonical(expected)), protocol = activationProtocol(expected);
    db = new DatabaseSync(ledgerPath);
    if (canonical(custody(ledgerPath)) !== canonical(inode)) fail();
    const objects = db.prepare("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name").all();
    const version = db.prepare('PRAGMA user_version').get().user_version;
    const application = db.prepare('PRAGMA application_id').get().application_id;
    if (!objects.length) {
      if (version !== 0 || application !== 0) fail();
      db.exec('BEGIN IMMEDIATE');
      for (const sql of Object.values(TABLES)) db.exec(sql);
      db.exec(`PRAGMA user_version=1; PRAGMA application_id=${APP_ID}; COMMIT`);
    } else if (version !== 1 || application !== APP_ID || objects.length !== 2
      || objects.some(o => o.type !== 'table' || !TABLES[o.name] || normalize(o.sql) !== normalize(TABLES[o.name]))) fail();
    db.exec('PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; BEGIN IMMEDIATE');
    const rows = db.prepare('SELECT * FROM activation_state').all();
    const old = rows[0];
    if (rows.length > 1 || old && (old.singleton !== 1 || old.identity !== identity
      || !Number.isSafeInteger(old.sequence) || old.sequence < 0)) fail();
    const acceptedIds = db.prepare('SELECT id FROM activation_ids LIMIT 10001').all();
    if (acceptedIds.length > 10000 || acceptedIds.some(r => typeof r.id !== 'string' || !UUID.test(r.id))
      || !old && acceptedIds.length || old && (acceptedIds.length > old.sequence || old.sequence > 0 && acceptedIds.length === 0
        || !SHA.test(old.boot_id) || !SHA.test(old.binding_hash)
        || old.activation_id !== null && !UUID.test(old.activation_id) || old.digest !== null && !SHA.test(old.digest))) fail();
    sequenceFloor = old?.sequence ?? 0;
    if (old) db.prepare('UPDATE activation_state SET boot_id=?,binding_hash=?,active=0,activation_id=NULL,digest=NULL WHERE singleton=1').run(expected.bootId, bindingHash);
    else db.prepare('INSERT INTO activation_state VALUES(1,?,?,?,0,0,NULL,NULL)').run(identity, expected.bootId, bindingHash);
    db.exec('COMMIT');
    const fault = () => {
      active = undefined; faulted = true;
      try { lockCustody(lock); db.prepare('UPDATE activation_state SET active=0 WHERE singleton=1 AND boot_id=?').run(expected.bootId); } catch { /* In-memory closure cannot be undone. */ }
      fail();
    };
    const store = operation => { try { return operation(); } catch { return fault(); } };
    const usable = () => {
      if (disposed || faulted) fail();
      store(() => { lockCustody(lock); if (canonical(custody(ledgerPath)) !== canonical(inode)) fail(); });
    };
    const observe = () => {
      usable();
      let value; try { value = now(); } catch { return fault(); }
      if (!Number.isSafeInteger(value) || value < lastObserved) return fault();
      lastObserved = value; return Math.floor(value / 1000);
    };
    const currentRow = () => {
      usable(); const row = store(() => db.prepare('SELECT * FROM activation_state WHERE singleton=1').get());
      if (!row || row.identity !== identity || row.boot_id !== expected.bootId || row.binding_hash !== bindingHash
        || !Number.isSafeInteger(row.sequence) || row.sequence !== sequenceFloor) return fault();
      return row;
    };
    const close = () => {
      active = undefined;
      if (disposed || faulted) return;
      currentRow(); store(() => db.prepare('UPDATE activation_state SET active=0 WHERE singleton=1 AND boot_id=?').run(expected.bootId));
    };
    const adapter = Object.freeze({
      profile: protocol.profile,
      challenge() {
        observe(); const row = currentRow();
        if (!Number.isSafeInteger(Math.max(sequenceFloor, row.sequence) + 1)) return fault();
        return { purpose: protocol.purpose, keyId, binding: structuredClone(expected), nextSequence: Math.max(sequenceFloor, row.sequence) + 1, maxLifetimeSeconds: 1800 };
      },
      accept(envelope) {
        // Every attempted replacement revokes the previous activation first.
        close(); const seconds = observe();
        let claims, digest;
        try {
          if (!exact(envelope, ['payload', 'signature']) || typeof envelope.payload !== 'string'
            || envelope.payload.length > 16384 || !/^[A-Za-z0-9_-]+$/u.test(envelope.payload)
            || typeof envelope.signature !== 'string' || !/^[A-Za-z0-9_-]{86}$/u.test(envelope.signature)) fail();
          const payload = Buffer.from(envelope.payload, 'base64url'), signature = Buffer.from(envelope.signature, 'base64url');
          if (payload.toString('base64url') !== envelope.payload || signature.toString('base64url') !== envelope.signature
            || !verify(null, Buffer.concat([Buffer.from(protocol.signingDomain), payload]), key, signature)) fail();
          claims = JSON.parse(payload.toString('utf8')); digest = hash(payload);
          if (!validClaims(claims, keyId) || canonical(claims) !== payload.toString('utf8')
            || hash(canonical(claims.binding)) !== bindingHash || claims.issuedAt > seconds
            || claims.notBefore > seconds || claims.expiresAt <= seconds) fail();
        } catch { fail(); }
        store(() => db.exec('BEGIN IMMEDIATE'));
        try {
          const row = currentRow();
          if (claims.sequence <= Math.max(row.sequence, sequenceFloor)
            || store(() => db.prepare('SELECT id FROM activation_ids WHERE id=?').get(claims.activationId))
            || store(() => db.prepare('SELECT count(*) AS n FROM activation_ids').get().n) >= 10000) fail();
          store(() => db.prepare('INSERT INTO activation_ids VALUES(?)').run(claims.activationId));
          store(() => db.prepare('UPDATE activation_state SET sequence=?,active=1,activation_id=?,digest=? WHERE singleton=1').run(claims.sequence, claims.activationId, digest));
          store(() => db.exec('COMMIT'));
        } catch {
          try { db.exec('ROLLBACK'); } catch { faulted = true; }
          active = undefined; fail();
        }
        sequenceFloor = claims.sequence; active = { claims, digest };
        return Object.freeze({ active: true, generation: claims.activationId, expiresAt: claims.expiresAt });
      },
      assertActive() {
        const seconds = observe(), row = currentRow();
        if (!active || seconds < active.claims.notBefore || seconds >= active.claims.expiresAt) { close(); fail(); }
        if (row.active !== 1 || row.sequence !== active.claims.sequence || row.digest !== active.digest
          || row.activation_id !== active.claims.activationId) return fault();
        return active.claims.activationId;
      },
      close,
      dispose() {
        if (disposed) return;
        try { close(); } finally {
          disposed = true; active = undefined; openedLedgers.delete(ledgerPath);
          try { db.close(); } catch { fail(); }
          try { releaseLock(lock); lock = undefined; } catch { fail(); }
        }
      },
    });
    authorities.add(adapter); return adapter;
  } catch {
    try { db?.exec('ROLLBACK'); } catch { /* No transaction. */ }
    let closed = true;
    try { db?.close(); } catch { closed = false; /* Retain ownership if SQLite cannot close. */ }
    if (lock && closed) try { releaseLock(lock); } catch { /* Preserve foreign or damaged lock. */ }
    if (ledgerReserved) openedLedgers.delete(ledgerPath);
    fail();
  }
}
