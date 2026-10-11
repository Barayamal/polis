import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { canonical, sha } from './contracts.mjs';
import { ACCESS_SCHEMA } from './store-schema.mjs';
import { IMAGE_ROLES } from '../production-activation/protocol.mjs';
import { recoverClosedProductionAccess } from './recovery.mjs';
import { createPlaintextCustody } from '../selfhost/recovery/plaintext-custody.mjs';

const at = Math.floor((Date.now() - 120000) / 1000) * 1000;
function descriptor() {
  const notice = { adultDeclaration: 'I am an adult.', eligibilityDeclaration: 'I am eligible.', registrationDeclaration: 'I consent to registration.' };
  const configuration = { deploymentId: 'recovery-test', conversationId: '9recoveryRound', consentVersion: 'reviewed-v1',
    noticeSha256: sha(canonical(notice)), notice, identityBindingSha256: sha('synthetic-identity-binding'), credentialBindingSha256: sha('synthetic-credential-binding'),
    statementIds: Array.from({ length: 15 }, (_, i) => i), statements: Array.from({ length: 15 }, (_, i) => `Synthetic reviewed statement ${i}.`) };
  const provider = { origin: 'https://polis.example.test', conversationId: configuration.conversationId,
    statementIds: configuration.statementIds, trustSha256: sha('synthetic-provider-trust') };
  const wordpress = { schemaVersion: 1, deploymentId: configuration.deploymentId, conversationId: configuration.conversationId,
    origin: 'https://wordpress.example.test', consentVersion: configuration.consentVersion, noticeSha256: configuration.noticeSha256,
    trustSha256: sha('synthetic-wordpress-trust'), requestKeySha256: sha('synthetic-request-key'), responseKeySha256: sha('synthetic-response-key') };
  const activation = { deploymentId: configuration.deploymentId, conversationId: configuration.conversationId,
    sourceRevision: 'a'.repeat(40), configSha256: sha('synthetic-source-configuration'), seedSha256: sha(canonical(configuration.statements)),
    providerSha256: sha(canonical(provider)), images: Object.fromEntries(IMAGE_ROLES.map(role => [role, 'sha256:' + sha('synthetic-' + role)])),
    recoveryEpoch: randomUUID(), scope: { maxParticipants: 20, statementCount: 15, suggestions: false } };
  return seal({ configuration, provider, wordpress, activation });
}
const seal = binding => ({ binding, bindingSha256: sha(canonical(binding)) });
function next(source) {
  const b = structuredClone(source.binding); b.activation.recoveryEpoch = randomUUID();
  b.activation.configSha256 = sha('synthetic-reviewed-target-configuration'); return seal(b);
}
function rows(path) {
  const db = new DatabaseSync(path, { readOnly: true });
  try { return Object.fromEntries(['meta', 'accounts', 'events', 'invitations'].map(table => [table, db.prepare(`SELECT * FROM ${table} ORDER BY 1`).all()])); }
  finally { db.close(); }
}
function fixture(t) {
  const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'fncp-access-recovery-test-')));
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const sourceDirectory = join(root, 'source'), targetDirectory = join(root, 'target');
  fs.mkdirSync(sourceDirectory, { mode: 0o700 }); fs.mkdirSync(targetDirectory, { mode: 0o700 });
  const sourcePath = join(sourceDirectory, 'access.sqlite'), targetPath = join(targetDirectory, 'access.sqlite');
  fs.closeSync(fs.openSync(sourcePath, 'wx', 0o600));
  const sourceDescriptor = descriptor(), targetDescriptor = next(sourceDescriptor);
  const db = new DatabaseSync(sourcePath); db.exec(ACCESS_SCHEMA);
  db.prepare('INSERT INTO meta VALUES(1,1,?,?,0,?)').run(sourceDescriptor.bindingSha256, at, randomUUID()); db.close();
  const options = { sourcePath, targetPath, sourceDescriptor, targetDescriptor };
  const sql = fn => { const db = new DatabaseSync(sourcePath); try { return fn(db); } finally { db.close(); } };
  const run = () => recoverClosedProductionAccess(options);
  return { root, sourceDirectory, targetDirectory, sourcePath, targetPath, sourceDescriptor, targetDescriptor, options, sql, run };
}
function account(db, n = 1) {
  const accountId = 'acct_' + Buffer.from(sha('synthetic-account-' + n), 'hex').toString('base64url');
  const xid = 'fncp_' + Buffer.from(sha('synthetic-xid-' + n), 'hex').toString('base64url');
  const receiptId = randomUUID(), registrationId = randomUUID();
  const receipt = { receiptId, accountId, consentVersion: 'reviewed-v1', adultSelfAttested: true,
    eligibilitySelfAttested: true, registrationConsent: true, issuedAt: at / 1000, expiresAt: at / 1000 + 60 };
  db.prepare('INSERT INTO accounts(account_id,xid,registration_id,receipt_id,receipt_json) VALUES(?,?,?,?,?)')
    .run(accountId, xid, registrationId, receiptId, canonical(receipt));
  return { accountId, registrationId };
}
function event(db, a, state = 'approved', applied = 1) {
  const version = state === 'approved' ? 1 : 2;
  const body = canonical({ schemaVersion: 1, eventId: randomUUID(), deploymentId: 'recovery-test', conversationId: '9recoveryRound',
    registrationId: a.registrationId, accountId: a.accountId, version, state, occurredAt: at / 1000 });
  const id = JSON.parse(body).eventId;
  db.prepare('INSERT INTO events VALUES(?,?,?,?,?,?,?)').run(id, a.accountId, version, state, sha(body), body, applied);
  db.prepare('UPDATE accounts SET state=?,provider_state=?,event_version=?,event_id=? WHERE account_id=?')
    .run(state === 'approved' && !applied ? 'pending' : state,
      state === 'approved' ? applied ? 'approved' : 'pending_allow' : applied ? 'removed' : 'pending_remove', version, id, a.accountId);
}
const rejects = fn => assert.throws(fn, e => e.message === 'Offline production access recovery denied.' && Object.keys(e).length === 0);
function noLocks(f) {
  for (const directory of [f.sourceDirectory, f.targetDirectory]) assert.deepEqual(fs.readdirSync(directory).filter(n => n.endsWith('.lock')), []);
}

test('exclusive recovery changes only the binding, preserves source bytes and every pending/terminal record', t => {
  const f = fixture(t);
  f.sql(db => {
    account(db, 1);
    const awaitingAllow = account(db, 2); event(db, awaitingAllow, 'approved', 0);
    const approved = account(db, 3); event(db, approved);
    db.prepare('INSERT INTO invitations VALUES(?,?,?,1)').run(sha('synthetic-consumed-invite'), approved.accountId, at + 600000);
    const awaitingRemoval = account(db, 4); event(db, awaitingRemoval); event(db, awaitingRemoval, 'revoked', 0);
    const removed = account(db, 5); event(db, removed, 'revoked');
    const learnedFromStatus = account(db, 6); event(db, learnedFromStatus);
    db.prepare("UPDATE accounts SET state='revoked',provider_state='pending_remove',event_version=2,event_id=? WHERE account_id=?").run(randomUUID(), learnedFromStatus.accountId);
  });
  // The separate activation replay ledger is an opaque file to this helper.
  const activation = join(f.sourceDirectory, 'activation.sqlite'); fs.writeFileSync(activation, 'synthetic retained activation ledger', { mode: 0o600 });
  const activationBytes = fs.readFileSync(activation), before = rows(f.sourcePath), sourceBytes = fs.readFileSync(f.sourcePath), stat = fs.statSync(f.sourcePath);
  const result = f.run();
  assert.deepEqual(Object.keys(result).sort(), ['profile', 'copied', 'accounts', 'events', 'invitations', 'revokedAccounts', 'pendingRemovals',
    'sourceSha256', 'targetSha256', 'sourceBindingSha256', 'targetBindingSha256', 'sourceUnchanged', 'historiesAndClocksPreserved', 'activationLedgerUnchanged', 'admissionGranted'].sort());
  assert.equal(result.accounts, 6); assert.equal(result.events, 6); assert.equal(result.invitations, 1);
  assert.equal(result.revokedAccounts, 3); assert.equal(result.pendingRemovals, 2); assert.equal(result.admissionGranted, false);
  assert.equal(result.sourceSha256, sha(sourceBytes)); assert.equal(result.targetSha256, sha(fs.readFileSync(f.targetPath)));
  assert.deepEqual(fs.readFileSync(f.sourcePath), sourceBytes); assert.deepEqual(fs.readFileSync(activation), activationBytes);
  assert.equal(fs.statSync(f.sourcePath).mtimeMs, stat.mtimeMs); assert.equal(fs.statSync(f.sourcePath).ctimeMs, stat.ctimeMs);
  assert.deepEqual(rows(f.sourcePath), before);
  const expected = structuredClone(before); expected.meta[0].binding_sha = f.targetDescriptor.bindingSha256;
  assert.equal(canonical(rows(f.targetPath)), canonical(expected));
  assert.equal(fs.statSync(f.targetPath).mode & 0o7777, 0o600);
  assert.equal(fs.existsSync(join(f.targetDirectory, 'activation.sqlite')), false); noLocks(f);
  const serialized = JSON.stringify(result);
  assert.doesNotMatch(serialized, /acct_|fncp_|registration|receipt|token_hash|@|\/private\//u);
});

for (const [name, change] of [
  ['unchanged epoch', b => {}],
  ['changed identity binding', b => { b.configuration.identityBindingSha256 = sha('different identity'); }],
  ['changed immutable credential binding', b => { b.configuration.credentialBindingSha256 = sha('different credential'); }],
  ['changed WordPress key', b => { b.wordpress.requestKeySha256 = sha('different request key'); }],
  ['changed TLS trust', b => { b.provider.trustSha256 = sha('different trust'); b.activation.providerSha256 = sha(canonical(b.provider)); }],
  ['changed source revision', b => { b.activation.sourceRevision = 'b'.repeat(40); }],
  ['changed exact image', b => { b.activation.images.api = 'sha256:' + sha('different image'); }],
  ['changed scope', b => { b.activation.scope.maxParticipants = 21; }],
  ['changed reviewed notice', b => { b.configuration.notice.adultDeclaration = 'Different declaration'; b.configuration.noticeSha256 = sha(canonical(b.configuration.notice)); b.wordpress.noticeSha256 = b.configuration.noticeSha256; }],
]) test(`rejects ${name} before target creation`, t => {
  const f = fixture(t), b = structuredClone(f.sourceDescriptor.binding);
  if (name !== 'unchanged epoch') b.activation.recoveryEpoch = randomUUID();
  change(b); f.options.targetDescriptor = seal(b);
  const hash = sha(fs.readFileSync(f.sourcePath)); rejects(f.run);
  assert.equal(fs.existsSync(f.targetPath), false); assert.equal(sha(fs.readFileSync(f.sourcePath)), hash); noLocks(f);
});

test('descriptor hash, exact shape and executable-array members reject without invoking getters', t => {
  const f = fixture(t); f.options.targetDescriptor.bindingSha256 = '0'.repeat(64); rejects(f.run);
  f.options.targetDescriptor = next(f.sourceDescriptor); f.options.targetDescriptor.extra = true; rejects(f.run);
  let invoked = false; f.options.targetDescriptor = next(f.sourceDescriptor);
  Object.defineProperty(f.options.targetDescriptor.binding.configuration.statementIds, 0, { get() { invoked = true; return 0; } });
  rejects(f.run); assert.equal(invoked, false); assert.equal(fs.existsSync(f.targetPath), false); noLocks(f);
});

for (const [name, mutate] of [
  ['extra table', db => db.exec('CREATE TABLE surprise(secret TEXT)')],
  ['extra index', db => db.exec('CREATE INDEX surprise ON accounts(state)')],
  ['extra trigger', db => db.exec('CREATE TRIGGER surprise AFTER UPDATE ON meta BEGIN DELETE FROM accounts; END')],
  ['faulted clock', db => db.exec('UPDATE meta SET faulted=1')],
  ['future clock', db => db.prepare('UPDATE meta SET last_ms=?').run(Date.now() + 3600000)],
  ['missing metadata', db => db.exec('DELETE FROM meta')],
  ['changed stored binding', db => db.prepare('UPDATE meta SET binding_sha=?').run('0'.repeat(64))],
  ['unapplied terminal barrier corruption', db => { const a = account(db); event(db, a, 'revoked', 0); db.exec("UPDATE accounts SET state='pending',provider_state='none',event_version=0,event_id=NULL"); }],
]) test(`rejects source ${name} without changing it`, t => {
  const f = fixture(t); f.sql(mutate); const bytes = fs.readFileSync(f.sourcePath); rejects(f.run);
  assert.deepEqual(fs.readFileSync(f.sourcePath), bytes); assert.equal(fs.existsSync(f.targetPath), false); noLocks(f);
});

for (const expires of [at - 1, at + 600000]) test(`unused invitation rejects even ${expires < at ? 'after expiry' : 'before expiry'}`, t => {
  const f = fixture(t); f.sql(db => { const a = account(db); event(db, a); db.prepare('INSERT INTO invitations VALUES(?,?,?,0)').run(sha('unused'), a.accountId, expires); });
  rejects(f.run); assert.equal(fs.existsSync(f.targetPath), false); noLocks(f);
});

for (const suffix of ['service.lock', 'access.sqlite.writer.lock', 'activation.sqlite.lock', 'access.sqlite-journal', 'access.sqlite-wal', 'access.sqlite-shm']) {
  for (const side of ['sourceDirectory', 'targetDirectory']) test(`rejects occupied ${side} ${suffix} and preserves it`, t => {
    const f = fixture(t), path = join(f[side], suffix); fs.writeFileSync(path, 'foreign custody sentinel', { mode: 0o600 });
    rejects(f.run); assert.equal(fs.readFileSync(path, 'utf8'), 'foreign custody sentinel'); assert.equal(fs.existsSync(f.targetPath), false);
  });
}

test('occupied target is never overwritten or removed', t => {
  const f = fixture(t); fs.writeFileSync(f.targetPath, 'occupied sentinel', { mode: 0o600 });
  rejects(f.run); assert.equal(fs.readFileSync(f.targetPath, 'utf8'), 'occupied sentinel'); noLocks(f);
});

test('nonprivate directory, symlink and multiply linked source reject', t => {
  const f = fixture(t); fs.chmodSync(f.targetDirectory, 0o750); rejects(f.run); fs.chmodSync(f.targetDirectory, 0o700);
  const real = f.sourcePath + '.real'; fs.renameSync(f.sourcePath, real); fs.symlinkSync(real, f.sourcePath); rejects(f.run);
  fs.unlinkSync(f.sourcePath); fs.renameSync(real, f.sourcePath); fs.linkSync(f.sourcePath, real); rejects(f.run);
  assert.equal(fs.existsSync(f.targetPath), false); noLocks(f);
});

test('target within repository rejects even with an owned0700 private directory', async t => {
  const f = fixture(t), repository = join(f.root, 'disposable-source-tree');
  // Keep the actual source image read-only. Import byte-identical public code
  // from a disposable source tree so its module-derived repository boundary
  // can be exercised with a real owned0700 directory inside that tree.
  for (const name of ['production-service/recovery.mjs', 'production-service/contracts.mjs',
    'production-service/store-schema.mjs', 'production-service/store-validation.mjs', 'production-activation/protocol.mjs']) {
    const target = join(repository, 'deploy/fncp', name); fs.mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
    fs.copyFileSync(fileURLToPath(new URL('../' + name, import.meta.url)), target);
  }
  const copy = await import(pathToFileURL(join(repository, 'deploy/fncp/production-service/recovery.mjs')).href);
  const inside = join(repository, 'private'); fs.mkdirSync(inside, { mode: 0o700 }); f.options.targetPath = join(inside, 'access.sqlite');
  rejects(() => copy.recoverClosedProductionAccess(f.options)); assert.deepEqual(fs.readdirSync(inside), []); noLocks(f);
});

test('a real partial-copy write failure removes only the invocation-created target', t => {
  const f = fixture(t), original = fs.writeSync; let injected = false;
  t.mock.method(fs, 'writeSync', (fd, bytes, offset, length, position) => {
    if (!injected) { injected = true; original(fd, bytes, offset, Math.min(length, 64), position); throw new Error('private write error sentinel'); }
    return original(fd, bytes, offset, length, position);
  });
  const bytes = fs.readFileSync(f.sourcePath); rejects(f.run); assert.equal(injected, true);
  assert.equal(fs.existsSync(f.targetPath), false); assert.deepEqual(fs.readFileSync(f.sourcePath), bytes); noLocks(f);
});

test('a replaced target inode is preserved after partial-copy failure', t => {
  const f = fixture(t), original = fs.writeSync; let injected = false;
  t.mock.method(fs, 'writeSync', (fd, bytes, offset, length, position) => {
    if (!injected) { injected = true; original(fd, bytes, offset, Math.min(length, 64), position);
      fs.renameSync(f.targetPath, f.targetPath + '.moved'); fs.writeFileSync(f.targetPath, 'replacement sentinel', { mode: 0o600 });
      throw new Error('private error sentinel'); }
    return original(fd, bytes, offset, length, position);
  });
  rejects(f.run); assert.equal(fs.readFileSync(f.targetPath, 'utf8'), 'replacement sentinel');
  assert.equal(fs.statSync(f.targetPath + '.moved').size, 64); noLocks(f);
});

test('parent mode drift during copy rejects and conservatively preserves the untrusted target', t => {
  const f = fixture(t), original = fs.writeSync; let injected = false;
  t.mock.method(fs, 'writeSync', (fd, bytes, offset, length, position) => {
    const result = original(fd, bytes, offset, length, position);
    if (!injected) { injected = true; fs.chmodSync(f.targetDirectory, 0o750); }
    return result;
  });
  rejects(f.run); assert.equal(fs.existsSync(f.targetPath), true);
  // The helper cannot delete files after losing parent custody; the test owns
  // this entire disposable directory and cleans it after restoring its mode.
  fs.chmodSync(f.targetDirectory, 0o700);
});

test('creation observer tracks plaintext before a late lock-release throw, preserving an unknown replacement lock', async t => {
  const f = fixture(t), custody = createPlaintextCustody(), unlink = fs.unlinkSync;
  const lock = join(f.targetDirectory, 'service.lock'), source = fs.readFileSync(f.sourcePath); let injected = false, observed = false;
  t.mock.method(fs, 'unlinkSync', path => {
    if (path === lock && !injected) { injected = true; fs.renameSync(lock, lock + '.moved'); fs.writeFileSync(lock, 'foreign replacement lock', { mode: 0o600 }); throw new Error('synthetic late release failure'); }
    return unlink(path);
  });
  rejects(() => recoverClosedProductionAccess(f.options, (path, stat) => {
    observed = true; assert.equal(path, f.targetPath); assert.equal(stat.size, 0n); custody.record(path, stat);
  }));
  assert.equal(injected, true); assert.equal(observed, true); assert.equal(fs.existsSync(f.targetPath), true);
  await custody.cleanup(); assert.equal(fs.existsSync(f.targetPath), false);
  assert.equal(fs.readFileSync(lock, 'utf8'), 'foreign replacement lock'); assert.equal(fs.existsSync(lock + '.moved'), true);
  assert.deepEqual(fs.readFileSync(f.sourcePath), source);
});
