import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { createHash, randomUUID } from 'node:crypto';
import { ACCESS_SCHEMA } from './store-schema.mjs';
import { canonical, sha } from './contracts.mjs';
import { validateExistingProductionStore } from './store-validation.mjs';

const configuration = { deploymentId: 'test-deployment', conversationId: '9fncpTestRound', consentVersion: 'reviewed-v1' };
const bindingSha = 'a'.repeat(64), at = 1789390000000;
function fixture(t, { schema = ACCESS_SCHEMA, fresh = false } = {}) {
  const db = new DatabaseSync(':memory:'); t.after(() => db.close());
  db.exec('PRAGMA foreign_keys=ON;PRAGMA trusted_schema=OFF;'); db.exec(schema);
  if (!fresh) db.prepare('INSERT INTO meta VALUES(1,1,?,?,0,?)').run(bindingSha, at, randomUUID());
  const validate = () => validateExistingProductionStore(db, { schema: ACCESS_SCHEMA, configuration, bindingSha });
  return { db, validate };
}
function account(db, n = 1) {
  const accountId = 'acct_' + createHash('sha256').update('account-' + n).digest('base64url');
  const xid = 'fncp_' + createHash('sha256').update('xid-' + n).digest('base64url');
  const receiptId = randomUUID(), registrationId = randomUUID();
  const receipt = { receiptId, accountId, consentVersion: configuration.consentVersion,
    adultSelfAttested: true, eligibilitySelfAttested: true, registrationConsent: true,
    issuedAt: at / 1000, expiresAt: at / 1000 + 60 };
  db.prepare('INSERT INTO accounts(account_id,xid,registration_id,receipt_id,receipt_json) VALUES(?,?,?,?,?)')
    .run(accountId, xid, registrationId, receiptId, canonical(receipt));
  return { accountId, xid, receiptId, registrationId, receipt };
}
function event(db, a, state = 'approved', applied = 1) {
  const version = state === 'approved' ? 1 : 2;
  const value = { schemaVersion: 1, eventId: randomUUID(), ...configuration,
    registrationId: a.registrationId, accountId: a.accountId, version, state, occurredAt: at / 1000 };
  delete value.consentVersion;
  const body = canonical(value);
  db.prepare('INSERT INTO events VALUES(?,?,?,?,?,?,?)').run(value.eventId, a.accountId, version, state, sha(body), body, applied);
  db.prepare('UPDATE accounts SET state=?,provider_state=?,event_version=?,event_id=? WHERE account_id=?')
    .run(state === 'approved' && !applied ? 'pending' : state,
      state === 'approved' ? applied ? 'approved' : 'pending_allow' : applied ? 'removed' : 'pending_remove', version, value.eventId, a.accountId);
  return value;
}
function invitation(db, a, used = 0, n = 1) {
  db.prepare('INSERT INTO invitations VALUES(?,?,?,?)').run(sha('invitation-' + n), a.accountId, at + 600_000, used);
}
const rejects = fn => assert.throws(fn, error => error.code === 'access_store_rejected' && error.status === 503 && !error.message.includes('acct_'));

test('trusted empty schema and ordinary pending/approved/removal states validate without changing source DB', t => {
  const f = fixture(t, { fresh: true }); assert.equal(f.validate().fresh, true);
  f.db.prepare('INSERT INTO meta VALUES(1,1,?,?,0,?)').run(bindingSha, at, randomUUID());
  account(f.db, 1); const pending = account(f.db, 2); event(f.db, pending, 'approved', 0);
  const approved = account(f.db, 3); event(f.db, approved); invitation(f.db, approved);
  const revoked = account(f.db, 4); event(f.db, revoked, 'revoked', 0);
  const removed = account(f.db, 5); event(f.db, removed, 'revoked', 1);
  const before = f.db.prepare('SELECT total_changes() AS n').get().n;
  assert.deepEqual(f.validate(), { fresh: false, accounts: 5, events: 4, invitations: 1 });
  assert.equal(f.db.prepare('SELECT total_changes() AS n').get().n, before);
});

test('revocation learned through signed status can lack v2 event but remains terminal', t => {
  const { db, validate } = fixture(t); const a = account(db); event(db, a);
  db.prepare("UPDATE accounts SET state='revoked',provider_state='pending_remove',event_version=2,event_id=?").run(randomUUID());
  assert.equal(validate().accounts, 1);
});

test('account removed before event-applied update is a valid crash reconciliation state', t => {
  const { db, validate } = fixture(t); const a = account(db); event(db, a, 'revoked', 0);
  db.exec("UPDATE accounts SET provider_state='removed'"); assert.equal(validate().events, 1);
});

for (const [name, change] of [
  ['unreviewed table', db => db.exec('CREATE TABLE unexpected(value TEXT)')],
  ['unreviewed index', db => db.exec('CREATE INDEX surprise ON accounts(state)')],
  ['unreviewed trigger', db => db.exec('CREATE TRIGGER surprise AFTER INSERT ON accounts BEGIN SELECT 1; END')],
  ['unreviewed view', db => db.exec('CREATE VIEW surprise AS SELECT account_id FROM accounts')],
]) test(`exact schema rejects ${name}`, t => { const { db, validate } = fixture(t); change(db); rejects(validate); });

test('same column names with relaxed uniqueness/constraints are rejected', t => {
  const { validate } = fixture(t, { schema: ACCESS_SCHEMA.replace('xid TEXT NOT NULL UNIQUE', 'xid TEXT NOT NULL') }); rejects(validate);
});

test('missing metadata cannot reinitialize populated state; faulted metadata and changed bindings reject', t => {
  const { db, validate } = fixture(t); account(db);
  const meta = db.prepare('SELECT * FROM meta').get(); db.exec('DELETE FROM meta'); rejects(validate);
  db.prepare('INSERT INTO meta VALUES(1,1,?,?,0,?)').run(meta.binding_sha, meta.last_ms, meta.boot_id);
  db.exec('UPDATE meta SET faulted=1'); rejects(validate); db.exec('UPDATE meta SET faulted=0');
  rejects(() => validateExistingProductionStore(db, { schema: ACCESS_SCHEMA, configuration, bindingSha: 'b'.repeat(64) }));
});

for (const [name, mutate] of [
  ['changed account', r => { r.accountId = 'acct_' + 'B'.repeat(43); }],
  ['changed receipt ID', r => { r.receiptId = randomUUID(); }],
  ['wrong declaration', r => { r.adultSelfAttested = false; }],
  ['wrong notice version', r => { r.consentVersion = 'different'; }],
  ['extra email field', r => { r.email = 'private-sentinel@example.test'; }],
  ['long receipt lifetime', r => { r.expiresAt += 1; }],
  ['future issue time', r => { r.issuedAt += 1; r.expiresAt += 1; }],
]) test(`receipt rejects ${name}`, t => {
  const { db, validate } = fixture(t); const a = account(db); mutate(a.receipt);
  db.prepare('UPDATE accounts SET receipt_json=?').run(canonical(a.receipt)); rejects(validate);
});

test('receipt canonical encoding is required; valid expired committed receipts remain recoverable', t => {
  const { db, validate } = fixture(t); const a = account(db);
  db.exec('UPDATE meta SET last_ms=last_ms+120000'); assert.equal(validate().accounts, 1);
  db.prepare('UPDATE accounts SET receipt_json=?').run(' ' + canonical(a.receipt)); rejects(validate);
});

test('a delayed original registration event can precede the replacement retry receipt without changing its bound account', t => {
  const { db, validate } = fixture(t); const a = account(db); const committed = event(db, a);
  const retry = { ...a.receipt, receiptId: randomUUID(), issuedAt: a.receipt.issuedAt + 120,
    expiresAt: a.receipt.expiresAt + 120 };
  db.prepare('UPDATE accounts SET receipt_id=?,receipt_json=? WHERE account_id=?')
    .run(retry.receiptId, canonical(retry), a.accountId);
  db.exec('UPDATE meta SET last_ms=last_ms+120000');
  assert.ok(committed.occurredAt < retry.issuedAt);
  assert.deepEqual(validate(), { fresh: false, accounts: 1, events: 1, invitations: 0 });
  // A later receipt never permits a different registration to claim that event.
  db.prepare('UPDATE accounts SET registration_id=? WHERE account_id=?').run(randomUUID(), a.accountId);
  rejects(validate);
});

for (const [name, mutate] of [
  ['digest mismatch', (db, e) => db.prepare('UPDATE events SET digest=?').run('0'.repeat(64))],
  ['wrong deployment', (db, e) => { e.deploymentId = 'wrong-deployment'; const body = canonical(e); db.prepare('UPDATE events SET body=?,digest=?').run(body, sha(body)); }],
  ['wrong conversation', (db, e) => { e.conversationId = '9wrongRound'; const body = canonical(e); db.prepare('UPDATE events SET body=?,digest=?').run(body, sha(body)); }],
  ['wrong registration reference', (db, e) => { e.registrationId = randomUUID(); const body = canonical(e); db.prepare('UPDATE events SET body=?,digest=?').run(body, sha(body)); }],
  ['extra identity field', (db, e) => { e.email = 'private-sentinel@example.test'; const body = canonical(e); db.prepare('UPDATE events SET body=?,digest=?').run(body, sha(body)); }],
  ['noncanonical body', (db, e) => { const body = ' ' + canonical(e); db.prepare('UPDATE events SET body=?,digest=?').run(body, sha(body)); }],
  ['negative occurrence time', (db, e) => { e.occurredAt = -1; const body = canonical(e); db.prepare('UPDATE events SET body=?,digest=?').run(body, sha(body)); }],
  ['future occurrence time', (db, e) => { e.occurredAt = at / 1000 + 31; const body = canonical(e); db.prepare('UPDATE events SET body=?,digest=?').run(body, sha(body)); }],
]) test(`event rejects ${name}`, t => { const { db, validate } = fixture(t); const a = account(db); const e = event(db, a); mutate(db, e); rejects(validate); });

test('pending and approved accounts require their own matching event and applied state', t => {
  const { db, validate } = fixture(t); const a = account(db); const e = event(db, a);
  const b = account(db, 2); const other = event(db, b);
  db.prepare('UPDATE accounts SET event_id=? WHERE account_id=?').run(other.eventId, a.accountId); rejects(validate);
  db.prepare('UPDATE accounts SET event_id=? WHERE account_id=?').run(e.eventId, a.accountId);
  db.prepare('UPDATE events SET applied=0 WHERE event_id=?').run(e.eventId); rejects(validate);
});

test('v2 event without terminal account barrier is rejected instead of resuming prior approval', t => {
  const { db, validate } = fixture(t); const a = account(db); const prior = event(db, a); event(db, a, 'revoked', 0);
  db.prepare("UPDATE accounts SET state='approved',provider_state='approved',event_version=1,event_id=?").run(prior.eventId); rejects(validate);
});

test('revoked status exception cannot point at another account event', t => {
  const { db, validate } = fixture(t); const a = account(db), b = account(db, 2); const other = event(db, b, 'revoked', 0);
  db.prepare("UPDATE accounts SET state='revoked',provider_state='pending_remove',event_version=2,event_id=? WHERE account_id=?").run(other.eventId, a.accountId); rejects(validate);
});

test('unconsumed invitations require an approved current account and at most one per account', t => {
  const { db, validate } = fixture(t); const a = account(db); event(db, a); invitation(db, a); invitation(db, a, 0, 2); rejects(validate);
  db.exec('UPDATE invitations SET used=1'); assert.equal(validate().invitations, 2);
  event(db, a, 'revoked', 0); db.prepare('UPDATE invitations SET used=0 WHERE token_hash=?').run(sha('invitation-1')); rejects(validate);
});

test('invalid invitation token hash and unbounded future expiry fail', t => {
  const { db, validate } = fixture(t); const a = account(db); event(db, a); invitation(db, a);
  db.exec("UPDATE invitations SET token_hash='bad'"); rejects(validate);
  db.prepare('UPDATE invitations SET token_hash=?,expires_ms=?').run(sha('invitation-1'), at + 600001); rejects(validate);
});

test('twenty accounts and forty terminal events pass; account21 denies', t => {
  const { db, validate } = fixture(t); for (let i = 0; i < 20; i++) { const a = account(db, i); event(db, a); event(db, a, 'revoked', 1); }
  assert.deepEqual(validate(), { fresh: false, accounts: 20, events: 40, invitations: 0 }); account(db, 21); rejects(validate);
});

test('1024 retained invitations pass and row1025 denies without deleting history', t => {
  const { db, validate } = fixture(t); const a = account(db); event(db, a);
  for (let i = 0; i < 1024; i++) invitation(db, a, 1, i);
  assert.equal(validate().invitations, 1024); invitation(db, a, 1, 1025); rejects(validate);
  assert.equal(db.prepare('SELECT count(*) AS n FROM invitations').get().n, 1025);
});
