import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, createHmac } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { request as httpRequest } from 'node:http';
import { createWordPressEventGate, validEvent, ROUND } from './wordpress-events.mjs';
import { createWordPressReceiver } from './wordpress-receiver.mjs';
class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
const event = (extra = {}) => ({ schema_version: 1, event_id: randomUUID(), subject: 'synthetic_alice',
  round_id: ROUND, version: 1, state: 'approved', occurred_at: '2026-09-13T02:30:00Z', ...extra });
function model(t, apply = async () => {}) {
  const db = new DatabaseSync(':memory:'); db.exec('PRAGMA foreign_keys=ON; CREATE TABLE fixtures (id TEXT PRIMARY KEY);');
  db.prepare('INSERT INTO fixtures VALUES(?)').run('synthetic_alice'); t.after(() => db.close());
  return { db, gate: createWordPressEventGate({ db, apply, HttpError }) };
}
test('event schema rejects real subjects, unexpected fields, dates, rounds and noninteger versions', () => {
  assert.equal(validEvent(event()), true);
  for (const extra of [{ subject: 'alice@barayamal.com' }, { subject: 33 }, { round_id: 'live' }, { version: 1.2 },
    { version: 0 }, { occurred_at: '2026-02-31T00:00:00Z' }, { email: 'fixture@example.test' }, { state: 'pending' }]) assert.ok(!validEvent(event(extra)));
});
test('identical retry is idempotent, changed ID/version payload conflicts; reordered JSON accepted', async (t) => {
  let applies = 0; const { gate } = model(t, async () => { applies++; }); const value = event();
  assert.equal((await gate.ingest(value)).outcome, 'APPLIED');
  assert.equal((await gate.ingest(Object.fromEntries(Object.entries(value).reverse()))).outcome, 'IDEMPOTENT_NO_OP');
  assert.equal(applies, 1);
  await assert.rejects(gate.ingest({ ...value, state: 'revoked' }), (e) => e.status === 409);
  await assert.rejects(gate.ingest({ ...value, event_id: randomUUID() }), (e) => e.status === 409);
});
test('pending failure is durable and denies access until exact retry applies', async (t) => {
  let failed = true; const apply = async () => { if (failed) throw new Error('provider failure'); };
  const { gate, db } = model(t, apply); const value = event();
  await assert.rejects(gate.ingest(value)); assert.throws(() => gate.assertCurrent(value.subject));
  const restarted = createWordPressEventGate({ db, apply, HttpError });
  assert.throws(() => restarted.assertCurrent(value.subject)); failed = false;
  await restarted.ingest(value); assert.doesNotThrow(() => restarted.assertCurrent(value.subject));
});
test('revocation denies before provider completion; failed removal and stale approve cannot restore access', async (t) => {
  let gate; const result = model(t, async (value) => { if (value.state === 'revoked') { assert.throws(() => gate.assertCurrent(value.subject)); throw new Error('offline'); } }); gate = result.gate;
  const first = event(); await gate.ingest(first); const revoke = event({ version: 2, state: 'revoked' });
  await assert.rejects(gate.ingest(revoke)); assert.throws(() => gate.assertCurrent(first.subject));
  assert.equal((await gate.ingest(first)).outcome, 'STALE_NO_OP');
  await assert.rejects(gate.ingest(event({ version: 3 })), (e) => e.status === 409);
  assert.throws(() => gate.assertNotRevoked(first.subject));
});
test('unknown fixture rejected; revocation before approval stays terminal', async (t) => {
  const { gate } = model(t); await assert.rejects(gate.ingest(event({ subject: 'synthetic_unknown' })), (e) => e.status === 409);
  await gate.ingest(event({ version: 2, state: 'revoked' }));
  assert.equal((await gate.ingest(event())).outcome, 'STALE_NO_OP');
  assert.throws(() => gate.assertCurrent('synthetic_alice'));
});
test('20-subject synthetic cap does not prevent existing-subject revocation', async (t) => {
  const { gate, db } = model(t);
  for (let i = 0; i < 21; i++) {
    const subject = 'synthetic_fixture_' + i; db.prepare('INSERT INTO fixtures VALUES(?)').run(subject);
    if (i < 20) await gate.ingest(event({ subject })); else await assert.rejects(gate.ingest(event({ subject })), (e) => e.status === 409);
  }
  await gate.ingest(event({ subject: 'synthetic_fixture_0', version: 2, state: 'revoked' }));
});
test('full regular journal reserves terminal revocation; repeated terminal versions do not grow storage', async (t) => {
  const { gate, db } = model(t);
  for (let version = 1; version <= 200; version++) await gate.ingest(event({ version }));
  await assert.rejects(gate.ingest(event({ version: 201 })), (e) => e.status === 409);
  await gate.ingest(event({ version: 201, state: 'revoked' }));
  assert.throws(() => gate.assertCurrent('synthetic_alice'));
  assert.equal((await gate.ingest(event({ version: 202, state: 'revoked' }))).outcome, 'TERMINAL_NO_OP');
  assert.equal(db.prepare('SELECT count(*) AS n FROM wordpress_events').get().n, 201);
});
test('200 ordinary events across 20 subjects reserve all 20 terminal revocations and stop at 220 rows', async (t) => {
  const { gate, db } = model(t);
  const subjects = Array.from({ length: 20 }, (_, index) => 'synthetic_capacity_' + index);
  const staleApprovals = new Map();
  for (const subject of subjects) {
    db.prepare('INSERT INTO fixtures VALUES(?)').run(subject);
    for (let version = 1; version <= 10; version++) {
      const approval = event({ subject, version });
      await gate.ingest(approval);
      if (version === 9) staleApprovals.set(subject, approval);
    }
  }
  assert.equal(db.prepare('SELECT count(*) AS n FROM wordpress_events').get().n, 200);
  await assert.rejects(gate.ingest(event({ subject: subjects[0], version: 11 })), (e) => e.status === 409);
  for (const subject of subjects) {
    assert.equal((await gate.ingest(event({ subject, version: 11, state: 'revoked' }))).outcome, 'APPLIED');
    assert.throws(() => gate.assertCurrent(subject), (e) => e.status === 403);
    assert.throws(() => gate.assertNotRevoked(subject), (e) => e.status === 409);
  }
  assert.equal(db.prepare('SELECT count(*) AS n FROM wordpress_events').get().n, 220);
  for (const subject of subjects) {
    assert.equal((await gate.ingest(event({ subject, version: 12, state: 'revoked' }))).outcome, 'TERMINAL_NO_OP');
    assert.equal((await gate.ingest(staleApprovals.get(subject))).outcome, 'STALE_NO_OP');
    await assert.rejects(gate.ingest(event({ subject, version: 12 })), (e) => e.status === 409);
    assert.throws(() => gate.assertCurrent(subject), (e) => e.status === 403);
  }
  assert.equal(db.prepare('SELECT count(*) AS n FROM wordpress_events').get().n, 220);
});

const secret = 'synthetic_wordpress_receiver_key_'.repeat(3);
async function receiver(t) {
  const values = []; const time = Date.parse('2026-09-13T02:30:00Z');
  const app = createWordPressReceiver({ mode: 'fixture-only', secret, now: () => time,
    ingest: async (value) => { values.push(value); return { ok: true, event_id: value.event_id, version: value.version }; } });
  const origin = await app.listen(0); t.after(() => app.close());
  const request = async ({ value = event(), raw, stamp = String(time / 1000), headers = {}, path = '/internal/wordpress/events' } = {}) => {
    raw ??= JSON.stringify(value);
    const response = await fetch(origin + path, { method: 'POST', headers: { 'Content-Type': 'application/json',
      'X-FNCP-WP-Timestamp': stamp, 'X-FNCP-WP-Event-ID': value.event_id,
      'X-FNCP-WP-Signature': 'sha256=' + createHmac('sha256', secret).update(stamp + '.').update(raw).digest('hex'), ...headers }, body: raw });
    return { status: response.status, body: await response.json() };
  };
  return { request, values, time, wrongHost: () => new Promise((resolve, reject) => {
    const req = httpRequest(origin + '/internal/wordpress/events', { method: 'POST', headers: { Host: 'attacker.test' } }, (res) => {
      res.resume(); res.on('end', () => resolve(res.statusCode));
    }); req.on('error', reject); req.end();
  }) };
}
test('receiver verifies exact raw-body HMAC and matching event ACK', async (t) => {
  const h = await receiver(t); const value = event(); const response = await h.request({ value });
  assert.equal(response.status, 200); assert.equal(response.body.event_id, value.event_id); assert.equal(h.values.length, 1);
});
test('receiver refuses stale/future signatures, tampered body and mismatched IDs', async (t) => {
  const h = await receiver(t);
  assert.equal((await h.request({ stamp: String(h.time / 1000 - 301) })).status, 401);
  assert.equal((await h.request({ stamp: String(h.time / 1000 + 301) })).status, 401);
  assert.equal((await h.request({ headers: { 'X-FNCP-WP-Signature': 'sha256=' + '0'.repeat(64) } })).status, 401);
  assert.equal((await h.request({ headers: { 'X-FNCP-WP-Event-ID': randomUUID() } })).status, 400);
  assert.equal(h.values.length, 0);
});
test('receiver rejects browsers, cookies, authorization, wrong host, path and content type', async (t) => {
  const h = await receiver(t);
  for (const headers of [{ Origin: 'http://127.0.0.1:8102' }, { Cookie: 'bad=1' }, { Authorization: 'Bearer bad' },
    { 'Sec-Fetch-Site': 'same-origin' }]) assert.equal((await h.request({ headers })).status, 403);
  assert.equal(await h.wrongHost(), 403);
  assert.equal((await h.request({ path: '/internal/wordpress/events?extra=1' })).status, 403);
  assert.equal((await h.request({ headers: { 'Content-Type': 'text/plain' } })).status, 415);
  assert.equal(h.values.length, 0);
});
test('receiver enforces event shape and size limit before side effects', async (t) => {
  const h = await receiver(t);
  assert.equal((await h.request({ value: event({ email: 'synthetic@example.test' }) })).status, 400);
  assert.equal((await h.request({ raw: ' '.repeat(4097) })).status, 413);
  assert.equal(h.values.length, 0);
});
