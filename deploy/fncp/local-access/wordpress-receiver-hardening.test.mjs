/** Fresh loopback and in-memory fixtures only; no WordPress/provider services. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { connect } from 'node:net';
import { createHmac, randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { createWordPressReceiver, MAX_RECEIVER_REQUESTS } from './wordpress-receiver.mjs';
import { createWordPressEventGate, ROUND } from './wordpress-events.mjs';

const secret = 'synthetic_receiver_hardening_key_'.repeat(3);
const time = Date.parse('2026-09-13T02:30:00Z');
const event = () => ({ schema_version: 1, event_id: randomUUID(), subject: 'synthetic_alice',
  round_id: ROUND, version: 1, state: 'approved', occurred_at: '2026-09-13T02:30:00Z' });
const pause = () => { let release; const promise = new Promise(resolve => { release = resolve; }); return { promise, release }; };
const turn = () => new Promise(resolve => setImmediate(resolve));

async function harness(t, options = {}) {
  const values = []; const requests = new Set(); const releases = [];
  const app = createWordPressReceiver({ mode: 'fixture-only', secret, now: () => time,
    ingest: async value => { values.push(value); return { ok: true, event_id: value.event_id, version: value.version }; }, ...options });
  const h = { app, origin: await app.listen(0), values, requests, releases };
  t.after(async () => {
    for (const release of releases) release();
    for (const request of requests) request.destroy();
    await app.close();
  });
  return h;
}

function send(h, { value = event(), raw = JSON.stringify(value), stamp = String(time / 1000), headers = {}, partial = false } = {}) {
  let ready; const arrived = new Promise(resolve => { ready = resolve; });
  let finish; const done = new Promise(resolve => { finish = resolve; });
  const req = httpRequest(h.origin + '/internal/wordpress/events', { method: 'POST', agent: false,
    headers: { 'Content-Type': 'application/json', 'X-FNCP-WP-Timestamp': stamp, 'X-FNCP-WP-Event-ID': value.event_id,
      'X-FNCP-WP-Signature': 'sha256=' + createHmac('sha256', secret).update(stamp + '.').update(raw).digest('hex'),
      ...(partial ? { Expect: '100-continue', 'Transfer-Encoding': 'chunked' } : {}), ...headers },
  }, res => {
    ready(); const chunks = [];
    res.on('data', chunk => chunks.push(chunk));
    res.on('error', () => finish({ transportError: true }));
    res.on('end', () => {
      let body; try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { body = null; }
      finish({ status: res.statusCode, body, headers: res.headers });
    });
  });
  h.requests.add(req);
  req.on('continue', () => { if (partial) req.write(raw.slice(0, 1)); ready(); });
  req.on('error', () => { ready(); finish({ transportError: true }); });
  req.on('close', () => h.requests.delete(req));
  if (partial) req.flushHeaders(); else req.end(raw);
  return { req, arrived, done, complete: () => req.end(raw.slice(1)) };
}

const invalidClocks = [
  ['NaN', NaN], ['positive infinity', Infinity], ['negative infinity', -Infinity],
  ['numeric string', String(time)], ['undefined', undefined], ['fractional milliseconds', time + 0.5],
  ['unsafe integer', Number.MAX_SAFE_INTEGER + 1], ['negative time', -1],
];
for (const [label, value] of invalidClocks) test(`receiver rejects ${label} clock before ingest`, async t => {
  const h = await harness(t, { now: () => value });
  assert.equal((await send(h).done).status, 401);
  assert.deepEqual(h.values, []);
});
test('receiver rejects a throwing clock and a nonfunction clock configuration', async t => {
  const h = await harness(t, { now: () => { throw new Error('Invented clock failure.'); } });
  assert.equal((await send(h).done).status, 401); assert.deepEqual(h.values, []);
  assert.throws(() => createWordPressReceiver({ mode: 'fixture-only', secret, ingest() {}, now: time }), /configuration/u);
});

for (const [label, shifted] of [['aged body', time + 301_000], ['clock moved backwards', time - 301_000],
  ['invalid clock', NaN], ['failed clock', null]]) {
  test(`receiver rechecks ${label} immediately before ingest after body collection`, async t => {
    const checked = pause(); let current = time;
    const h = await harness(t, { now: () => { checked.release(); if (current === null) throw new Error('Clock unavailable.'); return current; } });
    const pending = send(h, { partial: true });
    await checked.promise; await pending.arrived; current = shifted; pending.complete();
    const result = await pending.done;
    assert.equal(result.status, 401); assert.deepEqual(h.values, []);
  });
}
for (const seconds of [-300, 300]) test(`receiver accepts exact ${seconds}-second freshness boundary at both checks`, async t => {
  let clocks = 0;
  const h = await harness(t, { now: () => { clocks++; return time + seconds * 1000; } });
  assert.equal((await send(h).done).status, 200);
  assert.equal(clocks, 2); assert.equal(h.values.length, 1);
});

test('receiver bounds slow body readers before collection and recovers after an aborted body', { timeout: 10_000 }, async t => {
  const h = await harness(t); const held = [];
  for (let i = 0; i < MAX_RECEIVER_REQUESTS; i++) {
    const pending = send(h, { partial: true }); await pending.arrived; held.push(pending);
  }
  const overflow = send(h, { partial: true });
  const result = await overflow.done;
  assert.equal(result.status, 503); assert.equal(result.headers.connection, 'close');
  assert.deepEqual(result.body, { error: 'Local request capacity reached.' });
  assert.deepEqual(h.values, []);
  held[0].req.destroy();
  let recovered;
  for (let i = 0; i < 100; i++) {
    await turn(); recovered = await send(h).done;
    if (recovered.status === 200) break;
    assert.equal(recovered.status, 503);
  }
  assert.equal(recovered.status, 200); assert.equal(h.values.length, 1);
});

test('receiver bounds unsettled ingests and retains their slots after client disconnect', { timeout: 10_000 }, async t => {
  const gate = pause(); const entered = pause(); let ingests = 0;
  const h = await harness(t, { ingest: async value => {
    ingests++; if (ingests === MAX_RECEIVER_REQUESTS) entered.release(); await gate.promise;
    return { ok: true, event_id: value.event_id, version: value.version };
  } }); h.releases.push(gate.release);
  const pending = Array.from({ length: MAX_RECEIVER_REQUESTS }, () => send(h));
  await entered.promise; pending[0].req.destroy(); await pending[0].done; await turn();
  assert.equal((await send(h).done).status, 503); assert.equal(ingests, MAX_RECEIVER_REQUESTS);
  gate.release(); assert.ok((await Promise.all(pending.slice(1).map(value => value.done))).every(result => result.status === 200));
  assert.equal((await send(h).done).status, 200); assert.equal(ingests, MAX_RECEIVER_REQUESTS + 1);
});

test('receiver never ingests an aborted incomplete body and subsequent requests still work', async t => {
  const checked = pause();
  const h = await harness(t, { now: () => { checked.release(); return time; } });
  const request = send(h, { partial: true }); await checked.promise; await request.arrived;
  request.req.destroy(); await request.done; await turn();
  assert.deepEqual(h.values, []);
  assert.equal((await send(h).done).status, 200); assert.equal(h.values.length, 1);
});

test('receiver failures before ingest repeatedly release admission slots', async t => {
  const h = await harness(t);
  for (let i = 0; i <= MAX_RECEIVER_REQUESTS; i++) {
    assert.equal((await send(h, { raw: '{' }).done).status, 400);
    assert.equal((await send(h, { headers: { 'X-FNCP-WP-Signature': 'sha256=' + '0'.repeat(64) } }).done).status, 401);
  }
  assert.deepEqual(h.values, []);
  assert.equal((await send(h).done).status, 200); assert.equal(h.values.length, 1);
});

test('receiver does not claim an event was unapplied or automatically retry after ingest throws', async t => {
  let ingests = 0;
  const h = await harness(t, { ingest: async () => { ingests++; throw new Error('Invented ambiguous completion.'); } });
  const result = await send(h).done;
  assert.equal(result.status, 503);
  assert.deepEqual(result.body, { error: 'Synthetic event outcome unconfirmed; retain and retry the same event.' });
  await turn(); assert.equal(ingests, 1);
});

test('receiver does not label an applied event failed when its acknowledgement cannot serialize', async t => {
  let ingests = 0;
  const h = await harness(t, { ingest: async () => { ingests++; const ack = {}; ack.circular = ack; return ack; } });
  const result = await send(h).done;
  assert.equal(result.status, 503);
  assert.deepEqual(result.body, { error: 'Synthetic event outcome unconfirmed; retain and retry the same event.' });
  assert.equal(ingests, 1);
});

test('lost HTTP acknowledgement preserves exact-event retry with one applied in-memory gate operation', async t => {
  const db = new DatabaseSync(':memory:');
  db.exec("PRAGMA foreign_keys=ON; CREATE TABLE fixtures(id TEXT PRIMARY KEY); INSERT INTO fixtures VALUES('synthetic_alice');");
  class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
  const entered = pause(); const release = pause(); const applied = pause(); let applies = 0;
  const gate = createWordPressEventGate({ db, HttpError, apply: async () => { applies++; entered.release(); await release.promise; } });
  const h = await harness(t, { ingest: async value => { const result = await gate.ingest(value); applied.release(); return result; } });
  h.releases.push(release.release); t.after(() => db.close());
  const value = event(); const first = send(h, { value }); await entered.promise;
  first.req.destroy(); await first.done; release.release(); await applied.promise;
  const retried = await send(h, { value }).done;
  assert.equal(retried.status, 200); assert.equal(retried.body.outcome, 'IDEMPOTENT_NO_OP');
  assert.equal(retried.body.event_id, value.event_id); assert.equal(applies, 1);
  assert.equal(db.prepare('SELECT count(*) AS n FROM wordpress_events WHERE applied=1').get().n, 1);
});

test('receiver close drains an admitted disconnected ingest, is idempotent, and cannot reopen', async t => {
  const entered = pause(); const gate = pause(); let ingests = 0;
  const h = await harness(t, { ingest: async value => { ingests++; entered.release(); await gate.promise; return { ok: true, event_id: value.event_id }; } });
  h.releases.push(gate.release);
  const pending = send(h); await entered.promise; pending.req.destroy(); await pending.done;
  let closed = false;
  const firstClose = h.app.close().then(() => { closed = true; }); const secondClose = h.app.close();
  await turn(); assert.equal(closed, false);
  await assert.rejects(h.app.listen(0), /closing/u);
  assert.equal((await send(h).done).transportError, true); assert.equal(ingests, 1);
  gate.release(); await Promise.all([firstClose, secondClose]); assert.equal(closed, true);
  await h.app.close(); assert.equal(ingests, 1);
});

test('receiver can close before listening without becoming reusable', async () => {
  const app = createWordPressReceiver({ mode: 'fixture-only', secret, ingest: async () => assert.fail('No ingest expected.') });
  await Promise.all([app.close(), app.close()]);
  await assert.rejects(app.listen(0), /closing/u);
});

test('receiver refuses a new pipelined request on an admitted socket after close starts', { timeout: 10_000 }, async t => {
  const entered = pause(); const gate = pause(); let ingests = 0;
  const h = await harness(t, { ingest: async value => {
    ingests++; entered.release(); await gate.promise; return { ok: true, event_id: value.event_id };
  } }); h.releases.push(gate.release);
  const origin = new URL(h.origin); const socket = connect(Number(origin.port), '127.0.0.1');
  t.after(() => socket.destroy());
  let finish; const finished = new Promise(resolve => { finish = resolve; }); let output = '';
  socket.setEncoding('utf8'); socket.on('data', chunk => { output += chunk; });
  socket.on('end', finish); socket.on('error', finish);
  const rawRequest = () => {
    const value = event(); const raw = JSON.stringify(value); const stamp = String(time / 1000);
    const signature = 'sha256=' + createHmac('sha256', secret).update(stamp + '.').update(raw).digest('hex');
    return `POST /internal/wordpress/events HTTP/1.1\r\nHost: ${origin.host}\r\nContent-Type: application/json\r\n` +
      `Content-Length: ${Buffer.byteLength(raw)}\r\nX-FNCP-WP-Timestamp: ${stamp}\r\nX-FNCP-WP-Event-ID: ${value.event_id}\r\n` +
      `X-FNCP-WP-Signature: ${signature}\r\n\r\n${raw}`;
  };
  socket.write(rawRequest()); await entered.promise;
  const closed = h.app.close(); socket.write(rawRequest());
  await turn(); await turn(); assert.equal(ingests, 1);
  gate.release(); await Promise.all([finished, closed]);
  assert.equal(ingests, 1);
  assert.match(output, /HTTP\/1\.1 200 OK/u);
  assert.equal((output.match(/HTTP\/1\.1 200 OK/gu) ?? []).length, 1);
  assert.match(output, /Connection: close/iu);
  // The admitted reply closes the socket. Node may discard the second
  // response queued behind it; no second acknowledgement or ingest is allowed.
});
