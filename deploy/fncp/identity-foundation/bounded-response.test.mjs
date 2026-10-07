import assert from 'node:assert/strict';
import { getEventListeners } from 'node:events';
import { setTimeout as delay, setImmediate as turn } from 'node:timers/promises';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import { boundedJsonResponse } from './bounded-response.mjs';
import { createIdentityFoundation } from './identity.mjs';
import { createSyntheticIdentityHarness } from './synthetic-harness.mjs';

const endpoint = 'https://identity.example.invalid/token';
const json = (body = '{}') => new Response(body, { headers: { 'content-type': 'application/json' } });
const never = () => new Promise(() => {});
const failed = { message: 'Identity transport failed.' };
const denied = { ok: false, error: 'authentication_failed' };
const run = (transport, init = {}, budget = {}) => boundedJsonResponse(transport, endpoint, init,
  { timeoutMs: 60, ...budget });
const stream = (source) => new Response(new ReadableStream(source), {
  headers: { 'content-type': 'application/json' },
});

test('bounded response forces cookie/redirect isolation and removes caller listener on success', async () => {
  const caller = new AbortController();
  let signal;
  const response = await run((_input, init) => {
    assert.equal(init.redirect, 'error'); assert.equal(init.credentials, 'omit');
    assert.notEqual(init.signal, caller.signal); signal = init.signal;
    return json('{"safe":true}');
  }, { signal: caller.signal, redirect: 'follow', credentials: 'include' });
  assert.deepEqual(await response.json(), { safe: true });
  assert.equal(getEventListeners(caller.signal, 'abort').length, 0);
  assert.equal(getEventListeners(signal, 'abort').length, 0);
});

test('an already aborted caller never invokes transport', async () => {
  let calls = 0;
  await assert.rejects(run(() => { calls++; return json(); }, { signal: AbortSignal.abort() }), failed);
  assert.equal(calls, 0);
});

test('noncooperative transport is independently timed out and gets an aborted signal', { timeout: 2000 }, async () => {
  let signal;
  await assert.rejects(run((_input, init) => { signal = init.signal; return never(); }), failed);
  assert.equal(signal.aborted, true);
  assert.equal(getEventListeners(signal, 'abort').length, 0);
});

test('caller abort promptly fences a noncooperative transport', { timeout: 2000 }, async () => {
  const caller = new AbortController();
  let started;
  const ready = new Promise((resolve) => { started = resolve; });
  const result = run(() => { started(); return never(); }, { signal: caller.signal }, { timeoutMs: 5000 });
  await ready; caller.abort(new Error('invented-private-detail'));
  await assert.rejects(result, failed);
  assert.equal(getEventListeners(caller.signal, 'abort').length, 0);
});

for (const disposition of ['resolve', 'reject']) {
  test(`late transport ${disposition} is handled without revival or unhandled rejection`, { timeout: 2000 }, async () => {
    let finish;
    let cancelled = 0;
    const promise = new Promise((resolve, reject) => { finish = disposition === 'resolve' ? resolve : reject; });
    await assert.rejects(run(() => promise), failed);
    finish(disposition === 'resolve' ? stream({ cancel() { cancelled++; return never(); } })
      : new Error('invented-private-detail'));
    await turn();
    assert.equal(cancelled, disposition === 'resolve' ? 1 : 0);
  });
}

test('body timeout does not wait for a never-settling stream cancellation', { timeout: 2000 }, async () => {
  let cancelled = 0;
  await assert.rejects(run(() => stream({ pull: never, cancel() { cancelled++; return never(); } })), failed);
  assert.equal(cancelled, 1);
});

test('one budget covers headers and body, not a new timeout for each read', { timeout: 2000 }, async () => {
  let cancelled = 0;
  await assert.rejects(run(async () => {
    await delay(40);
    return stream({ pull: never, cancel() { cancelled++; } });
  }), failed);
  assert.equal(cancelled, 1);
});

test('synchronously available empty chunks cannot starve the deadline timer indefinitely', { timeout: 2000 }, async () => {
  let cancelled = 0;
  await assert.rejects(run(() => stream({ pull(c) { c.enqueue(new Uint8Array()); }, cancel() { cancelled++; } })), failed);
  assert.equal(cancelled, 1);
});

test('bytes are bounded and failure cancellation cannot delay rejection', { timeout: 2000 }, async () => {
  let cancelled = 0;
  await assert.rejects(run(() => stream({
    start(c) { c.enqueue(new Uint8Array(65_537)); },
    cancel() { cancelled++; return never(); },
  })), failed);
  assert.equal(cancelled, 1);
  const response = await run(() => json(' '.repeat(65_536)));
  assert.equal((await response.text()).length, 65_536);
});

test('chunk storage is copied before a producer can alter an earlier chunk', async () => {
  const chunk = new TextEncoder().encode('{"x":1}');
  let first = true;
  const body = new ReadableStream({ pull(c) {
    if (first) { first = false; c.enqueue(chunk); }
    else { chunk.fill(120); c.close(); }
  } }, { highWaterMark: 0 });
  const response = await run(() => new Response(body, { headers: { 'content-type': 'application/json' } }));
  assert.equal(await response.text(), '{"x":1}');
});

for (const [name, build] of [
  ['redirect', () => new Response('{}', { status: 302, headers: { 'content-type': 'application/json' } })],
  ['HTML', () => new Response('<html>invented</html>')],
  ['missing body', () => new Response(null, { headers: { 'content-type': 'application/json' } })],
  ['invalid stream chunk', () => stream({ start(c) { c.enqueue('not-bytes'); c.close(); } })],
  ['synchronous adapter error', () => { throw new Error('invented-private-detail'); }],
]) test(`rejects ${name} without exposing transport details`, async () => {
  await assert.rejects(run(build), failed);
});

for (const budget of [{ timeoutMs: 5001 }, { timeoutMs: 0 }, { timeoutMs: 1.5 },
  { maxBytes: 65_537 }, { maxBytes: 0 }]) {
  test(`internal response budget cannot weaken ceilings: ${JSON.stringify(budget)}`, async () => {
    let calls = 0;
    await assert.rejects(run(() => { calls++; return json(); }, {}, budget), failed);
    assert.equal(calls, 0);
  });
}

test('real identity completion independently fences stalled token/stream/JWKS and burns callback',
  { timeout: 12_000, concurrency: true }, async (t) => {
    await Promise.all(['token', 'token-body', 'jwks'].map((stage) => t.test(stage, { concurrency: true }, async () => {
      const h = await createSyntheticIdentityHarness({ signingAlgorithm: 'ES256' });
      let stalled = false;
      let release;
      let signal;
      const held = new Promise((resolve) => { release = resolve; });
      const identity = createIdentityFoundation({ ...h.options, transport: {
        kind: 'SYNTHETIC_INTERCEPT', fetch: async (input, init) => {
          const target = stage === 'jwks' ? h.options.jwksUri : h.options.tokenEndpoint;
          if (!stalled && String(input) === target) {
            stalled = true; signal = init.signal;
            if (stage === 'token-body') return stream({ pull: never, cancel: never });
            return held; // Explicitly ignores abort, unlike a cooperative fetch.
          }
          return h.options.transport.fetch(input, init);
        },
      } });
      const browserSessionId = randomBytes(32).toString('base64url');
      const start = await identity.begin({ browserSessionId });
      const callbackUrl = h.authorizationResponse(start.authorizationUrl);
      assert.deepEqual(await identity.complete({ browserSessionId, callbackUrl }), denied);
      assert.equal(stalled, true); assert.equal(signal.aborted, true);
      release(json()); await turn();
      assert.deepEqual(await identity.complete({ browserSessionId, callbackUrl }), denied);
      const next = await identity.begin({ browserSessionId });
      const recovered = await identity.complete({ browserSessionId,
        callbackUrl: h.authorizationResponse(next.authorizationUrl) });
      assert.equal(recovered.ok, true);
      assert.equal(recovered.principal.eligibilityVerified, false);
    })));
  });
