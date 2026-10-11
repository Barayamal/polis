import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import test from 'node:test';
import { createOidcHttpsTransport } from './https-transport.mjs';
import { createTestIssuer } from './test-support/https-issuer.mjs';

const denied = { ok: false, error: 'authentication_failed' };
const fixture = async (t, options) => { const h = await createTestIssuer(options); t.after(() => h.close()); return h; };
const transportFor = (t, h, timeoutMs = 1000) => {
  const transport = createOidcHttpsTransport({ tokenEndpoint: h.options.tokenEndpoint,
    jwksUri: h.options.jwksUri, ca: h.options.ca, timeoutMs });
  t.after(() => transport.close()); return transport;
};

test('verified HTTPS succeeds without global fetch and returns only required response headers', async t => {
  const h = await fixture(t); const transport = transportFor(t, h);
  const oldFetch = globalThis.fetch;
  try {
    globalThis.fetch = () => { throw new Error('Global fetch must not be used.'); };
    const response = await transport.fetch(h.options.jwksUri, { method: 'GET' });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).keys.length, 1);
    assert.deepEqual([...response.headers.keys()], ['content-type']);
    assert.equal((await h.authenticate()).ok, true);
  } finally { globalThis.fetch = oldFetch; }
});

for (const [name, options] of [['wrong CA', { wrongCa: true }], ['wrong certificate hostname', { wrongHost: true }]]) {
  test(`${name} is rejected by native TLS before any HTTP endpoint is reached`, async t => {
    const h = await fixture(t, options);
    assert.deepEqual(await h.authenticate(), denied);
    assert.equal(h.calls.length, 0);
  });
}

test('custom private CA is not silently trusted when CA configuration is absent', async t => {
  const h = await fixture(t); const untrusted = h.createAdapter({ ca: undefined });
  assert.deepEqual(await h.authenticate({}, untrusted), denied);
  assert.equal(h.calls.length, 0);
});

test('NODE_TLS_REJECT_UNAUTHORIZED cannot disable the explicit verifier', async t => {
  const h = await fixture(t, { wrongCa: true });
  const previous = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  try {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    assert.deepEqual(await h.authenticate(), denied);
    assert.equal(h.calls.length, 0);
  } finally {
    if (previous === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    else process.env.NODE_TLS_REJECT_UNAUTHORIZED = previous;
  }
});

test('fixed endpoint/method/header rules deny arbitrary routes and ambient credentials', async t => {
  const h = await fixture(t); const transport = transportFor(t, h);
  for (const [url, init] of [
    [h.options.jwksUri + '?unexpected=1', {}], [h.options.authorizationEndpoint, {}],
    [h.options.jwksUri, { method: 'POST' }], [h.options.tokenEndpoint, { method: 'GET' }],
    [h.options.jwksUri, { headers: { cookie: 'untrusted=secret' } }],
    [h.options.jwksUri, { headers: { authorization: 'Bearer secret' } }],
    [h.options.jwksUri, { headers: { host: 'elsewhere.invalid' } }],
    [h.options.tokenEndpoint, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' }],
    [h.options.tokenEndpoint, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'x'.repeat(16_385) }],
  ]) await assert.rejects(transport.fetch(url, init), { message: 'OIDC transport unavailable.' });
  assert.equal(h.calls.length, 0);
});

for (const behavior of ['redirect', 'oversized', 'wrong-content-type', 'compressed', 'truncated']) {
  test(`transport rejects ${behavior} responses and never follows a redirect`, async t => {
    const h = await fixture(t); const transport = transportFor(t, h); h.setBehavior(behavior);
    await assert.rejects(transport.fetch(h.options.jwksUri), { message: 'OIDC transport unavailable.' });
    assert.deepEqual(h.calls.map(call => call.endpoint), ['jwks']);
  });
}

for (const behavior of ['slow-headers', 'stalled-body']) {
  test(`one deadline bounds ${behavior}, including the complete response body`, async t => {
    const h = await fixture(t); const transport = transportFor(t, h, 120); h.setBehavior(behavior);
    const start = performance.now();
    await assert.rejects(transport.fetch(h.options.jwksUri), { message: 'OIDC transport unavailable.' });
    assert.ok(performance.now() - start < 1000);
    assert.equal(h.calls.length, 1);
  });
}

test('abort and close terminate admitted HTTPS work; a closed transport cannot reopen', async t => {
  const h = await fixture(t); const transport = transportFor(t, h); h.setBehavior('stalled-body');
  const controller = new AbortController();
  const operation = transport.fetch(h.options.jwksUri, { signal: controller.signal });
  const rejection = assert.rejects(operation, { message: 'OIDC transport unavailable.' });
  controller.abort(); await rejection;
  const pending = transport.fetch(h.options.jwksUri);
  const closedRejection = assert.rejects(pending, { message: 'OIDC transport unavailable.' });
  transport.close(); await closedRejection;
  await assert.rejects(transport.fetch(h.options.jwksUri), { message: 'OIDC transport unavailable.' });
});

test('concurrent endpoint requests are bounded before opening additional sockets', async t => {
  const h = await fixture(t); const transport = transportFor(t, h); h.setBehavior('stalled-body');
  const operations = Array.from({ length: 32 }, () => transport.fetch(h.options.jwksUri));
  const outcomes = Promise.allSettled(operations);
  await assert.rejects(transport.fetch(h.options.jwksUri), { message: 'OIDC transport unavailable.' });
  transport.close();
  assert.ok((await outcomes).every(value => value.status === 'rejected'));
  assert.ok(h.calls.length <= 32);
});
