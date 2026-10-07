import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import { createSyntheticBrowserDriver } from './synthetic-browser-driver.mjs';
import { createSyntheticTlsLab } from './synthetic-tls-lab.mjs';

const denied = { ok: false, error: 'authentication_failed' };
const binding = () => randomBytes(32).toString('base64url');
async function lab(t, options) {
  const h = await createSyntheticTlsLab(options);
  t.after(async () => { await h.close(); assert.equal(h.summary().listenersClosed, true); });
  return h;
}

test('actual token and JWKS bytes cross certificate-verified loopback HTTPS under synthetic interception', async (t) => {
  const h = await lab(t);
  const result = await h.authenticate();
  assert.equal(result.ok, true);
  assert.equal(h.identity.isVerifiedPrincipal(result.principal), true);
  assert.equal(result.principal.eligibilityVerified, false);
  assert.equal(h.identity.publicResult(result).productionReady, false);
  assert.deepEqual({ token: h.summary().token, jwks: h.summary().jwks, authorized: h.summary().tlsAuthorized },
    { token: 1, jwks: 1, authorized: 2 });
  assert.equal(h.summary().unexpected, 0);
  assert.doesNotMatch(JSON.stringify(h.summary()), /BEGIN|nonce|invented-subject|access.token|acct_|code_verifier/iu);
});

for (const [name, options] of [['wrong trust anchor', { trust: 'wrong-ca' }],
  ['certificate SAN mismatch', { certificate: 'wrong-san' }]]) {
  test(`${name} fails before a token HTTP request reaches the server`, async (t) => {
    const h = await lab(t, options);
    assert.deepEqual(await h.authenticate(), denied);
    assert.equal(h.summary().token, 0); assert.equal(h.summary().jwks, 0);
    assert.equal(h.summary().tlsAuthorized, 0); assert.equal(h.summary().clientRequests, 1);
  });
}

for (const endpoint of ['token', 'jwks']) {
  for (const behavior of ['redirect', 'slow-headers', 'stalled-body', 'oversized', 'wrong-content-type', 'truncated']) {
    test(`${endpoint} ${behavior} fails closed over actual TLS without retry or redirect follow`, async (t) => {
      const h = await lab(t, { behavior, faultEndpoint: endpoint, timeoutMs: 100 });
      const start = Date.now();
      assert.deepEqual(await h.authenticate(), denied);
      assert.ok(Date.now() - start < 2000);
      assert.equal(h.summary().token, 1);
      assert.equal(h.summary().jwks, endpoint === 'jwks' ? 1 : 0);
      assert.equal(h.summary().clientRequests, endpoint === 'jwks' ? 2 : 1);
      assert.equal(h.summary().unexpected, 0);
    });
  }
}

test('actual TLS callback is one-use and concurrent completion makes one token request', async (t) => {
  const h = await lab(t); const browserSessionId = binding();
  const start = await h.identity.begin({ browserSessionId });
  const callbackUrl = h.authorizationResponse(start.authorizationUrl);
  const results = await Promise.all([h.identity.complete({ browserSessionId, callbackUrl }),
    h.identity.complete({ browserSessionId, callbackUrl })]);
  assert.equal(results.filter((result) => result.ok).length, 1);
  assert.deepEqual(await h.identity.complete({ browserSessionId, callbackUrl }), denied);
  assert.equal(h.summary().token, 1);
});

test('swapped code fails PKCE over TLS and cannot be redeemed after its failed exchange', async (t) => {
  const h = await lab(t); const a = binding(); const b = binding();
  const startA = await h.identity.begin({ browserSessionId: a });
  const startB = await h.identity.begin({ browserSessionId: b });
  const callbackA = new URL(h.authorizationResponse(startA.authorizationUrl));
  const callbackB = h.authorizationResponse(startB.authorizationUrl);
  callbackA.searchParams.set('code', new URL(callbackB).searchParams.get('code'));
  assert.deepEqual(await h.identity.complete({ browserSessionId: a, callbackUrl: callbackA.href }), denied);
  assert.deepEqual(await h.identity.complete({ browserSessionId: b, callbackUrl: callbackB }), denied);
  assert.equal(h.summary().token, 2); assert.equal(h.summary().jwks, 0);
});

test('unchanged synthetic browser driver accepts the exact invented callback with TLS token/JWKS exchange', async (t) => {
  const h = await lab(t);
  const driver = createSyntheticBrowserDriver({ mode: 'SYNTHETIC_ONLY', identity: h.identity,
    syntheticAuthorizationResponse: h.authorizationResponse });
  const browserSessionId = binding();
  assert.deepEqual(await driver.begin({ browserSessionId }), { ok: true });
  const response = await driver.injectTestResponse({ browserSessionId,
    syntheticSubject: 'synthetic_tls_participant', emailVerifiedByIssuer: true });
  const result = await driver.complete({ browserSessionId, callbackUrl: response.callback.callbackUrl });
  assert.equal(result.ok, true); assert.equal(driver.isVerifiedPrincipal(result.principal), true);
  assert.deepEqual(await driver.complete({ browserSessionId, callbackUrl: response.callback.callbackUrl }), denied);
  assert.equal(h.summary().token, 1); assert.equal(h.summary().jwks, 1);
  assert.equal(h.summary().browserRedirectTested, false);
});

test('transport rejects external destinations, aliases, ambient headers and unsafe request modes before sockets', async (t) => {
  const h = await lab(t);
  for (const [url, init] of [
    ['https://real-provider.example/token', { method: 'POST', body: '' }],
    ['https://identity.example.invalid:443/token', { method: 'POST', body: '' }],
    ['https://identity.example.invalid/token?next=1', { method: 'POST', body: '' }],
    ['http://127.0.0.1/token', { method: 'POST', body: '' }],
    ['https://identity.example.invalid/jwks', { method: 'POST', body: '' }],
    ['https://identity.example.invalid/jwks', { headers: { cookie: 'never-forward' } }],
    ['https://identity.example.invalid/jwks', { redirect: 'follow' }],
    ['https://identity.example.invalid/jwks', { credentials: 'include' }],
  ]) await assert.rejects(h.transport.fetch(url, { redirect: 'error', credentials: 'omit', ...init }),
    { message: 'Synthetic loopback TLS transport rejected.' });
  assert.equal(h.summary().clientRequests, 0);
});

test('caller abort cancels a stalled TLS body without an automatic retry', async (t) => {
  const h = await lab(t, { behavior: 'stalled-body', faultEndpoint: 'jwks', timeoutMs: 1000 });
  const controller = new AbortController();
  const pending = h.transport.fetch('https://identity.example.invalid/jwks',
    { redirect: 'error', credentials: 'omit', signal: controller.signal });
  const timer = setTimeout(() => controller.abort(), 30);
  try { await assert.rejects(pending, { message: 'Synthetic loopback TLS transport rejected.' }); }
  finally { clearTimeout(timer); }
  assert.equal(h.summary().clientRequests, 1);
});

test('closed lab rejects reuse and independently verifies the listener is gone', async (t) => {
  const h = await lab(t); await h.close(); await h.close();
  assert.equal(h.summary().listenersClosed, true);
  assert.deepEqual(await h.authenticate(), denied);
  assert.equal(h.summary().clientRequests, 0);
});

test('configuration cannot select an external host, key, CA, port or unbounded timeout', async () => {
  for (const options of [{ host: 'example.org' }, { port: 443 }, { ca: 'caller' }, { key: 'caller' },
    { timeoutMs: 0 }, { timeoutMs: 2001 }, { certificate: 'caller' }, { trust: 'none' },
    { behavior: 'caller' }, { faultEndpoint: 'authorize' }, Object.create(null)]) {
    await assert.rejects(createSyntheticTlsLab(options), { message: 'Synthetic loopback TLS transport rejected.' });
  }
});
