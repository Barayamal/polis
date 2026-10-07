import assert from 'node:assert/strict';
import { randomBytes, X509Certificate } from 'node:crypto';
import { createServer } from 'node:https';
import test from 'node:test';
import { createDocumentRedirectTlsLab, createRedirectTlsLab, createTwoAccountDocumentRedirectTlsLab } from './redirect-tls-lab.mjs';

const session = () => randomBytes(32).toString('base64url');

test('two-account TLS helper rejects every caller-selected configuration', async () => {
  for (const value of [undefined, null, {}, { subject: 'invented-subject-2' }, { account: 1 }]) {
    await assert.rejects(createTwoAccountDocumentRedirectTlsLab(value), /Synthetic HTTPS redirect lab rejected/u);
  }
});

test('two-account TLS helper signs exactly two distinct fixed accounts and refuses a third', async t => {
  const lab = await createTwoAccountDocumentRedirectTlsLab(); t.after(() => lab.close());
  assert.equal(lab.summary().fixedInventedAccountCount, 2);
  assert.equal(lab.summary().committedIssuerDocument, true);
  const principals = [];
  const malformed = await lab.identity.begin({ browserSessionId: session() });
  const injected = new URL(malformed.authorizationUrl); injected.searchParams.set('sub', 'invented-subject-2');
  assert.equal((await lab.request(injected.href)).status, 400);
  assert.equal(lab.summary().authorize, 0);
  for (let index = 0; index < 2; index++) {
    const browserSessionId = session(); const begin = await lab.identity.begin({ browserSessionId });
    const response = await lab.request(begin.authorizationUrl); assert.equal(response.status, 200);
    const matched = /id="continue-invented" href="([^"]+)"/u.exec(response.body); assert.ok(matched);
    const callbackUrl = matched[1].replaceAll('&amp;', '&');
    const completed = await lab.identity.complete({ browserSessionId, callbackUrl });
    assert.equal(completed.ok, true); assert.equal(lab.identity.isVerifiedPrincipal(completed.principal), true);
    assert.equal(completed.principal.eligibilityVerified, false); principals.push(completed.principal);
  }
  assert.notEqual(principals[0].accountId, principals[1].accountId);
  const third = await lab.identity.begin({ browserSessionId: session() });
  assert.equal((await lab.request(third.authorizationUrl)).status, 400);
  assert.equal(lab.summary().authorize, 2); assert.equal(lab.summary().token, 2);
  assert.equal(lab.summary().rejectedIssuerRequests, 2);
  await lab.close(); assert.equal(lab.summary().listenersClosed, true);
});

test('redirect TLS helper rejects caller-selected configuration', async () => {
  for (const options of [{}, { issuer: 'https://example.com/' }, null, undefined]) {
    await assert.rejects(createRedirectTlsLab(options), /Synthetic HTTPS redirect lab rejected/u);
  }
});

test('committed-document TLS helper rejects all caller-selected configuration', async () => {
  for (const options of [{}, { issuer: 'https://example.com/' }, { mode: 'redirect' },
    { claims: {} }, { callbackUri: 'https://example.com/' }, null, undefined]) {
    await assert.rejects(createDocumentRedirectTlsLab(options), /Synthetic HTTPS redirect lab rejected/u);
  }
  await assert.rejects(createDocumentRedirectTlsLab(undefined, undefined), /Synthetic HTTPS redirect lab rejected/u);
});

test('committed issuer document provides one escaped fixed callback link and completes the real TLS protocol', async (t) => {
  const lab = await createDocumentRedirectTlsLab();
  t.after(() => lab.close());
  const browserSessionId = session();
  const start = await lab.identity.begin({ browserSessionId });
  assert.equal(start.ok, true);
  const response = await lab.request(start.authorizationUrl);
  assert.equal(response.status, 200);
  assert.equal(response.headers.location, undefined);
  assert.equal(response.headers['set-cookie'], undefined);
  assert.equal(response.headers['content-type'], 'text/html; charset=utf-8');
  assert.equal(response.headers['cache-control'], 'no-store');
  assert.equal(response.headers['referrer-policy'], 'no-referrer');
  assert.equal(response.headers['x-content-type-options'], 'nosniff');
  assert.equal(response.headers['content-security-policy'],
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
  assert.match(response.body, /<title>Invented sign-in — local test only<\/title>/u);
  assert.match(response.body, /No real identity or heritage verification/u);
  assert.doesNotMatch(response.body, /<(?:script|form|input|iframe|base|link)\b/iu);
  const links = [...response.body.matchAll(/<a id="continue-invented" href="([^"]+)">Continue invented sign-in<\/a>/gu)];
  assert.equal(links.length, 1);
  assert.equal((response.body.match(/\bhref=/gu) ?? []).length, 1);
  const escaped = links[0][1];
  assert.match(escaped, /&amp;state=/u); assert.match(escaped, /&amp;iss=/u);
  assert.doesNotMatch(escaped, /&(?!amp;)/u);
  const callback = new URL(escaped.replaceAll('&amp;', '&'));
  assert.equal(callback.origin + callback.pathname, lab.callbackUri);
  assert.deepEqual([...callback.searchParams.keys()].sort(), ['code', 'iss', 'state']);
  assert.equal(callback.searchParams.get('state'), new URL(start.authorizationUrl).searchParams.get('state'));
  assert.equal(callback.searchParams.get('iss'), new URL('/', lab.authorizationEndpoint).href);
  assert.equal(lab.summary().authorize, 1);
  assert.equal(lab.summary().committedIssuerDocument, true);
  assert.equal(lab.summary().token, 0); assert.equal(lab.summary().jwks, 0);
  const result = await lab.identity.complete({ browserSessionId, callbackUrl: callback.href });
  assert.equal(result.ok, true);
  assert.equal(lab.identity.isVerifiedPrincipal(result.principal), true);
  assert.equal(result.principal.eligibilityVerified, false);
  assert.equal(lab.summary().token, 1); assert.equal(lab.summary().jwks, 1);
  assert.equal(lab.summary().tlsAuthorized, 3);
  assert.equal((await lab.identity.complete({ browserSessionId, callbackUrl: callback.href })).ok, false);
  assert.equal(lab.summary().token, 1);
  await lab.close();
  assert.equal(lab.summary().listenersClosed, true);
  await assert.rejects(lab.request(start.authorizationUrl));
});

test('document mode preserves fixed scope, rejects injected claims/targets and copies public certificates', async (t) => {
  const lab = await createDocumentRedirectTlsLab();
  t.after(() => lab.close());
  for (const [key, value] of [['email_verified', 'true'], ['claims', '{}'],
    ['redirect_uri', 'https://example.com/'], ['state', '<script>'], ['returnTo', 'https://example.com/']]) {
    const start = await lab.identity.begin({ browserSessionId: session() });
    const url = new URL(start.authorizationUrl); url.searchParams.set(key, value);
    const response = await lab.request(url.href);
    assert.equal(response.status, 400); assert.equal(response.body, '{}');
    assert.equal(response.headers.location, undefined);
  }
  assert.equal(lab.summary().authorize, 0);
  await assert.rejects(lab.request(new URL('/continue', lab.authorizationEndpoint)));
  const copies = lab.publicTestCertificates();
  const expected = copies.map((cert) => Buffer.from(cert));
  copies.forEach((cert) => cert.fill(0));
  assert.deepEqual(lab.publicTestCertificates(), expected);
  assert.deepEqual(expected.map((cert) => new X509Certificate(cert).subjectAltName),
    ['DNS:browser.example.invalid', 'DNS:identity.issuer.invalid']);
  assert.equal(lab.summary().realBrowserEngineTested, false);
});

test('redirect TLS lab uses actual verified loopback HTTPS with fixed invented identity', async (t) => {
  const lab = await createRedirectTlsLab();
  t.after(() => lab.close());

  await t.test('fixed logical origins are distinct with explicit synthetic app TLS configuration', () => {
    assert.equal(new URL(lab.authorizationEndpoint).hostname, 'identity.issuer.invalid');
    assert.equal(new URL(lab.browserTls.origin).hostname, 'browser.example.invalid');
    assert.notEqual(new URL(lab.authorizationEndpoint).port, String(lab.browserPort));
    assert.equal(lab.callbackUri, `${lab.browserTls.origin}/oidc/callback`);
    assert.equal(lab.browserTls.mode, 'SYNTHETIC_HTTPS_REDIRECT');
    assert.ok(Buffer.isBuffer(lab.browserTls.key));
    assert.ok(Buffer.isBuffer(lab.browserTls.cert));
    assert.equal(lab.driver, undefined);
    assert.equal(lab.authorizationResponse, undefined);
    assert.equal(lab.injectTestResponse, undefined);
  });

  await t.test('authorization endpoint sends exact callback redirect without following it', async () => {
    const browserSessionId = session();
    const start = await lab.identity.begin({ browserSessionId });
    assert.equal(start.ok, true);
    const response = await lab.request(start.authorizationUrl);
    assert.equal(response.status, 303);
    assert.equal(response.body, '');
    assert.equal(response.headers['cache-control'], 'no-store');
    assert.equal(response.headers['referrer-policy'], 'no-referrer');
    const callback = new URL(response.headers.location);
    assert.equal(callback.origin + callback.pathname, lab.callbackUri);
    assert.deepEqual([...callback.searchParams.keys()].sort(), ['code', 'iss', 'state']);
    assert.equal(lab.summary().token, 0);
    assert.equal(lab.summary().jwks, 0);
    const completed = await lab.identity.complete({ browserSessionId, callbackUrl: callback.href });
    assert.equal(completed.ok, true);
    assert.equal(lab.identity.isVerifiedPrincipal(completed.principal), true);
    assert.equal(completed.principal.emailVerifiedByIssuer, true);
    assert.equal(completed.principal.eligibilityVerified, false);
    assert.equal(lab.summary().authorize, 1);
    assert.equal(lab.summary().token, 1);
    assert.equal(lab.summary().jwks, 1);
    assert.equal(lab.summary().tlsAuthorized, 3);
    assert.equal((await lab.identity.complete({ browserSessionId, callbackUrl: callback.href })).ok, false);
  });

  await t.test('profile-trust input contains only two public certificates and defensive copies', () => {
    const first = lab.publicTestCertificates();
    assert.equal(first.length, 2);
    assert.deepEqual(first.map(cert => new X509Certificate(cert).subjectAltName),
      ['DNS:browser.example.invalid', 'DNS:identity.issuer.invalid']);
    assert.ok(first.every(cert => Buffer.isBuffer(cert) && !cert.toString().includes('PRIVATE KEY')));
    const expected = first.map(cert => Buffer.from(cert));
    first.forEach(cert => cert.fill(0)); first.pop();
    assert.deepEqual(lab.publicTestCertificates(), expected);
    assert.deepEqual(lab.browserTls.cert, expected[0]);
  });

  for (const name of ['claims', 'sub', 'email_verified', 'request_uri', 'returnTo']) {
    await t.test(`issuer rejects arbitrary ${name} authorization input`, async () => {
      const start = await lab.identity.begin({ browserSessionId: session() });
      const url = new URL(start.authorizationUrl); url.searchParams.set(name, 'invented-value');
      const response = await lab.request(url.href);
      assert.equal(response.status, 400); assert.equal(response.headers.location, undefined);
      assert.equal(response.body, '{}');
    });
  }

  await t.test('issuer rejects duplicate state and unbound redirect target', async () => {
    for (const mutate of [
      (url) => url.searchParams.append('state', session()),
      (url) => url.searchParams.set('redirect_uri', 'https://outside.example.invalid/oidc/callback'),
    ]) {
      const start = await lab.identity.begin({ browserSessionId: session() });
      const url = new URL(start.authorizationUrl); mutate(url);
      assert.equal((await lab.request(url.href)).status, 400);
    }
  });

  for (const [name, target] of [
    ['remote origin', () => 'https://example.com/'],
    ['loopback IP origin', () => `https://127.0.0.1:${lab.browserPort}/`],
    ['wrong port', () => 'https://browser.example.invalid:1/'],
    ['app unknown path', () => `${lab.browserTls.origin}/unknown`],
    ['issuer unknown path', () => new URL('/unknown', lab.authorizationEndpoint).href],
    ['app API query', () => `${lab.browserTls.origin}/api/session?unexpected=1`],
    ['issuer token query', () => new URL('/token?unexpected=1', lab.authorizationEndpoint).href],
    ['fragment', () => `${lab.browserTls.origin}/#secret`],
    ['credentials', () => `https://user:pass@browser.example.invalid:${lab.browserPort}/`],
    ['HTTP', () => lab.browserTls.origin.replace('https:', 'http:') + '/'],
    ['normalized traversal', () => `${lab.browserTls.origin}/unknown/../`],
  ]) {
    await t.test(`adapter rejects ${name} before opening a socket`, async () => {
      const before = lab.summary().clientRequests;
      await assert.rejects(lab.request(target()), /Synthetic HTTPS redirect lab rejected/u);
      assert.equal(lab.summary().clientRequests, before);
    });
  }

  await t.test('adapter rejects caller-supplied routing headers and unsupported body modes', async () => {
    for (const options of [{ headers: { host: 'example.com' } }, { redirect: 'follow' },
      { method: 'TRACE' }, { method: 'GET', body: 'data' }, { method: 'POST', body: {} }]) {
      await assert.rejects(lab.request(lab.browserTls.origin + '/', options));
    }
  });

  await t.test('app certificate verifies separately and Set-Cookie arrays remain separate', async () => {
    const app = createServer({ key: lab.browserTls.key, cert: lab.browserTls.cert, minVersion: 'TLSv1.2' }, (req, res) => {
      assert.equal(req.headers.host, new URL(lab.browserTls.origin).host);
      res.writeHead(303, { location: '/', 'set-cookie': [
        '__Host-invented-a=one; Path=/; Secure; HttpOnly; SameSite=Lax',
        '__Host-invented-b=two; Path=/; Secure; HttpOnly; SameSite=Strict',
      ] }); res.end('');
    });
    await new Promise((resolve, reject) => { app.once('error', reject); app.listen(lab.browserPort, '127.0.0.1', resolve); });
    try {
      const result = await lab.request(`${lab.browserTls.origin}/`);
      assert.equal(result.status, 303); assert.equal(result.headers.location, '/');
      assert.equal(result.headers['set-cookie'].length, 2);
      assert.ok(result.headers['set-cookie'].every((value) => value.includes('Secure')));
    } finally { await new Promise((resolve, reject) => app.close((error) => error ? reject(error) : resolve())); }
  });

  await t.test('summary is aggregate-only and never claims rendered browser or production verification', () => {
    const summary = lab.summary();
    assert.equal(summary.actualLoopbackTls, true);
    assert.equal(summary.logicalEndpointInterception, true);
    assert.equal(summary.realIdentityProvider, false);
    assert.equal(summary.realBrowserEngineTested, false);
    assert.equal(summary.globalTrustChanged, false);
    assert.equal(summary.productionReady, false);
    assert.ok(Object.entries(summary).every(([key, value]) =>
      !/cookie|code|tokenvalue|secret|privatekey|certificate|url/iu.test(key)
      && ['number', 'boolean'].includes(typeof value) || key === 'mode'));
  });

  await t.test('close is idempotent and rejects subsequent requests', async () => {
    assert.equal(lab.close(), lab.close()); await lab.close();
    assert.equal(lab.summary().listenersClosed, true);
    await assert.rejects(lab.request(lab.authorizationEndpoint));
  });
});
