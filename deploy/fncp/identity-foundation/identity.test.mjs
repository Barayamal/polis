import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { generateKeyPair } from 'jose';
import test from 'node:test';
import { createIdentityFoundation } from './identity.mjs';
import { createSyntheticIdentityHarness } from './synthetic-harness.mjs';

const binding = () => randomBytes(32).toString('base64url');
const denied = { ok: false, error: 'authentication_failed' };
const jsonResponse = (body, status = 200) => new Response(JSON.stringify(body), {
  status, headers: { 'content-type': 'application/json' },
});
const originalFetch = globalThis.fetch;
test.before(() => {
  globalThis.fetch = () => { throw new Error('Network is disabled in synthetic identity tests.'); };
});
test.after(() => { globalThis.fetch = originalFetch; });

test('real RS256 code+PKCE+state+nonce/JWKS flow produces only a private opaque principal', async () => {
  const h = await createSyntheticIdentityHarness();
  const result = await h.authenticate();
  assert.equal(result.ok, true);
  assert.equal(result.principal.assurance, 'OIDC_ID_TOKEN_VERIFIED');
  assert.equal(result.principal.eligibilityVerified, false);
  assert.equal(result.principal.emailVerifiedByIssuer, true);
  assert.match(result.principal.accountId, /^acct_[A-Za-z0-9_-]{43}$/u);
  assert.equal(Object.isFrozen(result.principal), true);
  assert.deepEqual(h.identity.publicResult(result), { ok: true, authenticated: true,
    mode: 'SYNTHETIC_ONLY', emailVerifiedByIssuer: true, eligibilityVerified: false, productionReady: false });
  assert.doesNotMatch(JSON.stringify(result), /invented-subject|invented@example|access-token|refresh-token|id_token|nonce|issuer/u);
  assert.doesNotMatch(JSON.stringify(h.identity.publicResult(result)), /acct_|fncp_|token|claims/u);
  assert.deepEqual(h.identity.publicResult({ ok: true, principal: { ...result.principal } }), denied);
  assert.deepEqual(h.calls.map((item) => item.endpoint), ['token', 'jwks']);
  assert.ok(h.calls.every((item) => item.redirect === 'error' && item.credentials === 'omit'));
});

test('ES256 and confidential client basic authentication are supported without returning secret', async () => {
  const h = await createSyntheticIdentityHarness({ signingAlgorithm: 'ES256', clientSecret: 'invented-private-secret' });
  const result = await h.authenticate();
  assert.equal(result.ok, true);
  assert.doesNotMatch(JSON.stringify(result), /invented-private-secret|authorization/u);
});

test('configuration rejects non-HTTPS/noncanonical/dynamic destinations and unsafe modes', async () => {
  const h = await createSyntheticIdentityHarness();
  const variants = [
    { issuer: 'http://identity.example.invalid/' },
    { tokenEndpoint: 'https://user:secret@example.invalid/token' },
    { jwksUri: 'https://identity.example.invalid/jwks?next=secret' },
    { callbackUri: 'https://participant.example.invalid/callback#secret' },
    { authorizationEndpoint: 'https://identity.example.invalid' },
    { tokenEndpoint: h.options.jwksUri }, { mode: 'PRODUCTION' }, { signingAlgorithm: 'HS256' },
    { identityKey: new Uint8Array(16) }, { transport: { kind: 'REMOTE', fetch } },
    { extra: 'invented-secret' }, { clientSecret: 'secret\nunsafe' },
    { trustedAdditionalAudiences: ['invented-client'] }, { trustedAdditionalAudiences: ['other', 'other'] },
  ];
  for (const variant of variants) assert.throws(() => createIdentityFoundation({ ...h.options, ...variant }),
    { message: 'Identity foundation configuration rejected.' });
  assert.equal(h.calls.length, 0);
});

test('begin fixes endpoints/scopes and returns state+nonce+S256 challenge but no verifier', async () => {
  const h = await createSyntheticIdentityHarness();
  const [a, b] = await Promise.all([h.identity.begin({ browserSessionId: binding() }),
    h.identity.begin({ browserSessionId: binding() })]);
  const url = new URL(a.authorizationUrl);
  assert.equal(url.origin + url.pathname, h.options.authorizationEndpoint);
  assert.equal(url.searchParams.get('scope'), 'openid email');
  assert.equal(url.searchParams.get('response_type'), 'code');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(url.searchParams.get('redirect_uri'), h.options.callbackUri);
  assert.notEqual(url.searchParams.get('state'), new URL(b.authorizationUrl).searchParams.get('state'));
  assert.notEqual(url.searchParams.get('nonce'), new URL(b.authorizationUrl).searchParams.get('nonce'));
  assert.equal(url.searchParams.has('code_verifier'), false);
  assert.equal(h.calls.length, 0);
  assert.deepEqual(await h.identity.begin({ browserSessionId: 'short' }), denied);
  assert.deepEqual(await h.identity.begin({ browserSessionId: binding(), redirect_uri: 'https://attacker.invalid/' }), denied);
});

test('callback is one-use, including simultaneous attempts', async () => {
  const h = await createSyntheticIdentityHarness();
  const browserSessionId = binding();
  const start = await h.identity.begin({ browserSessionId });
  const callbackUrl = h.authorizationResponse(start.authorizationUrl);
  const results = await Promise.all([h.identity.complete({ browserSessionId, callbackUrl }),
    h.identity.complete({ browserSessionId, callbackUrl })]);
  assert.equal(results.filter((result) => result.ok).length, 1);
  assert.equal(h.calls.filter((item) => item.endpoint === 'token').length, 1);
  assert.deepEqual(await h.identity.complete({ browserSessionId, callbackUrl }), denied);
});

test('different browser binding cannot consume original login or redeem forwarded callback', async () => {
  const h = await createSyntheticIdentityHarness();
  const browserSessionId = binding();
  const start = await h.identity.begin({ browserSessionId });
  const callbackUrl = h.authorizationResponse(start.authorizationUrl);
  assert.deepEqual(await h.identity.complete({ browserSessionId: binding(), callbackUrl }), denied);
  assert.equal(h.calls.length, 0);
  assert.equal((await h.identity.complete({ browserSessionId, callbackUrl })).ok, true);
});

test('a swapped authorization code fails the synthetic token endpoint PKCE check', async () => {
  const h = await createSyntheticIdentityHarness();
  const firstBinding = binding();
  const secondBinding = binding();
  const firstStart = await h.identity.begin({ browserSessionId: firstBinding });
  const secondStart = await h.identity.begin({ browserSessionId: secondBinding });
  const firstCallback = new URL(h.authorizationResponse(firstStart.authorizationUrl));
  const secondCallback = new URL(h.authorizationResponse(secondStart.authorizationUrl));
  firstCallback.searchParams.set('code', secondCallback.searchParams.get('code'));
  assert.deepEqual(await h.identity.complete({ browserSessionId: firstBinding, callbackUrl: firstCallback.href }), denied);
  assert.deepEqual(h.calls.map((item) => item.endpoint), ['token']);
});

for (const [name, mutate] of [
  ['wrong state', (url) => url.searchParams.set('state', 'wrong-state')],
  ['missing state', (url) => url.searchParams.delete('state')],
  ['wrong response issuer', (url) => url.searchParams.set('iss', 'https://attacker.invalid/')],
  ['missing response issuer', (url) => url.searchParams.delete('iss')],
  ['wrong callback host', (url) => { url.hostname = 'attacker.invalid'; }],
  ['wrong callback path', (url) => { url.pathname = '/wrong'; }],
  ['callback fragment', (url) => { url.hash = 'secret'; }],
  ['duplicate code', (url) => url.searchParams.append('code', 'injected')],
  ['unexpected callback parameter', (url) => url.searchParams.set('xid', 'injected')],
  ['provider error', (url) => url.searchParams.set('error', 'invented-sensitive-error')],
]) {
  test(`rejects ${name} before exchange and burns the callback transaction`, async () => {
    const h = await createSyntheticIdentityHarness();
    const browserSessionId = binding();
    const start = await h.identity.begin({ browserSessionId });
    const original = h.authorizationResponse(start.authorizationUrl);
    const url = new URL(original); mutate(url);
    assert.deepEqual(await h.identity.complete({ browserSessionId, callbackUrl: url.href }), denied);
    assert.deepEqual(await h.identity.complete({ browserSessionId, callbackUrl: original }), denied);
    assert.equal(h.calls.length, 0);
  });
}

test('pending transactions expire and a newer login replaces the older transaction', async () => {
  let now = Date.now();
  const h = await createSyntheticIdentityHarness({ now: () => now });
  const browserSessionId = binding();
  const start = await h.identity.begin({ browserSessionId });
  const callbackUrl = h.authorizationResponse(start.authorizationUrl);
  now += 300_000;
  assert.deepEqual(await h.identity.complete({ browserSessionId, callbackUrl }), denied);
  now = Date.now();
  const first = await h.identity.begin({ browserSessionId });
  await h.identity.begin({ browserSessionId });
  assert.deepEqual(await h.identity.complete({ browserSessionId,
    callbackUrl: h.authorizationResponse(first.authorizationUrl) }), denied);
  assert.equal(h.calls.length, 0);
});

test('normalized callback path aliases and unknown input fields are not accepted', async () => {
  const h = await createSyntheticIdentityHarness();
  const browserSessionId = binding();
  const start = await h.identity.begin({ browserSessionId });
  const callbackUrl = h.authorizationResponse(start.authorizationUrl);
  assert.deepEqual(await h.identity.complete({ browserSessionId, callbackUrl, role: 'owner' }), denied);
  assert.deepEqual(await h.identity.complete({ browserSessionId,
    callbackUrl: callbackUrl.replace('/oidc/callback?', '/alias/../oidc/callback?') }), denied);
  assert.equal(h.calls.length, 0);
});

test('pending transaction capacity is bounded and expired slots are recovered', async () => {
  let now = Date.now();
  const h = await createSyntheticIdentityHarness({ now: () => now });
  const results = await Promise.all(Array.from({ length: 130 }, () => h.identity.begin({ browserSessionId: binding() })));
  assert.equal(results.filter((result) => result.ok).length, 128);
  now += 300_000;
  assert.equal((await h.identity.begin({ browserSessionId: binding() })).ok, true);
});

test('a grant completing after the transaction deadline cannot mint a principal', async () => {
  let now = Date.now();
  const h = await createSyntheticIdentityHarness({ now: () => now });
  h.transformTokenResponse((response) => { now += 300_000; return response; });
  assert.deepEqual(await h.authenticate(), denied);
});

for (const [name, claims, omit = []] of [
  ['wrong ID issuer', { iss: 'https://other-issuer.invalid/' }],
  ['wrong audience', { aud: 'untrusted-client' }],
  ['missing audience', {}, ['aud']],
  ['multi audience without azp', { aud: ['invented-client', 'other-client'] }],
  ['multi audience wrong azp', { aud: ['invented-client', 'other-client'], azp: 'other-client' }],
  ['multi audience not explicitly trusted', { aud: ['invented-client', 'other-client'], azp: 'invented-client' }],
  ['single audience wrong azp', { azp: 'other-client' }],
  ['duplicate audience', { aud: ['invented-client', 'invented-client'], azp: 'invented-client' }],
  ['expired token', { exp: Math.floor(Date.now() / 1000) - 1 }],
  ['missing expiration', {}, ['exp']],
  ['missing issued at', {}, ['iat']],
  ['future issued at', { iat: Math.floor(Date.now() / 1000) + 300 }],
  ['old issued at', { iat: Math.floor(Date.now() / 1000) - 700 }],
  ['future not before', { nbf: Math.floor(Date.now() / 1000) + 300 }],
  ['missing subject', {}, ['sub']],
  ['empty subject', { sub: '' }],
  ['wrong nonce', { nonce: 'other-transaction-nonce' }],
  ['missing nonce', {}, ['nonce']],
]) {
  test(`cryptographic protocol rejects ${name} with generic error only`, async () => {
    const h = await createSyntheticIdentityHarness();
    assert.deepEqual(await h.authenticate({ claims, omit }), denied);
  });
}

test('explicitly configured trusted multi audience with exact client azp can succeed', async () => {
  const h = await createSyntheticIdentityHarness({ trustedAdditionalAudiences: ['other-client'] });
  assert.equal((await h.authenticate({ claims: { aud: ['invented-client', 'other-client'], azp: 'invented-client' } })).ok, true);
});

test('signature from an untrusted RSA key is denied even with otherwise valid claims', async () => {
  const h = await createSyntheticIdentityHarness();
  const untrusted = await generateKeyPair('RS256');
  assert.deepEqual(await h.authenticate({ key: untrusted.privateKey }), denied);
});

test('a different signed algorithm is denied by fixed client metadata', async () => {
  const h = await createSyntheticIdentityHarness();
  const key = await generateKeyPair('ES256');
  assert.deepEqual(await h.authenticate({ key: key.privateKey, header: { alg: 'ES256' } }), denied);
});

test('unknown key ID and unsigned alg none are denied', async () => {
  const h = await createSyntheticIdentityHarness();
  assert.deepEqual(await h.authenticate({ header: { kid: 'untrusted-kid' } }), denied);
  h.transformTokenResponse(async (response) => {
    const body = await response.json();
    const pieces = body.id_token.split('.');
    body.id_token = `${Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url')}.${pieces[1]}.`;
    return jsonResponse(body);
  });
  assert.deepEqual(await h.authenticate(), denied);
});

test('email claims never define identity, prove heritage, or automatically grant participation', async () => {
  const h = await createSyntheticIdentityHarness();
  const a = await h.authenticate();
  const b = await h.authenticate({ claims: { email: 'different@example.invalid' } });
  const c = await h.authenticate({ claims: { sub: 'invented-subject-2' } });
  assert.equal(a.principal.accountId, b.principal.accountId);
  assert.notEqual(a.principal.accountId, c.principal.accountId);
  for (const claim of [false, 'true', 1, null]) {
    const result = await h.authenticate({ claims: { email_verified: claim } });
    assert.equal(result.ok, true);
    assert.equal(result.principal.emailVerifiedByIssuer, false);
  }
  const missingEmail = await h.authenticate({ omit: ['email'] });
  assert.equal(missingEmail.principal.emailVerifiedByIssuer, false);
  assert.equal(h.identity.publicResult(a).eligibilityVerified, false);
  assert.equal(h.identity.publicResult(a).productionReady, false);
});

test('issuer+subject mapping is stable across restart, separates issuers and scopes XIDs by round', async () => {
  const identityKey = randomBytes(32);
  const a = await createSyntheticIdentityHarness({ identityKey });
  const b = await createSyntheticIdentityHarness({ identityKey });
  const c = await createSyntheticIdentityHarness({ identityKey, issuer: 'https://different.example.invalid/' });
  const pa = (await a.authenticate()).principal;
  const pb = (await b.authenticate()).principal;
  const pc = (await c.authenticate()).principal;
  assert.equal(pa.accountId, pb.accountId);
  assert.notEqual(pa.accountId, pc.accountId);
  assert.deepEqual(a.identity.participantXid(pa, 'round_one'), b.identity.participantXid(pb, 'round_one'));
  assert.notEqual(a.identity.participantXid(pa, 'round_one').xid, a.identity.participantXid(pa, 'round_two').xid);
  assert.match(a.identity.participantXid(pa, 'round_one').xid, /^fncp_[A-Za-z0-9_-]{43}$/u);
  assert.deepEqual(a.identity.participantXid({ ...pa }, 'round_one'), denied);
  assert.deepEqual(a.identity.participantXid(pb, 'round_one'), denied);
  assert.deepEqual(a.identity.participantXid(pa, 'email@example.invalid'), denied);
});

test('principal expiry and clock rollback invalidate identity capability', async () => {
  let now = Date.now();
  const h = await createSyntheticIdentityHarness({ now: () => now });
  const result = await h.authenticate();
  assert.equal(h.identity.isVerifiedPrincipal(result.principal), true);
  now += 301_000;
  assert.equal(h.identity.isVerifiedPrincipal(result.principal), false);
  assert.deepEqual(h.identity.publicResult(result), denied);
  assert.deepEqual(h.identity.participantXid(result.principal, 'round_one'), denied);
  now = Date.now() - 60_000;
  assert.equal(h.identity.isVerifiedPrincipal(result.principal), false);
});

test('malformed upstream bodies and thrown errors never appear in returned diagnostics', async () => {
  for (const transform of [
    () => new Response('{"private":"INVENTED_SECRET_SENTINEL" broken', { headers: { 'content-type': 'application/json' } }),
    () => { throw new Error('INVENTED_SECRET_SENTINEL'); },
    () => jsonResponse({ error: 'INVENTED_SECRET_SENTINEL' }, 400),
    () => new Response('x'.repeat(65_537), { headers: { 'content-type': 'application/json' } }),
    () => new Response(null, { status: 302, headers: { location: 'https://attacker.invalid/', 'content-type': 'application/json' } }),
    () => new Response('{}', { headers: { 'content-type': 'text/plain' } }),
  ]) {
    const h = await createSyntheticIdentityHarness();
    h.transformTokenResponse(transform);
    assert.deepEqual(await h.authenticate(), denied);
  }
});

test('ID token is mandatory and malformed/redirecting JWKS fail closed', async () => {
  const h = await createSyntheticIdentityHarness();
  h.transformTokenResponse(async (response) => {
    const body = await response.json(); delete body.id_token; return jsonResponse(body);
  });
  assert.deepEqual(await h.authenticate(), denied);
  const other = await createSyntheticIdentityHarness();
  other.transformJwksResponse(() => jsonResponse({ keys: [] }));
  assert.deepEqual(await other.authenticate(), denied);
  const redirect = await createSyntheticIdentityHarness();
  redirect.transformJwksResponse(() => new Response(null, { status: 302,
    headers: { location: 'https://attacker.invalid/', 'content-type': 'application/json' } }));
  assert.deepEqual(await redirect.authenticate(), denied);
});
