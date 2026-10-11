import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import { generateKeyPair } from 'jose';
import { createProductionIdentity, isProductionIdentityAdapter, PARTICIPANT_IDENTITY_PROFILE } from './identity.mjs';
import { browserBinding, createTestIssuer } from './test-support/https-issuer.mjs';

const denied = { ok: false, error: 'authentication_failed' };
const fixture = async (t, options) => { const h = await createTestIssuer(options); t.after(() => h.close()); return h; };

for (const [signingAlgorithm, tokenEndpointAuthMethod] of [['RS256', 'client_secret_basic'], ['ES256', 'client_secret_post']]) {
  test(`${signingAlgorithm}/${tokenEndpointAuthMethod}: actual verified HTTPS code flow creates only opaque capability`, async t => {
    const h = await fixture(t, { signingAlgorithm, tokenEndpointAuthMethod });
    const result = await h.authenticate();
    assert.equal(result.ok, true);
    assert.equal(isProductionIdentityAdapter(h.identity), true);
    assert.equal(result.principal.profile, PARTICIPANT_IDENTITY_PROFILE);
    assert.equal(Object.isFrozen(result.principal), true);
    assert.equal(h.identity.isVerifiedPrincipal(result.principal), true);
    assert.deepEqual(h.identity.publicResult(result), { ok: true, authenticated: true,
      emailVerifiedByIssuer: true, eligibilityVerified: false, participantAccessGranted: false });
    assert.doesNotMatch(JSON.stringify(result), /invented-subject|invented@example|SENSITIVE_|PRIVATE_CLIENT|id_token|nonce/u);
    assert.doesNotMatch(JSON.stringify(h.identity.publicResult(result)), /acct_|fncp_|token|claims|issuer/u);
    assert.deepEqual(h.calls.map(call => call.endpoint), ['token', 'jwks']);
    assert.equal(result.principal.mode, undefined); // It cannot impersonate the synthetic-only brand.
  });
}

test('configuration rejects dynamic/unsafe endpoints, transport injection, invalid keys and accessors before network', async t => {
  const h = await fixture(t);
  const variants = [{ issuer: 'http://id.example.invalid/' }, { tokenEndpoint: 'https://secret@id.example.invalid/token' },
    { jwksUri: 'https://id.example.invalid/jwks?callback=elsewhere' }, { callbackUri: 'https://participant.example.invalid/callback#secret' },
    { authorizationEndpoint: 'https://id.example.invalid' }, { tokenEndpoint: h.options.jwksUri },
    { mode: 'SYNTHETIC_ONLY' }, { transport: { kind: 'SYNTHETIC_INTERCEPT', fetch() {} } },
    { signingAlgorithm: 'HS256' }, { clientSecret: '' }, { clientSecret: 'secret\nunsafe' },
    { tokenEndpointAuthMethod: 'none' }, { identityKey: randomBytes(16) }, { identityKey: randomBytes(65) },
    { ca: Buffer.from('not a certificate') }, { now: () => NaN }];
  for (const variant of variants) assert.throws(() => createProductionIdentity({ ...h.options, ...variant }),
    { message: 'Participant OIDC configuration rejected.' });
  let read = 0;
  const accessor = { ...h.options }; Object.defineProperty(accessor, 'clientSecret', { enumerable: true, get() { read++; return 'secret'; } });
  assert.throws(() => createProductionIdentity(accessor), { message: 'Participant OIDC configuration rejected.' });
  assert.equal(read, 0); assert.equal(h.calls.length, 0);
});

test('authorization fixes issuer endpoints, scope, callback and PKCE without accepting arbitrary request parameters', async t => {
  const h = await fixture(t);
  const start = await h.identity.begin({ browserSessionId: browserBinding() });
  const url = new URL(start.authorizationUrl);
  assert.equal(url.origin + url.pathname, h.options.authorizationEndpoint);
  assert.equal(url.searchParams.get('scope'), 'openid email');
  assert.equal(url.searchParams.get('redirect_uri'), h.options.callbackUri);
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(url.searchParams.has('code_verifier'), false);
  assert.deepEqual(await h.identity.begin({ browserSessionId: 'short' }), denied);
  assert.deepEqual(await h.identity.begin({ browserSessionId: browserBinding(), redirect_uri: 'https://other.invalid/' }), denied);
  assert.equal(h.calls.length, 0);
});

test('callback binds the browser, is one-use under concurrency, and cannot be replayed', async t => {
  const h = await fixture(t);
  const browserSessionId = browserBinding();
  const start = await h.identity.begin({ browserSessionId });
  const callbackUrl = h.authorizationResponse(start.authorizationUrl);
  assert.deepEqual(await h.identity.complete({ browserSessionId: browserBinding(), callbackUrl }), denied);
  assert.equal(h.calls.length, 0);
  const results = await Promise.all([h.identity.complete({ browserSessionId, callbackUrl }), h.identity.complete({ browserSessionId, callbackUrl })]);
  assert.equal(results.filter(result => result.ok).length, 1);
  assert.equal(h.calls.filter(call => call.endpoint === 'token').length, 1);
  assert.deepEqual(await h.identity.complete({ browserSessionId, callbackUrl }), denied);
});

for (const [name, mutate] of [
  ['wrong state', url => url.searchParams.set('state', 'untrusted')],
  ['missing state', url => url.searchParams.delete('state')],
  ['missing issuer', url => url.searchParams.delete('iss')],
  ['wrong issuer', url => url.searchParams.set('iss', 'https://other.example.invalid/')],
  ['duplicate code', url => url.searchParams.append('code', 'untrusted')],
  ['extra identity claim', url => url.searchParams.append('xid', 'untrusted')],
  ['provider error', url => url.searchParams.set('error_description', 'sensitive-provider-body')],
  ['different callback host', url => { url.hostname = 'other.example.invalid'; }],
  ['callback fragment', url => { url.hash = 'secret'; }],
]) test(`rejects ${name} before a token request and burns the transaction`, async t => {
  const h = await fixture(t);
  const browserSessionId = browserBinding(); const start = await h.identity.begin({ browserSessionId });
  const original = h.authorizationResponse(start.authorizationUrl); const url = new URL(original); mutate(url);
  assert.deepEqual(await h.identity.complete({ browserSessionId, callbackUrl: url.href }), denied);
  assert.deepEqual(await h.identity.complete({ browserSessionId, callbackUrl: original }), denied);
  assert.equal(h.calls.length, 0);
});

for (const [name, claims, omit = []] of [
  ['wrong ID issuer', { iss: 'https://other.example.invalid/' }], ['wrong audience', { aud: 'other-client' }],
  ['multiple audiences', { aud: ['invented-client', 'other-client'], azp: 'invented-client' }],
  ['wrong authorized party', { azp: 'other-client' }], ['duplicate audience', { aud: ['invented-client', 'invented-client'], azp: 'invented-client' }],
  ['unverified email', { email_verified: false }], ['missing email', {}, ['email']],
  ['missing subject', {}, ['sub']], ['missing nonce', {}, ['nonce']], ['wrong nonce', { nonce: 'other-login' }],
  ['expired token', { exp: Math.floor(Date.now() / 1000) - 1 }], ['missing expiration', {}, ['exp']],
  ['future issued at', { iat: Math.floor(Date.now() / 1000) + 300 }],
  ['old issued at', { iat: Math.floor(Date.now() / 1000) - 700 }], ['missing issued at', {}, ['iat']],
  ['future not before', { nbf: Math.floor(Date.now() / 1000) + 300 }],
]) test(`cryptographic claim validation denies ${name} with no provider details`, async t => {
  const h = await fixture(t);
  assert.deepEqual(await h.authenticate({ claims, omit }), denied);
});

test('untrusted signature and unknown key ID cannot mint a principal', async t => {
  const h = await fixture(t);
  const key = await generateKeyPair('ES256');
  assert.deepEqual(await h.authenticate({ key: key.privateKey }), denied);
  assert.deepEqual(await h.authenticate({ header: { kid: 'untrusted-key' } }), denied);
});

test('opaque identity is issuer+subject, not email; round mapping is stable with retained key', async t => {
  const h = await fixture(t);
  const first = await h.authenticate();
  const changedEmail = await h.authenticate({ claims: { email: 'changed@example.invalid' } });
  const otherSubject = await h.authenticate({ claims: { sub: 'invented-subject-two' } });
  assert.equal(first.ok && changedEmail.ok && otherSubject.ok, true);
  assert.equal(first.principal.accountId, changedEmail.principal.accountId);
  assert.notEqual(first.principal.accountId, otherSubject.principal.accountId);
  const roundOne = h.identity.participantXid(first.principal, 'round_one');
  assert.equal(roundOne.ok, true);
  assert.notEqual(roundOne.xid, h.identity.participantXid(first.principal, 'round_two').xid);
  const restarted = h.createAdapter();
  const afterRestart = await h.authenticate({}, restarted);
  assert.equal(afterRestart.principal.accountId, first.principal.accountId);
  assert.deepEqual(restarted.participantXid(afterRestart.principal, 'round_one'), roundOne);
  assert.equal(restarted.isVerifiedPrincipal(first.principal), false);
  const changedKey = h.createAdapter({ identityKey: randomBytes(32) });
  assert.notEqual((await h.authenticate({}, changedKey)).principal.accountId, first.principal.accountId);
});

test('copied, serialized, forged and other-instance principals are rejected', async t => {
  const h = await fixture(t); const result = await h.authenticate();
  assert.equal(result.ok, true);
  const other = h.createAdapter();
  for (const principal of [{ ...result.principal }, Object.freeze({ ...result.principal }), JSON.parse(JSON.stringify(result.principal)), {}]) {
    assert.equal(h.identity.isVerifiedPrincipal(principal), false);
    assert.equal(h.identity.principalDeadline(principal), null);
    assert.deepEqual(h.identity.participantXid(principal, 'round_one'), denied);
  }
  assert.equal(other.isVerifiedPrincipal(result.principal), false);
  assert.equal(isProductionIdentityAdapter(Object.freeze({ ...h.identity })), false);
});

test('discard, expiry and replacement consume pending state; capacity is bounded', async t => {
  let now = Date.now(); const h = await fixture(t, { now: () => now });
  const browserSessionId = browserBinding(); const start = await h.identity.begin({ browserSessionId });
  const callbackUrl = h.authorizationResponse(start.authorizationUrl);
  h.identity.discard({ browserSessionId });
  assert.deepEqual(await h.identity.complete({ browserSessionId, callbackUrl }), denied);
  const again = await h.identity.begin({ browserSessionId });
  await h.identity.begin({ browserSessionId });
  assert.deepEqual(await h.identity.complete({ browserSessionId, callbackUrl: h.authorizationResponse(again.authorizationUrl) }), denied);
  const results = await Promise.all(Array.from({ length: 130 }, () => h.identity.begin({ browserSessionId: browserBinding() })));
  assert.equal(results.filter(result => result.ok).length, 128);
  now += 300_000;
  assert.equal((await h.identity.begin({ browserSessionId: browserBinding() })).ok, true);
});

test('principal expiry denies all derived capabilities', async t => {
  let now = Date.now(); const h = await fixture(t, { now: () => now }); const result = await h.authenticate();
  assert.equal(result.ok, true); now = h.identity.principalDeadline(result.principal);
  assert.equal(h.identity.isVerifiedPrincipal(result.principal), false);
  assert.deepEqual(h.identity.publicResult(result), denied);
  assert.deepEqual(h.identity.participantXid(result.principal, 'round_one'), denied);
});

for (const anomaly of ['backward', 'non-finite', 'throws']) test(`clock ${anomaly} latches adapter closed; correction never restores old authority`, async t => {
  let now = Date.now(); let throwing = false;
  const h = await fixture(t, { now: () => { if (throwing) throw new Error('private-clock-error'); return now; } });
  const result = await h.authenticate(); assert.equal(result.ok, true);
  const original = now;
  if (anomaly === 'backward') now -= 1; else if (anomaly === 'non-finite') now = NaN; else throwing = true;
  assert.equal(h.identity.isVerifiedPrincipal(result.principal), false);
  throwing = false; now = original + 1;
  assert.equal(h.identity.isVerifiedPrincipal(result.principal), false);
  assert.deepEqual(await h.identity.begin({ browserSessionId: browserBinding() }), denied);
});

test('close invalidates issued principals and pending login without exposing tokens', async t => {
  const h = await fixture(t); const result = await h.authenticate();
  const browserSessionId = browserBinding(); const start = await h.identity.begin({ browserSessionId });
  const callbackUrl = h.authorizationResponse(start.authorizationUrl);
  h.identity.close(); h.identity.close();
  assert.equal(h.identity.isVerifiedPrincipal(result.principal), false);
  assert.deepEqual(await h.identity.complete({ browserSessionId, callbackUrl }), denied);
  assert.deepEqual(await h.identity.begin({ browserSessionId: browserBinding() }), denied);
});

test('closure during a live token grant cancels transport and cannot mint a late principal', async t => {
  const h = await fixture(t);
  let release; h.setGate(new Promise(resolve => { release = resolve; }));
  const operation = h.authenticate();
  const timeout = Date.now() + 2000;
  while (!h.calls.length && Date.now() < timeout) await new Promise(resolve => setTimeout(resolve, 5));
  assert.equal(h.calls.length, 1);
  h.identity.close(); release();
  assert.deepEqual(await operation, denied);
});
