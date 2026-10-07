import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import { createSyntheticIdentityHarness } from './synthetic-harness.mjs';
import { createSyntheticBrowserDriver } from './synthetic-browser-driver.mjs';

const binding = () => randomBytes(32).toString('base64url');
const failed = { ok: false, error: 'authentication_failed' };
const originalFetch = globalThis.fetch;
test.before(() => { globalThis.fetch = () => { throw new Error('Network disabled in synthetic browser-driver tests.'); }; });
test.after(() => { globalThis.fetch = originalFetch; });
async function harness(options = {}) {
  const source = await createSyntheticIdentityHarness(options);
  let injections = 0;
  const config = { mode: 'SYNTHETIC_ONLY', identity: source.identity,
    syntheticAuthorizationResponse: (...args) => { injections++; return source.authorizationResponse(...args); },
    ...(options.now ? { now: options.now } : {}) };
  return { source, config, driver: createSyntheticBrowserDriver(config), injections: () => injections };
}
const injection = (browserSessionId, syntheticSubject = 'synthetic_alice', emailVerifiedByIssuer = true) =>
  ({ browserSessionId, syntheticSubject, emailVerifiedByIssuer });

test('begin reveals no URL or grant; explicit private injection and JSON callback complete real OIDC', async () => {
  const h = await harness(); const browserSessionId = binding();
  assert.deepEqual(await h.driver.begin({ browserSessionId }), { ok: true });
  assert.equal(h.injections(), 0); assert.equal(h.source.calls.length, 0);
  const response = await h.driver.injectTestResponse(injection(browserSessionId));
  assert.equal(response.ok, true); assert.equal(h.injections(), 1); assert.equal(h.source.calls.length, 0);
  assert.equal(new URL(response.callback.callbackUrl).origin, 'https://participant.example.invalid');
  assert.deepEqual(Object.keys(response.callback), ['callbackUrl']);
  const result = await h.driver.complete({ browserSessionId, ...JSON.parse(JSON.stringify(response.callback)) });
  assert.equal(result.ok, true); assert.equal(h.driver.isVerifiedPrincipal(result.principal), true);
  assert.equal(result.principal.emailVerifiedByIssuer, true);
  assert.equal(result.principal.eligibilityVerified, false);
  assert.doesNotMatch(JSON.stringify(result), /synthetic_alice|@|token|nonce|code|https:/u);
  assert.equal(h.source.calls.filter((entry) => entry.endpoint === 'token').length, 1);
});

test('configuration requires explicit synthetic mode and complete in-process interfaces', async () => {
  const h = await harness();
  for (const changes of [{ mode: 'PRODUCTION' }, { mode: undefined }, { identity: {} },
    { syntheticAuthorizationResponse: undefined }, { now: 1 }, { arbitrary: 'INVENTED_SECRET' }]) {
    assert.throws(() => createSyntheticBrowserDriver({ ...h.config, ...changes }),
      { message: 'Synthetic browser driver configuration rejected.' });
  }
});

test('no callback can complete before explicit private injection', async () => {
  const h = await harness(); const browserSessionId = binding();
  await h.driver.begin({ browserSessionId });
  assert.deepEqual(await h.driver.complete({ browserSessionId,
    callbackUrl: 'https://participant.example.invalid/oidc/callback?code=invented' }), failed);
  assert.deepEqual(await h.driver.injectTestResponse(injection(browserSessionId)), failed);
  assert.equal(h.injections(), 0); assert.equal(h.source.calls.length, 0);
});

test('injection is one-use and a duplicate does not destroy the issued callback', async () => {
  const h = await harness(); const browserSessionId = binding();
  await h.driver.begin({ browserSessionId });
  const results = await Promise.all([h.driver.injectTestResponse(injection(browserSessionId)),
    h.driver.injectTestResponse(injection(browserSessionId, 'synthetic_other'))]);
  assert.equal(results.filter((result) => result.ok).length, 1); assert.equal(h.injections(), 1);
  const response = results.find((result) => result.ok);
  assert.equal((await h.driver.complete({ browserSessionId, ...response.callback })).ok, true);
});

test('callback completion is one-use even under concurrent requests', async () => {
  const h = await harness(); const browserSessionId = binding();
  await h.driver.begin({ browserSessionId });
  const response = await h.driver.injectTestResponse(injection(browserSessionId));
  const results = await Promise.all([h.driver.complete({ browserSessionId, ...response.callback }),
    h.driver.complete({ browserSessionId, ...response.callback })]);
  assert.equal(results.filter((result) => result.ok).length, 1);
  assert.equal(h.source.calls.filter((entry) => entry.endpoint === 'token').length, 1);
});

test('forwarded callback cannot authenticate a different browser binding', async () => {
  const h = await harness(); const alice = binding(); const bob = binding();
  await h.driver.begin({ browserSessionId: alice }); await h.driver.begin({ browserSessionId: bob });
  const a = await h.driver.injectTestResponse(injection(alice));
  await h.driver.injectTestResponse(injection(bob, 'synthetic_bob'));
  assert.deepEqual(await h.driver.complete({ browserSessionId: bob, ...a.callback }), failed);
  assert.equal((await h.driver.complete({ browserSessionId: alice, ...a.callback })).ok, true);
});

test('exact inputs permit only invented subjects and Boolean mail claims, not arbitrary signing fields', async () => {
  const h = await harness(); const browserSessionId = binding();
  await h.driver.begin({ browserSessionId });
  for (const changes of [{ syntheticSubject: 'real-person@example.com' }, { syntheticSubject: 'alice' },
    { emailVerifiedByIssuer: 'true' }, { claims: { role: 'admin' } }, { header: { alg: 'none' } },
    { privateKey: 'INVENTED_PRIVATE_KEY' }, { authorizationUrl: 'https://attacker.invalid/' }]) {
    assert.deepEqual(await h.driver.injectTestResponse({ ...injection(browserSessionId), ...changes }), failed);
  }
  assert.equal(h.injections(), 0);
  const response = await h.driver.injectTestResponse(injection(browserSessionId, 'synthetic_alice', false));
  const result = await h.driver.complete({ browserSessionId, ...response.callback });
  assert.equal(result.ok, true); assert.equal(result.principal.emailVerifiedByIssuer, false);
});

test('discard and replacement login invalidate old callback capabilities', async () => {
  const h = await harness(); const browserSessionId = binding();
  await h.driver.begin({ browserSessionId });
  const old = await h.driver.injectTestResponse(injection(browserSessionId));
  assert.deepEqual(h.driver.discard({ browserSessionId }), { ok: true });
  assert.deepEqual(await h.driver.complete({ browserSessionId, ...old.callback }), failed);
  await h.driver.begin({ browserSessionId });
  const replaced = await h.driver.injectTestResponse(injection(browserSessionId));
  await h.driver.begin({ browserSessionId });
  assert.deepEqual(await h.driver.complete({ browserSessionId, ...replaced.callback }), failed);
  assert.equal(h.source.calls.length, 0);
});

for (const action of ['discard', 'new-login']) {
  test(`${action} during callback exchange cannot revive the old browser identity`, async () => {
    const h = await harness(); const browserSessionId = binding();
    await h.driver.begin({ browserSessionId });
    const response = await h.driver.injectTestResponse(injection(browserSessionId));
    const entered = Promise.withResolvers(); const release = Promise.withResolvers();
    h.source.transformTokenResponse(async (value) => { entered.resolve(); await release.promise; return value; });
    const completion = h.driver.complete({ browserSessionId, ...response.callback });
    await entered.promise;
    if (action === 'discard') h.driver.discard({ browserSessionId });
    else await h.driver.begin({ browserSessionId });
    release.resolve();
    assert.deepEqual(await completion, failed);
    if (action === 'new-login') {
      h.source.transformTokenResponse(undefined);
      const fresh = await h.driver.injectTestResponse(injection(browserSessionId, 'synthetic_new'));
      assert.equal((await h.driver.complete({ browserSessionId, ...fresh.callback })).ok, true);
    }
  });
}

test('five-minute deadline denies unissued and already-issued callbacks', async () => {
  let now = Date.now(); const h = await harness({ now: () => now });
  const a = binding(); const b = binding();
  await h.driver.begin({ browserSessionId: a }); await h.driver.begin({ browserSessionId: b });
  const response = await h.driver.injectTestResponse(injection(b));
  now += 300_000;
  assert.deepEqual(await h.driver.injectTestResponse(injection(a)), failed);
  assert.deepEqual(await h.driver.complete({ browserSessionId: b, ...response.callback }), failed);
  assert.equal(h.source.calls.length, 0);
});

test('capacity is bounded at 128 pending flows and reopens only after expiry', async () => {
  let now = Date.now(); const h = await harness({ now: () => now });
  const results = await Promise.all(Array.from({ length: 130 }, () => h.driver.begin({ browserSessionId: binding() })));
  assert.equal(results.filter((result) => result.ok).length, 128);
  now += 300_000;
  assert.deepEqual(await h.driver.begin({ browserSessionId: binding() }), { ok: true });
});

test('principal verification delegates exact capability and expiry, without converting claims to authority', async () => {
  let now = Date.now(); const h = await harness({ now: () => now }); const browserSessionId = binding();
  await h.driver.begin({ browserSessionId }); const response = await h.driver.injectTestResponse(injection(browserSessionId));
  const result = await h.driver.complete({ browserSessionId, ...response.callback });
  assert.equal(h.driver.isVerifiedPrincipal(result.principal), true);
  assert.equal(h.driver.isVerifiedPrincipal({ ...result.principal }), false);
  now += 301_000;
  assert.equal(h.driver.isVerifiedPrincipal(result.principal), false);
});

test('upstream injection errors and malformed callback values expose only generic failure', async () => {
  const h = await harness();
  for (const response of ['INVENTED_PRIVATE_ERROR', 'http://127.0.0.1/callback',
    'https://real-identity.example.com/callback', 'https://participant.example.invalid/wrong',
    'https://participant.example.invalid/oidc/callback#INVENTED_SECRET']) {
    const driver = createSyntheticBrowserDriver({ ...h.config, syntheticAuthorizationResponse: () => response });
    const browserSessionId = binding(); await driver.begin({ browserSessionId });
    assert.deepEqual(await driver.injectTestResponse(injection(browserSessionId)), failed);
  }
  const driver = createSyntheticBrowserDriver({ ...h.config,
    syntheticAuthorizationResponse: () => { throw new Error('INVENTED_SECRET_UPSTREAM_ERROR'); } });
  const browserSessionId = binding(); await driver.begin({ browserSessionId });
  assert.deepEqual(await driver.injectTestResponse(injection(browserSessionId)), failed);
});

test('driver will not expose an authorization route from a non-synthetic identity dependency', async () => {
  const h = await harness();
  const driver = createSyntheticBrowserDriver({ ...h.config, identity: { ...h.source.identity,
    begin: async () => ({ ok: true, authorizationUrl: 'https://real-identity.example.com/authorize' }) } });
  assert.deepEqual(await driver.begin({ browserSessionId: binding() }), failed);
});

test('strict body fields reject caller-selected session aliases or callback metadata', async () => {
  const h = await harness(); const browserSessionId = binding();
  assert.deepEqual(await h.driver.begin({ browserSessionId, account: 'synthetic_alice' }), failed);
  assert.deepEqual(await h.driver.begin({ browserSessionId: 'short' }), failed);
  assert.deepEqual(h.driver.discard({ browserSessionId, all: true }), failed);
  await h.driver.begin({ browserSessionId }); const response = await h.driver.injectTestResponse(injection(browserSessionId));
  assert.deepEqual(await h.driver.complete({ browserSessionId, ...response.callback, role: 'owner' }), failed);
  assert.equal(h.source.calls.length, 0);
});
