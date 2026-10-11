import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import { createHttpsRedirectDriver } from './https-redirect-driver.mjs';
import { createSyntheticIdentityHarness } from './synthetic-harness.mjs';

const authorizationEndpoint = 'https://identity.example.invalid/authorize';
const callbackUri = 'https://participant.example.invalid/oidc/callback';
const issuer = 'https://identity.example.invalid/';
const binding = () => randomBytes(32).toString('base64url');
const failure = { ok: false, error: 'authentication_failed' };
const originalFetch = globalThis.fetch;
test.before(() => { globalThis.fetch = () => { throw new Error('No network in pure redirect-driver tests.'); }; });
test.after(() => { globalThis.fetch = originalFetch; });
function authorization() {
  const parsed = new URL(authorizationEndpoint);
  parsed.search = new URLSearchParams({ client_id: 'invented-client', redirect_uri: callbackUri,
    response_type: 'code', response_mode: 'query', scope: 'openid email',
    code_challenge: binding(), code_challenge_method: 'S256', state: binding(), nonce: binding() });
  return parsed.href;
}
function callback(start) {
  const parsed = new URL(callbackUri);
  parsed.search = new URLSearchParams({ code: binding(), state: new URL(start.authorizationUrl).searchParams.get('state'), iss: issuer });
  return parsed.href;
}
function stub(edit = () => {}) {
  const principal = Object.freeze({ invented: true });
  const calls = { begin: 0, complete: 0 };
  const identity = { async begin() { calls.begin++; return { ok: true, authorizationUrl: authorization() }; },
    async complete() { calls.complete++; return { ok: true, principal }; },
    isVerifiedPrincipal(value) { return value === principal; } };
  const options = { mode: 'SYNTHETIC_ONLY', identity, authorizationEndpoint, callbackUri };
  edit(options);
  return { options, identity, principal, calls, driver: createHttpsRedirectDriver(options) };
}
async function real(options = {}) {
  const source = await createSyntheticIdentityHarness(options);
  return { source, driver: createHttpsRedirectDriver({ mode: 'SYNTHETIC_ONLY', identity: source.identity,
    authorizationEndpoint, callbackUri, ...(options.now ? { now: options.now } : {}) }) };
}

for (const signingAlgorithm of ['RS256', 'ES256']) test(`validated redirect and actual ${signingAlgorithm} code exchange return only opaque principal`, async () => {
  const h = await real({ signingAlgorithm }); const browserSessionId = binding();
  const start = await h.driver.begin({ browserSessionId });
  assert.equal(start.ok, true); assert.deepEqual(Object.keys(start), ['ok', 'authorizationUrl']);
  assert.equal(new URL(start.authorizationUrl).origin, 'https://identity.example.invalid');
  assert.equal(h.source.calls.length, 0);
  const result = await h.driver.complete({ browserSessionId, callbackUrl: h.source.authorizationResponse(start.authorizationUrl) });
  assert.equal(result.ok, true); assert.equal(h.driver.isVerifiedPrincipal(result.principal), true);
  assert.equal(result.principal.eligibilityVerified, false);
  assert.equal(h.driver.isVerifiedPrincipal({ ...result.principal }), false);
  assert.doesNotMatch(JSON.stringify(result), /invented@example|token|nonce|code|https:/u);
  assert.equal(h.source.calls.filter(call => call.endpoint === 'token').length, 1);
  assert.ok(Object.isFrozen(h.driver)); assert.ok(Object.isFrozen(start)); assert.ok(Object.isFrozen(result));
  assert.equal(h.driver.mode, 'SYNTHETIC_ONLY'); assert.equal(h.driver.transport, 'HTTPS_REDIRECT_LAB');
  assert.equal(h.driver.injectTestResponse, undefined); assert.equal(h.driver.listen, undefined);
});

const invalidConfigurations = [
  ['missing mode', { mode: undefined }], ['production mode', { mode: 'PRODUCTION' }],
  ['missing foundation', { identity: {} }], ['unknown key', { sentinel: 'PRIVATE_SENTINEL' }],
  ['invalid clock type', { now: 1 }], ['negative clock', { now: () => -1 }],
  ['nonfinite clock', { now: () => NaN }], ['unsafe expiry arithmetic', { now: () => Number.MAX_SAFE_INTEGER }],
  ['throwing clock', { now: () => { throw Error('PRIVATE_SENTINEL'); } }],
  ['HTTP authorization', { authorizationEndpoint: 'http://identity.example.invalid/authorize' }],
  ['real authorization host', { authorizationEndpoint: 'https://identity.example.com/authorize' }],
  ['real callback host', { callbackUri: 'https://participant.example.com/callback' }],
  ['userinfo', { authorizationEndpoint: 'https://user:password@identity.example.invalid/authorize' }],
  ['noncanonical hostname', { authorizationEndpoint: 'https://IDENTITY.example.invalid/authorize' }],
  ['explicit default port', { authorizationEndpoint: 'https://identity.example.invalid:443/authorize' }],
  ['query in configuration', { callbackUri: callbackUri + '?selected=1' }],
  ['empty query in configuration', { callbackUri: callbackUri + '?' }],
  ['fragment in configuration', { callbackUri: callbackUri + '#private' }],
  ['empty fragment in configuration', { callbackUri: callbackUri + '#' }],
  ['same endpoints', { callbackUri: authorizationEndpoint }],
];
for (const [label, changes] of invalidConfigurations) test(`configuration rejects ${label} with generic failure`, () => {
  const h = stub();
  assert.throws(() => createHttpsRedirectDriver({ ...h.options, ...changes }),
    { message: 'HTTPS redirect driver configuration rejected.' });
});
test('configuration rejects accessors and symbol keys without invoking the accessor', () => {
  const h = stub(); let accessed = false;
  const options = { ...h.options }; Object.defineProperty(options, 'now', { get() { accessed = true; return Date.now; } });
  assert.throws(() => createHttpsRedirectDriver(options)); assert.equal(accessed, false);
  assert.throws(() => createHttpsRedirectDriver({ ...h.options, [Symbol('private')]: true }));
});

const badAuthorizations = [
  ['another host', value => value.replace('identity.example.invalid', 'wrong.example.invalid')],
  ['another route', value => value.replace('/authorize?', '/different?')],
  ['HTTP scheme', value => value.replace('https:', 'http:')],
  ['fragment', value => value + '#private'],
  ['duplicate state', value => value + '&state=' + binding()],
  ['encoded duplicate state', value => value + '&%73tate=' + binding()],
  ['unknown parameter', value => value + '&login_hint=PRIVATE_SENTINEL'],
  ['wrong callback', value => { const u = new URL(value); u.searchParams.set('redirect_uri', 'https://wrong.example.invalid/callback'); return u.href; }],
  ['implicit grant', value => { const u = new URL(value); u.searchParams.set('response_type', 'token'); return u.href; }],
  ['form-post response', value => { const u = new URL(value); u.searchParams.set('response_mode', 'form_post'); return u.href; }],
  ['plain PKCE', value => { const u = new URL(value); u.searchParams.set('code_challenge_method', 'plain'); return u.href; }],
  ['invalid PKCE challenge', value => { const u = new URL(value); u.searchParams.set('code_challenge', 'too-short'); return u.href; }],
  ['missing nonce', value => { const u = new URL(value); u.searchParams.delete('nonce'); return u.href; }],
  ['short state', value => { const u = new URL(value); u.searchParams.set('state', 'short'); return u.href; }],
  ['extra scopes', value => { const u = new URL(value); u.searchParams.set('scope', 'openid email admin'); return u.href; }],
];
for (const [label, edit] of badAuthorizations) test(`begin rejects ${label} from its adapter without exposing a URL`, async () => {
  const h = stub(options => { options.identity.begin = async () => ({ ok: true, authorizationUrl: edit(authorization()) }); });
  const browserSessionId = binding();
  assert.deepEqual(await h.driver.begin({ browserSessionId }), failure);
  assert.deepEqual(await h.driver.complete({ browserSessionId, callbackUrl: callback({ authorizationUrl: authorization() }) }), failure);
  assert.equal(h.calls.complete, 0);
});

const badCallbacks = [
  ['wrong host', value => value.replace('participant.example.invalid', 'wrong.example.invalid')],
  ['wrong route', value => value.replace('/oidc/callback?', '/other?')],
  ['HTTP callback', value => value.replace('https:', 'http:')],
  ['userinfo', value => value.replace('https://', 'https://user@')],
  ['fragment', value => value + '#PRIVATE_SENTINEL'],
  ['empty fragment', value => value + '#'],
  ['duplicate code', value => value + '&code=' + binding()],
  ['duplicate issuer alias', value => value + '&%69ss=' + encodeURIComponent(issuer)],
  ['unknown parameter', value => value + '&return_to=https://wrong.example.invalid/'],
  ['wrong state', value => { const u = new URL(value); u.searchParams.set('state', binding()); return u.href; }],
  ['missing issuer', value => { const u = new URL(value); u.searchParams.delete('iss'); return u.href; }],
  ['provider error', value => { const u = new URL(value); u.searchParams.delete('code'); u.searchParams.set('error', 'access_denied'); return u.href; }],
  ['provider error description', value => value + '&error_description=PRIVATE_SENTINEL'],
  ['oversized input', value => value + 'a'.repeat(8192)],
];
for (const [label, edit] of badCallbacks) test(`callback consumes and rejects ${label} before foundation exchange`, async () => {
  const h = stub(); const browserSessionId = binding(); const start = await h.driver.begin({ browserSessionId });
  const good = callback(start);
  assert.deepEqual(await h.driver.complete({ browserSessionId, callbackUrl: edit(good) }), failure);
  assert.deepEqual(await h.driver.complete({ browserSessionId, callbackUrl: good }), failure);
  assert.equal(h.calls.complete, 0);
});

test('foundation enforces issuer rather than trusting callback text', async () => {
  const h = await real(); const browserSessionId = binding(); const start = await h.driver.begin({ browserSessionId });
  const u = new URL(h.source.authorizationResponse(start.authorizationUrl)); u.searchParams.set('iss', 'https://wrong.example.invalid/');
  assert.deepEqual(await h.driver.complete({ browserSessionId, callbackUrl: u.href }), failure);
  assert.equal(h.source.calls.length, 0);
});
test('forwarded real authorization response cannot authenticate another browser binding', async () => {
  const h = await real(); const a = binding(); const b = binding();
  const start = await h.driver.begin({ browserSessionId: a }); await h.driver.begin({ browserSessionId: b });
  const callbackUrl = h.source.authorizationResponse(start.authorizationUrl);
  assert.deepEqual(await h.driver.complete({ browserSessionId: b, callbackUrl }), failure);
  assert.equal((await h.driver.complete({ browserSessionId: a, callbackUrl })).ok, true);
  assert.equal(h.source.calls.filter(call => call.endpoint === 'token').length, 1);
});
test('complete is one-use, including concurrent callbacks', async () => {
  const h = stub(); const browserSessionId = binding(); const start = await h.driver.begin({ browserSessionId });
  const input = { browserSessionId, callbackUrl: callback(start) };
  const results = await Promise.all([h.driver.complete(input), h.driver.complete(input)]);
  assert.equal(results.filter(result => result.ok).length, 1); assert.equal(h.calls.complete, 1);
  assert.deepEqual(await h.driver.complete(input), failure);
});
test('false or throwing foundation principal verification never grants a session', async () => {
  for (const verify of [() => false, () => 'true', () => { throw Error('PRIVATE_SENTINEL'); }]) {
    const h = stub(options => { options.identity.isVerifiedPrincipal = verify; });
    const browserSessionId = binding(); const start = await h.driver.begin({ browserSessionId });
    assert.deepEqual(await h.driver.complete({ browserSessionId, callbackUrl: callback(start) }), failure);
    assert.equal(h.driver.isVerifiedPrincipal({}), false);
  }
});
test('adapter exceptions and failure results remain generic and are never automatically retried', async () => {
  for (const result of ['throw', { ok: false, error: 'PRIVATE_SENTINEL' }, { ok: true, principal: { forged: true } }]) {
    let calls = 0;
    const h = stub(options => { options.identity.complete = async () => { calls++; if (result === 'throw') throw Error('PRIVATE_SENTINEL'); return result; }; });
    const browserSessionId = binding(); const start = await h.driver.begin({ browserSessionId });
    const input = { browserSessionId, callbackUrl: callback(start) };
    assert.deepEqual(await h.driver.complete(input), failure); assert.deepEqual(await h.driver.complete(input), failure);
    assert.equal(calls, 1);
  }
});
test('adapter methods are captured before caller mutation', async () => {
  const h = stub(); const browserSessionId = binding();
  h.identity.begin = () => { throw Error('Changed'); }; h.identity.complete = () => { throw Error('Changed'); };
  h.identity.isVerifiedPrincipal = () => false;
  const start = await h.driver.begin({ browserSessionId });
  assert.equal((await h.driver.complete({ browserSessionId, callbackUrl: callback(start) })).ok, true);
});
test('inputs reject fields, accessors, aliases and short bindings without reaching adapters', async () => {
  const h = stub(); const browserSessionId = binding();
  for (const input of [{ browserSessionId, selected: true }, { browserSessionId: 'short' },
    { browserSessionId, [Symbol('alias')]: true }, Object.create({ browserSessionId })]) {
    assert.deepEqual(await h.driver.begin(input), failure);
  }
  let read = false;
  assert.deepEqual(await h.driver.begin({ get browserSessionId() { read = true; return browserSessionId; } }), failure);
  assert.equal(read, false); assert.equal(h.calls.begin, 0);
  assert.deepEqual(h.driver.discard({ browserSessionId, all: true }), failure);
  const start = await h.driver.begin({ browserSessionId });
  assert.deepEqual(await h.driver.complete({ browserSessionId, callbackUrl: callback(start), authority: true }), failure);
  assert.equal(h.calls.complete, 0);
});
test('deadline is checked both before and after foundation work', async () => {
  let now = 1_000_000;
  const h = stub(options => { options.now = () => now; });
  const browserSessionId = binding(); const start = await h.driver.begin({ browserSessionId });
  now += 300_000;
  assert.deepEqual(await h.driver.complete({ browserSessionId, callbackUrl: callback(start) }), failure);
  assert.equal(h.calls.complete, 0);
  const after = stub(options => { options.now = () => now; options.identity.complete = async () => { now += 300_000; return { ok: true, principal: after.principal }; }; });
  const second = await after.driver.begin({ browserSessionId });
  assert.deepEqual(await after.driver.complete({ browserSessionId, callbackUrl: callback(second) }), failure);
});
test('rollback permanently discards pending flow even after wall clock recovers', async () => {
  let now = 1_000_000; const h = stub(options => { options.now = () => now; }); const browserSessionId = binding();
  const start = await h.driver.begin({ browserSessionId }); now--;
  assert.deepEqual(await h.driver.complete({ browserSessionId, callbackUrl: callback(start) }), failure);
  now++;
  assert.deepEqual(await h.driver.complete({ browserSessionId, callbackUrl: callback(start) }), failure);
  assert.equal(h.calls.complete, 0); assert.equal((await h.driver.begin({ browserSessionId })).ok, true);
});
test('invalid runtime clock clears pending flow without exposing clock errors', async () => {
  let state = 1_000_000; const h = stub(options => { options.now = () => { if (state === 'throw') throw Error('PRIVATE_SENTINEL'); return state; }; });
  for (const invalid of [NaN, -1, Number.MAX_SAFE_INTEGER, 'throw']) {
    state = 1_000_000; const browserSessionId = binding(); const start = await h.driver.begin({ browserSessionId });
    state = invalid;
    assert.deepEqual(await h.driver.complete({ browserSessionId, callbackUrl: callback(start) }), failure);
    state = 1_000_000;
    assert.deepEqual(await h.driver.complete({ browserSessionId, callbackUrl: callback(start) }), failure);
  }
  assert.equal(h.calls.complete, 0);
});
test('capacity reserves 128 entries before begin settles, with no automatic retry', async () => {
  const pending = [];
  const h = stub(options => { options.identity.begin = () => { const p = Promise.withResolvers(); pending.push(p); return p.promise; }; });
  const runs = Array.from({ length: 128 }, () => h.driver.begin({ browserSessionId: binding() }));
  assert.deepEqual(await h.driver.begin({ browserSessionId: binding() }), failure); assert.equal(pending.length, 128);
  pending.forEach(p => p.resolve({ ok: true, authorizationUrl: authorization() }));
  assert.ok((await Promise.all(runs)).every(result => result.ok));
});
test('capacity reopens on discard and expiry but does not evict a live unrelated flow', async () => {
  let now = 1_000_000; const h = stub(options => { options.now = () => now; });
  const ids = Array.from({ length: 128 }, binding);
  const starts = await Promise.all(ids.map(browserSessionId => h.driver.begin({ browserSessionId })));
  assert.deepEqual(await h.driver.begin({ browserSessionId: binding() }), failure);
  h.driver.discard({ browserSessionId: ids[0] });
  assert.equal((await h.driver.begin({ browserSessionId: binding() })).ok, true);
  assert.equal((await h.driver.complete({ browserSessionId: ids[1], callbackUrl: callback(starts[1]) })).ok, true);
  now += 300_000; assert.equal((await h.driver.begin({ browserSessionId: binding() })).ok, true);
});
for (const action of ['discard', 'replacement']) test(`${action} while begin awaits cannot publish its obsolete redirect`, async () => {
  const waiting = Promise.withResolvers(); let first = true;
  const h = stub(options => { options.identity.begin = () => { if (first) { first = false; return waiting.promise; } return { ok: true, authorizationUrl: authorization() }; }; });
  const browserSessionId = binding(); const old = h.driver.begin({ browserSessionId });
  if (action === 'discard') h.driver.discard({ browserSessionId });
  else assert.equal((await h.driver.begin({ browserSessionId })).ok, true);
  waiting.resolve({ ok: true, authorizationUrl: authorization() }); assert.deepEqual(await old, failure);
});
for (const action of ['discard', 'replacement']) test(`${action} during completion prevents stale principal success`, async () => {
  const waiting = Promise.withResolvers(); const entered = Promise.withResolvers(); let first = true;
  const h = stub(options => { options.identity.complete = () => { if (first) { first = false; entered.resolve(); return waiting.promise; } return { ok: true, principal: h.principal }; }; });
  const browserSessionId = binding(); const start = await h.driver.begin({ browserSessionId });
  const old = h.driver.complete({ browserSessionId, callbackUrl: callback(start) }); await entered.promise;
  let fresh;
  if (action === 'discard') h.driver.discard({ browserSessionId });
  else fresh = await h.driver.begin({ browserSessionId });
  waiting.resolve({ ok: true, principal: h.principal }); assert.deepEqual(await old, failure);
  if (fresh) assert.equal((await h.driver.complete({ browserSessionId, callbackUrl: callback(fresh) })).ok, true);
});
test('premature callback cancels unfinished begin and invokes no code exchange', async () => {
  const waiting = Promise.withResolvers(); const h = stub(options => { options.identity.begin = () => waiting.promise; });
  const browserSessionId = binding(); const start = h.driver.begin({ browserSessionId });
  assert.deepEqual(await h.driver.complete({ browserSessionId, callbackUrl: callback({ authorizationUrl: authorization() }) }), failure);
  waiting.resolve({ ok: true, authorizationUrl: authorization() }); assert.deepEqual(await start, failure);
  assert.equal(h.calls.complete, 0);
});
test('unfinished completion retains its admission slot until settled or explicitly discarded', async () => {
  const waiting = Promise.withResolvers(); const entered = Promise.withResolvers();
  const h = stub(options => { options.identity.complete = () => { entered.resolve(); return waiting.promise; }; });
  const ids = Array.from({ length: 128 }, binding);
  const starts = await Promise.all(ids.map(browserSessionId => h.driver.begin({ browserSessionId })));
  const completion = h.driver.complete({ browserSessionId: ids[0], callbackUrl: callback(starts[0]) }); await entered.promise;
  assert.deepEqual(await h.driver.begin({ browserSessionId: binding() }), failure);
  waiting.resolve({ ok: true, principal: h.principal }); assert.equal((await completion).ok, true);
  assert.equal((await h.driver.begin({ browserSessionId: binding() })).ok, true);
});
