/** Ephemeral BFF HTTP plus invented identity/registration/backend models only.
 * No browser, WordPress, Docker, external provider or persistent store is used.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { createLocalBrowser, MODE } from './browser-server.mjs';
import { CONSENT_VERSION } from '../wordpress-identity/registration-issuer.mjs';

const opaque = () => randomBytes(32).toString('base64url');
const declarations = () => ({ adultSelfAttested: true, eligibilitySelfAttested: true, registrationConsent: true, consentVersion: CONSENT_VERSION });
async function harness(t, settings = {}) {
  let stamp = 1_900_000_000_000; let currentPrincipal; let principalLive = true;
  let operation = settings.operation ?? (async () => ({ registrationId: randomUUID(), status: 'SUBMITTED_NOT_APPROVED' }));
  const calls = []; const backendCalls = []; const minted = new WeakSet(); let receiptCalls = 0;
  const driver = { mode: 'SYNTHETIC_ONLY', begin: async () => ({ ok: true }), discard() {},
    isVerifiedPrincipal: principal => principalLive && minted.has(principal),
    async complete() { currentPrincipal = Object.freeze({ mode: 'SYNTHETIC_ONLY', assurance: 'OIDC_ID_TOKEN_VERIFIED' });
      minted.add(currentPrincipal); return { ok: true, principal: currentPrincipal }; } };
  const backend = {
    authenticateIdentity: async principal => {
      assert.ok(principal === currentPrincipal);
      return { mode: 'SYNTHETIC_ONLY', assurance: 'OIDC_ID_TOKEN_VERIFIED', fixtureAuthToken: opaque() };
    },
    async request(path, body, credential) {
      backendCalls.push({ path, body, credential });
      if (path === '/session/logout') return { status: 200, body: {} };
      if (path === '/invitations/redeem' && settings.allowRedeem) return { status: 201, body: { mode: 'SYNTHETIC_ONLY', participationToken: opaque() } };
      return { status: 403, body: {} };
    },
  };
  const bridge = { mode: 'SYNTHETIC_ONLY', async register(request) { calls.push(request); return operation(request); } };
  const app = createLocalBrowser({ mode: MODE, backend, now: () => stamp, sessionLifetimeMs: settings.lifetime ?? 60_000,
    oidcDriver: driver, registrationBridge: bridge, registrationIssuer: { mode: 'SYNTHETIC_ONLY',
      async issue() { receiptCalls++; throw new Error('synthetic_private_receipt_sentinel'); } } });
  const origin = await app.listen(0); t.after(() => app.close());
  const client = () => {
    let cookie = ''; let csrf = '';
    const request = async (path, body, overrides = {}) => {
      const response = await fetch(origin + path, { method: body === undefined ? 'GET' : 'POST', redirect: 'error',
        headers: { 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'same-origin', 'Sec-Fetch-Dest': 'empty',
          ...(cookie ? { Cookie: cookie } : {}), ...(body === undefined ? {} : { Origin: origin,
            'Content-Type': 'application/json', 'X-CSRF-Token': csrf }), ...overrides },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
      const text = await response.text(); const result = JSON.parse(text);
      const setCookie = response.headers.getSetCookie()[0];
      if (setCookie) cookie = setCookie.includes('Max-Age=0') ? '' : setCookie.split(';')[0];
      if (typeof result.csrf === 'string') csrf = result.csrf;
      return { status: response.status, body: result, text, headers: response.headers };
    };
    return { request, async login() {
      await request('/api/session'); assert.equal((await request('/api/oidc/start', {})).status, 200);
      const result = await request('/api/oidc/callback', { callbackUrl: 'synthetic_model_callback' }); assert.equal(result.status, 200); return result;
    } };
  };
  const browser = client(); await browser.login();
  return { browser, client, origin, calls, backendCalls, principal: () => currentPrincipal, receiptCalls: () => receiptCalls,
    advance(ms = 60_001) { stamp += ms; }, expirePrincipal() { principalLive = false; }, setOperation(fn) { operation = fn; } };
}

test('seamless BFF accepts only the four declaration fields and privately binds current principal and browser deadline', async t => {
  const h = await harness(t); const result = await h.browser.request('/api/registration', declarations());
  assert.equal(result.status, 200); assert.equal(result.body.phase, 'authenticated');
  assert.equal(result.body.registrationStatus, 'SUBMITTED_NOT_APPROVED'); assert.equal(result.body.registrationEnabled, true);
  assert.match(result.body.registrationId, /^[0-9a-f-]{36}$/u);
  assert.equal(h.calls.length, 1); assert.ok(h.calls[0].principal === h.principal());
  assert.equal(Number.isSafeInteger(h.calls[0].browserDeadline), true);
  assert.deepEqual(Object.keys(h.calls[0].input).sort(), Object.keys(declarations()).sort());
  assert.equal(h.backendCalls.length, 0);
  assert.equal((await h.browser.request('/api/participation-init')).status, 403);
});

test('registration rejects unknown fields and missing or non-boolean declarations before the bridge', async t => {
  const h = await harness(t);
  for (const body of [{ ...declarations(), fixture: 'synthetic_caller' }, { ...declarations(), challenge: {} },
    { ...declarations(), receipt: {} }, { ...declarations(), principal: {} }, { ...declarations(), registrationId: randomUUID() },
    { ...declarations(), adultSelfAttested: false }, { ...declarations(), eligibilitySelfAttested: 'true' },
    { ...declarations(), registrationConsent: [] }, { ...declarations(), consentVersion: 'wrong' }, {}, null, []]) {
    assert.equal((await h.browser.request('/api/registration', body)).status, 400);
  }
  assert.equal(h.calls.length, 0);
});

test('exact same-origin credentials with only CSRF altered are denied before bridge work', async t => {
  const h = await harness(t);
  assert.equal((await h.browser.request('/api/registration', declarations(), { 'X-CSRF-Token': opaque() })).status, 403);
  assert.equal(h.calls.length, 0);
  assert.equal((await h.browser.request('/api/registration', declarations())).status, 200);
});

test('registration requires signed-in live principal and refuses visitors, participants and expired identities', async t => {
  const h = await harness(t, { allowRedeem: true }); const visitor = h.client(); await visitor.request('/api/session');
  assert.equal((await visitor.request('/api/registration', declarations())).status, 403);
  assert.equal((await h.browser.request('/api/redeem', { invitationToken: opaque() })).status, 200);
  assert.equal((await h.browser.request('/api/registration', declarations())).status, 403);
  const other = h.client(); await other.login(); h.expirePrincipal();
  assert.equal((await other.request('/api/registration', declarations())).status, 401);
  assert.equal(h.calls.length, 0);
});

test('bridge mode disables the manual receipt endpoint even when an issuer is configured', async t => {
  const h = await harness(t);
  assert.equal((await h.browser.request('/api/registration/receipt', { ...declarations(), challenge: {} })).status, 404);
  assert.equal(h.receiptCalls(), 0); assert.equal(h.calls.length, 0);
});

test('concurrent registration submissions serialize to one bridge attempt and retain the confirmed pending result', async t => {
  const h = await harness(t); let release; let started;
  const active = new Promise(resolve => { started = resolve; }); const hold = new Promise(resolve => { release = resolve; });
  h.setOperation(async () => { started(); await hold; return { registrationId: randomUUID(), status: 'SUBMITTED_NOT_APPROVED' }; });
  const first = h.browser.request('/api/registration', declarations()); await active;
  const second = h.browser.request('/api/registration', declarations()); release();
  assert.deepEqual((await Promise.all([first, second])).map(result => result.status).sort(), [200, 409]);
  assert.equal(h.calls.length, 1);
  assert.equal((await h.browser.request('/api/session')).body.registrationStatus, 'SUBMITTED_NOT_APPROVED');
});

test('uncertain registration outcome is latched and never automatically retried or disclosed', async t => {
  const h = await harness(t, { operation: async () => { throw new Error('synthetic_private_receipt_sentinel'); } });
  const outcome = await h.browser.request('/api/registration', declarations());
  assert.equal(outcome.status, 503); assert.equal(outcome.text.includes('synthetic_private_receipt_sentinel'), false);
  assert.match(outcome.body.error, /may already be recorded/u);
  const observed = await h.browser.request('/api/session');
  assert.equal(observed.body.registrationStatus, 'OUTCOME_UNCONFIRMED');
  assert.equal(Object.hasOwn(observed.body, 'registrationId'), false);
  assert.equal((await h.browser.request('/api/registration', declarations())).status, 409);
  assert.equal(h.calls.length, 1);
});

test('invalid bridge ACK cannot be adopted and extra private fields never enter the browser projection', async t => {
  const h = await harness(t, { operation: async () => ({ registrationId: 'not-a-reference', status: 'SUBMITTED_NOT_APPROVED',
    receipt: 'synthetic_private_receipt_sentinel' }) });
  assert.equal((await h.browser.request('/api/registration', declarations())).status, 503);
  assert.equal((await h.browser.request('/api/session')).body.registrationStatus, 'OUTCOME_UNCONFIRMED');
  const other = h.client(); await other.login();
  h.setOperation(async () => ({ registrationId: randomUUID(), status: 'SUBMITTED_NOT_APPROVED',
    receipt: 'synthetic_private_receipt_sentinel', fixture: 'synthetic_private_fixture', cookie: opaque(), csrfToken: opaque() }));
  const result = await other.request('/api/registration', declarations()); assert.equal(result.status, 200);
  for (const field of ['receipt', 'fixture', 'accountId', 'cookie', 'csrfToken', 'challenge', 'authToken']) assert.equal(Object.hasOwn(result.body, field), false);
  assert.equal(result.text.includes('synthetic_private_'), false);
});

for (const expiry of ['browser', 'principal']) test(`${expiry} expiry after possible registration commit withholds result and ends the session`, async t => {
  const h = await harness(t);
  h.setOperation(async () => { if (expiry === 'browser') h.advance(); else h.expirePrincipal();
    return { registrationId: randomUUID(), status: 'SUBMITTED_NOT_APPROVED' }; });
  const result = await h.browser.request('/api/registration', declarations());
  assert.equal(result.status, 401); assert.match(result.body.error, /may already be recorded/u);
  assert.equal(Object.hasOwn(result.body, 'registrationId'), false);
  assert.equal(h.calls.length, 1);
  assert.equal((await h.browser.request('/api/session')).body.phase, 'visitor');
});

test('logout removes the browser registration reference and does not repeat its submission', async t => {
  const h = await harness(t); await h.browser.request('/api/registration', declarations());
  assert.equal((await h.browser.request('/api/logout', {})).status, 200);
  const session = await h.browser.request('/api/session');
  assert.equal(session.body.phase, 'visitor'); assert.equal(session.body.registrationStatus, 'NOT_SUBMITTED');
  assert.equal(Object.hasOwn(session.body, 'registrationId'), false);
  assert.equal(h.calls.length, 1); assert.equal(h.backendCalls.filter(call => call.path === '/session/logout').length, 1);
});
