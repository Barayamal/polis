/** Actual TLS wire/navigation model, not a rendered browser or live provider. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { connect } from 'node:net';
import { request as httpsRequest } from 'node:https';
import { readFileSync } from 'node:fs';
import { createLocalBrowser, HTTPS_COOKIE_NAME, TRANSACTION_COOKIE_NAME } from '../local-browser/browser-server.mjs';
import { createRedirectTlsLab } from '../identity-foundation/redirect-tls-lab.mjs';
import { createHttpsRedirectDriver } from '../identity-foundation/https-redirect-driver.mjs';

const token = () => randomBytes(32).toString('base64url');
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
const seed = JSON.parse(readFileSync(new URL('../seed-statements.json', import.meta.url), 'utf8'))[0];
const nav = { 'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document' };
const apiMetadata = { 'sec-fetch-site': 'same-origin', 'sec-fetch-mode': 'same-origin', 'sec-fetch-dest': 'empty' };

async function fixture(t, options = {}) {
  const lab = await createRedirectTlsLab(); let browser;
  t.after(async () => { await browser?.close(); await lab.close(); });
  const driver = createHttpsRedirectDriver({ mode: 'SYNTHETIC_ONLY', identity: lab.identity,
    authorizationEndpoint: lab.authorizationEndpoint, callbackUri: lab.callbackUri });
  const authToken = token(); const participationToken = token(); const invitationToken = token();
  let authenticationCalls = 0; let registrations = 0;
  const backend = {
    async authenticateIdentity(principal) {
      authenticationCalls++;
      assert.equal(lab.identity.isVerifiedPrincipal(principal), true);
      await options.authenticate?.();
      return { mode: 'SYNTHETIC_ONLY', assurance: 'OIDC_ID_TOKEN_VERIFIED', fixtureAuthToken: authToken };
    },
    async request(path, body, credential) {
      if (path === '/session/logout') return { status: 200, body: {} };
      if (path === '/invitations/redeem') return body.invitationToken === invitationToken && credential === authToken
        ? { status: 200, body: { mode: 'SYNTHETIC_ONLY', participationToken } } : { status: 403, body: {} };
      if (path === '/polis/next-comment' && credential === participationToken)
        return { status: 200, body: { tid: 0, txt: seed } };
      if (path === '/polis/votes' && credential === participationToken) return { status: 200, body: { nextComment: null } };
      return { status: 403, body: {} };
    },
  };
  browser = createLocalBrowser({ mode: 'fixture-only', backend, oidcDriver: options.driver?.(driver) ?? driver,
    httpsRedirect: lab.browserTls, ...(options.now ? { now: options.now } : {}),
    registrationBridge: { mode: 'SYNTHETIC_ONLY', async register({ principal }) {
      assert.equal(lab.identity.isVerifiedPrincipal(principal), true); registrations++;
      return { status: 'SUBMITTED_NOT_APPROVED', registrationId: randomUUID() };
    } } });
  assert.equal(await browser.listen(lab.browserPort), lab.browserTls.origin);
  const cookies = new Map();
  const remember = res => {
    for (const line of res.headers['set-cookie'] ?? []) {
      const [pair, ...attrs] = line.split(';').map(v => v.trim()); const split = pair.indexOf('=');
      const name = pair.slice(0, split); const value = pair.slice(split + 1);
      if (attrs.includes('Max-Age=0')) cookies.delete(name); else cookies.set(name, { value, attrs });
    }
    return res;
  };
  const cookie = (crossSite = false) => [...cookies].filter(([, item]) => !crossSite || item.attrs.includes('SameSite=Lax'))
    .map(([name, item]) => `${name}=${item.value}`).join('; ');
  let csrf;
  async function api(path, body, headers = {}) {
    const result = remember(await lab.request(lab.browserTls.origin + path, {
      method: body === undefined ? 'GET' : 'POST', headers: { ...apiMetadata, cookie: cookie(),
        ...(body === undefined ? {} : { origin: lab.browserTls.origin, 'content-type': 'application/json', 'x-csrf-token': csrf }), ...headers },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    }));
    const data = JSON.parse(result.body); if (data.csrf) csrf = data.csrf;
    return { ...result, data };
  }
  async function start() { await api('/api/session'); const result = await api('/api/oidc/start', {});
    assert.equal(result.status, 200); return result; }
  async function authorize(url) { const result = await lab.request(url, { headers: nav });
    assert.equal(result.status, 303); return result.headers.location; }
  async function callback(url, headers = {}) { return remember(await lab.request(url, { headers: { ...nav, cookie: cookie(true), ...headers } })); }
  return { lab, browser, cookies, cookie, api, start, authorize, callback, remember, driver, authToken, participationToken,
    invitationToken, authenticationCalls: () => authenticationCalls, registrations: () => registrations };
}

test('actual HTTPS authorization redirect creates an opaque BFF session then registration, bound invitation and fixed voting work', async t => {
  const f = await fixture(t); const started = await f.start();
  assert.equal(started.data.authenticationTransport, 'HTTPS_REDIRECT_LAB');
  assert.equal(started.data.realBrowserEngineTested, false);
  assert.equal(f.cookies.get(HTTPS_COOKIE_NAME).attrs.includes('SameSite=Strict'), true);
  assert.equal(f.cookies.get(TRANSACTION_COOKIE_NAME).attrs.includes('SameSite=Lax'), true);
  for (const item of f.cookies.values()) for (const attr of ['Path=/', 'HttpOnly', 'Secure']) assert.ok(item.attrs.includes(attr));
  assert.equal(f.cookies.get(TRANSACTION_COOKIE_NAME).attrs.includes('Max-Age=300'), true);
  assert.doesNotMatch(f.cookie(true), new RegExp(HTTPS_COOKIE_NAME));
  const callbackUrl = await f.authorize(started.data.authorizationUrl);
  const callback = await f.callback(callbackUrl);
  assert.equal(callback.status, 303); assert.equal(callback.headers.location, '/'); assert.equal(callback.body, '');
  assert.equal(callback.headers['cache-control'], 'no-store'); assert.equal(callback.headers['referrer-policy'], 'no-referrer');
  assert.equal(f.cookies.has(TRANSACTION_COOKIE_NAME), false);
  const landing = await f.lab.request(f.lab.browserTls.origin + '/', { headers: nav });
  assert.equal(landing.status, 200); assert.equal(landing.headers['set-cookie'], undefined);
  const session = await f.api('/api/session'); assert.equal(session.data.phase, 'authenticated');
  assert.equal((await f.api('/api/next-comment')).status, 403);
  const registration = await f.api('/api/registration', { adultSelfAttested: true, eligibilitySelfAttested: true,
    registrationConsent: true, consentVersion: 'synthetic-registration-v1' });
  assert.equal(registration.data.registrationStatus, 'SUBMITTED_NOT_APPROVED'); assert.equal(f.registrations(), 1);
  assert.equal((await f.api('/api/redeem', { invitationToken: token() })).status, 403);
  assert.equal((await f.api('/api/redeem', { invitationToken: f.invitationToken })).data.phase, 'participant');
  const next = await f.api('/api/next-comment'); assert.equal(next.data.statement.tid, 0);
  assert.equal((await f.api('/api/votes', { tid: 0, vote: 0 })).data.saved, true);
  const projection = JSON.stringify([started, callback, session, registration]);
  for (const secret of [f.authToken, f.participationToken, 'invented-subject-1', 'invented@example.invalid', 'invented-access-token'])
    assert.equal(projection.includes(secret), false);
  assert.equal(f.authenticationCalls(), 1);
  assert.ok(f.lab.summary().authorize >= 1 && f.lab.summary().token >= 1 && f.lab.summary().jwks >= 1);
});

for (const mutation of ['missing-cookie', 'wrong-cookie', 'duplicate-cookie', 'state', 'issuer', 'duplicate-code', 'extra-parameter', 'provider-error']) {
  test(`HTTPS callback rejects ${mutation}, strips query and cannot sign in`, async t => {
    const f = await fixture(t); const started = await f.start(); const url = new URL(await f.authorize(started.data.authorizationUrl));
    const headers = {};
    if (mutation === 'missing-cookie') headers.cookie = '';
    if (mutation === 'wrong-cookie') headers.cookie = `${TRANSACTION_COOKIE_NAME}=${token()}`;
    if (mutation === 'duplicate-cookie') headers.cookie = f.cookie(true) + '; ' + f.cookie(true);
    if (mutation === 'state') url.searchParams.set('state', token());
    if (mutation === 'issuer') url.searchParams.set('iss', 'https://wrong.example.invalid/');
    if (mutation === 'duplicate-code') url.searchParams.append('code', token());
    if (mutation === 'extra-parameter') url.searchParams.set('returnTo', 'https://external.example.invalid/');
    if (mutation === 'provider-error') { url.searchParams.delete('code'); url.searchParams.set('error', 'access_denied');
      url.searchParams.set('error_description', 'PRIVATE_DESCRIPTION'); url.searchParams.set('error_uri', 'https://external.example.invalid/'); }
    const result = await f.callback(url.href, headers); assert.equal(result.status, 303); assert.equal(result.headers.location, '/');
    assert.equal(result.body, ''); assert.equal(f.authenticationCalls(), 0);
    assert.equal((await f.api('/api/session')).data.phase, 'visitor');
  });
}

for (const metadata of [ {}, { 'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty' },
  { 'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'iframe' },
  { ...nav, origin: 'https://wrong.example.invalid' } ]) {
  test(`HTTPS callback requires top-level navigation metadata ${JSON.stringify(metadata)}`, async t => {
    const f = await fixture(t); const started = await f.start(); const url = await f.authorize(started.data.authorizationUrl);
    const result = await f.lab.request(url, { headers: { ...metadata, cookie: f.cookie(true) } });
    assert.equal(result.status, 403); assert.equal(f.authenticationCalls(), 0);
  });
}

test('callback replay cannot mint a second session and does not clear an already authenticated main cookie', async t => {
  const f = await fixture(t); const started = await f.start(); const url = await f.authorize(started.data.authorizationUrl);
  const transactionCookie = f.cookie(true); await f.callback(url);
  const value = f.cookies.get(HTTPS_COOKIE_NAME).value;
  await f.callback(url, { cookie: transactionCookie });
  assert.equal(f.cookies.get(HTTPS_COOKIE_NAME).value, value);
  assert.equal((await f.api('/api/session')).data.phase, 'authenticated'); assert.equal(f.authenticationCalls(), 1);
});

test('cross-site GET callback without the Lax transaction cannot adopt a Strict application cookie', async t => {
  const f = await fixture(t); const started = await f.start(); const url = await f.authorize(started.data.authorizationUrl);
  await f.callback(url, { cookie: `${HTTPS_COOKIE_NAME}=${f.cookies.get(HTTPS_COOKIE_NAME).value}` });
  assert.equal(f.authenticationCalls(), 0);
});

test('HTTPS start still requires same-origin CSRF; fixture and manual callback endpoints do not authenticate', async t => {
  const f = await fixture(t); await f.api('/api/session');
  assert.equal((await f.api('/api/oidc/start', {}, { 'x-csrf-token': token() })).status, 403);
  assert.equal((await f.api('/api/oidc/start', {}, { origin: 'https://wrong.example.invalid' })).status, 403);
  assert.equal((await f.api('/api/oidc/start', {}, { 'sec-fetch-site': 'cross-site' })).status, 403);
  assert.equal((await f.api('/api/login', {})).status, 404);
  assert.equal((await f.api('/api/oidc/callback', { callbackUrl: f.lab.callbackUri })).status, 404);
  assert.equal(f.lab.summary().authorize, 0); assert.equal(f.authenticationCalls(), 0);
});

test('cross-site landing exception grants no API access or cross-site script access', async t => {
  const f = await fixture(t);
  for (const path of ['/api/session', '/app.js', '/style.css']) {
    assert.equal((await f.lab.request(f.lab.browserTls.origin + path, { headers: nav })).status, 403);
  }
});

test('new start invalidates the prior transaction even if its original cookie/code returns', async t => {
  const f = await fixture(t); const one = await f.start(); const firstCookie = f.cookie(true);
  const oldUrl = await f.authorize(one.data.authorizationUrl); const two = await f.start();
  const nextCookie = f.cookie(true); await f.callback(oldUrl, { cookie: firstCookie }); assert.equal(f.authenticationCalls(), 0);
  assert.equal(f.cookie(true), nextCookie);
  await f.callback(await f.authorize(two.data.authorizationUrl), { cookie: nextCookie });
  assert.equal((await f.api('/api/session')).data.phase, 'authenticated');
});

test('logout cancels pending authorization before callback', async t => {
  const f = await fixture(t); const started = await f.start(); const tx = f.cookie(true);
  const url = await f.authorize(started.data.authorizationUrl); assert.equal((await f.api('/api/logout', {})).status, 200);
  await f.callback(url, { cookie: tx }); assert.equal(f.authenticationCalls(), 0);
  assert.equal((await f.api('/api/session')).data.phase, 'visitor');
});

test('logout during asynchronous callback authentication prevents a late authenticated cookie', async t => {
  const entered = deferred(); const release = deferred();
  const f = await fixture(t, { authenticate: async () => { entered.resolve(); await release.promise; } });
  t.after(() => release.resolve());
  const started = await f.start(); const url = await f.authorize(started.data.authorizationUrl);
  const pending = f.callback(url); await entered.promise;
  assert.equal((await f.api('/api/logout', {})).status, 200); release.resolve();
  const result = await pending;
  assert.equal((result.headers['set-cookie'] ?? []).some(value => value.startsWith(HTTPS_COOKIE_NAME + '=')), false);
  assert.equal((await f.api('/api/session')).data.phase, 'visitor');
});

test('service close during callback authentication cancels late session creation', async t => {
  const entered = deferred(); const release = deferred();
  const f = await fixture(t, { authenticate: async () => { entered.resolve(); await release.promise; } });
  const started = await f.start(); const url = await f.authorize(started.data.authorizationUrl);
  const pending = f.callback(url); await entered.promise; const closing = f.browser.close(); release.resolve();
  const result = await pending; await closing;
  assert.equal((result.headers['set-cookie'] ?? []).some(value => value.startsWith(HTTPS_COOKIE_NAME + '=')), false);
  await new Promise((resolve, reject) => {
    const socket = connect({ host: '127.0.0.1', port: f.lab.browserPort });
    socket.once('connect', () => { socket.destroy(); reject(new Error('Owned test browser still listening.')); });
    socket.once('error', error => { socket.destroy(); error.code === 'ECONNREFUSED' ? resolve() : reject(error); });
  });
});

test('late callback response cannot clear a newer login transaction cookie after logout and restart', async t => {
  const entered = deferred(); const release = deferred(); let first = true;
  const f = await fixture(t, { authenticate: async () => { if (first) { first = false; entered.resolve(); await release.promise; } } });
  const startA = await f.start(); const callbackA = await f.authorize(startA.data.authorizationUrl);
  const pending = f.callback(callbackA); await entered.promise;
  await f.api('/api/logout', {}); const startB = await f.start(); const cookieB = f.cookie(true);
  release.resolve(); const stale = await pending;
  assert.equal(stale.headers['set-cookie'], undefined); assert.equal(f.cookie(true), cookieB);
  await f.callback(await f.authorize(startB.data.authorizationUrl));
  assert.equal((await f.api('/api/session')).data.phase, 'authenticated');
});

test('five-minute transaction expiration denies otherwise valid callback before backend authentication', async t => {
  let at = Date.now(); const f = await fixture(t, { now: () => at });
  const started = await f.start(); const url = await f.authorize(started.data.authorizationUrl);
  at += 300_000; await f.callback(url); assert.equal(f.authenticationCalls(), 0);
  assert.equal((await f.api('/api/session')).data.phase, 'visitor');
});

test('disconnected callback drains on close and cannot begin backend authentication after its identity exchange', async t => {
  const entered = deferred(); const release = deferred();
  const f = await fixture(t, { driver: driver => ({ ...driver, async complete(input) {
    const result = await driver.complete(input); entered.resolve(); await release.promise; return result;
  } }) });
  const started = await f.start(); const url = new URL(await f.authorize(started.data.authorizationUrl));
  let request;
  const disconnected = new Promise(resolve => {
    request = httpsRequest({ hostname: '127.0.0.1', port: f.lab.browserPort, servername: 'browser.example.invalid',
      ca: f.lab.browserTls.cert, rejectUnauthorized: true, agent: false, path: url.pathname + url.search,
      headers: { ...nav, cookie: f.cookie(true), host: url.host } }, response => response.resume());
    request.once('error', () => resolve()); request.end();
  });
  await entered.promise; request.destroy(); await disconnected;
  await new Promise(resolve => setTimeout(resolve, 20));
  let closed = false; const closing = f.browser.close().then(() => { closed = true; });
  await new Promise(resolve => setImmediate(resolve)); assert.equal(closed, false);
  release.resolve(); await closing; assert.equal(f.authenticationCalls(), 0);
});

test('malicious authorization destination from an injected adapter never leaves the BFF', async t => {
  const f = await fixture(t, { driver: driver => ({ ...driver, async begin() {
    return { ok: true, authorizationUrl: 'https://wrong.example.invalid/authorize?redirect_uri=' + encodeURIComponent(driver.callbackUri) };
  } }) });
  await f.api('/api/session'); const result = await f.api('/api/oidc/start', {});
  assert.equal(result.status, 503); assert.equal(result.body.includes('wrong.example.invalid'), false);
  assert.equal(f.cookies.has(TRANSACTION_COOKIE_NAME), false);
});

test('explicit HTTPS configuration cannot silently bind an ephemeral or different port', async t => {
  const f = await fixture(t); await f.browser.close();
  const another = createLocalBrowser({ mode: 'fixture-only', backend: { request() {}, authenticateIdentity() {} },
    oidcDriver: f.driver, httpsRedirect: f.lab.browserTls });
  t.after(() => another.close());
  await assert.rejects(another.listen(0), /exact configured/);
  await assert.rejects(another.listen(f.lab.browserPort === 65535 ? 65534 : f.lab.browserPort + 1), /exact configured/);
});
