import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readFileSync, realpathSync, rmSync } from 'node:fs';
import { request } from 'node:https';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createProductionBrowser } from './browser.mjs';
import { createProductionFixture } from './test-support/production-fixture.mjs';

// Protocol fixtures only: invented claims/notices, generated keys, actual TLS
// and branded runtime dependencies. No real provider, account or WordPress is
// contacted; cookie attributes here are not browser-engine evidence.
const ORIGIN = 'https://participant.example.invalid';
const CALLBACK = `${ORIGIN}/oidc/callback`;
const COOKIE = '__Host-fncp-session';
const TRANSACTION = '__Host-fncp-transaction';
const privateOutput = /acct_|fncp_[A-Za-z0-9_-]{43}|invented-subject|invented@example|SENSITIVE_|PRIVATE_CLIENT|access_token|refresh_token|id_token|"xid"|"pid"|"uid"/u;

function certificate() {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'fncp-browser-test-')));
  chmodSync(directory, 0o700);
  try {
    const key = join(directory, 'key.pem'); const cert = join(directory, 'cert.pem');
    const result = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
      '-noenc', '-days', '1', '-subj', '/CN=FNCP browser test', '-addext', 'subjectAltName=DNS:participant.example.invalid',
      '-keyout', key, '-out', cert], { stdio: ['ignore', 'pipe', 'pipe'], timeout: 10_000, maxBuffer: 8192 });
    assert.equal(result.status, 0, 'fresh test certificate created');
    chmodSync(key, 0o600); chmodSync(cert, 0o600);
    return { key: readFileSync(key), cert: readFileSync(cert) };
  } finally { rmSync(directory, { recursive: true, force: true }); }
}

async function until(fn, message = 'condition observed') {
  const deadline = performance.now() + 3000;
  while (!fn() && performance.now() < deadline) await new Promise(resolve => setTimeout(resolve, 5));
  assert.ok(fn(), message);
}

async function fixture(t, options = {}) {
  const cleanup = [];
  const h = await createProductionFixture({ after: fn => cleanup.push(fn) }, { callbackUri: CALLBACK });
  let browser;
  // The BFF owns and drains access before the protocol fixture removes its
  // databases and listeners. Test hooks run in registration order.
  t.after(async () => {
    let error;
    try { await browser?.close(); } catch (value) { error = value; }
    finally { for (const fn of cleanup) await fn(); }
    if (error) throw error;
  });
  const tls = certificate();
  const clock = options.now ?? (() => h.now());
  const settings = { origin: ORIGIN, tls, identity: h.identity, access: h.access, host: '127.0.0.1', port: options.port ?? 0, now: clock };
  browser = createProductionBrowser(settings);
  const { port } = options.autoStart === false ? {} : await browser.start();
  const jars = new Set();
  function client() {
    const jar = new Map(); jars.add(jar); let csrf = '';
    function headers(path, method, overrides = {}) {
      const cookie = [...jar].map(([name, value]) => `${name}=${value}`).join('; ');
      return { host: 'participant.example.invalid', connection: 'close',
        'sec-fetch-site': 'same-origin', 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty',
        ...(cookie ? { cookie } : {}), ...(csrf ? { 'x-csrf-token': csrf } : {}),
        ...(method === 'POST' ? { origin: ORIGIN, 'content-type': 'application/json' } : {}),
        ...overrides };
    }
    async function call(path, values, overrides = {}) {
      const method = overrides.method ?? (values === undefined ? 'GET' : 'POST');
      const raw = overrides.rawBody ?? (values === undefined ? undefined : JSON.stringify(values));
      return new Promise((resolve, reject) => {
        const req = request({ hostname: '127.0.0.1', port, servername: 'participant.example.invalid', ca: tls.cert,
          rejectUnauthorized: true, minVersion: 'TLSv1.2', agent: false, method, path,
          headers: headers(path, method, { ...(raw === undefined ? {} : { 'content-length': Buffer.byteLength(raw) }), ...overrides.headers }) }, res => {
          const chunks = []; res.on('data', chunk => chunks.push(chunk)); res.once('error', reject);
          res.once('end', () => {
            const text = Buffer.concat(chunks).toString('utf8'); let body;
            try { body = text && /application\/json/u.test(res.headers['content-type'] ?? '') ? JSON.parse(text) : text; }
            catch { reject(Error('invalid response JSON')); return; }
            if (overrides.saveCookies !== false) for (const cookie of res.headers['set-cookie'] ?? []) {
              const [name, value] = cookie.split(';')[0].split('=');
              if (!value || /Max-Age=0(?:;|$)/u.test(cookie)) jar.delete(name); else jar.set(name, value);
            }
            if (body?.csrf) csrf = body.csrf;
            resolve({ status: res.statusCode, headers: res.headers, body, text });
          });
        });
        req.setTimeout(10_000, () => req.destroy(Error('test request deadline')));
        req.once('error', reject); req.end(raw);
      });
    }
    async function login(entry = {}) {
      assert.equal((await call('/session')).status, 200);
      const anonymousCookie = jar.get(COOKIE);
      const begun = await call('/oidc/login', {}); assert.equal(begun.status, 200);
      const transactionCookie = jar.get(TRANSACTION);
      const callback = h.issuer.authorizationResponse(begun.body.authorizationUrl, entry);
      const target = new URL(callback);
      const completed = await call(target.pathname + target.search, undefined, { headers: {
        'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document', 'sec-fetch-user': '?1' } });
      assert.equal(completed.status, 303); assert.equal(completed.headers.location, '/');
      const status = await call('/session'); assert.equal(status.status, 200); assert.equal(status.body.authenticated, true);
      return { anonymousCookie, transactionCookie, sessionCookie: jar.get(COOKIE), callback, begun, completed, status };
    }
    function holdBody() {
      const req = request({ hostname: '127.0.0.1', port, servername: 'participant.example.invalid', ca: tls.cert,
        rejectUnauthorized: true, agent: false, method: 'POST', path: '/oidc/login',
        headers: headers('/oidc/login', 'POST', { 'content-length': '2' }) });
      req.on('error', () => {}); req.on('response', res => res.resume()); req.flushHeaders(); return req;
    }
    return { call, login, holdBody, jar, get csrf() { return csrf; } };
  }
  return { h, browser, settings, client, port };
}

test('factory rejects imitation brands, origin aliases, forwarding configuration and accessor injection', async t => {
  const x = await fixture(t);
  for (const patch of [{}, { identity: Object.freeze({ ...x.h.identity }) }, { access: Object.freeze({ ...x.h.access }) },
    { origin: 'http://participant.example.invalid' }, { origin: ORIGIN + '/' }, { origin: ORIGIN + '/callback' },
    { origin: 'https://wrong.example.invalid' }, { trustProxy: true }, { tls: { ...x.settings.tls, rejectUnauthorized: false } },
    { port: -1 }, { host: 'arbitrary.example.invalid' }]) {
    assert.throws(() => createProductionBrowser({ ...x.settings, ...patch }), { message: 'Production browser configuration rejected.' });
  }
  let touched = 0;
  const options = { ...x.settings }; Object.defineProperty(options, 'origin', { get() { touched++; return ORIGIN; }, enumerable: true });
  assert.throws(() => createProductionBrowser(options)); assert.equal(touched, 0);
  assert.equal(x.browser.snapshot().admissionClosed, false);
});

test('native verified HTTPS login rotates strict session cookies and consumes lax transaction without publishing identity', async t => {
  const x = await fixture(t); const c = x.client(); const result = await c.login();
  assert.notEqual(result.anonymousCookie, result.sessionCookie);
  assert.notEqual(result.transactionCookie, result.sessionCookie);
  assert.equal(c.jar.has(TRANSACTION), false);
  const setTransaction = result.begun.headers['set-cookie'].find(value => value.startsWith(TRANSACTION + '='));
  assert.match(setTransaction, /; Path=\/; Secure; HttpOnly; SameSite=Lax; Max-Age=300$/u);
  const setSession = result.completed.headers['set-cookie'].find(value => value.startsWith(COOKIE + '='));
  assert.match(setSession, /; Path=\/; Secure; HttpOnly; SameSite=Strict; Max-Age=[1-9][0-9]*$/u);
  assert.doesNotMatch(setSession + setTransaction, /Domain=/u);
  assert.doesNotMatch(result.status.text, privateOutput);
  assert.equal(result.status.body.participantAccessGranted, false);
  assert.equal(result.status.body.registrationState, 'unregistered');
  assert.equal(result.status.body.registrationReference, null);
  assert.equal(result.status.body.participationSession, false);
  assert.deepEqual(result.status.body.registrationNotice, x.h.access.registrationNotice());
  assert.equal(result.completed.body, '');
  assert.equal(result.completed.headers['referrer-policy'], 'no-referrer');
  assert.equal(result.completed.headers['cache-control'], 'no-store');
  assert.match(result.completed.headers['content-security-policy'], /frame-ancestors 'none'/u);
  assert.match(result.completed.headers['strict-transport-security'], /max-age=31536000/u);
});

test('old anonymous cookie, wrong transaction browser and callback replay cannot authenticate', async t => {
  const x = await fixture(t); const c = x.client(); const result = await c.login();
  const callback = new URL(result.callback);
  const nav = { 'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document' };
  for (const [cookie, status] of [['', 403], [`${TRANSACTION}=${result.transactionCookie}`, 401], [`${COOKIE}=${result.anonymousCookie}`, 401]]) {
    const response = await c.call(callback.pathname + callback.search, undefined, { headers: { ...nav, cookie }, saveCookies: false });
    assert.equal(response.status, status); assert.doesNotMatch(response.text, privateOutput);
    assert.ok(!response.text.includes(callback.search));
  }
  const oldSession = await c.call('/session', undefined, { headers: { cookie: `${COOKIE}=${result.anonymousCookie}` }, saveCookies: false });
  assert.equal(oldSession.body.authenticated, false);
});

test('callback metadata denies fetch/form/iframe completion before token exchange; the intended navigation still succeeds', async t => {
  const x = await fixture(t); const c = x.client(); await c.call('/session');
  const begun = await c.call('/oidc/login', {});
  const callback = new URL(x.h.issuer.authorizationResponse(begun.body.authorizationUrl));
  for (const headers of [
    { 'sec-fetch-site': 'same-origin', 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty' },
    { 'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'iframe' },
    { 'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document', origin: 'https://attacker.example.invalid' },
  ]) assert.equal((await c.call(callback.pathname + callback.search, undefined, { headers })).status, 403);
  assert.equal(x.h.issuer.calls.length, 0);
  assert.equal((await c.call(callback.pathname + callback.search, undefined, { headers: {
    'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document' } })).status, 303);
});

test('host, origin, fetch metadata, forwarded headers and synchronizer violations fail before login', async t => {
  const x = await fixture(t); const c = x.client(); await c.call('/session');
  for (const headers of [
    { host: 'attacker.example.invalid' }, { origin: 'https://attacker.example.invalid' }, { 'sec-fetch-site': 'cross-site' },
    { 'sec-fetch-mode': 'navigate' }, { 'sec-fetch-dest': 'iframe' }, { 'x-csrf-token': 'forged' },
    { forwarded: 'proto=https;host=participant.example.invalid' }, { 'x-forwarded-proto': 'https' },
    { 'x-forwarded-host': 'participant.example.invalid' }, { authorization: 'Bearer PRIVATE_MARKER' }, { 'x-fncp-account': 'acct_forged' },
  ]) {
    const response = await c.call('/oidc/login', {}, { headers }); assert.equal(response.status, 403);
    assert.doesNotMatch(response.text, /PRIVATE_MARKER|acct_forged|attacker/u);
  }
  assert.equal(x.h.issuer.calls.length, 0); assert.equal(x.browser.snapshot().transactions, 0);
});

test('unknown, administrative and normalized-alias routes cannot reach a capability', async t => {
  const x = await fixture(t); const c = x.client(); await c.call('/session');
  for (const path of ['/admin', '/activation', '/operator', '/test/auth', '/api/v3/votes', '/session?xid=untrusted',
    '/session?', '/nested/../session', '/%73ession', '//session', '/session/']) {
    const response = await c.call(path); assert.ok([400, 404].includes(response.status), path);
    assert.doesNotMatch(response.text, privateOutput);
  }
  assert.equal((await c.call('/health', {}, { method: 'POST' })).status, 404);
  assert.equal(x.h.issuer.calls.length, 0);
});

test('cookie duplication and unexpected ambient cookies cannot select a session', async t => {
  const x = await fixture(t); const c = x.client(); await c.call('/session');
  const value = c.jar.get(COOKIE);
  for (const cookie of [`${COOKIE}=${value}; ${COOKIE}=${value}`, `${COOKIE}=${value}; account=forged`, `${COOKIE}=short`, `${COOKIE}=${value}=extra`]) {
    assert.equal((await c.call('/session', undefined, { headers: { cookie }, saveCookies: false })).status, 403);
  }
});

test('malformed/oversized bodies and browser-supplied identity fields fail before a login transaction', async t => {
  const x = await fixture(t); const c = x.client(); await c.call('/session');
  for (const [values, overrides] of [[{ accountId: 'forged' }, {}], [{}, { rawBody: '{' }], [[], {}],
    [{}, { headers: { 'content-type': 'text/plain' } }], [{}, { rawBody: 'x'.repeat(4097) }], [{}, { headers: { 'content-encoding': 'gzip' } }]]) {
    const response = await c.call('/oidc/login', values, overrides); assert.ok([400, 403, 413].includes(response.status));
  }
  assert.equal(x.browser.snapshot().transactions, 0); assert.equal(x.h.issuer.calls.length, 0);
});

test('notice text is exact configured data; all three separate declarations and matching version are required', async t => {
  const x = await fixture(t); const c = x.client(); const { status } = await c.login();
  const notice = status.body.registrationNotice;
  const declarations = { consentVersion: notice.consentVersion, adultSelfAttested: true, eligibilitySelfAttested: true, registrationConsent: true };
  for (const patch of [{ adultSelfAttested: false }, { eligibilitySelfAttested: false }, { registrationConsent: false },
    { consentVersion: 'unreviewed-notice' }, { accountId: 'forged-account' }]) {
    assert.equal((await c.call('/registration', { ...declarations, ...patch })).status, 400);
  }
  const registered = await c.call('/registration', declarations); assert.equal(registered.status, 200);
  assert.equal(registered.body.registrationState, 'pending'); assert.equal(registered.body.participantAccessGranted, false);
  assert.match(registered.body.registrationReference,/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
  assert.equal(registered.body.participationSession, false); assert.deepEqual(registered.body.registrationNotice, notice);
  assert.doesNotMatch(registered.text, privateOutput);
  assert.equal((await c.call('/polis/participation-init')).status, 403);
  const assets = await c.call('/app.js', undefined, { headers: { 'sec-fetch-mode': 'no-cors', 'sec-fetch-dest': 'script' } });
  assert.equal(assets.status, 200); assert.match(assets.text, /\.textContent = notice\.adultDeclaration/u);
  assert.doesNotMatch(assets.text, /innerHTML|localStorage|sessionStorage|document\.cookie/u);
});

async function registeredClient(x, subject = 'invented-browser-account-one') {
  const c = x.client(); await c.login({ claims: { sub: subject } });
  const before = new Set(x.h.records.keys()); const notice = x.h.access.registrationNotice();
  const registered = await c.call('/registration', { consentVersion: notice.consentVersion,
    adultSelfAttested: true, eligibilitySelfAttested: true, registrationConsent: true });
  assert.equal(registered.status, 200);
  const accounts = [...x.h.records.keys()].filter(account => !before.has(account));
  assert.equal(accounts.length, 1);
  // The test operator reads its private protocol registry. This object is used
  // only by fixture event/invitation helpers, never as a verified principal.
  return { c, registrationReference: registered.body.registrationReference, account: Object.freeze({ accountId: accounts[0] }) };
}

test('two registered browser accounts receive only their own reference; a reference cannot select an account or grant access',async t=>{
  const x=await fixture(t),alice=await registeredClient(x,'invented-reference-alice'),bob=await registeredClient(x,'invented-reference-bob'),anonymous=x.client();
  assert.notEqual(alice.registrationReference,bob.registrationReference);
  for(const person of [alice,bob]){
    const status=await person.c.call('/session');assert.equal(status.status,200);assert.equal(status.body.registrationReference,person.registrationReference);
    const other=person===alice?bob:alice;assert.ok(!status.text.includes(other.registrationReference));assert.doesNotMatch(status.text,privateOutput);
    assert.equal((await person.c.call('/session?registrationReference='+other.registrationReference)).status,400);
    assert.equal((await person.c.call('/invitations/redeem',{invitationToken:person.registrationReference})).status,403);
    const notice=status.body.registrationNotice;
    assert.equal((await person.c.call('/registration',{consentVersion:notice.consentVersion,adultSelfAttested:true,eligibilitySelfAttested:true,registrationConsent:true,registrationReference:other.registrationReference})).status,400);
  }
  const guest=await anonymous.call('/session');assert.equal(guest.body.registrationReference,null);assert.ok(!guest.text.includes(alice.registrationReference));assert.ok(!guest.text.includes(bob.registrationReference));
  assert.equal((await alice.c.call('/session/logout',{})).status,200);
  const signedOut=await alice.c.call('/session');assert.equal(signedOut.body.registrationReference,null);assert.ok(!signedOut.text.includes(alice.registrationReference));
  assert.equal(x.h.votes.length,0);
});

async function participant(x) {
  const enrolled = await registeredClient(x); x.h.activate(); await x.h.approve(enrolled.account);
  const invitation = await x.h.invite(enrolled.account);
  assert.equal((await enrolled.c.call('/invitations/redeem', { invitationToken: invitation.invitationToken })).status, 200);
  const initial = await enrolled.c.call('/polis/participation-init'); assert.equal(initial.status, 200);
  return { ...enrolled, invitation, initial };
}

test('joined two-account protocol denies forwarded invitation, rotates on redemption and returns only the displayed fixed statement', async t => {
  const x = await fixture(t); const alice = await registeredClient(x, 'invented-browser-alice'); const bob = await registeredClient(x, 'invented-browser-bob');
  x.h.activate(); await x.h.approve(alice.account); await x.h.approve(bob.account);
  const invitation = await x.h.invite(alice.account);
  const forwarded = await bob.c.call('/invitations/redeem', { invitationToken: invitation.invitationToken });
  assert.equal(forwarded.status, 403); assert.equal(x.h.votes.length, 0);
  const oldCookie = alice.c.jar.get(COOKIE); const oldCsrf = alice.c.csrf;
  const redeemed = await alice.c.call('/invitations/redeem', { invitationToken: invitation.invitationToken });
  assert.equal(redeemed.status, 200); assert.notEqual(alice.c.jar.get(COOKIE), oldCookie); assert.notEqual(alice.c.csrf, oldCsrf);
  assert.doesNotMatch(redeemed.text, privateOutput); assert.ok(!redeemed.text.includes(invitation.invitationToken));
  assert.equal((await alice.c.call('/polis/participation-init', undefined, { headers: { cookie: `${COOKIE}=${oldCookie}`, 'x-csrf-token': oldCsrf }, saveCookies: false })).status, 401);
  assert.equal((await alice.c.call('/polis/votes', { tid: 0, vote: -1 })).status, 400, 'no vote before a statement is displayed');
  const initialized = await alice.c.call('/polis/participation-init');
  assert.equal(initialized.status, 200); assert.deepEqual(initialized.body, { statement: { tid: 0, text: x.h.configuration.statements[0] }, complete: false });
  assert.doesNotMatch(initialized.text, privateOutput);
  for (const input of [{ tid: 1, vote: -1 }, { tid: 0, vote: 2 }, { tid: 0, vote: -1, xid: 'untrusted' }]) {
    assert.equal((await alice.c.call('/polis/votes', input)).status, 400);
  }
  const voted = await alice.c.call('/polis/votes', { tid: 0, vote: -1 }); assert.equal(voted.status, 200);
  assert.equal(x.h.votes.length, 1); assert.equal(x.h.votes[0].tid, 0); assert.equal(x.h.votes[0].vote, -1);
  assert.doesNotMatch(voted.text, privateOutput);
  assert.equal((await bob.c.call('/polis/next-comment')).status, 403);
});

test('session cookie alone cannot authorize GET initialization without the synchronizer', async t => {
  const x = await fixture(t); const p = await participant(x);
  const before = x.h.calls.filter(call => call.peer === 'polis').length;
  assert.equal((await p.c.call('/polis/participation-init', undefined, { headers: { 'x-csrf-token': '' } })).status, 403);
  assert.equal((await p.c.call('/polis/next-comment', undefined, { headers: { 'x-csrf-token': 'forged' } })).status, 403);
  assert.equal(x.h.calls.filter(call => call.peer === 'polis').length, before);
});

test('a concurrent double click is denied while the first vote waits, then only one provider write occurs', async t => {
  const x = await fixture(t); const p = await participant(x);
  let entered = false; let release;
  const gate = new Promise(resolve => { release = resolve; });
  x.h.behavior.providerGate = async operation => { if (operation === 'votes') { entered = true; await gate; } };
  const first = p.c.call('/polis/votes', { tid: 0, vote: -1 });
  t.after(release); await until(() => entered);
  const duplicate = await p.c.call('/polis/votes', { tid: 0, vote: -1 }); assert.equal(duplicate.status, 409);
  release(); assert.equal((await first).status, 200); assert.equal(x.h.votes.length, 1);
});

test('logout during an in-flight vote removes authority before waiting and withholds its late result', async t => {
  const x = await fixture(t); const p = await participant(x);
  let entered = false; let release; const gate = new Promise(resolve => { release = resolve; });
  x.h.behavior.providerGate = async operation => { if (operation === 'votes') { entered = true; await gate; } };
  const vote = p.c.call('/polis/votes', { tid: 0, vote: -1 }); t.after(release); await until(() => entered);
  const logout = await p.c.call('/session/logout', {}); assert.equal(logout.status, 200);
  release(); const late = await vote; assert.equal(late.status, 401); assert.doesNotMatch(late.text, privateOutput);
  assert.equal(x.h.votes.length, 1, 'an already dispatched write may have occurred; no success is claimed');
  assert.equal((await p.c.call('/session')).body.authenticated, false);
});

test('terminal revocation during an in-flight vote blocks its result and future participation', async t => {
  const x = await fixture(t); const p = await participant(x);
  let entered = false; let release; const gate = new Promise(resolve => { release = resolve; });
  x.h.behavior.providerGate = async operation => { if (operation === 'votes') { entered = true; await gate; } };
  const vote = p.c.call('/polis/votes', { tid: 0, vote: -1 }); t.after(release); await until(() => entered);
  const revoked = x.h.revoke(p.account); release();
  const late = await vote; assert.ok([401, 403].includes(late.status)); await revoked;
  assert.equal(x.h.votes.length, 1, 'no assertion that a dispatched vote was unapplied');
  assert.ok([401, 403].includes((await p.c.call('/polis/next-comment')).status));
  assert.doesNotMatch(late.text, privateOutput);
});

test('expiry during provider work withholds its response and never retries the uncertain vote', async t => {
  const x = await fixture(t); const p = await participant(x);
  let entered = false; let release; const gate = new Promise(resolve => { release = resolve; });
  x.h.behavior.providerGate = async operation => { if (operation === 'votes') { entered = true; await gate; } };
  const vote = p.c.call('/polis/votes', { tid: 0, vote: 0 }); t.after(release); await until(() => entered);
  x.h.advance(300_000); release();
  const late = await vote; assert.equal(late.status, 401);
  assert.equal(x.h.votes.length, 1); assert.equal(x.h.votes[0].vote, 0);
  assert.equal((await p.c.call('/polis/votes', { tid: 0, vote: 0 })).status, 401); assert.equal(x.h.votes.length, 1);
});

test('unreviewed provider statement is never rendered or echoed', async t => {
  const x = await fixture(t); const p = await participant(x); x.h.behavior.badStatement = true;
  const response = await p.c.call('/polis/next-comment'); assert.equal(response.status, 503);
  assert.doesNotMatch(response.text, /Unreviewed text|SENSITIVE_|acct_/u);
});

test('close during a live OIDC grant cancels completion and clears transaction custody', async t => {
  const x = await fixture(t); const c = x.client(); await c.call('/session');
  const begun = await c.call('/oidc/login', {});
  const callback = new URL(x.h.issuer.authorizationResponse(begun.body.authorizationUrl));
  let release; x.h.issuer.setGate(new Promise(resolve => { release = resolve; })); t.after(release);
  const completed = c.call(callback.pathname + callback.search, undefined, { headers: {
    'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document' } }).catch(error => error);
  await until(() => x.h.issuer.calls.some(call => call.endpoint === 'token'));
  const stopped = x.browser.close(); release(); const result = await completed;
  assert.ok(result instanceof Error || result.status !== 303); assert.equal((await stopped).closed, true);
  assert.equal(x.browser.snapshot().sessions, 0); assert.equal(x.browser.snapshot().transactions, 0);
});

test('close racing the first listen attempt cannot leave a late listener', async t => {
  const x = await fixture(t, { autoStart: false });
  const started = x.browser.start(); const stopped = x.browser.close();
  await assert.rejects(started); const result = await stopped;
  assert.equal(result.closed, true); assert.equal(x.browser.snapshot().listenerOpen, false);
});

test('logout clears browser authority and rotates a fresh anonymous session', async t => {
  const x = await fixture(t); const c = x.client(); const before = await c.login();
  const oldCsrf = c.csrf;
  const response = await c.call('/session/logout', {}); assert.equal(response.status, 200);
  assert.equal(c.jar.has(COOKIE), false); assert.equal(response.body.authenticated, false);
  const after = await c.call('/session'); assert.equal(after.body.authenticated, false); assert.notEqual(c.csrf, oldCsrf);
  assert.notEqual(c.jar.get(COOKIE), before.sessionCookie);
  assert.equal((await c.call('/registration', {}, { headers: { cookie: `${COOKIE}=${before.sessionCookie}`, 'x-csrf-token': oldCsrf } })).status, 401);
});

test('expired transaction cannot perform a token grant and later pruning recovers capacity', async t => {
  const x = await fixture(t); const c = x.client(); await c.call('/session');
  const begun = await c.call('/oidc/login', {});
  const callback = new URL(x.h.issuer.authorizationResponse(begun.body.authorizationUrl));
  x.h.setTime(x.h.now() + 300_000);
  const response = await c.call(callback.pathname + callback.search, undefined, { headers: {
    'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document' } });
  assert.equal(response.status, 401); assert.equal(x.h.issuer.calls.length, 0);
  assert.equal((await c.call('/session')).status, 200); assert.equal(x.browser.snapshot().transactions, 0);
});

test('128 combined browser states are bounded; expiry permits new sessions without evicting live authority', async t => {
  const x = await fixture(t);
  for (let i = 0; i < 128; i++) assert.equal((await x.client().call('/session')).status, 200);
  assert.equal(x.browser.snapshot().sessions, 128);
  assert.equal((await x.client().call('/session')).status, 503);
  x.h.setTime(x.h.now() + 600_000);
  assert.equal((await x.client().call('/session')).status, 200); assert.equal(x.browser.snapshot().sessions, 1);
});

test('32 body readers reserve admission before bytes; further requests fail and aborted readers drain', async t => {
  const x = await fixture(t); const clients = [];
  for (let i = 0; i < 32; i++) { const c = x.client(); assert.equal((await c.call('/session')).status, 200); clients.push(c); }
  const held = clients.map(c => c.holdBody());
  t.after(() => held.forEach(req => req.destroy()));
  await until(() => x.browser.snapshot().pendingOperations === 32, 'all body-reader slots occupied');
  assert.equal((await x.client().call('/health')).status, 503);
  held.forEach(req => req.destroy());
  await until(() => x.browser.snapshot().pendingOperations === 0, 'aborted readers released all slots');
  assert.equal((await x.client().call('/health')).status, 200);
});

test('an incomplete body has a total five-second deadline and releases its session operation', { timeout: 10_000 }, async t => {
  const x = await fixture(t); const c = x.client(); assert.equal((await c.call('/session')).status, 200);
  const started = performance.now(); const held = c.holdBody();
  const response = new Promise((resolve, reject) => {
    held.once('response', res => { res.once('end', () => resolve(res.statusCode)); }); held.once('error', reject);
  });
  assert.equal(await response, 408); assert.ok(performance.now() - started >= 4500);
  await until(() => x.browser.snapshot().pendingOperations === 0);
  assert.equal((await c.call('/oidc/login', {})).status, 200);
});

for (const anomaly of ['rollback', 'invalid', 'throws']) test(`${anomaly} browser clock closes and drains, with no revival after correction`, async t => {
  let broken = false; let time = Date.now();
  const x = await fixture(t, { now: () => { if (broken && anomaly === 'throws') throw Error('PRIVATE_CLOCK_DETAIL');
    return broken ? anomaly === 'rollback' ? time - 1 : NaN : time; } });
  const c = x.client(); assert.equal((await c.call('/session')).status, 200);
  broken = true;
  try { const response = await c.call('/session'); assert.equal(response.status, 503); assert.doesNotMatch(response.text, /PRIVATE_CLOCK_DETAIL/u); }
  catch (error) { assert.ok(['ECONNRESET', 'ECONNREFUSED'].includes(error.code)); }
  const result = await x.browser.close(); assert.equal(result.closed, true); assert.equal(result.pendingOperations, 0);
  broken = false; time++;
  assert.equal(x.browser.snapshot().admissionClosed, true); await assert.rejects(x.browser.start());
});

test('close clears sessions/transactions, refuses listener and start cannot restart the owner', async t => {
  const x = await fixture(t); const c = x.client(); await c.call('/session'); await c.call('/oidc/login', {});
  const first = x.browser.close(); const second = x.browser.close(); assert.equal(first, second);
  assert.deepEqual(await first, { closed: true, listenerClosed: true, pendingOperations: 0, sessionsCleared: true, transactionsCleared: true });
  assert.equal(x.browser.snapshot().phase, 'CLOSED'); await assert.rejects(x.browser.start());
  await new Promise((resolve, reject) => {
    const socket = connect({ host: '127.0.0.1', port: x.port });
    socket.once('connect', () => { socket.destroy(); reject(Error('listener remained open')); });
    socket.once('error', error => { socket.destroy(); if (error.code === 'ECONNREFUSED') resolve(); else reject(error); });
  });
});

test('OIDC cross-site redirect can reach only the safe top-level document', async t => {
  const h = await fixture(t); const client = h.client();
  for (const site of ['cross-site', 'same-site']) {
    const headers = { 'sec-fetch-site': site, 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document' };
    assert.equal((await client.call('/', undefined, { headers })).status, 200);
    for (const path of ['/session', '/app.js', '/style.css']) assert.equal((await client.call(path, undefined, { headers })).status, 403);
    assert.equal((await client.call('/', undefined, { headers: { ...headers, 'sec-fetch-dest': 'iframe' } })).status, 403);
  }
});
