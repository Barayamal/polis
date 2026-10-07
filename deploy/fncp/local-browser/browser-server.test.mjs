import test from 'node:test';
import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { readFileSync } from 'node:fs';
import { createLocalBrowser, LocalAccessBackend, BACKEND_ORIGIN, COOKIE_NAME, MODE } from './browser-server.mjs';
import { createBrowserClient } from './integration-client.mjs';

const seeds = JSON.parse(readFileSync(new URL('../seed-statements.json', import.meta.url), 'utf8'));
const secret = 'synthetic_fixture_secret_'.repeat(3);
const invitation = 'synthetic_bound_invitation_'.repeat(3);
const auth = 'server_only_fixture_auth_'.repeat(3);
const participant = 'server_only_participation_'.repeat(3);
const tid = 27;

for (const operation of ['login', 'redeem', 'participate']) test(`browser deadline during ${operation} cannot revive a session or return a late response`, async (t) => {
  const h = await harness(t, { sessionLifetimeMs: 100 });
  if (operation === 'redeem') await h.login();
  if (operation === 'participate') await h.redeem();
  const original = h.backend.request.bind(h.backend);
  h.backend.request = async (...args) => { const result = await original(...args); h.advance(101); return result; };
  const result = operation === 'login' ? await h.request('/api/login', { fixture: 'synthetic_alice', fixtureSecret: secret }) :
    operation === 'redeem' ? await h.request('/api/redeem', { invitationToken: invitation }) : await h.request('/api/participation-init');
  assert.equal(result.status, 401); assert.match(result.headers['set-cookie'][0], /Max-Age=0/u);
  assert.equal((await h.request('/api/session')).body.phase, 'visitor');
});

test('deadline during synthetic OIDC start discards pending flow', async (t) => {
  let clock = 1000; let discarded = 0;
  const backend = new ModelBackend(); backend.authenticateIdentity = () => { throw new Error('must not be called'); };
  const app = createLocalBrowser({ mode: MODE, backend, now: () => clock, sessionLifetimeMs: 100,
    oidcDriver: { mode: 'SYNTHETIC_ONLY', begin: async () => { clock += 101; return { ok: true }; },
      complete: () => { throw new Error('must not be called'); }, discard: () => { discarded += 1; return { ok: true }; }, isVerifiedPrincipal: () => false } });
  const origin = await app.listen(0); t.after(() => app.close());
  const browser = createBrowserClient(origin); await browser.session();
  assert.equal((await browser.oidcStart()).status, 503); assert.equal(discarded, 1);
  assert.equal((await browser.session()).body.oidcPending, false);
});

/** Intentionally a model, not evidence of the real Pol.is origin. */
class ModelBackend {
  calls = []; revoked = false; outage = false; used = false; malicious = false; voted = false;
  async request(path, body, credential) {
    this.calls.push({ path, body, credential });
    if (this.outage) throw new Error('hidden backend diagnostic secret');
    if (path === '/test-auth/mailbox-simulator') {
      return body.fixture === 'synthetic_alice' && body.fixtureSecret === secret ?
        { status: 200, body: { fixtureAuthToken: auth, mailboxOwnership: 'SIMULATED_NOT_VERIFIED' } } : { status: 401, body: {} };
    }
    if (path === '/invitations/redeem') {
      if (credential !== auth) return { status: 401, body: {} };
      if (body.invitationToken !== invitation || this.used || this.revoked) return { status: 403, body: {} };
      this.used = true; return { status: 201, body: { participationToken: participant, mode: 'SYNTHETIC_ONLY' } };
    }
    if (path === '/session/logout') { this.revoked = true; return { status: 200, body: {} }; }
    if (this.revoked || credential !== participant) return { status: 401, body: { error: 'hidden upstream detail' } };
    if (path === '/polis/votes') this.voted = true;
    const next = this.voted ? null : { tid, txt: this.malicious ? 'Unexpected non-synthetic statement.' : seeds[0],
      currentPid: 55, xid: 'hidden-xid', auth: 'hidden-comment-auth' };
    return { status: 200, body: { ...(path === '/polis/next-comment' ? next ?? {} : { nextComment: next }),
      fixtureAuthToken: auth, participationToken: participant, currentPid: 55, xid: 'hidden-xid',
      auth: { token: 'hidden-upstream-auth' }, user: { email: 'must-not-return@example.test' } } };
  }
}

async function raw(origin, path, { method = 'GET', body, cookie, csrf, headers = {}, browser = true } = {}) {
  const payload = body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = httpRequest(origin + path, { method,
      headers: { ...(browser ? { 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'same-origin', 'Sec-Fetch-Dest': 'empty' } : {}),
        ...(cookie ? { Cookie: cookie } : {}), ...(csrf ? { 'X-CSRF-Token': csrf } : {}),
        ...(method === 'POST' ? { Origin: origin, 'Content-Type': 'application/json' } : {}),
        ...(payload === undefined ? {} : { 'Content-Length': Buffer.byteLength(payload) }), ...headers },
    }, (res) => {
      const chunks = []; res.on('data', (chunk) => chunks.push(chunk)); res.on('error', reject);
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let decoded; try { decoded = JSON.parse(text); } catch { decoded = text; }
        resolve({ status: res.statusCode, body: decoded, text, headers: res.headers,
          cookie: res.headers['set-cookie']?.[0]?.split(';')[0] });
      });
    });
    req.on('error', reject); if (payload !== undefined) req.write(payload); req.end();
  });
}

async function harness(t, options = {}) {
  let time = 100_000; const backend = new ModelBackend();
  const app = createLocalBrowser({ mode: MODE, backend, now: () => time, ...options });
  const origin = await app.listen(0); t.after(() => app.close());
  const session = await raw(origin, '/api/session');
  assert.equal(session.status, 200);
  let cookie = session.cookie; let csrf = session.body.csrf;
  async function request(path, body, extra = {}) {
    const result = await raw(origin, path, { method: body === undefined ? 'GET' : 'POST', cookie, csrf, body, ...extra });
    if (result.cookie) cookie = result.headers['set-cookie'][0].includes('Max-Age=0') ? '' : result.cookie;
    if (typeof result.body?.csrf === 'string') csrf = result.body.csrf;
    return result;
  }
  async function login() { const result = await request('/api/login', { fixture: 'synthetic_alice', fixtureSecret: secret }); assert.equal(result.status, 200); return result; }
  async function redeem() { await login(); const result = await request('/api/redeem', { invitationToken: invitation }); assert.equal(result.status, 200); return result; }
  return { origin, backend, request, login, redeem, initial: session, credentials: () => ({ cookie, csrf }), advance: (ms) => { time += ms; } };
}

test('configuration is fixture-only, session storage is bounded and expiry cannot be extended past 15 minutes', () => {
  for (const mode of [undefined, 'true', 'production']) assert.throws(() => createLocalBrowser({ mode }));
  for (const maxSessions of [0, 257, Infinity]) assert.throws(() => createLocalBrowser({ mode: MODE, maxSessions }));
  for (const sessionLifetimeMs of [0, Infinity, 900001]) assert.throws(() => createLocalBrowser({ mode: MODE, sessionLifetimeMs }));
  assert.equal(BACKEND_ORIGIN, 'http://127.0.0.1:8099');
});

test('transport model uses fixed backend, exact route allowlist and no browser authority forwarding', async (t) => {
  const calls = [];
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    calls.push({ url, options });
    return Response.json({ mode: 'SYNTHETIC_ONLY', productionReady: false, heritageVerification: false, realEmailEnabled: false });
  });
  const backend = new LocalAccessBackend();
  await backend.verifySynthetic();
  await backend.request('/invitations/redeem', { invitationToken: invitation }, auth);
  assert.ok(calls.every(({ url, options }) => url.startsWith(BACKEND_ORIGIN + '/') && options.redirect === 'error'));
  assert.deepEqual(calls[1].options.headers, { 'Content-Type': 'application/json', Authorization: `Bearer ${auth}` });
  await assert.rejects(backend.request('/test-admin/approve', { fixture: 'synthetic_alice' }, auth));
  await assert.rejects(backend.request('https://example.org', {}));
  await assert.rejects(backend.request('/polis/participation-init', {}));
});

test('cookies are random, HttpOnly, same-site strict, independent of CSRF and rotated after authentication', async (t) => {
  const h = await harness(t); const before = h.credentials();
  assert.match(h.initial.headers['set-cookie'][0], /; Path=\/; HttpOnly; SameSite=Strict; Max-Age=900$/u);
  assert.equal(h.initial.headers['set-cookie'][0].includes('Domain='), false);
  assert.notEqual(before.cookie.split('=')[1], before.csrf);
  await h.login(); const after = h.credentials();
  assert.notEqual(before.cookie, after.cookie); assert.notEqual(before.csrf, after.csrf);
  assert.equal((await raw(h.origin, '/api/redeem', { method: 'POST', body: { invitationToken: invitation }, ...before })).status, 401);
  const red = await h.request('/api/redeem', { invitationToken: invitation }); assert.equal(red.status, 200);
  assert.notEqual(after.cookie, h.credentials().cookie); assert.notEqual(after.csrf, h.credentials().csrf);
});

test('unrecognised cookies are never adopted and duplicate session cookies fail closed', async (t) => {
  const h = await harness(t); const attackerCookie = `${COOKIE_NAME}=${'a'.repeat(43)}`;
  const fresh = await raw(h.origin, '/api/session', { cookie: attackerCookie });
  assert.equal(fresh.status, 200); assert.notEqual(fresh.cookie, attackerCookie);
  assert.equal((await raw(h.origin, '/api/login', { method: 'POST', cookie: attackerCookie, csrf: fresh.body.csrf,
    body: { fixture: 'synthetic_alice', fixtureSecret: secret } })).status, 401);
  assert.equal((await h.request('/api/session', undefined, { cookie: `${h.credentials().cookie}; ${h.credentials().cookie}` })).status, 400);
});

test('CSRF, missing or wrong Origin and Fetch Metadata are rejected before backend calls', async (t) => {
  const h = await harness(t); const body = { fixture: 'synthetic_alice', fixtureSecret: secret };
  for (const extra of [{ csrf: '' }, { csrf: 'incorrect' }, { headers: { Origin: 'https://attacker.example' } },
    { headers: { Origin: '' } }, { headers: { 'Sec-Fetch-Site': 'same-site' } },
    { headers: { 'Sec-Fetch-Site': 'cross-site' } }, { headers: { 'Sec-Fetch-Mode': 'no-cors' } },
    { headers: { 'Sec-Fetch-Dest': 'document' } }, { browser: false }]) {
    assert.equal((await h.request('/api/login', body, extra)).status, 403);
  }
  assert.equal((await h.request('/api/session', undefined, { browser: false })).status, 403);
  assert.equal(h.backend.calls.length, 0);
});

test('Host and injected bearer/gateway authority fail closed; query tokens and private routes are absent', async (t) => {
  const h = await harness(t);
  for (const headers of [{ Host: 'localhost:8100' }, { Host: 'attacker.example' },
    { Authorization: `Bearer ${auth}` }, { 'X-FNCP-Gateway-Key': 'fake' }]) {
    assert.equal((await h.request('/api/session', undefined, { headers })).status, 403);
  }
  assert.equal((await h.request('/api/session?invite=hidden')).status, 400);
  assert.equal((await h.request('/api/%73ession')).status, 400);
  assert.equal((await h.request('/test-admin/status')).status, 404);
  assert.equal((await h.request('/api/approve', { fixture: 'synthetic_alice' })).status, 404);
  assert.equal(h.backend.calls.length, 0);
});

test('role confusion: visitor and fixture-auth cannot participate; caller tokens cannot become session authority', async (t) => {
  const h = await harness(t);
  assert.equal((await h.request('/api/participation-init')).status, 403);
  assert.equal((await h.request('/api/redeem', { invitationToken: invitation })).status, 403);
  assert.equal((await h.request('/api/login', { fixture: 'synthetic_alice', fixtureSecret: secret, participationToken: participant })).status, 400);
  await h.login(); assert.equal((await h.request('/api/participation-init')).status, 403);
  assert.equal((await h.request('/api/login', { fixture: 'synthetic_alice', fixtureSecret: secret })).status, 409);
  assert.equal(h.backend.calls.filter((call) => call.path.startsWith('/polis/')).length, 0);
});

test('invitation denial preserves account binding; replay and concurrent redemption cannot mint parallel browser sessions', async (t) => {
  const h = await harness(t); await h.login();
  assert.equal((await h.request('/api/redeem', { invitationToken: 'forwarded_wrong_invitation_'.repeat(3) })).status, 403);
  const credentials = h.credentials();
  const attempts = await Promise.all([1, 2].map(() => raw(h.origin, '/api/redeem', {
    method: 'POST', body: { invitationToken: invitation }, ...credentials,
  })));
  assert.deepEqual(attempts.map((result) => result.status).sort(), [200, 401]);
  const success = attempts.find((result) => result.status === 200);
  assert.equal((await raw(h.origin, '/api/redeem', { method: 'POST', body: { invitationToken: invitation },
    cookie: success.cookie, csrf: success.body.csrf })).status, 403);
});

test('only whitelisted statement text and TID reach the browser; upstream identity and tokens never escape', async (t) => {
  const h = await harness(t); const logged = await h.login();
  const redeemed = await h.request('/api/redeem', { invitationToken: invitation });
  const init = await h.request('/api/participation-init');
  const next = await h.request('/api/next-comment');
  for (const result of [logged, redeemed, init, next]) {
    for (const sensitive of [auth, participant, secret, invitation, 'hidden-xid', 'hidden-upstream-auth', 'must-not-return@example.test', 'currentPid']) {
      assert.equal(result.text.includes(sensitive), false);
    }
  }
  assert.deepEqual(init.body.statement, { tid, text: seeds[0] });
  assert.deepEqual(next.body.statement, { tid, text: seeds[0] });
  h.backend.malicious = true;
  const refused = await h.request('/api/next-comment'); assert.equal(refused.status, 503);
  assert.equal(refused.text.includes('Unexpected non-synthetic'), false);
});

test('strict body, displayed-statement binding and vote values reject extras, unknown TIDs and suggestions before transport', async (t) => {
  const h = await harness(t); await h.redeem();
  assert.equal((await h.request('/api/votes', { tid, vote: 0 })).status, 400);
  await h.request('/api/participation-init');
  for (const body of [{ tid, vote: '0' }, { tid, vote: 2 }, { tid: '27', vote: 0 }, { tid: -1, vote: 0 },
    { tid: Number.MAX_SAFE_INTEGER, vote: 0 }, { tid, vote: 0, txt: 'suggestion' }, { tid, vote: 0, xid: 'caller' },
    { tid, vote: 0, auth: 'caller' }, { tid, vote: 0, url: 'https://example.org' }, [], null]) {
    assert.equal((await h.request('/api/votes', body)).status, 400);
  }
  assert.equal((await h.request('/api/comments', { txt: 'not permitted' })).status, 404);
  assert.equal(h.backend.calls.filter((call) => call.path === '/polis/votes').length, 0);
  const vote = await h.request('/api/votes', { tid, vote: -1 });
  assert.equal(vote.status, 200); assert.equal(vote.body.saved, true); assert.equal(vote.body.complete, true);
  assert.deepEqual(h.backend.calls.at(-1).body, { tid, vote: -1 });
  assert.equal((await h.request('/api/votes', { tid, vote: -1 })).status, 400);
});

test('each Agree / Disagree / Pass numeric value is accepted without remapping', async (t) => {
  for (const vote of [-1, 1, 0]) {
    const h = await harness(t); await h.redeem(); await h.request('/api/participation-init');
    assert.equal((await h.request('/api/votes', { tid, vote })).status, 200);
    assert.equal(h.backend.calls.at(-1).body.vote, vote);
  }
});

test('expired browser sessions cannot vote and bounded memory refuses additional sessions until expiry', async (t) => {
  const h = await harness(t, { sessionLifetimeMs: 1000, maxSessions: 1 });
  assert.equal((await raw(h.origin, '/api/session')).status, 503);
  await h.redeem(); await h.request('/api/participation-init');
  h.advance(1001);
  assert.equal((await h.request('/api/votes', { tid, vote: 0 })).status, 401);
  assert.equal(h.backend.calls.filter((call) => call.path === '/polis/votes').length, 0);
  const fresh = await raw(h.origin, '/api/session'); assert.equal(fresh.status, 200); assert.equal(fresh.body.phase, 'visitor');
});

test('upstream revocation invalidates a warm browser session and reveals no backend diagnostics', async (t) => {
  const h = await harness(t); await h.redeem(); await h.request('/api/participation-init');
  h.backend.revoked = true;
  const denied = await h.request('/api/votes', { tid, vote: 0 }); assert.equal(denied.status, 401);
  assert.match(denied.headers['set-cookie'][0], /Max-Age=0/u);
  assert.equal(denied.text.includes('hidden upstream'), false);
  const fresh = await h.request('/api/session'); assert.equal(fresh.body.phase, 'visitor');
  assert.equal((await h.request('/api/next-comment')).status, 403);
});

test('logout clears browser authority even during backend outage; uncertain vote is never automatically retried', async (t) => {
  const h = await harness(t); await h.redeem(); await h.request('/api/participation-init');
  h.backend.outage = true;
  const failed = await h.request('/api/votes', { tid, vote: 0 }); assert.equal(failed.status, 503);
  assert.equal(failed.text.includes('hidden backend diagnostic'), false);
  assert.equal((await h.request('/api/votes', { tid, vote: 0 })).status, 400);
  assert.equal(h.backend.calls.filter((call) => call.path === '/polis/votes').length, 1);
  const old = h.credentials(); const loggedOut = await h.request('/api/logout', {});
  assert.equal(loggedOut.status, 200); assert.equal(loggedOut.body.browserSessionClosed, true);
  assert.equal(loggedOut.body.backendLogoutVerified, false);
  assert.equal((await raw(h.origin, '/api/next-comment', old)).status, 401);
});

test('body size, content type and method are constrained', async (t) => {
  const h = await harness(t);
  assert.equal((await h.request('/api/login', 'not-json')).status, 400);
  assert.equal((await h.request('/api/login', 'x'.repeat(4097))).status, 413);
  assert.equal((await h.request('/api/login', {}, { headers: { 'Content-Type': 'text/plain' } })).status, 415);
  assert.equal((await raw(h.origin, '/api/session', { method: 'PUT' })).status, 405);
  assert.equal((await raw(h.origin, '/api/session', { body: '{}' })).status, 400);
});

test('same-origin static shell has restrictive CSP and no third-party assets or credential persistence', async (t) => {
  const h = await harness(t); const page = await raw(h.origin, '/', { browser: false });
  assert.equal(page.status, 200); assert.match(page.headers['content-security-policy'], /default-src 'none'/u);
  assert.match(page.headers['content-security-policy'], /connect-src 'self'/u);
  assert.match(page.headers['content-security-policy'], /frame-ancestors 'none'/u);
  assert.equal(page.headers['referrer-policy'], 'no-referrer'); assert.equal(page.headers['cache-control'], 'no-store');
  assert.match(page.text, /SYNTHETIC ONLY/u); assert.match(page.text, /not verified/u);
  const js = (await raw(h.origin, '/app.js', { browser: false })).text;
  assert.ok(js.indexOf('history.replaceState') < js.indexOf('fetch('));
  assert.equal(/localStorage|sessionStorage|document\.cookie|innerHTML|https:\/\//u.test(js), false);
  assert.match(js, /mode: 'same-origin'/u);
  assert.match(page.text, /data-vote="-1">Agree/u);
  assert.match(page.text, /data-vote="1">Disagree/u);
  assert.match(page.text, /data-vote="0">Pass/u);
});

test('integration client keeps cookie and CSRF internal through the full model journey', async (t) => {
  const h = await harness(t); const client = createBrowserClient(h.origin);
  assert.throws(() => createBrowserClient('https://example.org'));
  assert.equal((await client.session()).status, 200);
  const login = await client.login('synthetic_alice', secret); assert.equal(login.status, 200); assert.equal(login.body.csrf, undefined);
  assert.equal((await client.redeem(invitation)).status, 200);
  const init = await client.initialize(); assert.equal(init.status, 200);
  assert.equal((await client.next()).status, 200);
  assert.equal((await client.vote(init.body.statement.tid, 0)).body.saved, true);
  assert.equal((await client.logout()).body.browserSessionClosed, true);
});
