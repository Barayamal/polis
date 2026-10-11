/** Fresh loopback/model lifecycle checks. No real identity, WordPress or Pol.is. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { readFileSync } from 'node:fs';
import { channel } from 'node:diagnostics_channel';
import { connect } from 'node:net';
import { createLocalBrowser } from './browser-server.mjs';

const seed = JSON.parse(readFileSync(new URL('../seed-statements.json', import.meta.url), 'utf8'))[0];
const token = label => ('synthetic_lifecycle_' + label + '_').repeat(3);
const registrationId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const declarations = { adultSelfAttested: true, eligibilitySelfAttested: true,
  registrationConsent: true, consentVersion: 'synthetic-registration-v1' };
const pause = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
const tick = () => new Promise(resolve => setImmediate(resolve));

async function harness(t, { oidc = false, registration = false, receipt = false } = {}) {
  const counts = { authenticate: 0, register: 0, issue: 0, vote: 0, login: 0, redeem: 0, discard: 0 };
  let discardFailure = false; let discardHook;
  const holds = new Map(); const releases = []; const requests = new Set();
  const principal = Object.freeze({ mode: 'SYNTHETIC_ONLY', assurance: 'OIDC_ID_TOKEN_VERIFIED' });
  async function reach(name) { const hold = holds.get(name); if (hold) { hold.entered.resolve(); await hold.release.promise; } }
  const backend = {
    async request(path) {
      if (path === '/test-auth/mailbox-simulator') {
        counts.login++; await reach('login');
        return { status: 200, body: { fixtureAuthToken: token('auth'), mailboxOwnership: 'SIMULATED_NOT_VERIFIED' } };
      }
      if (path === '/invitations/redeem') {
        counts.redeem++; await reach('redeem');
        return { status: 201, body: { mode: 'SYNTHETIC_ONLY', participationToken: token('participant') } };
      }
      if (path === '/session/logout') return { status: 200, body: {} };
      if (path === '/polis/next-comment') { await reach('next'); return { status: 200, body: { tid: 0, txt: seed } }; }
      if (path === '/polis/votes') { counts.vote++; await reach('vote'); }
      return { status: 200, body: { nextComment: { tid: 0, txt: seed } } };
    },
    async authenticateIdentity(value) {
      assert.equal(value, principal); counts.authenticate++; await reach('authenticate');
      return { mode: 'SYNTHETIC_ONLY', assurance: 'OIDC_ID_TOKEN_VERIFIED', fixtureAuthToken: token('auth') };
    },
  };
  const driver = { mode: 'SYNTHETIC_ONLY',
    async begin() { await reach('begin'); return { ok: true }; },
    async complete() { await reach('complete'); return { ok: true, principal }; },
    discard() { counts.discard++; discardHook?.(); if (discardFailure) throw new Error('Private synthetic cancellation failure'); },
    isVerifiedPrincipal: value => value === principal };
  const bridge = { mode: 'SYNTHETIC_ONLY', async register() {
    counts.register++; await reach('register'); return { status: 'SUBMITTED_NOT_APPROVED', registrationId };
  } };
  const issuer = { mode: 'SYNTHETIC_ONLY', async issue() {
    counts.issue++; await reach('issue'); return { receipt: 'synthetic_model_receipt_not_a_real_envelope' };
  } };
  const app = createLocalBrowser({ mode: 'fixture-only', backend,
    ...(oidc ? { oidcDriver: driver } : {}), ...(registration ? { registrationBridge: bridge } : {}),
    ...(receipt ? { registrationIssuer: issuer } : {}) });
  const origin = await app.listen(0);
  // Observe only this owned test listener. Waiting for the SERVER's close event
  // avoids mistaking the client's earlier close event for observed cancellation.
  const observations = new Map(); let sequence = 0;
  const requestStarted = channel('http.server.request.start');
  const observe = ({ request, response, socket }) => {
    if (socket.localPort !== Number(new URL(origin).port)) return;
    const observation = observations.get(request.headers['x-local-lifecycle-probe']);
    if (!observation) return;
    const ended = pause(); const closed = pause();
    request.once('end', ended.resolve); response.once('close', closed.resolve);
    observation.resolve({ ended: ended.promise, closed: closed.promise });
  };
  requestStarted.subscribe(observe);
  t.after(async () => {
    for (const release of releases) release(); for (const request of requests) request.destroy();
    try { await app.close(); } catch (error) { if (!discardFailure) throw error; }
    finally { requestStarted.unsubscribe(observe); }
  });
  function client() {
    let cookie; let csrf;
    function start(path, body, ready = false) {
      const arrived = pause(); const closed = pause(); const done = pause();
      const observation = pause(); const probe = String(++sequence); observations.set(probe, observation);
      const payload = body === undefined ? undefined : JSON.stringify(body);
      const req = httpRequest(origin + path, { method: body === undefined ? 'GET' : 'POST', agent: false,
        headers: { 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'same-origin', 'Sec-Fetch-Dest': 'empty',
          'X-Local-Lifecycle-Probe': probe,
          ...(ready ? { Expect: '100-continue' } : {}), ...(cookie ? { Cookie: cookie } : {}),
          ...(csrf ? { 'X-CSRF-Token': csrf } : {}), ...(body === undefined ? {} : {
            Origin: origin, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }) },
      }, res => {
        arrived.resolve(); const chunks = [];
        res.on('data', chunk => chunks.push(chunk));
        res.on('error', () => done.resolve({ disconnected: true }));
        res.on('end', () => {
          const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (res.headers['set-cookie']) cookie = res.headers['set-cookie'][0].split(';')[0];
          if (body.csrf) csrf = body.csrf;
          done.resolve({ status: res.statusCode, body, cookies: res.headers['set-cookie'] ?? [] });
        });
      });
      requests.add(req); req.on('continue', arrived.resolve);
      req.on('error', () => { arrived.resolve(); done.resolve({ disconnected: true }); });
      req.on('close', () => { requests.delete(req); closed.resolve(); }); req.end(payload);
      return { req, arrived: arrived.promise, done: done.promise, closed: closed.promise,
        async admitted() { await (await observation.promise).ended; await tick(); },
        async disconnect() { req.destroy(); await closed.promise; await (await observation.promise).closed; },
      };
    }
    const send = (path, body) => start(path, body).done;
    return { start, send,
      async login() {
        assert.equal((await send('/api/session')).status, 200);
        if (oidc) {
          assert.equal((await send('/api/oidc/start', {})).status, 200);
          assert.equal((await send('/api/oidc/callback', { callbackUrl: 'https://synthetic.invalid/callback' })).status, 200);
        } else assert.equal((await send('/api/login', { fixture: 'synthetic_lifecycle', fixtureSecret: token('secret') })).status, 200);
      },
      async participate() { await this.login(); assert.equal((await send('/api/redeem', { invitationToken: token('invite') })).status, 200);
        assert.equal((await send('/api/participation-init')).status, 200); },
    };
  }
  return { app, origin, counts, client, failDiscard(hook) { discardFailure = true; discardHook = hook; }, hold(name) {
    const entered = pause(); const release = pause(); holds.set(name, { entered, release }); releases.push(release.resolve);
    return { entered: entered.promise, release: release.resolve };
  } };
}

test('close denies already-admitted queued voting and withholds an in-flight result before drain completes', { timeout: 5000 }, async t => {
  const h = await harness(t); const c = h.client(); await c.participate();
  const hold = h.hold('next'); const active = c.start('/api/next-comment'); await hold.entered;
  const queued = c.start('/api/votes', { tid: 0, vote: 0 }, true); await queued.admitted();
  let closed = false; const closure = h.app.close().then(() => { closed = true; });
  await tick(); assert.equal(closed, false); hold.release();
  assert.equal((await active.done).status, 503); assert.equal((await queued.done).status, 503);
  await closure; assert.equal(h.counts.vote, 0); assert.equal(closed, true);
});

test('disconnect denies an admitted queued vote without dispatching a backend effect', { timeout: 5000 }, async t => {
  const h = await harness(t); const c = h.client(); await c.participate();
  const hold = h.hold('next'); const active = c.start('/api/next-comment'); await hold.entered;
  const queued = c.start('/api/votes', { tid: 0, vote: 0 }, true); await queued.admitted();
  await queued.disconnect(); hold.release();
  assert.equal((await active.done).status, 200); assert.equal((await queued.done).disconnected, true);
  assert.equal((await c.send('/api/session')).body.phase, 'participant'); assert.equal(h.counts.vote, 0);
});

test('already-started vote is drained once and never reported as saved after closure', { timeout: 5000 }, async t => {
  const h = await harness(t); const c = h.client(); await c.participate();
  const hold = h.hold('vote'); const active = c.start('/api/votes', { tid: 0, vote: 0 }); await hold.entered;
  const closure = h.app.close(); hold.release(); const result = await active.done; await closure;
  assert.equal(h.counts.vote, 1); assert.equal(result.status, 503);
  assert.match(result.body.error, /outcome could be confirmed/u); assert.equal(Object.hasOwn(result.body, 'saved'), false);
});

for (const operation of ['login', 'redeem']) test(`disconnect during ${operation} cannot mint replacement browser authority`, { timeout: 5000 }, async t => {
  const h = await harness(t); const c = h.client();
  if (operation === 'redeem') await c.login(); else await c.send('/api/session');
  const hold = h.hold(operation); const active = operation === 'login'
    ? c.start('/api/login', { fixture: 'synthetic_lifecycle', fixtureSecret: token('secret') })
    : c.start('/api/redeem', { invitationToken: token('invite') });
  await hold.entered; await active.disconnect(); hold.release();
  assert.equal((await active.done).disconnected, true);
  assert.equal((await c.send('/api/session')).body.phase, 'visitor'); assert.equal(h.counts[operation], 1);
});

test('disconnected OIDC exchange cannot begin backend authentication', { timeout: 5000 }, async t => {
  const h = await harness(t, { oidc: true }); const c = h.client(); await c.send('/api/session'); await c.send('/api/oidc/start', {});
  const hold = h.hold('complete'); const active = c.start('/api/oidc/callback', { callbackUrl: 'https://synthetic.invalid/callback' });
  await hold.entered; await active.disconnect(); hold.release();
  assert.equal((await c.send('/api/session')).body.phase, 'visitor'); assert.equal(h.counts.authenticate, 0);
  assert.equal(h.counts.discard, 1);
});

test('closing during backend OIDC authentication cannot restore session authority', { timeout: 5000 }, async t => {
  const h = await harness(t, { oidc: true }); const c = h.client(); await c.send('/api/session'); await c.send('/api/oidc/start', {});
  const hold = h.hold('authenticate'); const active = c.start('/api/oidc/callback', { callbackUrl: 'https://synthetic.invalid/callback' });
  await hold.entered; const closure = h.app.close(); hold.release(); const result = await active.done; await closure;
  assert.equal(result.status, 401); assert.equal(h.counts.authenticate, 1); assert.equal(h.counts.discard, 1);
  assert.equal(result.cookies.some(cookie => !cookie.includes('Max-Age=0')), false);
});

for (const condition of ['close', 'disconnect']) test(`${condition} during registration withholds its pending receipt without replaying the bridge`, { timeout: 5000 }, async t => {
  const h = await harness(t, { oidc: true, registration: true }); const c = h.client(); await c.login();
  const hold = h.hold('register'); const active = c.start('/api/registration', declarations); await hold.entered;
  let closure;
  if (condition === 'close') closure = h.app.close();
  else await active.disconnect();
  hold.release(); const result = await active.done; if (closure) await closure;
  assert.equal(h.counts.register, 1);
  if (condition === 'close') {
    assert.equal(result.status, 503); assert.equal(Object.hasOwn(result.body, 'registrationId'), false);
  } else assert.equal((await c.send('/api/session')).body.phase, 'visitor');
});

test('close prevents an already-admitted registration from reaching its independent bridge', { timeout: 5000 }, async t => {
  const h = await harness(t, { oidc: true, registration: true }); const participant = h.client(); const registrant = h.client();
  await participant.participate(); await registrant.login();
  const hold = h.hold('next'); const active = participant.start('/api/next-comment'); await hold.entered;
  const queued = registrant.start('/api/registration', declarations, true); await queued.admitted();
  const closure = h.app.close(); hold.release(); await active.done;
  assert.equal((await queued.done).status, 503); await closure; assert.equal(h.counts.register, 0);
});

test('disconnect during receipt issuance cannot release an envelope or retain browser authority', { timeout: 5000 }, async t => {
  const h = await harness(t, { oidc: true, receipt: true }); const c = h.client(); await c.login();
  const hold = h.hold('issue'); const active = c.start('/api/registration/receipt', declarations); await hold.entered;
  await active.disconnect(); hold.release();
  assert.equal((await active.done).disconnected, true); assert.equal(h.counts.issue, 1);
  assert.equal((await c.send('/api/session')).body.phase, 'visitor');
});

test('throwing cancellation still closes the listener and drains work once; re-entrant and repeated close share failure', { timeout: 5000 }, async t => {
  const h = await harness(t, { oidc: true }); const participant = h.client(); await participant.participate();
  const pending = [h.client(), h.client()];
  for (const client of pending) { await client.send('/api/session'); await client.send('/api/oidc/start', {}); }
  const hold = h.hold('next'); const active = participant.start('/api/next-comment'); await hold.entered;
  const discardedBefore = h.counts.discard; const nested = [];
  h.failDiscard(() => { nested.push(h.app.close()); });
  const closure = h.app.close(); assert.equal(h.app.close(), closure);
  assert.equal(nested.length, 2); assert.ok(nested.every(value => value === closure));
  let settled = false;
  const failed = assert.rejects(closure, { message: 'Local browser closure was not fully confirmed.' }).then(() => { settled = true; });
  await tick(); assert.equal(settled, false); hold.release();
  assert.equal((await active.done).status, 503); await failed;
  assert.equal(h.counts.discard, discardedBefore + 2); assert.equal(h.app.close(), closure);
  const connectCode = await new Promise(resolve => {
    const socket = connect({ host: '127.0.0.1', port: Number(new URL(h.origin).port) });
    socket.once('connect', () => { socket.destroy(); resolve('UNEXPECTED_OPEN'); });
    socket.once('error', error => resolve(error.code));
  });
  assert.equal(connectCode, 'ECONNREFUSED');
});
