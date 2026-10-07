/** Fresh loopback/model admission checks, not production load or provider QA. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { createLocalAccess, MAX_PENDING_OPERATIONS, INTEGRATED_IDENTITY_MODE } from './access-server.mjs';
import { createLocalBrowser, MAX_BROWSER_REQUESTS } from '../local-browser/browser-server.mjs';
import { ROUND } from './wordpress-events.mjs';

const adminSecret = 'synthetic_admission_admin_'.repeat(3);
const auth = 'synthetic_admission_browser_auth_'.repeat(3);
const fixtureSecret = 'synthetic_admission_fixture_secret_'.repeat(3);
const conversationId = '9syntheticAdmissionOnly';
const capacityMessage = 'Local request capacity reached.';
const pause = () => { let release; const promise = new Promise(resolve => { release = resolve; }); return { promise, release }; };
const waitTurn = () => new Promise(resolve => setImmediate(resolve));

function browserHeaders(origin) {
  return { Origin: origin, 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'same-origin', 'Sec-Fetch-Dest': 'empty' };
}

function startRequest(h, path, { body, method = body === undefined ? 'GET' : 'POST', headers = {}, partial = false, ready = false } = {}) {
  let acknowledge; const arrived = new Promise(resolve => { acknowledge = resolve; });
  let finish;
  const done = new Promise(resolve => { finish = resolve; });
  const req = httpRequest(h.origin + path, { method, agent: false,
    headers: { ...(h.browser ? browserHeaders(h.origin) : {}),
      ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {}),
      ...(partial || ready ? { Expect: '100-continue' } : {}),
      ...(partial ? { 'Transfer-Encoding': 'chunked' } : {}), ...headers },
  }, res => {
    acknowledge(); const chunks = [];
    res.on('data', chunk => chunks.push(chunk));
    res.on('error', () => finish({ transportError: true }));
    res.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8');
      let value; try { value = JSON.parse(text); } catch { value = text; }
      finish({ status: res.statusCode, body: value, headers: res.headers });
    });
  });
  h.requests.add(req);
  req.on('continue', () => { if (partial) req.write('{'); acknowledge(); });
  req.on('error', () => { acknowledge(); finish({ transportError: true }); });
  req.on('close', () => h.requests.delete(req));
  if (partial) req.flushHeaders();
  else req.end(body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body));
  return { req, arrived, done };
}
const send = (h, path, options) => startRequest(h, path, options).done;

async function harness(t, { browser = false, integrated = false, backend, provider } = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'fncp-admission-model-'));
  const dbPath = join(directory, 'invented.sqlite');
  const records = new WeakSet();
  const digest = value => createHash('sha256').update(value).digest('base64url');
  let verifies = 0;
  const identityFoundation = {
    isVerifiedPrincipal(principal) { verifies++; return records.has(principal); },
    participantXid(principal, round) { return { ok: true, xid: 'fncp_' + digest(principal.accountId + round) }; },
  };
  const model = provider ?? { calls: [], async allowlist() { this.calls.push('unexpected'); throw new Error('Model provider forbidden.'); },
    async participate() { this.calls.push('unexpected'); throw new Error('Model provider forbidden.'); } };
  const browserBackend = backend ?? { calls: [], async request(path) { this.calls.push(path); throw new Error('Model backend forbidden.'); } };
  const app = browser ? createLocalBrowser({ mode: 'fixture-only', backend: browserBackend }) :
    createLocalAccess({ mode: 'fixture-only', dbPath, adminSecret, conversationId, provider: model,
      ...(integrated ? { identityMode: INTEGRATED_IDENTITY_MODE, identityFoundation,
        admissionGuard: { assertActive: () => 'synthetic-admission-generation', close() {} } } : {}) });
  const h = { app, origin: await app.listen(0), browser, requests: new Set(), releases: [], model, backend: browserBackend,
    verificationCount: () => verifies,
    mint(label) {
      const principal = Object.freeze({ mode: 'SYNTHETIC_ONLY', assurance: 'OIDC_ID_TOKEN_VERIFIED', emailVerifiedByIssuer: true,
        accountId: 'acct_' + digest(label) }); records.add(principal); return principal;
    },
    snapshot() {
      const db = new DatabaseSync(dbPath, { readOnly: true });
      try {
        return Object.fromEntries(['round', 'fixtures', 'approvals', 'invitations', 'sessions', 'wordpress_events',
          ...(integrated ? ['identity_mappings'] : [])].map(table => [table, db.prepare(`SELECT * FROM ${table} ORDER BY 1`).all()]));
      } finally { db.close(); }
    },
  };
  t.after(async () => {
    for (const release of h.releases) release();
    for (const request of h.requests) request.destroy();
    await app.close();
    await rm(directory, { recursive: true }); // Exact test-owned mkdtemp directory only.
  });
  return h;
}

function assertCapacity(result) {
  assert.equal(result.status, 503);
  assert.deepEqual(result.body, { ...(Object.hasOwn(result.body, 'mode') ? { mode: 'SYNTHETIC_ONLY' } : {}), error: capacityMessage });
}

for (const browser of [false, true]) test(`${browser ? 'browser' : 'access'} reserves capacity before slow body collection and recovers after abort`, { timeout: 10_000 }, async t => {
  const h = await harness(t, { browser });
  const limit = browser ? MAX_BROWSER_REQUESTS : MAX_PENDING_OPERATIONS;
  const healthy = browser ? '/api/session' : '/health';
  const before = browser ? undefined : h.snapshot();
  const held = [];
  for (let i = 0; i < limit; i++) {
    const request = startRequest(h, browser ? '/api/login' : '/test-admin/fixtures', { method: 'POST', partial: true });
    await request.arrived; held.push(request);
  }
  assertCapacity(await send(h, healthy));
  const excess = startRequest(h, '/unused', { method: 'POST', partial: true });
  assertCapacity(await excess.done);
  assert.equal((await excess.done).headers.connection, 'close');
  if (!browser) {
    await assert.rejects(h.app.ingestWordPressEvent({}), error => error.status === 503 && error.message === capacityMessage);
    assert.deepEqual(h.snapshot(), before);
  }
  assert.equal(h.model.calls.length, 0); assert.equal(h.backend.calls.length, 0);
  held[0].req.destroy();
  let recovered;
  for (let i = 0; i < 100; i++) {
    await waitTurn(); recovered = await send(h, healthy);
    if (recovered.status === 200) break;
    assertCapacity(recovered);
  }
  assert.equal(recovered.status, 200);
  assert.equal(h.model.calls.length, 0); assert.equal(h.backend.calls.length, 0);
  if (!browser) assert.deepEqual(h.snapshot(), before);
});

test('browser running and queued dispatches share the reader bound, preserve serialization and release slots', { timeout: 10_000 }, async t => {
  const gate = pause(); const entered = pause();
  const backend = { calls: [], async request(path) {
    this.calls.push(path); entered.release(); await gate.promise;
    return { status: 200, body: { fixtureAuthToken: auth, mailboxOwnership: 'SIMULATED_NOT_VERIFIED' } };
  } };
  const h = await harness(t, { browser: true, backend }); h.releases.push(gate.release);
  const session = await send(h, '/api/session');
  const headers = { Cookie: session.headers['set-cookie'][0].split(';')[0], 'X-CSRF-Token': session.body.csrf };
  const active = send(h, '/api/login', { headers, body: { fixture: 'synthetic_alice', fixtureSecret } });
  await entered.promise;
  const queued = [];
  for (let i = 1; i < MAX_BROWSER_REQUESTS; i++) {
    const request = startRequest(h, '/api/session', { headers, ready: true });
    await request.arrived; queued.push(request.done);
  }
  assertCapacity(await send(h, '/api/login', { headers, body: { fixture: 'synthetic_alice', fixtureSecret } }));
  assert.deepEqual(backend.calls, ['/test-auth/mailbox-simulator']);
  gate.release(); assert.equal((await active).status, 200);
  assert.ok((await Promise.all(queued)).every(result => result.status === 200));
  assert.equal((await send(h, '/api/session')).status, 200);
  assert.deepEqual(backend.calls, ['/test-auth/mailbox-simulator']);
});

test('access HTTP and all three direct entry points share one finite queue; overflow cannot touch state or provider', { timeout: 10_000 }, async t => {
  const gate = pause(); const entered = pause(); const states = new Map();
  const provider = { calls: [], async allowlist(operation, xid) {
    this.calls.push(operation);
    if (operation === 'upsert') { entered.release(); await gate.promise; states.set(xid, { present: true, operationVersion: 1 }); }
    return states.get(xid);
  } };
  const h = await harness(t, { integrated: true, provider }); h.releases.push(gate.release);
  const principal = h.mint('synthetic_admission_alice');
  const other = h.mint('synthetic_admission_bob');
  const authenticated = await h.app.authenticateIdentity(principal);
  const event = { schema_version: 1, event_id: randomUUID(), subject: authenticated.fixture, round_id: ROUND,
    version: 1, state: 'approved', occurred_at: '2026-09-13T00:00:00Z' };
  const running = h.app.ingestWordPressEvent(event); await entered.promise;
  const queued = Array.from({ length: MAX_PENDING_OPERATIONS - 1 }, () => h.app.registrationIdentity(principal));
  const snapshot = h.snapshot(); const verificationCount = h.verificationCount();
  for (const operation of [() => h.app.authenticateIdentity(other), () => h.app.registrationIdentity(principal),
    () => h.app.ingestWordPressEvent({ ...event, event_id: randomUUID(), version: 2, state: 'revoked' })]) {
    await assert.rejects(operation(), error => error.status === 503 && error.message === capacityMessage);
  }
  assertCapacity(await send(h, '/health'));
  assert.deepEqual(h.snapshot(), snapshot); assert.equal(h.verificationCount(), verificationCount);
  assert.deepEqual(provider.calls, ['upsert']);
  gate.release(); assert.equal((await running).outcome, 'APPLIED');
  assert.ok((await Promise.all(queued)).every(result => result.fixture === authenticated.fixture));
  assert.deepEqual(provider.calls, ['upsert', 'readback']);
  assert.equal((await send(h, '/health')).status, 200);
  assert.equal((await h.app.authenticateIdentity(other)).mode, 'SYNTHETIC_ONLY');
});

for (const browser of [false, true]) test(`${browser ? 'browser' : 'access'} malformed and denied requests do not leak admission slots`, { timeout: 10_000 }, async t => {
  const h = await harness(t, { browser }); const before = browser ? undefined : h.snapshot();
  for (let i = 0; i < MAX_PENDING_OPERATIONS + 1; i++) {
    const invalid = await send(h, browser ? '/api/login' : '/test-admin/fixtures', { body: '{' });
    assert.equal(invalid.status, 400);
    const denied = await send(h, browser ? '/api/session' : '/health', { headers: { Origin: 'https://synthetic-invalid.example' } });
    assert.equal(denied.status, 403);
  }
  assert.equal((await send(h, browser ? '/api/session' : '/health')).status, 200);
  assert.equal(h.model.calls.length, 0); assert.equal(h.backend.calls.length, 0);
  if (!browser) assert.deepEqual(h.snapshot(), before);
});

test('rejected direct access operations release their slot and retain no synthetic state', async t => {
  const h = await harness(t, { integrated: true }); const before = h.snapshot();
  for (let i = 0; i < MAX_PENDING_OPERATIONS + 1; i++) {
    await assert.rejects(h.app.ingestWordPressEvent({}), error => error.status === 400);
    await assert.rejects(h.app.authenticateIdentity(Object.freeze({})), error => error.status === 401);
    await assert.rejects(h.app.registrationIdentity(Object.freeze({})), error => error.status === 401);
  }
  assert.equal((await send(h, '/health')).status, 200);
  assert.deepEqual(h.snapshot(), before); assert.equal(h.model.calls.length, 0);
});
