/** Fresh in-memory models and ephemeral HTTP only; not provider round closure. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { connect } from 'node:net';
import { createLocalAccess, INTEGRATED_IDENTITY_MODE } from './access-server.mjs';
import { ROUND } from './wordpress-events.mjs';
import { createLocalBrowser } from '../local-browser/browser-server.mjs';
import { createBrowserClient } from '../local-browser/integration-client.mjs';

const credentials = 'invented_shutdown_secret_'.repeat(3);
const digest = (value) => createHash('sha256').update(value).digest('base64url');
const pause = () => { let release; const promise = new Promise(resolve => { release = resolve; }); return { promise, release }; };
const turn = () => new Promise(resolve => setImmediate(resolve));
const closed = error => error.status === 503 && error.message === 'Local service is closing.';
const noProvider = { allowlist() { throw new Error('No provider call permitted.'); }, participate() { throw new Error('No provider call permitted.'); } };
function access(provider = noProvider, integrated = false) {
  const known = new WeakSet(); let verifications = 0;
  const app = createLocalAccess({ mode: 'fixture-only', dbPath: ':memory:', adminSecret: credentials,
    conversationId: '9syntheticShutdownRound', provider,
    ...(integrated ? { identityMode: INTEGRATED_IDENTITY_MODE, admissionGuard: {
      assertActive() { return 'synthetic_shutdown_generation'; }, close() {},
    }, identityFoundation: {
      isVerifiedPrincipal(principal) { verifications++; return known.has(principal); },
      participantXid(principal, round) { return { ok: true, xid: 'fncp_' + digest(principal.accountId + round) }; },
    } } : {}),
  });
  return { app, verifications: () => verifications, mint(label) {
    const principal = Object.freeze({ accountId: 'acct_' + digest(label), emailVerifiedByIssuer: true,
      assurance: 'OIDC_ID_TOKEN_VERIFIED', mode: 'SYNTHETIC_ONLY', eligibilityVerified: false });
    known.add(principal); return principal;
  } };
}
const browser = () => createLocalBrowser({ mode: 'fixture-only', backend: { request() { throw new Error('No backend call permitted.'); } } });
async function refused(origin) {
  await new Promise((resolve, reject) => {
    const socket = connect({ host: '127.0.0.1', port: Number(new URL(origin).port) });
    socket.setTimeout(1000);
    socket.once('connect', () => { socket.destroy(); reject(new Error('Listener remained open.')); });
    socket.once('timeout', () => { socket.destroy(); reject(new Error('Listener check timed out.')); });
    socket.once('error', error => { socket.destroy(); error.code === 'ECONNREFUSED' ? resolve() : reject(error); });
  });
}

for (const [name, make] of [['access', () => access().app], ['browser', browser]]) {
  test(`${name} close before listen is idempotent and permanently denies reuse`, async t => {
    const app = make(); t.after(() => app.close());
    const first = app.close(); assert.equal(app.close(), first); await first;
    assert.equal(app.close(), first);
    await assert.rejects(app.listen(0), { message: 'Local service is closing.' });
  });
  test(`${name} idle close drains once and independently removes its listener`, async t => {
    const app = make(); t.after(() => app.close()); const origin = await app.listen(0);
    const first = app.close(); assert.equal(app.close(), first); await first;
    await refused(origin); await assert.rejects(app.listen(0), { message: 'Local service is closing.' });
  });
}

test('all direct access entry points reject immediately after close without verifying or reopening SQLite', async t => {
  const h = access(noProvider, true); t.after(() => h.app.close());
  const principal = h.mint('synthetic_lifecycle_subject');
  const before = h.verifications(); await h.app.close();
  for (const operation of [() => h.app.authenticateIdentity(principal), () => h.app.registrationIdentity(principal),
    () => h.app.ingestWordPressEvent({})]) await assert.rejects(operation(), closed);
  assert.equal(h.verifications(), before);
});

test('close latches before await, drains admitted side effects, and does not admit new direct work', { timeout: 5000 }, async t => {
  const entered = pause(); const held = pause(); const calls = [];
  const provider = { async allowlist(operation) {
    calls.push(operation);
    if (operation === 'upsert') { entered.release(); await held.promise; }
    return { present: true, operationVersion: 1 };
  } };
  const h = access(provider, true); t.after(async () => { held.release(); await h.app.close(); });
  const origin = await h.app.listen(0); const principal = h.mint('synthetic_lifecycle_subject');
  const authenticated = await h.app.authenticateIdentity(principal);
  const event = { schema_version: 1, event_id: randomUUID(), subject: authenticated.fixture,
    round_id: ROUND, version: 1, state: 'approved', occurred_at: '2026-09-13T00:00:00Z' };
  const running = h.app.ingestWordPressEvent(event); await entered.promise;
  const previouslyAdmitted = h.app.registrationIdentity(principal);
  const closing = h.app.close(); assert.equal(h.app.close(), closing);
  let drained = false; closing.then(() => { drained = true; });
  const before = h.verifications();
  for (const operation of [() => h.app.authenticateIdentity(principal), () => h.app.registrationIdentity(principal),
    () => h.app.ingestWordPressEvent(event)]) await assert.rejects(operation(), closed);
  await turn(); assert.equal(drained, false); assert.equal(h.verifications(), before);
  assert.deepEqual(calls, ['upsert']);
  held.release(); assert.equal((await running).outcome, 'APPLIED');
  assert.equal((await previouslyAdmitted).fixture, authenticated.fixture);
  await closing; assert.deepEqual(calls, ['upsert', 'readback']); await refused(origin);
});

test('failed admitted operation is not retried and does not prevent the drain from completing', { timeout: 5000 }, async t => {
  const entered = pause(); const held = pause(); let calls = 0;
  const h = access({ async allowlist() { calls++; entered.release(); await held.promise; throw new Error('Invented upstream failure.'); } }, true);
  t.after(async () => { held.release(); await h.app.close(); });
  const principal = h.mint('synthetic_lifecycle_subject'); const authenticated = await h.app.authenticateIdentity(principal);
  const running = h.app.ingestWordPressEvent({ schema_version: 1, event_id: randomUUID(), subject: authenticated.fixture,
    round_id: ROUND, version: 1, state: 'approved', occurred_at: '2026-09-13T00:00:00Z' });
  const rejected = assert.rejects(running);
  await entered.promise; const closing = h.app.close(); held.release(); await rejected; await closing;
  assert.equal(calls, 1); await assert.rejects(h.app.ingestWordPressEvent({}), closed);
});

test('browser shutdown drains an admitted operation without restoring late authentication or replaying it', { timeout: 5000 }, async t => {
  const entered = pause(); const held = pause(); let calls = 0;
  const app = createLocalBrowser({ mode: 'fixture-only', backend: { async request(path) {
    calls++; assert.equal(path, '/test-auth/mailbox-simulator'); entered.release(); await held.promise;
    return { status: 200, body: { fixtureAuthToken: credentials, mailboxOwnership: 'SIMULATED_NOT_VERIFIED' } };
  } } });
  t.after(async () => { held.release(); await app.close(); });
  const origin = await app.listen(0); const client = createBrowserClient(origin); await client.session();
  const result = client.login('synthetic_alice', credentials); await entered.promise;
  const closing = app.close(); assert.equal(app.close(), closing); let drained = false;
  closing.then(() => { drained = true; }); await turn(); assert.equal(drained, false);
  held.release(); const response = await result;
  // Draining the already-started backend call is not permission to mint a new
  // browser session after closure has revoked local authority.
  assert.equal(response.status, 503);
  assert.deepEqual(response.body, { mode: 'SYNTHETIC_ONLY',
    error: 'The request ended before its outcome could be confirmed. Do not resubmit automatically.' });
  await closing;
  assert.equal(calls, 1); await refused(origin);
  await assert.rejects(app.listen(0), { message: 'Local service is closing.' });
});
