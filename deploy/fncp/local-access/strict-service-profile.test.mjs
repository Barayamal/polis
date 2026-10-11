/** Fresh in-memory SQLite/authority models and test-owned loopback listeners.
 * These tests do not integrate a real identity provider, WordPress or Pol.is.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { connect } from 'node:net';
import { createLocalAccess, INTEGRATED_IDENTITY_MODE, STRICT_SERVICE_HTTP_PROFILE, MAX_PENDING_OPERATIONS } from './access-server.mjs';
import { ROUND } from './wordpress-events.mjs';
import { createActivationAuthority } from '../activation-foundation/authority.mjs';
import { syntheticBinding, syntheticClaims, syntheticSigningFixture } from '../activation-foundation/synthetic-fixtures.mjs';

const secret = 'invented_strict_operator_secret_'.repeat(3);
const digest = value => createHash('sha256').update(value).digest('base64url');
const pause = () => { let release; const promise = new Promise(resolve => { release = resolve; }); return { promise, release }; };
const hasStatus = status => error => error.status === status;
const noProvider = { allowlist() { throw new Error('Unexpected provider call.'); }, participate() { throw new Error('Unexpected provider call.'); } };
const minimal = () => ({ mode: 'fixture-only', dbPath: ':memory:', adminSecret: secret,
  conversationId: '9syntheticStrictProfile', provider: noProvider });
const identity = () => ({ isVerifiedPrincipal() { return false; }, participantXid() { return { ok: false }; } });
const guard = () => ({ assertActive() { throw new Error('Closed.'); }, close() {} });

async function harness(t, options = {}) {
  const { providerPause } = options;
  const profile = Object.hasOwn(options, 'profile') ? options.profile : STRICT_SERVICE_HTTP_PROFILE;
  const known = new WeakSet(); const signer = syntheticSigningFixture(); const binding = syntheticBinding();
  const states = new Map(); const calls = []; let time = 1_000_000;
  const authority = createActivationAuthority({ mode: 'SYNTHETIC_ONLY', binding,
    publicKey: signer.publicKey, keyId: signer.keyId, ledgerPath: ':memory:', now: () => time });
  const provider = { async allowlist(operation, xid) {
    calls.push(operation); if (operation === 'upsert') await providerPause?.();
    if (operation === 'upsert') states.set(xid, { present: true, operationVersion: 1 });
    if (operation === 'remove') states.set(xid, { present: false, operationVersion: 2 });
    return states.get(xid) ?? { present: false, operationVersion: null };
  }, async participate() { calls.push('participate'); return { nextComment: { tid: 1, txt: 'Invented statement.' } }; } };
  const identityFoundation = {
    isVerifiedPrincipal(principal) { return known.has(principal); },
    participantXid(principal, round) { return { ok: true, xid: 'fncp_' + digest(principal.accountId + round) }; },
  };
  const app = createLocalAccess({ ...minimal(), conversationId: binding.conversationId, provider,
    identityMode: INTEGRATED_IDENTITY_MODE, identityFoundation, admissionGuard: authority,
    httpProfile: profile, now: () => time });
  t.after(async () => { try { await app.close(); } finally { authority.dispose(); } });
  let origin;
  const request = async (path, body, credential = secret) => {
    origin ??= await app.listen(0);
    const response = await fetch(origin + path, { method: body === undefined ? 'GET' : 'POST',
      redirect: 'error', signal: AbortSignal.timeout(3000), headers: {
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        ...(credential ? { Authorization: 'Bearer ' + credential } : {}),
      }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    return { status: response.status, body: await response.json() };
  };
  const mint = label => {
    const principal = Object.freeze({ mode: 'SYNTHETIC_ONLY', assurance: 'OIDC_ID_TOKEN_VERIFIED',
      accountId: 'acct_' + digest(label), emailVerifiedByIssuer: true, eligibilityVerified: false });
    known.add(principal); return principal;
  };
  return { app, authority, calls, request, origin: () => origin, mint,
    time: next => { time = next; },
    activate() { return authority.activate(signer.signClaims(syntheticClaims(authority.binding(), Math.floor(time / 1000),
      { sequence: authority.nextSequence() }))); },
    event(fixture, state = 'approved', version = 1) { return { schema_version: 1, event_id: randomUUID(),
      subject: fixture, round_id: ROUND, version, state, occurred_at: '2026-09-13T00:00:00Z' }; },
    async approved(label = 'synthetic_strict_alice') {
      const principal = mint(label); const authenticated = await app.authenticateIdentity(principal);
      assert.equal((await app.ingestWordPressEvent(this.event(authenticated.fixture))).outcome, 'APPLIED');
      return { principal, ...authenticated };
    },
  };
}

for (const [name, options] of [
  ['unknown HTTP profile', { httpProfile: 'production' }],
  ['null HTTP profile', { httpProfile: null }],
  ['legacy identity with strict service', { httpProfile: STRICT_SERVICE_HTTP_PROFILE }],
  ['strict identity without activation', { httpProfile: STRICT_SERVICE_HTTP_PROFILE, identityMode: INTEGRATED_IDENTITY_MODE, identityFoundation: identity() }],
  ['activation without strict identity', { httpProfile: STRICT_SERVICE_HTTP_PROFILE, admissionGuard: guard() }],
  ['strict profile without identity foundation', { httpProfile: STRICT_SERVICE_HTTP_PROFILE, identityMode: INTEGRATED_IDENTITY_MODE, admissionGuard: guard() }],
]) test(name + ' is rejected before a database is opened', () => {
  assert.throws(() => createLocalAccess({ ...minimal(), ...options }), /configuration|requires/);
});

test('strict profile returns only three frozen operator methods without raw dispatch or approval', async t => {
  const h = await harness(t);
  assert.equal(Object.isFrozen(h.app.operator), true);
  assert.deepEqual(Object.keys(h.app.operator).sort(), ['issueInvitation', 'setRoundOpen', 'status']);
  for (const name of ['approve', 'revoke', 'fixtures', 'dispatch', 'activate', 'sign', 'injectTestResponse']) {
    assert.equal(h.app.operator[name], undefined); assert.equal(h.app[name], undefined);
  }
});

test('default legacy HTTP profile is unchanged and has no private operator capability', async t => {
  const app = createLocalAccess(minimal()); t.after(() => app.close()); const origin = await app.listen(0);
  assert.equal(app.operator, undefined);
  const response = await fetch(origin + '/test-admin/status', { headers: { Authorization: 'Bearer ' + secret } });
  assert.equal(response.status, 200); assert.equal((await response.json()).open, false);
});

test('default integrated profile retains existing test admin behavior without private operator capability', async t => {
  const h = await harness(t, { profile: undefined });
  // Explicit undefined is intentionally identical to the preexisting profile.
  assert.equal(h.app.operator, undefined);
  assert.equal((await h.request('/test-admin/status')).status, 200);
});

for (const path of ['/test-admin/status', '/test-admin/fixtures', '/test-admin/round', '/test-admin/approve',
  '/test-admin/revoke', '/test-admin/invitations', '/test-admin/activate', '/test-admin', '/test-admin-extra',
  '/test-auth/mailbox-simulator', '/test-auth', '/test-auth-extra']) {
  test('strict profile denies HTTP ' + path + ' even with the correct bearer', async t => {
    const h = await harness(t); h.activate();
    for (const body of [undefined, {}]) assert.equal((await h.request(path, body)).status, 404);
    assert.deepEqual(h.calls, []); assert.equal((await h.app.operator.status()).fixtures, 0);
  });
}

test('strict HTTP health remains available, but never advertises production or heritage verification', async t => {
  const h = await harness(t); const result = await h.request('/health', undefined, undefined);
  assert.equal(result.status, 200); assert.equal(result.body.identityMode, INTEGRATED_IDENTITY_MODE);
  assert.equal(result.body.productionReady, false); assert.equal(result.body.heritageVerification, false);
});

test('private operators require exact primitive inputs and no extra arguments', async t => {
  const h = await harness(t);
  for (const call of [() => h.app.operator.status({}), () => h.app.operator.setRoundOpen(),
    () => h.app.operator.setRoundOpen('true'), () => h.app.operator.setRoundOpen({ open: true }),
    () => h.app.operator.setRoundOpen(false, true), () => h.app.operator.issueInvitation(),
    () => h.app.operator.issueInvitation({ fixture: 'synthetic_alice' }),
    () => h.app.operator.issueInvitation('synthetic_alice'),
    () => h.app.operator.issueInvitation('person@example.invalid'),
    () => h.app.operator.issueInvitation('synthetic_i' + 'a'.repeat(39), 900),
  ]) await assert.rejects(call(), hasStatus(400));
  assert.equal((await h.app.operator.status()).open, false); assert.deepEqual(h.calls, []);
});

test('strict private round open requires separately signed authority; status and close remain available', async t => {
  const h = await harness(t);
  assert.equal((await h.app.operator.status()).open, false);
  await assert.rejects(h.app.operator.setRoundOpen(true), hasStatus(403));
  assert.equal((await h.app.operator.setRoundOpen(false)).open, false);
  h.activate(); assert.equal((await h.app.operator.status()).open, false);
  assert.equal((await h.app.operator.setRoundOpen(true)).open, true);
  assert.equal((await h.app.operator.setRoundOpen(false)).open, false);
  await assert.rejects(h.app.operator.setRoundOpen(true), hasStatus(403));
});

test('invitation issuance still requires current identity, signed-event approval and open round', async t => {
  const h = await harness(t); h.activate();
  const principal = h.mint('synthetic_not_approved'); const account = await h.app.authenticateIdentity(principal);
  await assert.rejects(h.app.operator.issueInvitation(account.fixture), hasStatus(403));
  assert.equal((await h.app.ingestWordPressEvent(h.event(account.fixture))).outcome, 'APPLIED');
  await assert.rejects(h.app.operator.issueInvitation(account.fixture), hasStatus(403));
  await h.app.operator.setRoundOpen(true);
  const invitation = await h.app.operator.issueInvitation(account.fixture);
  assert.match(invitation.invitationToken, /^[A-Za-z0-9_-]{43}$/u);
  assert.equal(invitation.expiresAt, 1_600_000); assert.equal(invitation.delivery, 'LOCAL_RESPONSE_ONLY_NO_EMAIL_OR_MESSAGE');
  assert.deepEqual(h.calls, ['upsert', 'readback']);
});

test('private invitation replacement invalidates earlier token and keeps current-account binding', async t => {
  const h = await harness(t); h.activate(); await h.app.operator.setRoundOpen(true);
  const alice = await h.approved(); const bob = await h.approved('synthetic_strict_bob');
  const first = await h.app.operator.issueInvitation(alice.fixture); const second = await h.app.operator.issueInvitation(alice.fixture);
  assert.notEqual(first.invitationToken, second.invitationToken);
  assert.equal((await h.request('/invitations/redeem', { invitationToken: first.invitationToken }, alice.fixtureAuthToken)).status, 403);
  assert.equal((await h.request('/invitations/redeem', { invitationToken: second.invitationToken }, bob.fixtureAuthToken)).status, 403);
  assert.equal((await h.request('/invitations/redeem', { invitationToken: second.invitationToken }, alice.fixtureAuthToken)).status, 201);
});

test('signed revocation still works while every HTTP operator route is removed', async t => {
  const h = await harness(t); h.activate(); await h.app.operator.setRoundOpen(true);
  const account = await h.approved(); await h.app.operator.issueInvitation(account.fixture);
  assert.equal((await h.app.ingestWordPressEvent(h.event(account.fixture, 'revoked', 2))).outcome, 'APPLIED');
  await assert.rejects(h.app.operator.issueInvitation(account.fixture), hasStatus(401));
  assert.deepEqual(h.calls, ['upsert', 'readback', 'remove', 'readback']);
});

test('expired authority closes strict service and cannot be revived by operator open or invitation', async t => {
  const h = await harness(t); h.activate(); await h.app.operator.setRoundOpen(true); const account = await h.approved();
  h.time(1_300_000);
  assert.equal((await h.app.operator.status()).open, false);
  await assert.rejects(h.app.operator.setRoundOpen(true), hasStatus(403));
  await assert.rejects(h.app.operator.issueInvitation(account.fixture), hasStatus(403));
});

test('a new activation generation invalidates prior strict operator invitation eligibility', async t => {
  const h = await harness(t); h.activate(); await h.app.operator.setRoundOpen(true); const account = await h.approved();
  const invitation = await h.app.operator.issueInvitation(account.fixture); h.activate();
  assert.equal((await h.app.operator.status()).open, false); await h.app.operator.setRoundOpen(true);
  await assert.rejects(h.app.operator.issueInvitation(account.fixture), hasStatus(401));
  assert.equal((await h.request('/invitations/redeem', { invitationToken: invitation.invitationToken }, account.fixtureAuthToken)).status, 401);
});

test('operator requests share the 32-operation queue cap with signed event ingest', { timeout: 5000 }, async t => {
  const entered = pause(); const held = pause(); t.after(() => held.release());
  const h = await harness(t, { providerPause: async () => { entered.release(); await held.promise; } });
  h.activate(); const account = await h.app.authenticateIdentity(h.mint('synthetic_queue_bound'));
  const approval = h.app.ingestWordPressEvent(h.event(account.fixture)); await entered.promise;
  const pending = Array.from({ length: MAX_PENDING_OPERATIONS - 1 }, () => h.app.operator.status());
  for (const call of [() => h.app.operator.status(), () => h.app.operator.setRoundOpen(false),
    () => h.app.operator.issueInvitation(account.fixture)]) await assert.rejects(call(), hasStatus(503));
  held.release(); await approval; assert.equal((await Promise.all(pending)).length, 31);
  assert.equal((await h.app.operator.status()).fixtures, 1);
});

test('shutdown rejects new operator work but drains previously admitted operator work', { timeout: 5000 }, async t => {
  const entered = pause(); const held = pause(); t.after(() => held.release());
  const h = await harness(t, { providerPause: async () => { entered.release(); await held.promise; } });
  h.activate(); const account = await h.app.authenticateIdentity(h.mint('synthetic_shutdown_operator'));
  await h.request('/health'); const approval = h.app.ingestWordPressEvent(h.event(account.fixture)); await entered.promise;
  const admitted = h.app.operator.status(); const closing = h.app.close();
  for (const call of [() => h.app.operator.status(), () => h.app.operator.setRoundOpen(false),
    () => h.app.operator.issueInvitation(account.fixture)]) await assert.rejects(call(), hasStatus(503));
  held.release(); await approval; assert.equal((await admitted).fixtures, 1); await closing;
  await new Promise((resolve, reject) => {
    const socket = connect({ host: '127.0.0.1', port: Number(new URL(h.origin()).port) }); socket.setTimeout(1000);
    socket.once('connect', () => { socket.destroy(); reject(new Error('Owned listener remained open.')); });
    socket.once('timeout', () => { socket.destroy(); reject(new Error('Owned listener check timed out.')); });
    socket.once('error', error => { socket.destroy(); error.code === 'ECONNREFUSED' ? resolve() : reject(error); });
  });
});
