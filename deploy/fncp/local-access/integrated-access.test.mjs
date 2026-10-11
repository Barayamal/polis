/** Invented-principal/provider tests only. Not a real OIDC or Pol.is deployment. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { DatabaseSync } from 'node:sqlite';
import { createLocalAccess, MODE, INTEGRATED_IDENTITY_MODE } from './access-server.mjs';
import { ROUND } from './wordpress-events.mjs';
import { createControlledLocalAccess } from '../activation-foundation/controlled-access.mjs';
import { syntheticBinding, syntheticSigningFixture, syntheticClaims } from '../activation-foundation/synthetic-fixtures.mjs';

const digest = value => createHash('sha256').update(value).digest('base64url');
const adminSecret = 'synthetic_admin_credential_'.repeat(3);
const conversationId = '9syntheticIdentityRound';
function brandedFoundation(now) {
  const records = new WeakMap();
  const valid = principal => records.has(principal) && records.get(principal).expires > now();
  return { foundation: Object.freeze({
    isVerifiedPrincipal: valid,
    participantXid(principal, round) { return valid(principal) ? { ok: true, xid: 'fncp_' + digest(principal.accountId + ':' + round) } : { ok: false }; },
  }), mint(label = 'synthetic_alice', changes = {}) {
    const principal = Object.freeze({ accountId: 'acct_' + digest(label), emailVerifiedByIssuer: true,
      assurance: 'OIDC_ID_TOKEN_VERIFIED', mode: 'SYNTHETIC_ONLY', eligibilityVerified: false, ...changes });
    records.set(principal, { expires: now() + 10_000 }); return principal;
  } };
}
async function harness(t, settings = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'fncp-integrated-access-'));
  let stamp = 1_000_000; let generation = 0; let active = false;
  const identity = brandedFoundation(() => stamp); const states = new Map();
  const provider = { calls: [], pause: undefined,
    async allowlist(operation, xid) {
      this.calls.push({ operation, xid }); await this.pause?.(operation);
      if (operation === 'upsert') states.set(xid, { present: true, operationVersion: 1 });
      if (operation === 'remove') states.set(xid, { present: false, operationVersion: 2 });
      return states.get(xid) ?? { present: false, operationVersion: null };
    },
    async participate(kind, xid) {
      this.calls.push({ operation: kind, xid }); await this.pause?.(kind);
      return { nextComment: { tid: 1, txt: 'Synthetic statement only.' } };
    } };
  const guard = { assertActive() { if (!active) throw new Error('Closed fixture guard.'); return String(generation); }, close() { active = false; } };
  const config = { mode: MODE, identityMode: INTEGRATED_IDENTITY_MODE, identityFoundation: identity.foundation,
    admissionGuard: guard, dbPath: join(directory, 'integrated.sqlite'), adminSecret, conversationId, provider, now: () => stamp,
    ...(settings.authLifetimeMs === undefined ? {} : { authLifetimeMs: settings.authLifetimeMs }) };
  let app = createLocalAccess(config); let origin = await app.listen(0);
  t.after(async () => { await app.close(); await rm(directory, { recursive: true }); });
  const request = async (path, body, token) => {
    const result = await fetch(origin + path, { method: body === undefined ? 'GET' : 'POST',
      headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...(token ? { Authorization: 'Bearer ' + token } : {}) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    return { status: result.status, body: await result.json() };
  };
  const admin = (path, body) => request('/test-admin/' + path, body, adminSecret);
  const event = (fixture, version = 1, state = 'approved') => ({ schema_version: 1, event_id: randomUUID(),
    subject: fixture, round_id: ROUND, version, state, occurred_at: '2026-09-13T02:30:00Z' });
  const activate = async () => { active = true; generation++; assert.equal((await admin('round', { open: true })).status, 200); };
  const login = principal => app.authenticateIdentity(principal);
  const registration = principal => app.registrationIdentity(principal);
  const wp = event => app.ingestWordPressEvent(event);
  async function participant(label = 'synthetic_alice') {
    await activate(); const principal = identity.mint(label); const user = await login(principal);
    await wp(event(user.fixture)); const invitation = await admin('invitations', { fixture: user.fixture });
    assert.equal(invitation.status, 201);
    const redeemed = await request('/invitations/redeem', { invitationToken: invitation.body.invitationToken }, user.fixtureAuthToken);
    assert.equal(redeemed.status, 201);
    return { ...user, principal, participationToken: redeemed.body.participationToken, invitationToken: invitation.body.invitationToken };
  }
  return { directory, config, provider, identity, request, admin, event, activate, login, registration, wp, participant,
    activateClosed() { active = true; generation++; },
    advance(ms = 10_001) { stamp += ms; }, closeAuthority() { active = false; },
    async restart() { await app.close(); app = createLocalAccess(config); origin = await app.listen(0); },
    snapshot() { const db = new DatabaseSync(config.dbPath, { readOnly: true }); try {
      return { mappings: db.prepare('SELECT * FROM identity_mappings').all(), approvals: db.prepare('SELECT * FROM approvals').all(),
        sessions: db.prepare('SELECT * FROM sessions').all(), events: db.prepare('SELECT * FROM wordpress_events').all(),
        rounds: db.prepare('SELECT * FROM round').all(), invitations: db.prepare('SELECT * FROM invitations').all() };
    } finally { db.close(); } },
  };
}

test('strict integration requires explicit mode, an admission guard and the trusted identity interface', () => {
  const base = { mode: MODE, dbPath: ':memory:', adminSecret, conversationId, provider: {} };
  const foundation = brandedFoundation(Date.now).foundation;
  for (const extra of [{ identityMode: true }, { identityFoundation: foundation },
    { identityMode: INTEGRATED_IDENTITY_MODE }, { identityMode: INTEGRATED_IDENTITY_MODE, identityFoundation: foundation }]) {
    assert.throws(() => createLocalAccess({ ...base, ...extra }), /identity integration/);
  }
});
test('verified sign-in creates only opaque mapping/authentication; never approval, provider access or invitations', async t => {
  const h = await harness(t); const user = await h.login(h.identity.mint());
  assert.deepEqual(Object.keys(user).sort(), ['assurance', 'fixture', 'fixtureAuthToken', 'mode']);
  assert.equal(user.assurance, 'OIDC_ID_TOKEN_VERIFIED'); assert.equal(user.mode, 'SYNTHETIC_ONLY');
  assert.match(user.fixture, /^synthetic_i[a-f0-9]{39}$/u);
  assert.equal(h.provider.calls.length, 0); assert.equal(h.snapshot().approvals.length, 0);
  assert.equal((await h.admin('status')).body.open, false);
  assert.equal((await h.admin('invitations', { fixture: user.fixture })).status, 403);
  for (const [path, body] of [['/test-admin/fixtures', { fixture: 'synthetic_forged' }],
    ['/test-auth/mailbox-simulator', { fixture: user.fixture, fixtureSecret: 'a'.repeat(43) }],
    ['/identity/authenticate', { principal: { accountId: 'forged' } }]]) {
    assert.equal((await h.request(path, body, adminSecret)).status, 404);
  }
});
test('copied, forged, other-instance, expired, non-verified-email and wrong-assurance principals are rejected', async t => {
  const h = await harness(t); const principal = h.identity.mint();
  const others = brandedFoundation(() => 1_000_000);
  for (const candidate of [null, Object.freeze({ ...principal }), others.mint(),
    h.identity.mint('synthetic_no_email', { emailVerifiedByIssuer: false }),
    h.identity.mint('synthetic_wrong_mode', { mode: 'production' }),
    h.identity.mint('synthetic_bad_id', { accountId: 'person@example.test' }),
    h.identity.mint('synthetic_bad_assurance', { assurance: 'SIMULATED' })]) {
    await assert.rejects(h.login(candidate), e => e.status === 401);
  }
  h.advance(); await assert.rejects(h.login(principal), e => e.status === 401);
  assert.equal(h.snapshot().mappings.length, 0); assert.equal(h.provider.calls.length, 0);
});
test('missing WordPress event denies invitation and redemption despite direct local approval', async t => {
  const h = await harness(t); await h.activate(); const user = await h.login(h.identity.mint());
  assert.equal((await h.admin('approve', { fixture: user.fixture })).status, 200);
  assert.equal((await h.admin('invitations', { fixture: user.fixture })).status, 403);
  assert.equal((await h.request('/invitations/redeem', { invitationToken: 'a'.repeat(43) }, user.fixtureAuthToken)).status, 403);
  assert.equal(h.snapshot().events.length, 0);
  const mapping = h.snapshot().mappings[0]; assert.equal(h.snapshot().approvals[0].xid, mapping.xid);
  assert.ok(h.provider.calls.every(call => call.xid === mapping.xid));
});
test('applied WordPress approval plus identity and activation enables the complete bounded access journey', async t => {
  const h = await harness(t); const user = await h.participant();
  assert.equal((await h.request('/polis/participation-init', undefined, user.participationToken)).status, 200);
  assert.equal((await h.request('/polis/next-comment', undefined, user.participationToken)).status, 200);
  assert.equal((await h.request('/polis/votes', { tid: 1, vote: 1 }, user.participationToken)).status, 200);
  assert.equal(h.snapshot().events[0].applied, 1);
  assert.equal(h.snapshot().approvals[0].xid, h.config.identityFoundation.participantXid(user.principal, conversationId).xid);
});
test('same opaque account re-login is stable and replaces capabilities; distinct account cannot claim its invitation', async t => {
  const h = await harness(t); const alice = await h.participant();
  const originalMapping = h.snapshot().mappings[0];
  const again = await h.login(h.identity.mint());
  assert.equal(again.fixture, alice.fixture); assert.deepEqual(h.snapshot().mappings[0], originalMapping);
  assert.equal((await h.request('/polis/participation-init', undefined, alice.participationToken)).status, 401);
  const invitation = await h.admin('invitations', { fixture: again.fixture }); assert.equal(invitation.status, 201);
  const bob = await h.login(h.identity.mint('synthetic_bob')); await h.wp(h.event(bob.fixture));
  assert.notEqual(bob.fixture, again.fixture);
  assert.equal((await h.request('/invitations/redeem', { invitationToken: invitation.body.invitationToken }, bob.fixtureAuthToken)).status, 403);
  assert.equal((await h.request('/invitations/redeem', { invitationToken: invitation.body.invitationToken }, again.fixtureAuthToken)).status, 201);
});
test('principal expiry denies existing warm sessions and invitations without provider calls', async t => {
  const h = await harness(t); const user = await h.participant(); const calls = h.provider.calls.length; h.advance();
  assert.equal((await h.request('/polis/votes', { tid: 1, vote: 0 }, user.participationToken)).status, 401);
  assert.equal((await h.admin('invitations', { fixture: user.fixture })).status, 401);
  assert.equal(h.provider.calls.length, calls); assert.equal(h.snapshot().sessions.length, 0);
});
test('principal expiry during provider work withholds the response and does not retry an already dispatched operation', async t => {
  const h = await harness(t); const user = await h.participant(); const before = h.provider.calls.length;
  h.provider.pause = async operation => { if (operation === 'vote') h.advance(); };
  assert.equal((await h.request('/polis/votes', { tid: 1, vote: -1 }, user.participationToken)).status, 401);
  assert.equal(h.provider.calls.length, before + 1);
  assert.equal((await h.request('/polis/votes', { tid: 1, vote: -1 }, user.participationToken)).status, 401);
  assert.equal(h.provider.calls.length, before + 1);
});
test('expiry during allowlist upsert keeps approval and WordPress event pending, never grants invitations', async t => {
  const h = await harness(t); await h.activate(); const user = await h.login(h.identity.mint());
  h.provider.pause = async operation => { if (operation === 'upsert') h.advance(); };
  await assert.rejects(h.wp(h.event(user.fixture)), e => e.status === 401);
  assert.equal(h.snapshot().events[0].applied, 0); assert.equal(h.snapshot().approvals[0].state, 'pending');
  assert.equal((await h.admin('invitations', { fixture: user.fixture })).status, 401);
  assert.deepEqual(h.provider.calls.map(call => call.operation), ['upsert']);
});
test('pending newer WordPress event denies warm participation even when the local approval already exists', async t => {
  const h = await harness(t); const user = await h.participant();
  h.provider.pause = async operation => { if (operation === 'upsert') throw new Error('Synthetic failure.'); };
  await assert.rejects(h.wp(h.event(user.fixture, 2)));
  const calls = h.provider.calls.length;
  assert.equal((await h.request('/polis/votes', { tid: 1, vote: 1 }, user.participationToken)).status, 403);
  assert.equal((await h.admin('invitations', { fixture: user.fixture })).status, 403);
  assert.equal(h.provider.calls.length, calls);
});
test('missing WordPress authority or immutable identity mapping denies an already issued warm session', async t => {
  const h = await harness(t); const user = await h.participant(); const calls = h.provider.calls.length;
  const db = new DatabaseSync(h.config.dbPath);
  try { db.prepare('DELETE FROM wordpress_events').run(); } finally { db.close(); }
  assert.equal((await h.request('/polis/participation-init', undefined, user.participationToken)).status, 403);
  const editor = new DatabaseSync(h.config.dbPath);
  try { editor.prepare('DELETE FROM identity_mappings').run(); } finally { editor.close(); }
  assert.equal((await h.request('/polis/participation-init', undefined, user.participationToken)).status, 401);
  assert.equal(h.provider.calls.length, calls);
});
test('a restored approval XID differing from its immutable identity mapping fails before any provider call', async t => {
  const h = await harness(t); const user = await h.participant(); const calls = h.provider.calls.length;
  const db = new DatabaseSync(h.config.dbPath);
  try { db.prepare('UPDATE approvals SET xid=?').run('fncp_' + 'a'.repeat(43)); } finally { db.close(); }
  assert.equal((await h.request('/polis/votes', { tid: 1, vote: 0 }, user.participationToken)).status, 403);
  assert.equal(h.provider.calls.length, calls);
  await h.login(h.identity.mint());
  assert.equal((await h.admin('approve', { fixture: user.fixture })).status, 403);
  assert.equal(h.provider.calls.length, calls);
});
test('activation closure during approval leaves the durable event pending and cannot produce usable approval', async t => {
  const h = await harness(t); await h.activate(); const user = await h.login(h.identity.mint());
  h.provider.pause = async operation => { if (operation === 'upsert') h.closeAuthority(); };
  await assert.rejects(h.wp(h.event(user.fixture)), e => e.status === 403);
  assert.equal(h.snapshot().events[0].applied, 0); assert.equal(h.snapshot().approvals[0].state, 'pending');
  assert.equal(h.snapshot().sessions.length, 0);
  assert.equal((await h.admin('status')).body.open, false);
  assert.equal((await h.admin('revoke', { fixture: user.fixture })).status, 200);
});
test('WordPress revocation invalidates capabilities before failed provider removal and survives restart', async t => {
  const h = await harness(t); const user = await h.participant();
  h.provider.pause = async operation => { if (operation === 'remove') throw new Error('Synthetic failure.'); };
  await assert.rejects(h.wp(h.event(user.fixture, 2, 'revoked')));
  assert.equal(h.snapshot().approvals[0].state, 'revoked'); assert.equal(h.snapshot().sessions.length, 0);
  await assert.rejects(h.login(h.identity.mint()), e => [403, 409].includes(e.status));
  await h.restart(); assert.equal((await h.admin('status')).body.open, false);
  assert.equal((await h.request('/polis/votes', { tid: 1, vote: 0 }, user.participationToken)).status, 401);
});
test('generation change and restart invalidate authentication and participation while preserving opaque mappings', async t => {
  const h = await harness(t); const user = await h.participant(); const originalMapping = h.snapshot().mappings[0];
  await h.activate();
  assert.equal((await h.request('/polis/participation-init', undefined, user.participationToken)).status, 401);
  assert.equal((await h.request('/invitations/redeem', { invitationToken: user.invitationToken }, user.fixtureAuthToken)).status, 401);
  const fresh = await h.login(h.identity.mint()); assert.equal(fresh.fixture, user.fixture);
  await h.restart(); assert.equal((await h.admin('status')).body.open, false);
  assert.equal(h.snapshot().sessions.length, 0); assert.deepEqual(h.snapshot().mappings[0], originalMapping);
});
test('strict logout removes auth-only or participation capabilities even after principal/activation expiry', async t => {
  const h = await harness(t); await h.activate(); const auth = await h.login(h.identity.mint()); h.advance(); h.closeAuthority();
  assert.equal((await h.request('/session/logout', {}, auth.fixtureAuthToken)).status, 200);
  assert.equal(h.snapshot().sessions.length, 0);
  const user = await h.participant('synthetic_bob'); h.advance(); h.closeAuthority();
  assert.equal((await h.request('/session/logout', {}, user.participationToken)).status, 200);
  assert.equal(h.snapshot().sessions.length, 0);
});
test('strict mapped identity capacity is twenty without automatic provider changes', async t => {
  const h = await harness(t);
  for (let index = 0; index < 20; index++) await h.login(h.identity.mint('synthetic_capacity_' + index));
  await assert.rejects(h.login(h.identity.mint('synthetic_capacity_20')), e => e.status === 409);
  assert.equal(h.snapshot().mappings.length, 20); assert.equal(h.provider.calls.length, 0);
});
test('strict/legacy database conversion is rejected without adding identity tables to the legacy database', async t => {
  const h = await harness(t);
  assert.throws(() => createLocalAccess({ ...h.config, identityMode: undefined, identityFoundation: undefined }), /mode conversion/);
  const legacyPath = join(h.directory, 'separate-legacy.sqlite');
  const legacy = createLocalAccess({ ...h.config, dbPath: legacyPath, identityMode: undefined, identityFoundation: undefined, admissionGuard: undefined });
  await legacy.close();
  assert.throws(() => createLocalAccess({ ...h.config, dbPath: legacyPath }), /mode conversion/);
  const db = new DatabaseSync(legacyPath, { readOnly: true });
  try { assert.equal(db.prepare("SELECT count(*) AS n FROM sqlite_master WHERE name='identity_mappings'").get().n, 0); }
  finally { db.close(); }
});
test('controlled wrapper exposes only the in-process authentication method using a real signed synthetic activation', async t => {
  const identity = brandedFoundation(() => 1_000_000); const signer = syntheticSigningFixture(); const binding = syntheticBinding();
  const app = createControlledLocalAccess({ mode: MODE, dbPath: ':memory:', adminSecret, conversationId: binding.conversationId,
    provider: {}, identityMode: INTEGRATED_IDENTITY_MODE, identityFoundation: identity.foundation,
    activation: { mode: 'SYNTHETIC_ONLY', binding, keyId: signer.keyId, publicKey: signer.publicKey, ledgerPath: ':memory:', now: () => 1_000_000 } });
  t.after(() => app.close());
  app.activate(signer.signClaims(syntheticClaims(app.activationBinding(), 1000)));
  const principal = identity.mint();
  const user = await app.authenticateIdentity(principal);
  assert.equal(user.assurance, 'OIDC_ID_TOKEN_VERIFIED'); assert.match(user.fixtureAuthToken, /^[A-Za-z0-9_-]{43}$/u);
  assert.deepEqual(await app.registrationIdentity(principal), { mode: 'SYNTHETIC_ONLY', fixture: user.fixture, roundId: ROUND });
  app.closeAuthority();
  await assert.rejects(app.registrationIdentity(principal), e => e.status === 403 && e.message === 'Current deployment activation required.');
});

test('registration identity is a minimal read of current authentication under active authority, even while the round is closed', async t => {
  const h = await harness(t); h.activateClosed();
  const principal = h.identity.mint(); const user = await h.login(principal);
  const before = h.snapshot();
  assert.equal(before.rounds[0].open, 0);
  assert.deepEqual(await h.registration(principal), { mode: 'SYNTHETIC_ONLY', fixture: user.fixture, roundId: ROUND });
  assert.deepEqual(await h.registration(principal), { mode: 'SYNTHETIC_ONLY', fixture: user.fixture, roundId: ROUND });
  assert.deepEqual(h.snapshot(), before);
  assert.equal(before.approvals.length, 0); assert.equal(before.events.length, 0); assert.equal(before.invitations.length, 0);
  assert.equal(before.sessions.length, 1); assert.equal(h.provider.calls.length, 0);
  for (const path of ['/registration-identity', '/identity/registration', '/identity/registration-identity']) {
    assert.equal((await h.request(path, { principal: {}, fixture: user.fixture }, user.fixtureAuthToken)).status, 404);
  }
});

test('registration rejects an unmapped, copied, foreign, replaced or expired principal and cannot create a mapping', async t => {
  const h = await harness(t); h.activateClosed();
  const principal = h.identity.mint();
  await assert.rejects(h.registration(principal), e => e.status === 401);
  assert.equal(h.snapshot().mappings.length, 0); assert.equal(h.snapshot().sessions.length, 0);
  const user = await h.login(principal); const before = h.snapshot();
  for (const candidate of [null, Object.freeze({ ...principal }), brandedFoundation(() => 1_000_000).mint(),
    h.identity.mint(), h.identity.mint('synthetic_other'),
    h.identity.mint('synthetic_unverified', { emailVerifiedByIssuer: false })]) {
    await assert.rejects(h.registration(candidate), e => e.status === 401);
  }
  assert.deepEqual(h.snapshot(), before);
  assert.equal((await h.registration(principal)).fixture, user.fixture);
  h.advance(); await assert.rejects(h.registration(principal), e => e.status === 401);
  assert.equal(h.provider.calls.length, 0);
});

test('registration binds to the exact current principal and auth capability; re-login is stable and logout removes access', async t => {
  const h = await harness(t); h.activateClosed();
  const previous = h.identity.mint(); const first = await h.login(previous);
  const current = h.identity.mint(); const second = await h.login(current);
  assert.equal(first.fixture, second.fixture);
  await assert.rejects(h.registration(previous), e => e.status === 401);
  assert.equal((await h.registration(current)).fixture, second.fixture);
  assert.equal(h.snapshot().sessions.length, 1);
  assert.equal((await h.request('/session/logout', {}, second.fixtureAuthToken)).status, 200);
  await assert.rejects(h.registration(current), e => e.status === 401);
  assert.equal(h.snapshot().sessions.length, 0); assert.equal(h.provider.calls.length, 0);
});

test('registration requires unexpired fixture-auth and cannot fall back to a longer-lived participation capability', async t => {
  const h = await harness(t, { authLifetimeMs: 1000 }); const user = await h.participant();
  assert.equal((await h.registration(user.principal)).fixture, user.fixture);
  h.advance(1001); const before = h.snapshot(); const calls = h.provider.calls.length;
  await assert.rejects(h.registration(user.principal), e => e.status === 401);
  assert.deepEqual(h.snapshot(), before); assert.equal(h.provider.calls.length, calls);
  // Independent participation still has a valid principal/session: registration
  // specifically requires current authentication, not any retained capability.
  assert.equal((await h.request('/polis/participation-init', undefined, user.participationToken)).status, 200);
  assert.equal((await h.request('/session/logout', {}, user.participationToken)).status, 200);
  await assert.rejects(h.registration(user.principal), e => e.status === 401);
});

test('registration rejects missing or mismatched persisted auth rows even when the in-memory principal is live', async t => {
  const h = await harness(t); h.activateClosed(); const principal = h.identity.mint();
  await h.login(principal);
  const alter = sql => { const db = new DatabaseSync(h.config.dbPath); try { db.exec(sql); } finally { db.close(); } };
  for (const sql of ["UPDATE sessions SET kind='participation'", "UPDATE sessions SET round='9syntheticOtherRound'",
    "UPDATE sessions SET fixture='synthetic_wrong'", 'DELETE FROM sessions']) {
    await h.login(principal); alter(sql);
    await assert.rejects(h.registration(principal), e => e.status === 401);
  }
  assert.equal(h.provider.calls.length, 0); assert.equal(h.snapshot().approvals.length, 0);
});

test('registration requires the immutable current account mapping and denies missing or changed restore rows', async t => {
  const h = await harness(t); h.activateClosed(); const principal = h.identity.mint();
  const user = await h.login(principal);
  const mapping = h.snapshot().mappings[0];
  const alter = callback => { const db = new DatabaseSync(h.config.dbPath); try { callback(db); } finally { db.close(); } };
  alter(db => db.prepare('UPDATE identity_mappings SET xid=?').run('fncp_' + 'a'.repeat(43)));
  await assert.rejects(h.registration(principal), e => e.status === 401);
  alter(db => db.prepare('UPDATE identity_mappings SET xid=?').run(mapping.xid));
  await h.login(principal); assert.equal((await h.registration(principal)).fixture, user.fixture);
  alter(db => db.prepare('DELETE FROM identity_mappings').run());
  await assert.rejects(h.registration(principal), e => e.status === 401);
  assert.equal(h.snapshot().mappings.length, 0); assert.equal(h.provider.calls.length, 0);
});

test('registration cannot revive auth across authority closure, generation replacement or restart', async t => {
  const h = await harness(t); h.activateClosed(); const principal = h.identity.mint();
  const user = await h.login(principal); const originalMapping = h.snapshot().mappings[0];
  h.closeAuthority();
  await assert.rejects(h.registration(principal), e => e.status === 403);
  h.activateClosed(); await assert.rejects(h.registration(principal), e => e.status === 401);
  await h.login(principal); assert.equal((await h.registration(principal)).fixture, user.fixture);
  h.activateClosed(); await assert.rejects(h.registration(principal), e => e.status === 401);
  await h.login(principal); assert.equal((await h.registration(principal)).fixture, user.fixture);
  await h.restart(); await assert.rejects(h.registration(principal), e => e.status === 401);
  assert.deepEqual(h.snapshot().mappings[0], originalMapping);
  assert.equal(h.snapshot().sessions.length, 0); assert.equal(h.provider.calls.length, 0);
});

test('registration is denied after pre-approval WordPress revocation and failed removal of an approved account', async t => {
  const h = await harness(t); h.activateClosed(); const principal = h.identity.mint(); const user = await h.login(principal);
  await h.wp(h.event(user.fixture, 1, 'revoked'));
  await assert.rejects(h.registration(principal), e => e.status === 401);
  assert.equal(h.provider.calls.length, 0);
  const approved = await h.participant('synthetic_approved');
  h.provider.pause = async operation => { if (operation === 'remove') throw new Error('Invented model failure.'); };
  await assert.rejects(h.wp(h.event(approved.fixture, 2, 'revoked')));
  const calls = h.provider.calls.length;
  await assert.rejects(h.registration(approved.principal), e => e.status === 401);
  assert.equal(h.provider.calls.length, calls); assert.equal(h.snapshot().sessions.length, 0);
});

test('registration identity is absent in standalone and controlled legacy fixture APIs', async t => {
  const base = { mode: MODE, dbPath: ':memory:', adminSecret, conversationId, provider: {} };
  const standalone = createLocalAccess(base); t.after(() => standalone.close());
  assert.equal(Object.hasOwn(standalone, 'registrationIdentity'), false);
  const signer = syntheticSigningFixture(); const binding = syntheticBinding();
  const controlled = createControlledLocalAccess({ ...base, conversationId: binding.conversationId,
    activation: { mode: 'SYNTHETIC_ONLY', binding, keyId: signer.keyId, publicKey: signer.publicKey,
      ledgerPath: ':memory:', now: () => 1_000_000 } });
  t.after(() => controlled.close());
  assert.equal(Object.hasOwn(controlled, 'registrationIdentity'), false);
});
