/** Real signed synthetic OIDC and loopback BFF/API/event protocol; MODEL Pol.is.
 * Never prints callback URLs, tokens, cookies, subjects, account IDs or XIDs.
 * Each test uses only fresh harness-owned temporary stores and ephemeral ports.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createIntegratedJourney } from './proof-harness.mjs';

const seedTexts = JSON.parse(readFileSync(new URL('../seed-statements.json', import.meta.url), 'utf8'));
const check = (condition, label) => assert.equal(condition === true, true, label);

function modelProvider() {
  const states = new Map(); const calls = [];
  const statement = { tid: 1, txt: seedTexts[0] };
  return {
    calls,
    async allowlist(operation, xid) {
      calls.push({ operation, xid });
      if (operation === 'upsert' && states.get(xid)?.operationVersion !== 2) states.set(xid, { present: true, operationVersion: 1 });
      if (operation === 'remove') states.set(xid, { present: false, operationVersion: 2 });
      return states.get(xid) ?? { present: false, operationVersion: null };
    },
    async participate(kind, xid) {
      calls.push({ operation: kind, xid });
      if (states.get(xid)?.present !== true) throw new Error('Synthetic model provider denied access.');
      return kind === 'next' ? { ...statement } : { nextComment: { ...statement } };
    },
  };
}

async function harness(t, activationTtl = 1200) {
  let stamp = Date.now(); const provider = modelProvider();
  const h = await createIntegratedJourney({ provider, now: () => stamp });
  t.after(() => h.close());
  h.activate(activationTtl);
  assert.equal((await h.admin('round', { open: true })).status, 200);
  const participant = async subject => {
    const client = h.client(); const login = await h.login(client, subject);
    assert.equal(login.result.status, 200);
    check(typeof login.fixture === 'string', 'private opaque fixture returned to test driver');
    const approval = await h.sendEvent(h.event(login.fixture, 'approved', 1));
    assert.equal(approval.status, 200); assert.equal(approval.body.outcome, 'APPLIED');
    const issued = await h.admin('invitations', { fixture: login.fixture });
    assert.equal(issued.status, 201);
    assert.equal((await client.redeem(issued.body.invitationToken)).status, 200);
    assert.equal((await client.initialize()).status, 200);
    return { client, fixture: login.fixture };
  };
  return { h, provider, participant, advance: ms => { stamp += ms; } };
}

test('signed principal expiry denies a warm BFF session while the longer activation lease remains valid', async t => {
  const { h, provider, participant, advance } = await harness(t, 1200);
  const user = await participant('synthetic_lifecycle_expiry');
  const before = provider.calls.length;
  // The intercepted issuer creates 300-second ID tokens; activation is 1,200s.
  advance(301_000);
  assert.equal((await user.client.next()).status, 401);
  assert.equal((await user.client.session()).body.phase, 'visitor');
  assert.equal((await h.admin('invitations', { fixture: user.fixture })).status, 401);
  assert.equal((await h.admin('status')).body.open, true);
  assert.equal((await h.admin('round', { open: true })).status, 200);
  assert.equal(provider.calls.length, before, 'identity expiry makes no new model-provider call');
});

test('activation expiry and a new generation cannot revive old BFF participation/authentication or unused invitations', async t => {
  const { h, provider, participant, advance } = await harness(t, 30);
  const alice = await participant('synthetic_lifecycle_activation');
  const bob = h.client(); const login = await h.login(bob, 'synthetic_lifecycle_waiting');
  assert.equal(login.result.status, 200);
  assert.equal((await h.sendEvent(h.event(login.fixture, 'approved', 1))).status, 200);
  const old = await h.admin('invitations', { fixture: login.fixture }); assert.equal(old.status, 201);
  const before = provider.calls.length;
  advance(31_000);
  assert.equal((await alice.client.next()).status, 403);
  assert.equal((await bob.redeem(old.body.invitationToken)).status, 403);
  assert.equal((await h.admin('status')).body.open, false);
  h.activate(1200); assert.equal((await h.admin('round', { open: true })).status, 200);
  assert.equal((await alice.client.initialize()).status, 401);
  assert.equal((await bob.redeem(old.body.invitationToken)).status, 401);
  assert.equal(provider.calls.length, before, 'reopening dispatches no old capability to the model provider');
  assert.equal((await bob.logout()).body.browserSessionClosed, true);
  const fresh = await h.login(bob, 'synthetic_lifecycle_waiting'); assert.equal(fresh.result.status, 200);
  check(fresh.fixture === login.fixture, 'fresh login keeps the same opaque account mapping');
  assert.equal((await bob.redeem(old.body.invitationToken)).status, 403, 'fresh identity cannot reuse pre-generation invitation');
  const replacement = await h.admin('invitations', { fixture: fresh.fixture }); assert.equal(replacement.status, 201);
  assert.equal((await bob.redeem(replacement.body.invitationToken)).status, 200);
  assert.equal((await bob.initialize()).status, 200);
});

test('same signed account re-login keeps its mapping/XID but never creates approval automatically', async t => {
  const { h, provider } = await harness(t); const client = h.client();
  const first = await h.login(client, 'synthetic_lifecycle_stable'); assert.equal(first.result.status, 200);
  assert.equal((await h.admin('status')).body.fixtures, 1);
  assert.equal((await h.admin('status')).body.approvals.length, 0);
  assert.equal((await h.admin('invitations', { fixture: first.fixture })).status, 403);
  assert.equal(provider.calls.length, 0);
  assert.equal((await client.logout()).body.backendLogoutVerified, true);
  const second = await h.login(client, 'synthetic_lifecycle_stable'); assert.equal(second.result.status, 200);
  check(second.fixture === first.fixture, 'same account resolves to same private fixture');
  assert.equal((await h.admin('status')).body.fixtures, 1);
  assert.equal((await h.admin('status')).body.approvals.length, 0);
  assert.equal(provider.calls.length, 0, 're-login performs no model allowlist or participation action');
  const event = h.event(second.fixture, 'approved', 1);
  assert.equal((await h.sendEvent(event)).body.outcome, 'APPLIED');
  const xid = provider.calls.find(call => call.operation === 'upsert')?.xid;
  check(typeof xid === 'string', 'mapped model-provider pseudonym exists only after explicit WordPress event');
  const before = provider.calls.length;
  assert.equal((await client.logout()).body.backendLogoutVerified, true);
  const third = await h.login(client, 'synthetic_lifecycle_stable'); assert.equal(third.result.status, 200);
  check(third.fixture === first.fixture, 'mapping remains stable after approval and logout');
  assert.equal(provider.calls.length, before, 'approved-account re-login does not automatically upsert again');
  const invitation = await h.admin('invitations', { fixture: third.fixture }); assert.equal(invitation.status, 201);
  assert.equal((await client.redeem(invitation.body.invitationToken)).status, 200);
  assert.equal((await client.initialize()).status, 200);
  check(provider.calls.at(-1).xid === xid, 'participation uses the same immutable mapped pseudonym');
});

test('logout invalidates a pending signed callback and replay cannot create a mapping or approval', async t => {
  const { h, provider } = await harness(t); const client = h.client(); await client.session();
  const begun = await h.begin(client); assert.equal(begun.result.status, 200);
  const injected = await h.inject(begun.privateBinding, 'synthetic_lifecycle_cancelled'); check(injected.ok, 'private signed callback prepared');
  assert.equal((await client.logout()).body.browserSessionClosed, true);
  const attempted = await h.finish(client, injected.callback.callbackUrl);
  assert.equal(attempted.result.status, 401);
  assert.equal((await h.admin('status')).body.fixtures, 0);
  await client.session(); const newer = await h.begin(client); assert.equal(newer.result.status, 200);
  const replay = await h.finish(client, injected.callback.callbackUrl); assert.equal(replay.result.status, 401);
  assert.equal((await h.admin('status')).body.fixtures, 0); assert.equal(provider.calls.length, 0);
  const fresh = await h.login(client, 'synthetic_lifecycle_cancelled'); assert.equal(fresh.result.status, 200);
  assert.equal((await h.admin('status')).body.fixtures, 1);
  assert.equal((await h.admin('status')).body.approvals.length, 0);
  assert.equal(provider.calls.length, 0);
});

test('completed callback is single-use; replay after logout cannot revive the old signed-in browser session', async t => {
  const { h, provider } = await harness(t); const client = h.client(); await client.session();
  const begun = await h.begin(client); assert.equal(begun.result.status, 200);
  const injected = await h.inject(begun.privateBinding, 'synthetic_lifecycle_replay'); check(injected.ok, 'private signed callback prepared');
  const first = await h.finish(client, injected.callback.callbackUrl); assert.equal(first.result.status, 200);
  const duplicate = await h.finish(client, injected.callback.callbackUrl); assert.equal(duplicate.result.status, 403);
  assert.equal((await h.admin('status')).body.fixtures, 1);
  assert.equal((await client.logout()).body.backendLogoutVerified, true);
  const replay = await h.finish(client, injected.callback.callbackUrl); assert.equal(replay.result.status, 401);
  assert.equal((await client.session()).body.phase, 'visitor');
  assert.equal((await h.admin('invitations', { fixture: first.fixture })).status, 401);
  assert.equal((await h.admin('status')).body.approvals.length, 0); assert.equal(provider.calls.length, 0);
});

test('an expired pending signed callback creates no identity mapping, approval or provider action', async t => {
  const { h, provider, advance } = await harness(t); const client = h.client(); await client.session();
  const begun = await h.begin(client); assert.equal(begun.result.status, 200);
  const injected = await h.inject(begun.privateBinding, 'synthetic_lifecycle_callback_expiry'); check(injected.ok, 'private signed callback prepared');
  advance(301_000);
  const expired = await h.finish(client, injected.callback.callbackUrl); assert.equal(expired.result.status, 401);
  assert.equal((await client.session()).body.phase, 'visitor');
  assert.equal((await h.admin('status')).body.fixtures, 0);
  assert.equal((await h.admin('status')).body.approvals.length, 0); assert.equal(provider.calls.length, 0);
});
