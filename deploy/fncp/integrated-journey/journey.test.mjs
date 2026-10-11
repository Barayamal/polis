import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createIntegratedJourney, exerciseCoreJourney, closeProofServices } from './proof-harness.mjs';

const seeds = JSON.parse(readFileSync(new URL('../seed-statements.json', import.meta.url), 'utf8'));
class ModelProvider {
  states = new Map(); votes = 0;
  async allowlist(operation, xid) {
    if (operation === 'upsert' && this.states.get(xid)?.operationVersion !== 2) this.states.set(xid, { present: true, operationVersion: 1 });
    if (operation === 'remove') this.states.set(xid, { present: false, operationVersion: 2 });
    return this.states.get(xid) ?? { present: false, operationVersion: null };
  }
  async participate(kind, xid) {
    if (!this.states.get(xid)?.present) throw new Error('MODEL denial.');
    if (kind === 'vote') this.votes += 1;
    const statement = { tid: this.votes, txt: seeds[this.votes] };
    return kind === 'next' ? statement : { nextComment: statement, auth: { token: 'never-return-this' }, xid };
  }
}
async function harness(t) {
  const provider = new ModelProvider(); const h = await createIntegratedJourney({ provider });
  t.after(() => h.close()); return { h, provider };
}
const metadata = { 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'same-origin', 'Sec-Fetch-Dest': 'empty' };

test('integrated protocol with MODEL Pol.is: signed identity, current WP approval, binding and warm revocation', async (t) => {
  const { h, provider } = await harness(t);
  const result = await exerciseCoreJourney(h);
  assert.equal(result.checks.length, 25); assert.equal(result.voteCount, 1); assert.equal(provider.votes, 1);
  assert.equal(provider.states.size, 2);
  assert.ok([...provider.states.values()].every((state) => !state.present && state.operationVersion === 2));
});

test('integrated browser protocol: wrong browser callback is denied without moving the matching identity', async (t) => {
  const { h, provider } = await harness(t); h.activate(); await h.admin('round', { open: true });
  const alice = h.client(); const bob = h.client(); await alice.session(); await bob.session();
  const a = await h.begin(alice); const b = await h.begin(bob);
  const callbackA = await h.inject(a.privateBinding, 'synthetic_alice');
  await h.inject(b.privateBinding, 'synthetic_bob');
  assert.equal((await h.finish(bob, callbackA.callback.callbackUrl)).result.status, 401);
  const completed = await h.finish(alice, callbackA.callback.callbackUrl);
  assert.equal(completed.result.status, 200); assert.equal(completed.result.body.phase, 'authenticated');
  assert.equal((await h.admin('invitations', { fixture: completed.fixture })).status, 403);
  assert.equal(provider.states.size, 0);
});

test('integrated browser protocol: unverified issuer-email claim gives no mapped approval or invitation', async (t) => {
  const { h, provider } = await harness(t); h.activate(); await h.admin('round', { open: true });
  const browser = h.client(); const result = await h.login(browser, 'synthetic_unverified', false);
  assert.equal(result.result.status, 401); assert.equal(result.fixture, undefined);
  assert.equal((await browser.session()).body.phase, 'visitor'); assert.equal(provider.states.size, 0);
});

test('integrated browser protocol: cookie and CSRF rotate; callbacks never enter URL routes or response projection', async (t) => {
  const { h } = await harness(t); h.activate(); await h.admin('round', { open: true });
  const sessionResponse = await fetch(h.origin + '/api/session', { headers: metadata });
  const cookie = sessionResponse.headers.get('set-cookie').split(';')[0];
  assert.match(sessionResponse.headers.get('set-cookie'), /HttpOnly; SameSite=Strict/u);
  const session = await sessionResponse.json();
  const post = (body, headers = {}) => fetch(h.origin + '/api/oidc/start', { method: 'POST', redirect: 'error',
    headers: { ...metadata, Cookie: cookie, Origin: h.origin, 'Content-Type': 'application/json',
      'X-CSRF-Token': session.csrf, ...headers }, body: JSON.stringify(body) });
  assert.equal((await post({}, { 'X-CSRF-Token': 'forged' })).status, 403);
  assert.equal((await post({}, { Origin: 'https://external.example.invalid' })).status, 403);
  assert.equal((await post({}, { 'Sec-Fetch-Site': 'same-site' })).status, 403);
  const rotatedResponse = await post({}); const rotated = await rotatedResponse.json();
  assert.equal(rotatedResponse.status, 200); assert.notEqual(rotated.csrf === session.csrf, true);
  assert.notEqual(rotatedResponse.headers.get('set-cookie').split(';')[0] === cookie, true);
  assert.equal((await post({})).status, 401);
  assert.equal((await fetch(h.origin + '/api/oidc/callback?code=synthetic', { headers: metadata })).status, 400);
  assert.equal((await fetch(h.origin + '/api/oidc/callback', { headers: metadata })).status, 401);
  assert.ok(!/authorizationUrl|callbackUrl|principal|accountId|fixture|xid|nonce|verifier|id_token/iu.test(JSON.stringify(rotated)));
  assert.equal(rotated.authentication, 'SIGNED_SYNTHETIC_OIDC');
});

test('integrated BFF: direct identity/admin injection and extra callback claims are unavailable', async (t) => {
  const { h, provider } = await harness(t);
  const sessionResponse = await fetch(h.origin + '/api/session', { headers: metadata });
  const cookie = sessionResponse.headers.get('set-cookie').split(';')[0]; const session = await sessionResponse.json();
  const headers = { ...metadata, Cookie: cookie, Origin: h.origin, 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrf };
  const response = await fetch(h.origin + '/api/identity', { headers }); assert.equal(response.status, 404);
  assert.equal((await fetch(h.origin + '/api/test-admin/approve', { method: 'POST', headers,
    body: JSON.stringify({ fixture: 'synthetic_forged' }) })).status, 404);
  assert.equal((await fetch(h.origin + '/api/oidc/callback', { method: 'POST', headers,
    body: JSON.stringify({ callbackUrl: 'https://participant.example.invalid/oidc/callback', emailVerifiedByIssuer: true }) })).status, 400);
  assert.equal((await h.request('/identity/authenticate', { accountId: 'acct_' + 'a'.repeat(43) })).status, 404);
  assert.equal((await h.request('/health', undefined, undefined, { Origin: h.origin })).status, 403);
  assert.equal((await fetch(h.origin + '/api/session', { headers: { ...metadata, 'X-FNCP-Gateway-Key': 'forged' } })).status, 403);
  assert.equal(provider.states.size, 0);
});

test('private driver captures stay separate under concurrent invented sign-ins', async (t) => {
  const { h, provider } = await harness(t); h.activate(); await h.admin('round', { open: true });
  const clients = [h.client(), h.client()];
  const results = await Promise.all(clients.map((client, i) => h.login(client, i ? 'synthetic_concurrent_bob' : 'synthetic_concurrent_alice')));
  assert.ok(results.every((result) => result.result.status === 200));
  assert.equal(results[0].fixture === results[1].fixture, false);
  assert.equal((await h.admin('status')).body.fixtures, 2); assert.equal(provider.states.size, 0);
});

test('cleanup attempts every owned service after failure instead of abandoning later listeners', async () => {
  const attempted = [];
  await assert.rejects(closeProofServices([0, 1, 2].map((n) => ({ async close() {
    attempted.push(n); if (n === 0 || n === 2) throw new Error('private failure');
  } }))), /Some synthetic proof services/u);
  assert.deepEqual(attempted, [0, 1, 2]);
});
