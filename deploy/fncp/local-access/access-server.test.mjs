import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { DatabaseSync } from 'node:sqlite';
import { request as httpRequest } from 'node:http';
import { createLocalAccess, LocalPolisProvider, MODE, POLIS_ORIGIN } from './access-server.mjs';

const adminSecret = 'synthetic_admin_credential_'.repeat(3);
const conversationId = '9syntheticRoundTest';

/** Model/fake origin: passing these tests does NOT prove the actual Pol.is stack. */
class ModelProvider {
  states = new Map(); requests = []; failUpsert = false; failRemove = false;
  async allowlist(operation, xid) {
    if (operation === 'upsert') {
      if (this.failUpsert) throw new Error('model failure');
      if (this.states.get(xid)?.operationVersion !== 2) this.states.set(xid, { present: true, operationVersion: 1 });
    }
    if (operation === 'remove') {
      if (this.failRemove) throw new Error('model failure');
      this.states.set(xid, { present: false, operationVersion: 2 });
    }
    return this.states.get(xid) ?? { present: false, operationVersion: null };
  }
  async participate(kind, xid, body) {
    this.requests.push({ kind, xid, body });
    if (!this.states.get(xid)?.present) throw new Error('model access denied');
    return { nextComment: { tid: 1, txt: 'Synthetic statement only.' },
      auth: { token: 'must-not-escape' }, xid, pid: 22, vote: body.vote };
  }
}

async function harness(t, options = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'fncp-local-access-model-'));
  const provider = new ModelProvider();
  let time = 1_000_000;
  const config = { mode: MODE, dbPath: join(directory, 'synthetic.sqlite'),
    adminSecret, conversationId, provider, now: () => time, ...options };
  let app = createLocalAccess(config);
  let origin = await app.listen(0);
  t.after(async () => { await app.close(); await rm(directory, { recursive: true }); });
  async function request(path, body, credential, extra = {}) {
    const response = await fetch(origin + path, {
      method: body === undefined ? 'GET' : 'POST',
      headers: { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...(credential ? { Authorization: `Bearer ${credential}` } : {}), ...(extra.headers ?? {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    return { status: response.status, body: await response.json(), headers: response.headers };
  }
  const admin = (path, body) => request('/test-admin/' + path, body, adminSecret);
  async function fixture(name) {
    const created = await admin('fixtures', { fixture: name }); assert.equal(created.status, 201);
    const auth = await request('/test-auth/mailbox-simulator', { fixture: name, fixtureSecret: created.body.fixtureSecret });
    assert.equal(auth.status, 200); assert.equal(auth.body.mailboxOwnership, 'SIMULATED_NOT_VERIFIED');
    return { name, secret: created.body.fixtureSecret, auth: auth.body.fixtureAuthToken };
  }
  async function invite(user, ttlSeconds) {
    const approved = await admin('approve', { fixture: user.name }); assert.equal(approved.status, 200);
    assert.equal((await admin('round', { open: true })).status, 200);
    const issued = await admin('invitations', { fixture: user.name, ...(ttlSeconds ? { ttlSeconds } : {}) });
    assert.equal(issued.status, 201); return issued.body.invitationToken;
  }
  async function participant(user) {
    const invitationToken = await invite(user);
    const redeemed = await request('/invitations/redeem', { invitationToken }, user.auth);
    assert.equal(redeemed.status, 201); return redeemed.body.participationToken;
  }
  return { request, admin, fixture, invite, participant, provider, config,
    async wrongHost() {
      return new Promise((resolve, reject) => {
        const req = httpRequest(origin + '/health', { headers: { Host: 'attacker.example' } }, (res) => {
          res.resume(); res.on('end', () => resolve(res.statusCode));
        }); req.on('error', reject); req.end();
      });
    },
    advance: (ms) => { time += ms; },
    async restart() { await app.close(); app = createLocalAccess(config); origin = await app.listen(0); },
  };
}

test('configuration fails without exact synthetic mode or independent credentials', () => {
  const base = { mode: MODE, dbPath: ':memory:', adminSecret, conversationId, provider: new ModelProvider() };
  for (const mode of [undefined, 'true', 'production', 'synthetic']) {
    assert.throws(() => createLocalAccess({ ...base, mode }), /fixture-only/);
  }
  assert.throws(() => createLocalAccess({ ...base, provider: { gatewaySecret: adminSecret } }), /separate/);
  assert.equal(POLIS_ORIGIN, 'http://127.0.0.1:5500');
  assert.throws(() => new LocalPolisProvider({ conversationId, gatewaySecret: adminSecret, providerSecret: adminSecret }), /configuration/);
});

test('transport model: fixed loopback origin, no redirects, narrow payloads and separated credentials', async (t) => {
  const calls = [];
  const xid = 'fncp_' + 'x'.repeat(43);
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    calls.push({ url, options });
    if (url.endsWith('/upsert') || url.endsWith('/remove')) return new Response(null, { status: 204 });
    if (url.endsWith('/readback')) return Response.json({ conversationId, participantXid: xid, present: true, operationVersion: 1 });
    return Response.json({ nextComment: { tid: 1 }, auth: { token: 'secret' }, xid, uid: 10 });
  });
  const provider = new LocalPolisProvider({ conversationId,
    gatewaySecret: 'gateway_secret_'.repeat(4), providerSecret: 'provider_secret_'.repeat(4) });
  await provider.allowlist('upsert', xid);
  assert.equal((await provider.allowlist('readback', xid)).present, true);
  await provider.allowlist('remove', xid);
  const response = await provider.participate('vote', xid, { tid: 1, vote: 0, xid: 'ignored', url: 'https://example.org' });
  assert.deepEqual(response, { nextComment: { tid: 1 } });
  assert.equal(calls.length, 4);
  assert.ok(calls.every(({ url, options }) => url.startsWith(POLIS_ORIGIN + '/') && options.redirect === 'error'));
  const privateCall = calls[0].options;
  assert.equal(privateCall.headers.Authorization, `Bearer ${provider.providerSecret}`);
  assert.equal(privateCall.headers['X-FNCP-Gateway-Key'], undefined);
  assert.match(privateCall.headers['Idempotency-Key'], /^allow-[a-f0-9]{64}$/u);
  const publicCall = calls[3].options;
  assert.equal(publicCall.headers.Authorization, undefined);
  assert.equal(publicCall.headers.Cookie, undefined);
  assert.equal(publicCall.headers['X-FNCP-Gateway-Key'], provider.gatewaySecret);
  assert.equal(publicCall.headers['X-FNCP-Participant-XID'], xid);
  assert.deepEqual(JSON.parse(publicCall.body), { conversation_id: conversationId, tid: 1, vote: 0 });
  await assert.rejects(provider.participate('https://example.org', xid), /Invalid participant route/);
});

test('model: no production claims, admin unauthenticated access or browser-origin access', async (t) => {
  const h = await harness(t);
  const health = await h.request('/health');
  assert.equal(health.body.mode, 'SYNTHETIC_ONLY'); assert.equal(health.body.productionReady, false);
  assert.equal(health.headers.get('cache-control'), 'no-store');
  assert.equal((await h.request('/test-admin/status')).status, 404);
  assert.equal((await h.request('/health', undefined, undefined, { headers: { Origin: 'https://example.org' } })).status, 403);
  assert.equal(await h.wrongHost(), 403);
  assert.equal((await h.request('/health', undefined, undefined, { headers: { Cookie: 'session=fake' } })).status, 403);
  assert.equal((await h.admin('fixtures', { fixture: 'real@example.org' })).status, 400);
  assert.equal((await h.admin('round', { open: 'true' })).status, 400);
});

test('transport model: preserve safe rejection classes without reflecting provider details', async (t) => {
  let status = 400;
  t.mock.method(globalThis, 'fetch', async () => Response.json({ error: 'PRIVATE_PROVIDER_DETAIL' }, { status }));
  const provider = new LocalPolisProvider({ conversationId,
    gatewaySecret: 'gateway_secret_'.repeat(4), providerSecret: 'provider_secret_'.repeat(4) });
  for (const [upstream, expected, message] of [[400, 400, 'Invalid participation request.'],
    [403, 403, 'Participation denied.'], [500, 503, 'Provider unavailable.']]) {
    status = upstream;
    await assert.rejects(provider.participate('vote', 'fncp_' + 'x'.repeat(43), { tid: 999, vote: 0 }),
      (error) => error.status === expected && error.message === message);
  }
});

test('model: unapproved accounts and fixture-auth tokens cannot vote', async (t) => {
  const h = await harness(t); const user = await h.fixture('synthetic_alice');
  assert.equal((await h.admin('invitations', { fixture: user.name })).status, 403);
  assert.equal((await h.request('/polis/participation-init', undefined, user.auth)).status, 401);
  assert.equal((await h.request('/invitations/redeem', { invitationToken: 'a'.repeat(43) }, user.auth)).status, 403);
  assert.equal((await h.request('/test-auth/mailbox-simulator', { fixture: user.name, fixtureSecret: 'b'.repeat(43) })).status, 401);
  assert.equal(h.provider.requests.length, 0);
});

test('model: forwarded invitation denied without consuming it; replay and concurrent redemption denied', async (t) => {
  const h = await harness(t); const alice = await h.fixture('synthetic_alice'); const bob = await h.fixture('synthetic_bob');
  const invitationToken = await h.invite(alice);
  await h.admin('approve', { fixture: bob.name });
  assert.equal((await h.request('/invitations/redeem', { invitationToken }, bob.auth)).status, 403);
  const attempts = await Promise.all([1, 2].map(() => h.request('/invitations/redeem', { invitationToken }, alice.auth)));
  assert.deepEqual(attempts.map((x) => x.status).sort(), [201, 403]);
  assert.equal((await h.request('/invitations/redeem', { invitationToken }, alice.auth)).status, 403);
  const participation = attempts.find((x) => x.status === 201).body.participationToken;
  const init = await h.request('/polis/participation-init', undefined, participation);
  assert.equal(init.status, 200); assert.ok(init.body.nextComment);
  assert.equal(JSON.stringify(init.body).includes('must-not-escape'), false);
  assert.equal(init.body.xid, undefined); assert.equal(init.body.pid, undefined);
  assert.match(h.provider.requests[0].xid, /^fncp_[A-Za-z0-9_-]{43}$/u);
});

test('model: invitation expiry, replacement and session expiry fail closed', async (t) => {
  const h = await harness(t, { sessionLifetimeMs: 1000 }); const user = await h.fixture('synthetic_alice');
  const expired = await h.invite(user, 1); h.advance(1001);
  assert.equal((await h.request('/invitations/redeem', { invitationToken: expired }, user.auth)).status, 403);
  const replaced = await h.invite(user);
  const newest = await h.invite(user);
  assert.equal((await h.request('/invitations/redeem', { invitationToken: replaced }, user.auth)).status, 403);
  const redeemed = await h.request('/invitations/redeem', { invitationToken: newest }, user.auth);
  h.advance(1001);
  assert.equal((await h.request('/polis/participation-init', undefined, redeemed.body.participationToken)).status, 401);
});

test('model: strict vote envelope and route allowlist prevent caller identity or arbitrary proxying', async (t) => {
  const h = await harness(t); const user = await h.fixture('synthetic_alice'); const session = await h.participant(user);
  for (const body of [{ tid: 1, vote: 0, xid: 'injected' }, { tid: 1, vote: 2 }, { tid: -1, vote: 0 },
    { tid: '1', vote: 0 }, { tid: 1, vote: '0' }, { tid: 1, vote: 0, url: 'https://example.org' }]) {
    assert.equal((await h.request('/polis/votes', body, session)).status, 400);
  }
  assert.equal((await h.request('/polis/participation-init?xid=attacker', undefined, session)).status, 400);
  assert.equal((await h.request('/polis/participation-init', undefined, session, { headers: { 'X-FNCP-Participant-XID': 'attacker' } })).status, 403);
  for (const route of ['/polis/comments', '/polis/math/pca2', '/api/v3/votes', '/fncp/private/xid-allowlist/upsert']) {
    assert.equal((await h.request(route, {}, session)).status, 404);
  }
  assert.equal(h.provider.requests.length, 0);
  assert.equal((await h.request('/polis/votes', { tid: 1, vote: 0 }, session)).status, 200);
  assert.deepEqual(h.provider.requests[0].body, { tid: 1, vote: 0 });
});

test('model: approvals and token hashes persist across restart; different-round DB reuse rejected', async (t) => {
  const h = await harness(t); const user = await h.fixture('synthetic_alice'); const session = await h.participant(user);
  await h.restart();
  assert.equal((await h.request('/polis/participation-init', undefined, session)).status, 200);
  const db = new DatabaseSync(h.config.dbPath, { readOnly: true });
  const stored = JSON.stringify({ sessions: db.prepare('SELECT * FROM sessions').all(), fixtures: db.prepare('SELECT * FROM fixtures').all() });
  db.close();
  assert.equal(stored.includes(session), false); assert.equal(stored.includes(user.secret), false); assert.equal(stored.includes(user.auth), false);
  assert.throws(() => createLocalAccess({ ...h.config, conversationId: '8differentRound' }), /different round/);
});

test('model: provider failure leaves pending approval; no invitation issued', async (t) => {
  const h = await harness(t); const user = await h.fixture('synthetic_alice'); h.provider.failUpsert = true;
  assert.equal((await h.admin('approve', { fixture: user.name })).status, 503);
  assert.equal((await h.admin('invitations', { fixture: user.name })).status, 403);
  const status = await h.admin('status');
  assert.deepEqual(status.body.approvals, [{ state: 'pending', count: 1 }]);
  h.provider.failUpsert = false; assert.equal((await h.admin('approve', { fixture: user.name })).status, 200);
});

test('model: warm session revoked locally even when provider removal fails; retry verifies removal', async (t) => {
  const h = await harness(t); const user = await h.fixture('synthetic_alice'); const session = await h.participant(user);
  assert.equal((await h.request('/polis/participation-init', undefined, session)).status, 200);
  h.provider.failRemove = true;
  assert.equal((await h.admin('revoke', { fixture: user.name })).status, 503);
  assert.equal((await h.request('/polis/votes', { tid: 1, vote: 0 }, session)).status, 401);
  assert.equal((await h.admin('invitations', { fixture: user.name })).status, 403);
  assert.equal((await h.admin('approve', { fixture: user.name })).status, 409);
  h.provider.failRemove = false;
  assert.equal((await h.admin('revoke', { fixture: user.name })).body.providerRemovalVerified, true);
});

test('model: round closure invalidates warm sessions and outstanding invitations', async (t) => {
  const h = await harness(t); const user = await h.fixture('synthetic_alice'); const session = await h.participant(user);
  const invitationToken = await h.invite(user);
  assert.equal((await h.admin('round', { open: false })).status, 200);
  assert.equal((await h.request('/polis/participation-init', undefined, session)).status, 401);
  assert.equal((await h.request('/invitations/redeem', { invitationToken }, user.auth)).status, 403);
  await h.admin('round', { open: true });
  assert.equal((await h.request('/invitations/redeem', { invitationToken }, user.auth)).status, 403);
});

test('model: replacement session and logout invalidate previously issued participation tokens', async (t) => {
  const h = await harness(t); const user = await h.fixture('synthetic_alice');
  const old = await h.participant(user); const current = await h.participant(user);
  assert.equal((await h.request('/polis/participation-init', undefined, old)).status, 401);
  assert.equal((await h.request('/polis/participation-init', undefined, current)).status, 200);
  assert.equal((await h.request('/session/logout', {}, current)).status, 200);
  assert.equal((await h.request('/polis/participation-init', undefined, current)).status, 401);
});
