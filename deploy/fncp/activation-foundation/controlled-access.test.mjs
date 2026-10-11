import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, link, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { createServer } from 'node:net';
import { MODE } from '../local-access/access-server.mjs';
import { createControlledLocalAccess } from './controlled-access.mjs';
import { syntheticBinding, syntheticClaims, syntheticSigningFixture } from './synthetic-fixtures.mjs';

async function harness(t) {
  const directory = await mkdtemp(join(tmpdir(), 'fncp-controlled-test-'));
  const signer = syntheticSigningFixture(); let ms = 1_000_000;
  const states = new Map(); const provider = { calls: 0, pause: undefined,
    async allowlist(operation, xid) {
      if (operation === 'upsert') states.set(xid, { present: true, operationVersion: 1 });
      if (operation === 'remove') states.set(xid, { present: false, operationVersion: 2 });
      return states.get(xid) ?? { present: false, operationVersion: null };
    },
    async participate() { this.calls++; await this.pause?.(); return { nextComment: { tid: 1, txt: 'Synthetic statement.' } }; } };
  const binding = syntheticBinding(); const adminSecret = 'synthetic_admin_credential_'.repeat(3);
  const config = { mode: MODE, dbPath: join(directory, 'access.sqlite'), adminSecret, conversationId: binding.conversationId,
    provider, now: () => ms,
    activation: { mode: 'SYNTHETIC_ONLY', binding, keyId: signer.keyId, publicKey: signer.publicKey,
      ledgerPath: join(directory, 'authority.sqlite'), now: () => ms } };
  let app = createControlledLocalAccess(config); let origin = await app.listen(0); let closed = false;
  t.after(async () => { if (!closed) await app.close(); await rm(directory, { recursive: true }); });
  const request = async (path, body, credential) => {
    const response = await fetch(origin + path, { method: body === undefined ? 'GET' : 'POST',
      headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        ...(credential ? { Authorization: `Bearer ${credential}` } : {}) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    return { status: response.status, body: await response.json() };
  };
  const admin = (path, body) => request('/test-admin/' + path, body, adminSecret);
  const sign = (changes = {}) => signer.signClaims(syntheticClaims(app.activationBinding(), Math.floor(ms / 1000),
    { sequence: app.nextActivationSequence(), ...changes }));
  const authenticate = async (user) => {
    const result = await request('/test-auth/mailbox-simulator', { fixture: user.name, fixtureSecret: user.secret });
    assert.equal(result.status, 200); return result.body.fixtureAuthToken;
  };
  async function fixture(name = 'synthetic_alice') {
    const result = await admin('fixtures', { fixture: name }); assert.equal(result.status, 201);
    const user = { name, secret: result.body.fixtureSecret }; user.auth = await authenticate(user); return user;
  }
  async function participant() {
    app.activate(sign()); assert.equal((await admin('round', { open: true })).status, 200);
    const user = await fixture(); assert.equal((await admin('approve', { fixture: user.name })).status, 200);
    const issued = await admin('invitations', { fixture: user.name }); assert.equal(issued.status, 201);
    const redeemed = await request('/invitations/redeem', { invitationToken: issued.body.invitationToken }, user.auth);
    assert.equal(redeemed.status, 201);
    return { ...user, token: redeemed.body.participationToken, invitation: issued.body.invitationToken };
  }
  return { config, directory, provider, request, admin, fixture, participant, authenticate, sign,
    activate: (token) => app.activate(token ?? sign()), closeAuthority: () => app.closeAuthority(),
    setTime: (next) => { ms = next; }, origin: () => origin,
    async restart() { await app.close(); app = createControlledLocalAccess(config); origin = await app.listen(0); },
    async close() { closed = true; await app.close(); } };
}

test('controlled API cannot open from ordinary admin configuration or expose an activation endpoint', async (t) => {
  const h = await harness(t);
  assert.equal((await h.admin('round', { open: true })).status, 403);
  assert.equal((await h.admin('activate', { envelope: h.sign() })).status, 404);
  assert.equal((await h.admin('status')).body.open, false);
  assert.equal((await h.request('/health')).body.productionReady, false);
});
test('signed authority plus separate local round open allows the bounded synthetic journey', async (t) => {
  const h = await harness(t); const user = await h.participant();
  assert.equal((await h.request('/polis/participation-init', undefined, user.token)).status, 200);
  assert.equal((await h.request('/polis/votes', { tid: 1, vote: 0 }, user.token)).status, 200);
  assert.equal(h.provider.calls, 2);
  assert.equal((await h.admin('revoke', { fixture: user.name })).status, 200);
  assert.equal((await h.request('/polis/votes', { tid: 1, vote: 0 }, user.token)).status, 401);
  assert.equal(h.provider.calls, 2);
});
test('lease expiry closes every protected route; status, revoke and explicit close remain available', async (t) => {
  const h = await harness(t); const user = await h.participant(); h.setTime(1_300_000);
  for (const [path, body, credential] of [['/polis/participation-init', undefined, user.token],
    ['/polis/next-comment', undefined, user.token], ['/polis/votes', { tid: 1, vote: 1 }, user.token],
    ['/invitations/redeem', { invitationToken: user.invitation }, user.auth]]) {
    assert.equal((await h.request(path, body, credential)).status, 403);
  }
  assert.equal((await h.admin('invitations', { fixture: user.name })).status, 403);
  assert.equal((await h.admin('round', { open: true })).status, 403);
  assert.equal((await h.admin('status')).body.open, false); assert.equal(h.provider.calls, 0);
  assert.equal((await h.admin('revoke', { fixture: user.name })).status, 200);
  assert.equal((await h.admin('round', { open: false })).status, 200);
});
test('new activation invalidates all old auth, unused invitations and participation sessions before reopen', async (t) => {
  const h = await harness(t); const user = await h.participant();
  const pending = await h.admin('invitations', { fixture: user.name }); assert.equal(pending.status, 201);
  h.activate(); assert.equal((await h.admin('status')).body.open, false);
  assert.equal((await h.admin('round', { open: true })).status, 200);
  assert.equal((await h.request('/polis/participation-init', undefined, user.token)).status, 401);
  assert.equal((await h.request('/invitations/redeem', { invitationToken: pending.body.invitationToken }, user.auth)).status, 401);
  const freshAuth = await h.authenticate(user);
  assert.equal((await h.request('/invitations/redeem', { invitationToken: pending.body.invitationToken }, freshAuth)).status, 403);
});
test('restart does not revive a persisted open round or any old authority/session', async (t) => {
  const h = await harness(t); const user = await h.participant(); const oldEnvelope = h.sign();
  await h.restart(); assert.equal((await h.admin('status')).body.open, false);
  assert.throws(() => h.activate(oldEnvelope), /denied/);
  assert.equal((await h.request('/polis/participation-init', undefined, user.token)).status, 403);
  h.activate(); await h.admin('round', { open: true });
  assert.equal((await h.request('/polis/participation-init', undefined, user.token)).status, 401);
});
test('expiry during provider work withholds response but does not claim to undo an already-dispatched vote', async (t) => {
  const h = await harness(t); const user = await h.participant();
  h.provider.pause = async () => { h.setTime(1_300_000); };
  assert.equal((await h.request('/polis/votes', { tid: 1, vote: -1 }, user.token)).status, 403);
  assert.equal(h.provider.calls, 1, 'one operation reached provider before expiry');
  assert.equal((await h.request('/polis/votes', { tid: 1, vote: -1 }, user.token)).status, 403);
  assert.equal(h.provider.calls, 1, 'no retry or future dispatch after expiry');
});
test('in-process authority close during provider work denies response and future dispatch', async (t) => {
  const h = await harness(t); const user = await h.participant(); h.provider.pause = async () => h.closeAuthority();
  assert.equal((await h.request('/polis/participation-init', undefined, user.token)).status, 403);
  assert.equal((await h.admin('status')).body.open, false);
});
test('controlled fixture capacity stops the 21st identity without freeing terminal identities', async (t) => {
  const h = await harness(t);
  for (let i = 0; i < 20; i++) assert.equal((await h.admin('fixtures', { fixture: 'synthetic_person_' + i })).status, 201);
  assert.equal((await h.admin('fixtures', { fixture: 'synthetic_extra' })).status, 409);
  assert.equal((await h.admin('status')).body.fixtures, 20);
});
test('mandatory guard cannot be overridden and configured conversations/stores must differ correctly', async (t) => {
  const h = await harness(t);
  for (const options of [{ ...h.config, admissionGuard: { assertActive() { return 'fake'; }, close() {} } },
    { ...h.config, conversationId: '9syntheticOther' },
    { ...h.config, provider: { ...h.provider, conversationId: '9syntheticOther' } },
    { ...h.config, dbPath: h.config.activation.ledgerPath }]) {
    assert.throws(() => createControlledLocalAccess(options), /configuration denied/);
  }
  const alias = join(h.directory, 'alias.sqlite'); await link(h.config.activation.ledgerPath, alias);
  assert.throws(() => createControlledLocalAccess({ ...h.config, dbPath: alias }), /configuration denied/);
  const linkedParent = join(h.directory, 'linked-parent'); await symlink(h.directory, linkedParent);
  assert.throws(() => createControlledLocalAccess({ ...h.config, dbPath: join(linkedParent, 'new.sqlite'),
    activation: { ...h.config.activation, ledgerPath: join(h.directory, 'new.sqlite') } }), /configuration denied/);
});
test('API listener is still closed when authority persistence fails during cleanup', async (t) => {
  const h = await harness(t); const port = Number(new URL(h.origin()).port);
  const external = new DatabaseSync(h.config.activation.ledgerPath);
  external.exec('ALTER TABLE activation_state RENAME TO held_state');
  await assert.rejects(h.close(), /cleanup could not be fully verified/);
  external.exec('ALTER TABLE held_state RENAME TO activation_state'); external.close();
  const socket = createServer(); await new Promise((resolve, reject) => {
    socket.once('error', reject); socket.listen(port, '127.0.0.1', resolve);
  }); await new Promise((resolve) => socket.close(resolve));
});
