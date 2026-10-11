/** Actual origin integration test. Synthetic writes only to 127.0.0.1:5500.
 * Does NOT send email, reopen production, or perform participant testing.
 * Generated synthetic votes remain in the disposable Pol.is database.
 */
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createLocalAccess, MODE } from './access-server.mjs';
import { readStagingProvider } from './staging-config.mjs';

process.umask(0o077);
let app; let directory; let request; let admin; let failure = false;
const allocated = new Set();
let underlying;
try {
  const config = readStagingProvider(process.env.FNCP_LOCAL_SYNTHETIC_MODE);
  underlying = config.provider;
  const provider = {
    async allowlist(operation, xid) {
      if (operation === 'upsert') allocated.add(xid);
      return underlying.allowlist(operation, xid);
    },
    participate: (...args) => underlying.participate(...args),
  };
  const adminSecret = randomBytes(32).toString('base64url');
  let simulatedTime = Date.now();
  directory = await mkdtemp(join(tmpdir(), 'fncp-local-access-real-'));
  app = createLocalAccess({ mode: MODE, dbPath: join(directory, 'synthetic.sqlite'),
    adminSecret, conversationId: config.conversationId, provider, now: () => simulatedTime });
  const origin = await app.listen(0);
  request = async (path, body, credential) => {
    const response = await fetch(origin + path, {
      method: body === undefined ? 'GET' : 'POST',
      headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        ...(credential ? { Authorization: `Bearer ${credential}` } : {}) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    return { status: response.status, body: await response.json() };
  };
  admin = (path, body) => request('/test-admin/' + path, body, adminSecret);
  const check = (label, actual, expected) => {
    assert.equal(actual, expected, label);
    console.log(`PASS ${label}`);
  };
  const newFixture = async (prefix) => {
    const fixture = 'synthetic_' + prefix + '_' + randomBytes(6).toString('hex');
    const created = await admin('fixtures', { fixture }); check(`${prefix} fixture created`, created.status, 201);
    const authenticated = await request('/test-auth/mailbox-simulator', { fixture, fixtureSecret: created.body.fixtureSecret });
    check(`${prefix} simulated mailbox authentication`, authenticated.status, 200);
    return { fixture, auth: authenticated.body.fixtureAuthToken };
  };
  check('explicit synthetic-only boundary', (await request('/health')).body.productionReady, false);
  const alice = await newFixture('alice'); const bob = await newFixture('bob');
  check('unapproved invitation denied', (await admin('invitations', { fixture: bob.fixture })).status, 403);
  check('round opened locally for synthetic run', (await admin('round', { open: true })).status, 200);
  check('actual provider approval/readback for Alice', (await admin('approve', { fixture: alice.fixture })).status, 200);
  check('actual provider approval/readback for Bob', (await admin('approve', { fixture: bob.fixture })).status, 200);
  const expiry = await admin('invitations', { fixture: alice.fixture, ttlSeconds: 1 });
  check('expiry fixture invitation issued', expiry.status, 201); simulatedTime += 1001;
  check('expired invitation denied', (await request('/invitations/redeem', { invitationToken: expiry.body.invitationToken }, alice.auth)).status, 403);
  const issued = await admin('invitations', { fixture: alice.fixture }); check('bound invitation issued locally only', issued.status, 201);
  const redeemBody = { invitationToken: issued.body.invitationToken };
  check('forwarded invitation denied to different approved account', (await request('/invitations/redeem', redeemBody, bob.auth)).status, 403);
  const redeemed = await request('/invitations/redeem', redeemBody, alice.auth);
  check('correct account invitation redeemed', redeemed.status, 201);
  check('invitation replay denied', (await request('/invitations/redeem', redeemBody, alice.auth)).status, 403);
  const participationToken = redeemed.body.participationToken;
  check('fixture-auth cannot replace participation session', (await request('/polis/participation-init', undefined, alice.auth)).status, 401);
  const init = await request('/polis/participation-init', undefined, participationToken);
  check('actual Pol.is participation initialised', init.status, 200);
  check('Pol.is bearer not exposed', init.body.auth, undefined);
  assert.ok(Number.isSafeInteger(init.body.nextComment?.tid), 'Synthetic seed statement required.');
  const tid = init.body.nextComment.tid;
  check('caller-supplied identity denied', (await request('/polis/votes', { tid, vote: 0, xid: 'not-accepted' }, participationToken)).status, 400);
  check('unknown fixed-statement ID denied without a false outage', (await request('/polis/votes', { tid: Number.MAX_SAFE_INTEGER, vote: 0 }, participationToken)).status, 400);
  check('actual fixed-statement vote stored', (await request('/polis/votes', { tid, vote: 0 }, participationToken)).status, 200);
  check('actual warm session remains usable before revocation', (await request('/polis/participation-init', undefined, participationToken)).status, 200);
  check('actual provider removal/readback verified', (await admin('revoke', { fixture: alice.fixture })).status, 200);
  check('warm session denied after revocation', (await request('/polis/votes', { tid, vote: 0 }, participationToken)).status, 401);
  check('revoked account cannot be silently reapproved', (await admin('approve', { fixture: alice.fixture })).status, 409);
  check('second synthetic approval removed', (await admin('revoke', { fixture: bob.fixture })).status, 200);
  check('local round closed', (await admin('round', { open: false })).status, 200);
  console.log('ACTUAL_POLIS_ORIGIN_SMOKE=PASS; fixture mailbox authentication is simulated; no production or WordPress assurance claimed.');
} catch {
  failure = true;
  console.error('ACTUAL_POLIS_ORIGIN_SMOKE=FAIL; no secrets or response contents logged. Inspect the last PASS stage.');
} finally {
  // Remove only opaque XIDs allocated by this execution. Votes are synthetic
  // and intentionally retained with the disposable test conversation.
  for (const xid of allocated) {
    try {
      await underlying.allowlist('remove', xid);
      const result = await underlying.allowlist('readback', xid);
      if (result.present || result.operationVersion !== 2) throw new Error();
    } catch {
      failure = true;
      console.error('Synthetic provider cleanup could not be verified; dispose of this synthetic stack before any other use.');
    }
  }
  if (app) await app.close();
  if (directory) await rm(directory, { recursive: true });
  process.exitCode = failure ? 1 : 0;
}
