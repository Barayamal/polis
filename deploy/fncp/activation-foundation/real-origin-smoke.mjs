/** Signed-authority integration with the already-prepared loopback Pol.is stack.
 * Uses only NEW invented fixtures and temporary access/authority DBs. Does not
 * activate a deployment, prove real OIDC/email or mutate the persistent WP API.
 */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { readFileSync, mkdtempSync, rmSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readStagingProvider } from '../local-access/staging-config.mjs';
import { MODE } from '../local-access/access-server.mjs';
import { createControlledLocalAccess } from './controlled-access.mjs';
import { syntheticSigningFixture, syntheticClaims } from './synthetic-fixtures.mjs';

process.umask(0o077);
const root = fileURLToPath(new URL('../../../', import.meta.url));
const context = 'colima-fncp-c-20260913';
const report = { classification: 'LOCAL_SYNTHETIC_ACTIVATION_PROOF_NOT_LAUNCH', checks: [], outcome: 'FAIL',
  runtimeBindingObservedBeforeAndAfter: false, sourceSeedsNotIndependentDatabaseReadback: true,
  fixtureAuthenticationSimulated: true, actualOidcProviderIntegrated: false,
  allocatedAllowlistRemovalVerified: false, noExternalSends: true };
const services = { server: 'server', math: 'math', alpha: 'client-participation-alpha', proxy: 'nginx-proxy' };
const sha = (value) => createHash('sha256').update(value).digest('hex');
const docker = (args) => execFileSync('docker', ['--context', context, ...args], { cwd: root, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
function observedBinding(conversationId, recoveryEpoch) {
  const images = {};
  for (const [role, service] of Object.entries(services)) {
    const [container] = JSON.parse(docker(['inspect', `fncp-polis-staging-${service}-1`]));
    if (!container.State.Running || container.Config.Labels?.['com.docker.compose.project'] !== 'fncp-polis-staging' ||
        container.Config.Labels?.['com.docker.compose.service'] !== service ||
        Object.values(container.HostConfig.PortBindings ?? {}).flat().some((value) => value.HostIp !== '127.0.0.1')) throw new Error();
    images[role] = container.Image;
  }
  const [migration] = JSON.parse(docker(['image', 'inspect', 'fncp-polis-staging-polis-migration']));
  images.migration = migration.Id;
  const seeds = readFileSync(new URL('../seed-statements.json', import.meta.url));
  const parsed = JSON.parse(seeds); assert.equal(parsed.length, 15); assert.equal(new Set(parsed).size, 15);
  return { deploymentId: 'synthetic_signed_origin_proof', conversationId, recoveryEpoch,
    images, configSha256: sha(readFileSync(new URL('../.env.staging', import.meta.url))), seedSha256: sha(seeds),
    scope: { maxParticipants: 20, statementCount: 15, suggestions: false } };
}
let app; let directory; let underlying; const allocated = new Set(); let before;
const check = (label, actual, expected) => {
  assert.deepEqual(actual, expected); report.checks.push(label); console.log(`PASS ${label}`);
};
try {
  const config = readStagingProvider(process.env.FNCP_LOCAL_SYNTHETIC_MODE); underlying = config.provider;
  before = observedBinding(config.conversationId, randomUUID());
  const signer = syntheticSigningFixture(); let clock = Date.now();
  directory = mkdtempSync(join(tmpdir(), 'fncp-signed-origin-'));
  const adminSecret = randomBytes(32).toString('base64url');
  const provider = {
    conversationId: config.conversationId,
    async allowlist(operation, xid) { if (operation === 'upsert') allocated.add(xid); return underlying.allowlist(operation, xid); },
    participate: (...args) => underlying.participate(...args),
  };
  app = createControlledLocalAccess({ mode: MODE, dbPath: join(directory, 'access.sqlite'), adminSecret,
    conversationId: config.conversationId, provider, now: () => clock,
    activation: { mode: 'SYNTHETIC_ONLY', binding: before, publicKey: signer.publicKey, keyId: signer.keyId,
      ledgerPath: join(directory, 'activation.sqlite'), now: () => clock } });
  const origin = await app.listen(0);
  const request = async (path, body, credential) => {
    const response = await fetch(origin + path, { method: body === undefined ? 'GET' : 'POST',
      headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        ...(credential ? { Authorization: `Bearer ${credential}` } : {}) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    return { status: response.status, body: await response.json() };
  };
  const admin = (path, body) => request('/test-admin/' + path, body, adminSecret);
  const envelope = () => signer.signClaims(syntheticClaims(app.activationBinding(), Math.floor(clock / 1000),
    { sequence: app.nextActivationSequence(), expiresAt: Math.floor(clock / 1000) + 120 }));
  check('ordinary local open cannot replace signed activation', (await admin('round', { open: true })).status, 403);
  app.activate(envelope());
  check('separate round open after signed test authority', (await admin('round', { open: true })).status, 200);
  const fixture = 'synthetic_signed_' + randomBytes(6).toString('hex');
  const created = await admin('fixtures', { fixture }); check('new invented fixture created', created.status, 201);
  const auth = await request('/test-auth/mailbox-simulator', { fixture, fixtureSecret: created.body.fixtureSecret });
  check('mailbox authentication explicitly simulated', auth.body.mailboxOwnership, 'SIMULATED_NOT_VERIFIED');
  check('actual Pol.is allowlist approval and readback', (await admin('approve', { fixture })).status, 200);
  const invitation = await admin('invitations', { fixture }); check('local-only account-bound invitation', invitation.status, 201);
  const body = { invitationToken: invitation.body.invitationToken };
  const redeemed = await request('/invitations/redeem', body, auth.body.fixtureAuthToken);
  check('account-bound redemption under current signed authority', redeemed.status, 201);
  const token = redeemed.body.participationToken;
  const init = await request('/polis/participation-init', undefined, token); check('actual Pol.is initialisation', init.status, 200);
  assert.ok(Number.isSafeInteger(init.body.nextComment?.tid));
  check('actual invented vote accepted before expiry', (await request('/polis/votes', { tid: init.body.nextComment.tid, vote: 0 }, token)).status, 200);
  clock += 121_000;
  check('warm vote denied after authority expiry', (await request('/polis/votes', { tid: init.body.nextComment.tid, vote: 0 }, token)).status, 403);
  check('round remains closed after expiry', (await admin('status')).body.open, false);
  app.activate(envelope()); await admin('round', { open: true });
  check('fresh authority does not revive old participation session', (await request('/polis/participation-init', undefined, token)).status, 401);
  check('fresh authority does not revive old fixture-auth session', (await request('/invitations/redeem', body, auth.body.fixtureAuthToken)).status, 401);
  check('revocation still available', (await admin('revoke', { fixture })).body.providerRemovalVerified, true);
  check('explicit final local round close', (await admin('round', { open: false })).body.open, false);
  check('runtime/config/source-seed binding unchanged at final observation', observedBinding(config.conversationId, before.recoveryEpoch), before);
  report.runtimeBindingObservedBeforeAndAfter = true;
  report.imageIds = before.images; report.configSha256 = before.configSha256; report.seedSha256 = before.seedSha256;
  report.outcome = 'PASS';
} catch {
  console.error('SIGNED_ACTUAL_ORIGIN_PROOF=FAIL; details redacted; inspect last PASS stage.');
} finally {
  let cleaned = true;
  for (const xid of allocated) {
    try { await underlying.allowlist('remove', xid); const value = await underlying.allowlist('readback', xid);
      if (value.present || value.operationVersion !== 2) throw new Error(); }
    catch { cleaned = false; }
  }
  report.allocatedAllowlistRemovalVerified = cleaned && allocated.size > 0;
  report.allocatedSyntheticIdentities = allocated.size;
  try { if (app) await app.close(); } catch { cleaned = false; }
  if (cleaned && directory) rmSync(directory, { recursive: true });
  if (!cleaned) report.outcome = 'FAIL';
  report.generatedAt = new Date().toISOString();
  const folder = new URL('../evidence/', import.meta.url); mkdirSync(folder, { recursive: true, mode: 0o700 });
  const path = new URL(`signed-origin-${report.generatedAt.replace(/[:.]/g, '-')}.json`, folder);
  writeFileSync(path, JSON.stringify(report, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  console.log(`SIGNED_ACTUAL_ORIGIN_PROOF=${report.outcome}; evidence ${fileURLToPath(path)}`);
  process.exitCode = report.outcome === 'PASS' ? 0 : 1;
}
