/** Fresh-target-only SQLite recovery and closed current-service cold start. */
import { createHmac, createPublicKey, generateKeyPairSync, randomBytes, randomUUID, sign, verify } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { createConnection } from 'node:net';
import { existsSync, lstatSync, realpathSync, writeFileSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { SIGNING_DOMAIN as ACTIVATION_DOMAIN } from '../activation-foundation/authority.mjs';
import { createControlledLocalAccess } from '../activation-foundation/controlled-access.mjs';
import { INTEGRATED_IDENTITY_MODE } from '../local-access/access-server.mjs';
import { canonical, readStrictStore, prepareStrictRecoveryManifest, validateStrictRecovery, publicKeyFingerprint,
  MODE as STRICT_MODE, SIGNING_DOMAIN, MAPPING_ALGORITHM } from '../strict-recovery/contract.mjs';
import { need, sha256 } from './crypto.mjs';

export function keyPackage({ identity, activation, wordpressSecrets, providerSecrets }) {
  need(Buffer.isBuffer(identity.key) && identity.key.length >= 32 && identity.key.length <= 64 && identity.keyVersion === 1);
  need(identity.issuer === 'https://identity.example.invalid/' && identity.clientId === 'invented-client');
  need(Array.isArray(identity.syntheticSubjects) && identity.syntheticSubjects.length >= 1 && identity.syntheticSubjects.length <= 20 &&
    new Set(identity.syntheticSubjects).size === identity.syntheticSubjects.length && identity.syntheticSubjects.every(s => typeof s === 'string' && /^synthetic_[a-z0-9_]{1,80}$/u.test(s)));
  need(activation.publicKey?.type === 'public' && activation.publicKey.asymmetricKeyType === 'ed25519' && /^synthetic_[a-z][a-z0-9_]{0,63}$/u.test(activation.keyId));
  const secrets = [...Object.values(wordpressSecrets), ...Object.values(providerSecrets)];
  need(secrets.length === 5 && new Set(secrets).size === 5 && secrets.every(s => typeof s === 'string' && /^[!-~]{32,512}$/u.test(s)));
  return { version: 1, mode: 'SYNTHETIC_ONLY', identity: { ...identity, key: identity.key.toString('base64url') },
    activation: { keyId: activation.keyId, publicKey: activation.publicKey.export({ type: 'spki', format: 'pem' }), priorEnvelope: activation.priorEnvelope },
    wordpressSecrets, providerSecrets };
}

export function fingerprints(keys) {
  const key = Buffer.from(keys.identity.key, 'base64url'); need(key.toString('base64url') === keys.identity.key);
  return { mappingAlgorithm: MAPPING_ALGORITHM, mappingKeyVersion: keys.identity.keyVersion,
    issuerConfigurationSha256: sha256(canonical({ issuer: keys.identity.issuer, clientId: keys.identity.clientId })),
    fingerprints: { identityMapping: sha256(key), activationVerification: publicKeyFingerprint(keys.activation.publicKey),
      wordpressEvent: sha256(keys.wordpressSecrets.event), providerGateway: sha256(keys.providerSecrets.gateway),
      providerAllowlist: sha256(keys.providerSecrets.allowlist) } };
}
/** Recompute the ACTUAL HMAC mapping from invented issuer+subject inputs, not email. */
export function verifyMappings(mappings, keys) {
  const key = Buffer.from(keys.identity.key, 'base64url'); const hmac = value => createHmac('sha256', key).update(JSON.stringify(value)).digest('base64url');
  try {
    need(mappings.length === keys.identity.syntheticSubjects.length);
    const found = new Set();
    for (const subject of keys.identity.syntheticSubjects) {
      const account = 'acct_' + hmac(['fncp-account-v1', keys.identity.issuer, subject]);
      const row = mappings.find(r => r.account_id === account);
      need(row && !found.has(account) && row.fixture === 'synthetic_i' + sha256(account).slice(0, 39) &&
        row.xid === 'fncp_' + hmac(['fncp-xid-v1', account, row.round])); found.add(account);
    }
    return { issuerSubjectMappingsVerified: mappings.length, emailIdentifiersUsed: false };
  } finally { key.fill(0); }
}
function freshFile(path, bytes, sources) {
  need(Buffer.isBuffer(bytes) && bytes.length >= 512 && !existsSync(path));
  const parent = dirname(path); const stat = lstatSync(parent);
  need(stat.isDirectory() && !stat.isSymbolicLink() && realpathSync(parent) === parent && (stat.mode & 0o777) === 0o700);
  need(!sources.map(p => realpathSync(p)).includes(resolve(path)));
  writeFileSync(path, bytes, { flag: 'wx', mode: 0o600 });
}
function read(path, kind) {
  const db = new DatabaseSync(path, { readOnly: true });
  try { return readStrictStore(db, kind); } finally { db.close(); }
}

/** Private negative-only probe. No real issuer, provider transport or voter
 * capability is constructed. Its sole listener is an ephemeral loopback port.
 * The random replay canaries were NEVER valid historical credentials. */
async function coldStart({ accessPath, activationPath, source, binding, keys, now }) {
  let providerCalls = 0; let app; let base; let targetBinding; let listenerClosed = false;
  let httpNegativeChecks = 0; let staleApprovalRetries = 0; let terminalRevocationRetries = 0;
  const adminSecret = randomBytes(32).toString('base64url');
  const canary = randomBytes(32).toString('base64url');
  const noProvider = () => { providerCalls++; throw new Error('Closed recovery provider call denied.'); };
  const request = async (path, { body, authorization, status } = {}) => {
    const response = await fetch(base + path, { method: body === undefined ? 'GET' : 'POST', redirect: 'error',
      signal: AbortSignal.timeout(3000), headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        ...(authorization ? { Authorization: 'Bearer ' + authorization } : {}) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    need(response.status === status && response.headers.get('cache-control') === 'no-store');
    const text = await response.text(); need(text.length <= 4096);
    const result = JSON.parse(text); need(result.mode === 'SYNTHETIC_ONLY');
    if (status >= 400) { need(typeof result.error === 'string'); httpNegativeChecks++; }
    return result;
  };
  const checkClosed = async () => {
    const status = await request('/test-admin/status', { authorization: adminSecret, status: 200 });
    need(status.open === false && status.fixtures === source.access.tables.fixtures.length && status.approvals.length === 1 &&
      status.approvals[0].state === 'revoked' && status.approvals[0].count === source.access.tables.approvals.length);
  };
  try {
    app = createControlledLocalAccess({ mode: 'fixture-only', dbPath: accessPath, adminSecret,
      conversationId: binding.conversationId, identityMode: INTEGRATED_IDENTITY_MODE,
      identityFoundation: { isVerifiedPrincipal: () => false, participantXid: () => ({ ok: false }) },
      provider: { allowlist: noProvider, participate: noProvider }, now,
      activation: { mode: 'SYNTHETIC_ONLY', binding, publicKey: createPublicKey(keys.activation.publicKey),
        keyId: keys.activation.keyId, ledgerPath: activationPath, now } });
    targetBinding = app.activationBinding();
    need(targetBinding.bootId !== source.binding.bootId && targetBinding.recoveryEpoch !== source.binding.recoveryEpoch);
    let denied = false; try { app.activate(keys.activation.priorEnvelope); } catch { denied = true; } need(denied);
    base = await app.listen(0); need(/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/u.test(base));
    const health = await request('/health', { status: 200 });
    need(health.productionReady === false && health.realEmailEnabled === false && health.heritageVerification === false &&
      health.identityMode === INTEGRATED_IDENTITY_MODE);
    await checkClosed();
    await request('/test-admin/status', { authorization: canary, status: 404 });
    await request('/test-admin/round', { authorization: adminSecret, body: { open: true }, status: 403 });
    await request('/test-auth/mailbox-simulator', { body: { fixture: 'synthetic_invalid_canary', fixtureSecret: canary }, status: 404 });
    await request('/invitations/redeem', { authorization: canary, body: { invitationToken: canary }, status: 403 });
    await request('/polis/participation-init', { authorization: canary, status: 403 });
    await request('/polis/next-comment', { authorization: canary, status: 403 });
    for (const row of source.access.tables.identity_mappings) {
      await request('/test-admin/approve', { authorization: adminSecret, body: { fixture: row.fixture }, status: 403 });
      await request('/test-admin/invitations', { authorization: adminSecret, body: { fixture: row.fixture }, status: 403 });
      const events = source.wordpress.events.filter(entry => entry.event.subject === row.fixture).map(entry => entry.event);
      const oldApproval = events.find(event => event.state === 'approved');
      const terminal = events.filter(event => event.state === 'revoked').sort((a, b) => b.version - a.version)[0];
      need(terminal && (!oldApproval || oldApproval.version < terminal.version) && terminal.version < Number.MAX_SAFE_INTEGER);
      if (oldApproval) {
        need((await app.ingestWordPressEvent(oldApproval)).outcome === 'STALE_NO_OP'); staleApprovalRetries++;
      }
      need((await app.ingestWordPressEvent(terminal)).outcome === 'IDEMPOTENT_NO_OP'); terminalRevocationRetries++;
      need((await app.ingestWordPressEvent({ ...terminal, event_id: randomUUID(), version: terminal.version + 1 })).outcome === 'TERMINAL_NO_OP');
      let terminalDenied = false;
      try { await app.ingestWordPressEvent({ ...(oldApproval ?? terminal), state: 'approved', event_id: randomUUID(), version: terminal.version + 1 }); }
      catch (error) { terminalDenied = error.status === 409; } need(terminalDenied);
      // This frozen assertion is deliberately UNVERIFIED by the fresh service;
      // no live/synthetic IdP is started or accepted by this negative probe.
      const principal = Object.freeze({ mode: 'SYNTHETIC_ONLY', assurance: 'OIDC_ID_TOKEN_VERIFIED',
        emailVerifiedByIssuer: true, accountId: row.account_id });
      let authDenied = false;
      try { await app.authenticateIdentity(principal); } catch (error) { authDenied = error.status === 401; } need(authDenied);
      let registrationDenied = false;
      try { await app.registrationIdentity(principal); } catch (error) { registrationDenied = error.status === 403; } need(registrationDenied);
    }
    await checkClosed(); need(providerCalls === 0);
  } finally {
    if (app) { await app.close(); listenerClosed = true; }
  }
  // Verify the owned port is gone, without issuing an HTTP request to any
  // subsequently re-used port. A bound/re-used port fails closed, not success.
  need(base && listenerClosed);
  await new Promise((accept, reject) => {
    const socket = createConnection({ host: '127.0.0.1', port: Number(new URL(base).port) });
    socket.setTimeout(1500);
    socket.once('error', error => { socket.destroy(); error.code === 'ECONNREFUSED' ? accept() : reject(new Error('Closed recovery listener verification denied.')); });
    socket.once('connect', () => { socket.destroy(); reject(new Error('Closed recovery listener remained available.')); });
    socket.once('timeout', () => { socket.destroy(); reject(new Error('Closed recovery listener verification timed out.')); });
  });
  need(canonical(read(accessPath, 'access')) === canonical(source.access));
  return { targetBinding, public: { actualControlledAccessServiceStarted: true, loopbackOnly: true, listenersClosed: true,
    providerCalls, closedBeforeAndAfter: true, oldSignedActivationRejected: true, restoredSessionsAbsent: true,
    retainedInvitationsConsumed: true, originalRawCredentialReplayTested: false, invalidReplayCanariesRejected: true,
    terminalApprovalRetriesNonGranting: true, terminalJournalUnchanged: true, httpNegativeChecks,
    staleApprovalRetries, terminalRevocationRetries } };
}

/** Caller has authenticated all encrypted components. Writes ONLY two new files.
 * Restored authority intentionally writes a new boot and clears active state.
 * This function NEVER activates the recovered installation. It starts/closes
 * one negative-only current access service at an ephemeral loopback port. */
export async function restoreStrictSqlite({ directory, accessBytes, activationBytes, sourcePaths, source, restoredWordPress,
  restoredProvider, keys, now = Date.now }) {
  const accessPath = resolve(directory, 'restored-access.sqlite'); const activationPath = resolve(directory, 'restored-activation.sqlite');
  need(Array.isArray(sourcePaths) && sourcePaths.length === 2);
  freshFile(accessPath, accessBytes, sourcePaths); freshFile(activationPath, activationBytes, sourcePaths);
  const recoveredAccess = read(accessPath, 'access'); const recoveredActivation = read(activationPath, 'activation');
  need(canonical(recoveredAccess) === canonical(source.access) && canonical(recoveredActivation) === canonical(source.activation));
  verifyMappings(recoveredAccess.tables.identity_mappings, keys);
  need(recoveredAccess.tables.round.length === 1 && recoveredAccess.tables.round[0].open === 0 &&
    recoveredAccess.tables.sessions.length === 0 && recoveredAccess.tables.invitations.every(row => row.used === 1) &&
    recoveredAccess.tables.approvals.length > 0 && recoveredAccess.tables.approvals.every(row => row.state === 'revoked') &&
    recoveredActivation.tables.activation_state.length === 1 && recoveredActivation.tables.activation_state[0].active === 0);
  const { bootId: _oldBoot, ...previous } = source.binding;
  const binding = { ...previous, recoveryEpoch: randomUUID() };
  const oldEnvelope = keys.activation.priorEnvelope;
  need(typeof oldEnvelope?.payload === 'string' && typeof oldEnvelope.signature === 'string');
  const oldPayload = Buffer.from(oldEnvelope.payload, 'base64url'); const oldClaims = JSON.parse(oldPayload);
  need(canonical(oldClaims) === oldPayload.toString('utf8') && canonical(oldClaims.binding) === canonical(source.binding) &&
    verify(null, Buffer.concat([ACTIVATION_DOMAIN, oldPayload]), createPublicKey(keys.activation.publicKey), Buffer.from(oldEnvelope.signature, 'base64url')));
  need(source.activation.tables.activation_ids.some(row => row.id === oldClaims.activationId));
  const probe = await coldStart({ accessPath, activationPath, source, binding, keys, now });
  const targetBinding = probe.targetBinding;
  const restored = { binding: targetBinding, access: read(accessPath, 'access'), activation: read(activationPath, 'activation'),
    wordpress: restoredWordPress, provider: restoredProvider, volatile: { oidcPending: 0, principalCapabilities: 0, browserSessions: 0 } };
  const keyState = fingerprints(keys); const keyContinuity = { source: keyState, restored: keyState };
  const signer = generateKeyPairSync('ed25519'); const stamp = Math.floor(now() / 1000); const recoveryId = randomUUID();
  const keyId = 'synthetic_expanded_recovery';
  const claims = prepareStrictRecoveryManifest({ mode: STRICT_MODE, recoveryId, keyId, signerFingerprint: publicKeyFingerprint(signer.publicKey),
    issuedAt: stamp, expiresAt: stamp + 1200, source, targetBinding, keyContinuity });
  const payload = Buffer.from(canonical(claims));
  const envelope = { payload: payload.toString('base64url'), signature: sign(null, Buffer.concat([SIGNING_DOMAIN, payload]), signer.privateKey).toString('base64url') };
  const result = validateStrictRecovery({ mode: STRICT_MODE, envelope, publicKey: signer.publicKey, expectedRecoveryId: recoveryId,
    expectedKeyId: keyId, source, restored, targetBinding, keyContinuity, now }); need(result.ok);
  // The function owns a fresh private directory; this manifest is consumed by
  // exclusive creation, never as an activation grant or automatic reboot plan.
  writeFileSync(resolve(directory, 'consumed-recovery-id'), recoveryId + '\n', { flag: 'wx', mode: 0o600 });
  return { restored, manifest: { envelope, publicKey: signer.publicKey.export({ type: 'spki', format: 'pem' }) },
    public: { ...result, actualMultiStoreRestorePerformed: false, requiresExternalRecoveryIdConsumption: false,
      localRecoveryIdConsumed: true, sqliteStoresActuallyRestored: 2, oldSignedActivationRejected: true,
      originalSignatureVerified: true, restoredAuthorityActive: false, noListenersStarted: false, coldStart: probe.public,
      identityMappingProof: verifyMappings(restored.access.tables.identity_mappings, keys),
      restoredAccessSha256: sha256(readFileSync(accessPath)), restoredActivationSha256: sha256(readFileSync(activationPath)) } };
}
