/** Private, synthetic, in-process proof composition. Not a deployable service.
 * Actual loopback HTTP between BFF/API/signed-event receiver; intercepted OIDC
 * token/JWKS with real signatures. No WP UI, external issuer, mail or browser
 * rendering. Only newly created temporary access/authority stores are opened.
 */
import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, realpath, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createSyntheticIdentityHarness } from '../identity-foundation/synthetic-harness.mjs';
import { createSyntheticBrowserDriver } from '../identity-foundation/synthetic-browser-driver.mjs';
import { createControlledLocalAccess } from '../activation-foundation/controlled-access.mjs';
import { syntheticBinding, syntheticClaims, syntheticSigningFixture } from '../activation-foundation/synthetic-fixtures.mjs';
import { INTEGRATED_IDENTITY_MODE } from '../local-access/access-server.mjs';
import { createWordPressReceiver } from '../local-access/wordpress-receiver.mjs';
import { createLocalBrowser } from '../local-browser/browser-server.mjs';
import { createBrowserClient } from '../local-browser/integration-client.mjs';
import { createRegistrationIssuer } from '../wordpress-identity/registration-issuer.mjs';
import { createServerRegistrationBridge } from '../wordpress-identity/server-registration.mjs';

const opaque = /^[A-Za-z0-9_-]{32,512}$/u;
const routes = new Map([['/health', 'GET'], ['/invitations/redeem', 'POST'],
  ['/polis/participation-init', 'GET'], ['/polis/next-comment', 'GET'],
  ['/polis/votes', 'POST'], ['/session/logout', 'POST']]);

/** Always attempt every owned shutdown; the caller retains stores on failure. */
export async function closeProofServices(services) {
  let failed = false;
  for (const service of services) { try { await service.close(); } catch { failed = true; } }
  if (failed) throw new Error('Some synthetic proof services could not be closed.');
}

export async function createIntegratedJourney({ provider, binding = syntheticBinding(), now = Date.now, wordpressRegistration } = {}) {
  if (!provider || typeof provider.allowlist !== 'function' || typeof provider.participate !== 'function') {
    throw new Error('An explicit synthetic proof provider is required.');
  }
  if (wordpressRegistration && (!/^[A-Za-z0-9_-]{43}$/u.test(wordpressRegistration.eventSecret ?? '') ||
      wordpressRegistration.receiverPort !== 8101 || new Set([wordpressRegistration.eventSecret,
        wordpressRegistration.challengeSecret, wordpressRegistration.registrationSecret]).size !== 3)) throw new Error('Explicit local WordPress proof configuration required.');
  const directory = await realpath(await mkdtemp(join(tmpdir(), 'fncp-integrated-journey-')));
  const adminSecret = randomBytes(32).toString('base64url');
  const wpSecret = wordpressRegistration?.eventSecret ?? randomBytes(32).toString('base64url');
  let app; let browser; let receiver; let closed = false;
  try {
    const identityKey = randomBytes(32);
    const identity = await createSyntheticIdentityHarness({ now, identityKey });
    const driver = createSyntheticBrowserDriver({ mode: 'SYNTHETIC_ONLY', identity: identity.identity,
      syntheticAuthorizationResponse: identity.authorizationResponse, now });
    const signer = syntheticSigningFixture();
    let priorEnvelope; let closedBinding; let retained = false;
    app = createControlledLocalAccess({ mode: 'fixture-only', dbPath: join(directory, 'access.sqlite'),
      identityMode: INTEGRATED_IDENTITY_MODE, identityFoundation: identity.identity,
      adminSecret, conversationId: binding.conversationId, provider, now,
      activation: { mode: 'SYNTHETIC_ONLY', binding, publicKey: signer.publicKey, keyId: signer.keyId,
        ledgerPath: join(directory, 'activation.sqlite'), now } });
    const apiOrigin = await app.listen(0);
    const request = async (path, body, credential, extraHeaders = {}) => {
      const response = await fetch(apiOrigin + path, { method: body === undefined ? 'GET' : 'POST',
        redirect: 'error', signal: AbortSignal.timeout(11000),
        headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
          ...(credential ? { Authorization: `Bearer ${credential}` } : {}), ...extraHeaders },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
      let size = 0; const chunks = [];
      for await (const chunk of response.body ?? []) {
        size += chunk.length; if (size > 512 * 1024) throw new Error('Local proof response limit.'); chunks.push(chunk);
      }
      return { status: response.status, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) };
    };
    // Binding and account observations stay in this private test driver, never
    // in HTTP responses, browser scripts, logs, URLs or persisted evidence.
    let lastBinding; let lastFixture; let captureChain = Promise.resolve();
    const captured = (action) => {
      const result = captureChain.then(action); captureChain = result.catch(() => {}); return result;
    };
    const backend = {
      request(path, body, credential) {
        const method = routes.get(path);
        if (!method || (method === 'GET' ? body !== undefined : body === undefined) ||
            credential !== undefined && !opaque.test(credential)) throw new Error('Invalid private BFF operation.');
        return request(path, body, credential);
      },
      async authenticateIdentity(principal) {
        const result = await app.authenticateIdentity(principal); lastFixture = result.fixture; return result;
      },
    };
    const registrationIssuer = wordpressRegistration ? createRegistrationIssuer({ mode: 'SYNTHETIC_ONLY',
      challengeSecret: wordpressRegistration.challengeSecret, registrationSecret: wordpressRegistration.registrationSecret,
      registrationIdentity: (principal) => app.registrationIdentity(principal),
      principalDeadline: (principal) => identity.identity.principalDeadline(principal), now }) : undefined;
    const registrationBridge = wordpressRegistration?.seamlessRegistration === true
      ? createServerRegistrationBridge({ registrationIssuer, now }) : undefined;
    browser = createLocalBrowser({ mode: 'fixture-only', backend, now, registrationIssuer, registrationBridge,
      oidcDriver: { mode: 'SYNTHETIC_ONLY',
        begin(input) { lastBinding = input.browserSessionId; return driver.begin(input); },
        complete: (input) => driver.complete(input), discard: (input) => driver.discard(input),
        isVerifiedPrincipal: (principal) => driver.isVerifiedPrincipal(principal) } });
    const origin = await browser.listen(0);
    receiver = createWordPressReceiver({ mode: 'fixture-only', secret: wpSecret, now,
      ingest: (event) => app.ingestWordPressEvent(event) });
    const receiverOrigin = await receiver.listen(wordpressRegistration?.receiverPort ?? 0);
    const admin = (path, body) => request('/test-admin/' + path, body, adminSecret);
    const sendEvent = async (event, validSignature = true) => {
      const raw = JSON.stringify(event); const stamp = String(Math.floor(now() / 1000));
      const signature = createHmac('sha256', validSignature ? wpSecret : randomBytes(32)).update(stamp + '.' + raw).digest('hex');
      const response = await fetch(receiverOrigin + '/internal/wordpress/events', { method: 'POST', redirect: 'error',
        signal: AbortSignal.timeout(11000), headers: { 'Content-Type': 'application/json',
          'X-FNCP-WP-Timestamp': stamp, 'X-FNCP-WP-Signature': 'sha256=' + signature, 'X-FNCP-WP-Event-ID': event.event_id }, body: raw });
      return { status: response.status, body: await response.json() };
    };
    return {
      origin, client: () => createBrowserClient(origin), admin, request, sendEvent,
      event(fixture, state, version) { return { schema_version: 1, event_id: randomUUID(), subject: fixture,
        round_id: 'synthetic_round_local', version, state, occurred_at: new Date(now()).toISOString().replace(/\.\d{3}Z$/u, 'Z') }; },
      activate(ttlSeconds = 1200) {
        const envelope = signer.signClaims(syntheticClaims(app.activationBinding(), Math.floor(now() / 1000),
          { sequence: app.nextActivationSequence(), expiresAt: Math.floor(now() / 1000) + ttlSeconds }));
        const result = app.activate(envelope); priorEnvelope = envelope; return result;
      },
      closeAuthority: () => app.closeAuthority(),
      async begin(client) {
        return captured(async () => {
          lastBinding = undefined;
          const result = await client.oidcStart();
          return { result, privateBinding: lastBinding };
        });
      },
      inject(privateBinding, syntheticSubject, emailVerifiedByIssuer = true) {
        return driver.injectTestResponse({ browserSessionId: privateBinding, syntheticSubject, emailVerifiedByIssuer });
      },
      async finish(client, callbackUrl) {
        return captured(async () => {
          lastFixture = undefined;
          const result = await client.oidcCallback(callbackUrl);
          return { result, fixture: lastFixture };
        });
      },
      async login(client, syntheticSubject, emailVerifiedByIssuer = true) {
        await client.session();
        const started = await this.begin(client);
        if (started.result.status !== 200) return { result: started.result };
        const response = await this.inject(started.privateBinding, syntheticSubject, emailVerifiedByIssuer);
        if (!response.ok) throw new Error('Private synthetic injection failed.');
        return this.finish(client, response.callback.callbackUrl);
      },
      async close({ preserveStores = false } = {}) {
        if (typeof preserveStores !== 'boolean') throw new Error('Exact cleanup choice required.');
        if (closed) return;
        // Retain new temporary stores on uncertain shutdown. Never touch old
        // local WordPress/access stores or the provider database here.
        closedBinding = app.activationBinding();
        await closeProofServices([browser, receiver, app]);
        if (!preserveStores) await rm(directory, { recursive: true });
        closed = true; retained = preserveStores;
      },
      privateRecoveryContext() {
        if (!closed || !retained || !priorEnvelope || !wordpressRegistration?.seamlessRegistration) {
          throw new Error('Closed retained seamless synthetic proof required.');
        }
        // Private in-process capability only. Never expose through HTTP or logs.
        return { sourceAccessPath: join(directory, 'access.sqlite'), sourceActivationPath: join(directory, 'activation.sqlite'),
          sourceBinding: closedBinding,
          identity: { key: Buffer.from(identityKey), keyVersion: 1, issuer: identity.options.issuer,
            clientId: identity.options.clientId, syntheticSubjects: ['synthetic_wp_bound_alice', 'synthetic_wp_bound_bob'] },
          activation: { publicKey: signer.publicKey, keyId: signer.keyId, priorEnvelope } };
      },
    };
  } catch (error) {
    let stopped = true;
    for (const service of [browser, receiver, app]) { try { if (service) await service.close(); } catch { stopped = false; } }
    if (stopped) await rm(directory, { recursive: true });
    throw new Error('Synthetic integrated proof setup failed.');
  }
}

/** One invented vote only, with two new identity mappings. No fixture-password
 * authentication, direct-admin approval or public activation endpoint is used.
 * Throws stage labels only, without credential/body values. */
export async function exerciseCoreJourney(h) {
  const checks = [];
  const check = (label, condition) => { if (!condition) throw new Error('Integrated stage failed: ' + label); checks.push(label); };
  check('ordinary open cannot replace signed authority', (await h.admin('round', { open: true })).status === 403);
  h.activate();
  check('explicit open after signed synthetic authority', (await h.admin('round', { open: true })).status === 200);
  const alice = h.client(); const bob = h.client();
  const a = await h.login(alice, 'synthetic_integrated_alice');
  const b = await h.login(bob, 'synthetic_integrated_bob');
  check('two signed synthetic OIDC sign-ins through cookie and CSRF protocol', a.result.status === 200 && b.result.status === 200 &&
    a.result.body.phase === 'authenticated' && b.result.body.authentication === 'SIGNED_SYNTHETIC_OIDC' && a.fixture !== b.fixture);
  check('fixture-password browser fallback unavailable', (await alice.login('synthetic_fallback', 'a'.repeat(43))).status === 404);
  check('fixture provisioning API unavailable in strict mode', (await h.admin('fixtures', { fixture: 'synthetic_fallback' })).status === 404);
  check('signed identity alone cannot obtain an invitation', (await h.admin('invitations', { fixture: a.fixture })).status === 403);
  check('signed identity alone cannot initialize participation', (await alice.initialize()).status === 403);
  const approvalA = h.event(a.fixture, 'approved', 1); const approvalB = h.event(b.fixture, 'approved', 1);
  check('forged WordPress event signature rejected', (await h.sendEvent(approvalA, false)).status === 401);
  check('two signed current WordPress approval events applied',
    (await h.sendEvent(approvalA)).body.outcome === 'APPLIED' && (await h.sendEvent(approvalB)).body.outcome === 'APPLIED');
  check('duplicate approval event is an idempotent no-op', (await h.sendEvent(approvalA)).body.outcome === 'IDEMPOTENT_NO_OP');
  const issued = await h.admin('invitations', { fixture: a.fixture });
  check('account-bound invitation issued only after approval', issued.status === 201);
  check('forwarded invitation rejected for another approved account', (await bob.redeem(issued.body.invitationToken)).status === 403);
  check('matching account can still redeem the unconsumed invitation', (await alice.redeem(issued.body.invitationToken)).status === 200);
  check('already redeemed invitation not reusable in browser session', (await alice.redeem(issued.body.invitationToken)).status === 403);
  const initialized = await alice.initialize();
  check('only a known fixed synthetic statement reaches the browser protocol', initialized.status === 200 && Number.isSafeInteger(initialized.body.statement?.tid));
  const voted = await alice.vote(initialized.body.statement.tid, 0);
  check('one invented vote accepted through integrated controls', voted.status === 200 && voted.body.saved === true);
  const warm = await alice.next();
  check('warm signed-in session remains usable before revocation', warm.status === 200 && Number.isSafeInteger(warm.body.statement?.tid));
  check('signed WordPress revocation applied', (await h.sendEvent(h.event(a.fixture, 'revoked', 2))).body.outcome === 'APPLIED');
  check('warm vote denied after revocation', [401, 403].includes((await alice.vote(warm.body.statement.tid, 0)).status));
  check('old approval cannot revive the revoked account', (await h.sendEvent(approvalA)).body.outcome === 'STALE_NO_OP');
  check('new approval cannot reverse terminal revocation', (await h.sendEvent(h.event(a.fixture, 'approved', 3))).status === 409);
  check('auth-only logout verified by backend', (await bob.logout()).body.backendLogoutVerified === true);
  check('logged-out identity cannot receive a fresh invitation', [401, 403].includes((await h.admin('invitations', { fixture: b.fixture })).status));
  check('second synthetic identity terminally revoked', (await h.sendEvent(h.event(b.fixture, 'revoked', 2))).body.outcome === 'APPLIED');
  check('final local round closed', (await h.admin('round', { open: false })).body.open === false);
  return { checks, voteCount: 1 };
}
