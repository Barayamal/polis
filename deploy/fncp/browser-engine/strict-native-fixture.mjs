/** TEST ONLY: real strict access/activation/BFF, invented issuer, model WordPress
 * and Pol.is. All stores are :memory:. Private capabilities never enter evidence.
 * No browser launcher, retained paths, HTTP administration or production default.
 */
import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createStrictLocalService, STRICT_SERVICE_MODE } from '../strict-service/service.mjs';
import { createHttpsRedirectDriver } from '../identity-foundation/https-redirect-driver.mjs';
import { syntheticBinding, syntheticClaims, syntheticSigningFixture } from '../activation-foundation/synthetic-fixtures.mjs';
import { canonical, signEnvelope, CHALLENGE_DOMAIN, RECEIPT_DOMAIN, CONSENT_VERSION } from '../wordpress-identity/registration-issuer.mjs';

const fixedSeeds = Object.freeze(JSON.parse(readFileSync(new URL('../seed-statements.json', import.meta.url), 'utf8')));
const opaque = () => randomBytes(32).toString('base64url');
const digest = value => createHash('sha256').update(value).digest('hex');
const endpoint = 'http://127.0.0.1:8103/wp-admin/admin-post.php';
const fail = () => new Error('Strict native synthetic fixture rejected; KEEP_CLOSED.');
const exact = (value, keys) => {
  if (!value || ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
      Reflect.ownKeys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key)) ||
      Object.values(Object.getOwnPropertyDescriptors(value)).some(item => !Object.hasOwn(item, 'value'))) throw fail();
};
const reject = condition => { if (!condition) throw fail(); };

export async function createStrictNativeFixture(options) {
  return createNativeFixture(options, 1);
}

/** Fixed two-account test mode; no caller-selected account or capacity. */
export async function createTwoAccountStrictNativeFixture(options) {
  return createNativeFixture(options, 2);
}

async function createNativeFixture(options, accountCount) {
  exact(options, ['lab', 'seeds']);
  const { lab, seeds } = options;
  reject(Array.isArray(seeds) && Object.getPrototypeOf(seeds) === Array.prototype && seeds.length === 15 && fixedSeeds.length === 15 &&
    Reflect.ownKeys(seeds).length === 16 && fixedSeeds.every((text, i) => {
      const descriptor = Object.getOwnPropertyDescriptor(seeds, String(i));
      return descriptor && Object.hasOwn(descriptor, 'value') && descriptor.value === text;
    }));
  exact(lab, ['identity', 'authorizationEndpoint', 'callbackUri', 'browserPort', 'publicTestCertificates', 'browserTls', 'request', 'close', 'summary']);
  exact(lab.browserTls, ['mode', 'origin', 'key', 'cert']);
  reject(Object.isFrozen(lab) && Number.isInteger(lab.browserPort) && lab.browserPort > 0 && lab.browserPort <= 65535 &&
    lab.browserTls.origin === `https://browser.example.invalid:${lab.browserPort}` &&
    lab.callbackUri === lab.browserTls.origin + '/oidc/callback' && typeof lab.summary === 'function' &&
    ['request', 'close', 'publicTestCertificates'].every(key => typeof lab[key] === 'function'));
  const authorization = new URL(lab.authorizationEndpoint);
  reject(authorization.href === lab.authorizationEndpoint && authorization.protocol === 'https:' &&
    authorization.hostname === 'identity.issuer.invalid' && authorization.port &&
    authorization.pathname === '/authorize' && !authorization.search && !authorization.hash && !authorization.username && !authorization.password);
  const summary = lab.summary();
  reject(summary.mode === 'SYNTHETIC_ONLY' && summary.actualLoopbackTls === true && summary.realIdentityProvider === false &&
    summary.globalTrustChanged === false && summary.productionReady === false && summary.listenersClosed === false);
  reject((summary.fixedInventedAccountCount ?? 1) === accountCount);

  const checks = []; const aggregate = { authentications: 0, registrations: 0, providerCalls: 0,
    providerParticipationCalls: 0, votes: 0, agree: 0, disagree: 0, pass: 0 };
  const record = (name, condition) => { reject(condition); checks.push(Object.freeze({ name, result: 'PASS' })); };
  const signer = syntheticSigningFixture(); const binding = syntheticBinding();
  const eventSecret = opaque(); const challengeSecret = opaque(); const registrationSecret = opaque();
  const states = new Map(); const registrationSessions = new Map(); const accounts = []; const verifiedAccounts = new Set();
  let origins; let service;
  let startAttempted = false; let closing = false; let closePromise; let busy = false;
  let approvalStarted = false; let approved = false; let issueStarted = false; let revokeStarted = false; let revoked = false;
  let participationAtRevocation;
  const running = () => reject(!closing && service.snapshot().state === 'RUNNING');
  const alive = () => { running(); reject(!revoked); };
  const statement = state => state.next < fixedSeeds.length ? { tid: state.next, txt: fixedSeeds[state.next] } : null;
  const provider = Object.freeze({ conversationId: binding.conversationId,
    async allowlist(operation, xid) {
      reject(!closing && ['upsert', 'readback', 'remove'].includes(operation) && /^fncp_[A-Za-z0-9_-]{43}$/u.test(xid));
      aggregate.providerCalls++;
      let state = states.get(xid);
      if (operation === 'upsert') {
        reject(!revoked && (!state || state.operationVersion !== 2));
        if (!state) { state = { present: true, operationVersion: 1, next: 0 }; states.set(xid, state); }
      } else if (operation === 'remove') {
        state = { present: false, operationVersion: 2, next: state?.next ?? 0 }; states.set(xid, state);
      }
      return Object.freeze({ present: state?.present ?? false, operationVersion: state?.operationVersion ?? null });
    },
    async participate(kind, xid, values = {}) {
      aggregate.providerCalls++; aggregate.providerParticipationCalls++;
      reject(!closing && !revoked && ['init', 'next', 'vote'].includes(kind));
      const state = states.get(xid); reject(state?.present === true && state.operationVersion === 1);
      exact(values, kind === 'vote' ? ['tid', 'vote'] : []);
      if (kind === 'vote') {
        reject(Number.isSafeInteger(values.tid) && values.tid === state.next && state.next < 15 && [-1, 0, 1].includes(values.vote));
        state.next++; aggregate.votes++;
        aggregate[values.vote === -1 ? 'agree' : values.vote === 1 ? 'disagree' : 'pass']++;
      }
      return kind === 'next' ? statement(state) : { nextComment: statement(state) };
    },
  });
  const response = (body, cookie) => new Response(JSON.stringify(body), { headers: {
    'Content-Type': 'application/json', 'Cache-Control': 'no-store',
    ...(cookie ? { 'Set-Cookie': `fncp_wp_identity=${cookie}; Path=/; HttpOnly; SameSite=Strict` } : {}),
  } });
  const registrationFetch = async (url, init) => {
    alive(); reject(!init.signal?.aborted && init.redirect === 'error' && typeof url === 'string');
    const form = typeof init.body === 'string' ? new URLSearchParams(init.body) : undefined;
    if (url === endpoint + '?action=fncp_identity_session') {
      reject(init.method === 'GET' && init.body === undefined && !init.headers.Cookie &&
        registrationSessions.size < accountCount && !approvalStarted);
      const guest = opaque(); const csrf = opaque();
      registrationSessions.set(guest, { guest, csrf, stage: 1 });
      return response({ mode: 'SYNTHETIC_ONLY', csrfToken: csrf }, guest);
    }
    const guest = /^fncp_wp_identity=([A-Za-z0-9_-]{43})$/u.exec(init.headers.Cookie ?? '')?.[1];
    const session = registrationSessions.get(guest);
    reject(session && url === endpoint && init.method === 'POST' &&
      init.headers.Origin === 'http://127.0.0.1:8103' && form?.get('csrfToken') === session.csrf);
    if (session.stage === 1) {
      reject(form.size === 2 && form.get('action') === 'fncp_identity_challenge');
      const seconds = Math.floor(Date.now() / 1000);
      session.challenge = signEnvelope({ schemaVersion: 1, purpose: 'wordpress-registration-challenge', audience: 'fncp-synthetic-bff',
        challengeId: randomUUID(), browserBinding: digest(guest), roundId: 'synthetic_round_local', issuedAt: seconds,
        expiresAt: seconds + 120 }, challengeSecret, CHALLENGE_DOMAIN);
      session.stage = 2; return response({ mode: 'SYNTHETIC_ONLY', challenge: session.challenge });
    }
    reject(session.stage === 2 && form.size === 3 && form.get('action') === 'fncp_identity_register');
    const challenge = session.challenge;
    const receipt = JSON.parse(form.get('receipt')); exact(receipt, ['payload', 'signature']);
    reject(typeof receipt.payload === 'string' && /^[A-Za-z0-9_-]{1,8192}$/u.test(receipt.payload) &&
      typeof receipt.signature === 'string' && /^[a-f0-9]{64}$/u.test(receipt.signature));
    const expected = createHmac('sha256', registrationSecret).update(RECEIPT_DOMAIN + receipt.payload).digest();
    reject(timingSafeEqual(expected, Buffer.from(receipt.signature, 'hex')));
    const raw = Buffer.from(receipt.payload, 'base64url');
    reject(raw.toString('base64url') === receipt.payload);
    const claims = JSON.parse(raw.toString('utf8'));
    exact(claims, ['schemaVersion', 'purpose', 'audience', 'assertionId', 'challengeId', 'browserBinding', 'challengeDigest',
      'fixture', 'roundId', 'issuedAt', 'expiresAt', 'consentVersion', 'adultSelfAttested', 'eligibilitySelfAttested', 'registrationConsent']);
    const challengeClaims = JSON.parse(Buffer.from(challenge.payload, 'base64url').toString('utf8'));
    const seconds = Math.floor(Date.now() / 1000);
    reject(raw.toString('utf8') === canonical(claims) && claims.schemaVersion === 1 &&
      claims.purpose === 'wordpress-registration-receipt' && claims.audience === 'fncp-synthetic-wordpress' &&
      /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u.test(claims.assertionId) &&
      claims.challengeId === challengeClaims.challengeId && claims.browserBinding === digest(guest) &&
      claims.challengeDigest === digest(canonical(challenge)) && claims.roundId === 'synthetic_round_local' &&
      /^synthetic_i[a-f0-9]{39}$/u.test(claims.fixture) && claims.consentVersion === CONSENT_VERSION &&
      claims.adultSelfAttested === true && claims.eligibilitySelfAttested === true && claims.registrationConsent === true &&
      Number.isSafeInteger(claims.issuedAt) && Number.isSafeInteger(claims.expiresAt) &&
      claims.issuedAt >= challengeClaims.issuedAt && claims.issuedAt <= seconds && claims.expiresAt > seconds &&
      claims.expiresAt <= Math.min(claims.issuedAt + 60, challengeClaims.expiresAt));
    alive(); reject(accounts.length < accountCount && !accounts.some(account => account.fixture === claims.fixture) && !approvalStarted);
    accounts.push({ fixture: claims.fixture, approved: false, revoked: false });
    session.stage = 3; aggregate.registrations++;
    record('signed server-side registration receipt binds the private fixture without granting approval', true);
    return response({ mode: 'SYNTHETIC_ONLY', registered: true, registrationId: randomUUID(), csrfToken: opaque() }, opaque());
  };
  const driver = createHttpsRedirectDriver({ mode: 'SYNTHETIC_ONLY', identity: lab.identity,
    authorizationEndpoint: lab.authorizationEndpoint, callbackUri: lab.callbackUri });
  service = await createStrictLocalService({ mode: STRICT_SERVICE_MODE, identity: lab.identity,
    oidcDriver: { ...driver, async complete(input) {
      const result = await driver.complete(input);
      if (result?.ok === true && lab.identity.isVerifiedPrincipal(result.principal) === true) {
        const accountId = result.principal.accountId;
        reject(typeof accountId === 'string' && (verifiedAccounts.has(accountId) || verifiedAccounts.size < accountCount));
        verifiedAccounts.add(accountId); aggregate.authentications++;
      }
      return result;
    } }, provider, activation: { binding, publicKey: signer.publicKey, keyId: signer.keyId },
    storage: { access: ':memory:', activation: ':memory:' }, eventSecret,
    ports: { access: 0, receiver: 0, browser: lab.browserPort }, httpsRedirect: lab.browserTls,
    registration: { challengeSecret, registrationSecret, fetch: registrationFetch },
  });
  const counts = () => Object.freeze({ ...aggregate, participationCalls: aggregate.providerParticipationCalls,
    distinctVerifiedAccounts: verifiedAccounts.size,
    approvedAccounts: accounts.filter(account => account.approved && !account.revoked).length,
    activeAllowlistEntries: [...states.values()].filter(state => state.present).length,
    participationAfterRevocation: participationAtRevocation === undefined ? 0 : aggregate.providerParticipationCalls - participationAtRevocation });
  const evidence = () => Object.freeze({ mode: 'SYNTHETIC_ONLY', classification: 'KEEP_CLOSED', strictServiceComposed: true,
    actualAccessActivationAndBff: true, accessAndActivationStores: 'FRESH_IN_MEMORY', signedWordPressModel: true,
    modeledPolisProvider: true, realWordPress: false, realPolis: false, realIdentityProvider: false,
    realEmailEnabled: false, indigenousHeritageVerified: false, productionReady: false, httpTestAdministration: false,
    fixedInventedAccountCount: accountCount,
    authenticationCounter: 'VERIFIED_DRIVER_COMPLETIONS_NOT_BACKEND_ACCEPTANCE',
    checks: Object.freeze([...checks]), counts: counts() });
  const event = (state, version, subject) => ({ schema_version: 1, event_id: randomUUID(), subject,
    round_id: 'synthetic_round_local', version, state, occurred_at: new Date().toISOString().replace(/\.\d{3}Z$/u, 'Z') });
  const send = async (value, secret = eventSecret) => {
    running(); const raw = JSON.stringify(value); const stamp = String(Math.floor(Date.now() / 1000));
    const signature = createHmac('sha256', secret).update(stamp + '.' + raw).digest('hex');
    const result = await fetch(origins.receiver + '/internal/wordpress/events', { method: 'POST', redirect: 'error',
      signal: AbortSignal.timeout(3000), headers: { 'Content-Type': 'application/json', 'X-FNCP-WP-Timestamp': stamp,
        'X-FNCP-WP-Signature': 'sha256=' + signature, 'X-FNCP-WP-Event-ID': value.event_id }, body: raw });
    const text = await result.text(); reject(text.length <= 4096); running();
    return { status: result.status, body: JSON.parse(text) };
  };
  const denied = async operation => {
    let status; try { await operation(); } catch (error) { status = error.status; }
    return status === 403;
  };
  const action = async operation => {
    running(); reject(!busy); busy = true;
    try { return await operation(); } finally { busy = false; }
  };
  return Object.freeze({
    async start() {
      reject(!startAttempted && !closing); startAttempted = true;
      try {
        ({ origins } = await service.start());
        record('strict service starts all three listeners with no open round or provider calls',
          (await service.operator.status()).open === false && aggregate.providerCalls === 0);
        record('opening without signed activation is denied', await denied(() => service.operator.setRoundOpen(true)));
        service.operator.activate(signer.signClaims(syntheticClaims(service.operator.activationBinding(),
          Math.floor(Date.now() / 1000), { sequence: service.operator.nextActivationSequence() })));
        record('signed synthetic activation does not automatically open the round',
          (await service.operator.status()).open === false && aggregate.providerCalls === 0);
        running(); return origins;
      } catch { await service.close(); throw fail(); }
    },
    close() {
      if (!closePromise) { closing = true; closePromise = service.close(); }
      return closePromise;
    },
    snapshot: () => service.snapshot(), counts, evidence,
    approve: () => action(async () => {
      reject(accounts.length === accountCount && verifiedAccounts.size === accountCount && !approvalStarted && !revoked);
      approvalStarted = true;
      for (const [index, account] of accounts.entries()) {
        record('registration alone cannot obtain a strict invitation', await denied(() => service.operator.issueInvitation(account.fixture)));
        account.approvalEvent = event('approved', 1, account.fixture); const before = aggregate.providerCalls;
        record('forged WordPress approval is denied before provider dispatch',
          (await send(account.approvalEvent, opaque())).status === 401 && aggregate.providerCalls === before);
        const applied = await send(account.approvalEvent);
        record('signed WordPress approval applies with provider upsert and readback', applied.status === 200 &&
          applied.body.outcome === 'APPLIED' && aggregate.providerCalls === before + 2 && counts().activeAllowlistEntries === index + 1);
        account.approved = true;
        const duplicate = await send(account.approvalEvent);
        record('exact duplicate approval is idempotent with no provider replay', duplicate.status === 200 &&
          duplicate.body.outcome === 'IDEMPOTENT_NO_OP' && aggregate.providerCalls === before + 2);
        record('signed approval alone cannot issue an invitation while the round is closed',
          (await service.operator.status()).open === false && await denied(() => service.operator.issueInvitation(account.fixture)));
      }
      running(); approved = true; return evidence();
    }),
    openAndIssue: () => action(async () => {
      reject(approved && !issueStarted && !revoked); issueStarted = true;
      const before = aggregate.providerCalls;
      record('private explicit open is separate from signed approval', (await service.operator.setRoundOpen(true)).open === true);
      const invitations = [];
      for (const account of accounts) {
        const invitation = await service.operator.issueInvitation(account.fixture);
        record('strict account-bound invitation is issued locally with no provider or delivery action',
          /^[A-Za-z0-9_-]{43}$/u.test(invitation.invitationToken) &&
          invitation.delivery === 'LOCAL_RESPONSE_ONLY_NO_EMAIL_OR_MESSAGE' && aggregate.providerCalls === before &&
          !invitations.some(other => other.invitationToken === invitation.invitationToken));
        invitations.push(Object.freeze(invitation));
      }
      running(); return accountCount === 1 ? invitations[0] : Object.freeze({ invitations: Object.freeze(invitations) });
    }),
    revoke: () => action(async () => {
      reject(approved && !revokeStarted); revokeStarted = true;
      const participationBefore = aggregate.providerParticipationCalls; const callsBefore = aggregate.providerCalls;
      for (const [index, account] of accounts.entries()) {
        const result = await send(event('revoked', 2, account.fixture));
        record('signed revocation removes the provider allowlist with verified readback', result.status === 200 &&
          result.body.outcome === 'APPLIED' && counts().activeAllowlistEntries === accountCount - index - 1 &&
          aggregate.providerCalls === callsBefore + (index + 1) * 2);
        account.revoked = true;
        // Reuse the original event: a changed event_id at the same version is a
        // conflicting event, not a stale retry, and must remain rejected.
        const stale = await send(account.approvalEvent);
        record('original old approval is a stale no-op after terminal revocation', stale.status === 200 && stale.body.outcome === 'STALE_NO_OP');
        record('changed old-version event identity remains a conflict', (await send({ ...account.approvalEvent, event_id: randomUUID() })).status === 409);
        record('newer signed approval cannot reverse terminal revocation', (await send(event('approved', 3, account.fixture))).status === 409);
      }
      revoked = true; participationAtRevocation = participationBefore;
      record('revocation and rejected approvals perform no participation or extra provider operation',
        aggregate.providerParticipationCalls === participationBefore && aggregate.providerCalls === callsBefore + accountCount * 2);
      return evidence();
    }),
  });
}
