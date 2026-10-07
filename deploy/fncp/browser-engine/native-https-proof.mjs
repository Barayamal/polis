/** OPT-IN TEST ONLY. Full installed Chrome149, fresh profile-only synthetic trust,
 * actual loopback TLS, actual BFF/assets, signed invented IdP and in-memory model.
 * No OS trust/hosts changes, personal profile, certificate exemptions or downloads.
 * Internal Chrome schema bootstrap is QA support, NOT production provisioning.
 */
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { channel } from 'node:diagnostics_channel';
import { createServer } from 'node:https';
import { connect } from 'node:net';
import { createLocalBrowser, HTTPS_COOKIE_NAME, TRANSACTION_COOKIE_NAME } from '../local-browser/browser-server.mjs';
import { createRedirectTlsLab } from '../identity-foundation/redirect-tls-lab.mjs';
import { createHttpsRedirectDriver } from '../identity-foundation/https-redirect-driver.mjs';
import { createDisposableChromeTrust } from './disposable-chrome-trust.mjs';
import { nativeHttpsRequestAllowed } from './native-https-policy.mjs';
import { createCallbackMetadataCollector } from './callback-metadata.mjs';
import { createStrictNativeFixture } from './strict-native-fixture.mjs';

const opaque = () => randomBytes(32).toString('base64url');
const seeds = JSON.parse(readFileSync(new URL('../seed-statements.json', import.meta.url), 'utf8'));
const refused = port => new Promise(resolve => {
  const socket = connect({ host: '127.0.0.1', port }); let done = false;
  const finish = value => { if (!done) { done = true; socket.destroy(); resolve(value); } };
  socket.setTimeout(1000); socket.once('timeout', () => finish(false)); socket.once('connect', () => finish(false));
  socket.once('error', error => finish(error.code === 'ECONNREFUSED'));
});
const metadataOnly = headers => {
  const normalized = Object.fromEntries(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]));
  const cookieNames = new Set((normalized.cookie ?? '').split(';').map(part => part.trim().split('=', 1)[0]));
  return { site: normalized['sec-fetch-site'] ?? 'ABSENT', mode: normalized['sec-fetch-mode'] ?? 'ABSENT',
    dest: normalized['sec-fetch-dest'] ?? 'ABSENT', appCookiePresent: cookieNames.has(HTTPS_COOKIE_NAME),
    transactionCookiePresent: cookieNames.has(TRANSACTION_COOKIE_NAME) };
};

export async function runNativeHttpsProof({ chromium, executablePath, issuerFlow = 'IMMEDIATE_BOUNCE', composition = 'BFF_MODEL' } = {}) {
  if (!chromium || typeof chromium.launchPersistentContext !== 'function' || typeof executablePath !== 'string') throw new Error('Explicit installed full test browser required.');
  if (!['IMMEDIATE_BOUNCE', 'COMMITTED_ISSUER_DOCUMENT'].includes(issuerFlow)) throw new Error('Fixed synthetic issuer flow required.');
  if (!['BFF_MODEL', 'STRICT_SERVICE', 'STRICT_SERVICE_WARM_REVOKE'].includes(composition)) throw new Error('Fixed synthetic composition required.');
  const strict = composition !== 'BFF_MODEL'; const warmRevoke = composition === 'STRICT_SERVICE_WARM_REVOKE';
  const checks = []; const callbacks = []; const receivedCallbacks = []; const counters = { authentications: 0, registrations: 0, redemptions: 0, votes: 0, agree: 0, disagree: 0, pass: 0 };
  const result = { schemaVersion: 1, mode: 'SYNTHETIC_ONLY', classification: 'KEEP_CLOSED',
    check: 'NATIVE_BROWSER_HTTPS_WITH_DISPOSABLE_PROFILE_TRUST', issuerFlow, composition, browserNativeHttpsVerified: false,
    actualStrictServiceComposition: strict, actualInMemoryAccessAndActivationStores: strict, warmVoteRevocationVerified: false,
    crossSiteRedirectVerified: false, realBrowserEngineTested: false, realWordPress: false, realPolis: false,
    realIdentityProvider: false, realMailboxVerified: false, indigenousHeritageVerified: false, productionReady: false,
    certificateValidationDisabled: false, globalTrustChanged: false, personalBrowserProfileUsed: false,
    externalNetworkPermitted: false, dependenciesInstalled: false, noMetadataOrCookieFabrication: true,
    internalSchemaQaBootstrap: true, officialTrustProvisioningApi: false,
    browserClosed: false, profileRemoved: false, applicationClosed: false, issuerClosed: false, negativeTlsClosed: false,
    listenersIndependentlyRefused: false, checks, counters, callbackMetadata: callbacks, serverReceivedCallbackMetadata: receivedCallbacks };
  let stage = 'setup'; let lab; let negativeLab; let negativeServer; let negativeClosed = false; let app; let profile; let context; let browser; let timer; let launchAttempted = false; let collector;
  let strictFixture; let strictOrigins;
  let strictAccessVoteRequests = 0;
  const syncCounters = () => {
    if (!strictFixture) return;
    const current = strictFixture.counts();
    for (const key of ['authentications', 'registrations', 'votes', 'agree', 'disagree', 'pass']) counters[key] = current[key];
  };
  let callbackUrl; let registered = false; let approved = false; let redeemed = false; let nextIndex = 0;
  let authToken = opaque(); let participationToken = opaque(); const invitation = opaque();
  let pageErrors = 0; let unexpectedRequests = 0; let routingErrors = 0; let requestCount = 0; let negativeHttpRequests = 0; let lifetimeExpired = false;
  const record = (name, condition) => { assert.equal(Boolean(condition), true); checks.push({ name, result: 'PASS' }); };
  const denied = () => ({ status: 403, body: {} });
  const serverRequests = channel('http.server.request.start');
  const onServerRequest = ({ request }) => {
    if (lab && request.socket.localPort === lab.browserPort && request.headers.host === new URL(lab.browserTls.origin).host && request.url.startsWith('/oidc/callback?')) {
      receivedCallbacks.push(metadataOnly(request.headers));
    }
    if (strictOrigins && request.socket.localPort === Number(new URL(strictOrigins.access).port)
      && request.method === 'POST' && request.url === '/polis/votes') strictAccessVoteRequests++;
  };
  serverRequests.subscribe(onServerRequest);
  try {
    lab = issuerFlow === 'IMMEDIATE_BOUNCE' ? await createRedirectTlsLab()
      : await (await import('../identity-foundation/redirect-tls-lab.mjs')).createDocumentRedirectTlsLab();
    negativeLab = await createRedirectTlsLab();
    const driver = createHttpsRedirectDriver({ mode: 'SYNTHETIC_ONLY', identity: lab.identity,
      authorizationEndpoint: lab.authorizationEndpoint, callbackUri: lab.callbackUri });
    const next = () => nextIndex < seeds.length ? { tid: nextIndex, txt: seeds[nextIndex] } : null;
    const backend = {
      async authenticateIdentity(principal) {
        assert.equal(lab.identity.isVerifiedPrincipal(principal), true); counters.authentications++;
        authToken = opaque(); return { mode: 'SYNTHETIC_ONLY', assurance: 'OIDC_ID_TOKEN_VERIFIED', fixtureAuthToken: authToken };
      },
      async request(path, body, credential) {
        if (path === '/session/logout') {
          if (![authToken, participationToken].includes(credential)) return denied();
          authToken = opaque(); participationToken = opaque(); return { status: 200, body: {} };
        }
        if (path === '/invitations/redeem') {
          if (!registered || !approved || redeemed || credential !== authToken || body.invitationToken !== invitation) return denied();
          redeemed = true; counters.redemptions++; return { status: 200, body: { mode: 'SYNTHETIC_ONLY', participationToken } };
        }
        if (!redeemed || credential !== participationToken) return denied();
        if (path === '/polis/participation-init') return { status: 200, body: { nextComment: next() } };
        if (path === '/polis/next-comment') return { status: 200, body: next() };
        if (path !== '/polis/votes' || body.tid !== nextIndex || nextIndex >= seeds.length || ![-1, 0, 1].includes(body.vote)) return denied();
        counters.votes++; nextIndex++; counters[body.vote === -1 ? 'agree' : body.vote === 1 ? 'disagree' : 'pass']++;
        return { status: 200, body: { nextComment: next() } };
      },
    };
    if (strict) {
      strictFixture = await createStrictNativeFixture({ lab, seeds });
      app = strictFixture;
      strictOrigins = await strictFixture.start();
      record('strict service starts closed and activation alone leaves round closed', strictFixture.evidence().checks.length >= 2 && strictFixture.evidence().checks.every(check => check.result === 'PASS') && strictFixture.counts().providerCalls === 0);
    } else {
    app = createLocalBrowser({ mode: 'fixture-only', backend, oidcDriver: driver, httpsRedirect: lab.browserTls,
      registrationBridge: { mode: 'SYNTHETIC_ONLY', async register({ principal }) {
        assert.equal(lab.identity.isVerifiedPrincipal(principal), true); assert.equal(registered, false);
        registered = true; counters.registrations++;
        return { status: 'SUBMITTED_NOT_APPROVED', registrationId: randomUUID() };
      } } });
    await app.listen(lab.browserPort);
    }
    negativeServer = createServer({ key: negativeLab.browserTls.key, cert: negativeLab.browserTls.cert, minVersion: 'TLSv1.2' }, (_req, res) => {
      negativeHttpRequests++; res.writeHead(200); res.end('synthetic TLS negative');
    });
    await new Promise((resolve, reject) => { negativeServer.once('error', reject); negativeServer.listen(negativeLab.browserPort, '127.0.0.1', resolve); });
    profile = createDisposableChromeTrust({ mode: 'SYNTHETIC_ONLY', certificates: lab.publicTestCertificates() });
    const appOrigin = lab.browserTls.origin;
    const policy = { appOrigin, issuerOrigin: new URL(lab.authorizationEndpoint).origin,
      untrustedOrigin: negativeLab.browserTls.origin, wrongHostOrigin: `https://wrong.example.invalid:${lab.browserPort}` };
    launchAttempted = true;
    context = await chromium.launchPersistentContext(profile.profilePath, { headless: true, executablePath, timeout: 15000,
      serviceWorkers: 'block', acceptDownloads: false, ignoreHTTPSErrors: false, viewport: { width: 1280, height: 1000 },
      proxy: { server: 'http://127.0.0.1:9', bypass: 'browser.example.invalid,identity.issuer.invalid,wrong.example.invalid' },
      args: ['--host-resolver-rules=MAP browser.example.invalid 127.0.0.1, MAP identity.issuer.invalid 127.0.0.1, MAP wrong.example.invalid 127.0.0.1, MAP * ~NOTFOUND, EXCLUDE 127.0.0.1', '--disable-background-networking'] });
    browser = context.browser(); result.browserVersion = browser.version(); result.realBrowserEngineTested = true;
    record('full browser version matches test-only profile schema', result.browserVersion === '149.0.7827.55');
    timer = setTimeout(() => { lifetimeExpired = true; void context.close().catch(() => { routingErrors++; }); }, 120000); timer.unref();
    await context.routeWebSocket('**/*', async socket => { unexpectedRequests++; try { await socket.close(); } catch { routingErrors++; } });
    await context.route('**/*', async route => {
      try {
        const request = route.request(); requestCount++;
        if (requestCount > 120 || !nativeHttpsRequestAllowed(policy, request.url(), request.method())) { unexpectedRequests++; await route.abort('blockedbyclient'); return; }
        // No request/response/header/cookie override: real Chrome emits and checks them.
        await route.continue();
      } catch { routingErrors++; try { await route.abort('failed'); } catch { /* Already closing. */ } }
    });
    const page = context.pages()[0] ?? await context.newPage();
    page.setDefaultTimeout(12000); page.setDefaultNavigationTimeout(12000); page.on('pageerror', () => { pageErrors++; });
    // CDP ExtraInfo is the final on-wire browser header observation, not route's
    // earlier interception view. Pair each redirect leg, retaining no raw secrets.
    const cdp = await context.newCDPSession(page); collector = createCallbackMetadataCollector(appOrigin);
    const refreshCallbacks = () => {
      const snapshot = collector.observations(); callbacks.splice(0, callbacks.length, ...snapshot.callbacks);
      result.callbackEvidenceComplete = snapshot.complete;
      result.callbackEvidenceRejectedEvents = snapshot.rejectedEvents;
    };
    cdp.on('Network.requestWillBeSent', event => {
      const url = new URL(event.request.url); const callback = url.origin === appOrigin && url.pathname === '/oidc/callback';
      if (callback) callbackUrl = event.request.url;
      collector.request(event);
    });
    cdp.on('Network.requestWillBeSentExtraInfo', event => collector.extra(event));
    cdp.on('Network.responseReceived', event => collector.response(event));
    await cdp.send('Network.enable');
    stage = 'strict-tls-negatives';
    for (const [name, origin, expected] of [
      ['untrusted same-host certificate rejected by native verifier', policy.untrustedOrigin, 'net::ERR_CERT_AUTHORITY_INVALID'],
      ['wrong hostname rejected despite trusted certificate', policy.wrongHostOrigin, 'net::ERR_CERT_COMMON_NAME_INVALID'],
    ]) {
      let code = 'NONE';
      // Each rejected navigation owns its own tab; Chrome's asynchronous error
      // page must not race/interfere with the next positive navigation.
      const negativePage = await context.newPage(); negativePage.setDefaultNavigationTimeout(12000);
      try { await negativePage.goto(origin + '/'); } catch (error) { code = String(error?.message).match(/net::ERR_[A-Z_]+/u)?.[0] ?? 'OTHER'; }
      finally { await negativePage.close(); }
      record(name, code === expected);
    }
    record('untrusted TLS never reaches HTTP handler', negativeHttpRequests === 0);
    stage = 'initial-page-navigation';
    const response = await page.goto(appOrigin + '/');
    stage = 'initial-page-render';
    await page.locator('#oidc-start-form:not([hidden])').waitFor();
    stage = 'initial-page-security';
    const security = await response.securityDetails();
    record('trusted synthetic host loads over browser-native TLS', response.status() === 200 && /^TLS 1\.[23]$/u.test(security?.protocol ?? ''));
    result.browserNativeHttpsVerified = true; result.tlsProtocol = security.protocol;
    record('actual page rendered with no manual callback or registration', (await page.title()).includes('Local synthetic proof') &&
      await page.locator('#login-form').isHidden() && await page.locator('#oidc-callback-form').isHidden() && await page.locator('#registration-form').isHidden());
    const before = (await context.cookies(appOrigin)).find(cookie => cookie.name === HTTPS_COOKIE_NAME);
    record('native Secure HttpOnly Strict application cookie', before?.secure && before.httpOnly && before.sameSite === 'Strict' && before.path === '/');
    record('application cookie is not script readable', await page.evaluate(() => document.cookie === ''));
    stage = 'native-cross-site-login';
    await page.locator('#oidc-start-form button').click();
    if (issuerFlow === 'COMMITTED_ISSUER_DOCUMENT') {
      await page.locator('#continue-invented').waitFor();
      record('real invented issuer document commits before user continuation', new URL(page.url()).origin === policy.issuerOrigin && (await page.title()).includes('Invented'));
      await page.locator('#continue-invented').click();
    }
    await page.locator('#registration-form:not([hidden])').waitFor();
    syncCounters();
    refreshCallbacks();
    record('actual cross-site issuer redirect returns to clean URL', page.url() === appOrigin + '/' && counters.authentications === 1);
    record('native callback has cross-site top-level Fetch Metadata', callbacks[0]?.site === 'cross-site' && callbacks[0].mode === 'navigate' && callbacks[0].dest === 'document');
    record('final browser metadata matches independent receiving-server observation', result.callbackEvidenceComplete && callbacks.length === 1 && receivedCallbacks.length === 1 && JSON.stringify(callbacks) === JSON.stringify(receivedCallbacks));
    // Chromium149's default immediate-bounce behavior includes Strict cookies
    // when the navigation initiator is still the app. A committed issuer page
    // changes that initiator. Neither case may rely on Strict for callback auth.
    record(issuerFlow === 'IMMEDIATE_BOUNCE' ? 'immediate bounce sends Lax transaction and observed Strict application cookie'
      : 'committed cross-site document sends Lax transaction and withholds Strict application cookie',
    callbacks[0]?.transactionCookiePresent && callbacks[0].appCookiePresent === (issuerFlow === 'IMMEDIATE_BOUNCE'));
    const after = await context.cookies(appOrigin); const authenticated = after.find(cookie => cookie.name === HTTPS_COOKIE_NAME);
    record('authenticated cookie rotates with all secure attributes', authenticated?.value !== before.value && authenticated?.secure && authenticated.httpOnly && authenticated.sameSite === 'Strict');
    record('one-use transaction cookie cleared', !after.some(cookie => cookie.name === TRANSACTION_COOKIE_NAME));
    result.crossSiteRedirectVerified = true;
    stage = 'registration';
    record('no automatic registration or invitation', counters.registrations === 0 && await page.locator('#invite-form').isHidden());
    record('all three declarations initially unchecked', !(await page.locator('#registration-adult').isChecked()) && !(await page.locator('#registration-eligibility').isChecked()) && !(await page.locator('#registration-consent').isChecked()));
    await page.locator('#registration-form button').click(); record('browser required fields prevent incomplete submission', counters.registrations === 0);
    for (const id of ['registration-adult', 'registration-eligibility', 'registration-consent']) await page.locator('#' + id).check();
    await page.locator('#registration-form button').click(); await page.locator('#registration-result:not([hidden])').waitFor();
    syncCounters();
    record('one registration remains explicitly unapproved', counters.registrations === 1 && (strict ? strictFixture.counts().providerCalls === 0 : !approved) && (await page.locator('#registration-result-title').textContent()).includes('not approved'));
    if (strict) {
      stage = 'strict-signed-approval-closed-round';
      record('native registration reaches real signed receipt bridge without provider access', strictFixture.counts().providerCalls === 0);
      const beforeApprovalChecks = strictFixture.evidence().checks.length;
      await strictFixture.approve();
      record('signed approval and replay controls cannot open the closed round', strictFixture.evidence().checks.length > beforeApprovalChecks && strictFixture.evidence().checks.every(check => check.result === 'PASS') && strictFixture.counts().participationCalls === 0 && strictFixture.counts().votes === 0);
      stage = 'strict-invitation';
      const issued = await strictFixture.openAndIssue();
      await page.locator('#show-invitation').click();
      await page.locator('#invitation').fill(opaque());
      const invalidReply = page.waitForResponse(response => response.url() === appOrigin + '/api/redeem' && response.request().method() === 'POST');
      await page.locator('#invite-form button').click();
      record('invented unrelated token cannot redeem a real strict invitation', [401, 403].includes((await invalidReply).status()) && strictFixture.counts().votes === 0);
      await page.locator('#status.error').waitFor();
      await page.locator('#invitation').fill(issued.invitationToken);
      await page.locator('#invite-form button').click(); await page.locator('#vote-panel:not([hidden])').waitFor();
      counters.redemptions++;
      record('actual strict invitation admits the authenticated account and clears input', strictFixture.counts().activeAllowlistEntries === 1 && await page.locator('#invitation').inputValue() === '');
    } else {
    stage = 'model-approval-invitation';
    await page.locator('#show-invitation').click(); await page.locator('#invitation').fill(invitation); await page.locator('#invite-form button').click();
    await page.locator('#status.error').waitFor(); record('valid invitation cannot bypass separate model approval', counters.redemptions === 0 && await page.locator('#vote-panel').isHidden());
    approved = true; // Explicit in-memory test fixture decision only, never an admin HTTP route.
    await page.locator('#invitation').fill(invitation); await page.locator('#invite-form button').click(); await page.locator('#vote-panel:not([hidden])').waitFor();
    record('bound model invitation redeemed once and input cleared', counters.redemptions === 1 && await page.locator('#invitation').inputValue() === '');
    }
    stage = strict ? 'strict-service-model-provider-votes' : 'model-votes';
    assert.equal(seeds.length, 15);
    for (let index = 0; index < (warmRevoke ? 1 : 15); index++) {
      await page.waitForFunction(text => document.getElementById('statement')?.textContent === text && !document.querySelector('[data-vote="0"]').disabled, seeds[index]);
      await page.locator(`[data-vote="${[-1, 1, 0][index % 3]}"]`).click();
    }
    if (warmRevoke) {
      stage = 'strict-warm-vote-revocation';
      await page.waitForFunction(text => document.getElementById('statement')?.textContent === text && !document.querySelector('[data-vote="0"]').disabled, seeds[1]);
      syncCounters(); record('warm revocation starts with a displayed unvoted statement', counters.votes === 1);
      await strictFixture.revoke(); const beforeDeniedVote = strictFixture.counts(); const beforeAccessVotes = strictAccessVoteRequests;
      const deniedReply = page.waitForResponse(response => response.url() === appOrigin + '/api/votes' && response.request().method() === 'POST');
      await page.locator('[data-vote="1"]').click();
      const deniedStatus = (await deniedReply).status();
      await page.locator('#status.error').waitFor(); syncCounters();
      record('signed revocation denies an already displayed warm vote at strict access before provider dispatch', [401, 403].includes(deniedStatus) && counters.votes === 1 && beforeAccessVotes === 1 && strictAccessVoteRequests === beforeAccessVotes + 1 && strictFixture.counts().providerCalls === beforeDeniedVote.providerCalls && strictFixture.counts().activeAllowlistEntries === 0);
      result.warmVoteRevocationVerified = true;
    } else {
    await page.locator('#complete:not([hidden])').waitFor();
    syncCounters();
    record('15 fixed model statements record 5 Agree 5 Disagree 5 Pass', counters.votes === 15 && counters.agree === 5 && counters.disagree === 5 && counters.pass === 5);
    if (strict) {
      await strictFixture.revoke(); syncCounters();
      record('completed strict journey is terminally revoked with no additional vote', counters.votes === 15 && strictFixture.counts().approvedAccounts === 0 && strictFixture.counts().activeAllowlistEntries === 0 && strictFixture.counts().participationAfterRevocation === 0);
    }
    }
    stage = 'logout-replay';
    if (!warmRevoke) await page.locator('#logout').click();
    await page.locator('#oidc-start-form:not([hidden])').waitFor();
    await page.reload(); await page.locator('#oidc-start-form:not([hidden])').waitFor();
    record('logout and reload do not revive account', counters.authentications === 1 && await page.locator('#registration-form').isHidden());
    assert.equal(typeof callbackUrl, 'string'); const replay = callbackUrl;
    await page.goto(replay); await page.locator('#oidc-start-form:not([hidden])').waitFor();
    record('spent callback replay stays logged out and returns clean', counters.authentications === 1 && page.url() === appOrigin + '/' && await page.locator('#registration-form').isHidden());
    record('application cookie alone cannot authorize a spent callback', receivedCallbacks[1]?.appCookiePresent && !receivedCallbacks[1]?.transactionCookiePresent && counters.authentications === 1);
    if (issuerFlow === 'COMMITTED_ISSUER_DOCUMENT') {
      stage = 'cancel-before-issuer-return';
      await page.locator('#oidc-start-form button').click(); await page.locator('#continue-invented').waitFor();
      const cancellationPage = await context.newPage(); cancellationPage.setDefaultTimeout(12000);
      try {
        await cancellationPage.goto(appOrigin + '/'); await cancellationPage.locator('#logout:not([hidden])').waitFor();
        record('separate application tab exposes explicit pending-login cancellation', (await cancellationPage.locator('#logout').textContent()).includes('Cancel synthetic sign-in'));
        await cancellationPage.locator('#logout').click(); await cancellationPage.locator('#oidc-start-form:not([hidden])').waitFor();
        record('native cancellation clears transaction cookie', !(await context.cookies(appOrigin)).some(cookie => cookie.name === TRANSACTION_COOKIE_NAME));
      } finally { await cancellationPage.close(); }
      await page.locator('#continue-invented').click(); await page.locator('#oidc-start-form:not([hidden])').waitFor();
      record('late issuer return after cancellation cannot authenticate or register', page.url() === appOrigin + '/' && counters.authentications === 1 && counters.registrations === 1 &&
        await page.locator('#registration-form').isHidden() && lab.summary().token === 1);
    }
    refreshCallbacks();
    record('all final callback observations agree independently', result.callbackEvidenceComplete && JSON.stringify(callbacks) === JSON.stringify(receivedCallbacks));
    record('no page storage or script-readable cookie', await page.evaluate(() => !localStorage.length && !sessionStorage.length && document.cookie === ''));
    record('no script errors or unexpected network destinations', pageErrors === 0 && unexpectedRequests === 0);
    result.outcome = 'PASS';
  } catch (error) {
    result.outcome = 'FAIL'; result.failedStage = stage;
    result.failureKind = error?.name === 'TimeoutError' ? 'TIMEOUT' : error?.code === 'ERR_ASSERTION' ? 'ASSERTION' : 'SETUP_OR_TRANSPORT';
    result.networkFailureCode = String(error?.message).match(/net::ERR_[A-Z_]+/u)?.[0] ?? 'NONE';
    result.failureClass = ['Error', 'TypeError', 'TimeoutError', 'AssertionError'].includes(error?.name) ? error.name : 'OTHER';
    result.navigationDownloadStarted = String(error?.message).includes('Download is starting');
  } finally {
    clearTimeout(timer);
    serverRequests.unsubscribe(onServerRequest);
    try { if (context) { await context.close(); result.browserClosed = !browser?.isConnected(); } } catch { /* Separate browser termination below. */ }
    try { if (browser?.isConnected()) { await browser.close(); result.browserClosed = !browser.isConnected(); } } catch { result.browserClosed = false; }
    try { if (app) { await app.close(); result.applicationClosed = true; } } catch { result.applicationClosed = false; }
    try { if (negativeServer) { negativeServer.closeAllConnections(); await new Promise((resolve, reject) => negativeServer.close(error => error ? reject(error) : resolve())); negativeClosed = true; } } catch { negativeClosed = false; }
    try { if (lab) { await lab.close(); result.issuerClosed = true; } } catch { result.issuerClosed = false; }
    try { if (negativeLab) { await negativeLab.close(); result.negativeTlsClosed = negativeClosed; } } catch { result.negativeTlsClosed = false; }
    const ports = [lab?.browserPort, lab && Number(new URL(lab.authorizationEndpoint).port), negativeLab?.browserPort, negativeLab && Number(new URL(negativeLab.authorizationEndpoint).port),
      ...(strictOrigins ? [Number(new URL(strictOrigins.access).port), Number(new URL(strictOrigins.receiver).port)] : [])].filter(Number.isInteger);
    result.listenerCount = ports.length;
    result.listenersIndependentlyRefused = ports.length === (strict ? 6 : 4) && (await Promise.all(ports.map(refused))).every(Boolean);
    try { if (profile && (result.browserClosed || !launchAttempted)) { profile.cleanup({ browserClosed: true }); result.profileRemoved = profile.summary().cleaned; } } catch { result.profileRemoved = false; }
    if (profile && !result.profileRemoved) result.ownedProfileCleanupRequired = profile.profilePath;
    if (collector) {
      const snapshot = collector.observations(); callbacks.splice(0, callbacks.length, ...snapshot.callbacks);
      result.callbackEvidenceComplete = snapshot.complete; result.callbackEvidenceRejectedEvents = snapshot.rejectedEvents;
    }
    if (strictFixture) {
      syncCounters(); result.strictServiceEvidence = strictFixture.evidence(); result.strictServiceCounts = strictFixture.counts(); result.strictAccessVoteRequests = strictAccessVoteRequests;
      result.strictServiceLifecycle = strictFixture.snapshot();
      if (result.strictServiceLifecycle.state !== 'CLOSED') result.outcome = 'FAIL';
    }
    if (lifetimeExpired || routingErrors || pageErrors || unexpectedRequests || requestCount > 120 || ![result.browserClosed, result.profileRemoved, result.applicationClosed, result.issuerClosed, result.negativeTlsClosed, result.listenersIndependentlyRefused].every(Boolean)) result.outcome = 'FAIL';
  }
  return { ...result, passedChecks: checks.length, pageErrors, unexpectedRequests, routingErrors, requestCount, lifetimeExpired, negativeHttpRequests,
    profileTrust: profile?.summary(), serverToServerTls: lab?.summary() };
}
