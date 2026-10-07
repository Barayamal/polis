/** OPT-IN TEST ONLY. Two fixed invented accounts in separate fresh Chrome149
 * profiles, actual TLS and strict local service; WordPress/Pol.is remain models.
 * No global trust, real accounts, external sends, retained data or runtime defaults.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { connect } from 'node:net';
import { channel } from 'node:diagnostics_channel';
import { createTwoAccountDocumentRedirectTlsLab } from '../identity-foundation/redirect-tls-lab.mjs';
import { createTwoAccountStrictNativeFixture } from './strict-native-fixture.mjs';
import { createDisposableChromeTrust } from './disposable-chrome-trust.mjs';
import { nativeCrossAccountRequestAllowed } from './native-https-policy.mjs';
import { createCallbackMetadataCollector } from './callback-metadata.mjs';
import { HTTPS_COOKIE_NAME, TRANSACTION_COOKIE_NAME } from '../local-browser/browser-server.mjs';

const seeds = JSON.parse(readFileSync(new URL('../seed-statements.json', import.meta.url), 'utf8'));
const refused = port => new Promise(resolve => {
  const socket = connect({ host: '127.0.0.1', port }); let done = false;
  const finish = value => { if (!done) { done = true; socket.destroy(); resolve(value); } };
  socket.setTimeout(1000); socket.once('timeout', () => finish(false)); socket.once('connect', () => finish(false));
  socket.once('error', error => finish(error.code === 'ECONNREFUSED'));
});
const metadata = headers => {
  const cookies = new Set((headers.cookie ?? '').split(';').map(part => part.trim().split('=', 1)[0]));
  return { site: headers['sec-fetch-site'] ?? 'ABSENT', mode: headers['sec-fetch-mode'] ?? 'ABSENT',
    dest: headers['sec-fetch-dest'] ?? 'ABSENT', appCookiePresent: cookies.has(HTTPS_COOKIE_NAME),
    transactionCookiePresent: cookies.has(TRANSACTION_COOKIE_NAME) };
};

export async function runNativeCrossAccountProof(options) {
  if (!options || Object.getPrototypeOf(options) !== Object.prototype || Reflect.ownKeys(options).length !== 2
    || !Object.hasOwn(options, 'chromium') || !Object.hasOwn(options, 'executablePath')
    || Object.values(Object.getOwnPropertyDescriptors(options)).some(item => !Object.hasOwn(item, 'value')))
    throw new Error('Explicit fixed local browser dependencies required.');
  const { chromium, executablePath } = options;
  if (!chromium || typeof chromium.launchPersistentContext !== 'function' || typeof executablePath !== 'string')
    throw new Error('Explicit fixed local browser dependencies required.');
  const result = { schemaVersion: 1, check: 'TWO_APPROVED_ACCOUNTS_NATIVE_HTTPS_INVITATION_BINDING', mode: 'SYNTHETIC_ONLY',
    classification: 'KEEP_CLOSED', realWordPress: false, realPolis: false, realIdentityProvider: false,
    realMailboxVerified: false, indigenousHeritageVerified: false, productionReady: false,
    globalTrustChanged: false, certificateValidationDisabled: false, personalProfileUsed: false,
    realBrowserEngineTested: false, browserNativeHttpsVerified: false,
    externalMessageSent: false, externalNetworkPermitted: false, runtimeAccessRulesChanged: false,
    twoApprovedAccountsVerified: false, reciprocalForwardingDenied: false, rightfulTokensNotBurned: false,
    independentWarmRevocationVerified: false, browserClosed: false, profilesRemoved: false,
    listenersIndependentlyRefused: false, checks: [] };
  const record = (name, condition) => { assert.equal(Boolean(condition), true, name); result.checks.push({ name, result: 'PASS' }); };
  let lab; let fixture; let origins; let timer; let stage = 'setup';
  let pageErrors = 0; let requestCount = 0; let unexpectedRequests = 0; let routingErrors = 0; let lifetimeExpired = false;
  const entries = []; const receivedCallbacks = [];
  const accessRequests = { redeem: 0, vote: 0 };
  const serverRequests = channel('http.server.request.start');
  const observe = ({ request }) => {
    if (origins && request.socket.localPort === Number(new URL(origins.access).port) && request.method === 'POST') {
      if (request.url === '/invitations/redeem') accessRequests.redeem++;
      if (request.url === '/polis/votes') accessRequests.vote++;
    }
    if (lab && request.socket.localPort === lab.browserPort && request.headers.host === new URL(lab.browserTls.origin).host
      && request.url.startsWith('/oidc/callback?')) receivedCallbacks.push(metadata(request.headers));
  };
  serverRequests.subscribe(observe);
  try {
    lab = await createTwoAccountDocumentRedirectTlsLab(); fixture = await createTwoAccountStrictNativeFixture({ lab, seeds });
    origins = await fixture.start();
    const appOrigin = lab.browserTls.origin; const issuerOrigin = new URL(lab.authorizationEndpoint).origin;
    record('actual strict service starts closed before two-account sign-in', fixture.counts().providerCalls === 0 && fixture.evidence().checks.length >= 3);
    timer = setTimeout(() => { lifetimeExpired = true; for (const entry of entries) void entry.context?.close().catch(() => { routingErrors++; }); }, 120000); timer.unref();
    for (let index = 0; index < 2; index++) {
      stage = 'fresh-profile-' + (index + 1);
      const entry = { profile: createDisposableChromeTrust({ mode: 'SYNTHETIC_ONLY', certificates: lab.publicTestCertificates() }),
        launched: false, browserClosed: false, profileRemoved: false };
      entries.push(entry); entry.launched = true;
      entry.context = await chromium.launchPersistentContext(entry.profile.profilePath, { headless: true, executablePath,
        timeout: 15000, serviceWorkers: 'block', acceptDownloads: false, ignoreHTTPSErrors: false,
        proxy: { server: 'http://127.0.0.1:9', bypass: 'browser.example.invalid,identity.issuer.invalid' },
        args: ['--host-resolver-rules=MAP browser.example.invalid 127.0.0.1, MAP identity.issuer.invalid 127.0.0.1, MAP * ~NOTFOUND, EXCLUDE 127.0.0.1', '--disable-background-networking'] });
      entry.browser = entry.context.browser();
      result.realBrowserEngineTested = true; entry.browserVersion = entry.browser.version();
      record('account ' + (index + 1) + ' uses pinned full Chrome in a new profile', entry.browserVersion === '149.0.7827.55');
      await entry.context.routeWebSocket('**/*', async socket => { unexpectedRequests++; try { await socket.close(); } catch { routingErrors++; } });
      await entry.context.route('**/*', async route => {
        try {
          const request = route.request(); requestCount++;
          if (requestCount > 160 || !nativeCrossAccountRequestAllowed({ appOrigin, issuerOrigin }, request.url(), request.method())) {
            unexpectedRequests++; await route.abort('blockedbyclient'); return;
          }
          await route.continue(); // No request/body/header/cookie/response fabrication.
        } catch { routingErrors++; try { await route.abort('failed'); } catch { /* Already closing. */ } }
      });
      entry.page = entry.context.pages()[0] ?? await entry.context.newPage();
      entry.page.setDefaultTimeout(12000); entry.page.setDefaultNavigationTimeout(12000); entry.page.on('pageerror', () => { pageErrors++; });
      entry.collector = createCallbackMetadataCollector(appOrigin);
      const cdp = await entry.context.newCDPSession(entry.page);
      cdp.on('Network.requestWillBeSent', event => entry.collector.request(event));
      cdp.on('Network.requestWillBeSentExtraInfo', event => entry.collector.extra(event));
      cdp.on('Network.responseReceived', event => entry.collector.response(event));
      await cdp.send('Network.enable');
      const response = await entry.page.goto(appOrigin + '/');
      await entry.page.locator('#oidc-start-form:not([hidden])').waitFor();
      record('account ' + (index + 1) + ' starts separately unauthenticated over native TLS', response.status() === 200 &&
        /^TLS 1\.[23]$/u.test((await response.securityDetails())?.protocol ?? '') && await entry.page.locator('#registration-form').isHidden());
      await entry.page.locator('#oidc-start-form button').click(); await entry.page.locator('#continue-invented').waitFor();
      record('account ' + (index + 1) + ' commits the actual invented issuer document', new URL(entry.page.url()).origin === issuerOrigin);
      await entry.page.locator('#continue-invented').click(); await entry.page.locator('#registration-form:not([hidden])').waitFor();
      record('account ' + (index + 1) + ' signs in through a clean callback', entry.page.url() === appOrigin + '/' && fixture.counts().authentications === index + 1);
      const cookie = (await entry.context.cookies(appOrigin)).find(item => item.name === HTTPS_COOKIE_NAME);
      record('account ' + (index + 1) + ' has secure non-script-readable session state', cookie?.secure && cookie.httpOnly && cookie.sameSite === 'Strict'
        && await entry.page.evaluate(() => document.cookie === '' && localStorage.length === 0 && sessionStorage.length === 0));
      for (const id of ['registration-adult', 'registration-eligibility', 'registration-consent']) await entry.page.locator('#' + id).check();
      await entry.page.locator('#registration-form button').click(); await entry.page.locator('#registration-result:not([hidden])').waitFor();
      record('account ' + (index + 1) + ' registers separately without approval', fixture.counts().registrations === index + 1
        && fixture.counts().approvedAccounts === 0 && fixture.counts().providerCalls === 0
        && (await entry.page.locator('#registration-result-title').textContent()).includes('not approved'));
    }
    stage = 'both-approved-round-open';
    result.browserNativeHttpsVerified = true;
    record('two distinct verified accounts use two isolated profiles', fixture.counts().distinctVerifiedAccounts === 2 &&
      entries[0].profile.profilePath !== entries[1].profile.profilePath && lab.summary().authorize === 2 && lab.summary().token === 2);
    await fixture.approve();
    record('both accounts approved with independent provider readbacks and no participation', fixture.counts().approvedAccounts === 2 &&
      fixture.counts().activeAllowlistEntries === 2 && fixture.counts().participationCalls === 0 && fixture.counts().providerCalls === 4);
    result.twoApprovedAccountsVerified = true;
    const { invitations } = await fixture.openAndIssue();
    assert.equal(invitations.length, 2); assert.notEqual(invitations[0].invitationToken, invitations[1].invitationToken);
    record('both invitations stay local and require separate round opening', invitations.every(item => item.delivery === 'LOCAL_RESPONSE_ONLY_NO_EMAIL_OR_MESSAGE'));
    const redeem = async (entry, token) => {
      await entry.page.locator('#invitation').fill(token);
      const response = entry.page.waitForResponse(reply => reply.url() === appOrigin + '/api/redeem' && reply.request().method() === 'POST');
      await entry.page.locator('#invite-form button').click(); return (await response).status();
    };
    for (const entry of entries) await entry.page.locator('#show-invitation').click();
    stage = 'reciprocal-valid-token-forwarding';
    for (let index = 0; index < 2; index++) {
      const before = accessRequests.redeem; const calls = fixture.counts().providerCalls;
      const status = await redeem(entries[index], invitations[1 - index].invitationToken);
      await entries[index].page.locator('#status.error').waitFor();
      record('approved account ' + (index + 1) + ' cannot redeem the other valid invitation at the strict backend', status === 403
        && accessRequests.redeem === before + 1 && fixture.counts().providerCalls === calls && fixture.counts().participationCalls === 0
        && await entries[index].page.locator('#vote-panel').isHidden());
    }
    result.reciprocalForwardingDenied = true;
    stage = 'rightful-invitations-survive';
    for (let index = 0; index < 2; index++) {
      const before = accessRequests.redeem;
      record('rightful account ' + (index + 1) + ' redeems its unchanged invitation after forwarding denial',
        await redeem(entries[index], invitations[index].invitationToken) === 200 && accessRequests.redeem === before + 1);
      await entries[index].page.locator('#vote-panel:not([hidden])').waitFor();
      await entries[index].page.waitForFunction(text => document.getElementById('statement')?.textContent === text &&
        !document.querySelector('[data-vote="0"]').disabled, seeds[0]);
      record('rightful account ' + (index + 1) + ' begins its own statement sequence and clears invitation',
        await entries[index].page.locator('#invitation').inputValue() === '');
      await entries[index].page.locator('[data-vote="-1"]').click();
      await entries[index].page.waitForFunction(text => document.getElementById('statement')?.textContent === text &&
        !document.querySelector('[data-vote="0"]').disabled, seeds[1]);
    }
    record('separate accounts each cast their own first model vote', fixture.counts().votes === 2 && fixture.counts().agree === 2 && accessRequests.vote === 2);
    result.rightfulTokensNotBurned = true;
    stage = 'both-warm-sessions-revoked';
    await fixture.revoke(); const beforeDenied = fixture.counts();
    for (let index = 0; index < 2; index++) {
      const before = accessRequests.vote;
      const response = entries[index].page.waitForResponse(reply => reply.url() === appOrigin + '/api/votes' && reply.request().method() === 'POST');
      await entries[index].page.locator('[data-vote="1"]').click(); const status = (await response).status();
      await entries[index].page.locator('#oidc-start-form:not([hidden])').waitFor();
      record('revoked account ' + (index + 1) + ' has its displayed warm vote denied at strict access', [401, 403].includes(status)
        && accessRequests.vote === before + 1 && fixture.counts().providerCalls === beforeDenied.providerCalls
        && fixture.counts().votes === 2 && fixture.counts().activeAllowlistEntries === 0);
      await entries[index].page.reload(); await entries[index].page.locator('#oidc-start-form:not([hidden])').waitFor();
      record('revoked account ' + (index + 1) + ' cannot revive a session by reload', await entries[index].page.locator('#vote-panel').isHidden());
    }
    result.independentWarmRevocationVerified = true;
    const callbacks = entries.flatMap(entry => entry.collector.observations().callbacks);
    record('both native callback collectors match independent receiving-server metadata', entries.every(entry => entry.collector.observations().complete)
      && callbacks.length === 2 && JSON.stringify(callbacks) === JSON.stringify(receivedCallbacks));
    record('both committed cross-site callbacks use only their transaction cookie', callbacks.every(item => item.site === 'cross-site'
      && item.mode === 'navigate' && item.dest === 'document' && !item.appCookiePresent && item.transactionCookiePresent));
    result.callbackMetadata = callbacks; result.receivingServerCallbackMetadata = receivedCallbacks;
    record('no page errors or unexpected browser destination', pageErrors === 0 && unexpectedRequests === 0 && requestCount <= 160);
    result.outcome = 'PASS';
  } catch (error) {
    result.outcome = 'FAIL'; result.failedStage = stage;
    result.failureKind = error?.name === 'TimeoutError' ? 'TIMEOUT' : error?.code === 'ERR_ASSERTION' ? 'ASSERTION' : 'SETUP_OR_TRANSPORT';
    result.networkFailureCode = String(error?.message).match(/net::ERR_[A-Z_]+/u)?.[0] ?? 'NONE';
  } finally {
    clearTimeout(timer); serverRequests.unsubscribe(observe);
    for (const entry of entries) {
      try { if (entry.context) { await entry.context.close(); entry.browserClosed = !entry.browser?.isConnected(); } } catch { /* Retry owned process closure below. */ }
      try { if (entry.browser?.isConnected()) { await entry.browser.close(); entry.browserClosed = !entry.browser.isConnected(); } } catch { entry.browserClosed = false; }
      try { if (entry.browserClosed || !entry.launched) { entry.profile.cleanup({ browserClosed: true }); entry.profileRemoved = entry.profile.summary().cleaned; } } catch { entry.profileRemoved = false; }
    }
    try { if (fixture) await fixture.close(); } catch { result.outcome = 'FAIL'; }
    try { if (lab) await lab.close(); } catch { result.outcome = 'FAIL'; }
    const ports = origins ? [...Object.values(origins).map(origin => Number(new URL(origin).port)), Number(new URL(lab.authorizationEndpoint).port)] : [];
    result.listenerCount = ports.length; result.listenersIndependentlyRefused = ports.length === 4 && (await Promise.all(ports.map(refused))).every(Boolean);
    result.browserClosed = entries.length === 2 && entries.every(entry => entry.browserClosed);
    result.profilesRemoved = entries.length === 2 && entries.every(entry => entry.profileRemoved);
    result.profileCount = entries.length;
    result.browserVersions = entries.map(entry => entry.browserVersion ?? 'UNCONFIRMED');
    const pending = entries.filter(entry => !entry.profileRemoved).map(entry => entry.profile.profilePath);
    if (pending.length) result.ownedProfileCleanupRequired = pending;
    result.strictServiceLifecycle = fixture?.snapshot(); result.strictServiceEvidence = fixture?.evidence(); result.strictServiceCounts = fixture?.counts();
    result.accessRequestCounts = accessRequests; result.issuerSummary = lab?.summary();
    if (lifetimeExpired || routingErrors || pageErrors || unexpectedRequests || requestCount > 160 || !result.browserClosed || !result.profilesRemoved || !result.listenersIndependentlyRefused
      || result.strictServiceLifecycle?.state !== 'CLOSED' || result.issuerSummary?.listenersClosed !== true) result.outcome = 'FAIL';
  }
  return { ...result, passedChecks: result.checks.length, pageErrors, requestCount, unexpectedRequests, routingErrors, lifetimeExpired };
}
