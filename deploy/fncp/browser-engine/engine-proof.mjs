/** OPT-IN TEST SUPPORT. Actual isolated browser engine over an intercepted
 * local-TLS transport. Not browser-native TLS, production login or real data.
 * No dependency download, global trust edit, personal profile or persistent browser.
 */
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createLocalBrowser, HTTPS_COOKIE_NAME, TRANSACTION_COOKIE_NAME } from '../local-browser/browser-server.mjs';
import { createRedirectTlsLab } from '../identity-foundation/redirect-tls-lab.mjs';
import { createHttpsRedirectDriver } from '../identity-foundation/https-redirect-driver.mjs';

const opaque = () => randomBytes(32).toString('base64url');
const seeds = JSON.parse(readFileSync(new URL('../seed-statements.json', import.meta.url), 'utf8'));
const metadataOnly = headers => ({ site: headers['sec-fetch-site'] ?? 'ABSENT',
  mode: headers['sec-fetch-mode'] ?? 'ABSENT', dest: headers['sec-fetch-dest'] ?? 'ABSENT',
  appCookiePresent: (headers.cookie ?? '').includes(HTTPS_COOKIE_NAME + '='),
  transactionCookiePresent: (headers.cookie ?? '').includes(TRANSACTION_COOKIE_NAME + '=') });

export async function runBrowserEngineProof({ chromium, executablePath, screenshotPath } = {}) {
  if (!chromium || typeof chromium.launch !== 'function' || typeof executablePath !== 'string') throw new Error('Explicit installed test browser required.');
  const checks = []; const requests = []; let stage = 'setup'; let lab; let app; let browser; let context;
  const result = { schemaVersion: 1, classification: 'KEEP_CLOSED', mode: 'SYNTHETIC_ONLY',
    check: 'ISOLATED_BROWSER_ENGINE_WITH_INTERCEPTED_VERIFIED_LOCAL_TLS',
    realBrowserEngineTested: false, browserNativeTlsVerified: false, networkInterception: true,
    externalNetworkPermitted: false, realIdentityProvider: false, realMailboxVerified: false,
    indigenousHeritageVerified: false, realWordPressOrPolis: false, productionReady: false,
    personalBrowserProfileUsed: false, globalTrustChanged: false, certificateValidationDisabled: false,
    dependenciesInstalled: false, checks, browserClosed: false, appClosed: false, issuerClosed: false };
  let authCalls = 0; let registrationCalls = 0; let votes = 0; let pageErrors = 0; let blocked = 0;
  let callbackUrl; let callbackHeader; let savedAppCookie; let authorized = false; let registered = false;
  let authToken = opaque(); let participationToken = opaque(); const invitationToken = opaque();
  const record = (name, condition) => { assert.equal(Boolean(condition), true, 'Synthetic browser check failed.'); checks.push({ name, result: 'PASS' }); };
  try {
    lab = await createRedirectTlsLab();
    const driver = createHttpsRedirectDriver({ mode: 'SYNTHETIC_ONLY', identity: lab.identity,
      authorizationEndpoint: lab.authorizationEndpoint, callbackUri: lab.callbackUri });
    const backend = {
      async authenticateIdentity(principal) {
        assert.equal(lab.identity.isVerifiedPrincipal(principal), true); authCalls++;
        authToken = opaque(); return { mode: 'SYNTHETIC_ONLY', assurance: 'OIDC_ID_TOKEN_VERIFIED', fixtureAuthToken: authToken };
      },
      async request(path, body, credential) {
        if (path === '/session/logout') { authToken = opaque(); participationToken = opaque(); return { status: 200, body: {} }; }
        if (path === '/invitations/redeem') {
          if (!authorized || credential !== authToken || body.invitationToken !== invitationToken) return { status: 403, body: {} };
          authorized = false; return { status: 200, body: { mode: 'SYNTHETIC_ONLY', participationToken } };
        }
        if (credential !== participationToken) return { status: 403, body: {} };
        if (path === '/polis/participation-init') return { status: 200, body: { nextComment: { tid: 0, txt: seeds[0] } } };
        if (path === '/polis/next-comment') return { status: 200, body: { tid: 0, txt: seeds[0] } };
        if (path === '/polis/votes') { votes++; return { status: 200, body: { nextComment: null } }; }
        return { status: 403, body: {} };
      },
    };
    app = createLocalBrowser({ mode: 'fixture-only', backend, oidcDriver: driver, httpsRedirect: lab.browserTls,
      registrationBridge: { mode: 'SYNTHETIC_ONLY', async register({ principal }) {
        assert.equal(lab.identity.isVerifiedPrincipal(principal), true); registrationCalls++; registered = true;
        return { status: 'SUBMITTED_NOT_APPROVED', registrationId: randomUUID() };
      } } });
    await app.listen(lab.browserPort);
    browser = await chromium.launch({ headless: true, executablePath,
      // Even if interception accidentally misses a URL, no direct DNS/HTTP
      // fallback is usable. These flags affect only this fresh headless process.
      proxy: { server: 'http://127.0.0.1:9', bypass: '' },
      args: ['--host-resolver-rules=MAP * ~NOTFOUND', '--disable-background-networking'] });
    result.browserVersion = browser.version(); result.realBrowserEngineTested = true;
    context = await browser.newContext({ serviceWorkers: 'block', acceptDownloads: false,
      ignoreHTTPSErrors: false, viewport: { width: 1280, height: 1000 } });
    const appOrigin = lab.browserTls.origin; const issuerOrigin = new URL(lab.authorizationEndpoint).origin;
    await context.route('**/*', async route => {
      try {
        const request = route.request(); const url = new URL(request.url());
        if (![appOrigin, issuerOrigin].includes(url.origin)) { blocked++; await route.abort('blockedbyclient'); return; }
        if (url.origin === appOrigin && url.pathname === '/favicon.ico') { await route.fulfill({ status: 204, body: '' }); return; }
        const headers = await request.allHeaders();
        const observed = { endpoint: url.pathname, method: request.method(), ...metadataOnly(headers) };
        if (requests.length >= 100) { blocked++; await route.abort('blockedbyclient'); return; }
        requests.push(observed);
        if (url.pathname === '/oidc/callback') { callbackUrl = request.url(); callbackHeader = observed; }
        // Preserve browser-originated Cookie, Fetch Metadata and CSRF exactly.
        // Strip transport framing only; Node generates fixed Host/body length.
        for (const key of ['host', 'connection', 'transfer-encoding', 'content-length']) delete headers[key];
        const response = await lab.request(request.url(), { method: request.method(), headers,
          ...(request.postData() === null ? {} : { body: request.postData() }) });
        const replyHeaders = {};
        for (const [key, value] of Object.entries(response.headers)) {
          if (['connection', 'content-length', 'transfer-encoding'].includes(key) || value === undefined) continue;
          replyHeaders[key] = Array.isArray(value) ? value.join('\n') : String(value);
        }
        await route.fulfill({ status: response.status, headers: replyHeaders, body: response.body });
      } catch { blocked++; try { await route.abort('failed'); } catch { /* Context is closing. */ } }
    });
    const page = await context.newPage(); page.setDefaultTimeout(12000); page.setDefaultNavigationTimeout(12000);
    page.on('pageerror', () => { pageErrors++; });
    stage = 'initial-page';
    await page.goto(appOrigin + '/');
    await page.locator('#oidc-start-form:not([hidden])').waitFor();
    record('invented-only page rendered', (await page.title()).includes('Local synthetic proof'));
    record('fixture and manual callback hidden', await page.locator('#login-form').isHidden() && await page.locator('#oidc-callback-form').isHidden());
    record('no registration before login', await page.locator('#registration-form').isHidden());
    const before = await context.cookies(appOrigin);
    const appCookie = before.find(cookie => cookie.name === HTTPS_COOKIE_NAME);
    savedAppCookie = appCookie?.value;
    record('browser accepts Secure HttpOnly Strict app cookie', appCookie?.secure && appCookie.httpOnly && appCookie.sameSite === 'Strict' && appCookie.path === '/');
    record('HttpOnly cookie inaccessible to script', await page.evaluate(() => document.cookie === ''));
    stage = 'redirect-login';
    await page.locator('#oidc-start-form button').click();
    await page.locator('#registration-form:not([hidden])').waitFor({ timeout: 12000 });
    record('actual script navigates through invented issuer and returns clean', page.url() === appOrigin + '/' && authCalls === 1);
    record('browser supplies cross-site top-level callback metadata', callbackHeader?.site === 'cross-site' && callbackHeader.mode === 'navigate' && callbackHeader.dest === 'document');
    record('cross-site callback carries Lax transaction but not Strict application cookie', callbackHeader?.transactionCookiePresent && !callbackHeader.appCookiePresent);
    const after = await context.cookies(appOrigin);
    record('authenticated application cookie rotates', after.find(cookie => cookie.name === HTTPS_COOKIE_NAME)?.value !== savedAppCookie);
    record('transaction cookie cleared by callback', !after.some(cookie => cookie.name === TRANSACTION_COOKIE_NAME));
    record('browser JavaScript cannot read authenticated HttpOnly cookie', await page.evaluate(() => document.cookie === ''));
    record('no automatic registration or invitation', registrationCalls === 0 && await page.locator('#invite-form').isHidden());
    record('three declarations initially unchecked', !(await page.locator('#registration-adult').isChecked()) &&
      !(await page.locator('#registration-eligibility').isChecked()) && !(await page.locator('#registration-consent').isChecked()));
    stage = 'registration';
    await page.locator('#registration-form button').click();
    record('native required declarations prevent submission', registrationCalls === 0 && !registered);
    for (const id of ['registration-adult', 'registration-eligibility', 'registration-consent']) await page.locator('#' + id).check();
    await page.locator('#registration-form button').click();
    await page.locator('#registration-result:not([hidden])').waitFor();
    record('registration is submitted once and not approved', registrationCalls === 1 && (await page.locator('#registration-result-title').textContent()).includes('not approved') && !authorized);
    record('invitation still needs explicit reveal', await page.locator('#invite-form').isHidden());
    if (screenshotPath) await page.screenshot({ path: screenshotPath, fullPage: true });
    stage = 'model-invitation-vote';
    // Explicit test-only model decision, never a runtime operator HTTP endpoint.
    authorized = true;
    await page.locator('#show-invitation').click();
    await page.locator('#invitation').fill(invitationToken);
    await page.locator('#invite-form button').click();
    await page.locator('#vote-panel:not([hidden])').waitFor();
    record('bound model invitation unlocks exact fixed statement', (await page.locator('#statement').textContent()) === seeds[0]);
    record('invitation secret cleared after redemption', await page.locator('#invitation').inputValue() === '');
    await page.locator('#pass').click();
    await page.locator('#complete:not([hidden])').waitFor();
    record('actual button submits one model response', votes === 1);
    stage = 'logout-replay';
    await page.locator('#logout').click();
    await page.locator('#oidc-start-form:not([hidden])').waitFor();
    record('logout removes participant controls', await page.locator('#vote-panel').isHidden() && await page.locator('#registration-form').isHidden());
    await page.reload(); await page.locator('#oidc-start-form:not([hidden])').waitFor();
    record('reload after logout does not revive account', authCalls === 1 && await page.locator('#registration-form').isHidden());
    await page.goto(callbackUrl); await page.locator('#oidc-start-form:not([hidden])').waitFor();
    record('replayed callback remains logged out and returns clean', authCalls === 1 && page.url() === appOrigin + '/');
    record('no local/session storage populated', await page.evaluate(() => localStorage.length === 0 && sessionStorage.length === 0));
    record('no browser script errors', pageErrors === 0);
    record('no unexpected document network requests', blocked === 0);
    result.outcome = 'PASS';
  } catch (error) { result.outcome = 'FAIL'; result.failedStage = stage;
    result.failureKind = error?.name === 'TimeoutError' ? 'TIMEOUT' : error?.code === 'ERR_ASSERTION' ? 'ASSERTION' : 'SETUP_OR_TRANSPORT'; }
  finally {
    try { if (context) await context.close(); } catch { /* Always attempt browser termination separately. */ }
    try { if (browser) { await browser.close(); result.browserClosed = true; } } catch { result.browserClosed = false; }
    try { if (app) await app.close(); result.appClosed = true; } catch { result.appClosed = false; }
    try { if (lab) await lab.close(); result.issuerClosed = true; } catch { result.issuerClosed = false; }
    if (![result.browserClosed, result.appClosed, result.issuerClosed].every(Boolean)) result.outcome = 'FAIL';
  }
  return { ...result, passedChecks: checks.length, authenticationCalls: authCalls, registrationCalls, modelVotes: votes,
    pageErrors, blockedRequests: blocked, requestMetadata: requests, transport: lab?.summary() };
}
