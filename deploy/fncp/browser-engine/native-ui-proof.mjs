/** OPT-IN browser test only. Native loopback HTTP, actual BFF and page assets,
 * signed invented identity through private JSON callback, in-memory application
 * model. NOT cross-site HTTPS, real WordPress/Pol.is or production assurance.
 * No autostart, dependency download, retained state, external URL or real profile.
 */
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { connect } from 'node:net';
import { join } from 'node:path';
import { createLocalBrowser, COOKIE_NAME } from '../local-browser/browser-server.mjs';
import { createSyntheticIdentityHarness } from '../identity-foundation/synthetic-harness.mjs';
import { createSyntheticBrowserDriver } from '../identity-foundation/synthetic-browser-driver.mjs';
import { nativeRequestAllowed } from './native-policy.mjs';

const opaque = () => randomBytes(32).toString('base64url');
const seeds = JSON.parse(readFileSync(new URL('../seed-statements.json', import.meta.url), 'utf8'));
const refused = port => new Promise(resolve => {
  const socket = connect({ host: '127.0.0.1', port }); let done = false;
  const finish = value => { if (!done) { done = true; socket.destroy(); resolve(value); } };
  socket.setTimeout(1000); socket.once('timeout', () => finish(false)); socket.once('connect', () => finish(false));
  socket.once('error', error => finish(error.code === 'ECONNREFUSED'));
});

export async function runNativeUiProof({ chromium, executablePath, screenshotDirectory } = {}) {
  if (!chromium || typeof chromium.launch !== 'function' || typeof executablePath !== 'string') throw new Error('Explicit installed test browser required.');
  const checks = []; const counters = { authentications: 0, registrations: 0, redemptions: 0, votes: 0, agree: 0, disagree: 0, pass: 0, logouts: 0, rejections: 0 };
  const result = { schemaVersion: 1, classification: 'KEEP_CLOSED', check: 'NATIVE_LOOPBACK_BROWSER_UI_WITH_SIGNED_INVENTED_JSON_LOGIN',
    mode: 'SYNTHETIC_ONLY', browserEngineTested: false, browserNativeHttpsVerified: false,
    crossSiteRedirectVerified: false, realWordPress: false, realPolis: false, realIdentityProvider: false,
    indigenousHeritageVerified: false, realMailboxVerified: false, productionReady: false,
    noMetadataOrCookieFabrication: true, personalBrowserProfileUsed: false, globalTrustChanged: false,
    certificateValidationDisabled: false, externalNetworkPermitted: false, dependenciesInstalled: false,
    checks, counters, browserStarted: false, applicationStarted: false,
    browserClosed: false, applicationClosed: false, listenerIndependentlyRefused: false };
  let stage = 'setup'; let browser; let context; let app; let port; let timer;
  let pageErrors = 0; let unexpectedRequests = 0; let routingErrors = 0; let responseCount = 0; let requestCount = 0; let lifetimeExpired = false;
  let binding; let registered = false; let approved = false; let invitationUsed = false; let nextIndex = 0;
  let authToken = opaque(); let participationToken = opaque(); const invitation = opaque();
  const record = (name, condition) => { assert.equal(Boolean(condition), true); checks.push({ name, result: 'PASS' }); };
  const denied = () => { counters.rejections++; return { status: 403, body: {} }; };
  try {
    assert.equal(seeds.length, 15);
    const harness = await createSyntheticIdentityHarness();
    const driver = createSyntheticBrowserDriver({ mode: 'SYNTHETIC_ONLY', identity: harness.identity,
      syntheticAuthorizationResponse: harness.authorizationResponse });
    // Capture only this fresh fixture's private binding, never expose an HTTP
    // injection/approval endpoint or serialize the binding in evidence.
    const wrappedDriver = { ...driver, async begin(input) { binding = input.browserSessionId; return driver.begin(input); } };
    const next = () => nextIndex < seeds.length ? { tid: nextIndex, txt: seeds[nextIndex] } : null;
    const backend = {
      async authenticateIdentity(principal) {
        assert.equal(harness.identity.isVerifiedPrincipal(principal), true); counters.authentications++;
        authToken = opaque(); return { mode: 'SYNTHETIC_ONLY', assurance: 'OIDC_ID_TOKEN_VERIFIED', fixtureAuthToken: authToken };
      },
      async request(path, body, credential) {
        if (path === '/session/logout') {
          if (![authToken, participationToken].includes(credential)) return denied();
          counters.logouts++; authToken = opaque(); participationToken = opaque(); return { status: 200, body: {} };
        }
        if (path === '/invitations/redeem') {
          if (!registered || !approved || invitationUsed || credential !== authToken || body.invitationToken !== invitation) return denied();
          invitationUsed = true; counters.redemptions++; return { status: 200, body: { mode: 'SYNTHETIC_ONLY', participationToken } };
        }
        if (!invitationUsed || credential !== participationToken) return denied();
        if (path === '/polis/participation-init') return { status: 200, body: { nextComment: next() } };
        if (path === '/polis/next-comment') return { status: 200, body: next() };
        if (path !== '/polis/votes' || body.tid !== nextIndex || nextIndex >= 15 || ![-1, 0, 1].includes(body.vote)) return denied();
        nextIndex++; counters.votes++; counters[body.vote === -1 ? 'agree' : body.vote === 1 ? 'disagree' : 'pass']++;
        return { status: 200, body: { nextComment: next() } };
      },
    };
    app = createLocalBrowser({ mode: 'fixture-only', backend, oidcDriver: wrappedDriver,
      registrationBridge: { mode: 'SYNTHETIC_ONLY', async register({ principal }) {
        assert.equal(harness.identity.isVerifiedPrincipal(principal), true);
        assert.equal(registered, false); registered = true; counters.registrations++;
        return { status: 'SUBMITTED_NOT_APPROVED', registrationId: randomUUID() };
      } } });
    const origin = await app.listen(0); port = Number(new URL(origin).port);
    result.applicationStarted = true;
    assert.match(origin, /^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/u);
    browser = await chromium.launch({ headless: true, executablePath, timeout: 10000,
      proxy: { server: 'http://127.0.0.1:9', bypass: '127.0.0.1' },
      args: ['--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1', '--disable-background-networking'] });
    result.browserStarted = true; result.browserEngineTested = true; result.browserVersion = browser.version();
    context = await browser.newContext({ serviceWorkers: 'block', acceptDownloads: false,
      ignoreHTTPSErrors: false, viewport: { width: 1280, height: 1000 } });
    timer = setTimeout(() => { lifetimeExpired = true;
      void Promise.allSettled([browser.close(), app.close()]); }, 120000); timer.unref();
    await context.routeWebSocket('**/*', async socket => {
      unexpectedRequests++; try { await socket.close(); } catch { routingErrors++; }
    });
    await context.route('**/*', async route => {
      try {
        const request = route.request(); requestCount++;
        if (requestCount > 120 || !nativeRequestAllowed(origin, request.url(), request.method())) {
          unexpectedRequests++; await route.abort('blockedbyclient'); return;
        }
        // Continue unmodified: Chromium itself emits cookies/Origin/Fetch Metadata.
        await route.continue();
      } catch {
        routingErrors++; try { await route.abort('failed'); } catch { /* Already closing. */ }
      }
    });
    const page = await context.newPage(); page.setDefaultTimeout(10000); page.setDefaultNavigationTimeout(10000);
    page.on('pageerror', () => { pageErrors++; }); page.on('response', () => { responseCount++; });
    const focused = id => page.evaluate(expected => document.activeElement?.id === expected, id);
    const noOverflow = () => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth);
    stage = 'visitor';
    await page.goto(origin + '/'); await page.locator('#oidc-start-form:not([hidden])').waitFor();
    record('page renders actual local assets with synthetic warning', (await page.title()).includes('Local synthetic proof'));
    record('fixture login and registration hidden in signed visitor mode', await page.locator('#login-form').isHidden() && await page.locator('#registration-form').isHidden());
    const initialCookie = (await context.cookies(origin)).find(cookie => cookie.name === COOKIE_NAME);
    record('native browser stores HttpOnly Strict loopback cookie', initialCookie?.httpOnly && initialCookie.sameSite === 'Strict' && !initialCookie.secure);
    record('cookie not available to page JavaScript', await page.evaluate(() => document.cookie === ''));
    record('desktop page has no horizontal overflow', await noOverflow());
    stage = 'signed-json-login';
    await page.locator('#oidc-start-form button').click(); await page.locator('#oidc-callback-form:not([hidden])').waitFor();
    record('manual synthetic callback is labelled, with keyboard focus', (await page.locator('#oidc-start-help').textContent()).includes('private in-process test driver') && await focused('oidc-callback'));
    const injected = await driver.injectTestResponse({ browserSessionId: binding, syntheticSubject: 'synthetic_browser_local', emailVerifiedByIssuer: true });
    assert.equal(injected.ok, true);
    await page.locator('#oidc-callback').fill(injected.callback.callbackUrl); await page.locator('#oidc-callback-form button').click();
    await page.locator('#registration-form:not([hidden])').waitFor();
    record('signed invented login completes without a browser redirect', counters.authentications === 1 && page.url() === origin + '/');
    record('manual callback cleared and registration receives focus', await page.locator('#oidc-callback').inputValue() === '' && await focused('registration-adult'));
    const authenticatedCookie = (await context.cookies(origin)).find(cookie => cookie.name === COOKIE_NAME);
    record('session cookie rotates and keeps HttpOnly Strict loopback attributes', authenticatedCookie?.value && authenticatedCookie.value !== initialCookie.value
      && authenticatedCookie.httpOnly && authenticatedCookie.sameSite === 'Strict' && !authenticatedCookie.secure);
    stage = 'registration';
    record('declarations initially unchecked and invitation unavailable', !(await page.locator('#registration-adult').isChecked()) && !(await page.locator('#registration-eligibility').isChecked()) && !(await page.locator('#registration-consent').isChecked()) && await page.locator('#invite-form').isHidden());
    await page.locator('#registration-form button').click();
    record('native required fields prevent incomplete submission', counters.registrations === 0 && await focused('registration-adult'));
    const csrfDenied = await page.evaluate(async () => (await fetch('/api/registration', { method: 'POST', mode: 'same-origin', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': 'invented_wrong_csrf' }, body: '{}' })).status);
    record('wrong CSRF rejected before registration model', csrfDenied === 403 && counters.registrations === 0);
    await page.setViewportSize({ width: 390, height: 844 });
    record('mobile declarations have no horizontal overflow', await noOverflow());
    if (screenshotDirectory) await page.screenshot({ path: join(screenshotDirectory, 'registration-mobile.png'), fullPage: true });
    for (const id of ['registration-adult', 'registration-eligibility', 'registration-consent']) await page.locator('#' + id).check();
    await page.locator('#registration-form button').click(); await page.locator('#registration-result:not([hidden])').waitFor();
    record('one registration stays explicitly unapproved', counters.registrations === 1 && !approved && (await page.locator('#registration-result-title').textContent()).includes('not approved'));
    record('confirmation heading receives focus', await focused('registration-result-title'));
    record('no automatic invitation redemption', await page.locator('#invite-form').isHidden() && counters.redemptions === 0);
    await page.setViewportSize({ width: 1280, height: 1000 });
    if (screenshotDirectory) await page.screenshot({ path: join(screenshotDirectory, 'registration-pending-desktop.png'), fullPage: true });
    stage = 'model-approval-invitation';
    await page.locator('#show-invitation').click(); record('explicit reveal focuses invitation', await focused('invitation'));
    await page.locator('#invitation').fill(invitation); await page.locator('#invite-form button').click();
    await page.locator('#status.error').waitFor();
    record('correct model invitation cannot bypass separate approval', counters.redemptions === 0 && await page.locator('#vote-panel').isHidden());
    record('failed invitation clears secret and focuses error', await page.locator('#invitation').inputValue() === '' && await focused('status'));
    approved = true; // Private in-process test fixture only; no HTTP admin route.
    await page.locator('#invitation').fill(invitation); await page.locator('#invite-form button').click();
    await page.locator('#vote-panel:not([hidden])').waitFor();
    record('one model-approved invitation redemption succeeds and input is cleared', counters.redemptions === 1 && await page.locator('#invitation').inputValue() === '');
    stage = 'fixed-statements';
    for (let index = 0; index < 15; index++) {
      await page.waitForFunction(text => document.getElementById('statement')?.textContent === text && !document.querySelector('[data-vote="0"]').disabled, seeds[index]);
      assert.equal(await focused('statement'), true);
      assert.equal(await page.locator('#statement').textContent(), seeds[index]);
      await page.locator(`[data-vote="${[-1, 1, 0][index % 3]}"]`).click();
    }
    await page.locator('#complete:not([hidden])').waitFor();
    record('15 exact fixed statements processed as 5 Agree 5 Disagree 5 Pass', counters.votes === 15 && nextIndex === 15
      && counters.agree === 5 && counters.disagree === 5 && counters.pass === 5);
    record('completion receives focus and vote controls disappear', await focused('complete') && await page.locator('#vote-actions').isHidden());
    await page.setViewportSize({ width: 390, height: 844 }); record('mobile completion has no horizontal overflow', await noOverflow());
    if (screenshotDirectory) await page.screenshot({ path: join(screenshotDirectory, 'completion-mobile.png'), fullPage: true });
    stage = 'logout';
    await page.locator('#logout').click(); await page.locator('#oidc-start-form:not([hidden])').waitFor();
    record('logout removes participant controls and focuses status', counters.logouts === 1 && await page.locator('#vote-panel').isHidden() && await focused('status'));
    await page.reload(); await page.locator('#oidc-start-form:not([hidden])').waitFor();
    record('reload cannot revive authenticated model session', counters.authentications === 1 && await page.locator('#registration-form').isHidden());
    record('page storage empty and no script-readable cookie', await page.evaluate(() => localStorage.length === 0 && sessionStorage.length === 0 && document.cookie === ''));
    record('browser script completed without errors', pageErrors === 0);
    record('no unexpected browser destinations requested', unexpectedRequests === 0);
    result.outcome = 'PASS';
  } catch (error) {
    result.outcome = 'FAIL'; result.failedStage = stage;
    result.failureKind = error?.name === 'TimeoutError' ? 'TIMEOUT' : error?.code === 'ERR_ASSERTION' ? 'ASSERTION' : 'SETUP_OR_TRANSPORT';
    result.networkFailureCode = String(error?.message).match(/net::ERR_[A-Z_]+/u)?.[0] ?? 'NONE';
  } finally {
    clearTimeout(timer);
    try { if (context) await context.close(); } catch { /* Browser close below remains mandatory. */ }
    try { if (browser) { await browser.close(); result.browserClosed = true; } } catch { result.browserClosed = false; }
    try { if (app) { await app.close(); result.applicationClosed = true; } } catch { result.applicationClosed = false; }
    if (port !== undefined) result.listenerIndependentlyRefused = await refused(port);
    if (lifetimeExpired || routingErrors || ![result.browserClosed, result.applicationClosed, result.listenerIndependentlyRefused].every(Boolean)) result.outcome = 'FAIL';
  }
  return { ...result, passedChecks: checks.length, pageErrors, unexpectedRequests, routingErrors, responseCount, requestCount, lifetimeExpired };
}
