/** Native Chromium UI over fixed loopback HTTP with a signed invented callback.
 * The caller supplies the actual fresh WordPress/strict-access/Pol.is services.
 * No real identity, native HTTPS, production activation or mailbox verification.
 * Only this helper's fresh browser/profile directories are created and removed.
 */
import { access, lstat, mkdir, realpath, rm } from 'node:fs/promises';
import { constants } from 'node:fs';
import { join } from 'node:path';

const ROOT = '/run/fncp/journey';
const BROWSER_ROOT = ROOT + '/native-browser';
const SCREENSHOTS = ROOT + '/screenshots';
const subjects = ['synthetic_native_alice', 'synthetic_native_bob'];
const allowed = new Map([
  ['/', 'GET'], ['/app.js', 'GET'], ['/style.css', 'GET'], ['/favicon.ico', 'GET'],
  ['/api/session', 'GET'], ['/api/oidc/start', 'POST'], ['/api/oidc/callback', 'POST'],
  ['/api/registration', 'POST'], ['/api/redeem', 'POST'], ['/api/participation-init', 'GET'],
  ['/api/next-comment', 'GET'], ['/api/votes', 'POST'], ['/api/logout', 'POST'],
]);
const error = stage => new Error('Native fresh WordPress journey failed at ' + stage + '.');
const assert = (condition, stage) => { if (!condition) throw error(stage); };

export function nativeJourneyRequestAllowed(origin, url, method) {
  try {
    if (origin !== 'http://127.0.0.1:8100') return false;
    const target = new URL(url);
    return target.origin === origin && !target.username && !target.password && !target.search && !target.hash &&
      target.href === origin + target.pathname && allowed.get(target.pathname) === method;
  } catch { return false; }
}

/** Private callback contracts:
 * injectLogin(subject) -> the one callback URL for the just-started UI session.
 * operator.decide(registrationId, state) -> real WordPress {status,body.outcome}.
 * issueInvitation(registrationId, subject) -> only the account-bound opaque token.
 * setRoundOpen(boolean) -> succeeds or throws, affects only this fresh round.
 * Registration references, callbacks, cookies and invitations never leave this
 * helper except through those explicit private in-process callbacks.
 */
export async function exerciseNativeWordPressJourney({ origin, injectLogin, operator, setRoundOpen,
  issueInvitation, screenshotDirectory = SCREENSHOTS }) {
  assert(process.platform === 'linux' && process.getuid?.() === 1000, 'PLATFORM');
  assert(origin === 'http://127.0.0.1:8100' && screenshotDirectory === SCREENSHOTS &&
    [injectLogin, operator?.decide, setRoundOpen, issueInvitation].every(value => typeof value === 'function'), 'INPUT');
  const result = { classification: 'ACTUAL_NATIVE_HTTP_WORDPRESS_STRICT_POLIS_JOURNEY', outcome: 'FAIL',
    browserEngineTested: false, realWordPress: true, realPolis: true,
    authenticationTransport: 'SIGNED_INVENTED_CALLBACK_SUBMITTED_THROUGH_NATIVE_UI',
    browserNativeHttpsVerified: false, realIdentity: false, mailboxVerified: false, heritageVerified: false,
    productionReady: false, activationFixtureOnly: true, browserSandboxEnabled: false,
    outerContainerIsolationRequired: true, personalProfileUsed: false, globalTrustChanged: false,
    certificateValidationDisabled: false, fabricatedCookiesOrHeaders: false,
    registrations: 0, inventedVotes: 0, checks: [], screenshots: [], initializationStatuses: [], httpResponses: [] };
  let browser; let timer; let expired = false; let stage = 'PREPARE'; let ownedDirectory = false;
  let browserClosed = false; let profilesRemoved = false; let pageErrors = 0; let blockedRequests = 0; let routeErrors = 0;
  let requests = 0; const contexts = [];
  const record = (name, condition = true) => { assert(condition && !expired, name); result.checks.push(name); };
  const bounded = async (promise, label) => {
    let deadline;
    try { return await Promise.race([promise, new Promise((_, reject) => { deadline = setTimeout(() => reject(error(label)), 12000); })]); }
    finally { clearTimeout(deadline); }
  };
  const safeCloseRound = async () => { await bounded(Promise.resolve().then(() => setRoundOpen(false)), 'ROUND_CLOSE'); };
  try {
    const root = await lstat(ROOT);
    assert(root.isDirectory() && !root.isSymbolicLink() && root.uid === 1000 &&
      (root.mode & 0o077) === 0 && await realpath(ROOT) === ROOT, 'ROOT');
    await mkdir(BROWSER_ROOT, { mode: 0o700 }); ownedDirectory = true;
    await mkdir(BROWSER_ROOT + '/home', { mode: 0o700 }); await mkdir(BROWSER_ROOT + '/tmp', { mode: 0o700 });
    await mkdir(SCREENSHOTS, { mode: 0o700 }); // Fresh output only, no overwrites.
    let executablePath;
    for (const candidate of ['/usr/bin/chromium-browser', '/usr/bin/chromium']) {
      try { await access(candidate, constants.X_OK); executablePath = candidate; break; } catch { /* Fixed Alpine alternative only. */ }
    }
    assert(executablePath, 'CHROMIUM_AVAILABLE');
    const { chromium } = await import('playwright-core');
    stage = 'LAUNCH';
    browser = await chromium.launch({ executablePath, headless: true, timeout: 15000,
      // The caller supplies a nonprivileged, no-network container. Linux user
      // namespaces/setuid sandbox are unavailable in that explicit QA image.
      chromiumSandbox: false,
      env: { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', TZ: 'UTC', HOME: BROWSER_ROOT + '/home', TMPDIR: BROWSER_ROOT + '/tmp' },
      proxy: { server: 'http://127.0.0.1:9', bypass: '127.0.0.1' },
      args: ['--disable-background-networking', '--disable-dev-shm-usage',
        '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1'] });
    result.browserEngineTested = true; result.browserVersion = browser.version();
    timer = setTimeout(() => { expired = true; void browser.close().catch(() => {}); }, 120000);
    const pages = [];
    for (let index = 0; index < 2; index++) {
      stage = 'CONTEXT_' + index;
      const context = await browser.newContext({ serviceWorkers: 'block', acceptDownloads: false,
        ignoreHTTPSErrors: false, viewport: index ? { width: 390, height: 844 } : { width: 1280, height: 960 } });
      contexts.push(context);
      stage = 'ROUTING_' + index;
      await context.routeWebSocket('**/*', async socket => { blockedRequests++; try { await socket.close(); } catch { routeErrors++; } });
      await context.route('**/*', async route => {
        try {
          const request = route.request();
          if (++requests > 180 || !nativeJourneyRequestAllowed(origin, request.url(), request.method())) {
            blockedRequests++; await route.abort('blockedbyclient'); return;
          }
          // Continue unchanged: Chromium supplies real cookies, Origin, Fetch
          // Metadata and CSRF-bearing page JavaScript requests.
          await route.continue();
        } catch { routeErrors++; try { await route.abort('failed'); } catch { /* Closing. */ } }
      });
      stage = 'PAGE_' + index;
      const page = await context.newPage(); page.setDefaultTimeout(8000); page.setDefaultNavigationTimeout(8000);
      page.on('pageerror', () => { pageErrors++; }); pages.push(page);
    }
    const idle = page => page.locator('#workspace[aria-busy="false"]').waitFor();
    const observeResponse=async(response,path)=>{const item={path,status:response.status()};if(item.status>=400){const body=await response.json();const reasons=['Request verification failed. Reload this page.','Browser session ended. Start again.','Synthetic identity session ended. Start again.','Authentication or participation session ended. Start again.','Access denied. Check the approved synthetic account and invitation, or contact the local operator.','The outcome could not be confirmed. Do not resubmit automatically.','The local proof could not confirm this operation.','Browser request metadata required.','Same-origin access required.','The local service is unavailable. No automatic retry was made.','Sign in with the matching synthetic account first.','Redeem your account-bound invitation first.'];item.reason=reasons.includes(body?.error)?body.error:'UNCLASSIFIED_FIXED_ERROR';}result.httpResponses.push(item);};
    const responseForClick = async (page, path, selector) => {
      const [response] = await Promise.all([page.waitForResponse(response =>
        response.url() === origin + path && response.request().method() === allowed.get(path), { timeout: 12000 }),
      page.locator(selector).click()]);
      await idle(page); await observeResponse(response,path); return response;
    };
    const registrations = [];
    for (let index = 0; index < 2; index++) {
      stage = index ? 'BOB_REGISTRATION' : 'ALICE_REGISTRATION';
      const page = pages[index]; await page.goto(origin + '/');
      await page.locator('#oidc-start-form:not([hidden])').waitFor(); await idle(page);
      record('native visitor has no fixture-login or voting form ' + index,
        await page.locator('#login-form').isHidden() && await page.locator('#vote-panel').isHidden());
      record('native private cookie not script-readable ' + index, await page.evaluate(() => document.cookie === ''));
      record('native layout fits viewport ' + index, await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      record('native OIDC start ' + index, (await responseForClick(page, '/api/oidc/start', '#oidc-start-form button')).status() === 200);
      await page.locator('#oidc-callback-form:not([hidden])').waitFor();
      const callback = await bounded(Promise.resolve().then(() => injectLogin(subjects[index])), 'INJECT_LOGIN');
      assert(typeof callback === 'string' && callback.length <= 8192 &&
        /^https:\/\/[^/]+\.invalid\//u.test(callback), 'PRIVATE_CALLBACK');
      await page.locator('#oidc-callback').fill(callback);
      record('native signed callback accepted ' + index,
        (await responseForClick(page, '/api/oidc/callback', '#oidc-callback-form button')).status() === 200);
      await page.locator('#registration-form:not([hidden])').waitFor();
      record('callback cleared after native submission ' + index, await page.locator('#oidc-callback').inputValue() === '');
      for (const id of ['registration-adult', 'registration-eligibility', 'registration-consent']) {
        record('independent declaration initially unchecked ' + index + ' ' + id, !(await page.locator('#' + id).isChecked()));
      }
      await page.locator('#registration-form button').click();
      record('native required declarations prevent incomplete submission ' + index,
        await page.locator('#registration-form').isVisible() && await page.locator('#registration-result').isHidden());
      for (const id of ['registration-adult', 'registration-eligibility', 'registration-consent']) await page.locator('#' + id).check();
      record('native registration accepted ' + index,
        (await responseForClick(page, '/api/registration', '#registration-form button')).status() === 200);
      await page.locator('#registration-result:not([hidden])').waitFor();
      const registrationId = (await page.locator('#registration-reference').textContent())?.trim();
      assert(typeof registrationId === 'string' && /^[a-f0-9-]{36}$/u.test(registrationId), 'REGISTRATION_REFERENCE');
      registrations.push(registrationId); result.registrations++;
      record('registration awaits separate approval ' + index,
        (await page.locator('#registration-result-title').textContent()).includes('not approved') &&
        await page.locator('#invite-form').isHidden() && await page.locator('#vote-panel').isHidden());
    }
    record('two independent WordPress registrations', registrations[0] !== registrations[1]);
    stage = 'SEPARATE_APPROVAL';
    for (const registrationId of registrations) {
      const approval = await bounded(operator.decide(registrationId, 'approved'), 'APPROVAL');
      record('actual WordPress approval acknowledged', approval.status === 200 && approval.body?.outcome === 'ACKNOWLEDGED');
    }
    await bounded(Promise.resolve().then(() => setRoundOpen(true)), 'ROUND_OPEN');
    const invitations = [];
    for (let index = 0; index < 2; index++) {
      const invitation = await bounded(Promise.resolve().then(() => issueInvitation(registrations[index], subjects[index])), 'INVITATION');
      assert(typeof invitation === 'string' && /^[A-Za-z0-9_-]{32,512}$/u.test(invitation), 'PRIVATE_INVITATION');
      invitations.push(invitation); await pages[index].locator('#show-invitation').click();
      await pages[index].locator('#invite-form:not([hidden])').waitFor();
    }
    record('separate invitations issued', invitations[0] !== invitations[1]);
    stage = 'CROSS_ACCOUNT';
    for (let index = 0; index < 2; index++) {
      const page = pages[index]; await page.locator('#invitation').fill(invitations[1 - index]);
      const denied = await responseForClick(page, '/api/redeem', '#invite-form button');
      record('forwarded valid invitation denied ' + index, denied.status() === 403);
      record('forwarded secret cleared with no vote controls ' + index,
        await page.locator('#invitation').inputValue() === '' && await page.locator('#vote-panel').isHidden());
    }
    stage = 'RIGHTFUL_REDEMPTION';
    for (let index = 0; index < 2; index++) {
      const page = pages[index]; await page.locator('#invitation').fill(invitations[index]);
      const initialized = page.waitForResponse(response => response.url() === origin + '/api/participation-init', { timeout: 12000 });
      // Observe rejection immediately even if redemption itself fails first.
      void initialized.catch(() => {});
      record('unchanged rightful invitation redeemed ' + index,
        (await responseForClick(page, '/api/redeem', '#invite-form button')).status() === 200);
      const initializationResponse=await initialized;const initializationStatus=initializationResponse.status();result.initializationStatuses.push(initializationStatus);await observeResponse(initializationResponse,'/api/participation-init');
      record('native participant initialized ' + index, initializationStatus === 200);
      await page.locator('#vote-actions:not([hidden])').waitFor();
      record('actual statement displayed ' + index, (await page.locator('#statement').textContent()).trim().length > 0);
    }
    stage = 'VOTE_AND_SELECTIVE_REVOCATION';
    const vote = await responseForClick(pages[0], '/api/votes', '#agree');
    const saved = await vote.json(); record('one native Agree vote accepted', vote.status() === 200 && saved.saved === true);
    result.inventedVotes = 1;
    await pages[0].locator('#vote-actions:not([hidden])').waitFor();
    const revokeAlice = await bounded(operator.decide(registrations[0], 'revoked'), 'ALICE_REVOKE');
    record('Alice WordPress revocation acknowledged', revokeAlice.status === 200 && revokeAlice.body?.outcome === 'ACKNOWLEDGED');
    record('Alice displayed warm vote denied after revocation',
      [401, 403].includes((await responseForClick(pages[0], '/api/votes', '#agree')).status()));
    record('Bob existing session remains usable after only Alice revoked',
      (await responseForClick(pages[1], '/api/next-comment', '#refresh')).status() === 200);
    record('Bob still has an actual statement and vote actions', await pages[1].locator('#vote-actions').isVisible() &&
      (await pages[1].locator('#statement').textContent()).trim().length > 0);
    stage = 'ROUND_CLOSURE_WHILE_BOB_APPROVED';
    await safeCloseRound();
    record('approved Bob displayed warm vote denied by round closure before his revocation',
      [401, 403].includes((await responseForClick(pages[1], '/api/votes', '#agree')).status()));
    const revokeBob = await bounded(operator.decide(registrations[1], 'revoked'), 'BOB_REVOKE');
    record('Bob WordPress revocation acknowledged', revokeBob.status === 200 && revokeBob.body?.outcome === 'ACKNOWLEDGED');
    stage = 'CLOSED_SCREENSHOTS'; await safeCloseRound();
    for (let index = 0; index < 2; index++) {
      const page = pages[index]; await page.reload();
      await page.locator('#oidc-start-form:not([hidden])').waitFor(); await idle(page);
      record('closed reload cannot restore participant access ' + index, await page.locator('#vote-panel').isHidden());
      record('safe screenshot contains no private reference or input ' + index,
        (await page.locator('#registration-reference').textContent()).trim() === '' &&
        await page.locator('#invitation').inputValue() === '' && await page.locator('#oidc-callback').inputValue() === '');
      const name = index ? 'native-closed-mobile.png' : 'native-closed-desktop.png';
      await page.screenshot({ path: join(SCREENSHOTS, name), fullPage: true }); result.screenshots.push(name);
      record('browser storage has no account material ' + index,
        await page.evaluate(() => localStorage.length === 0 && sessionStorage.length === 0 && document.cookie === ''));
    }
    record('no page script errors', pageErrors === 0);
    record('browser requested no unapproved destination', blockedRequests === 0 && routeErrors === 0);
    result.outcome = 'PASS';
  } catch (failure) {
    result.failedStage = stage;
    const check = /^Native fresh WordPress journey failed at ([A-Za-z0-9_ -]{1,120})\.$/u.exec(failure?.message ?? '');
    if (check) result.failedCheck = check[1];
    result.failureKind = failure?.name === 'TimeoutError' ? 'TIMEOUT' : 'CHECK_OR_RUNTIME';
    if (/^(LAUNCH|CONTEXT_[01]|ROUTING_[01]|PAGE_[01])$/u.test(stage)) {
      // No page has navigated and no login/callback/invitation has been supplied
      // in these phases. Capture only a bounded first-line setup diagnostic.
      result.launchFailure = String(failure?.message ?? 'Browser setup failed').split('\n')[0]
        .replace(/\b(?:https?|file):\/\/\S+/gu, '[url]')
        .replace(/\/(?:[^\s:]+\/)*[^\s:]*/gu, '[path]')
        .replace(/[^A-Za-z0-9 _.:()\[\],'-]/gu, '?').slice(0, 200);
      result.browserConnectedAtFailure = browser?.isConnected() === true;
    }
  } finally {
    clearTimeout(timer);
    try { await safeCloseRound(); } catch { result.outcome = 'FAIL'; result.roundClosureUnconfirmed = true; }
    for (const context of contexts) { try { await bounded(context.close(), 'CONTEXT_CLOSE'); } catch { result.outcome = 'FAIL'; } }
    if (browser) {
      try { await bounded(browser.close(), 'BROWSER_CLOSE'); browserClosed = true; } catch { result.outcome = 'FAIL'; }
    }
    if (ownedDirectory && (!browser || browserClosed)) {
      try { await rm(BROWSER_ROOT, { recursive: true }); profilesRemoved = true; } catch { result.outcome = 'FAIL'; }
    }
    if (expired || !browserClosed || !profilesRemoved || routeErrors) result.outcome = 'FAIL';
  }
  return { ...result, browserClosed, profilesRemoved, lifetimeExpired: expired,
    passedChecks: result.checks.length, pageErrors, blockedRequests, routeErrors, requests };
}
