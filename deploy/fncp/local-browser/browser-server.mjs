/** Local browser proof only. No real identity, email, eligibility or production service. */
import { createServer } from 'node:http';
import { createServer as createSecureServer } from 'node:https';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';

export const MODE = 'fixture-only';
export const BACKEND_ORIGIN = 'http://127.0.0.1:8099';
export const COOKIE_NAME = 'fncp_local_browser';
export const HTTPS_COOKIE_NAME = '__Host-fncp_browser';
export const TRANSACTION_COOKIE_NAME = '__Host-fncp_oidc_tx';
// Counts body readers as well as queued/running dispatches; not a socket limit.
export const MAX_BROWSER_REQUESTS = 32;
const opaque = /^[A-Za-z0-9_-]{32,512}$/u;
const fixturePattern = /^synthetic_[a-z][a-z0-9_]{0,39}$/u;
const random = () => randomBytes(32).toString('base64url');
const digest = (value) => createHash('sha256').update(value).digest();
const same = (a, b) => typeof a === 'string' && typeof b === 'string' && timingSafeEqual(digest(a), digest(b));
const keyOf = (value) => digest(value).toString('hex');
const seedTexts = JSON.parse(readFileSync(new URL('../seed-statements.json', import.meta.url), 'utf8'));
if (!Array.isArray(seedTexts) || seedTexts.length !== 15 || new Set(seedTexts).size !== 15 ||
    seedTexts.some((text) => typeof text !== 'string' || !text || text.length > 3000)) {
  throw new Error('Fifteen unique synthetic seed texts required.');
}
const allowedTexts = new Set(seedTexts);
const assets = new Map([
  ['/', ['text/html; charset=utf-8', readFileSync(new URL('./public/index.html', import.meta.url))]],
  ['/app.js', ['text/javascript; charset=utf-8', readFileSync(new URL('./public/app.js', import.meta.url))]],
  ['/style.css', ['text/css; charset=utf-8', readFileSync(new URL('./public/style.css', import.meta.url))]],
]);
const backendRoutes = new Map([
  ['/health', 'GET'], ['/test-auth/mailbox-simulator', 'POST'], ['/invitations/redeem', 'POST'],
  ['/polis/participation-init', 'GET'], ['/polis/next-comment', 'GET'], ['/polis/votes', 'POST'],
  ['/session/logout', 'POST'],
]);

class BrowserError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function exact(body, keys) {
  if (!body || Array.isArray(body) || typeof body !== 'object' ||
      keys.some((key) => !Object.hasOwn(body, key)) || Object.keys(body).some((key) => !keys.includes(key))) {
    throw new BrowserError(400, 'Invalid request.');
  }
}

/** This executable transport has no caller-selectable origin or admin route. */
export class LocalAccessBackend {
  async request(path, body, credential) {
    const method = backendRoutes.get(path);
    if (!method || (method === 'GET' ? body !== undefined : body === undefined) ||
        (credential !== undefined && !opaque.test(credential))) throw new Error('Invalid backend operation.');
    const response = await fetch(BACKEND_ORIGIN + path, {
      method, redirect: 'error', signal: AbortSignal.timeout(11000),
      headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        ...(credential ? { Authorization: `Bearer ${credential}` } : {}) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    // Browser Cookie, Origin, Fetch Metadata, CSRF and caller authority are never forwarded.
    const chunks = []; let size = 0;
    for await (const chunk of response.body ?? []) {
      size += chunk.length;
      if (size > 512 * 1024) throw new Error('Backend response too large.');
      chunks.push(chunk);
    }
    return { status: response.status, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) };
  }

  async verifySynthetic() {
    const result = await this.request('/health');
    if (result.status !== 200 || result.body?.mode !== 'SYNTHETIC_ONLY' ||
        result.body?.productionReady !== false || result.body?.heritageVerification !== false ||
        result.body?.realEmailEnabled !== false) throw new Error('Synthetic backend required.');
  }
}

/** Deliberately project an allowlist, never return arbitrary backend objects. */
function statementFrom(body, kind) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('Invalid synthetic statement response.');
  const candidate = kind === 'next' ? body : body.nextComment;
  if (candidate === undefined || candidate === null ||
      (typeof candidate === 'object' && !Array.isArray(candidate) && !Object.hasOwn(candidate, 'tid'))) return null;
  if (!Number.isSafeInteger(candidate.tid) || candidate.tid < 0 || !allowedTexts.has(candidate.txt)) {
    throw new Error('Unexpected synthetic statement.');
  }
  return { tid: candidate.tid, text: candidate.txt };
}

export function createLocalBrowser({ mode, backend = new LocalAccessBackend(), now = Date.now,
  sessionLifetimeMs = 15 * 60_000, maxSessions = 64, oidcDriver, registrationIssuer, registrationBridge, httpsRedirect } = {}) {
  if (mode !== MODE || !backend || typeof backend.request !== 'function' ||
      !Number.isSafeInteger(sessionLifetimeMs) || sessionLifetimeMs < 1 || sessionLifetimeMs > 15 * 60_000 ||
      !Number.isSafeInteger(maxSessions) || maxSessions < 1 || maxSessions > 256) {
    throw new Error('Explicit fixture-only mode and bounded session configuration required.');
  }
  if (oidcDriver && (oidcDriver.mode !== 'SYNTHETIC_ONLY' ||
      ['begin', 'complete', 'discard', 'isVerifiedPrincipal'].some((key) => typeof oidcDriver[key] !== 'function') ||
      typeof backend.authenticateIdentity !== 'function')) throw new Error('Strict synthetic identity bridge required.');
  if (registrationIssuer && (!oidcDriver || registrationIssuer.mode !== 'SYNTHETIC_ONLY' ||
      typeof registrationIssuer.issue !== 'function')) throw new Error('Strict synthetic registration bridge required.');
  if (registrationBridge && (!oidcDriver || registrationBridge.mode !== 'SYNTHETIC_ONLY' ||
      typeof registrationBridge.register !== 'function')) throw new Error('Strict server registration bridge required.');
  let tls;
  if (httpsRedirect !== undefined) {
    try {
      exact(httpsRedirect, ['mode', 'origin', 'key', 'cert']);
      const origin = new URL(httpsRedirect.origin);
      if (httpsRedirect.mode !== 'SYNTHETIC_HTTPS_REDIRECT' || origin.protocol !== 'https:' ||
          origin.hostname !== 'browser.example.invalid' || !origin.port || origin.origin !== httpsRedirect.origin ||
          !Buffer.isBuffer(httpsRedirect.key) || !Buffer.isBuffer(httpsRedirect.cert) ||
          !httpsRedirect.key.length || !httpsRedirect.cert.length || httpsRedirect.key.length > 65_536 || httpsRedirect.cert.length > 65_536 ||
          !oidcDriver || oidcDriver.transport !== 'HTTPS_REDIRECT_LAB' ||
          oidcDriver.callbackUri !== origin.origin + '/oidc/callback') throw new Error();
      const endpoint = new URL(oidcDriver.authorizationEndpoint);
      if (endpoint.protocol !== 'https:' || !endpoint.hostname.endsWith('.invalid') || endpoint.username ||
          endpoint.password || endpoint.search || endpoint.hash || /[?#]/u.test(oidcDriver.authorizationEndpoint) || endpoint.href !== oidcDriver.authorizationEndpoint ||
          endpoint.hostname === origin.hostname) throw new Error();
      tls = { origin: origin.origin, port: Number(origin.port), authorizationEndpoint: endpoint.href,
        callbackUri: oidcDriver.callbackUri, key: Buffer.from(httpsRedirect.key), cert: Buffer.from(httpsRedirect.cert) };
    } catch { throw new Error('Explicit fixed synthetic HTTPS redirect configuration required.'); }
  } else if (oidcDriver?.transport === 'HTTPS_REDIRECT_LAB') {
    throw new Error('HTTPS redirect driver requires the HTTPS browser profile.');
  }
  const cookieName = tls ? HTTPS_COOKIE_NAME : COOKIE_NAME;
  const cookieFlags = `Path=/; HttpOnly; SameSite=Strict${tls ? '; Secure' : ''}`;
  const setCookie = (res, value) => {
    const previous = res.getHeader('Set-Cookie');
    const name = value.split('=', 1)[0];
    const values = (previous ? Array.isArray(previous) ? previous : [previous] : [])
      .filter(item => !String(item).startsWith(name + '='));
    res.setHeader('Set-Cookie', [...values, value]);
  };
  const transactions = new Map();
  // Tokens live only here, not in cookies, HTML, localStorage, files, logs or URLs.
  const sessions = new Map();
  const callbackRequests = new Set();
  let chain = Promise.resolve(); let pendingRequests = 0;
  let closing = false; let closePromise; let cancelListen;
  const forget = (session) => {
    if (!session || sessions.get(session.key) !== session) return;
    sessions.delete(session.key);
    if (session.oidcTransactionKey) transactions.delete(session.oidcTransactionKey);
    if (session.oidcBinding) oidcDriver?.discard({ browserSessionId: session.oidcBinding });
  };
  const prune = () => {
    for (const session of sessions.values()) {
      if (session.expires <= now() || session.principal && !oidcDriver?.isVerifiedPrincipal(session.principal)) forget(session);
    }
  };
  const clearTransaction = (res) => setCookie(res, `${TRANSACTION_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);
  const clearCookie = (res) => setCookie(res, `${cookieName}=; ${cookieFlags}; Max-Age=0`);
  const state = (session) => ({ mode: 'SYNTHETIC_ONLY', csrf: session.csrf,
    phase: session.participationToken ? 'participant' : session.authToken ? 'authenticated' : 'visitor',
    expiresAt: session.expires, fixedStatements: 15,
    authentication: oidcDriver ? 'SIGNED_SYNTHETIC_OIDC' : 'FIXTURE_PASSWORD_SIMULATION',
    ...(tls ? { authenticationTransport: 'HTTPS_REDIRECT_LAB', realBrowserEngineTested: false } : {}),
    oidcPending: session.oidcPending === true,
    ...(registrationBridge ? { registrationEnabled: true, registrationStatus: session.registrationStatus ?? 'NOT_SUBMITTED',
      ...(session.registrationId ? { registrationId: session.registrationId } : {}) } : {}) });
  const end = (session, res) => { forget(session); clearCookie(res); if (tls) clearTransaction(res); };
  const fresh = (res, old, values = {}) => {
    forget(old);
    prune();
    if (sessions.size >= maxSessions) throw new BrowserError(503, 'Local browser session capacity reached. Try again after expiry.');
    const value = random(); const session = { key: keyOf(value), csrf: random(),
      expires: now() + sessionLifetimeMs, ...values };
    sessions.set(session.key, session);
    // The legacy HTTP profile never claims Secure. TLS uses an independent host-only cookie.
    setCookie(res, `${cookieName}=${value}; ${cookieFlags}; Max-Age=${Math.ceil(sessionLifetimeMs / 1000)}`);
    return session;
  };
  function cookieFor(req, name) {
    const values = (req.headers.cookie ?? '').split(';').map((value) => value.trim())
      .filter((value) => value.startsWith(name + '='));
    if (values.length > 1) throw new BrowserError(400, 'Ambiguous browser session.');
    const value = values[0]?.slice(name.length + 1);
    if (value !== undefined && !opaque.test(value)) throw new BrowserError(400, 'Invalid browser session.');
    return value;
  }
  const sessionFor = (req) => { const value = cookieFor(req, cookieName); return value ? sessions.get(keyOf(value)) : undefined; };
  function requireSession(session) {
    if (!session) throw new BrowserError(401, 'Browser session ended. Start again.');
  }
  function requireParticipant(session) {
    requireSession(session);
    if (!session.participationToken) throw new BrowserError(403, 'Redeem your account-bound invitation first.');
  }
  function requireLiveRequest(req, res, session, operationStarted = false) {
    if (!closing && !req.aborted && !res.destroyed && !res.writableEnded) return;
    // A request that never reached an adapter must not be dispatched later.
    // An adapter already in flight may have applied a side effect: deny local
    // authority/results, drain it, and never manufacture rollback or a retry.
    if (session) forget(session);
    throw new BrowserError(503, operationStarted
      ? 'The request ended before its outcome could be confirmed. Do not resubmit automatically.'
      : 'The local request is no longer active.');
  }
  async function call(req, path, body, credential, session, res, invalidateOnDenial = false) {
    let result;
    try { result = await backend.request(path, body, credential); }
    catch { throw new BrowserError(503, 'The local service is unavailable. No automatic retry was made.'); }
    requireLiveRequest(req, res, session, true);
    if (session && (session.expires <= now() || sessions.get(session.key) !== session)) {
      end(session, res); throw new BrowserError(401, 'Browser session ended. Start again.');
    }
    if (oidcDriver && session?.principal && !oidcDriver.isVerifiedPrincipal(session.principal)) {
      end(session, res); throw new BrowserError(401, 'Synthetic identity session ended. Start again.');
    }
    if (![200, 201].includes(result.status)) {
      if (invalidateOnDenial && [401, 403].includes(result.status)) end(session, res);
      const status = [400, 401, 403, 409].includes(result.status) ? result.status : 503;
      throw new BrowserError(status, status === 503 ? 'The outcome could not be confirmed. Do not resubmit automatically.' :
        status === 401 ? 'Authentication or participation session ended. Start again.' :
          status === 403 ? 'Access denied. Check the approved synthetic account and invitation, or contact the local operator.' :
            status === 409 ? 'This operation is not available in the current state.' : 'Invalid request.');
    }
    return result.body;
  }
  async function dispatch(req, res, body) {
    // Admission may precede dispatch by an asynchronous queue/body-read delay.
    // Revalidate here, not only when the HTTP request first reaches the handler.
    requireLiveRequest(req, res);
    prune(); let session = sessionFor(req);
    const route = `${req.method} ${req.url}`;
    if (route === 'GET /api/session') return state(session ?? fresh(res));
    requireSession(session);
    if (req.method === 'POST' && !same(req.headers['x-csrf-token'], session.csrf)) {
      throw new BrowserError(403, 'Request verification failed. Reload this page.');
    }
    if (route === 'POST /api/login') {
      if (oidcDriver) throw new BrowserError(404, 'Fixture-password sign-in is unavailable in the OIDC proof.');
      exact(body, ['fixture', 'fixtureSecret']);
      if (session.authToken || session.participationToken) throw new BrowserError(409, 'Log out before changing accounts.');
      if (typeof body.fixture !== 'string' || !fixturePattern.test(body.fixture) ||
          typeof body.fixtureSecret !== 'string' || !opaque.test(body.fixtureSecret)) throw new BrowserError(400, 'Use the private synthetic fixture credentials.');
      const result = await call(req, '/test-auth/mailbox-simulator', body, undefined, session, res);
      if (!opaque.test(result?.fixtureAuthToken ?? '') || result?.mailboxOwnership !== 'SIMULATED_NOT_VERIFIED') {
        throw new BrowserError(503, 'The synthetic authentication result could not be verified.');
      }
      session = fresh(res, session, { authToken: result.fixtureAuthToken });
      return state(session);
    }
    if (route === 'POST /api/oidc/start' && oidcDriver) {
      exact(body, []);
      if (session.authToken || session.participationToken) throw new BrowserError(409, 'Log out before changing accounts.');
      session = fresh(res, session, { oidcBinding: random(), oidcPending: true });
      let result;
      try { result = await oidcDriver.begin({ browserSessionId: session.oidcBinding }); }
      catch { result = { ok: false }; }
      requireLiveRequest(req, res, session, true);
      if (closing || result?.ok !== true || session.expires <= now() || sessions.get(session.key) !== session) {
        end(session, res); throw new BrowserError(503, 'The synthetic identity flow could not start.');
      }
      if (tls) {
        try {
          const url = new URL(result.authorizationUrl);
          if (url.origin + url.pathname !== tls.authorizationEndpoint || url.username || url.password || url.hash ||
              url.href !== result.authorizationUrl || url.searchParams.getAll('redirect_uri').length !== 1 ||
              url.searchParams.get('redirect_uri') !== tls.callbackUri || result.authorizationUrl.length > 8192) throw new Error();
          const value = random(); const key = keyOf(value);
          session.oidcTransactionKey = key;
          transactions.set(key, { session, expires: Math.min(session.expires, now() + 300_000) });
          setCookie(res, `${TRANSACTION_COOKIE_NAME}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=300`);
          // This validated endpoint is navigated by window.location.assign, not fetch redirect following.
          return { ...state(session), authorizationUrl: url.href };
        } catch { end(session, res); throw new BrowserError(503, 'The synthetic identity redirect could not start.'); }
      }
      // No real redirect, authorization URL, state, nonce or verifier leaves here.
      return state(session);
    }
    if (route === 'POST /api/oidc/callback' && oidcDriver && !tls) {
      exact(body, ['callbackUrl']);
      if (!session.oidcPending || session.authToken || session.participationToken) throw new BrowserError(403, 'No pending synthetic identity flow.');
      session.oidcPending = false; // consume before any asynchronous exchange
      try {
        if (typeof body.callbackUrl !== 'string' || body.callbackUrl.length > 8192) throw new Error();
        const result = await oidcDriver.complete({ browserSessionId: session.oidcBinding, callbackUrl: body.callbackUrl });
        requireLiveRequest(req, res, session, true);
        if (result?.ok !== true || !oidcDriver.isVerifiedPrincipal(result.principal)) throw new Error();
        const authenticated = await backend.authenticateIdentity(result.principal);
        requireLiveRequest(req, res, session, true);
        if (closing || sessions.get(session.key) !== session || authenticated?.mode !== 'SYNTHETIC_ONLY' || authenticated.assurance !== 'OIDC_ID_TOKEN_VERIFIED' ||
            !opaque.test(authenticated.fixtureAuthToken ?? '') || !oidcDriver.isVerifiedPrincipal(result.principal) || session.expires <= now()) throw new Error();
        session = fresh(res, session, { authToken: authenticated.fixtureAuthToken, principal: result.principal });
        return state(session);
      } catch { end(session, res); throw new BrowserError(401, 'Synthetic identity authentication failed. Start again.'); }
    }
    if (route === 'POST /api/registration' && registrationBridge) {
      exact(body, ['adultSelfAttested', 'eligibilitySelfAttested', 'registrationConsent', 'consentVersion']);
      if (body.adultSelfAttested !== true || body.eligibilitySelfAttested !== true || body.registrationConsent !== true ||
          body.consentVersion !== 'synthetic-registration-v1') throw new BrowserError(400, 'Confirm all three synthetic declarations against the displayed notice.');
      if (!session.principal || !session.authToken || session.participationToken) throw new BrowserError(403, 'Current signed-in synthetic account required.');
      if (session.registrationStatus && session.registrationStatus !== 'NOT_SUBMITTED') throw new BrowserError(409, 'Do not resubmit. Ask the local operator to check the existing registration outcome.');
      session.registrationStatus = 'SUBMITTING';
      let result;
      try {
        result = await registrationBridge.register({ principal: session.principal, browserDeadline: session.expires, input: body });
        if (result?.status !== 'SUBMITTED_NOT_APPROVED' || typeof result.registrationId !== 'string' ||
            !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(result.registrationId)) throw new Error();
      } catch {
        session.registrationStatus = 'OUTCOME_UNCONFIRMED';
        throw new BrowserError(503, 'Registration outcome unconfirmed. It may already be recorded. Do not resubmit; ask the local operator to check.');
      }
      requireLiveRequest(req, res, session, true);
      if (session.expires <= now() || sessions.get(session.key) !== session || !oidcDriver.isVerifiedPrincipal(session.principal)) {
        end(session, res); throw new BrowserError(401, 'Session ended. Registration may already be recorded; ask the local operator to check before trying again.');
      }
      session.registrationStatus = result.status; session.registrationId = result.registrationId;
      return state(session);
    }
    if (route === 'POST /api/registration/receipt' && registrationIssuer && !registrationBridge) {
      if (!session.principal || !session.authToken || session.participationToken) throw new BrowserError(403, 'Current signed-in synthetic account required.');
      let result;
      try { result = await registrationIssuer.issue({ principal: session.principal, browserDeadline: session.expires, input: body }); }
      catch { throw new BrowserError(403, 'Synthetic registration receipt unavailable.'); }
      requireLiveRequest(req, res, session, true);
      if (session.expires <= now() || sessions.get(session.key) !== session || !oidcDriver.isVerifiedPrincipal(session.principal)) {
        end(session, res); throw new BrowserError(401, 'Synthetic identity session ended. Start again.');
      }
      // Deliberately return only the registration envelope, never backend tokens.
      return { mode: 'SYNTHETIC_ONLY', registrationOnly: true, eligibilityVerified: false, receipt: result.receipt };
    }
    if (route === 'POST /api/redeem') {
      exact(body, ['invitationToken']);
      if (!session.authToken || session.participationToken) throw new BrowserError(403, 'Sign in with the matching synthetic account first.');
      if (typeof body.invitationToken !== 'string' || !opaque.test(body.invitationToken)) throw new BrowserError(400, 'Enter a valid local invitation.');
      const result = await call(req, '/invitations/redeem', body, session.authToken, session, res);
      if (!opaque.test(result?.participationToken ?? '') || result?.mode !== 'SYNTHETIC_ONLY') {
        end(session, res); throw new BrowserError(503, 'The invitation outcome could not be verified. Ask the local operator for a new invitation.');
      }
      session = fresh(res, session, { participationToken: result.participationToken, currentTid: null,
        ...(oidcDriver ? { principal: session.principal } : {}),
        ...(registrationBridge ? { registrationStatus: session.registrationStatus, registrationId: session.registrationId } : {}) });
      return state(session);
    }
    if (route === 'POST /api/logout') {
      exact(body, []);
      const credential = session.participationToken ?? (oidcDriver ? session.authToken : undefined);
      end(session, res); // Local denial occurs even if the backend is unavailable.
      let backendLogoutVerified = !credential;
      if (credential) {
        try { backendLogoutVerified = [200, 401, 403].includes((await backend.request('/session/logout', {}, credential)).status); }
        catch { /* The backend token stays unreachable here and expires independently. */ }
      }
      return { browserSessionClosed: true, backendLogoutVerified, mode: 'SYNTHETIC_ONLY' };
    }
    const kind = { 'GET /api/participation-init': 'init', 'GET /api/next-comment': 'next', 'POST /api/votes': 'vote' }[route];
    if (!kind) throw new BrowserError(404, 'Not found.');
    requireParticipant(session);
    let payload;
    if (kind === 'vote') {
      exact(body, ['tid', 'vote']);
      if (!Number.isSafeInteger(body.tid) || body.tid < 0 || body.tid !== session.currentTid ||
          typeof body.vote !== 'number' || ![-1, 0, 1].includes(body.vote)) throw new BrowserError(400, 'Respond only to the displayed fixed statement.');
      payload = { tid: session.currentTid, vote: body.vote };
      // A lost reply must not leave a readily replayable current statement.
      session.currentTid = null;
    }
    const path = { init: '/polis/participation-init', next: '/polis/next-comment', vote: '/polis/votes' }[kind];
    const result = await call(req, path, payload, session.participationToken, session, res, true);
    const statement = statementFrom(result, kind);
    session.currentTid = statement?.tid ?? null;
    return { mode: 'SYNTHETIC_ONLY', statement, complete: statement === null, ...(kind === 'vote' ? { saved: true } : {}) };
  }

  async function redirectCallback(req, res) {
    // Callback runs outside the API serialization chain: logout/new login can
    // invalidate its binding while token exchange is pending. Never use the
    // Strict application cookie to identify a cross-site callback.
    let session; let transaction; let clearOwnedTransaction = false;
    try {
      prune();
      const value = cookieFor(req, TRANSACTION_COOKIE_NAME);
      const key = value ? keyOf(value) : undefined;
      transaction = key ? transactions.get(key) : undefined;
      if (key) transactions.delete(key); // one use before exchange/validation
      session = transaction?.session;
      if (!transaction || transaction.expires <= now() || sessions.get(session.key) !== session ||
          !session.oidcPending || session.authToken || session.participationToken) throw new Error();
      session.oidcPending = false;
      const callback = new URL(req.url, tls.origin);
      if (callback.origin + callback.pathname !== tls.callbackUri || callback.hash || callback.username ||
          callback.password || req.url.length > 8192) throw new Error();
      const current = () => !closing && !req.aborted && !res.destroyed && sessions.get(session.key) === session &&
        session.expires > now() && transaction.expires > now();
      const result = await oidcDriver.complete({ browserSessionId: session.oidcBinding, callbackUrl: callback.href });
      if (!current() || result?.ok !== true || !oidcDriver.isVerifiedPrincipal(result.principal)) throw new Error();
      const authenticated = await backend.authenticateIdentity(result.principal);
      if (!current() || authenticated?.mode !== 'SYNTHETIC_ONLY' || authenticated.assurance !== 'OIDC_ID_TOKEN_VERIFIED' ||
          !opaque.test(authenticated.fixtureAuthToken ?? '') || !oidcDriver.isVerifiedPrincipal(result.principal)) throw new Error();
      fresh(res, session, { authToken: authenticated.fixtureAuthToken, principal: result.principal });
      clearOwnedTransaction = true;
    } catch {
      // A late/unknown callback must not delete a newer application's OR
      // transaction's cookie. Only the still-owned flow may clear its cookie.
      if (session && sessions.get(session.key) === session) { clearOwnedTransaction = true; forget(session); }
    }
    if (res.destroyed || res.writableEnded) return;
    if (clearOwnedTransaction) clearTransaction(res);
    res.writeHead(303, { Location: '/' }); res.end();
  }

  const handler = async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
    res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer'); res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
    const json = (status, body) => {
      if (res.destroyed || res.writableEnded) return;
      if (closing || !req.complete) res.setHeader('Connection', 'close');
      res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(body));
    };
    let admitted = false;
    try {
      if (closing) throw new BrowserError(503, 'Local service is closing.');
      if (pendingRequests >= MAX_BROWSER_REQUESTS) throw new BrowserError(503, 'Local request capacity reached.');
      pendingRequests += 1; admitted = true; // Reserve before any body read.
      const origin = tls?.origin ?? `http://127.0.0.1:${server.address().port}`;
      if (req.socket.remoteAddress !== '127.0.0.1' || req.headers.host !== new URL(origin).host ||
          req.headers.authorization || Object.keys(req.headers).some((key) => key.startsWith('x-fncp-'))) {
        throw new BrowserError(403, 'Local browser origin only.');
      }
      const callback = tls && req.method === 'GET' && (req.url === '/oidc/callback' || req.url?.startsWith('/oidc/callback?'));
      if (!req.url?.startsWith('/') || (!callback && (req.url.includes('?') || req.url.includes('%'))) || req.url.includes('\\') || req.url.includes('#')) {
        throw new BrowserError(400, 'Only the exact local routes are available.');
      }
      const site = req.headers['sec-fetch-site'];
      if (callback) {
        if (!['same-origin', 'same-site', 'cross-site', 'none'].includes(site) ||
            req.headers['sec-fetch-mode'] !== 'navigate' || req.headers['sec-fetch-dest'] !== 'document' ||
            req.headers.origin || req.headers['transfer-encoding'] || Number(req.headers['content-length'] ?? 0) !== 0) {
          throw new BrowserError(403, 'Top-level identity callback required.');
        }
        const completion = redirectCallback(req, res);
        callbackRequests.add(completion);
        try { await completion; } finally { callbackRequests.delete(completion); }
        return;
      }
      if (req.headers.origin && req.headers.origin !== origin) throw new BrowserError(403, 'Same-origin access required.');
      // A clean landing document has no authority or participant content. The
      // subsequent same-origin API request, not a redirect-chain cookie, owns the session.
      const landing = tls && req.method === 'GET' && req.url === '/' &&
        ['same-site', 'cross-site'].includes(site) && req.headers['sec-fetch-mode'] === 'navigate' && req.headers['sec-fetch-dest'] === 'document';
      if (site && !['same-origin', 'none'].includes(site) && !landing) throw new BrowserError(403, 'Same-origin access required.');
      if (req.url.startsWith('/api/') && (site !== 'same-origin' ||
          !['same-origin', 'cors'].includes(req.headers['sec-fetch-mode']) || req.headers['sec-fetch-dest'] !== 'empty')) {
        throw new BrowserError(403, 'Browser request metadata required.');
      }
      if (!['GET', 'POST'].includes(req.method)) throw new BrowserError(405, 'Method not allowed.');
      if (req.method === 'POST' && req.headers.origin !== origin) throw new BrowserError(403, 'Same-origin mutation required.');
      if (req.method === 'GET' && (req.headers['transfer-encoding'] || Number(req.headers['content-length'] ?? 0) !== 0)) {
        throw new BrowserError(400, 'Unexpected body.');
      }
      if (req.method === 'GET' && assets.has(req.url)) {
        const [type, content] = assets.get(req.url); res.writeHead(200, { 'Content-Type': type }); res.end(content); return;
      }
      if (req.method === 'GET' && req.url === '/favicon.ico') { res.writeHead(204); res.end(); return; }
      if (!req.url.startsWith('/api/')) throw new BrowserError(404, 'Not found.');
      let body = {};
      if (req.method === 'POST') {
        if (req.headers['content-type'] !== 'application/json') throw new BrowserError(415, 'JSON required.');
        let size = 0; const chunks = [];
        for await (const chunk of req) {
          size += chunk.length;
          if (size > (oidcDriver && req.url === '/api/oidc/callback' ? 12288 : 4096)) throw new BrowserError(413, 'Request too large.');
          chunks.push(chunk);
        }
        try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
        catch { throw new BrowserError(400, 'Invalid JSON.'); }
      }
      const current = chain.then(() => dispatch(req, res, body));
      chain = current.catch(() => {});
      json(200, await current);
    } catch (error) {
      const status = error instanceof BrowserError ? error.status : 503;
      json(status, { mode: 'SYNTHETIC_ONLY', error: error instanceof BrowserError ? error.message : 'The local proof could not confirm this operation.' });
    } finally { if (admitted) pendingRequests -= 1; }
  };
  const server = tls ? createSecureServer({ key: tls.key, cert: tls.cert, minVersion: 'TLSv1.2' }, handler) : createServer(handler);
  server.headersTimeout = 5000; server.requestTimeout = 12000;
  return {
    async listen(port = 8100) {
      if (closing) throw new Error('Local service is closing.');
      if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('Invalid local port.');
      if (tls && port !== tls.port) throw new Error('The exact configured synthetic HTTPS port is required.');
      if (cancelListen || server.listening) throw new Error('Local service is already starting or listening.');
      return new Promise((resolve, reject) => {
        let settled = false;
        const settle = (error) => {
          if (settled) return;
          settled = true; cancelListen = undefined;
          server.off('error', onError); server.off('listening', onListening);
          if (error) reject(error);
          else resolve(tls?.origin ?? `http://127.0.0.1:${server.address().port}`);
        };
        const onError = (error) => settle(error);
        const onListening = () => settle();
        // Native close can suppress the listening callback. Settle our caller
        // explicitly, and detach both listeners on every completion path.
        cancelListen = () => settle(new Error('Local service is closing.'));
        server.once('error', onError); server.once('listening', onListening);
        try { server.listen(port, '127.0.0.1'); } catch (error) { settle(error); }
      });
    },
    close() {
      if (closePromise) return closePromise;
      closing = true;
      let resolveClose; let rejectClose;
      // Publish before any injected cancellation: a throw or re-entrant close
      // must neither leave the listener open nor repeat ownership/cleanup work.
      closePromise = new Promise((resolve, reject) => { resolveClose = resolve; rejectClose = reject; });
      let cleanupFailed = false;
      // Revoke ALL local authority immediately, before native listeners or
      // queued APIs drain. Already-started adapter effects cannot be undone.
      for (const session of sessions.values()) {
        try { forget(session); } catch { cleanupFailed = true; }
      }
      try { cancelListen?.(); } catch { cleanupFailed = true; }
      (async () => {
        try {
          await new Promise((resolve, reject) => server.close((error) => {
            if (error && error.code !== 'ERR_SERVER_NOT_RUNNING') reject(error); else resolve();
          }));
        } catch { cleanupFailed = true; }
        try { await chain; } catch { cleanupFailed = true; }
        const callbacks = await Promise.allSettled([...callbackRequests]);
        if (callbacks.some(result => result.status === 'rejected')) cleanupFailed = true;
        for (const session of sessions.values()) {
          try { forget(session); } catch { cleanupFailed = true; }
        }
        if (cleanupFailed) throw new Error('Local browser closure was not fully confirmed.');
      })().then(resolveClose, rejectClose);
      return closePromise;
    },
  };
}
