import { createServer } from 'node:https';
import { createHash, randomBytes, timingSafeEqual, X509Certificate, createPrivateKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { isIP } from 'node:net';
import { isProductionIdentityAdapter } from '../production-identity/identity.mjs';
import { isProductionAccess } from './access.mjs';

const SESSION = '__Host-fncp-session';
const TRANSACTION = '__Host-fncp-transaction';
const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const REGISTRATION = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const MAX_STATE = 128;
const MAX_OPERATIONS = 32;
const ANONYMOUS_MS = 600_000;
const TRANSACTION_MS = 300_000;
const BODY_MS = 5000;
const ownedIdentities = new WeakSet();
const ownedAccesses = new WeakSet();
const ASSETS = new Map([
  ['/', ['text/html; charset=utf-8', readFileSync(new URL('./public/index.html', import.meta.url))]],
  ['/app.js', ['text/javascript; charset=utf-8', readFileSync(new URL('./public/app.js', import.meta.url))]],
  ['/style.css', ['text/css; charset=utf-8', readFileSync(new URL('./public/style.css', import.meta.url))]],
]);
const ROUTES = new Map([
  ['/', 'GET'], ['/app.js', 'GET'], ['/style.css', 'GET'], ['/health', 'GET'],
  ['/session', 'GET'], ['/oidc/login', 'POST'], ['/oidc/callback', 'GET'],
  ['/registration', 'POST'], ['/invitations/redeem', 'POST'],
  ['/polis/participation-init', 'GET'], ['/polis/next-comment', 'GET'], ['/polis/votes', 'POST'],
  ['/session/logout', 'POST'],
]);
const random = () => randomBytes(32).toString('base64url');
const digest = value => createHash('sha256').update(value).digest();
const equal = (a, b) => typeof a === 'string' && typeof b === 'string'
  && timingSafeEqual(digest(a), digest(b));
const failure = (status = 403) => Object.assign(new Error('Browser operation unavailable.'), { status });
const configurationFailure = () => new Error('Production browser configuration rejected.');

function fields(value, required, optional = []) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw failure(400);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (required.some(key => !keys.includes(key)) || keys.some(key => ![...required, ...optional].includes(key))) throw failure(400);
  const result = Object.create(null);
  for (const key of keys) {
    if (!Object.hasOwn(descriptors[key], 'value')) throw failure(400);
    result[key] = descriptors[key].value;
  }
  return result;
}

function capture(instance, names) {
  if (!Object.isFrozen(instance)) throw configurationFailure();
  return Object.fromEntries(names.map(name => {
    const descriptor = Object.getOwnPropertyDescriptor(instance, name);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'function') throw configurationFailure();
    return [name, descriptor.value.bind(instance)];
  }));
}

function publicStatus(value) {
  const x = fields(value, ['authenticated', 'registrationState', 'registrationReference', 'participantAccessGranted', 'roundOpen']);
  if (x.authenticated !== true || !['unregistered', 'unconfirmed', 'pending', 'approved', 'revoked'].includes(x.registrationState)
    || (['unregistered', 'unconfirmed'].includes(x.registrationState) ? x.registrationReference !== null
      : typeof x.registrationReference !== 'string' || !REGISTRATION.test(x.registrationReference))
    || x.participantAccessGranted !== false || typeof x.roundOpen !== 'boolean') throw failure(503);
  return { authenticated: true, registrationState: x.registrationState, registrationReference: x.registrationReference,
    participantAccessGranted: false, roundOpen: x.roundOpen };
}

function publicNotice(value) {
  const x = fields(value, ['consentVersion', 'noticeSha256', 'adultDeclaration', 'eligibilityDeclaration', 'registrationDeclaration']);
  if (typeof x.consentVersion !== 'string' || !/^[A-Za-z0-9._-]{1,128}$/u.test(x.consentVersion)
    || !/^[0-9a-f]{64}$/u.test(x.noticeSha256)
    || ['adultDeclaration', 'eligibilityDeclaration', 'registrationDeclaration'].some(key =>
      typeof x[key] !== 'string' || !x[key].trim() || Buffer.byteLength(x[key]) > 12_000)) throw configurationFailure();
  const declarations = { adultDeclaration: x.adultDeclaration, eligibilityDeclaration: x.eligibilityDeclaration,
    registrationDeclaration: x.registrationDeclaration };
  if (createHash('sha256').update(JSON.stringify(declarations)).digest('hex') !== x.noticeSha256) throw configurationFailure();
  return Object.freeze({ consentVersion: x.consentVersion, noticeSha256: x.noticeSha256, ...declarations });
}

function publicParticipation(value) {
  const x = fields(value, ['statement', 'complete']);
  if (typeof x.complete !== 'boolean' || x.complete !== (x.statement === null)) throw failure(503);
  if (x.statement === null) return { statement: null, complete: true };
  const statement = fields(x.statement, ['tid', 'text']);
  if (!Number.isSafeInteger(statement.tid) || statement.tid < 0 || typeof statement.text !== 'string'
    || statement.text.length < 1 || Buffer.byteLength(statement.text) > 10_000) throw failure(503);
  return { statement: { tid: statement.tid, text: statement.text }, complete: false };
}

function cookie(name, value, maxAge = 0) {
  return `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=${name === TRANSACTION ? 'Lax' : 'Strict'}; Max-Age=${maxAge}`;
}

function parseCookies(req) {
  const raw = req.headers.cookie;
  const result = Object.create(null);
  if (raw === undefined) return result;
  if (typeof raw !== 'string' || raw.length > 2048) throw failure();
  for (const segment of raw.split(';')) {
    const pair = segment.trim().split('=');
    if (pair.length !== 2 || ![SESSION, TRANSACTION].includes(pair[0]) || Object.hasOwn(result, pair[0])
      || !TOKEN.test(pair[1])) throw failure();
    result[pair[0]] = pair[1];
  }
  return result;
}

function body(req) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0; let settled = false;
    const finish = (error, value) => {
      if (settled) return; settled = true; clearTimeout(timer);
      req.removeListener('data', data); req.removeListener('end', end);
      req.removeListener('aborted', aborted); req.removeListener('error', aborted);
      if (error) { req.resume(); reject(error); } else resolve(value);
    };
    const data = chunk => { size += chunk.length; if (size > 4096) finish(failure(413)); else chunks.push(chunk); };
    const end = () => {
      try { if (!size) throw failure(400); finish(null, JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { finish(failure(400)); }
    };
    const aborted = () => finish(failure(400));
    const timer = setTimeout(() => finish(failure(408)), BODY_MS);
    timer.unref();
    req.on('data', data); req.once('end', end); req.once('aborted', aborted); req.once('error', aborted);
  });
}

/** A direct-TLS participant BFF. Its two branded dependencies are private,
 * process-owned capabilities. No request can replace either dependency or
 * select a principal, account, XID, provider header, activation or operator. */
export function createProductionBrowser(options) {
  let config; let id; let authority; let origin; let expectedHost; let tls; let registrationNotice;
  try {
    config = fields(options, ['origin', 'tls', 'identity', 'access'], ['host', 'port', 'now']);
    origin = new URL(config.origin);
    if (origin.protocol !== 'https:' || config.origin !== origin.origin || origin.username || origin.password
      || !isProductionIdentityAdapter(config.identity) || !isProductionAccess(config.access)
      || ownedIdentities.has(config.identity) || ownedAccesses.has(config.access)) throw configurationFailure();
    expectedHost = origin.host;
    tls = fields(config.tls, ['key', 'cert']);
    if (!(tls.key instanceof Uint8Array) || !(tls.cert instanceof Uint8Array)
      || tls.key.length > 32_768 || tls.cert.length > 65_536) throw configurationFailure();
    const certificate = new X509Certificate(tls.cert);
    const hostname = origin.hostname.replace(/^\[|\]$/gu, '');
    if (!certificate.checkPrivateKey(createPrivateKey(tls.key))
      || !(isIP(hostname) ? certificate.checkIP(hostname) : certificate.checkHost(hostname, { subject: 'never' }))) throw configurationFailure();
    id = capture(config.identity, ['begin', 'complete', 'discard', 'isVerifiedPrincipal', 'principalDeadline', 'close']);
    authority = capture(config.access, ['authenticate', 'register', 'registrationNotice', 'status', 'redeem', 'participate', 'logout', 'closeAdmission', 'close']);
    registrationNotice = publicNotice(authority.registrationNotice());
    config.host ??= '127.0.0.1'; config.port ??= Number(origin.port || 443); config.now ??= Date.now;
    if (typeof config.host !== 'string' || !isIP(config.host) || !Number.isInteger(config.port)
      || config.port < 0 || config.port > 65535 || typeof config.now !== 'function') throw configurationFailure();
  } catch { throw configurationFailure(); }

  const sessions = new Map(); const transactions = new Map(); const operations = new Set(); const sockets = new Set();
  let lastNow = -1; let closed = false; let closingReason = null; let phase = 'CREATED';
  let startAttempted = false; let startPromise; let closePromise; let closeError = false; let listenerPort; let constructed = false;

  function denyAll(reason) {
    if (closed) return;
    closed = true; closingReason = reason;
    // Publish denial before invoking dependencies. No pending completion may
    // replace a session after this point, even if a provider write has occurred.
    sessions.clear(); transactions.clear();
    try { authority.closeAdmission(); } catch { closeError = true; }
    try { id.close(); } catch { closeError = true; }
  }
  function instant() {
    try {
      const value = config.now();
      if (!Number.isSafeInteger(value) || value < 0 || value < lastNow) throw failure(503);
      lastNow = value;
      if (closed) throw failure(503);
      return value;
    } catch {
      denyAll('CLOCK_OR_CLOSURE');
      if (constructed && !closePromise) queueMicrotask(() => { void close().catch(() => {}); });
      throw failure(503);
    }
  }
  try { instant(); } catch { throw configurationFailure(); }

  function live(session, token, requirePrincipal = true) {
    const current = instant();
    if (!session || sessions.get(token) !== session || session.expiresAt <= current) {
      if (session) sessions.delete(token); throw failure(401);
    }
    if (requirePrincipal && (!session.principal || !id.isVerifiedPrincipal(session.principal))) {
      sessions.delete(token); throw failure(401);
    }
    return session;
  }
  function prune() {
    const current = instant();
    for (const [token, session] of sessions) if (session.expiresAt <= current) sessions.delete(token);
    for (const [token, transaction] of transactions) if (transaction.expiresAt <= current) {
      transactions.delete(token); id.discard({ browserSessionId: transaction.binding });
    }
  }
  function capacity() { prune(); if (sessions.size + transactions.size >= MAX_STATE) throw failure(503); }
  function newSession(principal) {
    const current = instant(); capacity();
    const deadline = principal ? id.principalDeadline(principal) : current + ANONYMOUS_MS;
    if (!Number.isSafeInteger(deadline) || deadline <= current || (principal && !id.isVerifiedPrincipal(principal))) throw failure(401);
    const token = random();
    const session = { csrf: random(), expiresAt: deadline, principal, grant: null, displayedTid: null, busy: false };
    sessions.set(token, session); return { token, session };
  }
  function currentTransaction(token, transaction) {
    const current = instant();
    if (!transaction || transactions.get(token) !== transaction || transaction.expiresAt <= current) throw failure(401);
  }
  function reply(res, status, value, extra = {}) {
    if (res.destroyed || res.writableEnded) return;
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', ...extra });
    res.end(JSON.stringify(value));
  }
  const securityHeaders = {
    'cache-control': 'no-store', 'pragma': 'no-cache', 'referrer-policy': 'no-referrer',
    'content-security-policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    'strict-transport-security': 'max-age=31536000', 'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY', 'permissions-policy': 'camera=(), microphone=(), geolocation=()',
    'cross-origin-resource-policy': 'same-origin', 'cross-origin-opener-policy': 'same-origin',
  };
  function metadata(req, path) {
    const raw = req.rawHeaders;
    const counts = new Map();
    for (let i = 0; i < raw.length; i += 2) { const name = raw[i].toLowerCase(); counts.set(name, (counts.get(name) ?? 0) + 1); }
    const sensitive = ['host', 'origin', 'cookie', 'content-type', 'content-length', 'transfer-encoding', 'x-csrf-token', 'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-dest', 'sec-fetch-user'];
    if (sensitive.some(name => (counts.get(name) ?? 0) > 1) || req.headers.host !== expectedHost || !req.socket.encrypted
      || Object.keys(req.headers).some(name => name === 'forwarded' || name.startsWith('x-forwarded-')
        || name === 'authorization' || name.startsWith('x-fncp-'))
      || req.headers['content-encoding'] !== undefined) throw failure();
    if (req.method === 'GET' && (req.headers['transfer-encoding'] || Number(req.headers['content-length'] ?? 0) !== 0)) throw failure(400);
    if (req.method === 'POST' && (!/^application\/json(?:; charset=utf-8)?$/iu.test(req.headers['content-type'] ?? '')
      || (req.headers['content-length'] !== undefined && (!/^[0-9]+$/u.test(req.headers['content-length']) || Number(req.headers['content-length']) > 4096)))) throw failure(400);
    const site = req.headers['sec-fetch-site']; const mode = req.headers['sec-fetch-mode']; const dest = req.headers['sec-fetch-dest'];
    if (path === '/oidc/callback') {
      if (req.headers.origin !== undefined || !['cross-site', 'same-site', 'same-origin', 'none'].includes(site)
        || mode !== 'navigate' || dest !== 'document' || (req.headers['sec-fetch-user'] !== undefined && req.headers['sec-fetch-user'] !== '?1')) throw failure();
    } else if (ASSETS.has(path)) {
      if (req.headers.origin !== undefined && req.headers.origin !== origin.origin) throw failure();
      // A successful OIDC callback redirects to the public document. Real
      // browsers retain cross-site metadata through that navigation chain.
      // Only this safe top-level document may use that metadata; private
      // endpoints and script/style fetches keep their stricter policies.
      const topLevelDocument = path === '/' && mode === 'navigate' && dest === 'document';
      const allowedSites = topLevelDocument ? ['none', 'same-origin', 'same-site', 'cross-site'] : ['none', 'same-origin'];
      if (!allowedSites.includes(site) || !['navigate', 'no-cors', 'cors', 'same-origin'].includes(mode)
        || !['document', 'script', 'style', 'empty'].includes(dest)) throw failure();
    } else if (path !== '/health') {
      if (site !== 'same-origin' || !['cors', 'same-origin'].includes(mode) || dest !== 'empty'
        || (req.method === 'POST' ? req.headers.origin !== origin.origin : req.headers.origin !== undefined && req.headers.origin !== origin.origin)) throw failure();
    }
  }

  async function dispatch(req, res) {
    instant();
    if (typeof req.url !== 'string' || req.url.length > 4096 || !req.url.startsWith('/') || req.url.startsWith('//')
      || /[\\\x00-\x20#]/u.test(req.url)) throw failure(400);
    const url = new URL(req.url, origin);
    const path = url.pathname;
    if (path.includes('%') || req.url.split('?')[0] !== path
      || (path !== '/oidc/callback' && req.url.includes('?')) || url.origin !== origin.origin) throw failure(400);
    if (ROUTES.get(path) !== req.method) throw failure(404);
    metadata(req, path);
    if (ASSETS.has(path)) {
      const [contentType, content] = ASSETS.get(path); res.writeHead(200, { 'content-type': contentType }); res.end(content); return;
    }
    if (path === '/health') { reply(res, 200, { ok: true, profile: 'PARTICIPANT_HTTPS_BFF_V1', participantAccessGranted: false }); return; }
    const cookies = parseCookies(req);
    let token = cookies[SESSION]; let session = sessions.get(token);
    if (path === '/oidc/callback') {
      const transactionToken = cookies[TRANSACTION]; const transaction = transactions.get(transactionToken);
      currentTransaction(transactionToken, transaction);
      if (transaction.used) throw failure(401);
      transaction.used = true;
      res.setHeader('set-cookie', [cookie(TRANSACTION, ''), cookie(SESSION, '')]);
      try {
        const result = await id.complete({ browserSessionId: transaction.binding, callbackUrl: url.href });
        currentTransaction(transactionToken, transaction);
        if (result?.ok !== true || !id.isVerifiedPrincipal(result.principal)) throw failure(401);
        publicStatus(await authority.authenticate(result.principal));
        currentTransaction(transactionToken, transaction);
        if (!id.isVerifiedPrincipal(result.principal)) throw failure(401);
        transactions.delete(transactionToken);
        const created = newSession(result.principal);
        res.setHeader('set-cookie', [cookie(TRANSACTION, ''), cookie(SESSION, created.token,
          Math.floor((created.session.expiresAt - instant()) / 1000))]);
        // The callback query is never reflected into an error or application URL.
        res.writeHead(303, { location: '/' }); res.end();
      } finally {
        if (transactions.get(transactionToken) === transaction) transactions.delete(transactionToken);
        id.discard({ browserSessionId: transaction.binding });
      }
      return;
    }
    if (path === '/session') {
      prune();
      if (!session || sessions.get(token) !== session) {
        ({ token, session } = newSession(null)); res.setHeader('set-cookie', cookie(SESSION, token, ANONYMOUS_MS / 1000));
      }
      live(session, token, false);
      if (!session.principal) {
        reply(res, 200, { authenticated: false, registrationState: 'unregistered', registrationReference: null, participantAccessGranted: false,
          roundOpen: false, csrf: session.csrf, participationSession: false, registrationNotice }); return;
      }
      live(session, token);
      const status = publicStatus(await authority.status(session.principal)); live(session, token);
      if (status.registrationState !== 'approved' || !status.roundOpen) { session.grant = null; session.displayedTid = null; }
      reply(res, 200, { ...status, csrf: session.csrf, participationSession: session.grant !== null, registrationNotice }); return;
    }
    live(session, token, !['/oidc/login', '/session/logout'].includes(path));
    // Require a server-issued synchronizer on every private request, including
    // GET participation calls, whose upstream initialization can create rows.
    if (!equal(req.headers['x-csrf-token'], session.csrf)) throw failure();
    if (path === '/session/logout') {
      fields(await body(req), []); live(session, token, false);
      // Negative authority precedes an awaited backend logout; no late request
      // can put its grant or statement back into this removed session.
      sessions.delete(token);
      const transaction = transactions.get(cookies[TRANSACTION]);
      if (transaction) { transactions.delete(cookies[TRANSACTION]); id.discard({ browserSessionId: transaction.binding }); }
      res.setHeader('set-cookie', [cookie(SESSION, ''), cookie(TRANSACTION, '')]);
      if (session.principal) await authority.logout(session.principal);
      reply(res, 200, { ok: true, authenticated: false, participantAccessGranted: false }); return;
    }
    if (session.busy) throw failure(409);
    session.busy = true;
    try {
      if (path === '/oidc/login') {
        fields(await body(req), []); live(session, token, false);
        if (session.principal) throw failure(409);
        const previous = transactions.get(cookies[TRANSACTION]);
        if (previous) { transactions.delete(cookies[TRANSACTION]); id.discard({ browserSessionId: previous.binding }); }
        sessions.delete(token); capacity();
        const transactionToken = random(); const transaction = { binding: random(), expiresAt: instant() + TRANSACTION_MS, used: false };
        transactions.set(transactionToken, transaction);
        try {
          const result = await id.begin({ browserSessionId: transaction.binding });
          currentTransaction(transactionToken, transaction);
          if (result?.ok !== true) throw failure(401);
          const target = new URL(result.authorizationUrl);
          if (target.protocol !== 'https:' || target.username || target.password || target.hash
            || target.searchParams.get('redirect_uri') !== `${origin.origin}/oidc/callback`) throw failure(503);
          res.setHeader('set-cookie', [cookie(SESSION, ''), cookie(TRANSACTION, transactionToken, TRANSACTION_MS / 1000)]);
          reply(res, 200, { authorizationUrl: target.href });
        } catch {
          if (transactions.get(transactionToken) === transaction) transactions.delete(transactionToken);
          id.discard({ browserSessionId: transaction.binding }); throw failure(401);
        }
        return;
      }
      if (path === '/registration') {
        const values = fields(await body(req), ['consentVersion', 'adultSelfAttested', 'eligibilitySelfAttested', 'registrationConsent']);
        if (values.consentVersion !== registrationNotice.consentVersion
          || values.adultSelfAttested !== true || values.eligibilitySelfAttested !== true || values.registrationConsent !== true) throw failure(400);
        live(session, token);
        const status = publicStatus(await authority.register(session.principal, { ...values })); live(session, token);
        reply(res, 200, { ...status, csrf: session.csrf, participationSession: false, registrationNotice }); return;
      }
      if (path === '/invitations/redeem') {
        const values = fields(await body(req), ['invitationToken']);
        if (typeof values.invitationToken !== 'string' || !/^[A-Za-z0-9_-]{32,512}$/u.test(values.invitationToken)) throw failure(400);
        live(session, token);
        const grant = await authority.redeem(session.principal, values.invitationToken); live(session, token);
        if (!grant || typeof grant !== 'object' || !Object.isFrozen(grant)) throw failure(503);
        sessions.delete(token);
        const elevated = newSession(session.principal); elevated.session.grant = grant;
        res.setHeader('set-cookie', cookie(SESSION, elevated.token, Math.floor((elevated.session.expiresAt - instant()) / 1000)));
        reply(res, 200, { ok: true, participationSession: true, participantAccessGranted: false, csrf: elevated.session.csrf }); return;
      }
      const kind = { '/polis/participation-init': 'init', '/polis/next-comment': 'next', '/polis/votes': 'vote' }[path];
      if (!kind || !session.grant) throw failure(403);
      let values = {};
      if (kind === 'vote') {
        values = fields(await body(req), ['tid', 'vote']); live(session, token);
        if (!Number.isSafeInteger(values.tid) || values.tid < 0 || values.tid !== session.displayedTid || ![-1, 0, 1].includes(values.vote)) throw failure(400);
      }
      live(session, token);
      // Clear the displayed statement before any provider operation. An
      // uncertain vote cannot be retried by double-click or an automatic loop.
      session.displayedTid = null;
      const result = publicParticipation(await authority.participate(session.principal, session.grant, kind, { ...values }));
      live(session, token); session.displayedTid = result.statement?.tid ?? null;
      reply(res, 200, result);
    } finally { session.busy = false; }
  }

  const server = createServer({ key: tls.key, cert: tls.cert, minVersion: 'TLSv1.2',
    maxHeaderSize: 8192, requestTimeout: 12_000, headersTimeout: 5000 }, (req, res) => {
    req.on('error', () => {}); res.on('error', () => {});
    for (const [name, value] of Object.entries(securityHeaders)) res.setHeader(name, value);
    if (closed || phase !== 'RUNNING' || operations.size >= MAX_OPERATIONS) {
      res.setHeader('connection', 'close'); reply(res, 503, { error: 'Service unavailable. No automatic retry was made.' }); req.resume(); return;
    }
    // Reserve before reading a body or awaiting any capability.
    const operation = Promise.resolve().then(() => dispatch(req, res)).catch(error => {
      const status = [400, 401, 403, 404, 408, 409, 413].includes(error?.status) ? error.status : 503;
      const message = status === 404 ? 'Route unavailable.' : status === 401 ? 'Session ended. Sign in again.'
        : status === 409 ? 'Another operation is pending. No automatic retry was made.'
          : 'The outcome could not be confirmed. No automatic retry was made.';
      res.setHeader('connection', 'close'); reply(res, status, { error: message }); req.resume();
    }).finally(() => operations.delete(operation));
    operations.add(operation);
  });
  server.keepAliveTimeout = 1000; server.maxRequestsPerSocket = 32; server.maxConnections = 128;
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  server.on('tlsClientError', () => {});
  server.on('clientError', (_error, socket) => socket.destroy());
  server.on('error', () => {
    denyAll('LISTENER');
    if (constructed && !closePromise) queueMicrotask(() => { void close().catch(() => {}); });
  });
  constructed = true;
  ownedIdentities.add(config.identity); ownedAccesses.add(config.access);

  function close() {
    if (closePromise) return closePromise;
    denyAll('CLOSURE'); phase = 'CLOSING';
    let resolveClose; let rejectClose;
    closePromise = new Promise((resolve, reject) => { resolveClose = resolve; rejectClose = reject; });
    (async () => {
      // Wait for a started listen attempt to settle before closing the listener;
      // a close during startup therefore cannot leave a late listener behind.
      if (startPromise) await startPromise.catch(() => {});
      const stopped = server.listening ? new Promise(resolve => server.close(error => {
        if (error) closeError = true; resolve();
      })) : Promise.resolve();
      for (const socket of sockets) socket.destroy();
      await Promise.allSettled([...operations]);
      try { await authority.close(); } catch { closeError = true; }
      await stopped;
      phase = closeError ? 'FAILED' : 'CLOSED';
      if (closeError) throw failure(503);
      return Object.freeze({ closed: true, listenerClosed: !server.listening, pendingOperations: operations.size,
        sessionsCleared: sessions.size === 0, transactionsCleared: transactions.size === 0 });
    })().then(resolveClose, rejectClose);
    return closePromise;
  }
  async function start() {
    if (startAttempted || closed) throw failure(503);
    startAttempted = true; phase = 'STARTING'; instant();
    startPromise = new Promise((resolve, reject) => {
      const failed = () => { server.removeListener('listening', listening); reject(failure(503)); };
      const listening = () => { server.removeListener('error', failed); listenerPort = server.address().port; resolve(); };
      server.once('error', failed); server.once('listening', listening); server.listen(config.port, config.host);
    });
    try { await startPromise; instant(); phase = 'RUNNING'; return Object.freeze({ origin: origin.origin, port: listenerPort }); }
    catch { denyAll('STARTUP'); try { await close(); } catch {} throw failure(503); }
  }
  return Object.freeze({ start, close,
    snapshot() { return Object.freeze({ profile: 'PARTICIPANT_HTTPS_BFF_V1', phase, admissionClosed: closed,
      closingReason, listenerOpen: server.listening, pendingOperations: operations.size,
      sessions: sessions.size, transactions: transactions.size }); },
  });
}
