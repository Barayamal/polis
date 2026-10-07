/** TEST SUPPORT ONLY. Actual loopback HTTPS redirect protocol with invented identities.
 * Logical .invalid hosts are mapped only inside this explicit request adapter.
 * No DNS, hosts-file, global trust, real browser engine or production provider setup.
 */
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readFileSync, rmdirSync, unlinkSync } from 'node:fs';
import { createServer as createHttpsServer, request as httpsRequest } from 'node:https';
import { connect, createServer as createTcpServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createIdentityFoundation } from './identity.mjs';
import { createSyntheticIdentityHarness } from './synthetic-harness.mjs';

const ISSUER_HOST = 'identity.issuer.invalid';
const BROWSER_HOST = 'browser.example.invalid';
const MAX_BYTES = 65_536;
const APP_PATHS = new Set(['/', '/app.js', '/style.css', '/oidc/callback',
  '/api/session', '/api/login', '/api/oidc/start', '/api/oidc/callback',
  '/api/registration', '/api/registration/receipt', '/api/redeem', '/api/logout',
  '/api/participation-init', '/api/next-comment', '/api/votes']);
const reject = () => new Error('Synthetic HTTPS redirect lab rejected.');
const escapeAttribute = (value) => value.replace(/[&<>"']/gu, (character) =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);

function certificate(host) {
  const directory = mkdtempSync(join(tmpdir(), 'fncp-redirect-tls-'));
  const keyPath = join(directory, 'generated-key.pem');
  const certPath = join(directory, 'generated-certificate.pem');
  try {
    chmodSync(directory, 0o700);
    const result = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt',
      'ec_paramgen_curve:prime256v1', '-noenc', '-days', '1', '-subj', `/CN=${host}`,
      '-addext', `subjectAltName=DNS:${host}`, '-keyout', keyPath, '-out', certPath],
    { stdio: ['ignore', 'pipe', 'pipe'], timeout: 10_000, maxBuffer: 8192 });
    if (result.error || result.status !== 0) throw reject();
    chmodSync(keyPath, 0o600); chmodSync(certPath, 0o600);
    return { key: readFileSync(keyPath), cert: readFileSync(certPath) };
  } finally {
    // Delete only this invocation's two fresh generated files and exact temp directory.
    for (const path of [keyPath, certPath]) {
      try { unlinkSync(path); } catch (error) { if (error.code !== 'ENOENT') throw reject(); }
    }
    rmdirSync(directory);
  }
}

async function reservePort() {
  const server = createTcpServer();
  await new Promise((resolve, rejectPromise) => {
    server.once('error', rejectPromise); server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  return { port, release: () => new Promise((resolve, rejectPromise) =>
    server.close((error) => error ? rejectPromise(error) : resolve())) };
}

async function verifyClosed(port) {
  await new Promise((resolve, rejectPromise) => {
    const socket = connect({ host: '127.0.0.1', port });
    socket.setTimeout(500);
    socket.once('connect', () => { socket.destroy(); rejectPromise(reject()); });
    socket.once('timeout', () => { socket.destroy(); rejectPromise(reject()); });
    socket.once('error', (error) => {
      socket.destroy(); error.code === 'ECONNREFUSED' ? resolve() : rejectPromise(reject());
    });
  });
}

/** No caller-selectable host, issuer, claims, CA, credential, fixed port or remote transport. */
export async function createRedirectTlsLab(...args) {
  if (args.length) throw reject();
  return createTlsLab(false);
}

/** Separate fixed test mode: commit an invented issuer document before the
 * browser clicks its callback link. No browser headers or cookies are fabricated.
 */
export async function createDocumentRedirectTlsLab(...args) {
  if (args.length) throw reject();
  return createTlsLab(true);
}

/** Fixed two-account proof only. First valid authorization is invented A,
 * second is invented B; further authorizations are rejected. No account selector
 * or caller-provided claims, credentials, callback, certificate or transport.
 */
export async function createTwoAccountDocumentRedirectTlsLab(...args) {
  if (args.length) throw reject();
  return createTlsLab(true, 2);
}

async function createTlsLab(committedIssuerDocument, fixedInventedAccountCount = 1) {
  const issuerCredentials = certificate(ISSUER_HOST);
  const browserCredentials = certificate(BROWSER_HOST);
  const browserReservation = await reservePort();
  const browserPort = browserReservation.port;
  const browserOrigin = `https://${BROWSER_HOST}:${browserPort}`;
  const callbackUri = `${browserOrigin}/oidc/callback`;
  const counts = { authorize: 0, token: 0, jwks: 0, rejectedIssuerRequests: 0,
    clientRequests: 0, tlsAuthorized: 0, tlsErrors: 0 };
  const sockets = new Set();
  let stopped = false; let listenersClosed = false; let closePromise; let harness; let issuer;
  const server = createHttpsServer({ ...issuerCredentials, minVersion: 'TLSv1.2' }, async (req, res) => {
    req.on('error', () => {}); res.on('error', () => {});
    const deny = () => {
      counts.rejectedIssuerRequests += 1;
      if (!res.destroyed && !res.headersSent) {
        res.writeHead(400, { 'content-type': 'application/json', 'cache-control': 'no-store',
          'referrer-policy': 'no-referrer' }); res.end('{}');
      } else res.destroy();
    };
    try {
      if (stopped || !harness || req.socket.remoteAddress !== '127.0.0.1'
        || req.headers.host !== new URL(issuer).host || !req.url?.startsWith('/')
        || /[\\#]/u.test(req.url)) throw reject();
      const url = new URL(req.url, issuer);
      if (url.origin !== new URL(issuer).origin || url.username || url.password || url.hash) throw reject();
      const endpoint = req.method === 'GET' && url.pathname === '/authorize' ? 'authorize'
        : req.method === 'POST' && req.url === '/token' ? 'token'
          : req.method === 'GET' && req.url === '/jwks' ? 'jwks' : undefined;
      if (!endpoint) throw reject();
      let size = 0; const chunks = [];
      for await (const chunk of req) {
        size += chunk.length; if (size > MAX_BYTES) throw reject(); chunks.push(chunk);
      }
      if (req.method === 'GET' && size) throw reject();
      if (endpoint === 'authorize') {
        const keys = [...url.searchParams.keys()];
        const allowed = new Set(['client_id', 'redirect_uri', 'response_type', 'response_mode',
          'scope', 'code_challenge', 'code_challenge_method', 'state', 'nonce']);
        if (keys.length !== allowed.size || new Set(keys).size !== keys.length
          || keys.some((key) => !allowed.has(key)) || url.searchParams.get('scope') !== 'openid email'
          || !['state', 'nonce', 'code_challenge'].every((key) => /^[A-Za-z0-9_-]{32,128}$/u.test(url.searchParams.get(key)))) {
          throw reject();
        }
        // Claims cannot be supplied over HTTP. The dedicated two-account lab
        // follows a fixed sequence and refuses a third authorization outright.
        if (fixedInventedAccountCount === 2 && counts.authorize >= 2) throw reject();
        const location = fixedInventedAccountCount === 2 && counts.authorize === 1
          ? harness.authorizationResponse(url.href, { claims: { sub: 'invented-subject-2', email: 'invented-two@example.invalid' } })
          : harness.authorizationResponse(url.href);
        counts.authorize += 1;
        if (committedIssuerDocument) {
          // An actual committed issuer page creates an issuer-site initiator.
          // Immediate HTTP redirects intentionally remain the separate default
          // mode: their original app-site initiator can retain Strict cookies.
          const callback = new URL(location);
          if (callback.origin + callback.pathname !== callbackUri || callback.hash
            || callback.username || callback.password
            || [...callback.searchParams.keys()].sort().join(',') !== 'code,iss,state'
            || callback.searchParams.get('state') !== url.searchParams.get('state')
            || callback.searchParams.get('iss') !== issuer
            || !/^[A-Za-z0-9_-]{43}$/u.test(callback.searchParams.get('code'))) throw reject();
          res.writeHead(200, { 'cache-control': 'no-store', 'referrer-policy': 'no-referrer',
            'content-type': 'text/html; charset=utf-8', 'x-content-type-options': 'nosniff',
            'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'" });
          res.end('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            + '<title>Invented sign-in — local test only</title></head><body>'
            + '<h1>Invented sign-in</h1><p>Local test only. No real identity or heritage verification.</p>'
            + `<a id="continue-invented" href="${escapeAttribute(callback.href)}">Continue invented sign-in</a>`
            + '</body></html>');
          return;
        }
        res.writeHead(303, { location, 'cache-control': 'no-store', 'referrer-policy': 'no-referrer',
          'content-type': 'text/plain; charset=utf-8' }); res.end(''); return;
      }
      counts[endpoint] += 1;
      const response = await harness.options.transport.fetch(`${issuer}${endpoint}`, {
        method: req.method, headers: req.headers, redirect: 'error', credentials: 'omit',
        ...(endpoint === 'token' ? { body: Buffer.concat(chunks).toString('utf8') } : {}),
      });
      res.writeHead(response.status, { ...Object.fromEntries(response.headers), 'cache-control': 'no-store' });
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch { deny(); }
  });
  server.on('connection', (socket) => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  server.on('tlsClientError', () => { counts.tlsErrors += 1; });
  server.requestTimeout = 3000; server.headersTimeout = 3000;
  try {
    await new Promise((resolve, rejectPromise) => {
      server.once('error', rejectPromise); server.listen(0, '127.0.0.1', resolve);
    });
  } finally {
    // Keep the reservation until the issuer has a different port. The caller's
    // later browser bind must fail safely if another process wins this freed port.
    await browserReservation.release();
  }
  const issuerPort = server.address().port;
  issuer = `https://${ISSUER_HOST}:${issuerPort}/`;
  const authorizationEndpoint = `${issuer}authorize`;
  const tokenEndpoint = `${issuer}token`; const jwksUri = `${issuer}jwks`;
  const close = () => {
    if (closePromise) return closePromise;
    stopped = true;
    closePromise = (async () => {
      const closed = new Promise((resolve, rejectPromise) => server.close((error) => error ? rejectPromise(reject()) : resolve()));
      for (const socket of sockets) socket.destroy();
      await closed; await verifyClosed(issuerPort); listenersClosed = true;
    })();
    return closePromise;
  };

  function request(input, options = {}) {
    let url; let method; let headers; let body; let target;
    try {
      if (stopped || !options || Object.getPrototypeOf(options) !== Object.prototype
        || Object.keys(options).some((key) => !['method', 'headers', 'body'].includes(key))) throw reject();
      if (typeof input !== 'string' && !(input instanceof URL)) throw reject();
      const raw = String(input); url = new URL(raw);
      if (url.href !== raw || url.username || url.password || url.hash || url.protocol !== 'https:'
        || /[\\]/u.test(raw)) throw reject();
      method = options.method ?? 'GET';
      if (!['GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'DELETE'].includes(method)) throw reject();
      if (url.origin === new URL(issuer).origin && ['/authorize', '/token', '/jwks'].includes(url.pathname)) {
        target = { host: ISSUER_HOST, port: issuerPort, cert: issuerCredentials.cert, maxBytes: MAX_BYTES };
        if (url.search && url.pathname !== '/authorize') throw reject();
      } else if (url.origin === browserOrigin && APP_PATHS.has(url.pathname)) {
        target = { host: BROWSER_HOST, port: browserPort, cert: browserCredentials.cert, maxBytes: 512 * 1024 };
        if (url.search && url.pathname !== '/oidc/callback') throw reject();
      } else throw reject();
      headers = new Headers(options.headers);
      if ([...headers.keys()].length > 32 || [...headers].some(([name, value]) =>
        ['host', 'connection', 'transfer-encoding', 'content-length'].includes(name) || value.length > 16_384)) throw reject();
      body = options.body === undefined ? undefined : typeof options.body === 'string' ? options.body
        : options.body instanceof URLSearchParams ? options.body.toString() : null;
      if (body === null || (body !== undefined && (Buffer.byteLength(body) > MAX_BYTES
        || ['GET', 'HEAD'].includes(method)))) throw reject();
    } catch { return Promise.reject(reject()); }
    return new Promise((resolve, rejectPromise) => {
      let settled = false; let req; let response;
      const finish = (error, result) => {
        if (settled) return; settled = true; clearTimeout(timer);
        if (error) { response?.destroy(); req?.destroy(); rejectPromise(reject()); } else resolve(result);
      };
      const timer = setTimeout(() => finish(reject()), 3000);
      counts.clientRequests += 1;
      try {
        req = httpsRequest({ hostname: '127.0.0.1', port: target.port, path: url.pathname + url.search,
          method, servername: target.host, ca: target.cert, rejectUnauthorized: true,
          minVersion: 'TLSv1.2', agent: false,
          // Default Node SAN verification uses fixed SNI. No insecure checkServerIdentity override.
          headers: { ...Object.fromEntries(headers), host: url.host, connection: 'close',
            ...(body === undefined ? {} : { 'content-length': Buffer.byteLength(body) }) },
        }, (res) => {
          response = res;
          if (req.socket.remoteAddress !== '127.0.0.1' || req.socket.authorized !== true) return finish(reject());
          counts.tlsAuthorized += 1;
          let size = 0; const chunks = [];
          res.on('data', (chunk) => { size += chunk.length;
            if (size > target.maxBytes) return finish(reject()); chunks.push(chunk); });
          res.on('aborted', () => finish(reject())); res.on('error', () => finish(reject()));
          res.on('end', () => {
            if (!res.complete) return finish(reject());
            // No redirect following. Preserve Set-Cookie as an array for protocol test cookie jars.
            const responseHeaders = Object.fromEntries(Object.entries(res.headers).map(([key, value]) =>
              [key, Array.isArray(value) ? Object.freeze([...value]) : value]));
            finish(null, Object.freeze({ status: res.statusCode, headers: Object.freeze(responseHeaders),
              body: Buffer.concat(chunks).toString('utf8') }));
          });
        });
        req.on('error', () => finish(reject()));
        if (body !== undefined) req.write(body); req.end();
      } catch { finish(reject()); }
    });
  }

  try {
    harness = await createSyntheticIdentityHarness({ issuer, callbackUri });
    const transport = Object.freeze({ kind: 'SYNTHETIC_INTERCEPT', fetch: async (input, init = {}) => {
      const url = String(input); const method = init.method ?? 'GET';
      if (!((url === tokenEndpoint && method === 'POST') || (url === jwksUri && method === 'GET'))
        || init.redirect !== 'error' || init.credentials !== 'omit' || init.signal?.aborted) throw reject();
      const result = await request(url, { method, headers: init.headers,
        ...(init.body === undefined ? {} : { body: init.body }) });
      return new Response(result.body, { status: result.status, headers: result.headers });
    } });
    const identity = createIdentityFoundation({ ...harness.options, transport });
    return Object.freeze({ identity, authorizationEndpoint, callbackUri, browserPort,
      // Public test certificates only. A caller may bootstrap an isolated,
      // disposable browser profile; never install these in an OS/global store.
      // Fresh copies prevent an importer from mutating the lab's TLS material.
      publicTestCertificates: () => [Buffer.from(browserCredentials.cert), Buffer.from(issuerCredentials.cert)],
      browserTls: Object.freeze({ mode: 'SYNTHETIC_HTTPS_REDIRECT', origin: browserOrigin,
        key: browserCredentials.key, cert: browserCredentials.cert }), request, close,
      summary: () => Object.freeze({ mode: 'SYNTHETIC_ONLY', actualLoopbackTls: true,
        committedIssuerDocument, fixedInventedAccountCount,
        logicalEndpointInterception: true, realIdentityProvider: false, realBrowserEngineTested: false,
        globalTrustChanged: false, productionReady: false, ...counts, listenersClosed }),
    });
  } catch { await close(); throw reject(); }
}
