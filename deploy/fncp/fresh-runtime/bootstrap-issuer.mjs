/** Local synthetic bootstrap signing/JWKS capability only. Import performs no
 * I/O. This is NOT OIDC login, a real account, an email service, a container-
 * reachable identity topology, or production authentication. No caller chooses
 * claims, issuer, URLs, paths, keys, trust or deadlines. All returned credentials
 * and configuration are private handoffs; only summary() is aggregate-safe.
 */
import { spawnSync } from 'node:child_process';
import { generateKeyPair, createHash, randomBytes, sign } from 'node:crypto';
import { chmodSync, mkdtempSync, readFileSync, realpathSync, rmdirSync, unlinkSync } from 'node:fs';
import { createServer, request } from 'node:https';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { promisify } from 'node:util';

const AUDIENCE = 'fncp-fresh-synthetic-bootstrap';
const EMAIL = 'bootstrap-admin@bootstrap.example.invalid';
const LIFETIME_MS = 120_000;
const MAX_JWKS_BYTES = 4096;
const MAX_REQUESTS = 32;
const MAX_FETCHES = 8;
const MAX_CONNECTIONS = 8;
const JWKS_PATH = '/.well-known/jwks.json';
const failure = () => new Error('Local synthetic bootstrap issuer rejected; private details withheld.');
const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
const transportIssuers = new WeakMap();
const publicJwksIssuers = new WeakMap();
const apiTrustIssuers = new WeakMap();

/** Private, one-shot handoff to the HTTP adapter. Only a live capability from
 * this module is accepted, never a lookalike issuer/token supplied by callers.
 * Does not contact Pol.is or attest helper ownership/container reachability. */
export function claimBootstrapIssuerForTransport(issuer) {
  if (arguments.length !== 1 || !transportIssuers.has(issuer)) throw failure();
  return transportIssuers.get(issuer)();
}

/** Independent one-shot PUBLIC-ONLY handoff. The original branded issuer does
 * its existing verified local HTTPS fetch; neither signing key nor bearer is
 * released or minted. The signal observes that same issuer's close/expiry. */
export async function claimBootstrapIssuerPublicJwks(issuer) {
  if (arguments.length !== 1 || !publicJwksIssuers.has(issuer)) throw failure();
  return publicJwksIssuers.get(issuer)();
}

/** Separate one-shot PUBLIC-ONLY API role. Both public roles share the same
 * verified fetch, including its failure. This does not mint a token, extend the
 * original issuer lifetime, or grant a second JWKS-service claim. */
export async function claimBootstrapIssuerApiTrust(issuer) {
  if (arguments.length !== 1 || !apiTrustIssuers.has(issuer)) throw failure();
  return apiTrustIssuers.get(issuer)();
}

function freshCertificate() {
  const executable = process.platform === 'darwin' ? '/opt/homebrew/bin/openssl' :
    process.platform === 'linux' ? '/usr/bin/openssl' : undefined;
  if (!executable) throw failure();
  const directory = mkdtempSync(join(realpathSync(tmpdir()), 'fncp-bootstrap-tls-'));
  const keyPath = join(directory, 'generated-key.pem');
  const certPath = join(directory, 'generated-certificate.pem');
  try {
    chmodSync(directory, 0o700);
    const result = spawnSync(executable, ['req', '-x509', '-newkey', 'ec', '-pkeyopt',
      'ec_paramgen_curve:prime256v1', '-noenc', '-days', '1', '-subj', '/CN=127.0.0.1',
      '-addext', 'subjectAltName=IP:127.0.0.1', '-keyout', keyPath, '-out', certPath], {
      cwd: directory, shell: false, stdio: ['ignore', 'pipe', 'pipe'], timeout: 10_000, maxBuffer: 8192,
      env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C', OPENSSL_CONF: '/dev/null' },
    });
    if (result.error || result.status !== 0) throw failure();
    chmodSync(keyPath, 0o600); chmodSync(certPath, 0o600);
    const key = readFileSync(keyPath); const cert = readFileSync(certPath);
    if (key.length > 4096 || cert.length > 8192) throw failure();
    return { key, cert };
  } finally {
    // Only the two generated files and exact new directory owned by this call.
    // No archive, retained config, trust store or existing certificate is read.
    for (const path of [keyPath, certPath]) {
      try { unlinkSync(path); } catch (error) { if (error.code !== 'ENOENT') throw failure(); }
    }
    rmdirSync(directory);
  }
}
async function refused(port) {
  return new Promise((resolve, reject) => {
    const socket = connect({ host: '127.0.0.1', port });
    socket.setTimeout(500);
    socket.once('connect', () => { socket.destroy(); reject(failure()); });
    socket.once('timeout', () => { socket.destroy(); reject(failure()); });
    socket.once('error', error => { socket.destroy(); error.code === 'ECONNREFUSED' ? resolve() : reject(failure()); });
  });
}

/** Fresh HTTPS endpoint and ONE <=120-second RS256 bootstrap-admin token.
 * The fixed invented subject class receives a unique suffix per issuer, not a
 * caller-selected identity. Even the first authenticated Pol.is GET can create
 * its user/mapping: a future bootstrapper must journal before ANY such request.
 * This factory never makes that request or grants a round/participant authority.
 * close() stops issuance/JWKS serving, not a token already verified with cached
 * public keys. That token expires normally; ordinary-bootstrap service closure
 * and any downstream admission/revocation are separate required boundaries.
 */
export async function createBootstrapIssuer() {
  if (arguments.length !== 0) throw failure();
  let credentials; let privateKey; let server; let closePromise; let expiryTimer;
  let closed = false; let listenersClosed = false; let port;
  const sockets = new Set(); const clients = new Set();
  const publicJwksLifetime = new AbortController();
  let publicJwksClaimed = false; let apiTrustClaimed = false; let verifiedPublicPromise;
  const counts = { tokensIssued: 0, jwksRequests: 0, rejectedRequests: 0, clientFetches: 0,
    verifiedTlsFetches: 0, tlsErrors: 0 };
  let wallStart; let monotonicStart; let issuer; let jwks; let jwksText;
  const expired = () => {
    const now = Date.now(); const elapsed = performance.now() - monotonicStart;
    return !Number.isSafeInteger(now) || now < wallStart || now >= wallStart + LIFETIME_MS ||
      !Number.isFinite(elapsed) || elapsed < 0 || elapsed >= LIFETIME_MS;
  };
  const active = () => !closed && !expired();
  const close = function () {
    if (arguments.length !== 0) return Promise.reject(failure());
    if (closePromise) return closePromise;
    closed = true; clearTimeout(expiryTimer); privateKey = undefined;
    publicJwksLifetime.abort();
    closePromise = (async () => {
      try {
        for (const client of clients) client.destroy();
        if (server?.listening) {
          const completion = new Promise((resolve, reject) => server.close(error => error ? reject(failure()) : resolve()));
          for (const socket of sockets) socket.destroy();
          await completion;
        } else for (const socket of sockets) socket.destroy();
        if (port !== undefined) await refused(port);
        listenersClosed = true;
      } catch { throw failure(); }
      finally { credentials?.key.fill(0); }
    })();
    return closePromise;
  };
  const requireActive = () => {
    if (!active()) { void close().catch(() => {}); throw failure(); }
  };
  try {
    credentials = freshCertificate();
    const pair = await promisify(generateKeyPair)('rsa', { modulusLength: 2048 });
    privateKey = pair.privateKey;
    const publicJwk = pair.publicKey.export({ format: 'jwk' });
    const kid = createHash('sha256').update(pair.publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
    jwks = Object.freeze({ keys: Object.freeze([Object.freeze({ kty: 'RSA', n: publicJwk.n, e: publicJwk.e,
      kid, use: 'sig', alg: 'RS256' })]) });
    jwksText = JSON.stringify(jwks);
    if (Buffer.byteLength(jwksText) > MAX_JWKS_BYTES) throw failure();
    const subject = 'fncp-invented-bootstrap-admin-' + randomBytes(24).toString('hex');
    server = createServer({ ...credentials, minVersion: 'TLSv1.2', maxHeaderSize: 8192 }, (req, res) => {
      req.on('error', () => {}); res.on('error', () => {});
      const deny = () => {
        counts.rejectedRequests++;
        res.writeHead(403, { 'content-type': 'application/json', 'cache-control': 'no-store',
          'connection': 'close', 'x-content-type-options': 'nosniff' }); res.end('{}');
      };
      const hostCount = req.rawHeaders.filter((item, i) => i % 2 === 0 && item.toLowerCase() === 'host').length;
      if (!active() || counts.jwksRequests + counts.rejectedRequests >= MAX_REQUESTS ||
          req.socket.remoteAddress !== '127.0.0.1' || hostCount !== 1 || req.headers.host !== `127.0.0.1:${port}` ||
          req.method !== 'GET' || req.url !== JWKS_PATH || req.headers.origin !== undefined ||
          req.headers.authorization !== undefined || req.headers.cookie !== undefined ||
          req.headers['transfer-encoding'] !== undefined ||
          (req.headers['content-length'] !== undefined && req.headers['content-length'] !== '0')) {
        deny(); return;
      }
      counts.jwksRequests++;
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store',
        'connection': 'close', 'x-content-type-options': 'nosniff', 'content-length': Buffer.byteLength(jwksText) });
      res.end(jwksText);
    });
    server.requestTimeout = 1000; server.headersTimeout = 1000; server.keepAliveTimeout = 1;
    server.maxConnections = MAX_CONNECTIONS; server.maxRequestsPerSocket = 1;
    server.on('connection', socket => {
      sockets.add(socket); socket.once('close', () => sockets.delete(socket));
      socket.setTimeout(1000, () => socket.destroy());
      if (closed) socket.destroy();
    });
    server.on('tlsClientError', () => { counts.tlsErrors++; });
    // Keep a permanent sanitized handler; a later listener error must not become
    // an unhandled exception containing private endpoint details.
    server.on('error', () => { void close().catch(() => {}); });
    await new Promise((resolve, reject) => {
      const onError = () => reject(failure()); server.once('error', onError);
      server.listen(0, '127.0.0.1', () => { server.removeListener('error', onError); resolve(); });
    });
    port = server.address().port; issuer = `https://127.0.0.1:${port}/`;
    wallStart = Date.now(); monotonicStart = performance.now();
    expiryTimer = setTimeout(() => { void close().catch(() => {}); }, LIFETIME_MS);
    expiryTimer.unref();

    const capability = Object.freeze({
      configuration() {
        if (arguments.length !== 0) throw failure(); requireActive();
        return Object.freeze({ issuer, audience: AUDIENCE, jwksUri: issuer.slice(0, -1) + JWKS_PATH,
          certificatePem: credentials.cert.toString('utf8') });
      },
      issueToken() {
        if (arguments.length !== 0) throw failure(); requireActive();
        if (counts.tokensIssued !== 0) throw failure();
        counts.tokensIssued = 1; // Consume before signing; never repeat uncertain issuance.
        try {
          const now = Math.floor(Date.now() / 1000);
          if (!Number.isSafeInteger(now) || now < Math.floor(wallStart / 1000)) throw failure();
          const claims = { iss: issuer, aud: AUDIENCE, sub: subject, email: EMAIL, email_verified: false,
            name: 'Invented local bootstrap administrator', iat: now, nbf: now,
            exp: Math.floor((wallStart + LIFETIME_MS) / 1000), jti: randomBytes(24).toString('hex') };
          if (claims.exp <= now || claims.exp - now > 120) throw failure();
          const input = encode({ alg: 'RS256', typ: 'JWT', kid }) + '.' + encode(claims);
          const token = input + '.' + sign('RSA-SHA256', Buffer.from(input), privateKey).toString('base64url');
          if (Buffer.byteLength(token) > 4096) throw failure(); return token;
        } catch { throw failure(); }
      },
      async fetchJwks() {
        if (arguments.length !== 0) throw failure(); requireActive();
        if (counts.clientFetches >= MAX_FETCHES) throw failure(); counts.clientFetches++;
        return new Promise((resolve, reject) => {
          let finished = false; let req; let response;
          const finish = (ok) => {
            if (finished) return; finished = true; clearTimeout(timer);
            if (req) clients.delete(req);
            if (ok && active()) resolve(jwks);
            else { response?.destroy(); req?.destroy(); reject(failure()); }
          };
          const timer = setTimeout(() => finish(false), 1000);
          try {
            req = request({ hostname: '127.0.0.1', port, method: 'GET', path: JWKS_PATH, ca: credentials.cert,
              rejectUnauthorized: true, minVersion: 'TLSv1.2', agent: false,
              // Default IP SAN verification; no custom checkServerIdentity/SNI,
              // DNS interception, external URL, redirect, or system trust change.
              headers: { host: `127.0.0.1:${port}`, accept: 'application/json', connection: 'close' },
            }, res => {
              response = res;
              if (req.socket.remoteAddress !== '127.0.0.1' || req.socket.authorized !== true ||
                  !['TLSv1.2', 'TLSv1.3'].includes(req.socket.getProtocol()) || res.statusCode !== 200 ||
                  res.headers['content-type'] !== 'application/json') { finish(false); return; }
              counts.verifiedTlsFetches++;
              let size = 0; const chunks = [];
              res.on('data', chunk => { size += chunk.length; if (size > MAX_JWKS_BYTES) finish(false); else chunks.push(Buffer.from(chunk)); });
              res.on('error', () => finish(false)); res.on('aborted', () => finish(false));
              res.on('end', () => finish(res.complete && Buffer.concat(chunks).toString('utf8') === jwksText));
            });
            clients.add(req); req.on('error', () => finish(false)); req.end();
          } catch { finish(false); }
        });
      },
      close,
      summary() {
        if (arguments.length !== 0) throw failure();
        return Object.freeze({ mode: 'LOCAL_SYNTHETIC_BOOTSTRAP_ONLY', realIdentityProvider: false,
          oidcLoginImplemented: false, containerReachabilityVerified: false, polisMiddlewareExecuted: false,
          bootstrapExecuted: false, cachedTokenRevocationImplemented: false, globalTrustChanged: false, productionReady: false,
          tokenLifetimeSecondsMaximum: 120, closed, expired: expired(), listenersClosed,
          temporaryCertificateFilesRemoved: true, ...counts });
      },
    });
    transportIssuers.set(capability, () => {
      requireActive();
      return Object.freeze({ token: capability.issueToken(),
        assertActive() { if (arguments.length) throw failure(); requireActive(); },
      });
    });
    const assertActive = function () { if (arguments.length) throw failure(); requireActive(); };
    const verifiedPublic = () => {
      // Publish the promise before either public role yields. A rejected fetch
      // stays rejected; another role must never retry an uncertain fetch.
      if (!verifiedPublicPromise) verifiedPublicPromise = (async () => {
        await capability.fetchJwks(); requireActive();
      })();
      return verifiedPublicPromise;
    };
    publicJwksIssuers.set(capability, async () => {
      requireActive();
      if (publicJwksClaimed) throw failure();
      publicJwksClaimed = true; // Never retry an uncertain public fetch or reset the handoff cap.
      await verifiedPublic();
      requireActive();
      return Object.freeze({ publicJwksText: jwksText, signal: publicJwksLifetime.signal,
        assertActive,
      });
    });
    apiTrustIssuers.set(capability, async () => {
      requireActive();
      if (apiTrustClaimed) throw failure();
      apiTrustClaimed = true;
      await verifiedPublic();
      requireActive();
      return Object.freeze({ issuer, publicJwksText: jwksText, signal: publicJwksLifetime.signal,
        assertActive,
      });
    });
    return capability;
  } catch {
    await close().catch(() => {}); throw failure();
  }
}
