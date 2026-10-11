/** Public-only static JWKS/TLS services. No I/O on import. Each owns a NEW
 * loopback listener and generated DNS-SAN TLS credentials, not an attested
 * container, Docker namespace, launcher, external identity or production service.
 * A caller can name only the validated 24-hex namespace, not paths/keys/URLs.
 * The original branded issuer owns all token issuance and lifetime decisions.
 */
import { spawnSync } from 'node:child_process';
import { createHash, createPublicKey, X509Certificate } from 'node:crypto';
import { chmodSync, closeSync, constants, fstatSync, mkdtempSync, openSync, readSync,
  realpathSync, rmdirSync, unlinkSync } from 'node:fs';
import { createServer } from 'node:https';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { isProxy } from 'node:util/types';
import { claimBootstrapIssuerPublicJwks } from './bootstrap-issuer.mjs';

const failure = () => new Error('Fresh public JWKS service rejected; private details withheld.');
const MAX_BYTES = 8192;
const MAX_REQUESTS = 32;
const MAX_CONNECTIONS = 8;
const JWKS_PATH = '/.well-known/jwks.json';
const addListener = EventTarget.prototype.addEventListener;
const removeListener = EventTarget.prototype.removeEventListener;
const aborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted').get;
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

function exact(input) {
  if (!input || typeof input !== 'object' || isProxy(input) || Object.getPrototypeOf(input) !== Object.prototype ||
      Reflect.ownKeys(input).length !== 2) throw failure();
  const fields = Object.getOwnPropertyDescriptors(input);
  if (!fields.issuer || !Object.hasOwn(fields.issuer, 'value') || !fields.namespaceId ||
      !Object.hasOwn(fields.namespaceId, 'value')) throw failure();
  if (typeof fields.namespaceId.value !== 'string' || !/^[a-f0-9]{24}$/u.test(fields.namespaceId.value)) throw failure();
  return { issuer: fields.issuer.value, namespaceId: fields.namespaceId.value };
}
function publicBytes(text) {
  try {
    if (typeof text !== 'string' || Buffer.byteLength(text) > MAX_BYTES) throw failure();
    const document = JSON.parse(text);
    if (JSON.stringify(document) !== text || !document || Array.isArray(document) ||
        Object.keys(document).join() !== 'keys' || !Array.isArray(document.keys) || document.keys.length !== 1) throw failure();
    const key = document.keys[0];
    if (!key || Array.isArray(key) || Object.keys(key).sort().join() !== 'alg,e,kid,kty,n,use' ||
        key.kty !== 'RSA' || key.alg !== 'RS256' || key.use !== 'sig' || key.e !== 'AQAB' ||
        typeof key.n !== 'string' || !/^[A-Za-z0-9_-]{342}$/u.test(key.n) ||
        typeof key.kid !== 'string' || !/^[a-f0-9]{64}$/u.test(key.kid)) throw failure();
    const modulus = Buffer.from(key.n, 'base64url');
    if (modulus.length !== 256 || modulus.toString('base64url') !== key.n || (modulus[0] & 128) === 0 ||
        sha256(createPublicKey({ key, format: 'jwk' }).export({ format: 'der', type: 'spki' })) !== key.kid) throw failure();
    return Buffer.from(text, 'utf8');
  } catch { throw failure(); }
}
function readGenerated(path, limit) {
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const before = fstatSync(fd);
    if (!before.isFile() || before.size < 1 || before.size > limit) throw failure();
    const bytes = Buffer.alloc(limit + 1); let length = 0;
    while (length < bytes.length) {
      const count = readSync(fd, bytes, length, bytes.length - length, length);
      if (!count) break; length += count;
    }
    const after = fstatSync(fd);
    if (!after.isFile() || length !== before.size || after.size !== before.size || after.ino !== before.ino ||
        after.dev !== before.dev || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) throw failure();
    return Buffer.from(bytes.subarray(0, length));
  } catch { throw failure(); } finally { if (fd !== undefined) closeSync(fd); }
}
function freshCertificate(hostname) {
  const executable = process.platform === 'darwin' ? '/opt/homebrew/bin/openssl' :
    process.platform === 'linux' ? '/usr/bin/openssl' : undefined;
  if (!executable) throw failure();
  const directory = mkdtempSync(join(realpathSync(tmpdir()), 'fncp-public-jwks-tls-'));
  const keyPath = join(directory, 'generated-key.pem');
  const certPath = join(directory, 'generated-certificate.pem');
  let key;
  try {
    chmodSync(directory, 0o700);
    const result = spawnSync(executable, ['req', '-x509', '-newkey', 'ec', '-pkeyopt',
      'ec_paramgen_curve:prime256v1', '-noenc', '-days', '1', '-subj', '/CN=synthetic.invalid',
      '-addext', `subjectAltName=DNS:${hostname}`, '-keyout', keyPath, '-out', certPath], {
      cwd: directory, shell: false, stdio: ['ignore', 'pipe', 'pipe'], timeout: 10_000, maxBuffer: 8192,
      env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C', OPENSSL_CONF: '/dev/null' },
    });
    if (result.error || result.status !== 0) throw failure();
    chmodSync(keyPath, 0o600); chmodSync(certPath, 0o600);
    key = readGenerated(keyPath, 4096); const cert = readGenerated(certPath, MAX_BYTES);
    const parsed = new X509Certificate(cert);
    if (parsed.checkHost(hostname, { subject: 'never', wildcards: false }) !== hostname ||
        Date.parse(parsed.validFrom) > Date.now() || Date.parse(parsed.validTo) <= Date.now()) throw failure();
    return { key, cert, certificateSha256: sha256(parsed.raw) };
  } catch { key?.fill(0); throw failure(); }
  finally {
    for (const path of [keyPath, certPath]) {
      try { unlinkSync(path); } catch (error) { if (error.code !== 'ENOENT') throw failure(); }
    }
    rmdirSync(directory);
  }
}
async function refused(port) {
  await new Promise((resolve, reject) => {
    const socket = connect({ host: '127.0.0.1', port }); socket.setTimeout(500);
    socket.once('connect', () => { socket.destroy(); reject(failure()); });
    socket.once('timeout', () => { socket.destroy(); reject(failure()); });
    socket.once('error', error => { socket.destroy(); error.code === 'ECONNREFUSED' ? resolve() : reject(failure()); });
  });
}

/** Internal generation is the TLS ownership boundary: no supplied certificate,
 * file, private key, bind address, port, signer, fetcher or network callback.
 * configuration() is a PRIVATE handoff, not aggregate evidence. Its container
 * URI is an intended identity only; localPort is the actual test listener.
 */
export async function createBootstrapJwksService(options) {
  if (arguments.length !== 1) throw failure();
  return createService(options, false);
}

/** Fixed same-OS/namespace loopback role, always 127.0.0.1:8444. A future
 * container owner must separately arrange the exact private DNS/hosts mapping,
 * ownership and egress policy. Platform alone proves none of those conditions.
 * No existing listener is probed, adopted or displaced on a bind collision.
 */
export async function createBootstrapContainerJwksService(options) {
  if (arguments.length !== 1) throw failure();
  return createService(options, true);
}

async function createService(options, fixedLoopbackRole) {
  const { issuer, namespaceId } = exact(options);
  let handoff; let credentials; let server; let port; let closePromise;
  let closed = false; let listenersClosed = false; let ready = false; let failed = false;
  const sockets = new Set(); const connectionTimers = new Map();
  const counts = { servedRequests: 0, rejectedRequests: 0, tlsErrors: 0, publicHandoffs: 0 };
  const hostname = `fncp-fresh-jwks-${namespaceId}`;
  const hostHeader = `${hostname}:8444`;
  const jwksUri = `https://${hostHeader}${JWKS_PATH}`;
  const requireActive = () => {
    if (closed || failed || !handoff || aborted.call(handoff.signal)) throw failure();
    try { handoff.assertActive(); } catch { throw failure(); }
  };
  const onIssuerClosed = () => { void close().catch(() => {}); };
  const close = function () {
    if (arguments.length) return Promise.reject(failure());
    if (closePromise) return closePromise;
    closed = true;
    if (handoff) removeListener.call(handoff.signal, 'abort', onIssuerClosed);
    closePromise = (async () => {
      try {
        let timer;
        const deadline = new Promise((resolve, reject) => { timer = setTimeout(() => reject(failure()), 2000); });
        try {
          await Promise.race([(async () => {
            const completion = server?.listening ? new Promise((resolve, reject) =>
              server.close(error => error ? reject(failure()) : resolve())) : Promise.resolve();
            for (const socket of sockets) socket.destroy();
            for (const timeout of connectionTimers.values()) clearTimeout(timeout);
            connectionTimers.clear();
            await completion;
            if (port !== undefined) await refused(port);
          })(), deadline]);
          listenersClosed = true;
        } finally { clearTimeout(timer); }
      } catch { throw failure(); }
      finally { credentials?.key.fill(0); }
    })();
    return closePromise;
  };
  try {
    handoff = await claimBootstrapIssuerPublicJwks(issuer); counts.publicHandoffs = 1;
    requireActive(); const bytes = publicBytes(handoff.publicJwksText);
    credentials = freshCertificate(hostname); requireActive();
    server = createServer({ key: credentials.key, cert: credentials.cert, minVersion: 'TLSv1.2',
      maxHeaderSize: MAX_BYTES, handshakeTimeout: 1000 }, (req, res) => {
      req.on('error', () => {}); res.on('error', () => {});
      const deny = () => {
        counts.rejectedRequests++;
        res.writeHead(403, { 'content-type': 'application/json', 'cache-control': 'no-store',
          connection: 'close', 'x-content-type-options': 'nosniff' }); res.end('{}');
      };
      try { requireActive(); } catch { deny(); return; }
      const hostCount = req.rawHeaders.filter((item, i) => i % 2 === 0 && item.toLowerCase() === 'host').length;
      if (counts.servedRequests + counts.rejectedRequests >= MAX_REQUESTS || req.socket.remoteAddress !== '127.0.0.1' ||
          hostCount !== 1 || req.headers.host !== hostHeader || req.method !== 'GET' || req.url !== JWKS_PATH ||
          req.headers.origin !== undefined || req.headers.authorization !== undefined || req.headers.cookie !== undefined ||
          req.headers['transfer-encoding'] !== undefined ||
          (req.headers['content-length'] !== undefined && req.headers['content-length'] !== '0')) { deny(); return; }
      counts.servedRequests++;
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store', connection: 'close',
        'x-content-type-options': 'nosniff', 'content-length': bytes.length }); res.end(bytes);
    });
    server.requestTimeout = 1000; server.headersTimeout = 1000; server.keepAliveTimeout = 1;
    server.maxConnections = MAX_CONNECTIONS; server.maxRequestsPerSocket = 1;
    server.on('connection', socket => {
      sockets.add(socket);
      // Hard connection lifetime, not an inactivity timeout reset by drip-fed bytes.
      connectionTimers.set(socket, setTimeout(() => socket.destroy(), 1500));
      socket.once('close', () => { sockets.delete(socket); clearTimeout(connectionTimers.get(socket)); connectionTimers.delete(socket); });
      if (closed) socket.destroy();
    });
    server.on('tlsClientError', () => { counts.tlsErrors++; });
    server.on('clientError', (_error, socket) => socket.destroy());
    server.on('error', () => { failed = true; if (ready) void close().catch(() => {}); });
    await new Promise((resolve, reject) => {
      const error = () => reject(failure()); server.once('error', error);
      const listening = () => { server.removeListener('error', error); resolve(); };
      // Keep both bind targets literal: neither factory accepts a port/address.
      if (fixedLoopbackRole) server.listen(8444, '127.0.0.1', listening);
      else server.listen(0, '127.0.0.1', listening);
    });
    port = server.address().port; ready = true; requireActive();
    addListener.call(handoff.signal, 'abort', onIssuerClosed, { once: true });
    requireActive();
    return Object.freeze({
      configuration() {
        if (arguments.length) throw failure(); requireActive();
        return Object.freeze({ hostname, jwksUri, localAddress: '127.0.0.1', localPort: port,
          certificatePem: credentials.cert.toString('utf8'), certificateSha256: credentials.certificateSha256 });
      },
      close,
      summary() {
        if (arguments.length) throw failure();
        return Object.freeze({ mode: fixedLoopbackRole ? 'FIXED_LOOPBACK_JWKS_8444_ROLE_ONLY' : 'PUBLIC_JWKS_LOOPBACK_PRIMITIVE_ONLY', originalIssuerLifetime: true,
          tokenIssuanceImplemented: false, rsaPrivateKeyExported: false, tlsPrivateKeyExported: false,
          cachedTokenRevocationImplemented: false, containerRoleImplemented: false, containerReachabilityVerified: false,
          runtimeOwnershipVerified: false, productionReady: false, globalTrustChanged: false,
          closed, listenersClosed, temporaryCertificateFilesRemoved: true, responseByteLimit: MAX_BYTES,
          maximumRequests: MAX_REQUESTS, maximumConnections: MAX_CONNECTIONS, ...counts });
      },
    });
  } catch {
    await close().catch(() => {}); throw failure();
  }
}
