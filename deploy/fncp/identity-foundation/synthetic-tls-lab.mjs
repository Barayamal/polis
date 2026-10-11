/** TEST SUPPORT ONLY. Real loopback TLS, invented issuer/subjects, no real provider.
 * No default remote transport, trust-store mutation, persistent key or launch grant.
 */
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmodSync, mkdtempSync, readFileSync, rmdirSync, unlinkSync } from 'node:fs';
import { createServer, request } from 'node:https';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createIdentityFoundation } from './identity.mjs';
import { createSyntheticIdentityHarness } from './synthetic-harness.mjs';

const ISSUER = 'https://identity.example.invalid/';
const HOST = 'identity.example.invalid';
const ROUTES = new Map([[`${ISSUER}token`, ['POST', '/token']], [`${ISSUER}jwks`, ['GET', '/jwks']]]);
const ERROR = () => new Error('Synthetic loopback TLS transport rejected.');
const MAX_BYTES = 65_536;
const BEHAVIORS = ['normal', 'redirect', 'slow-headers', 'stalled-body', 'oversized', 'wrong-content-type', 'truncated'];

function certificate(host) {
  const directory = mkdtempSync(join(tmpdir(), 'fncp-synthetic-tls-'));
  const keyPath = join(directory, 'generated-key.pem');
  const certPath = join(directory, 'generated-certificate.pem');
  try {
    chmodSync(directory, 0o700);
    const result = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt',
      'ec_paramgen_curve:prime256v1', '-noenc', '-days', '1', '-subj', `/CN=${host}`,
      '-addext', `subjectAltName=DNS:${host}`, '-keyout', keyPath, '-out', certPath],
    { stdio: ['ignore', 'pipe', 'pipe'], timeout: 10_000, maxBuffer: 8192 });
    if (result.error || result.status !== 0) throw ERROR();
    chmodSync(keyPath, 0o600); chmodSync(certPath, 0o600);
    return { key: readFileSync(keyPath), cert: readFileSync(certPath) };
  } finally {
    // Only these two generated files in this invocation's own temporary directory.
    for (const path of [keyPath, certPath]) {
      try { unlinkSync(path); } catch (error) { if (error.code !== 'ENOENT') throw ERROR(); }
    }
    rmdirSync(directory);
  }
}

async function noListener(port) {
  return new Promise((resolve, reject) => {
    const socket = connect({ host: '127.0.0.1', port });
    socket.setTimeout(500);
    socket.once('connect', () => { socket.destroy(); reject(ERROR()); });
    socket.once('timeout', () => { socket.destroy(); reject(ERROR()); });
    socket.once('error', (error) => { socket.destroy(); error.code === 'ECONNREFUSED' ? resolve() : reject(ERROR()); });
  });
}

/** Fixed lab configurations only. No option selects a URL, host, port, CA or key. */
export async function createSyntheticTlsLab(options = {}) {
  if (!options || Object.getPrototypeOf(options) !== Object.prototype
    || Object.keys(options).some((key) => !['certificate', 'trust', 'behavior', 'faultEndpoint', 'timeoutMs'].includes(key))
    || !['matching', 'wrong-san'].includes(options.certificate ?? 'matching')
    || !['matching', 'wrong-ca'].includes(options.trust ?? 'matching')
    || !BEHAVIORS.includes(options.behavior ?? 'normal')
    || !['token', 'jwks'].includes(options.faultEndpoint ?? 'token')
    || !Number.isSafeInteger(options.timeoutMs ?? 1000)
    || (options.timeoutMs ?? 1000) < 50 || (options.timeoutMs ?? 1000) > 2000) throw ERROR();
  const timeoutMs = options.timeoutMs ?? 1000;
  const behavior = options.behavior ?? 'normal';
  const faultEndpoint = options.faultEndpoint ?? 'token';
  const credentials = certificate(options.certificate === 'wrong-san' ? 'wrong.example.invalid' : HOST);
  const ca = options.trust === 'wrong-ca' ? certificate('untrusted.example.invalid').cert : credentials.cert;
  const h = await createSyntheticIdentityHarness();
  const counts = { token: 0, jwks: 0, unexpected: 0, tlsAuthorized: 0, tlsErrors: 0, clientRequests: 0 };
  const sockets = new Set();
  let stopped = false; let listenersClosed = false;
  const server = createServer({ ...credentials, minVersion: 'TLSv1.2' }, async (req, res) => {
    req.on('error', () => {}); res.on('error', () => {});
    const endpoint = req.url === '/token' && req.method === 'POST' ? 'token'
      : req.url === '/jwks' && req.method === 'GET' ? 'jwks' : 'unexpected';
    counts[endpoint] += 1;
    try {
      if (req.socket.remoteAddress !== '127.0.0.1' || req.headers.host !== HOST
        || endpoint === 'unexpected') throw ERROR();
      const chunks = []; let size = 0;
      for await (const chunk of req) {
        size += chunk.length; if (size > MAX_BYTES) throw ERROR(); chunks.push(chunk);
      }
      if (endpoint === faultEndpoint && behavior !== 'normal') {
        if (behavior === 'slow-headers') return;
        res.setHeader('content-type', behavior === 'wrong-content-type' ? 'text/html' : 'application/json');
        if (behavior === 'redirect') {
          res.writeHead(302, { location: 'https://never-contact.example.invalid/redirected' }); res.end('{}'); return;
        }
        if (behavior === 'stalled-body') { res.writeHead(200); res.write('{'); return; }
        if (behavior === 'oversized') { res.end('x'.repeat(MAX_BYTES + 1)); return; }
        if (behavior === 'wrong-content-type') { res.end('{}'); return; }
        if (behavior === 'truncated') {
          res.writeHead(200, { 'content-length': '1000' }); res.write('{');
          res.flushHeaders(); setImmediate(() => res.destroy()); return;
        }
      }
      const response = await h.options.transport.fetch(`${ISSUER}${endpoint}`, {
        method: req.method, headers: req.headers,
        ...(endpoint === 'token' ? { body: Buffer.concat(chunks).toString('utf8') } : {}),
        redirect: 'error', credentials: 'omit',
      });
      res.writeHead(response.status, Object.fromEntries(response.headers));
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch { if (!res.destroyed) { res.writeHead(400, { 'content-type': 'application/json' }); res.end('{}'); } }
  });
  server.on('connection', (socket) => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  server.on('tlsClientError', () => { counts.tlsErrors += 1; });
  server.requestTimeout = 2000; server.headersTimeout = 2000;
  await new Promise((resolve, reject) => {
    server.once('error', reject); server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;

  const interceptedFetch = async (input, init = {}) => {
    const route = typeof input === 'string' || input instanceof URL ? ROUTES.get(String(input)) : undefined;
    const method = init.method ?? 'GET';
    const headers = new Headers(init.headers);
    const body = init.body === undefined ? undefined : init.body instanceof URLSearchParams ? init.body.toString()
      : typeof init.body === 'string' ? init.body : null;
    if (stopped || !route || method !== route[0] || init.redirect !== 'error' || init.credentials !== 'omit'
      || body === null || (method === 'GET' && body !== undefined)
      || (method === 'POST' && (body === undefined || Buffer.byteLength(body) > MAX_BYTES))
      || [...headers.keys()].some((key) => !['accept', 'content-type', 'user-agent'].includes(key))
      || (init.signal !== undefined && !(init.signal instanceof AbortSignal)) || init.signal?.aborted) throw ERROR();
    return new Promise((resolve, reject) => {
      let settled = false; let req; let response;
      const finish = (error, result) => {
        if (settled) return; settled = true;
        clearTimeout(timer); init.signal?.removeEventListener('abort', onAbort);
        if (error) { response?.destroy(); req?.destroy(); reject(ERROR()); } else resolve(result);
      };
      const onAbort = () => finish(ERROR());
      const timer = setTimeout(() => finish(ERROR()), timeoutMs);
      init.signal?.addEventListener('abort', onAbort, { once: true });
      counts.clientRequests += 1;
      try {
        req = request({ hostname: '127.0.0.1', port, path: route[1], method,
          servername: HOST, ca, rejectUnauthorized: true, minVersion: 'TLSv1.2', agent: false,
          // Keep default Node hostname verification. The logical hostname is
          // selected by fixed SNI; the actual socket destination is a literal IP.
          headers: { ...Object.fromEntries(headers), host: HOST, connection: 'close',
            ...(body === undefined ? {} : { 'content-length': Buffer.byteLength(body) }) },
        }, (res) => {
          response = res;
          if (req.socket.remoteAddress !== '127.0.0.1' || req.socket.authorized !== true) return finish(ERROR());
          counts.tlsAuthorized += 1;
          const chunks = []; let bytes = 0;
          res.on('data', (chunk) => {
            bytes += chunk.length;
            if (bytes > MAX_BYTES) return finish(ERROR());
            chunks.push(chunk);
          });
          res.on('aborted', () => finish(ERROR())); res.on('error', () => finish(ERROR()));
          res.on('end', () => {
            try {
              if (!res.complete) return finish(ERROR());
              const responseHeaders = new Headers();
              for (const [name, value] of Object.entries(res.headers)) {
                if (Array.isArray(value)) value.forEach((item) => responseHeaders.append(name, item));
                else if (value !== undefined) responseHeaders.set(name, value);
              }
              // No redirect following exists in https.request. The foundation
              // rejects this 3xx Response before interpreting a token/JWKS body.
              finish(null, new Response(Buffer.concat(chunks), { status: res.statusCode, headers: responseHeaders }));
            } catch { finish(ERROR()); }
          });
        });
        req.on('error', () => finish(ERROR()));
        if (body !== undefined) req.write(body); req.end();
      } catch { finish(ERROR()); }
    });
  };
  const transport = Object.freeze({ kind: 'SYNTHETIC_INTERCEPT', fetch: interceptedFetch });
  const identity = createIdentityFoundation({ ...h.options, transport });
  const close = async () => {
    if (listenersClosed) return;
    stopped = true;
    const closed = new Promise((resolve, reject) => server.close((error) => error ? reject(ERROR()) : resolve()));
    for (const socket of sockets) socket.destroy();
    await closed; await noListener(port); listenersClosed = true;
  };
  return Object.freeze({ identity, transport, authorizationResponse: h.authorizationResponse,
    async authenticate() {
      const browserSessionId = randomBytes(32).toString('base64url');
      const begin = await identity.begin({ browserSessionId });
      if (!begin.ok) return begin;
      return identity.complete({ browserSessionId, callbackUrl: h.authorizationResponse(begin.authorizationUrl) });
    }, close,
    summary: () => Object.freeze({ mode: 'SYNTHETIC_ONLY', actualLoopbackTls: true,
      logicalEndpointInterception: true, realIdentityProvider: false, browserRedirectTested: false,
      globalTrustChanged: false, productionReady: false, ...counts, listenersClosed }),
  });
}
