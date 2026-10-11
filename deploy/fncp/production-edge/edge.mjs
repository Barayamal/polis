import { createServer, request } from 'node:https';
import { createPrivateKey, X509Certificate } from 'node:crypto';
import { isIP } from 'node:net';
import { checkServerIdentity } from 'node:tls';

// Explicit loopback and container profiles share the sanitizer, never authority.
// No request header can select an upstream or principal.
const PROFILE = 'FNCP_PARTICIPANT_EDGE_LOOPBACK_CANDIDATE_V1';
export const CONTAINER_PROFILE = 'FNCP_PARTICIPANT_EDGE_CONTAINER_V1';
const ROUTES = new Map([
  ['/', 'GET'], ['/app.js', 'GET'], ['/style.css', 'GET'], ['/session', 'GET'],
  ['/oidc/login', 'POST'], ['/oidc/callback', 'GET'], ['/registration', 'POST'],
  ['/invitations/redeem', 'POST'], ['/polis/participation-init', 'GET'],
  ['/polis/next-comment', 'GET'], ['/polis/votes', 'POST'], ['/session/logout', 'POST'],
]);
const APPLICATION_COOKIES = new Set(['__Host-fncp-session', '__Host-fncp-transaction']);
const REVIEWED_DISCARD_COOKIES = new Set(['__cf_bm']);
const DISCARD_METADATA = new Set([
  'forwarded', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto',
  'x-forwarded-port', 'x-real-ip', 'cf-connecting-ip', 'cf-ipcountry',
  'cf-ray', 'cf-visitor', 'cdn-loop',
]);
const HOP_HEADERS = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
]);
const fail = (status = 403) => Object.assign(new Error('Participant edge request rejected.'), { status });
const configurationFailure = () => new Error('Participant edge configuration rejected.');
const loopback = value => value === '127.0.0.1' || value === '::1';
const fields = (value, names) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw configurationFailure();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).length !== names.length || names.some(name =>
    !Object.hasOwn(descriptors, name) || !Object.hasOwn(descriptors[name], 'value'))) throw configurationFailure();
  return Object.fromEntries(names.map(name => [name, descriptors[name].value]));
};
function bytes(value, limit) {
  if (!(value instanceof Uint8Array) || value.length < 1 || value.length > limit) throw configurationFailure();
  return Buffer.from(value);
}
function configure(options, container = false) {
  try {
    const x = fields(options, ['publicOrigin', 'listen', 'upstream', 'tls', 'discardCookies']);
    const origin = new URL(x.publicOrigin);
    if (origin.protocol !== 'https:' || origin.origin !== x.publicOrigin || origin.username || origin.password) throw configurationFailure();
    const hostname = origin.hostname.replace(/^\[|\]$/gu, '');
    const listen = fields(x.listen, ['host', 'port']);
    const upstream = fields(x.upstream, ['address', 'port', 'ca']);
    for (const endpoint of [listen, { host: upstream.address, port: upstream.port }]) {
      if ((!container && !loopback(endpoint.host)) || !Number.isInteger(endpoint.port) || endpoint.port < 0 || endpoint.port > 65535) throw configurationFailure();
    }
    if (upstream.port === 0 || container && (listen.host !== '0.0.0.0' || listen.port !== 8443
      || upstream.address !== 'participant-edge-upstream' || upstream.port !== 8443)) throw configurationFailure();
    const tlsInput = fields(x.tls, ['key', 'cert']);
    const tls = { key: bytes(tlsInput.key, 32_768), cert: bytes(tlsInput.cert, 65_536) };
    const certificate = new X509Certificate(tls.cert);
    if (certificate.ca || (certificate.keyUsage !== undefined && !certificate.keyUsage.includes('1.3.6.1.5.5.7.3.1'))
      || !certificate.checkPrivateKey(createPrivateKey(tls.key))
      || !(isIP(hostname) ? certificate.checkIP(hostname) : certificate.checkHost(hostname, { subject: 'never' }))
      || Date.parse(certificate.validFrom) > Date.now() || Date.parse(certificate.validTo) <= Date.now()) throw configurationFailure();
    const ca = bytes(upstream.ca, 65_536);
    new X509Certificate(ca); // The native TLS stack performs chain/time checks.
    if (!Array.isArray(x.discardCookies) || x.discardCookies.length > REVIEWED_DISCARD_COOKIES.size
      || x.discardCookies.some(name => !REVIEWED_DISCARD_COOKIES.has(name))
      || new Set(x.discardCookies).size !== x.discardCookies.length) throw configurationFailure();
    return { origin, hostname, listen, upstream: { ...upstream, ca }, tls,
      discardCookies: new Set(x.discardCookies) };
  } catch { throw configurationFailure(); }
}

function requestHeaders(req, config) {
  const seen = new Set();
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    const name = req.rawHeaders[i].toLowerCase();
    // Do not let Node's merge rules conceal duplicate authority/cookie fields.
    if (seen.has(name)) throw fail(400);
    seen.add(name);
  }
  if (!req.socket.encrypted || req.headers.host !== config.origin.host) throw fail();
  const connection = req.headers.connection;
  if (connection !== undefined && !/^(?:close|keep-alive)$/iu.test(connection)) throw fail(400);
  if (req.headers.authorization !== undefined || req.headers['proxy-authorization'] !== undefined
    || req.headers.upgrade !== undefined || req.headers.te !== undefined || req.headers.trailer !== undefined
    || req.headers['content-encoding'] !== undefined || Object.keys(req.headers).some(name =>
      name.startsWith('x-fncp-') || (name.startsWith('x-forwarded-') && !DISCARD_METADATA.has(name)))) throw fail();
  const headers = {};
  for (const [name, value] of Object.entries(req.headers)) {
    if (!HOP_HEADERS.has(name) && !DISCARD_METADATA.has(name) && name !== 'cookie') headers[name] = value;
  }
  if (req.headers.cookie !== undefined) {
    const raw = req.headers.cookie;
    if (typeof raw !== 'string' || Buffer.byteLength(raw) > 8192) throw fail(400);
    const cookieNames = new Set(); const retained = [];
    for (const segment of raw.split(';')) {
      const pair = segment.trim(); const index = pair.indexOf('=');
      const name = pair.slice(0, index); const value = pair.slice(index + 1);
      if (index < 1 || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u.test(name)
        || !/^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*$/u.test(value)
        || cookieNames.has(name)) throw fail(400);
      cookieNames.add(name);
      if (config.discardCookies.has(name)) continue;
      if (!APPLICATION_COOKIES.has(name)) throw fail();
      retained.push(pair); // Preserve the application value; the BFF validates it.
    }
    if (retained.length) headers.cookie = retained.join('; ');
  }
  headers.host = config.origin.host;
  headers.connection = 'close';
  return headers;
}

function route(req, config) {
  if (typeof req.url !== 'string' || req.url.length > 4096 || !req.url.startsWith('/') || req.url.startsWith('//')
    || /[\\\x00-\x20#]/u.test(req.url)) throw fail(400);
  const url = new URL(req.url, config.origin);
  if (url.origin !== config.origin.origin || url.pathname.includes('%') || req.url.split('?')[0] !== url.pathname
    || (url.pathname !== '/oidc/callback' && req.url.includes('?'))) throw fail(400);
  if (ROUTES.get(url.pathname) !== req.method) throw fail(404);
  if (req.method === 'GET' && (req.headers['transfer-encoding'] !== undefined || Number(req.headers['content-length'] ?? 0) !== 0)) throw fail(400);
  if (req.method === 'POST' && (!/^application\/json(?:; charset=utf-8)?$/iu.test(req.headers['content-type'] ?? '')
    || (req.headers['content-length'] !== undefined && (!/^[0-9]+$/u.test(req.headers['content-length'])
      || Number(req.headers['content-length']) > 4096)))) throw fail(400);
  return req.url;
}

function collect(stream, limit, timeout = 5000) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = []; let settled = false;
    const finish = (error, value) => {
      if (settled) return; settled = true; clearTimeout(timer);
      stream.removeListener('data', data); stream.removeListener('end', end);
      stream.removeListener('aborted', aborted); stream.removeListener('error', aborted);
      if (error) { stream.resume(); reject(error); } else resolve(value);
    };
    const data = chunk => { size += chunk.length; if (size > limit) finish(fail(413)); else chunks.push(chunk); };
    const end = () => finish(null, Buffer.concat(chunks));
    const aborted = () => finish(fail(400));
    const timer = setTimeout(() => finish(fail(408)), timeout); timer.unref();
    stream.on('data', data); stream.once('end', end); stream.once('aborted', aborted); stream.once('error', aborted);
  });
}

/** Loopback-only, fixed-authority edge seam for synthetic compatibility QA.
 * Origin, Fetch Metadata, CSRF and app cookies remain application inputs; this
 * module neither manufactures them nor turns proxy metadata into authority. */
export function createParticipantEdge(options) { return transport(options, false); }

/** Explicit cross-container transport; endpoints cannot be overridden. Callers
 * should load readonly owned material using createContainerParticipantEdge. */
export function createContainerParticipantTransport(options) { return transport(options, true); }

function transport(options, container) {
  const config = configure(options, container);
  const profile = container ? CONTAINER_PROFILE : PROFILE; const sockets = new Set(); const upstreamRequests = new Set();
  let phase = 'CREATED'; let pending = 0; let startPromise; let closePromise;
  const server = createServer({ ...config.tls, minVersion: 'TLSv1.2', maxHeaderSize: 16_384 }, async (req, res) => {
    req.on('error', () => {}); res.on('error', () => {});
    res.setHeader('cache-control', 'no-store'); res.setHeader('connection', 'close');
    if (phase !== 'RUNNING' || pending >= 32) { res.writeHead(503); res.end('Service unavailable.'); req.resume(); return; }
    pending += 1; let outgoing;
    const disconnect = () => { if (!res.writableEnded) outgoing?.destroy(); };
    res.once('close', disconnect);
    try {
      const path = route(req, config); const headers = requestHeaders(req, config);
      const body = await collect(req, 4096);
      if (req.method === 'POST') headers['content-length'] = String(body.length);
      if (phase !== 'RUNNING' || res.destroyed) throw fail(503);
      let deadline;
      const result = await new Promise((resolve, reject) => {
        outgoing = request({ hostname: config.upstream.address, port: config.upstream.port,
          method: req.method, path, headers, agent: false, ca: config.upstream.ca,
          rejectUnauthorized: true, minVersion: 'TLSv1.2',
          servername: isIP(config.hostname) ? '' : config.hostname,
          checkServerIdentity: (_hostname, certificate) => checkServerIdentity(config.hostname, certificate),
          maxHeaderSize: 16_384 }, async response => {
          response.on('error', () => {});
          try {
            const responseBody = await collect(response, 1_048_576);
            if (!response.complete) throw fail(502);
            const responseHeaders = Object.fromEntries(Object.entries(response.headers).filter(([name]) => !HOP_HEADERS.has(name)));
            responseHeaders['content-length'] = String(responseBody.length);
            responseHeaders.connection = 'close';
            resolve({ status: response.statusCode, headers: responseHeaders, body: responseBody });
          } catch { outgoing.destroy(); reject(fail(502)); }
        });
        upstreamRequests.add(outgoing);
        outgoing.setTimeout(5000, () => outgoing.destroy());
        outgoing.once('error', () => reject(fail(502)));
        outgoing.once('close', () => upstreamRequests.delete(outgoing));
        deadline = setTimeout(() => outgoing.destroy(), 5000); deadline.unref();
        outgoing.end(body);
      }).finally(() => clearTimeout(deadline));
      if (phase !== 'RUNNING' || res.destroyed) throw fail(503);
      res.writeHead(result.status, result.headers); res.end(result.body);
    } catch (error) {
      if (!res.destroyed && !res.headersSent) { res.writeHead(error.status ?? 502, { 'content-type': 'text/plain; charset=utf-8' }); res.end('Participant request unavailable.'); }
      req.resume();
    } finally { res.removeListener('close', disconnect); pending -= 1; }
  });
  server.headersTimeout = 5000; server.requestTimeout = 5000; server.keepAliveTimeout = 1;
  server.maxConnections = 64; server.setTimeout(5000, socket => socket.destroy());
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  server.on('tlsClientError', () => {});
  server.on('error', () => { if (phase === 'RUNNING') void close(); });
  server.on('upgrade', (_req, socket) => socket.destroy());
  server.on('connect', (_req, socket) => socket.destroy());
  async function start() {
    if (phase !== 'CREATED') throw fail(503);
    phase = 'STARTING';
    startPromise = new Promise((resolve, reject) => {
      const error = () => { server.removeListener('listening', ready); reject(fail(503)); };
      const ready = () => { server.removeListener('error', error); resolve(); };
      server.once('error', error); server.once('listening', ready); server.listen(config.listen.port, config.listen.host);
    });
    try {
      await startPromise;
      if (phase !== 'STARTING') throw fail(503);
      phase = 'RUNNING'; return Object.freeze({ profile, host: config.listen.host, port: server.address().port });
    } catch { if (phase !== 'CLOSING') phase = 'FAILED'; throw fail(503); }
  }
  function close() {
    if (closePromise) return closePromise;
    phase = 'CLOSING';
    closePromise = (async () => {
      if (startPromise) await startPromise.catch(() => {});
      const stopped = server.listening ? new Promise(resolve => server.close(resolve)) : Promise.resolve();
      for (const outgoing of upstreamRequests) outgoing.destroy();
      for (const socket of sockets) socket.destroy();
      await stopped; phase = 'CLOSED';
      return Object.freeze({ closed: true, listenerClosed: !server.listening });
    })();
    return closePromise;
  }
  return Object.freeze({ start, close, snapshot: () => Object.freeze({ profile, phase, pending, listenerOpen: server.listening }) });
}
