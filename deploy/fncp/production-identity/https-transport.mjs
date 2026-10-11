import { X509Certificate } from 'node:crypto';
import { request } from 'node:https';
import { performance } from 'node:perf_hooks';
import { checkServerIdentity } from 'node:tls';
import { isIP } from 'node:net';
import { validateTransportRelay } from './relay-route.mjs';

const fail = () => new Error('OIDC transport unavailable.');
const MAX_BYTES = 65_536;
const MAX_REQUEST_BYTES = 16_384;
const MAX_CONCURRENT = 32;

export function canonicalHttpsUrl(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 2048
    || /[\u0000-\u0020\u007f]/u.test(value)) throw fail();
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash
    || url.href !== value) throw fail();
  return value;
}

function certificateBundle(value) {
  if (value === undefined) return undefined; // Node's verified default trust store.
  if (!(value instanceof Uint8Array) || value.byteLength < 1 || value.byteLength > MAX_BYTES) throw fail();
  const ca = Buffer.from(value);
  const pem = ca.toString('utf8');
  const certificates = pem.match(/-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----/gu);
  if (!certificates?.length || pem.replace(/-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----/gu, '').trim()) throw fail();
  for (const certificate of certificates) new X509Certificate(certificate);
  return ca;
}

/** Native HTTPS only. There is no caller-supplied fetch, resolver, agent, TLS
 * verification override, proxy, discovery URL or redirect-following option.
 * A smaller timeout is useful for tests; the five-second ceiling cannot rise.
 */
export function createOidcHttpsTransport({ tokenEndpoint, jwksUri, ca, timeoutMs = 5000, relay }) {
  try {
    tokenEndpoint = canonicalHttpsUrl(tokenEndpoint);
    jwksUri = canonicalHttpsUrl(jwksUri);
    ca = certificateBundle(ca);
    if (relay !== undefined) relay = validateTransportRelay(relay, tokenEndpoint, jwksUri);
    if (tokenEndpoint === jwksUri || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 5000) throw fail();
  } catch { throw fail(); }
  const active = new Set();
  let closed = false;

  async function fetch(input, init = {}) {
    const url = typeof input === 'string' || input instanceof URL ? String(input) : '';
    const method = init.method ?? 'GET';
    let body; let headers;
    try {
      if (closed || active.size >= MAX_CONCURRENT || init.signal?.aborted
        || !((url === tokenEndpoint && method === 'POST') || (url === jwksUri && method === 'GET'))
        || (init.signal !== undefined && !(init.signal instanceof AbortSignal))) throw fail();
      headers = new Headers(init.headers);
      if ([...headers.keys()].some(name => !['accept', 'content-type', 'authorization', 'user-agent'].includes(name))
        || (method === 'GET' && headers.has('authorization'))) throw fail();
      body = init.body === undefined ? undefined : init.body instanceof URLSearchParams
        ? init.body.toString() : typeof init.body === 'string' ? init.body : null;
      if (body === null || (method === 'GET' && body !== undefined)
        || (method === 'POST' && (body === undefined || Buffer.byteLength(body) > MAX_REQUEST_BYTES
          || headers.get('content-type')?.split(';')[0] !== 'application/x-www-form-urlencoded'))
        || [...headers].some(([, value]) => value.length > 8192)) throw fail();
    } catch { throw fail(); }

    return new Promise((resolve, reject) => {
      let settled = false; let req; let response;
      const deadline = performance.now() + timeoutMs;
      const finish = (error, result) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        init.signal?.removeEventListener('abort', abort);
        active.delete(abort);
        if (error) { response?.destroy(); req?.destroy(); reject(fail()); }
        else resolve(result);
      };
      const abort = () => finish(fail());
      const timer = setTimeout(abort, timeoutMs);
      active.add(abort);
      init.signal?.addEventListener('abort', abort, { once: true });
      if (init.signal?.aborted || closed) { abort(); return; }
      try {
        const endpoint = new URL(url);
        const tlsHostname = endpoint.hostname.replace(/^\[|\]$/gu, '');
        const route = relay ? { hostname: relay.host,
          port: url === tokenEndpoint ? relay.tokenPort : relay.jwksPort,
          servername: isIP(tlsHostname) ? '' : tlsHostname,
          checkServerIdentity: (_relayHost, certificate) => checkServerIdentity(tlsHostname, certificate) } : {};
        req = request(url, {
          method, ca, rejectUnauthorized: true, minVersion: 'TLSv1.2',
          checkServerIdentity, agent: false, maxHeaderSize: 16_384,
          ...route,
          headers: { ...Object.fromEntries(headers), host: endpoint.host, connection: 'close',
            ...(body === undefined ? {} : { 'content-length': Buffer.byteLength(body) }) },
        }, res => {
          response = res;
          const contentType = res.headers['content-type'];
          const status = res.statusCode;
          if (closed || req.socket.authorized !== true || performance.now() >= deadline
            || !Number.isInteger(status) || status < 200 || status >= 500 || (status >= 300 && status < 400)
            || typeof contentType !== 'string' || !/^application\/(?:[a-z0-9.+-]+\+)?json(?:\s*;|$)/iu.test(contentType)
            || res.headers['content-encoding'] !== undefined) { abort(); return; }
          const chunks = []; let size = 0;
          res.on('data', chunk => {
            size += chunk.length;
            if (closed || size > MAX_BYTES || performance.now() >= deadline) { abort(); return; }
            if (chunk.length) chunks.push(Buffer.from(chunk));
          });
          res.on('aborted', abort); res.on('error', abort);
          res.on('end', () => {
            if (settled) return;
            try {
              if (closed || !res.complete || size < 1 || performance.now() >= deadline) throw fail();
              // Set-Cookie, upstream request IDs and unneeded headers never enter
              // the OAuth client. Bodies remain private to protocol processing.
              finish(null, new Response(Buffer.concat(chunks), { status,
                headers: { 'content-type': contentType } }));
            } catch { abort(); }
          });
        });
        req.on('error', abort);
        if (body !== undefined) req.write(body);
        req.end();
      } catch { abort(); }
    });
  }

  return Object.freeze({ fetch, close() {
    closed = true;
    for (const abort of [...active]) abort();
  } });
}
