/** Real, bounded loopback HTTPS transport for active bootstrap protocol calls.
 * Import performs no I/O. This does NOT implement Docker helper ownership:
 * assertOwned is a required trusted runtime-manager callback, not a sandbox or
 * independently verified attestation. There is no default manager or launcher.
 * Only use an endpoint/certificate created and owned by that manager. Tests use
 * newly created synthetic TLS services, not retained or actual Pol.is services.
 */
import { request } from 'node:https';
import { X509Certificate, createHash } from 'node:crypto';
import { checkServerIdentity } from 'node:tls';
import { isProxy } from 'node:util/types';
import { claimBootstrapIssuerForTransport } from './bootstrap-issuer.mjs';
import { httpRequestForBootstrap, verifyBootstrapProtocolRequest, bootstrapHttpAuthority } from './bootstrap-protocol.mjs';

const failure = () => new Error('Fresh bootstrap HTTPS transport rejected; private details withheld.');
const MAX_BYTES = 65536;
const DEADLINE_MS = 2000;
const MAX_REQUESTS = 19; // create + 15 seeds + seeds GET + close PUT + flags GET
function exact(value, names) {
  if (!value || typeof value !== 'object' || isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value)) || Reflect.ownKeys(value).length !== names.length) throw failure();
  const fields = Object.getOwnPropertyDescriptors(value);
  if (names.some(name => !fields[name] || !Object.hasOwn(fields[name], 'value'))) throw failure();
  return Object.fromEntries(names.map(name => [name, fields[name].value]));
}

export function createBootstrapHttpTransport(options) {
  if (arguments.length !== 1) throw failure();
  const { origin, certificatePem, issuer, assertOwned } = exact(options, ['origin', 'certificatePem', 'issuer', 'assertOwned']);
  let url; let credential; let certificateSha256;
  try {
    if (typeof origin !== 'string' || !/^https:\/\/127\.0\.0\.1:[1-9][0-9]{3,4}$/u.test(origin) ||
        typeof certificatePem !== 'string' || Buffer.byteLength(certificatePem) > 8192 ||
        typeof assertOwned !== 'function' || isProxy(assertOwned)) throw failure();
    url = new URL(origin);
    if (Number(url.port) < 1024 || Number(url.port) > 65535 || url.origin !== origin) throw failure();
    if (!/^-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+\n-----END CERTIFICATE-----\n?$/u.test(certificatePem)) throw failure();
    const cert = new X509Certificate(certificatePem);
    if (cert.checkIP('127.0.0.1') !== '127.0.0.1' || Date.parse(cert.validFrom) > Date.now() || Date.parse(cert.validTo) <= Date.now()) throw failure();
    certificateSha256 = createHash('sha256').update(cert.raw).digest('hex');
    credential = claimBootstrapIssuerForTransport(issuer);
  } catch { throw failure(); }
  const lease = Object.freeze({ origin, certificateSha256 }); // private, not aggregate evidence
  const consumed = new WeakSet();
  let closed = false; let failed = false; let busy = false; let pending; let scope; let authority; let ownedWait; let interrupt;
  const counts = { dispatched: 0, tlsResponses: 0, acceptedResponses: 0 };
  const check = async activeRequest => {
    if (closed || failed || authority?.signal.aborted) throw failure();
    credential.assertActive();
    await verifyBootstrapProtocolRequest(activeRequest);
    // The owner must reject cancellation, process replacement, invalid image or
    // stale resource identity. No caller-supplied boolean becomes verified proof.
    let timer; let rejectWait;
    const stop = () => rejectWait(failure());
    try {
      const denied = new Promise((resolve, reject) => {
        rejectWait = reject; ownedWait = stop; timer = setTimeout(stop, DEADLINE_MS);
        authority.signal.addEventListener('abort', stop, { once: true });
        if (closed || authority.signal.aborted) stop();
      });
      if (await Promise.race([Promise.resolve().then(() => {
        if (closed || failed || authority.signal.aborted) throw failure();
        return assertOwned(lease);
      }), denied]) !== undefined) throw failure();
    } finally { clearTimeout(timer); authority.signal.removeEventListener('abort', stop); if (ownedWait === stop) ownedWait = undefined; }
    credential.assertActive();
    await verifyBootstrapProtocolRequest(activeRequest);
    if (closed || failed || authority.signal.aborted) throw failure();
  };
  return Object.freeze({
    async send(activeRequest) {
      if (arguments.length !== 1 || closed || failed || busy || !activeRequest || typeof activeRequest !== 'object' ||
          isProxy(activeRequest) || consumed.has(activeRequest) || counts.dispatched >= MAX_REQUESTS) throw failure();
      busy = true; consumed.add(activeRequest);
      let signal; let abort; let deadlineTimer;
      const deadline = new Promise((resolve, reject) => {
        interrupt = () => { failed = true; ownedWait?.(); pending?.(); reject(failure()); };
        deadlineTimer = setTimeout(interrupt, DEADLINE_MS);
      });
      const run = async () => {
        authority = await bootstrapHttpAuthority(activeRequest);
        if (closed || failed) throw failure();
        if (scope !== undefined && scope !== authority.scope) throw failure();
        scope = authority.scope; signal = authority.signal;
        abort = interrupt;
        signal.addEventListener('abort', abort, { once: true });
        if (signal.aborted) throw failure();
        await check(activeRequest);
        const descriptor = await httpRequestForBootstrap(activeRequest);
        await check(activeRequest);
        // Consume before socket creation. An uncertain mutation is never retried,
        // including a caller repeating the same still-active branded request.
        counts.dispatched++;
        const response = await new Promise((resolve, reject) => {
          let req; let res; let done = false;
          const finish = (ok, value) => {
            if (done) return; done = true; clearTimeout(timer); pending = undefined;
            if (!ok) { failed = true; res?.destroy(); req?.destroy(); reject(failure()); }
            else resolve(value);
          };
          const timer = setTimeout(() => finish(false), DEADLINE_MS);
          pending = () => finish(false);
          try {
            const headers = { ...descriptor.headers, host: url.host, connection: 'close',
              authorization: 'Bearer ' + credential.token };
            if (descriptor.body !== null) headers['content-length'] = String(Buffer.byteLength(descriptor.body));
            req = request({ hostname: '127.0.0.1', port: Number(url.port), path: descriptor.path,
              method: descriptor.method, headers, ca: certificatePem, rejectUnauthorized: true,
              minVersion: 'TLSv1.2', agent: false, maxHeaderSize: 8192,
              checkServerIdentity(host, peer) {
                // Retain Node's normal IP-SAN check, then require the exact
                // owned leaf BEFORE releasing the bearer over this TLS socket.
                if (checkServerIdentity(host, peer) || !Buffer.isBuffer(peer.raw) ||
                    createHash('sha256').update(peer.raw).digest('hex') !== certificateSha256) return failure();
              },
              // No custom resolver, SNI override, redirect, proxy, cookie jar,
              // ambient CA or bearer-token refresh.
            }, incoming => {
              res = incoming;
              res.on('error', () => finish(false)); res.on('aborted', () => finish(false));
              if (closed || req.socket.remoteAddress !== '127.0.0.1' || req.socket.authorized !== true ||
                  !['TLSv1.2', 'TLSv1.3'].includes(req.socket.getProtocol())) { finish(false); return; }
              counts.tlsResponses++;
              const occurrences = name => res.rawHeaders.filter((field, i) => i % 2 === 0 && field.toLowerCase() === name).length;
              if (res.statusCode !== 200 || occurrences('content-type') !== 1 ||
                  !/^application\/json(?:; charset=utf-8)?$/iu.test(res.headers['content-type']) ||
                  res.headers.location !== undefined || res.headers['content-encoding'] !== undefined ||
                  (res.headers['content-length'] !== undefined &&
                    (!/^(0|[1-9][0-9]*)$/u.test(res.headers['content-length']) || Number(res.headers['content-length']) > MAX_BYTES))) {
                finish(false); return;
              }
              let size = 0; const chunks = [];
              res.on('data', chunk => { size += chunk.length; if (size > MAX_BYTES) finish(false); else chunks.push(Buffer.from(chunk)); });
              res.on('end', () => {
                try {
                  if (!res.complete || closed) throw failure();
                  // Preserve a BOM for protocol rejection; do not normalize
                  // malformed JSON bytes into apparently canonical JSON.
                  const body = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(Buffer.concat(chunks));
                  // JSON/domain invariants are checked by the protocol. Do not
                  // rewrite ambiguous upstream JSON into apparently clean JSON.
                  finish(true, Object.freeze({ status: 200, body }));
                } catch { finish(false); }
              });
            });
            req.on('error', () => finish(false)); req.end(descriptor.body ?? undefined);
          } catch { finish(false); }
        });
        await check(activeRequest); counts.acceptedResponses++; return response;
      };
      try {
        return await Promise.race([run(), deadline]);
      } catch { failed = true; throw failure(); }
      finally { clearTimeout(deadlineTimer); interrupt = undefined; if (signal && abort) signal.removeEventListener('abort', abort); busy = false; }
    },
    close() {
      if (arguments.length) throw failure();
      closed = true; interrupt?.(); ownedWait?.(); pending?.(); credential = undefined;
      // Denies transport only: caller independently closes helper + issuer.
    },
    summary() {
      if (arguments.length) throw failure();
      return Object.freeze({ mode: 'BOUNDED_LOOPBACK_HTTPS', ownership: 'TRUSTED_CALLBACK_NOT_INDEPENDENTLY_PROVED',
        actualPolisVerified: false, containerRuntimeVerified: false, productionReady: false,
        closed, failed, busy, ...counts, maximumRequests: MAX_REQUESTS, responseByteLimit: MAX_BYTES,
        requestDeadlineMs: DEADLINE_MS, wholeSendDeadlineMs: DEADLINE_MS, retries: 0, redirectsFollowed: 0 });
    },
  });
}
