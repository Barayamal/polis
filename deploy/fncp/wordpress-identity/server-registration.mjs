/** Private server-to-server synthetic registration handoff. No browser-visible
 * WordPress cookie, CSRF value, challenge, receipt, fixture or signing material.
 * One network attempt per principal object per process; no automatic retries,
 * duplicate adoption, approval, invitation, email or voting authority.
 */
import { CONSENT_VERSION } from './registration-issuer.mjs';

const ORIGIN = 'http://127.0.0.1:8103';
const ENDPOINT = ORIGIN + '/wp-admin/admin-post.php';
const COOKIE = 'fncp_wp_identity';
const OPAQUE = /^[A-Za-z0-9_-]{43}$/u;
const REGISTRATION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const INPUT_KEYS = ['adultSelfAttested', 'eligibilitySelfAttested', 'registrationConsent', 'consentVersion'];
const codes = Object.freeze({
  INVALID_INPUT: [400, 'Local registration input rejected.'],
  IDENTITY_REQUIRED: [401, 'Current synthetic sign-in required.'],
  ATTEMPT_USED: [409, 'This registration attempt cannot be repeated.'],
  BUSY: [429, 'Local registration capacity reached.'],
  UNCONFIRMED: [503, 'Local registration could not be confirmed. Do not retry this submission.'],
});
export class ServerRegistrationError extends Error {
  constructor(code) {
    const [status, message] = codes[code] ?? codes.UNCONFIRMED;
    super(message); this.name = 'ServerRegistrationError'; this.status = status; this.code = code in codes ? code : 'UNCONFIRMED';
  }
}
const fail = code => { throw new ServerRegistrationError(code); };
function exact(value, keys) {
  return !!value && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}
function envelope(value, limit) {
  if (!exact(value, ['payload', 'signature']) || typeof value.payload !== 'string' || value.payload.length > limit ||
      !/^[A-Za-z0-9_-]+$/u.test(value.payload) || typeof value.signature !== 'string' || !/^[0-9a-f]{64}$/u.test(value.signature)) throw new Error();
  return Object.freeze({ payload: value.payload, signature: value.signature });
}
function abortable(operation, signal) {
  if (signal.aborted) return Promise.reject(new Error());
  return new Promise((resolve, reject) => {
    const abort = () => reject(new Error());
    signal.addEventListener('abort', abort, { once: true });
    Promise.resolve(operation).then(value => { signal.removeEventListener('abort', abort); resolve(value); },
      () => { signal.removeEventListener('abort', abort); reject(new Error()); });
  });
}
async function boundedJson(response, signal) {
  if (response?.status !== 200 || !/^application\/json(?:\s*;[^\r\n]*)?$/iu.test(response.headers?.get('content-type') ?? '') ||
      !/(?:^|,)\s*no-store\s*(?:,|$)/iu.test(response.headers.get('cache-control') ?? '')) throw new Error();
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d{1,8}$/u.test(declared) || Number(declared) > 8192)) throw new Error();
  if (!response.body?.getReader) throw new Error();
  const reader = response.body.getReader(); const chunks = []; let length = 0;
  try {
    for (;;) {
      const { done, value } = await abortable(reader.read(), signal);
      if (done) break;
      length += value.byteLength; if (length > 8192) throw new Error(); chunks.push(Buffer.from(value));
    }
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } finally {
    reader.cancel().catch(() => {}); reader.releaseLock();
  }
}
function guestCookie(headers, required) {
  if (typeof headers.getSetCookie !== 'function') throw new Error();
  const cookies = headers.getSetCookie();
  if (!required) { if (cookies.length !== 0) throw new Error(); return undefined; }
  if (cookies.length !== 1 || cookies[0].length > 1024) throw new Error();
  const [pair, ...parts] = cookies[0].split(';').map(part => part.trim());
  if (!pair.startsWith(COOKIE + '=') || !OPAQUE.test(pair.slice(COOKIE.length + 1))) throw new Error();
  const attrs = new Map();
  for (const part of parts) {
    const divider = part.indexOf('='); const key = (divider < 0 ? part : part.slice(0, divider)).toLowerCase();
    const value = divider < 0 ? '' : part.slice(divider + 1);
    if (attrs.has(key) || !['path', 'httponly', 'samesite', 'expires', 'max-age'].includes(key)) throw new Error();
    attrs.set(key, value);
  }
  if (attrs.get('path') !== '/' || !attrs.has('httponly') || attrs.get('httponly') !== '' ||
      attrs.get('samesite')?.toLowerCase() !== 'strict') throw new Error();
  return pair;
}

/** fetchImpl is trusted dependency injection for model tests, not a request
 * parameter. Origin/paths, credentials and limits cannot be selected by callers.
 * Browser sessions retain principal objects; the bridge never receives cookies
 * or caller-provided WordPress challenges. A fresh login cannot override WP's
 * immutable fixture index: an uncertain/duplicate registration is not adopted.
 */
export function createServerRegistrationBridge({ registrationIssuer, now = Date.now,
  fetchImpl = globalThis.fetch, requestTimeoutMs = 3000 } = {}) {
  if (registrationIssuer?.mode !== 'SYNTHETIC_ONLY' || typeof registrationIssuer.issue !== 'function' ||
      typeof now !== 'function' || typeof fetchImpl !== 'function' ||
      !Number.isInteger(requestTimeoutMs) || requestTimeoutMs < 1 || requestTimeoutMs > 3000) {
    throw new Error('Synthetic server registration configuration rejected.');
  }
  const issue = registrationIssuer.issue.bind(registrationIssuer);
  const used = new WeakSet(); let inFlight = 0;
  return Object.freeze({ mode: 'SYNTHETIC_ONLY', async register(request) {
    let principal; let deadline; let consent;
    try {
      if (!exact(request, ['principal', 'browserDeadline', 'input']) || !exact(request.input, INPUT_KEYS) ||
          request.input.adultSelfAttested !== true || request.input.eligibilitySelfAttested !== true ||
          request.input.registrationConsent !== true || request.input.consentVersion !== CONSENT_VERSION) fail('INVALID_INPUT');
      principal = request.principal; deadline = request.browserDeadline;
      if (!principal || typeof principal !== 'object' || !Object.isFrozen(principal) || Array.isArray(principal) ||
          principal.mode !== 'SYNTHETIC_ONLY' || principal.assurance !== 'OIDC_ID_TOKEN_VERIFIED') fail('IDENTITY_REQUIRED');
      const at = now();
      if (!Number.isSafeInteger(at) || !Number.isSafeInteger(deadline) || deadline <= at) fail('IDENTITY_REQUIRED');
      consent = Object.freeze(Object.fromEntries(INPUT_KEYS.map(key => [key, request.input[key]])));
    } catch (error) { if (error instanceof ServerRegistrationError) throw error; fail('INVALID_INPUT'); }
    if (used.has(principal)) fail('ATTEMPT_USED');
    if (inFlight >= 4) fail('BUSY');
    used.add(principal); inFlight++;
    const controller = new AbortController();
    let timer;
    try {
      const startedAt = now();
      if (!Number.isSafeInteger(startedAt) || startedAt >= deadline) throw new Error();
      timer = setTimeout(() => controller.abort(), Math.min(9000, deadline - startedAt));
      const current = () => {
        const at = now();
        if (!Number.isSafeInteger(at) || at < startedAt || at >= deadline || controller.signal.aborted) throw new Error();
      };
      const call = async (action, fields, cookie) => {
        current();
        const url = ENDPOINT + (fields === undefined ? '?action=' + action : '');
        const body = fields === undefined ? undefined : new URLSearchParams({ action, ...fields }).toString();
        if (body !== undefined && Buffer.byteLength(body) > 16384) throw new Error();
        const signal = AbortSignal.any([controller.signal, AbortSignal.timeout(requestTimeoutMs)]);
        const response = await abortable(fetchImpl(url, {
          method: fields === undefined ? 'GET' : 'POST', redirect: 'error', signal,
          headers: { 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'same-origin', 'Sec-Fetch-Dest': 'empty',
            ...(fields === undefined ? {} : { Origin: ORIGIN, 'Content-Type': 'application/x-www-form-urlencoded' }),
            ...(cookie ? { Cookie: cookie } : {}) }, ...(body === undefined ? {} : { body }),
        }), signal);
        try {
          if (response.url && response.url !== url) throw new Error();
          const json = await boundedJson(response, signal); current();
          return { json, headers: response.headers };
        } finally { response.body?.cancel().catch(() => {}); }
      };
      const session = await call('fncp_identity_session');
      if (!exact(session.json, ['mode', 'csrfToken']) || session.json.mode !== 'SYNTHETIC_ONLY' || !OPAQUE.test(session.json.csrfToken ?? '')) throw new Error();
      const cookie = guestCookie(session.headers, true); const csrfToken = session.json.csrfToken;
      const challenged = await call('fncp_identity_challenge', { csrfToken }, cookie);
      if (!exact(challenged.json, ['mode', 'challenge']) || challenged.json.mode !== 'SYNTHETIC_ONLY') throw new Error();
      guestCookie(challenged.headers, false);
      const challenge = envelope(challenged.json.challenge, 2048);
      current();
      const issued = await abortable(issue({ principal, browserDeadline: deadline, input: { ...consent, challenge } }), controller.signal);
      current();
      if (!exact(issued, ['mode', 'registrationOnly', 'eligibilityVerified', 'receipt']) ||
          issued.mode !== 'SYNTHETIC_ONLY' || issued.registrationOnly !== true || issued.eligibilityVerified !== false) throw new Error();
      const receipt = envelope(issued.receipt, 8192);
      const registered = await call('fncp_identity_register', { csrfToken, receipt: JSON.stringify(receipt) }, cookie);
      if (!exact(registered.json, ['mode', 'registered', 'registrationId', 'csrfToken']) ||
          registered.json.mode !== 'SYNTHETIC_ONLY' || registered.json.registered !== true ||
          typeof registered.json.registrationId !== 'string' || !REGISTRATION_ID.test(registered.json.registrationId) ||
          !OPAQUE.test(registered.json.csrfToken ?? '')) throw new Error();
      const rotatedCookie = guestCookie(registered.headers, true);
      if (rotatedCookie === cookie || registered.json.csrfToken === csrfToken) throw new Error();
      current();
      return Object.freeze({ registrationId: registered.json.registrationId, status: 'SUBMITTED_NOT_APPROVED' });
    } catch { fail('UNCONFIRMED'); }
    finally { clearTimeout(timer); controller.abort(); inFlight--; }
  } });
}
