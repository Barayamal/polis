/** Pure server-side HTTPS redirect coordinator. SYNTHETIC_ONLY is mandatory.
 * No sockets, network default, signer, fixture injector, cookies or web routes.
 * The BFF owns the random browser binding and passes actual callback URLs here.
 * Cryptographic code/PKCE/nonce/issuer/token validation stays in the foundation.
 */
import { createHash, timingSafeEqual } from 'node:crypto';

const FAILURE = Object.freeze({ ok: false, error: 'authentication_failed' });
const OK = Object.freeze({ ok: true });
const TTL_MS = 300_000;
const CAPACITY = 128;
const opaque = /^[A-Za-z0-9_-]{32,256}$/u;
const digest = value => createHash('sha256').update(value).digest();
const fail = () => new Error('HTTPS redirect driver configuration rejected.');

function shape(value, keys, optional = []) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw fail();
  const names = Reflect.ownKeys(value);
  if (names.some(key => typeof key !== 'string' || ![...keys, ...optional].includes(key)) ||
      keys.some(key => !Object.hasOwn(value, key)) ||
      Object.values(Object.getOwnPropertyDescriptors(value)).some(item => !Object.hasOwn(item, 'value'))) throw fail();
}
function text(value, max = 2048) {
  return typeof value === 'string' && value.length > 0 && value.length <= max &&
    !/[\u0000-\u0020\u007f]/u.test(value);
}
function url(value, query = false) {
  if (!text(value, 8192)) throw fail();
  const parsed = new URL(value);
  if (parsed.protocol !== 'https:' || !parsed.hostname.endsWith('.invalid') ||
      parsed.hostname === '.invalid' || parsed.username || parsed.password || value.includes('#') ||
      (!query && value.includes('?')) || parsed.href !== value) throw fail();
  return parsed;
}
function keyOf(value) {
  if (typeof value !== 'string' || !opaque.test(value)) throw fail();
  return digest(value).toString('hex');
}
function parameters(parsed, names) {
  for (const [name, value] of parsed.searchParams) {
    if (!names.includes(name) || parsed.searchParams.getAll(name).length !== 1 ||
        typeof value !== 'string' || !value || value.length > 2048 || /[\u0000-\u001f\u007f]/u.test(value)) throw fail();
  }
}

export function createHttpsRedirectDriver(options) {
  let identity; let authorizationEndpoint; let callbackUri; let now;
  try {
    shape(options, ['mode', 'identity', 'authorizationEndpoint', 'callbackUri'], ['now']);
    if (options.mode !== 'SYNTHETIC_ONLY') throw fail();
    authorizationEndpoint = url(options.authorizationEndpoint).href;
    callbackUri = url(options.callbackUri).href;
    if (authorizationEndpoint === callbackUri) throw fail();
    if (!options.identity || ['begin', 'complete', 'isVerifiedPrincipal'].some(name =>
      typeof options.identity[name] !== 'function')) throw fail();
    // Capture these private adapter methods once; later caller reassignment is
    // not authority to replace the reviewed foundation during a live flow.
    identity = Object.freeze(Object.fromEntries(['begin', 'complete', 'isVerifiedPrincipal']
      .map(name => [name, options.identity[name].bind(options.identity)])));
    now = options.now ?? Date.now;
    if (typeof now !== 'function') throw fail();
  } catch { throw fail(); }

  const flows = new Map();
  let latest = -1;
  function stamp() {
    let at;
    try { at = now(); } catch { flows.clear(); throw fail(); }
    if (!Number.isSafeInteger(at) || at < 0 || at > Number.MAX_SAFE_INTEGER - TTL_MS || at < latest) {
      flows.clear(); throw fail();
    }
    latest = at;
    return at;
  }
  function prune(at) {
    for (const [key, flow] of flows) if (flow.expires <= at || flow.created > at) flows.delete(key);
  }
  function current(key) {
    const at = stamp(); prune(at);
    const flow = flows.get(key);
    if (!flow) throw fail();
    return flow;
  }
  // Reject an invalid clock without leaving a partly configured capability.
  try { stamp(); } catch { throw fail(); }

  return Object.freeze({
    mode: 'SYNTHETIC_ONLY', transport: 'HTTPS_REDIRECT_LAB', authorizationEndpoint, callbackUri,
    async begin(input) {
      let key; let flow;
      try {
        shape(input, ['browserSessionId']); key = keyOf(input.browserSessionId);
        const at = stamp(); prune(at);
        if (!flows.has(key) && flows.size >= CAPACITY) throw fail();
        flow = { phase: 'starting', created: at, expires: at + TTL_MS };
        flows.set(key, flow); // Reserve through awaits, including unresponsive adapters.
        const result = await identity.begin({ browserSessionId: input.browserSessionId });
        if (current(key) !== flow || result?.ok !== true) throw fail();
        const authorization = url(result.authorizationUrl, true);
        if (authorization.origin + authorization.pathname !== authorizationEndpoint) throw fail();
        parameters(authorization, ['client_id', 'redirect_uri', 'response_type', 'response_mode',
          'scope', 'code_challenge', 'code_challenge_method', 'state', 'nonce']);
        const p = authorization.searchParams;
        if (p.size !== 9 || !text(p.get('client_id'), 256) || p.get('redirect_uri') !== callbackUri ||
            p.get('response_type') !== 'code' || p.get('response_mode') !== 'query' ||
            p.get('scope') !== 'openid email' || p.get('code_challenge_method') !== 'S256' ||
            !/^[A-Za-z0-9_-]{43}$/u.test(p.get('code_challenge') ?? '') ||
            !opaque.test(p.get('state') ?? '') || !opaque.test(p.get('nonce') ?? '')) throw fail();
        flow.stateHash = digest(p.get('state')); flow.phase = 'awaiting-callback';
        return Object.freeze({ ok: true, authorizationUrl: authorization.href });
      } catch {
        if (key && flows.get(key) === flow) flows.delete(key);
        return FAILURE;
      }
    },
    async complete(input) {
      let key; let flow; let ownsCompletion = false;
      try {
        shape(input, ['browserSessionId', 'callbackUrl']); key = keyOf(input.browserSessionId);
        flow = current(key);
        if (flow.phase !== 'awaiting-callback') throw fail();
        // Keep the consumed record until settlement for bounded admission and
        // discard/new-begin cancellation. A duplicate cannot cancel its owner.
        flow.phase = 'completing'; ownsCompletion = true;
        const callback = url(input.callbackUrl, true);
        if (callback.origin + callback.pathname !== callbackUri) throw fail();
        parameters(callback, ['code', 'state', 'iss', 'error', 'error_description', 'error_uri']);
        const p = callback.searchParams;
        if (p.size !== 3 || !text(p.get('code')) || !opaque.test(p.get('state') ?? '') ||
            !text(p.get('iss')) || !flow.stateHash ||
            !timingSafeEqual(flow.stateHash, digest(p.get('state')))) throw fail();
        // The foundation, not browser claims or this coordinator, verifies the
        // configured issuer, nonce, PKCE, signature, audience and expiry.
        const result = await identity.complete({ browserSessionId: input.browserSessionId, callbackUrl: callback.href });
        if (current(key) !== flow || result?.ok !== true || identity.isVerifiedPrincipal(result.principal) !== true) throw fail();
        flows.delete(key);
        return Object.freeze({ ok: true, principal: result.principal });
      } catch {
        if (key && ownsCompletion && flows.get(key) === flow) flows.delete(key);
        // A callback received before begin settles burns that unfinished flow;
        // it cannot later become a valid browser login without a new begin.
        else if (key && flow?.phase === 'starting' && flows.get(key) === flow) flows.delete(key);
        return FAILURE;
      }
    },
    discard(input) {
      try {
        shape(input, ['browserSessionId']); flows.delete(keyOf(input.browserSessionId));
        // The underlying bounded foundation transaction expires/replaces itself;
        // cancellation never performs a fake callback or token exchange.
        return OK;
      } catch { return FAILURE; }
    },
    isVerifiedPrincipal(principal) {
      try { return identity.isVerifiedPrincipal(principal) === true; } catch { return false; }
    },
  });
}
