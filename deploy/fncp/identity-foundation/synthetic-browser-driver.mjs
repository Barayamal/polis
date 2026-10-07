/**
 * Server/test-only bridge for a SYNTHETIC browser-cookie/CSRF proof.
 * No listeners, stores, redirects, fetch, or automatic identity grant.
 * The unchanged identity foundation still processes its exact HTTPS callback.
 * Only begin/complete belong in the BFF's authenticated server-side wiring.
 * injectTestResponse is a private in-process proof-driver capability: never
 * export it through an HTTP endpoint or make it available to browser scripts.
 * Its returned callback is delivered to the local BFF as same-origin CSRF JSON,
 * never navigated to, logged, persisted or transmitted to a real issuer.
 */
import { createHash, timingSafeEqual } from 'node:crypto';

const FAILED = Object.freeze({ ok: false, error: 'authentication_failed' });
const OK = Object.freeze({ ok: true });
const TTL_MS = 300_000;
const CAPACITY = 128;
const hash = (value) => createHash('sha256').update(value).digest();

function exact(input, keys) {
  return input !== null && typeof input === 'object' && !Array.isArray(input)
    && [Object.prototype, null].includes(Object.getPrototypeOf(input))
    && Object.keys(input).length === keys.length
    && keys.every((key) => Object.hasOwn(input, key));
}

function bindingKey(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{32,256}$/u.test(value)) throw new Error();
  return hash(value).toString('hex');
}

function syntheticUrl(value) {
  if (typeof value !== 'string' || value.length > 8192 || /[\u0000-\u0020\u007f]/u.test(value)) throw new Error();
  const url = new URL(value);
  if (url.protocol !== 'https:' || !url.hostname.endsWith('.invalid')
    || url.username || url.password || url.hash || url.href !== value) throw new Error();
  return url;
}

export function createSyntheticBrowserDriver(options) {
  let identity; let authorize; let now;
  try {
    if (!options || typeof options !== 'object' || Array.isArray(options)
      || Object.keys(options).some((key) => !['mode', 'identity', 'syntheticAuthorizationResponse', 'now'].includes(key))
      || options.mode !== 'SYNTHETIC_ONLY') throw new Error();
    identity = options.identity;
    authorize = options.syntheticAuthorizationResponse;
    now = options.now ?? Date.now;
    if (!identity || !['begin', 'complete', 'isVerifiedPrincipal'].every((name) => typeof identity[name] === 'function')
      || typeof authorize !== 'function' || typeof now !== 'function') throw new Error();
  } catch { throw new Error('Synthetic browser driver configuration rejected.'); }

  const flows = new Map();
  const stamp = () => {
    const value = now();
    if (!Number.isSafeInteger(value) || value < 0) throw new Error();
    return value;
  };
  function prune(at) {
    for (const [key, flow] of flows) {
      if (flow.created > at || flow.expires <= at) flows.delete(key);
    }
  }
  function current(key) {
    const at = stamp(); prune(at);
    const flow = flows.get(key);
    if (!flow || flow.created > at || flow.expires <= at) throw new Error();
    return flow;
  }

  return Object.freeze({
    mode: 'SYNTHETIC_ONLY',
    async begin(input) {
      let key; let flow;
      try {
        if (!exact(input, ['browserSessionId'])) throw new Error();
        key = bindingKey(input.browserSessionId);
        const at = stamp(); prune(at);
        if (!flows.has(key) && flows.size >= CAPACITY) throw new Error();
        flow = { phase: 'starting', created: at, expires: at + TTL_MS };
        flows.set(key, flow);
        const result = await identity.begin({ browserSessionId: input.browserSessionId });
        if (current(key) !== flow || result?.ok !== true) throw new Error();
        const url = syntheticUrl(result.authorizationUrl);
        const callback = syntheticUrl(url.searchParams.get('redirect_uri'));
        if (callback.search || !url.searchParams.has('state') || !url.searchParams.has('nonce')) throw new Error();
        flow.authorizationUrl = url.href;
        flow.callbackBase = callback.href;
        flow.phase = 'awaiting-injection';
        return OK;
      } catch {
        if (key && flows.get(key) === flow) flows.delete(key);
        return FAILED;
      }
    },

    async injectTestResponse(input) {
      let key; let flow; let ownsInjection = false;
      try {
        if (!exact(input, ['browserSessionId', 'syntheticSubject', 'emailVerifiedByIssuer'])) throw new Error();
        key = bindingKey(input.browserSessionId); flow = current(key);
        if (flow.phase !== 'awaiting-injection'
          || typeof input.syntheticSubject !== 'string' || !/^synthetic_[a-z][a-z0-9_]{0,63}$/u.test(input.syntheticSubject)
          || typeof input.emailVerifiedByIssuer !== 'boolean') throw new Error();
        // Mark before await: two operator injections cannot both create a grant.
        flow.phase = 'injecting';
        ownsInjection = true;
        const response = await authorize(flow.authorizationUrl, { claims: {
          sub: input.syntheticSubject,
          email: `${input.syntheticSubject}@example.invalid`,
          email_verified: input.emailVerifiedByIssuer,
        } });
        if (current(key) !== flow) throw new Error();
        const callback = syntheticUrl(response);
        if (`${callback.origin}${callback.pathname}` !== flow.callbackBase) throw new Error();
        flow.callbackHash = hash(callback.href);
        flow.authorizationUrl = undefined;
        flow.phase = 'awaiting-callback';
        return Object.freeze({ ok: true, callback: Object.freeze({ callbackUrl: callback.href }) });
      } catch {
        // A duplicate injection must not destroy the already-issued callback.
        if (key && ownsInjection && flows.get(key) === flow) flows.delete(key);
        return FAILED;
      }
    },

    async complete(input) {
      let key; let flow; let ownsCompletion = false;
      try {
        if (!exact(input, ['browserSessionId', 'callbackUrl'])) throw new Error();
        key = bindingKey(input.browserSessionId);
        flow = current(key);
        if (flow.phase !== 'awaiting-callback') throw new Error();
        // Consume before validation/await, but retain the in-flight record so
        // discard/new begin can cancel it and capacity remains bounded.
        flow.phase = 'completing'; ownsCompletion = true;
        if (typeof input.callbackUrl !== 'string'
          || input.callbackUrl.length > 8192 || !flow.callbackHash
          || !timingSafeEqual(flow.callbackHash, hash(input.callbackUrl))) throw new Error();
        const result = await identity.complete({ browserSessionId: input.browserSessionId, callbackUrl: input.callbackUrl });
        const at = stamp();
        if (flows.get(key) !== flow || at < flow.created || at >= flow.expires || result?.ok !== true
          || !identity.isVerifiedPrincipal(result.principal)) throw new Error();
        flows.delete(key);
        return Object.freeze({ ok: true, principal: result.principal });
      } catch {
        if (key && ownsCompletion && flows.get(key) === flow) flows.delete(key);
        // Premature complete burns only its own not-yet-issued flow; a duplicate
        // cannot cancel another request that already owns callback processing.
        else if (key && flow?.phase === 'awaiting-injection' && flows.get(key) === flow) flows.delete(key);
        return FAILED;
      }
    },

    discard(input) {
      try {
        if (!exact(input, ['browserSessionId'])) throw new Error();
        // Invalidates this driver's capability immediately. The foundation's
        // bounded pending entry is replaced on same-binding begin or expires;
        // no fake callback or automatic exchange is used to cancel it.
        flows.delete(bindingKey(input.browserSessionId));
        return OK;
      } catch { return FAILED; }
    },

    isVerifiedPrincipal(principal) {
      try { return identity.isVerifiedPrincipal(principal) === true; } catch { return false; }
    },
  });
}
