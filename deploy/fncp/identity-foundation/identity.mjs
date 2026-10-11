import { createHash, createHmac } from 'node:crypto';
import * as oidc from 'openid-client';
import { boundedJsonResponse } from './bounded-response.mjs';

const FAILURE = Object.freeze({ ok: false, error: 'authentication_failed' });
const MODE = 'SYNTHETIC_ONLY';
const TRANSACTION_TTL_MS = 300_000;
const MAX_PENDING = 128;

function exactObject(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).every((key) => keys.includes(key));
}

function text(value, max = 2048) {
  return typeof value === 'string' && value.length > 0 && value.length <= max
    && !/[\u0000-\u001f\u007f]/u.test(value);
}

function httpsUrl(value) {
  if (!text(value)) throw new Error();
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash
    || url.href !== value) throw new Error();
  return value;
}

function sessionKey(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{32,256}$/u.test(value)) throw new Error();
  return createHash('sha256').update(value).digest('base64url');
}

/**
 * Offline protocol foundation, not production authentication. No network default,
 * server, cookie, email transport, participant registration or eligibility grant.
 * Caller must supply its server-side random session binding, never a query value.
 */
export function createIdentityFoundation(options) {
  try {
    if (!exactObject(options, ['mode', 'issuer', 'authorizationEndpoint', 'tokenEndpoint',
      'jwksUri', 'callbackUri', 'clientId', 'clientSecret', 'signingAlgorithm', 'identityKey',
      'transport', 'now', 'trustedAdditionalAudiences']) || options.mode !== MODE) throw new Error();
    const issuer = httpsUrl(options.issuer);
    const authorizationEndpoint = httpsUrl(options.authorizationEndpoint);
    const tokenEndpoint = httpsUrl(options.tokenEndpoint);
    const jwksUri = httpsUrl(options.jwksUri);
    const callbackUri = httpsUrl(options.callbackUri);
    if (new Set([authorizationEndpoint, tokenEndpoint, jwksUri, callbackUri]).size !== 4
      || !text(options.clientId, 256)
      || !['RS256', 'ES256'].includes(options.signingAlgorithm)
      || !(options.identityKey instanceof Uint8Array) || options.identityKey.byteLength < 32
      || options.identityKey.byteLength > 64
      || !exactObject(options.transport, ['kind', 'fetch'])
      || options.transport.kind !== 'SYNTHETIC_INTERCEPT'
      || typeof options.transport.fetch !== 'function'
      || (options.now !== undefined && typeof options.now !== 'function')
      || (options.clientSecret !== undefined && !text(options.clientSecret))) throw new Error();

    const identityKey = Buffer.from(options.identityKey);
    const clientId = options.clientId;
    const additionalAudiences = options.trustedAdditionalAudiences ?? [];
    if (!Array.isArray(additionalAudiences) || additionalAudiences.length > 8
      || !additionalAudiences.every((audience) => text(audience, 256) && audience !== clientId)
      || new Set(additionalAudiences).size !== additionalAudiences.length) throw new Error();
    const trustedAudiences = new Set([clientId, ...additionalAudiences]);
    const transport = options.transport.fetch;
    const now = options.now ?? Date.now;
    const pending = new Map();
    const principals = new WeakMap();
    const hmac = (parts) => createHmac('sha256', identityKey)
      .update(JSON.stringify(parts)).digest('base64url');
    const instant = () => {
      const value = now();
      if (!Number.isSafeInteger(value) || value < 0) throw new Error();
      return value;
    };
    const config = new oidc.Configuration({
      issuer,
      authorization_endpoint: authorizationEndpoint,
      token_endpoint: tokenEndpoint,
      jwks_uri: jwksUri,
      response_types_supported: ['code'],
      code_challenge_methods_supported: ['S256'],
      id_token_signing_alg_values_supported: [options.signingAlgorithm],
      // Require the response issuer (RFC 9207); do not infer it from the browser.
      authorization_response_iss_parameter_supported: true,
    }, clientId, {
      id_token_signed_response_alg: options.signingAlgorithm,
      [oidc.clockTolerance]: 0,
    }, options.clientSecret === undefined ? oidc.None() : oidc.ClientSecretBasic(options.clientSecret));
    config.timeout = 5;
    config[oidc.customFetch] = async (input, init) => {
      const url = String(input);
      const method = (init?.method ?? 'GET').toUpperCase();
      if (!((url === tokenEndpoint && method === 'POST') || (url === jwksUri && method === 'GET')))
        throw new Error();
      // Independently enforce the full response deadline even when an injected
      // adapter ignores the library's abort signal. No redirect/cookie defaults.
      return boundedJsonResponse(transport, input, init);
    };
    // Code-flow TLS checks alone are insufficient for this foundation's proof.
    // The maintained library resolves configured JWKS and verifies JWS signatures.
    oidc.enableNonRepudiationChecks(config);

    function prune(at) {
      for (const [key, transaction] of pending) {
        if (transaction.expiresAt <= at || transaction.createdAt > at) pending.delete(key);
      }
    }

    function verifiedRecord(principal) {
      const record = principal && typeof principal === 'object' && principals.get(principal);
      const at = instant();
      if (!record || record.expiresAt <= at || record.verifiedAt > at) throw new Error();
      return record;
    }

    return Object.freeze({
      async begin(input) {
        let key;
        let transaction;
        try {
          if (!exactObject(input, ['browserSessionId'])) throw new Error();
          key = sessionKey(input.browserSessionId);
          const at = instant();
          prune(at);
          if (!pending.has(key) && pending.size >= MAX_PENDING) throw new Error();
          transaction = {
            state: oidc.randomState(), nonce: oidc.randomNonce(),
            verifier: oidc.randomPKCECodeVerifier(), createdAt: at,
            expiresAt: at + TRANSACTION_TTL_MS,
          };
          // Reserve capacity before the asynchronous challenge calculation.
          pending.set(key, transaction);
          const challenge = await oidc.calculatePKCECodeChallenge(transaction.verifier);
          if (pending.get(key) !== transaction) throw new Error();
          const authorizationUrl = oidc.buildAuthorizationUrl(config, {
            redirect_uri: callbackUri, response_type: 'code', response_mode: 'query',
            scope: 'openid email', code_challenge: challenge, code_challenge_method: 'S256',
            state: transaction.state, nonce: transaction.nonce,
          });
          return Object.freeze({ ok: true, authorizationUrl: authorizationUrl.href });
        } catch {
          if (key && pending.get(key) === transaction) pending.delete(key);
          return FAILURE;
        }
      },

      async complete(input) {
        try {
          if (!exactObject(input, ['browserSessionId', 'callbackUrl'])) throw new Error();
          const key = sessionKey(input.browserSessionId);
          const transaction = pending.get(key);
          // One-use even on a malformed callback, provider error, or uncertain grant.
          // Delete before any await so two concurrent callbacks cannot both redeem.
          pending.delete(key);
          const at = instant();
          prune(at);
          if (!transaction || transaction.expiresAt <= at || transaction.createdAt > at
            || !text(input.callbackUrl, 8192)) throw new Error();
          const callback = new URL(input.callbackUrl);
          if (callback.hash || callback.username || callback.password
            || callback.href !== input.callbackUrl
            || `${callback.origin}${callback.pathname}` !== callbackUri) throw new Error();
          const allowed = ['code', 'state', 'iss', 'error', 'error_description', 'error_uri'];
          for (const [name, value] of callback.searchParams) {
            if (!allowed.includes(name) || callback.searchParams.getAll(name).length !== 1
              || !text(value)) throw new Error();
          }
          if (callback.searchParams.get('iss') !== issuer || callback.searchParams.has('error')
            || callback.searchParams.has('error_description') || callback.searchParams.has('error_uri')
            || !callback.searchParams.has('code')) throw new Error();
          const tokens = await oidc.authorizationCodeGrant(config, callback, {
            pkceCodeVerifier: transaction.verifier,
            expectedState: transaction.state,
            expectedNonce: transaction.nonce,
            idTokenExpected: true,
          });
          const claims = tokens.claims();
          const verifiedAt = instant();
          // Additional strict profile checks on already cryptographically verified
          // claims, not a second hand-written JWT decoder or signature verifier.
          const seconds = Math.floor(Date.now() / 1000);
          if (verifiedAt >= transaction.expiresAt || verifiedAt < transaction.createdAt
            || !claims || !text(claims.sub, 255)
            || !Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp)
            || claims.iat > seconds || claims.iat < seconds - 600
            || claims.exp <= claims.iat || claims.exp > claims.iat + 3600
            || claims.exp * 1000 <= verifiedAt
            || (claims.azp !== undefined && claims.azp !== clientId)
            || (Array.isArray(claims.aud) && (new Set(claims.aud).size !== claims.aud.length
              || !claims.aud.every((audience) => trustedAudiences.has(audience))))) throw new Error();
          const accountId = `acct_${hmac(['fncp-account-v1', issuer, claims.sub])}`;
          const principal = Object.freeze({
            accountId,
            emailVerifiedByIssuer: claims.email_verified === true && text(claims.email, 320),
            assurance: 'OIDC_ID_TOKEN_VERIFIED',
            eligibilityVerified: false,
            mode: MODE,
          });
          // Discard tokens, raw subject, email and all unselected claims. Issuer+
          // sub (never email) determines this stable opaque account pseudonym.
          principals.set(principal, {
            accountId, verifiedAt,
            expiresAt: Math.min(claims.exp * 1000, verifiedAt + 900_000),
          });
          return Object.freeze({ ok: true, principal });
        } catch {
          return FAILURE;
        }
      },

      isVerifiedPrincipal(principal) {
        try { verifiedRecord(principal); return true; } catch { return false; }
      },

      // Private server-side metadata, not a browser/session or eligibility grant.
      principalDeadline(principal) {
        try { return verifiedRecord(principal).expiresAt; } catch { return null; }
      },

      participantXid(principal, roundId) {
        try {
          const record = verifiedRecord(principal);
          if (typeof roundId !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/u.test(roundId)) throw new Error();
          return Object.freeze({ ok: true, xid: `fncp_${hmac(['fncp-xid-v1', record.accountId, roundId])}` });
        } catch { return FAILURE; }
      },

      publicResult(result) {
        try {
          if (result?.ok !== true) throw new Error();
          verifiedRecord(result.principal);
          return Object.freeze({ ok: true, authenticated: true, mode: MODE,
            emailVerifiedByIssuer: result.principal.emailVerifiedByIssuer,
            eligibilityVerified: false, productionReady: false });
        } catch { return FAILURE; }
      },
    });
  } catch {
    // Do not include configured URLs, secrets, token bodies or upstream errors.
    throw new Error('Identity foundation configuration rejected.');
  }
}
