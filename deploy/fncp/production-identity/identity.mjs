import { createHash, createHmac } from 'node:crypto';
import * as oidc from 'openid-client';
import { canonicalHttpsUrl, createOidcHttpsTransport } from './https-transport.mjs';
import { validateOidcRelayRoute } from './relay-route.mjs';

export const PARTICIPANT_IDENTITY_PROFILE = 'OIDC_PARTICIPANT_V1';
const FAILURE = Object.freeze({ ok: false, error: 'authentication_failed' });
const TRANSACTION_TTL_MS = 300_000;
const PRINCIPAL_TTL_MS = 900_000;
const MAX_PENDING = 128;
const adapters = new WeakSet();

export function isProductionIdentityAdapter(value) {
  return value !== null && typeof value === 'object' && adapters.has(value);
}

function fields(value, required, optional = []) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new Error();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const actual = Reflect.ownKeys(descriptors);
  if (required.some(key => !actual.includes(key)) || actual.some(key => typeof key !== 'string'
    || ![...required, ...optional].includes(key) || !Object.hasOwn(descriptors[key], 'value'))) throw new Error();
  return Object.fromEntries(actual.map(key => [key, descriptors[key].value]));
}

function text(value, max = 2048) {
  return typeof value === 'string' && value.length > 0 && value.length <= max
    && !/[\u0000-\u001f\u007f]/u.test(value);
}

function sessionKey(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43,256}$/u.test(value)) throw new Error();
  return createHash('sha256').update(value).digest('base64url');
}

/** Participant authentication only: this module grants no registration, adult
 * status, approval, invitation, activation, staff role or Pol.is access. The
 * owning BFF must supply a random server-held session binding, never a query or
 * caller-selected account. Existing synthetic compositions reject this profile.
 */
export function createProductionIdentity(options) {
  let transport;
  try {
    const settings = fields(options, ['issuer', 'authorizationEndpoint', 'tokenEndpoint', 'jwksUri',
      'callbackUri', 'clientId', 'clientSecret', 'tokenEndpointAuthMethod', 'signingAlgorithm', 'identityKey'], ['ca', 'now', 'relay']);
    const { issuer, authorizationEndpoint, tokenEndpoint, jwksUri, callbackUri } = Object.fromEntries(
      ['issuer', 'authorizationEndpoint', 'tokenEndpoint', 'jwksUri', 'callbackUri'].map(key => [key, canonicalHttpsUrl(settings[key])]));
    if (new Set([authorizationEndpoint, tokenEndpoint, jwksUri, callbackUri]).size !== 4
      || !text(settings.clientId, 256) || !text(settings.clientSecret)
      || !['client_secret_basic', 'client_secret_post'].includes(settings.tokenEndpointAuthMethod)
      || !['RS256', 'ES256'].includes(settings.signingAlgorithm)
      || !(settings.identityKey instanceof Uint8Array) || settings.identityKey.byteLength < 32 || settings.identityKey.byteLength > 64
      || (settings.now !== undefined && typeof settings.now !== 'function')) throw new Error();
    const identityKey = Buffer.from(settings.identityKey);
    const clientId = settings.clientId;
    const now = settings.now ?? Date.now;
    const relay = settings.relay === undefined ? undefined : validateOidcRelayRoute(settings.relay);
    transport = createOidcHttpsTransport({ tokenEndpoint, jwksUri, ca: settings.ca, ...(relay ? { relay } : {}) });
    const pending = new Map();
    let principals = new WeakMap();
    let closed = false;
    let lastObserved;
    const close = () => {
      closed = true; pending.clear(); principals = new WeakMap();
      identityKey.fill(0); transport.close();
    };
    const instant = () => {
      if (closed) throw new Error();
      let value;
      try { value = now(); } catch { close(); throw new Error(); }
      if (!Number.isSafeInteger(value) || value < 0 || value > Number.MAX_SAFE_INTEGER - PRINCIPAL_TTL_MS
        || (lastObserved !== undefined && value < lastObserved)) {
        close(); throw new Error();
      }
      lastObserved = value;
      return value;
    };
    instant(); // Invalid clocks reject configuration before any outbound request.
    const hmac = parts => createHmac('sha256', identityKey).update(JSON.stringify(parts)).digest('base64url');
    const config = new oidc.Configuration({
      issuer, authorization_endpoint: authorizationEndpoint, token_endpoint: tokenEndpoint, jwks_uri: jwksUri,
      response_types_supported: ['code'], code_challenge_methods_supported: ['S256'],
      id_token_signing_alg_values_supported: [settings.signingAlgorithm],
      authorization_response_iss_parameter_supported: true,
    }, clientId, { id_token_signed_response_alg: settings.signingAlgorithm, [oidc.clockTolerance]: 0 },
    settings.tokenEndpointAuthMethod === 'client_secret_basic'
      ? oidc.ClientSecretBasic(settings.clientSecret) : oidc.ClientSecretPost(settings.clientSecret));
    config.timeout = 5;
    config[oidc.customFetch] = transport.fetch;
    oidc.enableNonRepudiationChecks(config);

    function prune(at) {
      for (const [key, transaction] of pending) if (transaction.expiresAt <= at) pending.delete(key);
    }
    function verifiedRecord(principal) {
      const at = instant();
      const record = principal && typeof principal === 'object' && principals.get(principal);
      if (!record || record.expiresAt <= at || record.verifiedAt > at) throw new Error();
      return record;
    }

    const adapter = Object.freeze({
      profile: PARTICIPANT_IDENTITY_PROFILE,
      async begin(input) {
        let key; let transaction;
        try {
          const { browserSessionId } = fields(input, ['browserSessionId']);
          key = sessionKey(browserSessionId);
          const at = instant(); prune(at);
          if (!pending.has(key) && pending.size >= MAX_PENDING) throw new Error();
          transaction = { state: oidc.randomState(), nonce: oidc.randomNonce(),
            verifier: oidc.randomPKCECodeVerifier(), createdAt: at, expiresAt: at + TRANSACTION_TTL_MS };
          pending.set(key, transaction); // Reserve before the asynchronous calculation.
          const challenge = await oidc.calculatePKCECodeChallenge(transaction.verifier);
          if (instant() >= transaction.expiresAt || pending.get(key) !== transaction) throw new Error();
          const url = oidc.buildAuthorizationUrl(config, { redirect_uri: callbackUri, response_type: 'code',
            response_mode: 'query', scope: 'openid email', code_challenge: challenge,
            code_challenge_method: 'S256', state: transaction.state, nonce: transaction.nonce });
          return Object.freeze({ ok: true, authorizationUrl: url.href });
        } catch {
          if (key && pending.get(key) === transaction) pending.delete(key);
          return FAILURE;
        }
      },
      async complete(input) {
        try {
          const { browserSessionId, callbackUrl } = fields(input, ['browserSessionId', 'callbackUrl']);
          const key = sessionKey(browserSessionId);
          const transaction = pending.get(key);
          pending.delete(key); // One-use before any await, including uncertain grants.
          const at = instant(); prune(at);
          if (!transaction || transaction.expiresAt <= at || !text(callbackUrl, 8192)) throw new Error();
          const callback = new URL(callbackUrl);
          if (callback.hash || callback.username || callback.password || callback.href !== callbackUrl
            || `${callback.origin}${callback.pathname}` !== callbackUri) throw new Error();
          const allowed = ['code', 'state', 'iss', 'error', 'error_description', 'error_uri'];
          for (const [name, value] of callback.searchParams) if (!allowed.includes(name)
            || callback.searchParams.getAll(name).length !== 1 || !text(value)) throw new Error();
          if (callback.searchParams.get('iss') !== issuer || callback.searchParams.has('error')
            || callback.searchParams.has('error_description') || callback.searchParams.has('error_uri')
            || !callback.searchParams.has('code')) throw new Error();
          const tokens = await oidc.authorizationCodeGrant(config, callback, {
            pkceCodeVerifier: transaction.verifier, expectedState: transaction.state,
            expectedNonce: transaction.nonce, idTokenExpected: true,
          });
          const claims = tokens.claims();
          const verifiedAt = instant();
          const seconds = Math.floor(verifiedAt / 1000);
          if (verifiedAt >= transaction.expiresAt || !claims || !text(claims.sub, 255)
            || claims.email_verified !== true || !text(claims.email, 320)
            || !Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp)
            || claims.iat > seconds || claims.iat < seconds - 600 || claims.exp <= claims.iat
            || claims.exp > claims.iat + 3600 || claims.exp * 1000 <= verifiedAt
            || (claims.azp !== undefined && claims.azp !== clientId)
            || !(claims.aud === clientId || (Array.isArray(claims.aud) && claims.aud.length === 1 && claims.aud[0] === clientId))) throw new Error();
          const accountId = `acct_${hmac(['fncp-account-v1', issuer, claims.sub])}`;
          const principal = Object.freeze({ accountId, emailVerifiedByIssuer: true,
            assurance: 'OIDC_ID_TOKEN_VERIFIED', eligibilityVerified: false, profile: PARTICIPANT_IDENTITY_PROFILE });
          principals.set(principal, { accountId, verifiedAt,
            expiresAt: Math.min(claims.exp * 1000, verifiedAt + PRINCIPAL_TTL_MS) });
          // No raw subject, email, claims, access/refresh/ID token or provider
          // response is retained in the capability or exposed in a result.
          return Object.freeze({ ok: true, principal });
        } catch { return FAILURE; }
      },
      discard(input) {
        try {
          const { browserSessionId } = fields(input, ['browserSessionId']);
          pending.delete(sessionKey(browserSessionId));
        } catch { /* Discard grants no authority and leaks no transaction state. */ }
      },
      isVerifiedPrincipal(principal) {
        try { verifiedRecord(principal); return true; } catch { return false; }
      },
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
          return Object.freeze({ ok: true, authenticated: true, emailVerifiedByIssuer: true,
            eligibilityVerified: false, participantAccessGranted: false });
        } catch { return FAILURE; }
      },
      close,
    });
    adapters.add(adapter);
    return adapter;
  } catch {
    transport?.close();
    throw new Error('Participant OIDC configuration rejected.');
  }
}
