// TEST SUPPORT ONLY. Invented identities, generated ephemeral keys, no sockets.
import { createHash, randomBytes } from 'node:crypto';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { createIdentityFoundation } from './identity.mjs';

export async function createSyntheticIdentityHarness(overrides = {}) {
  const issuer = overrides.issuer ?? 'https://identity.example.invalid/';
  const authorizationEndpoint = `${issuer}authorize`;
  const tokenEndpoint = `${issuer}token`;
  const jwksUri = `${issuer}jwks`;
  const callbackUri = overrides.callbackUri ?? 'https://participant.example.invalid/oidc/callback';
  const clientId = 'invented-client';
  const signingAlgorithm = overrides.signingAlgorithm ?? 'RS256';
  const { privateKey, publicKey } = await generateKeyPair(signingAlgorithm);
  const jwk = { ...await exportJWK(publicKey), kid: 'synthetic-key', use: 'sig', alg: signingAlgorithm };
  const codes = new Map();
  const calls = [];
  let tokenTransform;
  let jwksTransform;
  const json = (body, status = 200) => new Response(JSON.stringify(body), {
    status, headers: { 'content-type': 'application/json' },
  });

  const fetch = async (input, init = {}) => {
    const url = String(input);
    // Aggregate method+endpoint records only: never tokens, codes or credentials.
    calls.push({ endpoint: url === tokenEndpoint ? 'token' : url === jwksUri ? 'jwks' : 'unexpected',
      method: init.method ?? 'GET', redirect: init.redirect, credentials: init.credentials });
    if (url === jwksUri && (init.method ?? 'GET') === 'GET') {
      const response = json({ keys: [jwk] });
      return jwksTransform ? jwksTransform(response) : response;
    }
    if (url !== tokenEndpoint || init.method !== 'POST') throw new Error('Unexpected synthetic transport route.');
    const body = new URLSearchParams(init.body);
    const code = body.get('code');
    const entry = codes.get(code);
    codes.delete(code);
    const headers = new Headers(init.headers);
    const authorization = headers.get('authorization') ?? '';
    let validClientAuthentication = body.get('client_id') === clientId;
    if (overrides.clientSecret !== undefined) {
      // RFC 6749 Basic values are form-encoded before base64 encoding.
      const decoded = authorization.startsWith('Basic ')
        ? Buffer.from(authorization.slice(6), 'base64').toString('utf8').split(':') : [];
      const formDecode = (value) => decodeURIComponent(value.replace(/\+/gu, ' '));
      validClientAuthentication = decoded.length === 2 && formDecode(decoded[0]) === clientId
        && formDecode(decoded[1]) === overrides.clientSecret;
    }
    if (!entry || body.get('grant_type') !== 'authorization_code'
      || body.get('redirect_uri') !== callbackUri
      || !validClientAuthentication
      || !body.get('code_verifier')
      || createHash('sha256').update(body.get('code_verifier')).digest('base64url') !== entry.challenge) {
      return json({ error: 'invalid_grant' }, 400);
    }
    const seconds = Math.floor(Date.now() / 1000);
    const claims = { iss: issuer, aud: clientId, sub: 'invented-subject-1',
      iat: seconds, exp: seconds + 300, nonce: entry.nonce,
      email: 'invented@example.invalid', email_verified: true, ...entry.claims };
    for (const name of entry.omit) delete claims[name];
    const idToken = await new SignJWT(claims)
      .setProtectedHeader({ alg: signingAlgorithm, kid: jwk.kid, ...entry.header })
      .sign(entry.key ?? privateKey);
    const response = json({ token_type: 'Bearer', access_token: 'invented-access-token-DO-NOT-RETURN',
      refresh_token: 'invented-refresh-token-DO-NOT-RETURN', id_token: idToken, expires_in: 300 });
    return tokenTransform ? tokenTransform(response) : response;
  };
  const options = {
    mode: 'SYNTHETIC_ONLY', issuer, authorizationEndpoint, tokenEndpoint, jwksUri, callbackUri,
    clientId, signingAlgorithm, identityKey: overrides.identityKey ?? randomBytes(32),
    transport: { kind: 'SYNTHETIC_INTERCEPT', fetch },
    ...(overrides.now ? { now: overrides.now } : {}),
    ...(overrides.trustedAdditionalAudiences ? { trustedAdditionalAudiences: overrides.trustedAdditionalAudiences } : {}),
    ...(overrides.clientSecret === undefined ? {} : { clientSecret: overrides.clientSecret }),
  };
  const identity = createIdentityFoundation(options);

  function authorizationResponse(authorizationUrl, { claims = {}, omit = [], header = {}, key } = {}) {
    const url = new URL(authorizationUrl);
    if (url.origin + url.pathname !== authorizationEndpoint || url.searchParams.get('client_id') !== clientId
      || url.searchParams.get('response_type') !== 'code' || url.searchParams.get('response_mode') !== 'query'
      || url.searchParams.get('redirect_uri') !== callbackUri
      || url.searchParams.get('code_challenge_method') !== 'S256') throw new Error('Invalid synthetic authorization.');
    const code = randomBytes(32).toString('base64url');
    codes.set(code, { challenge: url.searchParams.get('code_challenge'), nonce: url.searchParams.get('nonce'),
      claims, omit, header, key });
    const callback = new URL(callbackUri);
    callback.search = new URLSearchParams({ code, state: url.searchParams.get('state'), iss: issuer });
    return callback.href;
  }

  async function authenticate({ browserSessionId = randomBytes(32).toString('base64url'),
    claims = {}, omit = [], header = {}, key } = {}) {
    const start = await identity.begin({ browserSessionId });
    if (!start.ok) return start;
    return identity.complete({ browserSessionId,
      callbackUrl: authorizationResponse(start.authorizationUrl, { claims, omit, header, key }) });
  }

  return { identity, options, authenticate, authorizationResponse, calls,
    transformTokenResponse: (fn) => { tokenTransform = fn; },
    transformJwksResponse: (fn) => { jwksTransform = fn; } };
}
