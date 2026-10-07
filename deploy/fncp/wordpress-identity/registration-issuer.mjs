/** Offline, one-use-at-WordPress synthetic registration receipt. NOT an access token.
 * The opaque fixture is visible in this signed (not encrypted) envelope. It is
 * neither an XID nor a session credential. Never log/persist the envelope here.
 */
import { createHash, createHmac, randomUUID, timingSafeEqual } from 'node:crypto';

export const CHALLENGE_DOMAIN = 'FNCP_WP_CHALLENGE_SYNTHETIC_V1\n';
export const RECEIPT_DOMAIN = 'FNCP_BFF_REGISTRATION_SYNTHETIC_V1\n';
export const CONSENT_VERSION = 'synthetic-registration-v1';
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const hash = /^[0-9a-f]{64}$/u;
export function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
  return JSON.stringify(value);
}
function exact(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== keys.length || keys.some((key) => !Object.hasOwn(value, key))) throw new Error();
}
const digest = (value) => createHash('sha256').update(value).digest('hex');
export function signEnvelope(claims, secret, domain) {
  const payload = Buffer.from(canonical(claims)).toString('base64url');
  return Object.freeze({ payload, signature: createHmac('sha256', secret).update(domain + payload).digest('hex') });
}
export function verifyChallenge(envelope, secret, at) {
  exact(envelope, ['payload', 'signature']);
  if (typeof envelope.payload !== 'string' || !/^[A-Za-z0-9_-]{1,2048}$/u.test(envelope.payload) ||
      typeof envelope.signature !== 'string' || !hash.test(envelope.signature)) throw new Error();
  const signature = createHmac('sha256', secret).update(CHALLENGE_DOMAIN + envelope.payload).digest();
  if (!timingSafeEqual(signature, Buffer.from(envelope.signature, 'hex'))) throw new Error();
  const bytes = Buffer.from(envelope.payload, 'base64url');
  if (bytes.toString('base64url') !== envelope.payload) throw new Error();
  const claims = JSON.parse(bytes.toString('utf8'));
  if (canonical(claims) !== bytes.toString('utf8')) throw new Error();
  exact(claims, ['schemaVersion', 'purpose', 'audience', 'challengeId', 'browserBinding', 'roundId', 'issuedAt', 'expiresAt']);
  if (claims.schemaVersion !== 1 || claims.purpose !== 'wordpress-registration-challenge' ||
      claims.audience !== 'fncp-synthetic-bff' || claims.roundId !== 'synthetic_round_local' ||
      typeof claims.challengeId !== 'string' || typeof claims.browserBinding !== 'string' ||
      !uuid.test(claims.challengeId) || !hash.test(claims.browserBinding) ||
      !Number.isSafeInteger(at) || !Number.isSafeInteger(claims.issuedAt) || !Number.isSafeInteger(claims.expiresAt) ||
      claims.issuedAt > at || claims.issuedAt < 0 || claims.expiresAt <= at ||
      claims.expiresAt > claims.issuedAt + 120) throw new Error();
  return claims;
}

export function createRegistrationIssuer({ mode, challengeSecret, registrationSecret, registrationIdentity, principalDeadline, now = Date.now }) {
  if (mode !== 'SYNTHETIC_ONLY' || typeof challengeSecret !== 'string' || typeof registrationSecret !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(challengeSecret ?? '') ||
      !/^[A-Za-z0-9_-]{43}$/u.test(registrationSecret ?? '') || challengeSecret === registrationSecret ||
      typeof registrationIdentity !== 'function' || typeof principalDeadline !== 'function' || typeof now !== 'function') {
    throw new Error('Synthetic registration configuration rejected.');
  }
  return Object.freeze({ mode,
    async issue({ principal, browserDeadline, input }) {
      try {
        exact(input, ['challenge', 'adultSelfAttested', 'eligibilitySelfAttested', 'registrationConsent', 'consentVersion']);
        if (input.adultSelfAttested !== true || input.eligibilitySelfAttested !== true || input.registrationConsent !== true ||
            input.consentVersion !== CONSENT_VERSION) throw new Error();
        const before = Math.floor(now() / 1000);
        verifyChallenge(input.challenge, challengeSecret, before);
        const identity = await registrationIdentity(principal);
        exact(identity, ['mode', 'fixture', 'roundId']);
        if (identity.mode !== mode || identity.roundId !== 'synthetic_round_local' || typeof identity.fixture !== 'string' || !/^synthetic_i[0-9a-f]{39}$/u.test(identity.fixture)) throw new Error();
        const issuedAt = Math.floor(now() / 1000);
        const challenge = verifyChallenge(input.challenge, challengeSecret, issuedAt);
        const deadline = principalDeadline(principal);
        if (!Number.isSafeInteger(deadline) || !Number.isSafeInteger(browserDeadline) || issuedAt < before) throw new Error();
        const expiresAt = Math.min(challenge.expiresAt, Math.floor(deadline / 1000), Math.floor(browserDeadline / 1000), issuedAt + 60);
        if (expiresAt <= issuedAt) throw new Error();
        return Object.freeze({ mode, registrationOnly: true, eligibilityVerified: false,
          receipt: signEnvelope({ schemaVersion: 1, purpose: 'wordpress-registration-receipt', audience: 'fncp-synthetic-wordpress',
            assertionId: randomUUID(), challengeId: challenge.challengeId, browserBinding: challenge.browserBinding,
            challengeDigest: digest(canonical(input.challenge)), fixture: identity.fixture, roundId: identity.roundId,
            issuedAt, expiresAt, consentVersion: CONSENT_VERSION,
            adultSelfAttested: true, eligibilitySelfAttested: true, registrationConsent: true }, registrationSecret, RECEIPT_DOMAIN) });
      } catch { throw new Error('Synthetic registration receipt unavailable.'); }
    },
  });
}
