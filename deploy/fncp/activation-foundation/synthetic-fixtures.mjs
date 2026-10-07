/** Generated proof-only signing material. Never an owner or production signer. */
import { generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { PURPOSE, SIGNING_DOMAIN, canonical } from './authority.mjs';

export function syntheticSigningFixture() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { publicKey, privateKey, keyId: 'synthetic_test_key',
    signClaims(claims, serialize = canonical) {
      const payload = Buffer.from(serialize(claims));
      return { payload: payload.toString('base64url'),
        signature: sign(null, Buffer.concat([SIGNING_DOMAIN, payload]), privateKey).toString('base64url') };
    } };
}
export function syntheticBinding() {
  return { deploymentId: 'synthetic_activation_proof', conversationId: '9syntheticRoundTest',
    recoveryEpoch: randomUUID(), configSha256: 'a'.repeat(64), seedSha256: 'b'.repeat(64),
    images: Object.fromEntries(['server', 'math', 'alpha', 'proxy', 'migration'].map((name) => [name, 'sha256:' + 'c'.repeat(64)])),
    scope: { maxParticipants: 20, statementCount: 15, suggestions: false } };
}
export function syntheticClaims(binding, seconds = 1_000, overrides = {}) {
  return { schemaVersion: 1, purpose: PURPOSE, keyId: 'synthetic_test_key', activationId: randomUUID(),
    sequence: 1, issuedAt: seconds, notBefore: seconds, expiresAt: seconds + 300, binding, ...overrides };
}
