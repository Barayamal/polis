/** OFFLINE OPERATOR HELPER ONLY. Never imported by the running participant service.
 * Caller supplies a reviewed challenge and explicit times; no key or signature is
 * generated, persisted, sent or activated as a side effect of importing this file.
 */
import { sign, createPrivateKey, KeyObject } from 'node:crypto';
import { activationProtocol, canonical, exact, validClaims, fail } from './protocol.mjs';
export function signProductionActivation(options) {
  try {
    if (!exact(options, ['challenge', 'privateKey', 'activationId', 'issuedAt', 'notBefore', 'expiresAt'])) fail();
    const c = options.challenge;
    if (!exact(c, ['purpose', 'keyId', 'binding', 'nextSequence', 'maxLifetimeSeconds'])) fail();
    const protocol = activationProtocol(c.binding);
    if (c.purpose !== protocol.purpose || c.maxLifetimeSeconds !== 1800) fail();
    const claims = { schemaVersion: protocol.version, purpose: protocol.purpose, keyId: c.keyId, activationId: options.activationId,
      sequence: c.nextSequence, issuedAt: options.issuedAt, notBefore: options.notBefore, expiresAt: options.expiresAt, binding: c.binding };
    if (!validClaims(claims, c.keyId)) fail();
    const key = options.privateKey instanceof KeyObject ? options.privateKey : createPrivateKey(options.privateKey);
    if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') fail();
    const payload = Buffer.from(canonical(claims));
    return Object.freeze({ payload: payload.toString('base64url'), signature: sign(null, Buffer.concat([Buffer.from(protocol.signingDomain), payload]), key).toString('base64url') });
  } catch { fail(); }
}
