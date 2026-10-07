import { PARTICIPANT_IDENTITY_PROFILE, isProductionIdentityAdapter } from '../production-identity/identity.mjs';

const failure = () => new Error('Current participant identity required.');

/** Private in-process integration boundary. It is neither an HTTP endpoint nor
 * an access/activation/approval grant. Capture the actual adapter instance once;
 * request input never selects the verifier, round or account mapping function.
 */
export function createParticipantIdentityBoundary({ identity, conversationId }) {
  if (!isProductionIdentityAdapter(identity) || identity.profile !== PARTICIPANT_IDENTITY_PROFILE || !Object.isFrozen(identity)
    || typeof conversationId !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/u.test(conversationId)) throw failure();
  const capture = name => {
    const descriptor = Object.getOwnPropertyDescriptor(identity, name);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'function') throw failure();
    return descriptor.value.bind(identity);
  };
  const verified = capture('isVerifiedPrincipal');
  const deadline = capture('principalDeadline');
  const derive = capture('participantXid');
  let closed = false;
  return Object.freeze({
    current(principal) {
      try {
        if (closed || !principal || !Object.isFrozen(principal) || !verified(principal)
          || principal.profile !== PARTICIPANT_IDENTITY_PROFILE || principal.assurance !== 'OIDC_ID_TOKEN_VERIFIED'
          || principal.emailVerifiedByIssuer !== true || principal.eligibilityVerified !== false
          || !/^acct_[A-Za-z0-9_-]{43}$/u.test(principal.accountId)) throw failure();
        const expiresAt = deadline(principal);
        const derived = derive(principal, conversationId);
        if (!Number.isSafeInteger(expiresAt) || expiresAt < 0 || derived?.ok !== true
          || !/^fncp_[A-Za-z0-9_-]{43}$/u.test(derived.xid) || !verified(principal)) throw failure();
        return Object.freeze({ accountId: principal.accountId, participantXid: derived.xid, expiresAt });
      } catch { throw failure(); }
    },
    close() { closed = true; },
  });
}
