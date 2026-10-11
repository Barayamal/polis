import assert from 'node:assert/strict';
import test from 'node:test';
import { createParticipantIdentityBoundary } from './principal-boundary.mjs';
import { createTestIssuer } from '../production-identity/test-support/https-issuer.mjs';

test('only actual adapter and its live principal cross the private identity boundary', async t => {
  const h = await createTestIssuer(); t.after(() => h.close());
  const boundary = createParticipantIdentityBoundary({ identity: h.identity, conversationId: 'round_one' });
  const result = await h.authenticate(); assert.equal(result.ok, true);
  const value = boundary.current(result.principal);
  assert.equal(value.accountId, result.principal.accountId);
  assert.match(value.participantXid, /^fncp_[A-Za-z0-9_-]{43}$/u);
  assert.equal(value.expiresAt, h.identity.principalDeadline(result.principal));
  assert.throws(() => boundary.current(Object.freeze({ ...result.principal })), { message: 'Current participant identity required.' });
  const other = h.createAdapter();
  const otherResult = await h.authenticate({}, other);
  assert.throws(() => boundary.current(otherResult.principal), { message: 'Current participant identity required.' });
  boundary.close();
  assert.throws(() => boundary.current(result.principal), { message: 'Current participant identity required.' });
});

test('a branded fake verifier or copied adapter cannot establish the boundary', async t => {
  const h = await createTestIssuer(); t.after(() => h.close());
  for (const identity of [Object.freeze({ ...h.identity }), Object.freeze({ profile: 'OIDC_PARTICIPANT_V1',
    isVerifiedPrincipal: () => true, principalDeadline: () => Date.now() + 1000,
    participantXid: () => ({ ok: true, xid: 'fncp_' + 'a'.repeat(43) }) }), { profile: 'SYNTHETIC_ONLY' }]) {
    assert.throws(() => createParticipantIdentityBoundary({ identity, conversationId: 'round_one' }),
      { message: 'Current participant identity required.' });
  }
});

test('adapter closure and clock rollback invalidate the already composed boundary', async t => {
  let now = Date.now(); const h = await createTestIssuer({ now: () => now }); t.after(() => h.close());
  const boundary = createParticipantIdentityBoundary({ identity: h.identity, conversationId: 'round_one' });
  const result = await h.authenticate(); assert.equal(result.ok, true);
  assert.ok(boundary.current(result.principal));
  now -= 1;
  assert.throws(() => boundary.current(result.principal), { message: 'Current participant identity required.' });
  now += 2;
  assert.throws(() => boundary.current(result.principal), { message: 'Current participant identity required.' });
});
