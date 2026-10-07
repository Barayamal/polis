import { CONSENT_VERSION } from './registration-issuer.mjs';
/** Actual WP client + strict BFF; exactly one invented vote. Static labels only. */
export async function exerciseWordPressIdentityJourney({ h, wordpress, operator, seamless = false, observer = () => {} }) {
  const checks = []; const check = (label, okay) => { if (!okay) throw new Error('WP journey: ' + label); checks.push(label); observer(label); };
  check('unsigned ordinary round opening is denied', (await h.admin('round', { open: true })).status === 403);
  h.activate();
  const alice = h.client(); const bob = h.client();
  const a = await h.login(alice, 'synthetic_wp_bound_alice');
  const b = await h.login(bob, 'synthetic_wp_bound_bob');
  check('two signed synthetic accounts while round remains closed', a.result.status === 200 && b.result.status === 200);
  const wpA = wordpress(); const wpB = wordpress();
  let registeredA; let registeredB;
  if (seamless) {
    const consent = { adultSelfAttested: true, eligibilitySelfAttested: true, registrationConsent: true, consentVersion: CONSENT_VERSION };
    check('registration starts unsubmitted without voting permission', a.result.body.registrationEnabled === true && a.result.body.registrationStatus === 'NOT_SUBMITTED');
    check('browser cannot submit arbitrary identity or incomplete declarations',
      (await alice.register({ ...consent, fixture: a.fixture })).status === 400 &&
      (await alice.register({ ...consent, adultSelfAttested: false })).status === 400);
    check('manual receipt endpoint unavailable in seamless mode', (await alice.registrationReceipt(consent)).status === 404);
    registeredA = await alice.register(consent); registeredB = await bob.register(consent);
    check('two private server handoffs record submitted-not-approved references', registeredA.status === 200 && registeredB.status === 200 &&
      registeredA.body.registrationStatus === 'SUBMITTED_NOT_APPROVED' && registeredB.body.registrationStatus === 'SUBMITTED_NOT_APPROVED' &&
      registeredA.body.phase === 'authenticated' && registeredA.body.registrationId !== registeredB.body.registrationId);
    check('browser response contains no WordPress credentials or private identity',
      !/receipt|challenge|fixture|assertion|xid|signature|wordpressCookie/i.test(JSON.stringify(registeredA.body)));
    check('same signed-in session cannot resubmit registration', (await alice.register(consent)).status === 409);
  } else {
  check('independent WordPress guest sessions created without public registration', (await wpA.session()).status === 200 && (await wpB.session()).status === 200);
  check('WordPress challenge rejects invalid independent CSRF', (await wpA.challenge({ csrfToken: 'forged' })).status === 403);
  const challengeA = await wpA.challenge(); const challengeB = await wpB.challenge();
  check('separate signed WordPress challenges issued', challengeA.status === 200 && challengeB.status === 200);
  const consent = { adultSelfAttested: true, eligibilitySelfAttested: true, registrationConsent: true, consentVersion: CONSENT_VERSION };
  check('incomplete self-attestation cannot produce a receipt', (await alice.registrationReceipt({ ...consent, challenge: challengeA.body.challenge, adultSelfAttested: false })).status === 403);
  const receiptA = await alice.registrationReceipt({ ...consent, challenge: challengeA.body.challenge });
  const receiptB = await bob.registrationReceipt({ ...consent, challenge: challengeB.body.challenge });
  check('BFF binds two consent receipts to current private account mappings', receiptA.status === 200 && receiptB.status === 200 && receiptA.body.registrationOnly === true);
  check('forwarded receipt cannot register through another WordPress guest session', (await wpB.register(receiptA.body.receipt)).status === 403);
  check('forged receipt cannot consume the valid WordPress challenge', (await wpA.register({ ...receiptA.body.receipt, signature: '0'.repeat(64) })).status === 403);
  registeredA = await wpA.register(receiptA.body.receipt); registeredB = await wpB.register(receiptB.body.receipt);
  check('two immutable WordPress registration references recorded', registeredA.status === 200 && registeredB.status === 200 &&
    registeredA.body.registered === true && registeredB.body.registered === true && registeredA.body.registrationId !== registeredB.body.registrationId);
  check('consumed receipt cannot be replayed', [403, 409].includes((await wpA.register(receiptA.body.receipt)).status));
  }
  check('registration alone grants neither invitation nor voting', (await h.admin('invitations', { fixture: a.fixture })).status === 403 && (await alice.initialize()).status === 403);
  check('anonymous WordPress approval is denied', (await wpA.decide(registeredA.body.registrationId, 'approved')).status === 403);
  check('administrator with invalid nonce cannot approve', (await operator.decide(registeredA.body.registrationId, 'approved', { _fncp_nonce: 'forged' })).status === 403);
  check('administrator cannot inject an arbitrary fixture', (await operator.decide(registeredA.body.registrationId, 'approved', { subject: a.fixture })).status === 400);
  const approvedA = await operator.decide(registeredA.body.registrationId, 'approved');
  const approvedB = await operator.decide(registeredB.body.registrationId, 'approved');
  check('registered-reference admin decisions delivered and acknowledged by strict receiver', approvedA.status === 200 && approvedB.status === 200 &&
    approvedA.body.outcome === 'ACKNOWLEDGED' && approvedB.body.outcome === 'ACKNOWLEDGED');
  check('explicit round opening succeeds after signed authority and WordPress approvals', (await h.admin('round', { open: true })).status === 200);
  const invitation = await h.admin('invitations', { fixture: a.fixture });
  check('invitation issued only for current approved account', invitation.status === 201);
  check('forwarded invitation rejected by other approved signed-in account', (await bob.redeem(invitation.body.invitationToken)).status === 403);
  check('matching account redeems invitation once', (await alice.redeem(invitation.body.invitationToken)).status === 200);
  const init = await alice.initialize(); check('actual fixed synthetic statement returned', init.status === 200 && Number.isInteger(init.body.statement?.tid));
  const vote = await alice.vote(init.body.statement.tid, 0); check('one invented vote accepted by local Pol.is', vote.status === 200 && vote.body.saved === true);
  const warm = await alice.next(); check('warm session usable before WordPress revocation', warm.status === 200 && Number.isInteger(warm.body.statement?.tid));
  const revokedA = await operator.decide(registeredA.body.registrationId, 'revoked');
  check('WordPress revocation delivered and acknowledged', revokedA.status === 200 && revokedA.body.outcome === 'ACKNOWLEDGED');
  check('warm vote rejected after WordPress revocation', [401, 403].includes((await alice.vote(warm.body.statement.tid, 0)).status));
  check('terminally revoked WordPress registration cannot be reapproved', (await operator.decide(registeredA.body.registrationId, 'approved')).status === 409);
  check('second registration terminally revoked through WordPress', (await operator.decide(registeredB.body.registrationId, 'revoked')).body.outcome === 'ACKNOWLEDGED');
  check('local round closed', (await h.admin('round', { open: false })).body.open === false);
  check('post-close participant request denied', [401, 403].includes((await bob.initialize()).status));
  return { checks, inventedVotes: 1, registrations: 2 };
}
