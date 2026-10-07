import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import { createRegistrationIssuer, signEnvelope, verifyChallenge, canonical, CHALLENGE_DOMAIN, RECEIPT_DOMAIN, CONSENT_VERSION } from './registration-issuer.mjs';
import { createSyntheticIdentityHarness } from '../identity-foundation/synthetic-harness.mjs';
import { createIntegratedJourney } from '../integrated-journey/proof-harness.mjs';

function fixture() {
  const challengeSecret = randomBytes(32).toString('base64url'); const registrationSecret = randomBytes(32).toString('base64url');
  let clock = Date.now(); const principal = Object.freeze({ synthetic: true });
  const claims = { schemaVersion: 1, purpose: 'wordpress-registration-challenge', audience: 'fncp-synthetic-bff',
    challengeId: randomUUID(), browserBinding: 'a'.repeat(64), roundId: 'synthetic_round_local',
    issuedAt: Math.floor(clock / 1000), expiresAt: Math.floor(clock / 1000) + 120 };
  const challenge = signEnvelope(claims, challengeSecret, CHALLENGE_DOMAIN);
  const input = { challenge, adultSelfAttested: true, eligibilitySelfAttested: true, registrationConsent: true, consentVersion: CONSENT_VERSION };
  const options = { mode: 'SYNTHETIC_ONLY', challengeSecret, registrationSecret, now: () => clock,
    registrationIdentity: async (value) => { if (value !== principal) throw new Error(); return { mode: 'SYNTHETIC_ONLY', fixture: 'synthetic_i' + 'b'.repeat(39), roundId: 'synthetic_round_local' }; },
    principalDeadline: (value) => value === principal ? clock + 40_000 : null };
  return { input, claims, principal, options, now: () => clock, advance: (ms) => { clock += ms; },
    issue: (opts = {}, body = input, value = principal) => createRegistrationIssuer({ ...options, ...opts }).issue({ principal: value, browserDeadline: clock + 90_000, input: body }) };
}

test('registration receipt is registration-only and capped by principal expiry with exact consent facts', async () => {
  const f = fixture(); const result = await f.issue(); const claims = JSON.parse(Buffer.from(result.receipt.payload, 'base64url'));
  assert.equal(result.registrationOnly, true); assert.equal(result.eligibilityVerified, false);
  assert.equal(claims.expiresAt, Math.floor((f.now() + 40_000) / 1000));
  assert.equal(claims.consentVersion, CONSENT_VERSION); assert.equal(claims.eligibilitySelfAttested, true);
  assert.equal(claims.fixture, 'synthetic_i' + 'b'.repeat(39));
  assert.equal(canonical(claims), Buffer.from(result.receipt.payload, 'base64url').toString());
  assert.deepEqual(result.receipt, signEnvelope(claims, f.options.registrationSecret, RECEIPT_DOMAIN));
});

for (const [name, mutate] of [
  ['adult attestation absent', (i) => { delete i.adultSelfAttested; }],
  ['eligibility attestation false', (i) => { i.eligibilitySelfAttested = false; }],
  ['consent string truthy', (i) => { i.registrationConsent = 'true'; }],
  ['wrong notice version', (i) => { i.consentVersion = 'other'; }],
  ['caller-chosen fixture', (i) => { i.fixture = 'synthetic_forged'; }],
  ['tampered payload', (i) => { i.challenge.payload += 'a'; }],
  ['forged signature', (i) => { i.challenge.signature = '0'.repeat(64); }],
  ['extra envelope field', (i) => { i.challenge.secret = 'forged'; }],
]) test('receipt denies ' + name, async () => {
  const f = fixture(); const input = structuredClone(f.input); mutate(input); await assert.rejects(f.issue({}, input), /^Error: Synthetic registration receipt unavailable\.$/u);
});

for (const [name, patch] of [
  ['wrong audience', { audience: 'other' }], ['wrong round', { roundId: 'other' }],
  ['wrong purpose', { purpose: 'access' }], ['non-UUID challenge', { challengeId: 'other' }],
  ['malformed browser binding', { browserBinding: 'x' }], ['extended lifetime', { expiresAt: 9999999999 }],
  ['array browser binding', { browserBinding: ['a'.repeat(64)] }], ['array UUID', { challengeId: [randomUUID()] }],
]) test('even signed invalid challenge denied: ' + name, async () => {
  const f = fixture(); f.input.challenge = signEnvelope({ ...f.claims, ...patch }, f.options.challengeSecret, CHALLENGE_DOMAIN);
  await assert.rejects(f.issue());
});

test('challenge and principal are rechecked after asynchronous mapping; expired receipt never issued', async () => {
  const f = fixture();
  await assert.rejects(f.issue({ registrationIdentity: async (p) => { const r = await f.options.registrationIdentity(p); f.advance(121_000); return r; } }));
  const g = fixture(); await assert.rejects(g.issue({ principalDeadline: () => null }));
  const h = fixture(); await assert.rejects(h.issue({}, h.input, Object.freeze({ synthetic: true })));
});

test('receipt key cannot be used as challenge key and canonical parsing denies duplicate-key payload', () => {
  const f = fixture(); assert.throws(() => createRegistrationIssuer({ ...f.options, registrationSecret: f.options.challengeSecret }));
  assert.throws(() => verifyChallenge(signEnvelope(f.claims, f.options.registrationSecret, RECEIPT_DOMAIN), f.options.challengeSecret, Math.floor(f.now() / 1000)));
  const raw = canonical(f.claims).replace('{', '{"schemaVersion":1,');
  const payload = Buffer.from(raw).toString('base64url');
  const signature = createHmac('sha256', f.options.challengeSecret).update(CHALLENGE_DOMAIN + payload).digest('hex');
  assert.throws(() => verifyChallenge({ payload, signature }, f.options.challengeSecret, Math.floor(f.now() / 1000)));
});

test('private principal deadline accepts only minted live principal and never expands public projection', async () => {
  let clock = Date.now(); const h = await createSyntheticIdentityHarness({ now: () => clock });
  const result = await h.authenticate('synthetic_deadline'); assert.equal(result.ok, true);
  const deadline = h.identity.principalDeadline(result.principal); assert.ok(deadline > clock && deadline <= clock + 900_000);
  assert.equal(h.identity.principalDeadline({ ...result.principal }), null);
  assert.equal(Object.hasOwn(h.identity.publicResult(result), 'expiresAt'), false);
  clock = deadline; assert.equal(h.identity.principalDeadline(result.principal), null);
});

// Fixed receiver 8101 is intentionally serial within this test file. No actual WP/Pol.is here.
test('signed-in BFF issues only registration receipt; uncredentialed requests, account injection, logout and authority closure deny', async (t) => {
  const f = fixture(); const eventSecret = randomBytes(32).toString('base64url');
  const provider = { async allowlist() { throw new Error('No provider grant expected'); }, async participate() { throw new Error('No vote expected'); } };
  const h = await createIntegratedJourney({ provider, wordpressRegistration: { ...f.options, eventSecret, receiverPort: 8101 } });
  t.after(() => h.close()); h.activate(); const browser = h.client();
  await browser.session(); assert.equal((await browser.registrationReceipt(f.input)).status, 403);
  const identity = await h.login(browser, 'synthetic_wp_registration'); assert.equal(identity.result.status, 200);
  assert.equal((await browser.registrationReceipt({ ...f.input, fixture: identity.fixture })).status, 403);
  const receipt = await browser.registrationReceipt(f.input); assert.equal(receipt.status, 200); assert.equal(receipt.body.registrationOnly, true);
  assert.equal(JSON.parse(Buffer.from(receipt.body.receipt.payload, 'base64url')).fixture, identity.fixture);
  assert.equal((await h.admin('invitations', { fixture: identity.fixture })).status, 403);
  assert.equal((await fetch(h.origin + '/api/registration/receipt', { method: 'POST', headers: { Origin: h.origin, 'Content-Type': 'application/json' }, body: JSON.stringify(f.input) })).status, 403);
  h.closeAuthority(); assert.equal((await browser.registrationReceipt(f.input)).status, 403);
  await browser.logout(); assert.equal((await browser.registrationReceipt(f.input)).status, 401);
});
