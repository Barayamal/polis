import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import test from 'node:test';
import { validateWordPressRegistration } from './wordpress-contract.mjs';

const ROUND = 'synthetic_round_local';
const DOMAIN = 'FNCP_WP_CHALLENGE_SYNTHETIC_V1\n';
const FAILURE = 'Synthetic WordPress recovery contract rejected.';
const KEYS = ['schema_version', 'event_id', 'subject', 'round_id', 'version', 'state', 'occurred_at'];
const sha = (text) => createHash('sha256').update(text).digest('hex');
const uuid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const iso = (time) => new Date(time * 1000).toISOString().replace('.000Z', 'Z');
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
function signedRaw(raw, secret, domain = DOMAIN) {
  const payload = Buffer.from(raw).toString('base64url');
  return { payload, signature: createHmac('sha256', secret).update(domain + payload).digest('hex') };
}
function source(count = 1) {
  const now = 1800000400; const challengeSecret = 's'.repeat(43);
  const registry = { schemaVersion: 1, sessions: [], challenges: {}, assertions: {}, registrations: {}, fixtureIndex: {} };
  const journal = { schema_version: 1, subjects: {}, events: {} }; const mappings = [];
  for (let index = 0; index < count; index++) {
    const suffix = String.fromCharCode(65 + index).repeat(43);
    const account_id = `acct_${suffix}`; const fixture = `synthetic_i${sha(account_id).slice(0, 39)}`;
    mappings.push({ account_id, fixture, round: '123abcde', xid: `fncp_${suffix}` });
    const challengeId = uuid(index * 10 + 1); const registrationId = uuid(index * 10 + 2);
    const claims = { schemaVersion: 1, purpose: 'wordpress-registration-challenge', audience: 'fncp-synthetic-bff',
      challengeId, browserBinding: sha(`invented-cookie-${index}`), roundId: ROUND, issuedAt: now - 200, expiresAt: now - 80 };
    registry.challenges[challengeId] = { envelope: signedRaw(canonical(claims), challengeSecret), expiresAt: claims.expiresAt, consumed: true };
    registry.assertions[uuid(index * 10 + 3)] = now - 136;
    registry.registrations[registrationId] = { registrationId, fixture, roundId: ROUND, createdAt: now - 195,
      acceptedAt: now - 196, consentVersion: 'synthetic-registration-v1', adultSelfAttested: true,
      eligibilitySelfAttested: true, registrationConsent: true };
    registry.fixtureIndex[`${fixture}:${ROUND}`] = registrationId;
    for (let version = 1; version <= 2; version++) {
      const event = { schema_version: 1, event_id: uuid(index * 10 + version + 3), subject: fixture, round_id: ROUND,
        version, state: version === 1 ? 'approved' : 'revoked', occurred_at: iso(now - 190 + version * 10) };
      journal.events[event.event_id] = { event, body: JSON.stringify(event), delivered: true, attempts: 1,
        last_attempt_at: iso(now - 150), last_result: 'ACKNOWLEDGED' };
      journal.subjects[`${ROUND}:${fixture}`] = { version, state: event.state, event_id: event.event_id };
    }
  }
  return { registry, journal, mappings, now, challengeSecret };
}
const first = (map) => Object.values(map)[0];
const firstChallenge = (input) => first(input.registry.challenges);
const firstRegistration = (input) => first(input.registry.registrations);
const firstEvent = (input) => first(input.journal.events);
function changeClaims(input, fn) {
  const record = firstChallenge(input);
  const claims = JSON.parse(Buffer.from(record.envelope.payload, 'base64url').toString());
  fn(claims); record.envelope = signedRaw(canonical(claims), input.challengeSecret);
}
function changeEvent(input, fn) {
  const record = firstEvent(input); fn(record.event);
  record.body = JSON.stringify(Object.fromEntries(KEYS.map((key) => [key, record.event[key]])));
}
function rejected(mutator, count = 1) {
  const input = source(count); mutator(input);
  assert.throws(() => validateWordPressRegistration(input), (error) => {
    assert.equal(error.message, FAILURE); assert.equal(error.cause, undefined); return true;
  });
}

test('validates a closed synthetic checkpoint with an expired consumed signed challenge', () => {
  const input = source(); const before = JSON.stringify(input);
  const result = validateWordPressRegistration(input);
  assert.deepEqual(result.public.counts, { mappings: 1, registrations: 1, guestSessions: 0, retainedChallenges: 1,
    consumedChallenges: 1, assertionTombstones: 1, acknowledgedEvents: 2, revokedSubjects: 1 });
  assert.equal(result.events.length, 2); assert.equal(result.events.at(-1).event.state, 'revoked');
  assert.equal(result.events.every((item) => item.acknowledged === true), true);
  assert.equal(Object.values(result.public.hashes).every((value) => /^[0-9a-f]{64}$/u.test(value)), true);
  assert.equal(JSON.stringify(input), before); assert.equal(Object.isFrozen(input), false);
  assert.equal(Object.isFrozen(result.events[0].event), true);
  const publicText = JSON.stringify(result.public);
  for (const sensitive of [input.challengeSecret, input.mappings[0].fixture, input.mappings[0].account_id,
    input.mappings[0].xid, firstRegistration(input).registrationId, firstChallenge(input).envelope.payload]) {
    assert.equal(publicText.includes(sensitive), false);
  }
});

test('supports several independent exact mappings and PHP-pruned empty collections', () => {
  const input = source(3);
  input.registry.sessions = {}; input.registry.challenges = []; input.registry.assertions = [];
  const result = validateWordPressRegistration(input);
  assert.equal(result.public.counts.registrations, 3);
  assert.equal(result.public.counts.acknowledgedEvents, 6);
  assert.equal(result.public.counts.retainedChallenges, 0);
});

test('accepts a subject revoked directly at version one without a fictitious prior approval', () => {
  const input = source(); const events = Object.values(input.journal.events);
  delete input.journal.events[events[1].event.event_id];
  events[0].event.state = 'revoked'; events[0].body = JSON.stringify(events[0].event);
  input.journal.subjects[`${ROUND}:${input.mappings[0].fixture}`] = { version: 1, state: 'revoked', event_id: events[0].event.event_id };
  assert.equal(validateWordPressRegistration(input).public.counts.acknowledgedEvents, 1);
});

const negatives = [
  ['retained guest session', (s) => { s.registry.sessions = { [sha('cookie')]: {} }; }],
  ['unconsumed challenge', (s) => { firstChallenge(s).consumed = false; }],
  ['challenge signature tampering', (s) => { firstChallenge(s).envelope.signature = '0'.repeat(64); }],
  ['wrong challenge key', (s) => { s.challengeSecret = 'x'.repeat(43); }],
  ['wrong signature domain', (s) => {
    const c = firstChallenge(s); c.envelope = signedRaw(Buffer.from(c.envelope.payload, 'base64url').toString(), s.challengeSecret, 'FNCP_BFF_REGISTRATION_SYNTHETIC_V1\n');
  }],
  ['decoded JSON instead of encoded payload MAC', (s) => {
    const e = firstChallenge(s).envelope; e.signature = createHmac('sha256', s.challengeSecret).update(DOMAIN + Buffer.from(e.payload, 'base64url').toString()).digest('hex');
  }],
  ['noncanonical signed payload', (s) => {
    const c = firstChallenge(s); const raw = Buffer.from(c.envelope.payload, 'base64url').toString(); c.envelope = signedRaw(` ${raw}`, s.challengeSecret);
  }],
  ['signed UTF-8 BOM before canonical JSON', (s) => {
    const c = firstChallenge(s); const raw = Buffer.from(c.envelope.payload, 'base64url').toString(); c.envelope = signedRaw(`\uFEFF${raw}`, s.challengeSecret);
  }],
  ['duplicate signed claim key', (s) => {
    const c = firstChallenge(s); const raw = Buffer.from(c.envelope.payload, 'base64url').toString();
    c.envelope = signedRaw(raw.replace('{', '{"schemaVersion":1,'), s.challengeSecret);
  }],
  ['padded payload encoding', (s) => {
    const e = firstChallenge(s).envelope; e.payload += '=';
    e.signature = createHmac('sha256', s.challengeSecret).update(DOMAIN + e.payload).digest('hex');
  }],
  ['wrong challenge audience', (s) => changeClaims(s, (c) => { c.audience = 'other'; })],
  ['wrong challenge round', (s) => changeClaims(s, (c) => { c.roundId = 'other'; })],
  ['future challenge issue', (s) => changeClaims(s, (c) => { c.issuedAt = s.now + 1; })],
  ['challenge lifetime exceeds 120 seconds', (s) => changeClaims(s, (c) => { c.issuedAt -= 1; })],
  ['challenge metadata differs from signed expiry', (s) => { firstChallenge(s).expiresAt += 1; }],
  ['challenge map key differs from signed UUID', (s) => changeClaims(s, (c) => { c.challengeId = uuid(99); })],
  ['invalid assertion tombstone ID', (s) => { s.registry.assertions = { invalid: s.now }; }],
  ['newline suffix on a tombstone UUID', (s) => { s.registry.assertions = { [`${uuid(3)}\n`]: s.now }; }],
  ['invalid assertion tombstone expiry', (s) => { s.registry.assertions[uuid(3)] = 0; }],
  ['impossible future assertion tombstone', (s) => { s.registry.assertions[uuid(3)] = s.now + 61; }],
  ['extra participant data in registration', (s) => { firstRegistration(s).email = 'invented@example.invalid'; }],
  ['adult self-attestation is false', (s) => { firstRegistration(s).adultSelfAttested = false; }],
  ['eligibility self-attestation is false', (s) => { firstRegistration(s).eligibilitySelfAttested = false; }],
  ['registration consent is false', (s) => { firstRegistration(s).registrationConsent = false; }],
  ['unrecognised notice version', (s) => { firstRegistration(s).consentVersion = 'future'; }],
  ['acceptance occurs after registration', (s) => { firstRegistration(s).acceptedAt = s.now; }],
  ['registration accepted after receipt TTL', (s) => { firstRegistration(s).acceptedAt -= 60; }],
  ['future registration', (s) => { firstRegistration(s).createdAt = s.now + 1; }],
  ['registration fixture not mapped', (s) => { firstRegistration(s).fixture = `synthetic_i${'a'.repeat(39)}`; }],
  ['missing registration', (s) => { s.registry.registrations = []; }],
  ['fixture index reference drift', (s) => { s.registry.fixtureIndex[`${s.mappings[0].fixture}:${ROUND}`] = uuid(99); }],
  ['extra fixture index', (s) => { s.registry.fixtureIndex.extra = uuid(2); }],
  ['incorrect mapped fixture hash', (s) => { s.mappings[0].fixture = `synthetic_i${'b'.repeat(39)}`; }],
  ['extra mapping field', (s) => { s.mappings[0].email = 'invented@example.invalid'; }],
  ['WordPress round confused with provider conversation', (s) => { s.mappings[0].round = ROUND; }],
  ['unacknowledged journal event', (s) => { firstEvent(s).delivered = false; }],
  ['ACK delivery result contradiction', (s) => { firstEvent(s).last_result = 'PENDING'; }],
  ['ACK with no attempt', (s) => { firstEvent(s).attempts = 0; }],
  ['ACK with no timestamp', (s) => { firstEvent(s).last_attempt_at = null; }],
  ['ACK before event', (s) => { firstEvent(s).last_attempt_at = iso(s.now - 250); }],
  ['event body byte drift', (s) => { firstEvent(s).body += ' '; }],
  ['extra event field', (s) => { firstEvent(s).event.extra = true; }],
  ['event ID does not match journal key', (s) => changeEvent(s, (e) => { e.event_id = uuid(99); })],
  ['orphan journal subject', (s) => changeEvent(s, (e) => { e.subject = `synthetic_i${'c'.repeat(39)}`; })],
  ['invalid calendar date', (s) => changeEvent(s, (e) => { e.occurred_at = '2026-02-30T00:00:00Z'; })],
  ['event predates registration', (s) => changeEvent(s, (e) => { e.occurred_at = iso(s.now - 196); })],
  ['future event', (s) => changeEvent(s, (e) => { e.occurred_at = iso(s.now + 1); })],
  ['skipped event version', (s) => changeEvent(s, (e) => { e.version = 9; })],
  ['revoked event before another decision', (s) => changeEvent(s, (e) => { e.state = 'revoked'; })],
  ['nonterminal latest event', (s) => {
    const r = Object.values(s.journal.events)[1]; r.event.state = 'approved'; r.body = JSON.stringify(r.event);
  }],
  ['subject pointer references prior event', (s) => { first(s.journal.subjects).event_id = firstEvent(s).event.event_id; }],
  ['missing subject terminal pointer', (s) => { s.journal.subjects = []; }],
  ['extra journal record field', (s) => { firstEvent(s).digest = '0'.repeat(64); }],
  ['wrong registry schema', (s) => { s.registry.schemaVersion = 2; }],
  ['wrong journal schema', (s) => { s.journal.schema_version = 2; }],
  ['invalid clock', (s) => { s.now = Number.NaN; }],
  ['newline suffix on a signing secret', (s) => { s.challengeSecret += '\n'; s.registry.challenges = []; }],
  ['array masquerading as nonempty map', (s) => { s.registry.challenges = Object.values(s.registry.challenges); }],
  ['non-JSON inherited object', (s) => { s.registry = Object.assign(Object.create({ inherited: true }), s.registry); }],
  ['symbol field', (s) => { s.registry[Symbol('unexpected')] = true; }],
  ['prototype pollution key', (s) => { Object.defineProperty(s.registry, '__proto__', { value: {}, enumerable: true }); }],
  ['sparse mapping array', (s) => { delete s.mappings[0]; }],
  ['extra top-level input', (s) => { s.password = 'must never be reported'; }],
];
for (const [name, mutate] of negatives) test(`rejects ${name} with redacted diagnostic`, () => rejected(mutate));

test('rejects duplicate mappings, duplicate XIDs and mismatched provider rounds', () => {
  rejected((s) => { s.mappings[1] = { ...s.mappings[0] }; }, 2);
  rejected((s) => { s.mappings[1].xid = s.mappings[0].xid; }, 2);
  rejected((s) => { s.mappings[1].round = '987zyxwv'; }, 2);
});

test('rejects duplicate registrations for a single mapped fixture', () => {
  rejected((s) => {
    const entries = Object.values(s.registry.registrations);
    entries[1].fixture = entries[0].fixture;
  }, 2);
});

test('rejects reapproval after terminal revocation even when all events say ACK', () => {
  rejected((s) => {
    const original = firstEvent(s); const event = { ...original.event, event_id: uuid(99), version: 3, occurred_at: iso(s.now - 100) };
    s.journal.events[event.event_id] = { event, body: JSON.stringify(event), delivered: true, attempts: 1,
      last_attempt_at: iso(s.now - 99), last_result: 'ACKNOWLEDGED' };
    first(s.journal.subjects).version = 3; first(s.journal.subjects).event_id = event.event_id;
  });
});

test('does not execute accessors or toJSON while rejecting non-JSON input', () => {
  let invoked = 0; const input = source();
  Object.defineProperty(input.registry, 'sessions', { enumerable: true, get() { invoked++; throw new Error('sensitive data'); } });
  assert.throws(() => validateWordPressRegistration(input), { message: FAILURE });
  assert.equal(invoked, 0);
  rejected((s) => { s.registry.toJSON = () => { invoked++; return {}; }; });
  assert.equal(invoked, 0);
});

test('rejects empty and over-capacity mapping scope', () => {
  rejected((s) => { s.mappings = []; });
  assert.throws(() => validateWordPressRegistration(source(21)), { message: FAILURE });
});

test('public fingerprints bind registry and journal metadata changes without leaking them', () => {
  const input = source(); const before = validateWordPressRegistration(input);
  firstEvent(input).attempts++;
  const after = validateWordPressRegistration(input);
  assert.notEqual(after.public.hashes.journalSha256, before.public.hashes.journalSha256);
  assert.equal(after.public.hashes.eventsSha256, before.public.hashes.eventsSha256);
  assert.equal(after.public.hashes.registrySha256, before.public.hashes.registrySha256);
});
