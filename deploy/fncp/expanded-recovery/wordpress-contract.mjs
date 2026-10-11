import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

const FAILURE = 'Synthetic WordPress recovery contract rejected.';
const ROUND = 'synthetic_round_local';
const CONSENT = 'synthetic-registration-v1';
const DOMAIN = 'FNCP_WP_CHALLENGE_SYNTHETIC_V1\n';
const HEX = /^[0-9a-f]{64}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const FIXTURE = /^synthetic_i[0-9a-f]{39}$/u;
const EVENT_KEYS = ['schema_version', 'event_id', 'subject', 'round_id', 'version', 'state', 'occurred_at'];
const need = (value) => { if (!value) throw new Error(FAILURE); };
const int = (value) => Number.isSafeInteger(value) && value >= 0;
const sha = (value) => createHash('sha256').update(value).digest('hex');
const matches = (regex, value) => typeof value === 'string' && regex.exec(value)?.[0] === value;
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exact = (value, keys) => {
  if (!object(value)) return false;
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
};

// Copy only bounded JSON data, without evaluating getters, toJSON or prototypes.
// No database, runtime or filesystem APIs are used by this contract.
function copy(value, budget = { remaining: 40000 }, depth = 0) {
  need(--budget.remaining >= 0 && depth <= 20);
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number') { need(Number.isSafeInteger(value)); return value; }
  if (typeof value === 'string') { need(value.length <= 20000); return value; }
  need(typeof value === 'object' && value !== null && Object.getOwnPropertySymbols(value).length === 0);
  if (Array.isArray(value)) {
    need(value.length <= 1000 && Object.getPrototypeOf(value) === Array.prototype);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    need(Object.keys(descriptors).length === value.length + 1);
    const result = [];
    for (let index = 0; index < value.length; index++) {
      const item = descriptors[index];
      need(item && Object.hasOwn(item, 'value') && item.enumerable);
      result.push(copy(item.value, budget, depth + 1));
    }
    return result;
  }
  need([Object.prototype, null].includes(Object.getPrototypeOf(value)));
  const result = Object.create(null);
  for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
    need(key.length <= 300 && !['__proto__', 'prototype', 'constructor'].includes(key));
    need(Object.hasOwn(descriptor, 'value') && descriptor.enumerable);
    result[key] = copy(descriptor.value, budget, depth + 1);
  }
  return result;
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (object(value)) return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

function map(value, maximum) {
  // PHP encodes an empty associative array as []; nonempty collections are objects.
  need(object(value) || (Array.isArray(value) && value.length === 0));
  const entries = Object.entries(value);
  need(entries.length <= maximum);
  return entries;
}

function timestamp(value, now) {
  need(matches(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u, value));
  const millis = Date.parse(value);
  need(Number.isFinite(millis) && millis >= 0 && millis / 1000 <= now);
  need(new Date(millis).toISOString() === value.replace('Z', '.000Z'));
  return millis / 1000;
}

function challenge(id, record, now, secret) {
  need(matches(UUID, id) && exact(record, ['envelope', 'expiresAt', 'consumed']));
  need(record.consumed === true && int(record.expiresAt) && record.expiresAt > 0);
  const envelope = record.envelope;
  need(exact(envelope, ['payload', 'signature']) && matches(/^[A-Za-z0-9_-]+$/u, envelope.payload));
  need(envelope.payload.length <= 8192 && matches(HEX, envelope.signature));
  const expected = createHmac('sha256', secret).update(DOMAIN + envelope.payload).digest();
  need(timingSafeEqual(expected, Buffer.from(envelope.signature, 'hex')));
  const bytes = Buffer.from(envelope.payload, 'base64url');
  need(bytes.toString('base64url') === envelope.payload);
  const raw = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  need(Buffer.from(raw, 'utf8').equals(bytes)); // TextDecoder otherwise strips a leading UTF-8 BOM.
  const claims = copy(JSON.parse(raw));
  need(canonical(claims) === raw);
  need(exact(claims, ['schemaVersion', 'purpose', 'audience', 'challengeId', 'browserBinding', 'roundId', 'issuedAt', 'expiresAt']));
  need(claims.schemaVersion === 1 && claims.purpose === 'wordpress-registration-challenge' && claims.audience === 'fncp-synthetic-bff');
  need(claims.challengeId === id && matches(HEX, claims.browserBinding) && claims.roundId === ROUND);
  need(int(claims.issuedAt) && claims.issuedAt <= now && int(claims.expiresAt));
  need(claims.expiresAt > claims.issuedAt && claims.expiresAt - claims.issuedAt <= 120 && claims.expiresAt === record.expiresAt);
  // Expiry in the past is allowed only because this checkpoint requires consumed=true.
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

/**
 * Bounded synthetic recovery consistency validation. `now` is Unix seconds.
 * `events` is PRIVATE material for strict-recovery cross-store verification; never
 * log or publish it. Only `public` contains reportable aggregate counts/hashes.
 * Assertions retain only expiry tombstones, not signed receipts: this cannot
 * re-prove their original receipt signature or establish Indigenous heritage.
 * ACK metadata is validated here, then must be compared with the restored access
 * ledger by the caller. This function alone does not establish an actual restore.
 */
export function validateWordPressRegistration(input) {
  try {
    const source = copy(input);
    need(exact(source, ['registry', 'journal', 'mappings', 'now', 'challengeSecret']));
    const { registry, journal, mappings, now, challengeSecret } = source;
    need(int(now) && matches(/^[A-Za-z0-9_-]{32,256}$/u, challengeSecret));
    need(Array.isArray(mappings) && mappings.length > 0 && mappings.length <= 20);
    const fixtures = new Map(); const accounts = new Set(); const xids = new Set();
    let conversation;
    for (const mapping of mappings) {
      need(exact(mapping, ['account_id', 'fixture', 'round', 'xid']));
      need(matches(/^acct_[A-Za-z0-9_-]{43}$/u, mapping.account_id) && matches(/^fncp_[A-Za-z0-9_-]{43}$/u, mapping.xid));
      need(matches(/^[0-9][A-Za-z0-9_-]{5,99}$/u, mapping.round) && matches(FIXTURE, mapping.fixture));
      need(mapping.fixture === `synthetic_i${sha(mapping.account_id).slice(0, 39)}`);
      need(!accounts.has(mapping.account_id) && !fixtures.has(mapping.fixture) && !xids.has(mapping.xid));
      need(conversation === undefined || conversation === mapping.round);
      conversation = mapping.round; accounts.add(mapping.account_id); xids.add(mapping.xid); fixtures.set(mapping.fixture, mapping);
    }

    need(exact(registry, ['schemaVersion', 'sessions', 'challenges', 'assertions', 'registrations', 'fixtureIndex']) && registry.schemaVersion === 1);
    need(map(registry.sessions, 0).length === 0);
    const challenges = map(registry.challenges, 128);
    for (const [id, record] of challenges) challenge(id, record, now, challengeSecret);
    const assertions = map(registry.assertions, 128);
    for (const [id, expiry] of assertions) need(matches(UUID, id) && int(expiry) && expiry > 0 && expiry <= now + 60);
    const registrations = map(registry.registrations, 20);
    const indexes = map(registry.fixtureIndex, 20);
    need(registrations.length === mappings.length && indexes.length === registrations.length);
    const registered = new Map();
    for (const [id, record] of registrations) {
      need(exact(record, ['registrationId', 'fixture', 'roundId', 'createdAt', 'acceptedAt', 'consentVersion', 'adultSelfAttested', 'eligibilitySelfAttested', 'registrationConsent']));
      need(matches(UUID, id) && record.registrationId === id && fixtures.has(record.fixture) && !registered.has(record.fixture));
      need(record.roundId === ROUND && record.consentVersion === CONSENT);
      need(record.adultSelfAttested === true && record.eligibilitySelfAttested === true && record.registrationConsent === true);
      need(int(record.acceptedAt) && int(record.createdAt) && record.acceptedAt <= record.createdAt && record.createdAt <= now);
      need(record.createdAt - record.acceptedAt < 60);
      need(registry.fixtureIndex[`${record.fixture}:${ROUND}`] === id);
      registered.set(record.fixture, record);
    }
    for (const [key, id] of indexes) {
      const record = registry.registrations[id];
      need(record && key === `${record.fixture}:${ROUND}` && record.registrationId === id);
    }

    need(exact(journal, ['schema_version', 'subjects', 'events']) && journal.schema_version === 1);
    const subjects = map(journal.subjects, 20); const records = map(journal.events, 200);
    need(subjects.length === mappings.length && records.length >= mappings.length && records.length <= 2 * mappings.length);
    const histories = new Map();
    for (const [id, record] of records) {
      need(matches(UUID, id) && exact(record, ['event', 'body', 'delivered', 'attempts', 'last_attempt_at', 'last_result']));
      const event = record.event;
      need(exact(event, EVENT_KEYS) && event.schema_version === 1 && event.event_id === id);
      need(registered.has(event.subject) && event.round_id === ROUND && int(event.version) && event.version > 0);
      need(['approved', 'revoked'].includes(event.state));
      const occurred = timestamp(event.occurred_at, now);
      need(occurred >= registered.get(event.subject).createdAt);
      // The PHP producer serializes these event keys in this fixed insertion order.
      const body = JSON.stringify(Object.fromEntries(EVENT_KEYS.map((key) => [key, event[key]])));
      need(record.body === body && record.delivered === true && record.last_result === 'ACKNOWLEDGED');
      need(int(record.attempts) && record.attempts > 0 && timestamp(record.last_attempt_at, now) >= occurred);
      if (!histories.has(event.subject)) histories.set(event.subject, []);
      histories.get(event.subject).push(event);
    }
    need(histories.size === mappings.length);
    const events = [];
    for (const fixture of [...fixtures.keys()].sort()) {
      const history = histories.get(fixture).sort((a, b) => a.version - b.version);
      need(history.length >= 1 && history.length <= 2);
      for (let index = 0; index < history.length; index++) {
        const event = history[index];
        need(event.version === index + 1 && event.state === (index === history.length - 1 ? 'revoked' : 'approved'));
        if (index > 0) need(Date.parse(event.occurred_at) >= Date.parse(history[index - 1].occurred_at));
        events.push({ event, acknowledged: true });
      }
      const latest = history.at(-1); const subject = journal.subjects[`${ROUND}:${fixture}`];
      need(exact(subject, ['version', 'state', 'event_id']));
      need(subject.version === latest.version && subject.state === 'revoked' && subject.event_id === latest.event_id);
    }
    for (const [key, subject] of subjects) {
      const record = journal.events[subject.event_id];
      need(record && key === `${ROUND}:${record.event.subject}`);
    }
    return deepFreeze({ events, public: {
      counts: { mappings: mappings.length, registrations: registrations.length, guestSessions: 0,
        retainedChallenges: challenges.length, consumedChallenges: challenges.length, assertionTombstones: assertions.length,
        acknowledgedEvents: events.length, revokedSubjects: histories.size },
      hashes: { registrySha256: sha(canonical(registry)), journalSha256: sha(canonical(journal)),
        mappingsSha256: sha(canonical(mappings)), eventsSha256: sha(canonical(events)),
        // Same event digest construction used by the strict access event ledger.
        eventDigestsSha256: sha(canonical(events.map(({ event }) => sha(JSON.stringify(EVENT_KEYS.map((key) => event[key])))))) }
    } });
  } catch {
    // Do not expose identifiers, input data, parser diagnostics or signing material.
    throw new Error(FAILURE);
  }
}
