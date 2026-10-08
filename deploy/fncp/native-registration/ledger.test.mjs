import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { chmodSync, closeSync, existsSync, linkSync, mkdtempSync, openSync, readFileSync, realpathSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createNativeRegistrationFoundation } from './ledger.mjs';

// Every store, principal label, notice and reviewer in this suite is invented.
// These tests deliberately establish no production authentication, invitation,
// voting, provider-state or independently current restore-history authority.
const canonical = value => Array.isArray(value) ? '[' + value.map(canonical).join(',') + ']'
  : value && typeof value === 'object' ? '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}'
    : JSON.stringify(value);
const sha = value => createHash('sha256').update(value).digest('hex');
const notice = Object.freeze({
  adultDeclaration: 'Invented adult declaration for local tests only.',
  eligibilityDeclaration: 'Invented eligibility declaration for local tests only.',
  registrationDeclaration: 'Invented registration notice for local tests only.',
});

function configuration() {
  return {
    profile: 'FNCP_NATIVE_STORE_FOUNDATION_V1', mode: 'SYNTHETIC_ONLY',
    deploymentId: 'invented-native-foundation', epochId: randomUUID(),
    consentVersion: 'native-synthetic-v1', notice: { ...notice }, noticeSha256: sha(canonical(notice)),
  };
}

function fixture(t, { durable = false, initialTime = 2_000_000 } = {}) {
  const config = configuration();
  let time = initialTime;
  const directory = durable ? realpathSync(mkdtempSync(join(tmpdir(), 'fncp-native-foundation-'))) : null;
  if (directory) chmodSync(directory, 0o700);
  const storePath = directory ? join(directory, 'native-foundation.sqlite') : ':memory:';
  const openInstances = new Set();
  const open = (overrides = {}) => {
    const ledger = createNativeRegistrationFoundation({ configuration: config, storePath, now: () => time, ...overrides });
    openInstances.add(ledger);
    return ledger;
  };
  const close = ledger => { try { ledger.close(); } finally { openInstances.delete(ledger); } };
  t.after(() => {
    for (const ledger of openInstances) { try { ledger.close(); } catch {} }
    // This exact generated synthetic fixture is the only recursive target.
    if (directory) rmSync(directory, { recursive: true, force: true });
  });
  const declaration = overrides => ({ consentVersion: config.consentVersion, noticeSha256: config.noticeSha256,
    adultDeclaration: true, eligibilityDeclaration: true, registrationDeclaration: true, ...overrides });
  const participant = (suffix = 'one', overrides = {}) => ({ subject: 'invented-participant-' + suffix, expiresAt: time + 900_000, ...overrides });
  const register = (ledger, suffix = 'one', declarations = declaration(), principal = participant(suffix)) => ledger.registerSynthetic(principal, declarations);
  const decide = (ledger, registrationReference, kind, expectedVersion, overrides = {}) => ledger.recordSyntheticDecision({
    decisionId: randomUUID(), registrationReference, kind, reviewer: 'invented-reviewer-dean', expectedVersion, ...overrides,
  });
  const mutate = fn => {
    const db = new DatabaseSync(storePath);
    try { fn(db); } finally { db.close(); }
  };
  return { config, storePath, directory, open, close, declaration, participant, register, decide, mutate,
    setTime(value) { time = value; }, getTime() { return time; } };
}

function closedStatus(ledger) {
  const status = ledger.status();
  assert.equal(status.profile, 'FNCP_NATIVE_STORE_FOUNDATION_V1');
  assert.equal(status.mode, 'SYNTHETIC_ONLY');
  assert.equal(status.admissionAllowed, false);
  assert.equal(status.roundOpen, false);
  assert.equal(status.currentDenialHistoryVerified, false);
  assert.equal(status.productionAuthenticationVerified, false);
  assert.doesNotMatch(JSON.stringify(status), /invented-participant-|invented-reviewer-|acct_|fncp_|receipt_ref|registration_ref|account_key/u);
  return status;
}

test('synthetic foundation exposes no production participant or provider effects', t => {
  const h = fixture(t), ledger = h.open();
  const registration = h.register(ledger);
  assert.equal(registration.state, 'pending');
  assert.equal(registration.participantAccessGranted, false);
  assert.match(registration.registrationReference, /^[0-9a-f-]{36}$/u);
  assert.match(registration.receiptSha256, /^[0-9a-f]{64}$/u);
  const approved = h.decide(ledger, registration.registrationReference, 'approve', 0);
  assert.equal(approved.currentState, 'approved');
  assert.equal(approved.participantAccessGranted, false);
  assert.equal(closedStatus(ledger).approved, 1);
  for (const method of ['grant', 'participate', 'vote', 'issueInvitation', 'redeem', 'setRoundOpen', 'ingestWordPressEvent']) {
    assert.equal(Object.hasOwn(ledger, method), false, method + ' must not be exposed');
  }
});

for (const [name, mutate] of [
  ['production authority profile', c => { c.profile = 'FNCP_NATIVE_APPROVAL_AUTHORITY_V1'; }],
  ['WordPress profile', c => { c.profile = 'FNCP_PRODUCTION_WORDPRESS_V1'; }],
  ['non-synthetic mode', c => { c.mode = 'PRODUCTION'; }],
  ['ordinary deployment name', c => { c.deploymentId = 'community-pulse'; }],
  ['invalid epoch', c => { c.epochId = 'not-an-epoch'; }],
  ['changed notice digest', c => { c.noticeSha256 = 'f'.repeat(64); }],
  ['changed declaration version', c => { c.consentVersion = 'real-consent-v1'; }],
  ['WordPress configuration injection', c => { c.wordpress = {}; }],
  ['extra notice field', c => { c.notice.realParticipant = true; }],
]) test(`configuration rejects ${name}`, t => {
  const h = fixture(t), config = structuredClone(h.config); mutate(config);
  assert.throws(() => h.open({ configuration: config }));
});

test('configuration and principal Proxies/accessors reject without invoking accessor contents', t => {
  const h = fixture(t);
  assert.throws(() => h.open({ configuration: new Proxy(h.config, {}) }));
  const ledger = h.open();
  assert.throws(() => ledger.registerSynthetic(new Proxy(h.participant(), {}), h.declaration()));
  assert.throws(() => ledger.registerSynthetic(h.participant(), new Proxy(h.declaration(), {})));
  let reads = 0;
  const principal = { expiresAt: h.getTime() + 1_000 };
  Object.defineProperty(principal, 'subject', { enumerable: true, get() { reads++; return 'invented-participant-one'; } });
  assert.throws(() => ledger.registerSynthetic(principal, h.declaration()));
  assert.equal(reads, 0);
  assert.equal(closedStatus(ledger).registrations, 0);
});

for (const extra of ['accountId', 'participantXid', 'registrationReference', 'receiptId', 'role', 'reviewer', 'profile']) {
  test(`participant cannot choose ${extra}`, t => {
    const h = fixture(t), ledger = h.open();
    assert.throws(() => ledger.registerSynthetic(h.participant('one', { [extra]: 'caller-selected' }), h.declaration()));
    assert.equal(closedStatus(ledger).registrations, 0);
  });
}

for (const subject of ['participant-one', 'user@example.invalid', 'invented-participant-one ', ' invented-participant-one', 'invented-reviewer-dean']) {
  test(`noncanonical synthetic subject is rejected: ${subject}`, t => {
    const h = fixture(t), ledger = h.open();
    assert.throws(() => h.register(ledger, 'one', h.declaration(), h.participant('one', { subject })));
    assert.equal(closedStatus(ledger).registrations, 0);
  });
}

for (const field of ['adultDeclaration', 'eligibilityDeclaration', 'registrationDeclaration']) {
  for (const value of [false, 'true', 1, null, undefined]) test(`${field} must independently be affirmative boolean`, t => {
    const h = fixture(t), ledger = h.open();
    assert.throws(() => h.register(ledger, 'one', h.declaration({ [field]: value })));
    assert.equal(closedStatus(ledger).registrations, 0);
  });
}

for (const declaration of [
  { consentVersion: 'old-synthetic-v0' }, { noticeSha256: 'a'.repeat(64) }, { accountId: 'caller-selected' },
]) test('conflicting or extra consent does not alter a committed canonical receipt', t => {
  const h = fixture(t), ledger = h.open(), first = h.register(ledger);
  assert.throws(() => h.register(ledger, 'one', h.declaration(declaration)));
  const retry = h.register(ledger);
  assert.equal(retry.registrationReference, first.registrationReference);
  assert.equal(retry.receiptSha256, first.receiptSha256);
  assert.equal(closedStatus(ledger).registrations, 1);
});

test('key order and fresh fixture session expiry do not duplicate the canonical receipt', t => {
  const h = fixture(t), ledger = h.open(), first = h.register(ledger);
  h.setTime(h.getTime() + 1_000);
  const reordered = Object.fromEntries(Object.entries(h.declaration()).reverse());
  const retry = h.register(ledger, 'one', reordered);
  assert.equal(retry.registrationReference, first.registrationReference);
  assert.equal(retry.receiptSha256, first.receiptSha256);
  assert.equal(closedStatus(ledger).registrations, 1);
});

test('registration input is snapshotted before a trusted clock callback can mutate its original object', t => {
  const h = fixture(t); let armed = false;
  const principal = h.participant('original');
  const ledger = h.open({ now() {
    if (armed) { principal.subject = 'invented-participant-mutated'; armed = false; }
    return h.getTime();
  } });
  armed = true;
  const registration = h.register(ledger, 'original', h.declaration(), principal);
  const originalRetry = h.register(ledger, 'original');
  assert.equal(originalRetry.registrationReference, registration.registrationReference);
  assert.equal(closedStatus(ledger).registrations, 1);
});

test('decision input is snapshotted before a trusted clock callback can change the selected registration', t => {
  const h = fixture(t); let armed = false, request, alternate;
  const ledger = h.open({ now() {
    if (armed) { request.registrationReference = alternate; armed = false; }
    return h.getTime();
  } });
  const original = h.register(ledger, 'original'), other = h.register(ledger, 'other'); alternate = other.registrationReference;
  request = { decisionId: randomUUID(), registrationReference: original.registrationReference,
    kind: 'approve', reviewer: 'invented-reviewer-dean', expectedVersion: 0 };
  armed = true;
  const decision = ledger.recordSyntheticDecision(request);
  assert.equal(decision.registrationReference, original.registrationReference);
  assert.equal(h.register(ledger, 'original').state, 'approved');
  assert.equal(h.register(ledger, 'other').state, 'pending');
});

for (const expiry of ['expired', 'equal', 'fraction', 'NaN', 'infinite', 'unsafe']) test(`participant deadline rejects ${expiry}`, t => {
  const h = fixture(t), ledger = h.open();
  const values = { expired: h.getTime() - 1, equal: h.getTime(), fraction: h.getTime() + 0.5, NaN: NaN, infinite: Infinity, unsafe: Number.MAX_SAFE_INTEGER + 1 };
  assert.throws(() => h.register(ledger, 'one', h.declaration(), h.participant('one', { expiresAt: values[expiry] })));
  assert.equal(closedStatus(ledger).registrations, 0);
});

test('twenty lifetime slots include declined and revoked records; full-cohort retries still work', t => {
  const h = fixture(t), ledger = h.open();
  const records = Array.from({ length: 20 }, (_, index) => h.register(ledger, 'person-' + index));
  h.decide(ledger, records[0].registrationReference, 'decline', 0);
  h.decide(ledger, records[1].registrationReference, 'approve', 0);
  h.decide(ledger, records[1].registrationReference, 'revoke', 1);
  assert.throws(() => h.register(ledger, 'twenty-one'));
  assert.equal(h.register(ledger, 'person-0').registrationReference, records[0].registrationReference);
  assert.equal(h.register(ledger, 'person-0').state, 'revoked');
  const status = closedStatus(ledger);
  assert.equal(status.registrations, 20);
  assert.equal(status.revoked, 2);
  assert.equal(status.pending, 18);
  assert.equal(status.pendingRemovalJobs, 2);
});

test('interleaved requests at the last lifetime slot cannot produce a twenty-first record', async t => {
  const h = fixture(t), ledger = h.open();
  for (let index = 0; index < 19; index++) h.register(ledger, 'prior-' + index);
  const attempts = await Promise.allSettled(['last-a', 'last-b', 'last-a'].map(suffix => Promise.resolve().then(() => h.register(ledger, suffix))));
  assert.equal(closedStatus(ledger).registrations, 20);
  assert.equal(attempts.filter(attempt => attempt.status === 'rejected').length >= 1, true);
  const successes = attempts.filter(attempt => attempt.status === 'fulfilled').map(attempt => attempt.value.registrationReference);
  assert.equal(new Set(successes).size, 1);
});

test('exact decision retries are idempotent and reflect later terminal revocation', t => {
  const h = fixture(t), ledger = h.open(), { registrationReference } = h.register(ledger);
  const request = { decisionId: randomUUID(), registrationReference, kind: 'approve', reviewer: 'invented-reviewer-dean', expectedVersion: 0 };
  const approved = ledger.recordSyntheticDecision(request);
  assert.deepEqual(ledger.recordSyntheticDecision({ ...request }), approved);
  const revoked = h.decide(ledger, registrationReference, 'revoke', 1);
  assert.equal(revoked.currentState, 'revoked');
  const oldRetry = ledger.recordSyntheticDecision(request);
  assert.equal(oldRetry.decisionReference, approved.decisionReference);
  assert.equal(oldRetry.registrationReference, registrationReference);
  assert.equal(oldRetry.version, approved.version);
  assert.equal(oldRetry.currentState, 'revoked');
  assert.equal(oldRetry.participantAccessGranted, false);
  assert.equal(closedStatus(ledger).pendingRemovalJobs, 1);
});

for (const field of ['kind', 'reviewer', 'registrationReference', 'expectedVersion']) test(`decision-ID retry conflicts when ${field} changes`, t => {
  const h = fixture(t), ledger = h.open(), first = h.register(ledger), other = h.register(ledger, 'other');
  const request = { decisionId: randomUUID(), registrationReference: first.registrationReference, kind: 'approve', reviewer: 'invented-reviewer-dean', expectedVersion: 0 };
  ledger.recordSyntheticDecision(request);
  const changed = { kind: 'revoke', reviewer: 'invented-reviewer-other', registrationReference: other.registrationReference, expectedVersion: 1 };
  assert.throws(() => ledger.recordSyntheticDecision({ ...request, [field]: changed[field] }));
  assert.equal(closedStatus(ledger).approved, 1);
  assert.equal(closedStatus(ledger).pending, 1);
});

for (const terminal of ['decline', 'revoke']) test(`${terminal} of pending record is terminal; no delayed or new approval reopens it`, t => {
  const h = fixture(t), ledger = h.open(), { registrationReference } = h.register(ledger);
  const decision = h.decide(ledger, registrationReference, terminal, 0);
  assert.equal(decision.currentState, 'revoked');
  assert.equal(decision.version, 1);
  assert.throws(() => h.decide(ledger, registrationReference, 'approve', 0));
  assert.throws(() => h.decide(ledger, registrationReference, 'approve', 1));
  assert.equal(h.register(ledger).state, 'revoked');
  assert.equal(closedStatus(ledger).pendingRemovalJobs, 1);
});

test('version, decision kind and synthetic reviewer must match before any decision mutation', t => {
  const h = fixture(t), ledger = h.open(), { registrationReference } = h.register(ledger);
  for (const overrides of [{ expectedVersion: 1 }, { expectedVersion: -1 }, { expectedVersion: 0.5 },
    { kind: 'APPROVE' }, { reviewer: 'dean@example.invalid' }, { role: 'admin' }, { accountId: 'caller-selected' }]) {
    assert.throws(() => h.decide(ledger, registrationReference, 'approve', 0, overrides));
  }
  assert.equal(closedStatus(ledger).pending, 1);
  h.decide(ledger, registrationReference, 'approve', 0);
  assert.throws(() => h.decide(ledger, registrationReference, 'decline', 1));
  assert.throws(() => h.decide(ledger, registrationReference, 'revoke', 0));
  assert.equal(closedStatus(ledger).approved, 1);
});

test('durable reopen preserves receipt identity, terminal state, audits and lifetime slots', t => {
  const h = fixture(t, { durable: true }); let ledger = h.open();
  const first = h.register(ledger);
  h.decide(ledger, first.registrationReference, 'approve', 0);
  h.decide(ledger, first.registrationReference, 'revoke', 1);
  h.close(ledger); ledger = h.open();
  const retry = h.register(ledger);
  assert.equal(retry.registrationReference, first.registrationReference);
  assert.equal(retry.receiptSha256, first.receiptSha256);
  assert.equal(retry.state, 'revoked');
  assert.equal(closedStatus(ledger).registrations, 1);
  assert.equal(closedStatus(ledger).pendingRemovalJobs, 1);
});

test('second writer and unowned existing writer lock reject without stealing or removing the lock', t => {
  const h = fixture(t, { durable: true }), ledger = h.open();
  assert.throws(() => h.open());
  assert.equal(closedStatus(ledger).registrations, 0);
  h.close(ledger);
  const lock = h.storePath + '.writer.lock';
  const descriptor = openSync(lock, 'wx', 0o600); closeSync(descriptor);
  const original = readFileSync(lock);
  assert.throws(() => h.open());
  assert.equal(existsSync(lock), true);
  assert.deepEqual(readFileSync(lock), original);
});

for (const clockKind of ['backward', 'NaN', 'fraction', 'infinite', 'negative', 'unsafe']) test(`live ${clockKind} clock fault remains closed after apparent clock repair and reopen`, t => {
  const h = fixture(t, { durable: true }), ledger = h.open(); h.register(ledger);
  const healthy = h.getTime(), validIdentity = h.participant('later');
  const values = { backward: healthy - 1, NaN: NaN, fraction: healthy + 0.5, infinite: Infinity, negative: -1, unsafe: Number.MAX_SAFE_INTEGER + 1 };
  h.setTime(values[clockKind]); assert.throws(() => h.register(ledger, 'later', h.declaration(), validIdentity));
  h.setTime(healthy + 1_000); assert.throws(() => h.register(ledger, 'later'));
  const status = closedStatus(ledger);
  assert.equal(status.faulted, true);
  assert.equal(status.faultPersistenceVerified, true);
  assert.equal(status.countsVerifiedCurrent, false);
  assert.equal(status.registrations, null);
  h.close(ledger); assert.throws(() => h.open());
});

for (const bad of ['backward', 'invalid']) test(`constructor ${bad} clock rejects and persists the healthy-store fault before corrected reopen`, t => {
  const h = fixture(t, { durable: true }), ledger = h.open(); h.register(ledger); h.close(ledger);
  const healthy = h.getTime(); h.setTime(bad === 'backward' ? healthy - 1 : NaN);
  assert.throws(() => h.open());
  h.setTime(healthy + 1_000); assert.throws(() => h.open());
});

for (const operation of ['register', 'decision']) test(`${operation} clock fault at the transaction boundary survives rollback and corrected reopen`, t => {
  const h = fixture(t, { durable: true }), script = [];
  const ledger = h.open({ now: () => script.length ? script.shift() : h.getTime() });
  const first = h.register(ledger), healthy = h.getTime();
  if (operation === 'register') {
    script.push(healthy, healthy - 1);
    assert.throws(() => h.register(ledger, 'later'));
  } else {
    script.push(healthy, healthy, healthy - 1);
    assert.throws(() => h.decide(ledger, first.registrationReference, 'approve', 0));
  }
  assert.equal(closedStatus(ledger).faulted, true);
  h.close(ledger); h.setTime(healthy + 1_000);
  assert.throws(() => h.open());
});

test('ordinary decision rollback does not discard an already-observed clock high-water', t => {
  const h = fixture(t, { durable: true }), script = [];
  const ledger = h.open({ now: () => script.length ? script.shift() : h.getTime() });
  const first = h.register(ledger), healthy = h.getTime();
  script.push(healthy, healthy + 100);
  assert.throws(() => h.decide(ledger, first.registrationReference, 'approve', 1));
  h.setTime(healthy + 50);
  assert.throws(() => h.register(ledger, 'later'));
  h.close(ledger); h.setTime(healthy + 1_000);
  assert.throws(() => h.open());
});

test('changed storage permissions latch closure rather than allowing an apparent repair', t => {
  const h = fixture(t, { durable: true }), ledger = h.open(); h.register(ledger);
  chmodSync(h.storePath, 0o644); assert.throws(() => h.register(ledger, 'later'));
  chmodSync(h.storePath, 0o600); assert.throws(() => h.register(ledger, 'later'));
  const status = closedStatus(ledger);
  assert.equal(status.faulted, true);
  assert.equal(status.faultPersistenceVerified, true);
  h.close(ledger); assert.throws(() => h.open());
});

test('lost single-link custody closes locally and explicitly reports unverified fault persistence', t => {
  const h = fixture(t, { durable: true }), ledger = h.open(); h.register(ledger);
  linkSync(h.storePath, join(h.directory, 'runtime-alias.sqlite'));
  assert.throws(() => h.register(ledger, 'later'));
  assert.throws(() => h.register(ledger, 'later'));
  const status = closedStatus(ledger);
  assert.equal(status.faulted, true);
  assert.equal(status.faultPersistenceVerified, false);
  // No corrected-restart guarantee is asserted without a trusted latch target.
});

for (const alias of ['symlink', 'hardlink']) test(`${alias} store aliases reject without adopting the alternate store`, t => {
  const h = fixture(t, { durable: true }), ledger = h.open(); h.register(ledger); h.close(ledger);
  const alternateFixture = fixture(t, { durable: true });
  const alternate = alternateFixture.storePath;
  if (alias === 'symlink') symlinkSync(h.storePath, alternate); else linkSync(h.storePath, alternate);
  if (alias === 'symlink') assert.throws(() => h.open({ storePath: alternate }));
  else assert.throws(() => h.open());
});

for (const [name, change] of [
  ['extra trigger', db => db.exec('CREATE TRIGGER surprise AFTER INSERT ON registrations BEGIN SELECT 1; END')],
  ['missing metadata', db => db.exec('DELETE FROM meta')],
  ['changed opaque-account derivation key', db => db.exec("UPDATE meta SET account_key='" + 'f'.repeat(64) + "'")],
  ['rewritten receipt digest', db => db.exec("UPDATE receipts SET digest='" + 'f'.repeat(64) + "'")],
  ['rewritten event digest', db => db.exec("UPDATE events SET digest='" + 'f'.repeat(64) + "' WHERE sequence=1")],
  ['missing decision history', db => db.exec("DELETE FROM events WHERE kind='approve'")],
  ['missing terminal removal intent', db => db.exec('DELETE FROM removal_jobs')],
  ['rewritten approved projection', db => db.exec("UPDATE registrations SET state='approved' WHERE state='revoked'")],
]) test(`fresh synthetic store replay rejects ${name}`, t => {
  const h = fixture(t, { durable: true }), ledger = h.open(), { registrationReference } = h.register(ledger);
  h.decide(ledger, registrationReference, 'approve', 0); h.decide(ledger, registrationReference, 'revoke', 1); h.close(ledger);
  h.mutate(change); assert.throws(() => h.open());
});

test('changed configuration cannot reinterpret an existing synthetic namespace', t => {
  const h = fixture(t, { durable: true }), ledger = h.open(); h.register(ledger); h.close(ledger);
  for (const overrides of [{ epochId: randomUUID() }, { deploymentId: 'invented-other-deployment' }]) {
    assert.throws(() => h.open({ configuration: { ...h.config, ...overrides } }));
  }
});

test('live history fault cannot be cleared by repairing bytes or restarting the same synthetic generation', t => {
  const h = fixture(t, { durable: true }), ledger = h.open(); h.register(ledger);
  let original;
  h.mutate(db => {
    original = db.prepare('SELECT digest FROM events WHERE sequence=1').get().digest;
    db.prepare('UPDATE events SET digest=? WHERE sequence=1').run('f'.repeat(64));
  });
  assert.throws(() => h.register(ledger, 'later'));
  h.mutate(db => db.prepare('UPDATE events SET digest=? WHERE sequence=1').run(original));
  assert.throws(() => h.register(ledger, 'later'));
  assert.equal(closedStatus(ledger).faulted, true);
  h.close(ledger); assert.throws(() => h.open());
});

test('closed foundation cannot be reused after close; healthy equal clock remains valid before close', t => {
  const h = fixture(t), ledger = h.open();
  h.register(ledger); h.register(ledger, 'another');
  assert.equal(closedStatus(ledger).faulted, false);
  h.close(ledger);
  assert.throws(() => h.register(ledger, 'closed'));
  assert.equal(ledger.status().countsVerifiedCurrent, false);
  assert.equal(ledger.status().registrations, null);
});
