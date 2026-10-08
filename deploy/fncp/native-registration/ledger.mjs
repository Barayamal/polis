import { DatabaseSync } from 'node:sqlite';
import { randomBytes, randomUUID } from 'node:crypto';
import { constants, openSync, closeSync, lstatSync, fstatSync, realpathSync, unlinkSync } from 'node:fs';
import { dirname, basename, isAbsolute, resolve } from 'node:path';
import { SCHEMA, assertNativeFoundationSchema } from './store-schema.mjs';
import { FOUNDATION_PROFILE, FOUNDATION_MODE, LIFETIME_CAPACITY, NativeFoundationError,
  exactRecord, canonical, sha256, deriveOpaque, SHA256, UUID, validTime,
  validateConfiguration, validateSyntheticIdentity, validateConsent, validateSyntheticDecision } from './contracts.mjs';

const ZERO = '0'.repeat(64);
const MAX_STORE_BYTES = 2 * 1024 * 1024;
const instances = new WeakSet();
export const isNativeRegistrationFoundation = value => instances.has(value);
const error = (code, verified = false) => new NativeFoundationError(code, verified);

/** Isolated SQLite algorithms for invented identities only. This is NOT the
 * FNCP_NATIVE_APPROVAL_AUTHORITY_V1, a staff login, an admission service, a
 * provider adapter or a recovery authority. Every projection stays closed. */
export function createNativeRegistrationFoundation(options) {
  let configuration, configSha, storePath, now, db, lockFd, lockIdentity, dbIdentity, parentIdentity;
  let disposed = false, faulted = false, faultPersistenceVerified = false;
  let firstFaultCode, observedHighWater = -1, closeFailure;
  let verifiedCounts;
  const lockPath = () => storePath + '.writer.lock';
  const row = ref => db.prepare('SELECT * FROM registrations WHERE registration_ref=?').get(ref);
  const meta = () => db.prepare('SELECT * FROM meta WHERE singleton=1').get();
  const ownedFile = stat => stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1
    && stat.uid === process.getuid();
  const regular = stat => ownedFile(stat)
    && stat.uid === process.getuid() && (stat.mode & 0o777) === 0o600;
  const storage = (faultClosureOnly = false) => {
    if (storePath === ':memory:') return;
    const parent = dirname(storePath), p = lstatSync(parent), s = lstatSync(storePath), l = lstatSync(lockPath());
    // A mode-only fault may still be latched into the SAME owned inode under
    // the unchanged private parent. This exception only closes; never admits.
    if (!(faultClosureOnly ? ownedFile(s) && ownedFile(l) : regular(s) && regular(l))
      || s.size > MAX_STORE_BYTES || s.ino !== dbIdentity.ino || s.dev !== dbIdentity.dev
      || l.ino !== lockIdentity.ino || l.dev !== lockIdentity.dev || p.isSymbolicLink()
      || !p.isDirectory() || p.uid !== process.getuid() || (p.mode & 0o777) !== 0o700
      || p.ino !== parentIdentity.ino || p.dev !== parentIdentity.dev || realpathSync(parent) !== parent) throw error('storage_fault');
  };
  const latch = code => {
    faulted = true;
    firstFaultCode ??= code;
    faultPersistenceVerified = false;
    try {
      storage(true); assertNativeFoundationSchema(db);
      const m = meta();
      if (m?.profile !== FOUNDATION_PROFILE) return;
      db.prepare('UPDATE meta SET fault_code=COALESCE(fault_code,?) WHERE singleton=1').run(firstFaultCode);
      // A write inside a transaction is not yet a durable outcome.
      faultPersistenceVerified = !db.isTransaction && ['clock_fault', 'storage_fault', 'history_fault', 'configuration_fault'].includes(meta()?.fault_code);
    } catch { faultPersistenceVerified = false; }
  };
  const transaction = fn => {
    db.exec('BEGIN IMMEDIATE');
    try { const result = fn(); db.exec('COMMIT'); return result; }
    catch (failure) {
      try {
        db.exec('ROLLBACK');
        if (faulted) latch(firstFaultCode ?? 'storage_fault');
        else if (validTime(observedHighWater)) {
          storage();
          db.prepare('UPDATE meta SET last_ms=MAX(last_ms,?) WHERE singleton=1').run(observedHighWater);
        }
      } catch { latch('storage_fault'); }
      throw failure;
    }
  };
  const parse = text => {
    const value = JSON.parse(text);
    if (canonical(value) !== text) throw error('history_fault');
    return value;
  };
  const validateHistory = () => {
    assertNativeFoundationSchema(db);
    if (db.prepare('PRAGMA quick_check').get().quick_check !== 'ok'
      || db.prepare('PRAGMA foreign_key_check').all().length) throw error('history_fault');
    const m = meta();
    if (!m || m.profile !== FOUNDATION_PROFILE || m.config_sha !== configSha
      || !SHA256.test(m.account_key) || !validTime(m.last_ms) || !validTime(m.sequence)
      || !SHA256.test(m.last_digest) || (m.fault_code !== null && !['clock_fault', 'storage_fault', 'history_fault', 'configuration_fault'].includes(m.fault_code))) throw error('history_fault');
    const registrations = db.prepare('SELECT * FROM registrations ORDER BY registration_ref LIMIT 21').all();
    const receipts = db.prepare('SELECT * FROM receipts LIMIT 21').all();
    const events = db.prepare('SELECT * FROM events ORDER BY sequence LIMIT 61').all();
    const jobs = db.prepare('SELECT * FROM removal_jobs LIMIT 21').all();
    if (registrations.length > LIFETIME_CAPACITY || receipts.length !== registrations.length
      || events.length > LIFETIME_CAPACITY * 3 || jobs.length > registrations.length) throw error('history_fault');
    const projections = new Map(), receiptMap = new Map();
    for (const receipt of receipts) {
      const r = registrations.find(v => v.registration_ref === receipt.registration_ref);
      if (!r || !UUID.test(receipt.receipt_ref) || sha256(receipt.body) !== receipt.digest) throw error('history_fault');
      const body = parse(receipt.body);
      exactRecord(body, ['profile', 'deploymentId', 'epochId', 'registrationReference', 'receiptReference', 'accountId', 'accountKeySha256', 'consent', 'issuedAt']);
      if (body.profile !== FOUNDATION_PROFILE || body.deploymentId !== configuration.deploymentId
        || body.epochId !== configuration.epochId || body.registrationReference !== r.registration_ref
        || body.receiptReference !== receipt.receipt_ref || body.accountId !== r.account_id
        || body.accountKeySha256 !== sha256(m.account_key)
        || !validTime(body.issuedAt) || body.issuedAt > m.last_ms) throw error('history_fault');
      validateConsent(body.consent, configuration);
      if (sha256(canonical(body.consent)) !== r.request_sha) throw error('history_fault');
      receiptMap.set(r.registration_ref, receipt);
    }
    let previous = ZERO, sequence = 0, lastAt = 0;
    for (const event of events) {
      const body = parse(event.body);
      exactRecord(body, ['profile', 'deploymentId', 'epochId', 'accountKeySha256', 'sequence', 'eventReference', 'registrationReference', 'kind', 'version', 'requestSha256', 'receiptSha256', 'reviewerReference', 'occurredAt', 'previousDigest']);
      sequence++;
      if (event.sequence !== sequence || body.sequence !== sequence || event.event_ref !== body.eventReference
        || !UUID.test(event.event_ref) || body.profile !== FOUNDATION_PROFILE
        || body.deploymentId !== configuration.deploymentId || body.epochId !== configuration.epochId
        || body.accountKeySha256 !== sha256(m.account_key)
        || body.registrationReference !== event.registration_ref || body.kind !== event.kind
        || body.version !== event.version || body.requestSha256 !== event.request_sha
        || !SHA256.test(event.request_sha) || body.previousDigest !== previous || event.previous_digest !== previous
        || sha256(event.body) !== event.digest || !validTime(body.occurredAt)
        || body.occurredAt < lastAt || body.occurredAt > m.last_ms
        || body.receiptSha256 !== receiptMap.get(event.registration_ref)?.digest) throw error('history_fault');
      let projection = projections.get(event.registration_ref);
      if (event.kind === 'register') {
        if (projection || event.version !== 0 || body.reviewerReference !== null
          || event.request_sha !== registrations.find(r => r.registration_ref === event.registration_ref)?.request_sha
          || parse(receiptMap.get(event.registration_ref).body).issuedAt !== body.occurredAt) throw error('history_fault');
        projection = { state: 'pending', version: 0, terminalEvent: null };
      } else {
        if (!projection || projection.state === 'revoked' || event.version !== projection.version + 1
          || !/^synthetic-staff-[a-f0-9]{64}$/u.test(body.reviewerReference)
          || event.request_sha !== sha256(canonical({ decisionId: event.event_ref, registrationReference: event.registration_ref,
            kind: event.kind, reviewerReference: body.reviewerReference, expectedVersion: event.version - 1 }))) throw error('history_fault');
        if (event.kind === 'approve' && projection.state === 'pending') projection = { state: 'approved', version: event.version, terminalEvent: null };
        else if ((event.kind === 'decline' && projection.state === 'pending') || event.kind === 'revoke') projection = { state: 'revoked', version: event.version, terminalEvent: event.event_ref };
        else throw error('history_fault');
      }
      projections.set(event.registration_ref, projection); previous = event.digest; lastAt = body.occurredAt;
    }
    if (sequence !== m.sequence || previous !== m.last_digest || projections.size !== registrations.length) throw error('history_fault');
    for (const r of registrations) {
      const p = projections.get(r.registration_ref);
      if (!UUID.test(r.registration_ref) || !/^synthetic-account-[a-f0-9]{64}$/u.test(r.account_id)
        || !p || p.state !== r.state || p.version !== r.version) throw error('history_fault');
      const job = jobs.find(j => j.registration_ref === r.registration_ref);
      if (p.state === 'revoked') {
        if (!job || !UUID.test(job.job_ref) || job.event_ref !== p.terminalEvent || job.state !== 'pending') throw error('history_fault');
      } else if (job) throw error('history_fault');
    }
    verifiedCounts = Object.freeze({ registrations: registrations.length,
      pending: registrations.filter(r => r.state === 'pending').length,
      approved: registrations.filter(r => r.state === 'approved').length,
      revoked: registrations.filter(r => r.state === 'revoked').length,
      pendingRemovalJobs: jobs.length });
    return m;
  };
  const clock = () => {
    if (disposed || faulted) throw error('foundation_closed', faultPersistenceVerified);
    try {
      storage(); const m = validateHistory();
      if (m.fault_code) { faulted = true; faultPersistenceVerified = true; throw error('foundation_closed', true); }
      const at = now();
      if (!validTime(at) || at < m.last_ms || at < observedHighWater) { latch('clock_fault'); throw error('clock_fault', faultPersistenceVerified); }
      observedHighWater = at;
      db.prepare('UPDATE meta SET last_ms=? WHERE singleton=1').run(at);
      return at;
    } catch (failure) {
      if (!faulted) latch(failure?.code === 'storage_fault' ? 'storage_fault' : 'history_fault');
      throw error(failure instanceof NativeFoundationError ? failure.code : 'foundation_closed', faultPersistenceVerified);
    }
  };
  const releaseLock = () => {
    try { if (lockFd !== undefined) closeSync(lockFd); } finally {
      if (lockIdentity) {
        const current = lstatSync(lockPath());
        if (!regular(current) || current.ino !== lockIdentity.ino || current.dev !== lockIdentity.dev) throw error('lock_release_unconfirmed');
        unlinkSync(lockPath());
      }
    }
  };
  try {
    exactRecord(options, ['configuration', 'storePath'], ['now']);
    configuration = validateConfiguration(options.configuration);
    configSha = sha256(canonical(configuration));
    storePath = options.storePath; now = options.now ?? Date.now;
    if (typeof now !== 'function' || typeof storePath !== 'string') throw error('foundation_configuration_rejected');
    if (storePath !== ':memory:') {
      if (!isAbsolute(storePath) || resolve(storePath) !== storePath || basename(storePath) !== 'native-foundation.sqlite'
        || !/^fncp-native-foundation-[A-Za-z0-9_.-]+$/u.test(basename(dirname(storePath)))
        || storePath.includes('/2026-07-10/rev')) throw error('foundation_configuration_rejected');
      const parent = dirname(storePath), p = lstatSync(parent);
      if (!p.isDirectory() || p.isSymbolicLink() || realpathSync(parent) !== parent
        || p.uid !== process.getuid() || (p.mode & 0o777) !== 0o700) throw error('foundation_configuration_rejected');
      parentIdentity = p;
      lockFd = openSync(lockPath(), constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
      lockIdentity = fstatSync(lockFd);
      try { closeSync(openSync(storePath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600)); }
      catch (failure) { if (failure.code !== 'EEXIST') throw failure; }
      dbIdentity = lstatSync(storePath);
      if (!regular(dbIdentity) || !regular(lockIdentity) || dbIdentity.size > MAX_STORE_BYTES) throw error('foundation_configuration_rejected');
      storage();
    }
    db = new DatabaseSync(storePath, { timeout: 1000, allowExtension: false, enableForeignKeyConstraints: true, enableDoubleQuotedStringLiterals: false });
    db.exec('PRAGMA foreign_keys=ON;PRAGMA trusted_schema=OFF;PRAGMA journal_mode=DELETE;PRAGMA synchronous=FULL;');
    const objects = db.prepare("SELECT name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'").all();
    if (!objects.length) {
      const at = now(); if (!validTime(at)) throw error('clock_fault');
      transaction(() => {
        db.exec(SCHEMA);
        db.prepare('INSERT INTO meta VALUES(1,?,?,?,?,?,?,NULL)').run(FOUNDATION_PROFILE, configSha, randomBytes(32).toString('hex'), at, 0, ZERO);
      });
    }
    assertNativeFoundationSchema(db);
    const old = meta();
    if (old?.profile !== FOUNDATION_PROFILE) throw error('foundation_configuration_rejected');
    if (old.config_sha !== configSha) { latch('configuration_fault'); throw error('foundation_configuration_rejected', faultPersistenceVerified); }
    clock();
  } catch (failure) {
    if (db && !faulted) {
      try { if (meta()?.profile === FOUNDATION_PROFILE) latch('history_fault'); } catch { /* Foreign schema is not adopted. */ }
    }
    try { db?.close(); } catch { /* No durable-close claim on storage failure. */ }
    try { releaseLock(); } catch { /* Never unlink a different writer's lock. */ }
    throw error(failure instanceof NativeFoundationError ? failure.code : 'foundation_configuration_rejected', faultPersistenceVerified);
  }

  const append = (registrationReference, kind, version, requestSha256, receiptSha256, reviewerReference, occurredAt, eventReference) => {
    const m = meta(), sequence = m.sequence + 1;
    const body = canonical({ profile: FOUNDATION_PROFILE, deploymentId: configuration.deploymentId, epochId: configuration.epochId,
      accountKeySha256: sha256(m.account_key),
      sequence, eventReference, registrationReference, kind, version, requestSha256, receiptSha256, reviewerReference, occurredAt, previousDigest: m.last_digest });
    const digest = sha256(body);
    db.prepare('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)').run(sequence, eventReference, registrationReference, kind, version, requestSha256, body, digest, m.last_digest);
    db.prepare('UPDATE meta SET sequence=?,last_digest=? WHERE singleton=1').run(sequence, digest);
  };
  const registrationProjection = registration => {
    const receipt = db.prepare('SELECT digest FROM receipts WHERE registration_ref=?').get(registration.registration_ref);
    return Object.freeze({ registrationReference: registration.registration_ref, receiptSha256: receipt.digest,
      state: registration.state, participantAccessGranted: false });
  };
  const decisionProjection = event => Object.freeze({ decisionReference: event.event_ref,
    registrationReference: event.registration_ref, version: event.version,
    currentState: row(event.registration_ref).state, participantAccessGranted: false });
  const api = Object.freeze({
    profile: FOUNDATION_PROFILE,
    registerSynthetic(identity, input) {
      // Validate hostile shapes before the transaction or any getters can run.
      exactRecord(identity, ['subject', 'expiresAt']);
      const identityFields = Object.getOwnPropertyDescriptors(identity);
      const fixtureIdentity = Object.freeze({ subject: identityFields.subject.value, expiresAt: identityFields.expiresAt.value });
      const consent = validateConsent(input, configuration);
      const at = clock(); validateSyntheticIdentity(fixtureIdentity, at);
      const accountId = 'synthetic-account-' + deriveOpaque(meta().account_key, 'native-synthetic-account', fixtureIdentity.subject);
      const requestSha = sha256(canonical(consent));
      return transaction(() => {
        // Synchronous transaction is the reservation and receipt boundary.
        const commitAt = clock(); validateSyntheticIdentity(fixtureIdentity, commitAt);
        const existing = db.prepare('SELECT * FROM registrations WHERE account_id=?').get(accountId);
        if (existing) {
          if (existing.request_sha !== requestSha) throw error('receipt_conflict');
          return registrationProjection(existing);
        }
        if (db.prepare('SELECT count(*) AS n FROM registrations').get().n >= LIFETIME_CAPACITY) throw error('registration_capacity');
        const registrationReference = randomUUID(), receiptReference = randomUUID();
        const body = canonical({ profile: FOUNDATION_PROFILE, deploymentId: configuration.deploymentId, epochId: configuration.epochId,
          registrationReference, receiptReference, accountId, accountKeySha256: sha256(meta().account_key), consent, issuedAt: commitAt });
        const digest = sha256(body);
        db.prepare("INSERT INTO registrations VALUES(?,?,?,'pending',0)").run(registrationReference, accountId, requestSha);
        db.prepare('INSERT INTO receipts VALUES(?,?,?,?)').run(receiptReference, registrationReference, body, digest);
        append(registrationReference, 'register', 0, requestSha, digest, null, commitAt, randomUUID());
        return registrationProjection(row(registrationReference));
      });
    },
    recordSyntheticDecision(input) {
      validateSyntheticDecision(input);
      const decision = JSON.parse(canonical(input));
      const at = clock(), m = meta();
      const reviewerReference = 'synthetic-staff-' + deriveOpaque(m.account_key, 'native-synthetic-reviewer', decision.reviewer);
      const requestSha = sha256(canonical({ decisionId: decision.decisionId, registrationReference: decision.registrationReference,
        kind: decision.kind, reviewerReference, expectedVersion: decision.expectedVersion }));
      return transaction(() => {
        clock();
        const previous = db.prepare('SELECT * FROM events WHERE event_ref=?').get(decision.decisionId);
        if (previous) {
          if (previous.kind === 'register' || previous.request_sha !== requestSha) throw error('decision_conflict');
          return decisionProjection(previous);
        }
        const r = row(decision.registrationReference);
        if (!r || r.version !== decision.expectedVersion || r.state === 'revoked'
          || (['approve', 'decline'].includes(decision.kind) && r.state !== 'pending')) throw error('decision_rejected');
        const version = r.version + 1, state = decision.kind === 'approve' ? 'approved' : 'revoked';
        const receipt = db.prepare('SELECT digest FROM receipts WHERE registration_ref=?').get(r.registration_ref);
        const occurredAt = clock();
        append(r.registration_ref, decision.kind, version, requestSha, receipt.digest, reviewerReference, occurredAt, decision.decisionId);
        db.prepare('UPDATE registrations SET state=?,version=? WHERE registration_ref=?').run(state, version, r.registration_ref);
        if (state === 'revoked') db.prepare("INSERT INTO removal_jobs VALUES(?,?,?,'pending')").run(randomUUID(), r.registration_ref, decision.decisionId);
        return decisionProjection(db.prepare('SELECT * FROM events WHERE event_ref=?').get(decision.decisionId));
      });
    },
    status() {
      if (!disposed && !faulted) clock();
      // Never read damaged rows or report zero as preserved state after close.
      const countsVerifiedCurrent = !disposed && !faulted;
      const counts = countsVerifiedCurrent ? verifiedCounts
        : { registrations: null, pending: null, approved: null, revoked: null, pendingRemovalJobs: null };
      return Object.freeze({ profile: FOUNDATION_PROFILE, mode: FOUNDATION_MODE, ...counts, countsVerifiedCurrent, faulted,
        faultPersistenceVerified, roundOpen: false, admissionAllowed: false,
        currentDenialHistoryVerified: false, productionAuthenticationVerified: false });
    },
    close() {
      if (closeFailure) throw error('closure_unconfirmed', faultPersistenceVerified);
      if (disposed) return Object.freeze({ closed: true, admissionAllowed: false });
      disposed = true;
      let failed = false;
      try { db.close(); } catch { failed = true; }
      try { releaseLock(); } catch { failed = true; }
      if (failed) { closeFailure = true; throw error('closure_unconfirmed', faultPersistenceVerified); }
      return Object.freeze({ closed: true, admissionAllowed: false });
    },
  });
  instances.add(api);
  return api;
}
