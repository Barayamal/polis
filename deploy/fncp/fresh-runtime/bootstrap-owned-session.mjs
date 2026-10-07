/** Fresh-only composition, with an explicitly trusted injected lifecycle.
 * No Docker adapter/image approval/adoption/activation is supplied. Import has
 * no I/O; the factory creates only a new private evidence directory. run() also
 * owns a new local issuer and protocol. Default HTTPS/SQL transports are real,
 * but lifecycle and optional test factories remain trusted, not a sandbox.
 * The lifecycle must itself bound callbacks and independently prove exact new
 * resources. Cancellation denies continuation; it cannot terminate trusted code.
 * Private identities, credentials, endpoints and binding must not be reported.
 */
import { mkdtemp, realpath, chmod, lstat, open, readdir } from 'node:fs/promises';
import { constants } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, randomBytes, X509Certificate } from 'node:crypto';
import { isProxy } from 'node:util/types';
import { createBootstrapProtocol, verifyBootstrapProtocolRequest } from './bootstrap-protocol.mjs';
import { createBootstrapIssuer } from './bootstrap-issuer.mjs';
import { createBootstrapHttpTransport } from './bootstrap-http.mjs';
import { createBootstrapDatabaseExecutor } from './bootstrap-database-executor.mjs';
import { bootstrapSchemaQuery, bootstrapBaselineQuery } from './bootstrap-database-contract.mjs';
import { validateFreshBootstrapResult } from '../fresh-bootstrap-result.mjs';

const active = new WeakMap();
const failure = () => new Error('Fresh bootstrap owned session rejected; private evidence preserved and replay denied.');
const DEDICATED = 'sha256:07f8a21105ed90963ccdf0981d884323116187583a464bb581db14c621d33a98';
const sha = value => createHash('sha256').update(value).digest('hex');
const freeze = value => { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; };
function exact(value, names) {
  if (!value || typeof value !== 'object' || isProxy(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw failure();
  const fields = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(fields).length !== names.length || names.some(n => !fields[n] || !Object.hasOwn(fields[n], 'value'))) throw failure();
  return Object.fromEntries(names.map(n => [n, fields[n].value]));
}
const integer = n => Number.isSafeInteger(n) && n >= 0 && n <= 2147483647 && !Object.is(n, -0);
const stamp = info => ({ dev: info.dev, ino: info.ino, uid: info.uid, mode: info.mode, size: info.size });
const same = (a, b) => ['dev', 'ino', 'uid', 'mode', 'size'].every(k => a[k] === b[k]);
const regular = s => s.isFile() && !s.isSymbolicLink() && s.nlink === 1 && (s.mode & 0o777) === 0o600;
async function write(state, name, data) {
  const bytes = JSON.stringify(data) + '\n';
  const file = await open(join(state.directory, name), constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  try { await file.writeFile(bytes); await file.sync(); const info = await file.stat(); if (!regular(info)) throw failure(); state.files.set(name, { ...stamp(info), hash: sha(bytes) }); }
  finally { await file.close(); }
}
async function integrity(state) {
  const info = await lstat(state.directory);
  if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o777) !== 0o700 ||
      ['dev', 'ino', 'uid', 'mode'].some(k => info[k] !== state.stamp[k]) || await realpath(state.directory) !== state.directory) throw failure();
  const names = await readdir(state.directory);
  if (names.length !== state.files.size || names.some(n => !state.files.has(n))) throw failure();
  for (const [name, expected] of state.files) {
    const path = join(state.directory, name); const before = await lstat(path);
    if (!regular(before) || !same(before, expected)) throw failure();
    const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try { const now = await file.stat(); if (!regular(now) || !same(now, expected) || sha(await file.readFile()) !== expected.hash || !same(await lstat(path), expected)) throw failure(); }
    finally { await file.close(); }
  }
}
async function record(state, event, facts = {}) {
  await integrity(state); const next = state.sequence + 1;
  await write(state, `ledger-${String(next).padStart(4, '0')}.json`, { event, ...facts }); state.sequence = next;
}
/** Active in-process origin and private-file integrity only; not independent
 * Docker ownership. Copied or expired requests never acquire this capability. */
export async function verifyBootstrapOwnedSessionRequest(request) {
  try {
    if (arguments.length !== 1 || !request || typeof request !== 'object' || isProxy(request)) throw failure();
    const entry = active.get(request);
    if (!entry || (entry.state.cancelled && !entry.cleanup)) throw failure();
    await integrity(entry.state);
    if (active.get(request) !== entry || (entry.state.cancelled && !entry.cleanup)) throw failure();
  } catch { throw failure(); }
}
async function lifecycle(state, operation, payload, cleanup = false) {
  await integrity(state); if (state.cancelled && !cleanup) throw failure();
  const request = Object.freeze({ operation, payload: freeze(payload), signal: cleanup ? state.cleanupSignal.signal : state.aborter.signal });
  active.set(request, { state, cleanup });
  try { const result = await state.lifecycle(request); await verifyBootstrapOwnedSessionRequest(request); return result; }
  finally { active.delete(request); }
}
const resourceFields = ['sessionId', 'helperName', 'helperId', 'databaseId', 'databaseName', 'databaseUser', 'imageId',
  'apiOrigin', 'apiCertificatePem', 'databasePort', 'databaseCertificatePem', 'os', 'architecture', 'running',
  'ordinary', 'loopbackOnly', 'egressVerified', 'schemaReady'];
function certificate(pem) {
  if (typeof pem !== 'string' || Buffer.byteLength(pem) > 8192 || !/^-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+\n-----END CERTIFICATE-----\n?$/u.test(pem)) throw failure();
  const cert = new X509Certificate(pem);
  if (cert.checkIP('127.0.0.1') !== '127.0.0.1' || Date.parse(cert.validFrom) > Date.now() || Date.parse(cert.validTo) <= Date.now()) throw failure();
  return sha(cert.raw);
}
function resource(state, value, running) {
  const v = exact(value, resourceFields);
  for (const k of ['sessionId', 'helperName', 'databaseName', 'databaseUser']) if (v[k] !== state.names[k]) throw failure();
  if (typeof v.helperId !== 'string' || !/^[a-f0-9]{64}$/u.test(v.helperId) || typeof v.databaseId !== 'string' ||
      !/^[a-f0-9]{64}$/u.test(v.databaseId) || v.databaseId === v.helperId ||
      typeof v.imageId !== 'string' || !/^sha256:[a-f0-9]{64}$/u.test(v.imageId) || v.imageId === DEDICATED ||
      v.os !== 'linux' || v.architecture !== 'arm64' || v.running !== running ||
      ['ordinary', 'loopbackOnly', 'egressVerified', 'schemaReady'].some(k => v[k] !== true) ||
      typeof v.apiOrigin !== 'string' || !/^https:\/\/127\.0\.0\.1:[1-9][0-9]{3,4}$/u.test(v.apiOrigin) ||
      !Number.isSafeInteger(v.databasePort) || v.databasePort < 1024 || v.databasePort > 65535) throw failure();
  const origin = new URL(v.apiOrigin);
  if (origin.origin !== v.apiOrigin || Number(origin.port) < 1024 || Number(origin.port) > 65535 || Number(origin.port) === v.databasePort) throw failure();
  certificate(v.apiCertificatePem); certificate(v.databaseCertificatePem);
  if (state.resource && resourceFields.some(k => k !== 'running' && v[k] !== state.resource[k])) throw failure();
  return Object.freeze(v);
}
async function inspect(state, cleanup = false, running = true) {
  if (!state.resource) throw failure();
  const result = await lifecycle(state, running ? 'inspect' : 'inspect-closed', { helperId: state.resource.helperId, databaseId: state.resource.databaseId }, cleanup);
  return resource(state, result, running);
}
async function stopHelper(state) {
  if (!state.resource) { if (state.createAttempted) throw failure(); return; }
  if (state.helperClosed) return;
  if (!state.stopAttempted) {
    await inspect(state, true);
    await record(state, 'EXACT_HELPER_STOP_ATTEMPTED', { helperId: state.resource.helperId }); state.stopAttempted = true;
    const result = exact(await lifecycle(state, 'stop', { helperId: state.resource.helperId, databaseId: state.resource.databaseId }, true), ['helperId', 'running']);
    if (result.helperId !== state.resource.helperId || result.running !== false) throw failure();
    state.stopAcknowledged = true;
  }
  if (!state.stopAcknowledged) throw failure();
  await inspect(state, true, false); await record(state, 'EXACT_HELPER_CLOSED_INJECTED_READBACK'); state.helperClosed = true;
}
const contractScope = { classification: 'DATABASE_CONTRACT_ONLY', actualDatabaseRead: false, actualBootstrapExecuted: false,
  databaseOwnershipVerified: false, fullSchemaVerified: false, functionAndRuleBodiesVerified: false, databaseReady: false,
  activationGranted: false, roundOpen: false };
const schemaExpected = { ...contractScope, catalogAdmission: 'LIMITED_REQUIRED_OBJECTS_MATCHED', requiredTables: 11, requiredColumns: 58,
  requiredUniqueKeys: 14, requiredForeignKeys: 9, requiredIdTriggers: 4, voteUpsertRulePresence: true };
const baselineExpected = { ...contractScope, baselineAdmission: 'CLOSED_SEED_BASELINE_MATCHED', statements: 15, seedOwnerParticipants: 1,
  rawVoteHistoryRows: 15, latestUniqueVoteRows: 15, rawSeedOwnerPassVotes: 15, latestUniqueSeedOwnerPassVotes: 15,
  applicableWhitelistRows: 0, applicableXidRows: 0, providerOperationRows: 0, statementTextsVerified: false,
  otherConversationsInspected: false, actorOidcSubjectVerified: false,
  snapshotScope: 'ONE_INJECTED_RESULT_NOT_PERSISTENT_READINESS_OR_RUNTIME_EVIDENCE' };
async function databaseCheck(state, query, expected) {
  await integrity(state); if (state.cancelled || state.activeQuery) throw failure();
  state.activeQuery = query;
  try {
    const result = exact(await state.database.execute(query, { signal: state.aborter.signal }), Object.keys(expected));
    if (Object.entries(expected).some(([k, v]) => result[k] !== v || Object.is(result[k], -0))) throw failure();
    if (state.cancelled) throw failure(); await integrity(state); if (state.cancelled) throw failure();
  } finally { state.activeQuery = undefined; }
}
function capture(state, request, response) {
  if (!['create-conversation', 'create-seed'].includes(request.operation)) return;
  const value = exact(response, ['status', 'body']);
  if (value.status !== 200 || typeof value.body !== 'string' || Buffer.byteLength(value.body) > 65536) throw failure();
  const text = value.body.replace(/^[ \t\r\n]+|[ \t\r\n]+$/gu, ''); const body = JSON.parse(text);
  if (JSON.stringify(body) !== text || !body || Array.isArray(body) || typeof body !== 'object') throw failure();
  if (request.operation === 'create-conversation') {
    state.conversationId = validateFreshBootstrapResult({ conversationId: body.conversation_id, statementIds: Array.from({ length: 15 }, (_, i) => i) }).conversationId;
  } else {
    if (!integer(body.tid) || !integer(body.currentPid) || state.statementIds.includes(body.tid) || state.statementIds.length >= 15 ||
        (state.pid !== undefined && state.pid !== body.currentPid) || request.payload.conversation_id !== state.conversationId) throw failure();
    state.pid = body.currentPid; state.statementIds.push(body.tid);
  }
}
async function protocolDriver(state, request) {
  await verifyBootstrapProtocolRequest(request);
  if (request.operation === 'inspect-helper') {
    await inspect(state); if (!state.schemaAccepted) throw failure();
    return { id: state.resource.helperId, imageId: state.resource.imageId, os: 'linux', architecture: 'arm64', ordinary: true,
      owned: true, loopbackOnly: true, egressVerified: true, schemaReady: true, running: true };
  }
  if (request.operation === 'close-helper') {
    let failed = false;
    try {
      if (!state.cancelled && state.protocol.summary().closedConversationReadback) {
        const query = bootstrapBaselineQuery({ conversationId: state.conversationId, statementIds: state.statementIds, seedOwnerPid: state.pid });
        await record(state, 'CLOSED_RAW_AND_LATEST_BASELINE_ATTEMPTED');
        await databaseCheck(state, query, baselineExpected); await record(state, 'CLOSED_BASELINE_CONTRACT_ACCEPTED'); state.baselineAccepted = true;
      }
    } catch { failed = true; }
    // API/bootstrap work is over. Local client/issuer closure must not wait for
    // a trusted helper inspection/stop callback that may never settle.
    const closures = await Promise.allSettled([stopHelper(state), closeLocalComponents(state)]);
    if (closures.some(result => result.status === 'rejected')) failed = true;
    if (failed || request.payload.id !== state.resource?.helperId) throw failure();
    return { id: state.resource.helperId, running: false };
  }
  if (request.operation === 'inspect-closed') {
    if (request.payload.id !== state.resource?.helperId || !state.helperClosed) throw failure();
    await inspect(state, true, false); return { id: state.resource.helperId, running: false };
  }
  if (state.cancelled || state.activeHttp) throw failure(); state.activeHttp = request;
  try { const response = await state.transport.send(request); await verifyBootstrapProtocolRequest(request); capture(state, request, response); return response; }
  finally { state.activeHttp = undefined; }
}
function closeLocalComponents(state) {
  const pending = [];
  for (const [name, instance] of [['transport', state.transport], ['database', state.database], ['issuer', state.issuer]]) {
    if (!instance) continue;
    let closing = state.localClosures.get(name);
    if (!closing) {
      // Install the entry before invoking trusted code, including synchronous
      // or reentrant close callbacks. Pending/rejected closes are never replayed.
      closing = { instance, promise: undefined };
      state.localClosures.set(name, closing);
      closing.promise = Promise.resolve().then(() => instance.close()).then(() => {
        state.closedComponents.add(name);
      }, () => { state.failed = true; throw failure(); });
    }
    pending.push(closing.promise);
  }
  // Missing components are not marked closed: a later factory completion must
  // still be captured and closed by run's finally pass. These are client/issuer
  // closures, not evidence that any helper or database container has stopped.
  return Promise.allSettled(pending).then(results => {
    if (results.some(result => result.status === 'rejected')) throw failure();
  });
}
async function cleanup(state) {
  const results = await Promise.allSettled([stopHelper(state), closeLocalComponents(state)]);
  if (results.some(result => result.status === 'rejected')) throw failure();
}

/** lifecycle is mandatory trusted code. Optional factories are trusted model
 * seams, not authority flags. Existing paths/resources/credentials are rejected.
 * No callback or listener starts until the one-shot run has been journaled. */
export async function createBootstrapOwnedSession(options) {
  if (arguments.length !== 1) throw failure();
  const names = options && typeof options === 'object' && !isProxy(options) ? Reflect.ownKeys(options) : [];
  if (!names.includes('lifecycle') || names.some(k => !['lifecycle', 'databaseFactory', 'transportFactory'].includes(k))) throw failure();
  const values = exact(options, names);
  if (names.some(k => typeof values[k] !== 'function' || isProxy(values[k]))) throw failure();
  const state = { lifecycle: values.lifecycle, databaseFactory: values.databaseFactory ?? createBootstrapDatabaseExecutor,
    transportFactory: values.transportFactory ?? createBootstrapHttpTransport, files: new Map(), sequence: 0,
    names: freeze({ sessionId: randomBytes(24).toString('hex'), helperName: 'fncp-fresh-helper-' + randomBytes(12).toString('hex'),
      databaseName: 'fncp_fresh_' + randomBytes(12).toString('hex'), databaseUser: 'fncp_fresh_' + randomBytes(12).toString('hex') }),
    password: randomBytes(32).toString('hex'), attempted: false, cancelled: false, completed: false,
    aborter: new AbortController(), cleanupSignal: new AbortController(), createAttempted: false, resource: null,
    stopAttempted: false, stopAcknowledged: false, helperClosed: false, statementIds: [], schemaAccepted: false,
    baselineAccepted: false, localClosures: new Map(), closedComponents: new Set() };
  try {
    state.directory = await mkdtemp(join(await realpath(tmpdir()), 'fncp-owned-bootstrap-session-'));
    await chmod(state.directory, 0o700); state.stamp = stamp(await lstat(state.directory));
    await write(state, 'ownership.json', { ...state.names, classification: 'INJECTED_LIFECYCLE_COMPOSITION', replayAllowed: false });
  } catch { throw failure(); }
  const summary = () => Object.freeze({ classification: 'INJECTED_LIFECYCLE_COMPOSITION', actualRuntime: 'NOT_RUN',
    actualPolisBootstrapVerified: false, independentlyVerifiedDockerOwnership: false, ordinaryImageApproval: 'NOT_ESTABLISHED',
    attempted: state.attempted, cancelled: state.cancelled, completed: state.completed,
    phase: state.completed ? 'CLOSED_COMPOSITION_ACCEPTED' : state.cancelled ? 'CANCELLED' : state.attempted ? 'ATTEMPTED' : 'FRESH',
    catalogContractAccepted: state.schemaAccepted, closedRawAndLatestBaselineAccepted: state.baselineAccepted,
    helperClosure: state.helperClosed ? 'INJECTED_EXACT_ID_READBACK_ACCEPTED' : 'NOT_VERIFIED',
    creationOutcomeUnknown: state.createAttempted && !state.resource, stopOutcomeUnknown: state.stopAttempted && !state.stopAcknowledged,
    transportClosed: state.closedComponents.has('transport'), databaseExecutorClosed: state.closedComponents.has('database'),
    issuerClosed: state.closedComponents.has('issuer'), cachedTokenRevocationImplemented: false,
    activationGranted: false, roundOpen: false, privateEvidencePreserved: true, ledgerEntries: state.sequence });
  function deny() {
    state.cancelled = true; state.aborter.abort(); state.protocol?.cancel();
    // Denial is synchronous; independently start local closure without waiting
    // for the run or any trusted lifecycle callback. No lifecycle action is
    // invented, and completion flags still require each close acknowledgement.
    void closeLocalComponents(state).catch(() => { state.failed = true; });
  }
  async function run() {
    try {
      await record(state, 'SESSION_ATTEMPTED_BEFORE_ANY_CALLBACK'); if (state.cancelled) throw failure();
      state.issuer = await createBootstrapIssuer(); if (state.cancelled) throw failure();
      await record(state, 'FRESH_HELPER_CREATION_ATTEMPTED'); state.createAttempted = true;
      // This result is captured only from this unique request, never discovered
      // from names or adopted after an ambiguous/late cancelled create.
      state.resource = resource(state, await lifecycle(state, 'create', { ...state.names, databasePassword: state.password,
        issuer: state.issuer.configuration() }), true);
      await record(state, 'FRESH_IDENTITIES_CAPTURED', { helperId: state.resource.helperId, databaseId: state.resource.databaseId });
      if (state.cancelled) throw failure();
      const apiPin = certificate(state.resource.apiCertificatePem), dbPin = certificate(state.resource.databaseCertificatePem);
      const assertDatabaseOwned = async lease => {
        const l = exact(lease, ['port', 'database', 'user', 'certificateSha256']);
        if (!state.activeQuery || state.cancelled || l.port !== state.resource.databasePort || l.database !== state.names.databaseName ||
            l.user !== state.names.databaseUser || l.certificateSha256 !== dbPin) throw failure();
        await inspect(state); if (!state.activeQuery || state.cancelled) throw failure();
      };
      const databaseCandidate = await state.databaseFactory({ port: state.resource.databasePort, database: state.names.databaseName,
        user: state.names.databaseUser, password: state.password, certificatePem: state.resource.databaseCertificatePem, assertOwned: assertDatabaseOwned });
      const databaseMethods = exact(databaseCandidate, ['execute', 'close', 'summary']);
      if (Object.values(databaseMethods).some(f => typeof f !== 'function' || isProxy(f))) throw failure();
      state.database = databaseMethods;
      if (state.cancelled) throw failure(); await record(state, 'SCHEMA_CATALOG_CONTRACT_ATTEMPTED');
      await databaseCheck(state, bootstrapSchemaQuery(), schemaExpected); state.schemaAccepted = true;
      await record(state, 'SCHEMA_CATALOG_CONTRACT_ACCEPTED');
      if (state.cancelled) throw failure();
      const transportCandidate = await state.transportFactory({ origin: state.resource.apiOrigin, certificatePem: state.resource.apiCertificatePem, issuer: state.issuer,
        assertOwned: async lease => {
          const l = exact(lease, ['origin', 'certificateSha256']);
          if (!state.activeHttp || state.cancelled || l.origin !== state.resource.apiOrigin || l.certificateSha256 !== apiPin) throw failure();
          await verifyBootstrapProtocolRequest(state.activeHttp); await inspect(state);
          if (!state.activeHttp || state.cancelled) throw failure(); await verifyBootstrapProtocolRequest(state.activeHttp);
        } });
      const transportMethods = exact(transportCandidate, ['send', 'close', 'summary']);
      if (Object.values(transportMethods).some(f => typeof f !== 'function' || isProxy(f))) throw failure();
      state.transport = transportMethods;
      if (state.cancelled) throw failure();
      state.protocol = await createBootstrapProtocol({ driver: request => protocolDriver(state, request) });
      if (state.cancelled) throw failure();
      const result = await state.protocol.run();
      if (state.cancelled || !state.baselineAccepted || !state.helperClosed) throw failure();
      state.binding = validateFreshBootstrapResult(result.binding);
      if (state.binding.conversationId !== state.conversationId || state.binding.statementIds.some((id, i) => id !== state.statementIds[i])) throw failure();
    } catch { state.failed = true; }
    finally { state.protocol?.cancel(); try { await cleanup(state); } catch { state.failed = true; } state.password = undefined; }
    try {
      if (state.failed || state.cancelled || !state.binding) throw failure();
      await record(state, 'CLOSED_COMPOSITION_ACCEPTED_NOT_RUNTIME_APPROVAL');
      if (state.cancelled) throw failure(); state.completed = true;
      return freeze({ binding: state.binding, evidence: 'INJECTED_LIFECYCLE_COMPOSITION', rawSeedOwnerPassVotes: 15,
        latestUniqueSeedOwnerPassVotes: 15, actualRuntime: 'NOT_RUN', activationGranted: false, roundOpen: false });
    } catch { throw failure(); }
  }
  return Object.freeze({ privateDirectory: state.directory,
    summary() { if (arguments.length) throw failure(); return summary(); },
    evidenceDirectories() { if (arguments.length) throw failure(); return Object.freeze([state.directory, ...(state.protocol ? [state.protocol.privateDirectory] : [])]); },
    async verifyIntegrity() { if (arguments.length || state.running) throw failure(); try { await integrity(state); return true; } catch { throw failure(); } },
    cancel() { if (arguments.length) throw failure(); deny(); return summary(); },
    run() { if (arguments.length || state.attempted || state.cancelled) return Promise.reject(failure()); state.attempted = true; state.running = true;
      state.runPromise = run().finally(() => { state.running = false; }); return state.runPromise; },
    async close() {
      if (arguments.length) throw failure(); deny();
      if (!state.closePromise) state.closePromise = (async () => {
        const earlyLocalClosure = closeLocalComponents(state);
        // Observe early errors now, even while a trusted lifecycle keeps run
        // pending. run finally performs another pass for late-created clients.
        const earlyOutcome = earlyLocalClosure.then(() => true, () => false);
        if (state.runPromise) await state.runPromise.catch(() => {});
        let failed = !await earlyOutcome;
        // A rejected local close is remembered, but must not suppress another
        // independently permitted exact-helper readback. No close is replayed.
        try { await cleanup(state); } catch { failed = true; }
        if (failed) throw failure(); return summary(); })();
      return state.closePromise;
    },
  });
}
