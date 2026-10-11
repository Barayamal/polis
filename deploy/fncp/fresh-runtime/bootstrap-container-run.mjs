/** Fixed, one-attempt Linux container CLI. Import performs no I/O. The external
 * owner must attest NEW API/PG containers, their shared no-egress namespace,
 * source/image closure and fixed hosts entries before execution. This process
 * cannot attest Docker ownership and never calls the still-running holder a
 * stopped helper. Only aggregate output leaves this boundary; private generated
 * files remain in the owner's fresh tmpfs until its separate disposal.
 */
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { createHash, generateKeyPair, randomBytes, X509Certificate } from 'node:crypto';
import { promisify } from 'node:util';
import { request } from 'node:https';
import { checkServerIdentity } from 'node:tls';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createBootstrapIssuer } from './bootstrap-issuer.mjs';
import { createBootstrapContainerJwksService } from './bootstrap-jwks-service.mjs';
import { createBootstrapApiTrust } from './bootstrap-api-trust.mjs';
import { createBootstrapApiProcess } from './bootstrap-api-process.mjs';
import { createBootstrapDatabaseExecutor } from './bootstrap-database-executor.mjs';
import { bootstrapSchemaQuery, bootstrapBaselineQuery } from './bootstrap-database-contract.mjs';
import { validateFreshBootstrapResult } from '../fresh-bootstrap-result.mjs';

const ROOT = '/run/fncp/bootstrap';
const LAUNCH = ROOT + '/launch.json';
const SEED_URL = new URL('../seed-statements.json', import.meta.url);
const SEED_SHA = 'b8c49ddaab72740df997b4975e84b0a51501fa97e1c622420826f4840bc6e06b';
const MAX_BYTES = 65536;
const fail = () => new Error('FRESH_CONTAINER_BOOTSTRAP_FAILED');
const sha = value => createHash('sha256').update(value).digest('hex');
const same = (a, b) => ['dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtimeMs', 'ctimeMs'].every(k => a[k] === b[k]);
const plain = value => !!value && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
function canonical(text) {
  const cleaned = text.replace(/^[ \t\r\n]+|[ \t\r\n]+$/gu, '');
  const value = JSON.parse(cleaned);
  if (JSON.stringify(value) !== cleaned) throw fail();
  return value;
}
function exact(value, names) {
  if (!plain(value) || Reflect.ownKeys(value).length !== names.length || names.some(k => !Object.hasOwn(value, k))) throw fail();
  return value;
}
function launchValue(bytes) {
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  const value = exact(canonical(text), ['namespaceId', 'database', 'user', 'password', 'databaseCertificatePem', 'databaseCertificateSha256']);
  if (typeof value.namespaceId !== 'string' || !/^[a-f0-9]{24}$/u.test(value.namespaceId) ||
      !['database', 'user'].every(k => typeof value[k] === 'string' && /^fncp_fresh_[a-f0-9]{24}$/u.test(value[k])) ||
      typeof value.password !== 'string' || !/^[a-f0-9]{64}$/u.test(value.password) ||
      typeof value.databaseCertificateSha256 !== 'string' || !/^[a-f0-9]{64}$/u.test(value.databaseCertificateSha256) ||
      typeof value.databaseCertificatePem !== 'string' || Buffer.byteLength(value.databaseCertificatePem) > 8192 ||
      !/^-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+\n-----END CERTIFICATE-----\n?$/u.test(value.databaseCertificatePem)) throw fail();
  const cert = new X509Certificate(value.databaseCertificatePem);
  if (sha(cert.raw) !== value.databaseCertificateSha256 || cert.checkIP('127.0.0.1') !== '127.0.0.1' ||
      cert.checkHost(`fncp-fresh-pg-${value.namespaceId}`, { subject: 'never', wildcards: false }) !== `fncp-fresh-pg-${value.namespaceId}` ||
      !Number.isFinite(Date.parse(cert.validFrom)) || !Number.isFinite(Date.parse(cert.validTo)) ||
      Date.parse(cert.validFrom) > Date.now() || Date.parse(cert.validTo) <= Date.now() || !cert.verify(cert.publicKey)) throw fail();
  return Object.freeze(value);
}
async function readFixed(path, limit, privateFile = true) {
  const before = await lstat(path);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size < 1 || before.size > limit ||
      (privateFile && (before.uid !== 1000 || (before.mode & 0o777) !== 0o600))) throw fail();
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  let bytes;
  try {
    if (!same(await file.stat(), before)) throw fail();
    const buffer = Buffer.alloc(limit + 1); let size = 0;
    while (size < buffer.length) { const result = await file.read(buffer, size, buffer.length - size, size); if (!result.bytesRead) break; size += result.bytesRead; }
    if (size !== before.size || !same(await file.stat(), before)) throw fail(); bytes = buffer.subarray(0, size);
  } finally { await file.close(); }
  if (!same(await lstat(path), before)) throw fail();
  return { bytes, stamp: before };
}
async function fixedDirectory() {
  const info = await lstat(ROOT);
  if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== 1000 || (info.mode & 0o777) !== 0o700 || await realpath(ROOT) !== ROOT) throw fail();
  return info;
}
async function exclusive(name, bytes) {
  const file = await open(ROOT + '/' + name, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    await file.writeFile(bytes); await file.sync(); const info = await file.stat();
    if (!info.isFile() || info.nlink !== 1 || info.uid !== 1000 || (info.mode & 0o777) !== 0o600 || info.size !== Buffer.byteLength(bytes)) throw fail();
  } finally { await file.close(); }
}
function environment(value, issuer, jwks, pepper, encryption) {
  const n = value.namespaceId; const database = `postgres://${value.user}:${value.password}@fncp-fresh-pg-${n}:5432/${value.database}`;
  return Object.freeze({ PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C', FNCP_FRESH_BOOTSTRAP_LOCAL_ONLY: 'true', NODE_ENV: 'production',
    DEV_MODE: 'false', TESTING: 'false', ENABLE_TELEMETRY: 'false', USE_NETWORK_HOST: 'false', SHOULD_USE_TRANSLATION_API: 'false',
    BACKFILL_COMMENT_LANG_DETECTION: 'false', RUN_PERIODIC_EXPORT_TESTS: 'false', SERVER_LOG_TO_FILE: 'false', EMAIL_TRANSPORT_TYPES: 'disabled',
    ADMIN_EMAILS: '[]', ADMIN_UIDS: '[]', API_SERVER_PORT: '5000', DATABASE_SSL: 'true', AUTH_AUDIENCE: 'fncp-fresh-synthetic-bootstrap',
    AUTH_ISSUER: issuer, FNCP_BOOTSTRAP_DATABASE_CERTIFICATE_SHA256: value.databaseCertificateSha256,
    FNCP_BOOTSTRAP_JWKS_CERTIFICATE_SHA256: jwks.certificateSha256, LOGIN_CODE_PEPPER: pepper, ENCRYPTION_PASSWORD_00001: encryption,
    DATABASE_URL: database, READ_ONLY_DATABASE_URL: database, JWKS_URI: `https://fncp-fresh-jwks-${n}:8444/.well-known/jwks.json`,
    API_PROD_HOSTNAME: `fncp-fresh-api-${n}:8443`, DOMAIN_OVERRIDE: `fncp-fresh-api-${n}:8443`, POLIS_JWT_ISSUER: `https://fncp-fresh-api-${n}:8443/`,
    POLIS_JWT_AUDIENCE: 'fncp-fresh-synthetic-participants', JWT_PRIVATE_KEY_PATH: ROOT + '/participant-private.pem', JWT_PUBLIC_KEY_PATH: ROOT + '/participant-public.pem' });
}
function requestAt(step, binding, seeds) {
  if (!Number.isInteger(step) || step < 0 || step > 18 || !Array.isArray(seeds) || seeds.length !== 15) throw fail();
  if (step === 0) return { method: 'POST', path: '/api/v3/conversations', body: {
    topic: 'FNCP Option C fresh disposable access QA', description: 'Synthetic local test only. No genuine participant data.',
    is_active: true, is_anon: true, is_draft: false, is_data_open: false, topics_enabled: false, treevite_enabled: false,
    strict_moderation: true, profanity_filter: false, spam_filter: false } };
  const id = binding.conversationId;
  if (typeof id !== 'string' || !/^[0-9][0-9A-Za-z]{5,99}$/u.test(id)) throw fail();
  if (step < 16) return { method: 'POST', path: '/api/v3/comments', body: { conversation_id: id, txt: seeds[step - 1], is_seed: true } };
  if (step === 16) return { method: 'GET', path: `/api/v3/comments?conversation_id=${id}&moderation=true&include_voting_patterns=true`, body: null };
  if (step === 17) return { method: 'PUT', path: '/api/v3/conversations', body: { conversation_id: id, is_active: false,
    use_xid_whitelist: true, xid_required: true, send_created_email: false } };
  return { method: 'GET', path: `/api/v3/conversations?conversation_id=${id}`, body: null };
}
const integer = value => Number.isSafeInteger(value) && value >= 0 && value <= 2147483647 && !Object.is(value, -0);
function acceptAt(step, body, binding, seeds) {
  if (step === 0) {
    if (!plain(body) || typeof body.conversation_id !== 'string' || !/^[0-9][0-9A-Za-z]{5,99}$/u.test(body.conversation_id) ||
        /^9fncpBootstrap[0-9a-f]{48}$/u.test(body.conversation_id)) throw fail();
    validateFreshBootstrapResult({ conversationId: body.conversation_id, statementIds: Array.from({ length: 15 }, (_, n) => n) });
    binding.conversationId = body.conversation_id; return;
  }
  if (step < 16) {
    if (!plain(body) || !integer(body.tid) || !integer(body.currentPid) || binding.statementIds.includes(body.tid) ||
        binding.statementIds.length !== step - 1 || (binding.seedOwnerPid !== undefined && body.currentPid !== binding.seedOwnerPid)) throw fail();
    binding.statementIds.push(body.tid); binding.seedOwnerPid = body.currentPid; return;
  }
  if (step === 16) {
    if (!Array.isArray(body) || body.length !== 15 || new Set(body.map(row => row?.tid)).size !== 15) throw fail();
    for (let n = 0; n < 15; n++) {
      const row = body.find(row => row?.tid === binding.statementIds[n]);
      if (!plain(row) || row.conversation_id !== binding.conversationId || row.pid !== binding.seedOwnerPid || row.txt !== seeds[n] ||
          row.is_seed !== true || row.mod !== 1 || row.active !== true || row.agree_count !== 0 || row.disagree_count !== 0 ||
          row.pass_count !== 1 || row.count !== 1) throw fail();
    }
    return;
  }
  if (!plain(body) || body.conversation_id !== binding.conversationId) throw fail();
  if (step === 18 && (['is_active', 'is_data_open', 'is_draft', 'topics_enabled', 'treevite_enabled', 'profanity_filter', 'spam_filter'].some(k => body[k] !== false) ||
      ['is_owner', 'use_xid_whitelist', 'xid_required', 'strict_moderation', 'is_anon'].some(k => body[k] !== true))) throw fail();
}
async function send(config, descriptor, token, signal, check) {
  check(); const url = new URL(config.origin); const body = descriptor.body === null ? null : JSON.stringify(descriptor.body);
  return new Promise((resolveResult, reject) => {
    let req, res, done = false;
    const finish = (error, value) => {
      if (done) return; done = true; clearTimeout(timer); signal.removeEventListener('abort', abort);
      if (error) { res?.destroy(); req?.destroy(); reject(fail()); } else resolveResult(value);
    };
    const abort = () => finish(fail()); const timer = setTimeout(abort, 2000);
    signal.addEventListener('abort', abort, { once: true });
    try {
      check();
      const headers = { accept: 'application/json', 'content-type': 'application/json', 'x-forwarded-proto': 'https',
        host: url.host, connection: 'close', authorization: 'Bearer ' + token };
      if (body !== null) headers['content-length'] = String(Buffer.byteLength(body));
      req = request({ hostname: '127.0.0.1', port: Number(url.port), path: descriptor.path, method: descriptor.method,
        ca: config.certificatePem, rejectUnauthorized: true, minVersion: 'TLSv1.2', agent: false, maxHeaderSize: 8192, headers,
        checkServerIdentity(host, peer) {
          if (checkServerIdentity(host, peer) || !peer.raw || sha(peer.raw) !== config.certificateSha256) return fail();
        } }, response => {
        res = response; res.on('error', abort); res.on('aborted', abort);
        try {
          check();
          if (req.socket.authorized !== true || req.socket.remoteAddress !== '127.0.0.1' || !['TLSv1.2', 'TLSv1.3'].includes(req.socket.getProtocol()) ||
              res.statusCode !== 200 || res.headers.location !== undefined || res.headers['content-encoding'] !== undefined || res.headers['set-cookie'] !== undefined ||
              res.rawHeaders.filter((h, i) => i % 2 === 0 && h.toLowerCase() === 'content-type').length !== 1 ||
              !/^application\/json(?:; charset=utf-8)?$/iu.test(res.headers['content-type'] || '') ||
              (res.headers['content-length'] !== undefined && (!/^(0|[1-9][0-9]*)$/u.test(res.headers['content-length']) || Number(res.headers['content-length']) > MAX_BYTES))) throw fail();
        } catch { abort(); return; }
        let size = 0; const chunks = [];
        res.on('data', chunk => { size += chunk.length; if (size > MAX_BYTES) abort(); else chunks.push(Buffer.from(chunk)); });
        res.on('end', () => {
          try { check(); if (!res.complete) throw fail(); const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(Buffer.concat(chunks)); finish(null, canonical(text)); }
          catch { abort(); }
        });
      });
      req.on('error', abort); req.end(body ?? undefined);
    } catch { abort(); }
  });
}

function jwksDiagnostics(state) {
  const names = [['jwksServedRequests', 'servedRequests'], ['jwksRejectedRequests', 'rejectedRequests'], ['jwksTlsErrors', 'tlsErrors']];
  const values = {};
  for (const [publicName, sourceName] of names) {
    const count = state === undefined ? null : state[sourceName];
    if (state !== undefined && (!Number.isSafeInteger(count) || count < 0 || Object.is(count, -0))) throw fail();
    values[publicName] = count;
  }
  return Object.freeze(values);
}

async function run() {
  let phase = 'PLATFORM', failedPhase = null, launch, launchRead, directory, journal;
  let database, issuer, jwks, api, token; let schemaVerified = false, baselineVerified = false, closedReadback = false;
  let attempted = 0, accepted = 0, keysGenerated = false, cleanupComplete = false;
  let issuerAttempted = false, jwksAttempted = false, apiAttempted = false;
  const aborter = new AbortController(); const binding = { statementIds: [] };
  let timer;
  const abort = () => { aborter.abort(); void issuer?.close().catch(() => {}); };
  const check = () => { if (aborter.signal.aborted) throw fail(); if (api) api.assertActive(); };
  const record = async (event, facts = {}) => {
    if (!journal) throw fail(); await journal.writeFile(JSON.stringify({ event, phase, ...facts }) + '\n'); await journal.sync();
  };
  try {
    if (process.platform !== 'linux' || process.getuid?.() !== 1000 || process.argv.length !== 2 || process.execArgv.length !== 0) throw fail();
    process.once('SIGTERM', abort); process.once('SIGINT', abort);
    timer = setTimeout(abort, 90000);
    phase = 'LAUNCH_FILE'; directory = await fixedDirectory(); launchRead = await readFixed(LAUNCH, 16384); launch = launchValue(launchRead.bytes);
    phase = 'CLAIM_ATTEMPT'; check();
    journal = await open(ROOT + '/attempt.jsonl', constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    await record('ONE_SHOT_ATTEMPT_CLAIMED');
    const source = await readFixed(SEED_URL, 16384, false);
    if (sha(source.bytes) !== SEED_SHA) throw fail();
    const seeds = JSON.parse(source.bytes);
    if (!Array.isArray(seeds) || seeds.length !== 15 || new Set(seeds).size !== 15 || seeds.some(v => typeof v !== 'string' || !v.length || v.length > 1000)) throw fail();
    const assertLaunch = async lease => {
      check(); const nowDirectory = await fixedDirectory();
      if (['dev', 'ino', 'uid', 'gid', 'mode'].some(k => directory[k] !== nowDirectory[k])) throw fail();
      const current = await readFixed(LAUNCH, 16384);
      if (!same(current.stamp, launchRead.stamp) || sha(current.bytes) !== sha(launchRead.bytes) || lease.port !== 5432 ||
          lease.database !== launch.database || lease.user !== launch.user || lease.certificateSha256 !== launch.databaseCertificateSha256) throw fail();
      check();
    };
    phase = 'SCHEMA'; await record('SCHEMA_READ_ATTEMPTED'); check();
    database = createBootstrapDatabaseExecutor({ port: 5432, database: launch.database, user: launch.user, password: launch.password,
      certificatePem: launch.databaseCertificatePem, assertOwned: assertLaunch });
    const schema = await database.execute(bootstrapSchemaQuery(), { signal: aborter.signal }); check();
    if (schema.catalogAdmission !== 'LIMITED_REQUIRED_OBJECTS_MATCHED') throw fail(); schemaVerified = true; await record('SCHEMA_CONTRACT_MATCHED');
    phase = 'GENERATED_KEYS'; check();
    const pair = await promisify(generateKeyPair)('rsa', { modulusLength: 2048 }); check();
    const key = Buffer.from(pair.privateKey.export({ format: 'pem', type: 'pkcs8' }));
    try { check(); await exclusive('participant-private.pem', key); } finally { key.fill(0); }
    check(); await exclusive('participant-public.pem', pair.publicKey.export({ format: 'pem', type: 'spki' }));
    check(); await exclusive('postgres-cert.pem', launch.databaseCertificatePem); check(); keysGenerated = true;
    phase = 'ISSUER_JWKS'; check(); issuerAttempted = true; issuer = await createBootstrapIssuer(); check();
    check(); jwksAttempted = true; jwks = await createBootstrapContainerJwksService({ issuer, namespaceId: launch.namespaceId }); check();
    const jwksConfig = jwks.configuration(); check(); await exclusive('jwks-cert.pem', jwksConfig.certificatePem); check();
    const pepper = randomBytes(32).toString('hex'), encryption = randomBytes(32).toString('hex');
    if (pepper === encryption || [pepper, encryption].includes(launch.password)) throw fail();
    phase = 'API_START'; await record('ACTUAL_FIXED_APPLICATION_START_ATTEMPTED'); check();
    const trust = await createBootstrapApiTrust({ issuer }); check();
    apiAttempted = true; api = await createBootstrapApiProcess({ trust, environment: environment(launch, issuer.configuration().issuer, jwksConfig, pepper, encryption) }); check();
    const config = api.configuration(); token = issuer.issueToken();
    for (let step = 0; step < 19; step++) {
      phase = step === 0 ? 'CREATE_CONVERSATION' : step < 16 ? 'CREATE_SEED' : step === 16 ? 'READ_SEEDS' : step === 17 ? 'CLOSE_CONVERSATION' : 'READ_CLOSED_CONVERSATION';
      check(); await record('HTTP_ATTEMPTED_NO_REPLAY', { step }); check(); attempted++;
      const body = await send(config, requestAt(step, binding, seeds), token, aborter.signal, check); check();
      acceptAt(step, body, binding, seeds); accepted++; await record('HTTP_ACCEPTED', { step });
      if (step === 18) closedReadback = true;
    }
    phase = 'BASELINE'; await record('EXACT_CLOSED_BASELINE_ATTEMPTED');
    const baseline = await database.execute(bootstrapBaselineQuery(binding), { signal: aborter.signal }); check();
    if (baseline.baselineAdmission !== 'CLOSED_SEED_BASELINE_MATCHED') throw fail(); baselineVerified = true;
    check(); await exclusive('binding.json', JSON.stringify(binding) + '\n'); check(); await record('EXACT_CLOSED_BASELINE_MATCHED'); check(); phase = 'COMPLETE';
  } catch { failedPhase = phase; }
  finally {
    token = undefined; clearTimeout(timer); aborter.abort(); process.removeListener('SIGTERM', abort); process.removeListener('SIGINT', abort);
    const outcomes = await Promise.allSettled([Promise.resolve().then(() => api?.close()), Promise.resolve().then(() => jwks?.close()),
      Promise.resolve().then(() => issuer?.close()), Promise.resolve().then(() => database?.close())]);
    cleanupComplete = outcomes.every(v => v.status === 'fulfilled');
    if (journal) {
      try { await record('LOCAL_COMPONENT_CLOSE_CALLS_SETTLED', { knownCloseCallsFulfilled: cleanupComplete,
        factoriesWithoutReturnedCleanupEvidence: Number(issuerAttempted && !issuer) + Number(jwksAttempted && !jwks) + Number(apiAttempted && !api) }); await journal.close(); }
      catch { cleanupComplete = false; try { await journal.close(); } catch {} }
    }
  }
  const owner = api?.summary().owner, db = database?.summary(), issuerState = issuer?.summary(), jwksState = jwks?.summary();
  // A rejecting factory does not return its private cleanup observations. Do
  // not convert that missing evidence into a successful component-close claim.
  if ((issuerAttempted && !issuer) || (jwksAttempted && !jwks) || (apiAttempted && !api)) cleanupComplete = false;
  if (api && !(owner?.childExitVerified && owner?.ipcDisconnected && owner?.listenerClosureVerified)) cleanupComplete = false;
  if (issuer && !issuerState.listenersClosed) cleanupComplete = false;
  if (jwks && !jwksState.listenersClosed) cleanupComplete = false;
  if (database && !(db.closed && db.workersStarted === db.workersClosed)) cleanupComplete = false;
  if (!cleanupComplete && failedPhase === null) failedPhase = 'CLEANUP';
  return Object.freeze({ classification: 'ONE_SHOT_CONTAINER_LOCAL_ACTUAL_BOOTSTRAP', outcome: failedPhase === null ? 'PASS' : 'FAIL',
    phase: failedPhase ?? 'COMPLETE', schemaContractVerified: schemaVerified, keysGenerated, httpRequestsAttempted: attempted,
    httpResponsesAccepted: accepted, seedStatementsCreated: binding.statementIds.length, actualPolisAppExecuted: accepted > 0,
    closedConversationVerified: closedReadback, roundOpen: closedReadback ? false : 'UNVERIFIED', independentSqlBaselineVerified: baselineVerified,
    apiChildExitVerified: owner?.childExitVerified ?? false, apiIpcDisconnected: owner?.ipcDisconnected ?? false,
    apiListenerRefused: owner?.listenerClosureVerified ?? false, issuerClosed: issuerState?.listenersClosed ?? false,
    jwksClosed: jwksState?.listenersClosed ?? false, ...jwksDiagnostics(jwksState),
    databaseWorkersClosed: db ? db.closed && db.workersStarted === db.workersClosed : false,
    cleanupComplete, holderContainerStopped: false, databaseProcessStopped: false, containerOwnershipVerified: false,
    databaseOwnershipVerified: false, externalEgressVerified: false, activationGranted: false });
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try { const result = await run(); process.stdout.write(JSON.stringify(result) + '\n'); process.exitCode = result.outcome === 'PASS' ? 0 : 1; }
  catch { process.stdout.write(JSON.stringify({ outcome: 'FAIL', phase: 'FINALIZATION', classification: 'ONE_SHOT_CONTAINER_LOCAL_ACTUAL_BOOTSTRAP' }) + '\n'); process.exitCode = 1; }
}
