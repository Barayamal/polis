import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir, lstat, chmod, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash, X509Certificate } from 'node:crypto';
import { connect } from 'node:net';
import { createBootstrapOwnedSession, verifyBootstrapOwnedSessionRequest } from './bootstrap-owned-session.mjs';
import { verifyBootstrapProtocolRequest } from './bootstrap-protocol.mjs';
import { validateBootstrapSchemaResult, validateBootstrapBaselineResult } from './bootstrap-database-contract.mjs';

const ERROR = /Fresh bootstrap owned session rejected; private evidence preserved and replay denied\./u;
const ID = '1'.repeat(64), DATABASE_ID = '2'.repeat(64), IMAGE = 'sha256:' + '3'.repeat(64);
const CONVERSATION = '9OwnedSessionSynthetic';
const TIDS = [19, 44, 6, 250, 37, 9, 82, 103, 81, 1029, 37_001, 502, 21, 65, 714];
const PID = 41;
const api = value => Object.freeze({ status: 200, body: JSON.stringify(value) });
const pin = pem => createHash('sha256').update(new X509Certificate(pem).raw).digest('hex');
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
async function eventually(check) {
  const deadline = performance.now() + 1500;
  while (!check()) { assert.ok(performance.now() < deadline, 'Independent local closure must not wait for the held lifecycle callback.'); await new Promise(resolve => setTimeout(resolve, 10)); }
}
async function issuerListenerClosed(model) {
  const port = Number(new URL(model.create.issuer.issuer).port);
  await new Promise((resolve, reject) => {
    const socket = connect({ host: '127.0.0.1', port }); socket.setTimeout(500);
    socket.once('connect', () => { socket.destroy(); reject(new Error('Fresh owned issuer listener remained open.')); });
    socket.once('timeout', () => { socket.destroy(); reject(new Error('Fresh owned listener closure was not verified.')); });
    socket.once('error', error => { socket.destroy(); error.code === 'ECONNREFUSED' ? resolve() : reject(new Error('Unexpected fresh listener state.')); });
  });
}
const allLocalClosed = session => { const s = session.summary(); return s.transportClosed && s.databaseExecutorClosed && s.issuerClosed; };
const schemaRows = () => [{ server_major_17: true, transaction_read_only: true, origin_replication_role: true,
  tables_match: true, columns_match: true, unique_keys_match: true, foreign_keys_match: true,
  id_triggers_match: true, vote_rule_present: true, function_signatures_match: true }];
const baselineRows = () => [{ transaction_read_only: true, target_rows: 1, conversation_alias_rows: 1, owner_rows: 1, owner_mapping_rows: 1,
  participant_rows: 1, owner_participant_rows: 1, statement_rows: 15, valid_seed_rows: 15, distinct_expected_statement_ids: 15,
  raw_vote_rows: 15, raw_seed_owner_pass_rows: 15, raw_distinct_seed_ids: 15,
  latest_unique_vote_rows: 15, latest_seed_owner_pass_rows: 15, latest_distinct_seed_ids: 15,
  applicable_whitelist_rows: 0, applicable_xid_rows: 0, provider_operation_rows: 0, closed_flags_match: true }];
async function journal(session) {
  const files = (await readdir(session.privateDirectory)).filter(n => n.startsWith('ledger-')).sort();
  return Promise.all(files.map(n => readFile(join(session.privateDirectory, n), 'utf8').then(JSON.parse)));
}

/** Only lifecycle/API/SQL models. The session creates a real new loopback
 * issuer, but no HTTP fixture, Docker/VM, Pol.is, SQL server or retained state.
 * Captured private metadata is test-local and never aggregate/runtime proof. */
async function fixture(t, hooks = {}) {
  const model = { events: [], requests: [], seeds: [], queries: [], closes: [], running: false };
  let session;
  const lifecycle = async request => {
    await verifyBootstrapOwnedSessionRequest(request);
    model.requests.push(request); model.events.push('lifecycle:' + request.operation);
    assert.equal(Object.isFrozen(request), true); assert.equal(Object.isFrozen(request.payload), true);
    if (hooks.lifecycleBefore) { const v = await hooks.lifecycleBefore(request, model, session); if (v !== undefined) return v; }
    let result;
    if (request.operation === 'create') {
      model.create = request.payload; model.running = true;
      const { sessionId, helperName, databaseName, databaseUser, issuer } = request.payload;
      assert.match(request.payload.databasePassword, /^[a-f0-9]{64}$/u);
      model.resource = { sessionId, helperName, helperId: ID, databaseId: DATABASE_ID, databaseName, databaseUser,
        imageId: IMAGE, apiOrigin: 'https://127.0.0.1:34117', apiCertificatePem: issuer.certificatePem,
        databasePort: 54117, databaseCertificatePem: issuer.certificatePem, os: 'linux', architecture: 'arm64',
        running: true, ordinary: true, loopbackOnly: true, egressVerified: true, schemaReady: true };
      result = { ...model.resource };
    } else if (request.operation === 'inspect' || request.operation === 'inspect-closed') {
      assert.deepEqual(request.payload, { helperId: ID, databaseId: DATABASE_ID });
      result = { ...model.resource, running: model.running };
    } else if (request.operation === 'stop') {
      assert.deepEqual(request.payload, { helperId: ID, databaseId: DATABASE_ID });
      model.closes.push('helper'); model.running = false; result = { helperId: ID, running: false };
    } else assert.fail('Unknown model lifecycle operation');
    return hooks.lifecycleAfter ? await hooks.lifecycleAfter(request, result, model, session) ?? result : result;
  };
  const databaseFactory = async options => {
    model.databaseOptions = options;
    if (hooks.databaseFactory) return hooks.databaseFactory(options, model, session);
    const lease = Object.freeze({ port: options.port, database: options.database, user: options.user, certificateSha256: pin(options.certificatePem) });
    return Object.freeze({
      async execute(query, { signal }) {
        assert.equal(signal.aborted, false); model.queries.push(query); model.events.push('db:' + query.name);
        await options.assertOwned(lease);
        if (hooks.databaseBefore) { const v = await hooks.databaseBefore(query, model, session); if (v !== undefined) return v; }
        let result;
        if (query.name === 'fncp-bootstrap-schema-v1') result = validateBootstrapSchemaResult(query, schemaRows());
        else { assert.deepEqual(query.values, [CONVERSATION, TIDS, PID]); result = validateBootstrapBaselineResult(query, baselineRows()); }
        await options.assertOwned(lease);
        return hooks.databaseAfter ? await hooks.databaseAfter(query, result, model, session) ?? result : result;
      },
      async close() { model.closes.push('database'); if (hooks.databaseClose) await hooks.databaseClose(); },
      summary() { return Object.freeze({ mode: 'INJECTED_DATABASE_MODEL' }); },
    });
  };
  const transportFactory = async options => {
    model.transportOptions = options;
    if (hooks.transportFactory) return hooks.transportFactory(options, model, session);
    const lease = Object.freeze({ origin: options.origin, certificateSha256: pin(options.certificatePem) });
    return Object.freeze({
      async send(request) {
        await verifyBootstrapProtocolRequest(request); model.events.push('http:' + request.operation);
        await options.assertOwned(lease);
        if (hooks.httpBefore) { const v = await hooks.httpBefore(request, model, session); if (v !== undefined) return v; }
        let response;
        switch (request.operation) {
          case 'create-conversation': response = api({ conversation_id: CONVERSATION }); break;
          case 'create-seed': model.seeds.push(request.payload); response = api({ tid: TIDS[model.seeds.length - 1], currentPid: PID }); break;
          case 'read-seeds': response = api(model.seeds.map((s, i) => ({ tid: TIDS[i], conversation_id: CONVERSATION,
            txt: s.txt, pid: PID, is_seed: true, mod: 1, active: true, agree_count: 0, disagree_count: 0, pass_count: 1, count: 1 })).reverse()); break;
          case 'close-conversation': response = api({ conversation_id: CONVERSATION }); break;
          case 'read-conversation': response = api({ conversation_id: CONVERSATION, is_owner: true, is_active: false,
            use_xid_whitelist: true, xid_required: true, is_data_open: false, strict_moderation: true,
            is_anon: true, is_draft: false, topics_enabled: false, treevite_enabled: false, profanity_filter: false, spam_filter: false }); break;
          default: assert.fail('Unknown model HTTP operation');
        }
        await options.assertOwned(lease);
        return hooks.httpAfter ? await hooks.httpAfter(request, response, model, session) ?? response : response;
      },
      close() { model.closes.push('transport'); if (hooks.transportClose) hooks.transportClose(); },
      summary() { return Object.freeze({ mode: 'INJECTED_HTTP_MODEL' }); },
    });
  };
  session = await createBootstrapOwnedSession({ lifecycle, databaseFactory, transportFactory });
  t.after(async () => {
    await session.close().catch(() => {});
    for (const directory of session.evidenceDirectories()) await rm(directory, { recursive: true, force: true });
  });
  return { session, model };
}

test('factory exact-input rejection never evaluates accessors, proxies or adoption inputs', async () => {
  let reads = 0;
  for (const input of [undefined, null, {}, { lifecycle() {}, path: '/tmp/retained' }, { get lifecycle() { reads++; } },
    new Proxy({}, { ownKeys() { reads++; } }), { lifecycle: new Proxy(() => {}, {}) }, { lifecycle() {}, databaseFactory: undefined }]) {
    await assert.rejects(createBootstrapOwnedSession(input), ERROR);
  }
  await assert.rejects(createBootstrapOwnedSession(), ERROR);
  await assert.rejects(createBootstrapOwnedSession({ lifecycle() {} }, null), ERROR); assert.equal(reads, 0);
});

test('factory owns independent private directories and random names without calling lifecycle or opening an issuer', async t => {
  const a = await fixture(t), b = await fixture(t);
  assert.notEqual(a.session.privateDirectory, b.session.privateDirectory);
  const snapshots = [];
  for (const f of [a, b]) {
    assert.equal((await lstat(f.session.privateDirectory)).mode & 0o777, 0o700);
    assert.deepEqual(await readdir(f.session.privateDirectory), ['ownership.json']);
    assert.equal((await lstat(join(f.session.privateDirectory, 'ownership.json'))).mode & 0o777, 0o600);
    const owned = JSON.parse(await readFile(join(f.session.privateDirectory, 'ownership.json'), 'utf8')); snapshots.push(owned);
    assert.match(owned.databaseName, /^fncp_fresh_[a-f0-9]{24}$/u); assert.match(owned.databaseUser, /^fncp_fresh_[a-f0-9]{24}$/u);
    assert.notEqual(owned.databaseName, owned.databaseUser); assert.equal('password' in owned, false);
    assert.equal(await f.session.verifyIntegrity(), true); assert.deepEqual(f.model.events, []); assert.equal(f.session.summary().issuerClosed, false);
  }
  for (const key of ['sessionId', 'helperName', 'databaseName', 'databaseUser']) assert.notEqual(snapshots[0][key], snapshots[1][key]);
});

test('active lifecycle capabilities reject copies, extras, proxies and post-callback replay', async t => {
  let saved;
  const { session } = await fixture(t, { async lifecycleBefore(request) {
    saved = request; await verifyBootstrapOwnedSessionRequest(request);
    await assert.rejects(verifyBootstrapOwnedSessionRequest({ ...request }), ERROR);
    await assert.rejects(verifyBootstrapOwnedSessionRequest(request, undefined), ERROR);
  } });
  await assert.rejects(verifyBootstrapOwnedSessionRequest({ operation: 'create' }), ERROR);
  await assert.rejects(verifyBootstrapOwnedSessionRequest(new Proxy({}, {})), ERROR);
  await session.run(); await assert.rejects(verifyBootstrapOwnedSessionRequest(saved), ERROR);
});

test('single composition orders schema, source-derived HTTP, raw/latest baseline, exact stop and independent closures', async t => {
  const { session, model } = await fixture(t, { async lifecycleBefore(request, m, s) {
    const entries = await journal(s); assert.equal(entries[0].event, 'SESSION_ATTEMPTED_BEFORE_ANY_CALLBACK');
    if (request.operation === 'create') assert.equal(entries.at(-1).event, 'FRESH_HELPER_CREATION_ATTEMPTED');
    if (request.operation === 'stop') assert.equal(entries.at(-1).event, 'EXACT_HELPER_STOP_ATTEMPTED');
  } });
  const result = await session.run();
  assert.deepEqual(result, { binding: { conversationId: CONVERSATION, statementIds: TIDS }, evidence: 'INJECTED_LIFECYCLE_COMPOSITION',
    rawSeedOwnerPassVotes: 15, latestUniqueSeedOwnerPassVotes: 15, actualRuntime: 'NOT_RUN', activationGranted: false, roundOpen: false });
  assert.equal(Object.isFrozen(result.binding.statementIds), true);
  assert.equal(model.events.filter(e => e.startsWith('http:')).length, 19);
  assert.ok(model.events.indexOf('db:fncp-bootstrap-schema-v1') < model.events.indexOf('http:create-conversation'));
  assert.ok(model.events.indexOf('http:read-conversation') < model.events.indexOf('db:fncp-bootstrap-baseline-v1'));
  assert.ok(model.events.indexOf('db:fncp-bootstrap-baseline-v1') < model.events.indexOf('lifecycle:stop'));
  assert.deepEqual([...model.closes].sort(), ['database', 'helper', 'transport']);
  const summary = session.summary(); assert.equal(summary.completed, true); assert.equal(summary.issuerClosed, true);
  assert.equal(summary.closedRawAndLatestBaselineAccepted, true); assert.equal(summary.independentlyVerifiedDockerOwnership, false);
  assert.equal(summary.actualPolisBootstrapVerified, false); assert.equal(summary.activationGranted, false);
  assert.equal(summary.ordinaryImageApproval, 'NOT_ESTABLISHED');
  const text = JSON.stringify(summary);
  for (const privateValue of [CONVERSATION, ID, model.create.databasePassword, model.create.databaseName, model.resource.apiOrigin]) assert.equal(text.includes(privateValue), false);
  assert.equal(await session.verifyIntegrity(), true);
  await assert.rejects(session.run(), ERROR); await session.close(); await session.close();
  assert.deepEqual([...model.closes].sort(), ['database', 'helper', 'transport']);
});

test('transport and database ownership callbacks require the active operation and exact private lease', async t => {
  const { session, model } = await fixture(t); await session.run();
  const databaseLease = { port: model.resource.databasePort, database: model.create.databaseName, user: model.create.databaseUser,
    certificateSha256: pin(model.resource.databaseCertificatePem) };
  await assert.rejects(model.databaseOptions.assertOwned(databaseLease), ERROR);
  await assert.rejects(model.transportOptions.assertOwned({ origin: model.resource.apiOrigin, certificateSha256: pin(model.resource.apiCertificatePem) }), ERROR);
});

test('pre-run cancellation makes no creation attempt and never dispatches a callback', async t => {
  const { session, model } = await fixture(t); session.cancel();
  await assert.rejects(session.run(), ERROR); await session.close(); assert.deepEqual(model.events, []);
  assert.equal(session.summary().creationOutcomeUnknown, false);
});

test('cancellation during initial journal denies listener and callback continuation', async t => {
  const { session, model } = await fixture(t); const run = session.run(); session.cancel();
  await assert.rejects(run, ERROR); assert.deepEqual(model.events, []); assert.equal(session.summary().completed, false);
});

test('late cancelled creation cannot be adopted or automatically stopped from a late returned ID', async t => {
  const reached = deferred(), release = deferred();
  const { session, model } = await fixture(t, { async lifecycleAfter(request, result) {
    if (request.operation === 'create') { reached.resolve(); await release.promise; } return result;
  } });
  const run = session.run(); await reached.promise; session.cancel(); release.resolve();
  await assert.rejects(run, ERROR); assert.equal(model.requests.filter(r => r.operation === 'create').length, 1);
  assert.equal(model.requests.some(r => r.operation === 'stop'), false);
  assert.equal(session.summary().creationOutcomeUnknown, true); assert.equal(session.summary().issuerClosed, true);
  await assert.rejects(session.close(), ERROR); await assert.rejects(session.run(), ERROR);
});

test('cancel/close during a pending HTTP callback prevents later seed mutation and waits for exact known-helper cleanup', async t => {
  const reached = deferred(), release = deferred();
  const { session, model } = await fixture(t, { async httpBefore(request) {
    if (request.operation === 'create-conversation') { reached.resolve(); await release.promise; }
  } });
  const run = session.run(); await reached.promise; const closing = session.close(); release.resolve();
  await assert.rejects(run, ERROR); await closing;
  assert.equal(model.seeds.length, 0); assert.equal(model.closes.filter(n => n === 'helper').length, 1);
  assert.equal(session.summary().issuerClosed, true); assert.equal(session.summary().completed, false);
});

test('catalog rejection prevents authenticated HTTP and still closes the exact known helper and database', async t => {
  const { session, model } = await fixture(t, { databaseAfter(query, result) {
    return query.name.includes('schema') ? { ...result, databaseReady: true } : result;
  } });
  await assert.rejects(session.run(), ERROR); assert.equal(model.events.some(e => e.startsWith('http:')), false);
  assert.deepEqual([...model.closes].sort(), ['database', 'helper']); assert.equal(session.summary().issuerClosed, true);
});

test('cancellation after a schema response but during final integrity checking cannot open transport', async t => {
  const { session, model } = await fixture(t, { databaseAfter(query, result, m, s) {
    if (query.name.includes('schema')) setImmediate(() => s.cancel()); return result;
  } });
  await assert.rejects(session.run(), ERROR); assert.equal(model.transportOptions, undefined);
  assert.equal(model.events.some(e => e.startsWith('http:')), false); assert.equal(session.summary().completed, false);
  assert.equal(session.summary().issuerClosed, true);
});

test('closed raw-vote baseline rejection does not suppress helper or independent transport/database/issuer closure', async t => {
  const { session, model } = await fixture(t, { databaseAfter(query, result) {
    return query.name.includes('baseline') ? { ...result, rawVoteHistoryRows: 16 } : result;
  } });
  await assert.rejects(session.run(), ERROR); assert.deepEqual([...model.closes].sort(), ['database', 'helper', 'transport']);
  assert.equal(session.summary().helperClosure, 'INJECTED_EXACT_ID_READBACK_ACCEPTED');
  assert.equal(session.summary().closedRawAndLatestBaselineAccepted, false); assert.equal(session.summary().completed, false);
});

test('uncertain helper stop is never repeated or claimed closed', async t => {
  const { session, model } = await fixture(t, { lifecycleAfter(request, result) { if (request.operation === 'stop') throw Error('private failure'); return result; } });
  await assert.rejects(session.run(), ERROR); await assert.rejects(session.close(), ERROR);
  assert.equal(model.requests.filter(r => r.operation === 'stop').length, 1);
  assert.equal(session.summary().stopOutcomeUnknown, true); assert.equal(session.summary().issuerClosed, true);
});

test('independent close failure attempts every remaining component and cannot turn into later successful cleanup', async t => {
  const { session, model } = await fixture(t, { transportClose() { throw Error('private close'); } });
  await assert.rejects(session.run(), ERROR); await assert.rejects(session.close(), ERROR);
  assert.deepEqual([...model.closes].sort(), ['database', 'helper', 'transport']); assert.equal(session.summary().issuerClosed, true);
  assert.equal(session.summary().transportClosed, false); assert.equal(session.summary().completed, false);
});

test('read-only identity drift prevents further HTTP and prevents unsafe stop/adoption', async t => {
  const { session, model } = await fixture(t, { lifecycleAfter(request, result) {
    return request.operation === 'inspect' ? { ...result, helperId: '9'.repeat(64) } : result;
  } });
  await assert.rejects(session.run(), ERROR); assert.equal(model.requests.some(r => r.operation === 'stop'), false);
  assert.equal(model.events.some(e => e.startsWith('http:')), false); assert.equal(session.summary().issuerClosed, true);
});

test('caller-selected names, dedicated image and asserted false readiness are rejected without ID adoption', async t => {
  for (const alteration of [{ databaseName: 'fncp_fresh_' + '0'.repeat(24) }, { helperName: 'retained-helper' },
    { imageId: 'sha256:07f8a21105ed90963ccdf0981d884323116187583a464bb581db14c621d33a98' },
    { schemaReady: false }, { egressVerified: false }, { apiOrigin: 'https://localhost:34117' }, { databasePort: 0 }]) {
    const { session, model } = await fixture(t, { lifecycleAfter(request, result) { return request.operation === 'create' ? { ...result, ...alteration } : result; } });
    await assert.rejects(session.run(), ERROR); assert.equal(model.queries.length, 0);
    assert.equal(session.summary().creationOutcomeUnknown, true); assert.equal(session.summary().issuerClosed, true);
  }
});

test('malformed factory capabilities never evaluate getters during validation or cleanup', async t => {
  let getters = 0;
  const { session, model } = await fixture(t, { databaseFactory() { return { execute() {}, get close() { getters++; }, summary() {} }; } });
  await assert.rejects(session.run(), ERROR); assert.equal(getters, 0);
  assert.deepEqual(model.closes, ['helper']); assert.equal(session.summary().issuerClosed, true);
});

test('unsafe seed identifiers or changing creator PID deny baseline publication but still stop the helper', async t => {
  for (const bad of [{ tid: -1, currentPid: PID }, { tid: 44, currentPid: PID + 1 }]) {
    const { session, model } = await fixture(t, { httpAfter(request, response, m) {
      if (request.operation === 'create-seed' && m.seeds.length === 2) return api(bad); return response;
    } });
    await assert.rejects(session.run(), ERROR); assert.equal(model.queries.length, 1);
    assert.equal(model.closes.filter(n => n === 'helper').length, 1);
  }
});

test('ambiguous or BOM-normalized HTTP creation data is never accepted', async t => {
  for (const body of ['{"conversation_id":"9OwnedSessionSynthetic","conversation_id":"9OwnedSessionSynthetic"}', '\ufeff{"conversation_id":"9OwnedSessionSynthetic"}']) {
    const { session, model } = await fixture(t, { httpAfter(request, response) {
      return request.operation === 'create-conversation' ? { status: 200, body } : response;
    } });
    await assert.rejects(session.run(), ERROR); assert.equal(model.seeds.length, 0); assert.equal(model.closes.includes('helper'), true);
  }
});

test('closed readback mismatch suppresses database baseline and binding completion', async t => {
  const { session, model } = await fixture(t, { httpAfter(request, response) {
    return request.operation === 'read-conversation' ? api({ ...JSON.parse(response.body), is_active: true }) : response;
  } });
  await assert.rejects(session.run(), ERROR); assert.equal(model.queries.length, 1); assert.equal(session.summary().completed, false);
});

test('private ledger byte, mode and unexpected-file tampering reject before any callback', async t => {
  for (const mode of ['bytes', 'mode', 'extra']) {
    const { session, model } = await fixture(t); const ownership = join(session.privateDirectory, 'ownership.json');
    if (mode === 'bytes') await writeFile(ownership, '{}\n');
    if (mode === 'mode') await chmod(ownership, 0o644);
    if (mode === 'extra') await writeFile(join(session.privateDirectory, 'unexpected'), 'synthetic');
    await assert.rejects(session.run(), ERROR); assert.deepEqual(model.events, []);
    await assert.rejects(session.verifyIntegrity(), ERROR);
  }
});

test('public methods reject extra arguments without cancelling a fresh capability', async t => {
  const { session, model } = await fixture(t);
  assert.throws(() => session.summary(null), ERROR); assert.throws(() => session.cancel(null), ERROR);
  assert.throws(() => session.evidenceDirectories(null), ERROR);
  await assert.rejects(session.verifyIntegrity(null), ERROR); await assert.rejects(session.close(null), ERROR);
  await assert.rejects(session.run(null), ERROR); assert.equal(session.summary().cancelled, false);
  assert.deepEqual(model.events, []);
});

test('cancel closes the real issuer while creation remains pending without adopting or stopping a late helper', async t => {
  const reached = deferred(), release = deferred(); t.after(() => release.resolve()); let saved;
  const { session, model } = await fixture(t, { async lifecycleAfter(request, result) {
    if (request.operation === 'create') { saved = request; reached.resolve(); await release.promise; } return result;
  } });
  const run = assert.rejects(session.run(), ERROR); await reached.promise; session.cancel();
  let closeSettled = false;
  const closing = assert.rejects(session.close(), ERROR).then(() => { closeSettled = true; });
  await eventually(() => session.summary().issuerClosed); await issuerListenerClosed(model);
  assert.equal(closeSettled, false); assert.equal(session.summary().creationOutcomeUnknown, true);
  assert.equal(session.summary().helperClosure, 'NOT_VERIFIED'); assert.equal(session.summary().databaseExecutorClosed, false);
  await assert.rejects(verifyBootstrapOwnedSessionRequest(saved), ERROR);
  assert.equal(model.requests.some(request => request.operation === 'stop'), false);
  release.resolve(); await run; await closing;
  assert.equal(session.summary().completed, false); assert.equal(model.requests.some(request => request.operation === 'stop'), false);
  await assert.rejects(session.run(), ERROR);
});

test('close promptly shuts local components while an active lifecycle inspection is pending and denies late HTTP authority', async t => {
  const reached = deferred(), release = deferred(); t.after(() => release.resolve()); let held = false; let saved;
  const { session, model } = await fixture(t, { async lifecycleBefore(request, m) {
    if (!held && request.operation === 'inspect' && m.events.includes('http:create-conversation')) {
      held = true; saved = request; reached.resolve(); await release.promise;
    }
  } });
  const run = assert.rejects(session.run(), ERROR); await reached.promise;
  let settled = false; const closing = session.close().then(() => { settled = true; });
  await eventually(() => allLocalClosed(session)); await issuerListenerClosed(model);
  assert.equal(settled, false); assert.equal(model.running, true); assert.equal(session.summary().helperClosure, 'NOT_VERIFIED');
  await assert.rejects(verifyBootstrapOwnedSessionRequest(saved), ERROR);
  release.resolve(); await run; await closing;
  assert.equal(model.seeds.length, 0); assert.equal(session.summary().completed, false);
  assert.deepEqual([...model.closes].sort(), ['database', 'helper', 'transport']);
});

test('a held exact helper stop cannot delay local closure or become a successful close before acknowledgement', async t => {
  const reached = deferred(), release = deferred(); t.after(() => release.resolve());
  const { session, model } = await fixture(t, { async lifecycleBefore(request) {
    if (request.operation === 'stop') { reached.resolve(); await release.promise; }
  } });
  const run = assert.rejects(session.run(), ERROR); await reached.promise;
  await eventually(() => allLocalClosed(session)); await issuerListenerClosed(model);
  assert.equal(model.running, true); assert.equal(session.summary().helperClosure, 'NOT_VERIFIED');
  assert.equal(session.summary().stopOutcomeUnknown, true); assert.equal(session.summary().completed, false);
  let settled = 0; const a = session.close().then(() => { settled++; }); const b = session.close().then(() => { settled++; });
  await new Promise(resolve => setImmediate(resolve)); assert.equal(settled, 0);
  assert.equal(model.requests.filter(request => request.operation === 'stop').length, 1);
  release.resolve(); await run; await Promise.all([a, b]); assert.equal(settled, 2);
  assert.deepEqual([...model.closes].sort(), ['database', 'helper', 'transport']);
  assert.equal(session.summary().helperClosure, 'INJECTED_EXACT_ID_READBACK_ACCEPTED');
  assert.equal(session.summary().completed, false);
});

test('failure starts independent local closure even while the subsequent trusted helper stop remains pending', async t => {
  const reached = deferred(), release = deferred(); t.after(() => release.resolve());
  const { session, model } = await fixture(t, {
    httpBefore(request) { if (request.operation === 'create-conversation') throw new Error('Synthetic API failure.'); },
    async lifecycleBefore(request) { if (request.operation === 'stop') { reached.resolve(); await release.promise; } },
  });
  const run = assert.rejects(session.run(), ERROR); await reached.promise;
  // No caller close/cancel has been needed to close the real issuer and clients.
  await eventually(() => allLocalClosed(session)); await issuerListenerClosed(model);
  assert.equal(session.summary().helperClosure, 'NOT_VERIFIED'); assert.equal(session.summary().completed, false);
  release.resolve(); await run; await session.close();
  assert.equal(model.seeds.length, 0); assert.deepEqual([...model.closes].sort(), ['database', 'helper', 'transport']);
});

test('a pending local close is shared across cancel, close and run-finally without a premature acknowledgement or duplicate call', async t => {
  const reached = deferred(), release = deferred(); t.after(() => release.resolve());
  const { session, model } = await fixture(t, { async databaseClose() { reached.resolve(); await release.promise; } });
  const run = assert.rejects(session.run(), ERROR); await reached.promise;
  session.cancel(); let settled = false; const closing = session.close().then(() => { settled = true; });
  await eventually(() => session.summary().issuerClosed && session.summary().transportClosed); await issuerListenerClosed(model);
  assert.equal(session.summary().databaseExecutorClosed, false); assert.equal(settled, false);
  assert.equal(model.closes.filter(name => name === 'database').length, 1);
  release.resolve(); await run; await closing;
  assert.equal(session.summary().databaseExecutorClosed, true);
  assert.deepEqual([...model.closes].sort(), ['database', 'helper', 'transport']);
});

test('a local close that rejects after being shared is never retried or later reported as acknowledged', async t => {
  const reached = deferred(), release = deferred(); t.after(() => release.resolve());
  const { session, model } = await fixture(t, { async databaseClose() {
    reached.resolve(); await release.promise; throw new Error('Synthetic uncertain close.');
  } });
  const run = assert.rejects(session.run(), ERROR); await reached.promise;
  const closing = assert.rejects(session.close(), ERROR); session.cancel();
  await eventually(() => session.summary().issuerClosed && session.summary().transportClosed);
  assert.equal(session.summary().databaseExecutorClosed, false); release.resolve(); await run; await closing;
  await assert.rejects(session.close(), ERROR);
  assert.equal(model.closes.filter(name => name === 'database').length, 1);
  assert.equal(session.summary().databaseExecutorClosed, false); assert.equal(session.summary().completed, false);
});

test('remembered local close failure does not suppress a permitted read-only helper closure retry', async t => {
  let inspections = 0;
  const { session, model } = await fixture(t, {
    transportClose() { throw new Error('Synthetic uncertain client close.'); },
    lifecycleAfter(request, result) {
      if (request.operation === 'inspect-closed' && ++inspections <= 2) throw new Error('Synthetic readback interruption.');
      return result;
    },
  });
  await assert.rejects(session.run(), ERROR); assert.equal(inspections, 2);
  assert.equal(session.summary().helperClosure, 'NOT_VERIFIED');
  await assert.rejects(session.close(), ERROR); assert.equal(inspections, 3);
  assert.equal(session.summary().helperClosure, 'INJECTED_EXACT_ID_READBACK_ACCEPTED');
  assert.equal(session.summary().transportClosed, false); assert.equal(session.summary().completed, false);
  assert.equal(model.requests.filter(request => request.operation === 'stop').length, 1);
  assert.equal(model.closes.filter(name => name === 'transport').length, 1);
});

for (const component of ['database', 'transport']) {
  test(`a late-created ${component} capability is closed by run-finally after an earlier local shutdown pass`, async t => {
    const reached = deferred(), release = deferred(); t.after(() => release.resolve());
    const hooks = { [`${component}Factory`]: async (options, model) => {
      reached.resolve(); await release.promise;
      const invoke = () => { throw new Error('Late capability cannot perform work.'); };
      return Object.freeze({ [component === 'database' ? 'execute' : 'send']: invoke,
        close() { model.closes.push(component); }, summary() { return Object.freeze({ mode: 'LATE_SYNTHETIC_CAPABILITY' }); } });
    } };
    const { session, model } = await fixture(t, hooks); const run = assert.rejects(session.run(), ERROR); await reached.promise;
    const closing = session.close(); await eventually(() => session.summary().issuerClosed); await issuerListenerClosed(model);
    assert.equal(session.summary()[component === 'database' ? 'databaseExecutorClosed' : 'transportClosed'], false);
    release.resolve(); await run; await closing;
    assert.equal(model.closes.filter(name => name === component).length, 1);
    assert.equal(session.summary()[component === 'database' ? 'databaseExecutorClosed' : 'transportClosed'], true);
    assert.equal(session.summary().completed, false); assert.equal(model.seeds.length, 0);
    assert.equal(model.requests.filter(request => request.operation === 'stop').length, 1);
  });
}
