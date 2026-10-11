import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, readdir, rm, lstat, unlink, rename, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import * as protocol from './bootstrap-protocol.mjs';

const FAILURE = /Fresh bootstrap protocol failed; private evidence preserved and replay denied\./u;
const HELPER = 'a'.repeat(64);
const IMAGE = 'sha256:' + 'd'.repeat(64); // Invented model subject, not an approved runtime image.
const DEDICATED = 'sha256:07f8a21105ed90963ccdf0981d884323116187583a464bb581db14c621d33a98';
const CONVERSATION = '3SyntheticBootstrap';
const PID = 37;
const TIDS = [103, 7, 219, 48, 301, 76, 519, 1024, 614, 913, 1217, 1901, 2013, 111, 3077];
const api = body => ({ status: 200, body: JSON.stringify(body) });
const clone = value => JSON.parse(JSON.stringify(value));
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { resolve, promise }; };
const fixedSeeds = JSON.parse(await readFile(new URL('../seed-statements.json', import.meta.url), 'utf8'));

/** Entirely in-memory ordinary-helper/API model. Request verifications exercise
 * the real protocol's active brand, not a lookalike or bypassed verifier. */
function modelDriver(hooks = {}, verifier = protocol.verifyBootstrapProtocolRequest) {
  const state = { calls: [], seedPayloads: [], helperClosed: false, conversations: 0 };
  async function driver(request) {
    await verifier(request);
    assert.equal(Object.isFrozen(request), true); assert.equal(Object.isFrozen(request.payload), true);
    state.calls.push(request);
    if (hooks.before) { const override = await hooks.before(request, state); if (override !== undefined) return override; }
    const { operation, payload } = request; let output;
    switch (operation) {
      case 'inspect-helper':
        assert.deepEqual(payload, {});
        output = { id: HELPER, imageId: IMAGE, os: 'linux', architecture: 'arm64', ordinary: true, owned: true,
          loopbackOnly: true, egressVerified: true, schemaReady: true, running: true }; break;
      case 'create-conversation':
        state.conversations++; assert.equal(payload.is_active, true); assert.equal(payload.is_anon, true);
        assert.equal(payload.is_draft, false); assert.equal(payload.is_data_open, false); assert.equal(payload.strict_moderation, true);
        assert.equal(payload.spam_filter, false); assert.equal(payload.profanity_filter, false);
        output = api({ conversation_id: CONVERSATION, extra_api_field: 'synthetic' }); break;
      case 'create-seed': {
        const index = state.seedPayloads.length; assert.deepEqual(payload, { conversation_id: CONVERSATION, txt: fixedSeeds[index], is_seed: true });
        state.seedPayloads.push(payload); output = api({ tid: TIDS[index], currentPid: PID, extra_api_field: false }); break;
      }
      case 'read-seeds':
        assert.deepEqual(payload, { conversationId: CONVERSATION });
        output = api(state.seedPayloads.map((item, index) => ({ tid: TIDS[index], conversation_id: CONVERSATION, txt: item.txt, is_seed: true, pid: PID,
          mod: 1, active: true, agree_count: 0, disagree_count: 0, pass_count: 1, count: 1, extra_api_field: 'synthetic' })).reverse()); break;
      case 'close-conversation':
        assert.deepEqual(payload, { conversation_id: CONVERSATION, is_active: false, use_xid_whitelist: true, xid_required: true, send_created_email: false });
        output = api({ conversation_id: CONVERSATION }); break;
      case 'read-conversation':
        assert.deepEqual(payload, { conversationId: CONVERSATION });
        output = api({ conversation_id: CONVERSATION, is_owner: true, is_active: false, use_xid_whitelist: true, xid_required: true,
          is_data_open: false, strict_moderation: true, is_anon: true, is_draft: false, topics_enabled: false,
          treevite_enabled: false, profanity_filter: false, spam_filter: false, extra_api_field: 1 }); break;
      case 'close-helper':
        assert.equal(payload.id, HELPER); state.helperClosed = true;
        output = { id: HELPER, running: false }; break;
      case 'inspect-closed':
        assert.deepEqual(payload, { id: HELPER }); assert.equal(state.helperClosed, true);
        output = { id: HELPER, running: false }; break;
      default: assert.fail('Unexpected bootstrap model operation');
    }
    return hooks.after ? await hooks.after(request, output, state) ?? output : output;
  }
  return { driver, state, operations: () => state.calls.map(request => request.operation) };
}

async function fresh(t, hooks = {}, module = protocol) {
  const model = modelDriver(hooks, module.verifyBootstrapProtocolRequest);
  const instance = await module.createBootstrapProtocol({ driver: model.driver });
  // Only this test's new private evidence directory exists; the driver has no
  // runtime/network/filesystem implementation and has created no helper process.
  t.after(() => rm(instance.privateDirectory, { recursive: true, force: true }));
  return { instance, model };
}
async function journal(instance) {
  const names = (await readdir(instance.privateDirectory)).filter(name => name.startsWith('ledger-')).sort();
  return Promise.all(names.map(name => readFile(join(instance.privateDirectory, name), 'utf8').then(JSON.parse)));
}
async function isolatedSource(t) {
  const directory = await mkdtemp(join(tmpdir(), 'fncp-bootstrap-protocol-source-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const runtime = join(directory, 'fresh-runtime'); await mkdir(runtime);
  await writeFile(join(runtime, 'bootstrap-protocol.mjs'), await readFile(new URL('./bootstrap-protocol.mjs', import.meta.url)), { flag: 'wx' });
  await writeFile(join(directory, 'fresh-bootstrap-result.mjs'), await readFile(new URL('../fresh-bootstrap-result.mjs', import.meta.url)), { flag: 'wx' });
  const seedPath = join(directory, 'seed-statements.json');
  await writeFile(seedPath, await readFile(new URL('../seed-statements.json', import.meta.url)), { flag: 'wx' });
  return { module: await import(pathToFileURL(join(runtime, 'bootstrap-protocol.mjs')).href), seedPath };
}

test('bootstrap factory rejects adoption, missing/extra arguments, accessors and proxy callbacks without evaluating them', async () => {
  let reads = 0;
  for (const options of [undefined, null, {}, { driver: async () => {}, directory: '/tmp/retained' },
    { get driver() { reads++; } }, { driver: new Proxy(() => {}, {}) }, new Proxy({}, { get() { reads++; } })]) {
    await assert.rejects(protocol.createBootstrapProtocol(options), FAILURE);
  }
  await assert.rejects(protocol.createBootstrapProtocol(), FAILURE);
  await assert.rejects(protocol.createBootstrapProtocol({ driver() {} }, undefined), FAILURE);
  assert.equal(reads, 0);
});

test('private bootstrap evidence is exclusively created and does not cause a driver call before run', async t => {
  const a = await fresh(t); const b = await fresh(t); assert.notEqual(a.instance.privateDirectory, b.instance.privateDirectory);
  for (const { instance, model } of [a, b]) {
    assert.equal((await lstat(instance.privateDirectory)).mode & 0o777, 0o700);
    assert.deepEqual(await readdir(instance.privateDirectory), ['ownership.json']);
    assert.equal((await lstat(join(instance.privateDirectory, 'ownership.json'))).mode & 0o777, 0o600);
    assert.equal(await instance.verifyIntegrity(), true); assert.deepEqual(model.operations(), []);
  }
});

test('HTTP authority has stable private lineage per protocol and cannot be copied or used after callback', async t => {
  let scope; let saved; let signal;
  const a = await fresh(t, { async before(request) {
    if (['close-helper', 'inspect-closed'].includes(request.operation)) {
      await assert.rejects(protocol.bootstrapHttpAuthority(request), FAILURE); return;
    }
    const authority = await protocol.bootstrapHttpAuthority(request);
    assert.equal(Object.isFrozen(authority), true); assert.equal(Object.isFrozen(authority.scope), true);
    assert.deepEqual(Object.keys(authority), ['scope', 'signal']);
    if (scope) assert.equal(authority.scope, scope);
    scope = authority.scope; signal = authority.signal; saved = request;
    assert.equal(signal.aborted, false);
    await assert.rejects(protocol.bootstrapHttpAuthority({ ...request }), FAILURE);
    await assert.rejects(protocol.bootstrapHttpAuthority(request, undefined), FAILURE);
  } });
  await a.instance.run(); await assert.rejects(protocol.bootstrapHttpAuthority(saved), FAILURE);
  const b = await fresh(t, { async before(request) {
    if (request.operation === 'inspect-helper') assert.notEqual((await protocol.bootstrapHttpAuthority(request)).scope, scope);
  } });
  await b.instance.run(); a.instance.cancel(); assert.equal(signal.aborted, true);
});

test('protocol cancellation synchronously aborts a handed-off HTTP authority and still permits known helper cleanup', async t => {
  let f; let observed = false;
  f = await fresh(t, { async before(request) {
    if (request.operation !== 'create-conversation') return;
    const { signal } = await protocol.bootstrapHttpAuthority(request);
    signal.addEventListener('abort', () => { observed = true; }, { once: true });
    f.instance.cancel(); assert.equal(observed, true); assert.equal(signal.aborted, true);
    await assert.rejects(protocol.bootstrapHttpAuthority(request), FAILURE);
  } });
  await assert.rejects(f.instance.run(), FAILURE); assert.equal(f.model.state.helperClosed, true);
});

test('only active frozen requests verify; copied, forged, extra-argument and later replay requests fail', async t => {
  let saved;
  const f = await fresh(t, { async before(request) {
    saved = request; await protocol.verifyBootstrapProtocolRequest(request);
    await assert.rejects(protocol.verifyBootstrapProtocolRequest({ ...request }), FAILURE);
    await assert.rejects(protocol.verifyBootstrapProtocolRequest(request, undefined), FAILURE);
  } });
  await assert.rejects(protocol.verifyBootstrapProtocolRequest({ operation: 'inspect-helper', payload: {} }), FAILURE);
  await f.instance.run(); await assert.rejects(protocol.verifyBootstrapProtocolRequest(saved), FAILURE);
});

test('fixed HTTP mapping accepts only live HTTP-operation requests and exposes no origin, token or sending capability', async t => {
  const mapped = new Map(); let saved;
  const f = await fresh(t, { async before(request) {
    const expectedMethod = { 'create-conversation': 'POST', 'create-seed': 'POST', 'read-seeds': 'GET', 'close-conversation': 'PUT', 'read-conversation': 'GET' }[request.operation];
    await assert.rejects(protocol.httpRequestForBootstrap({ ...request }), FAILURE);
    await assert.rejects(protocol.httpRequestForBootstrap(request, undefined), FAILURE);
    if (!expectedMethod) { await assert.rejects(protocol.httpRequestForBootstrap(request), FAILURE); return; }
    saved = request; const value = await protocol.httpRequestForBootstrap(request); mapped.set(request.operation, value);
    assert.equal(Object.isFrozen(value), true); assert.equal(Object.isFrozen(value.headers), true);
    assert.deepEqual(Object.keys(value).sort(), ['body', 'headers', 'method', 'path']);
    assert.equal(value.method, expectedMethod);
    assert.deepEqual(value.headers, { accept: 'application/json', 'content-type': 'application/json', 'x-forwarded-proto': 'https' });
    const base = request.operation.includes('seed') ? '/api/v3/comments' : '/api/v3/conversations';
    if (expectedMethod === 'GET') {
      const query = '?conversation_id=' + CONVERSATION + (request.operation === 'read-seeds' ? '&moderation=true&include_voting_patterns=true' : '');
      assert.equal(value.path, base + query); assert.equal(value.body, null);
    } else { assert.equal(value.path, base); assert.equal(value.body, JSON.stringify(request.payload)); }
  } });
  await assert.rejects(protocol.httpRequestForBootstrap(), FAILURE); await f.instance.run();
  assert.equal(mapped.size, 5); await assert.rejects(protocol.httpRequestForBootstrap(saved), FAILURE);
});

test('one protocol run journals before callbacks and binds observed IDs only after exact readbacks and helper closure', async t => {
  const f = await fresh(t, { async before(request) {
    const events = await journal(f.instance); assert.ok(events.length > 0);
    assert.equal(events[0].event, 'BOOTSTRAP_ATTEMPTED_BEFORE_ANY_DRIVER_CALL');
    const preceding = { 'inspect-helper': 'BOOTSTRAP_ATTEMPTED_BEFORE_ANY_DRIVER_CALL', 'create-seed': 'SEED_MUTATION_ATTEMPTED',
      'close-conversation': 'CONVERSATION_CLOSE_AND_WHITELIST_ATTEMPTED', 'close-helper': 'HELPER_CLOSE_ATTEMPTED' }[request.operation];
    if (preceding) assert.equal(events.at(-1).event, preceding);
  } });
  const result = await f.instance.run();
  assert.deepEqual(result, { binding: { conversationId: CONVERSATION, statementIds: TIDS }, evidence: 'INJECTED_PROTOCOL_ONLY',
    latestUniqueSeedOwnerVotes: 15, rawVoteHistory: 'NOT_CHECKED', roundOpen: false, activationGranted: false });
  assert.equal(Object.isFrozen(result), true); assert.equal(Object.isFrozen(result.binding.statementIds), true);
  assert.deepEqual(f.model.operations(), ['inspect-helper', 'create-conversation', ...Array(15).fill('create-seed'),
    'read-seeds', 'close-conversation', 'read-conversation', 'close-helper', 'inspect-closed']);
  assert.equal(f.model.state.conversations, 1); assert.equal(f.instance.summary().completed, true);
  assert.equal(f.instance.summary().helperClosure, 'INJECTED_READBACK_ACCEPTED');
  assert.equal((await journal(f.instance)).at(-1).event, 'PROTOCOL_COMPLETE_INJECTED_READBACK_ONLY');
  const count = f.model.state.calls.length; await assert.rejects(f.instance.run(), FAILURE);
  await f.instance.close(); await f.instance.close(); assert.equal(f.model.state.calls.length, count);
});

test('all capability methods reject additional arguments without consuming a valid unstarted run', async t => {
  const f = await fresh(t);
  assert.throws(() => f.instance.summary(undefined), FAILURE); assert.throws(() => f.instance.cancel(undefined), FAILURE);
  await assert.rejects(f.instance.run(undefined), FAILURE); await assert.rejects(f.instance.close(undefined), FAILURE);
  await assert.rejects(f.instance.verifyIntegrity(undefined), FAILURE);
  assert.equal(f.instance.summary().attempted, false); assert.equal(f.instance.summary().cancelled, false);
  await f.instance.run();
});

test('ordinary helper checks reject dedicated image, wrong identity/architecture and missing safety attestations before API mutations', async t => {
  for (const mutate of [item => { item.id = 'invalid'; }, item => { item.imageId = DEDICATED; }, item => { item.architecture = 'amd64'; },
    item => { item.os = 'darwin'; }, ...['ordinary', 'owned', 'loopbackOnly', 'egressVerified', 'schemaReady', 'running'].map(key => item => { item[key] = false; })]) {
    const f = await fresh(t, { after(request, output) { if (request.operation === 'inspect-helper') mutate(output); return output; } });
    await assert.rejects(f.instance.run(), FAILURE);
    assert.deepEqual(f.model.operations(), ['inspect-helper']);
    assert.equal(f.instance.summary().completed, false); await assert.rejects(f.instance.close(), FAILURE);
  }
});

test('helper ID validation does not coerce an object or execute its toString', async t => {
  let coercions = 0;
  const f = await fresh(t, { after(request, output) {
    if (request.operation === 'inspect-helper') output.id = { toString() { coercions++; return HELPER; } }; return output;
  } });
  await assert.rejects(f.instance.run(), FAILURE); assert.equal(coercions, 0);
  assert.deepEqual(f.model.operations(), ['inspect-helper']);
});

test('unknown initial helper failure never dispatches identity-less cleanup or resumes inspection', async t => {
  const f = await fresh(t, { before(request) { if (request.operation === 'inspect-helper') throw new Error('PRIVATE_HELPER_ERROR'); } });
  await assert.rejects(f.instance.run(), FAILURE); assert.deepEqual(f.model.operations(), ['inspect-helper']);
  const count = f.model.state.calls.length;
  await assert.rejects(f.instance.run(), FAILURE); await assert.rejects(f.instance.close(), FAILURE);
  assert.equal(f.model.state.calls.length, count); assert.equal(f.instance.summary().helperClosure, 'NOT_VERIFIED');
});

test('status, body shape, duplicate JSON keys, malformed JSON and oversized responses fail closed before seed mutation', async t => {
  for (const output of [{ status: 201, body: JSON.stringify({ conversation_id: CONVERSATION }) }, { status: '200', body: '{}' },
    { status: 200, body: { conversation_id: CONVERSATION } }, { status: 200, body: '{' },
    { status: 200, body: '{"conversation_id":"3WrongId","conversation_id":"' + CONVERSATION + '"}' },
    { status: 200, body: '\uFEFF' + JSON.stringify({ conversation_id: CONVERSATION }) },
    { status: 200, body: '\u00A0' + JSON.stringify({ conversation_id: CONVERSATION }) },
    { status: 200, body: '{ "conversation_id": "' + CONVERSATION + '" }' }, { status: 200, body: 'x'.repeat(65537) },
    { status: 200, body: JSON.stringify({ conversation_id: CONVERSATION }), extra: true }]) {
    const f = await fresh(t, { before(request) { if (request.operation === 'create-conversation') return output; } });
    await assert.rejects(f.instance.run(), FAILURE); assert.equal(f.model.state.seedPayloads.length, 0);
    assert.deepEqual(f.model.operations().slice(-2), ['close-helper', 'inspect-closed']);
  }
});

test('invalid or absent-binding conversation IDs never become seed targets', async t => {
  for (const value of [undefined, null, 123456, 'abcde3', '3tiny', '9fncpBootstrap' + 'f'.repeat(48), '3synthetic/other']) {
    const f = await fresh(t, { before(request) { if (request.operation === 'create-conversation') return api({ conversation_id: value }); } });
    await assert.rejects(f.instance.run(), FAILURE); assert.equal(f.model.state.seedPayloads.length, 0);
  }
});

test('seed response IDs and creator PID reject duplicates, coercion, overflow, negative values and owner drift', async t => {
  for (const mutate of [item => { item.tid = '103'; }, item => { item.tid = -1; }, item => { item.tid = 2147483648; },
    item => { item.currentPid = '37'; }, item => { item.currentPid = -1; }, item => { item.tid = TIDS[0]; }, item => { item.currentPid = PID + 1; }]) {
    const f = await fresh(t, { after(request, output, state) {
      if (request.operation === 'create-seed' && state.seedPayloads.length === 2) { const body = JSON.parse(output.body); mutate(body); return api(body); }
    } });
    await assert.rejects(f.instance.run(), FAILURE); assert.equal(f.model.state.seedPayloads.length, 2);
    assert.equal(f.model.operations().includes('read-seeds'), false); assert.equal(f.model.operations().includes('close-conversation'), false);
  }
});

test('seed readback must exactly match membership, original texts, creator and unique pass-vote baseline', async t => {
  for (const mutate of [rows => rows.pop(), rows => rows.push(clone(rows[0])), rows => { rows[0].tid = rows[1].tid; },
    rows => { rows[0].conversation_id = '4ForeignSynthetic'; }, rows => { rows[0].txt += ' altered'; }, rows => { rows[0].pid++; }, rows => { rows[0].is_seed = false; },
    rows => { rows[0].mod = 0; }, rows => { rows[0].active = false; }, rows => { rows[0].agree_count = 1; },
    rows => { rows[0].disagree_count = 1; }, rows => { rows[0].pass_count = 0; }, rows => { rows[0].count = 2; }]) {
    const f = await fresh(t, { after(request, output) { if (request.operation === 'read-seeds') { const rows = JSON.parse(output.body); mutate(rows); return api(rows); } } });
    await assert.rejects(f.instance.run(), FAILURE); assert.equal(f.model.operations().includes('close-conversation'), false);
    assert.equal(f.instance.summary().latestUniqueSeedOwnerVotes, null); assert.equal(f.model.state.helperClosed, true);
  }
});

test('closing response must identify the same conversation before closed flags can be accepted', async t => {
  const f = await fresh(t, { before(request) { if (request.operation === 'close-conversation') return api({ conversation_id: '4DifferentSynthetic' }); } });
  await assert.rejects(f.instance.run(), FAILURE); assert.equal(f.model.operations().includes('read-conversation'), false);
  assert.equal(f.instance.summary().completed, false); assert.equal(f.model.state.helperClosed, true);
});

test('closed-conversation readback requires owner, closure, whitelist, XID and privacy/moderation flags', async t => {
  for (const key of ['is_owner', 'is_active', 'use_xid_whitelist', 'xid_required', 'is_data_open', 'strict_moderation', 'is_anon', 'is_draft',
    'topics_enabled', 'treevite_enabled', 'profanity_filter', 'spam_filter']) {
    const f = await fresh(t, { after(request, output) { if (request.operation === 'read-conversation') { const body = JSON.parse(output.body); body[key] = !body[key]; return api(body); } } });
    await assert.rejects(f.instance.run(), FAILURE); assert.equal(f.instance.summary().closedConversationReadback, false);
    assert.equal(f.instance.summary().completed, false); assert.equal(f.model.state.helperClosed, true);
  }
});

test('uncertain dispatched helper close never repeats and prevents a private binding from escaping', async t => {
  const f = await fresh(t, { after(request) { if (request.operation === 'close-helper') throw new Error('PRIVATE_CLOSE_ERROR'); } });
  await assert.rejects(f.instance.run(), FAILURE); assert.equal(f.instance.summary().completed, false);
  assert.equal(f.instance.summary().helperClosure, 'NOT_VERIFIED'); const calls = f.model.state.calls.length;
  await assert.rejects(f.instance.close(), FAILURE); assert.equal(f.model.state.calls.length, calls);
  assert.equal(f.model.operations().filter(operation => operation === 'close-helper').length, 1);
});

test('acknowledged helper close with failed independent inspection retries inspection only, never bootstrap or close', async t => {
  let failOnce = true;
  const f = await fresh(t, { before(request) { if (failOnce && request.operation === 'inspect-closed') { failOnce = false; throw new Error('PRIVATE_INSPECTION_ERROR'); } } });
  await assert.rejects(f.instance.run(), FAILURE); assert.equal(f.instance.summary().completed, false);
  const calls = f.model.state.calls.length; assert.equal((await f.instance.close()).helperClosure, 'INJECTED_READBACK_ACCEPTED');
  assert.equal(f.model.state.calls.length, calls + 1); assert.equal(f.model.operations().at(-1), 'inspect-closed');
  assert.equal(f.model.operations().filter(operation => operation === 'close-helper').length, 1); await assert.rejects(f.instance.run(), FAILURE);
});

test('helper close and independent stopped checks cannot substitute identity or running state', async t => {
  for (const operation of ['close-helper', 'inspect-closed']) for (const field of ['id', 'running']) {
    const f = await fresh(t, { after(request, output) { if (request.operation === operation) output[field] = field === 'id' ? 'b'.repeat(64) : true; return output; } });
    await assert.rejects(f.instance.run(), FAILURE); assert.equal(f.instance.summary().helperClosure, 'NOT_VERIFIED'); assert.equal(f.instance.summary().completed, false);
  }
});

test('cancellation during pending creation rejects late authority while cleanup requests remain valid', async t => {
  const entered = deferred(); const release = deferred(); let pending;
  const f = await fresh(t, { async after(request, output) {
    if (request.operation === 'create-conversation') { pending = request; entered.resolve(); await release.promise; }
    return output;
  }, async before(request) {
    if (['close-helper', 'inspect-closed'].includes(request.operation)) { assert.equal(f.instance.summary().cancelled, true); await protocol.verifyBootstrapProtocolRequest(request); }
  } });
  const rejected = assert.rejects(f.instance.run(), FAILURE); await entered.promise;
  f.instance.cancel(); await assert.rejects(protocol.verifyBootstrapProtocolRequest(pending), FAILURE); release.resolve(); await rejected;
  assert.equal(f.model.state.seedPayloads.length, 0); assert.equal(f.instance.summary().completed, false);
  assert.equal(f.instance.summary().helperClosure, 'INJECTED_READBACK_ACCEPTED');
});

test('cancellation during initial inspection cannot adopt a late helper ID or dispatch unnamed cleanup', async t => {
  const entered = deferred(); const release = deferred();
  const f = await fresh(t, { async after(request, output) {
    if (request.operation === 'inspect-helper') { entered.resolve(); await release.promise; } return output;
  } });
  const rejected = assert.rejects(f.instance.run(), FAILURE); await entered.promise; f.instance.cancel(); release.resolve(); await rejected;
  assert.deepEqual(f.model.operations(), ['inspect-helper']); await assert.rejects(f.instance.close(), FAILURE);
  assert.equal(f.instance.summary().helperClosure, 'NOT_VERIFIED'); assert.equal(f.instance.summary().completed, false);
});

test('a duplicate concurrent run is denied without cancelling the admitted run', async t => {
  const entered = deferred(); const release = deferred();
  const f = await fresh(t, { async after(request, output) { if (request.operation === 'create-conversation') { entered.resolve(); await release.promise; } return output; } });
  const running = f.instance.run(); await entered.promise; await assert.rejects(f.instance.run(), FAILURE);
  await assert.rejects(f.instance.verifyIntegrity(), FAILURE); assert.equal(f.instance.summary().cancelled, false);
  release.resolve(); assert.equal((await running).binding.conversationId, CONVERSATION); assert.equal(f.model.state.conversations, 1);
});

test('close during a pending callback latches cancellation and later becomes a verified cleanup no-op', async t => {
  const entered = deferred(); const release = deferred();
  const f = await fresh(t, { async after(request, output) { if (request.operation === 'create-seed') { entered.resolve(); await release.promise; } return output; } });
  const rejected = assert.rejects(f.instance.run(), FAILURE); await entered.promise; await assert.rejects(f.instance.close(), FAILURE);
  release.resolve(); await rejected; const count = f.model.state.calls.length;
  assert.equal((await f.instance.close()).helperClosure, 'INJECTED_READBACK_ACCEPTED'); assert.equal(f.model.state.calls.length, count);
  assert.equal(f.model.state.seedPayloads.length, 1);
});

test('cancel or close before run forbids all driver calls and any later bootstrap attempt', async t => {
  for (const method of ['cancel', 'close']) {
    const f = await fresh(t); await f.instance[method](); await assert.rejects(f.instance.run(), FAILURE);
    assert.deepEqual(f.model.operations(), []); assert.equal(f.instance.summary().completed, false);
  }
});

test('new private evidence tampering rejects run before callbacks and cannot be restored as a resumable attempt', async t => {
  const f = await fresh(t); const path = join(f.instance.privateDirectory, 'ownership.json'); const original = await readFile(path);
  await writeFile(path, 'tampered synthetic evidence'); await assert.rejects(f.instance.verifyIntegrity(), FAILURE);
  await assert.rejects(f.instance.run(), FAILURE); assert.deepEqual(f.model.operations(), []);
  await writeFile(path, original); await assert.rejects(f.instance.run(), FAILURE);
});

test('active request verification redacts filesystem errors after a new fixture file is removed', async t => {
  const f = await fresh(t, { async before(request) {
    if (request.operation === 'inspect-helper') {
      await unlink(join(f.instance.privateDirectory, 'ownership.json'));
      await assert.rejects(protocol.verifyBootstrapProtocolRequest(request), error => FAILURE.test(error.message) && !error.message.includes(f.instance.privateDirectory));
    }
  } });
  await assert.rejects(f.instance.run(), FAILURE); assert.equal(f.instance.summary().completed, false);
});

test('pinned seed-source drift or a symbolic-link replacement is rejected without modifying the production source pin', async t => {
  for (const kind of ['content', 'symlink']) {
    const isolated = await isolatedSource(t); const f = await fresh(t, {}, isolated.module);
    if (kind === 'content') await writeFile(isolated.seedPath, JSON.stringify(fixedSeeds.slice().reverse()));
    else { const target = isolated.seedPath + '.own-original'; await rename(isolated.seedPath, target); await symlink(target, isolated.seedPath); }
    await assert.rejects(f.instance.verifyIntegrity(), FAILURE); await assert.rejects(f.instance.run(), FAILURE);
    assert.deepEqual(f.model.operations(), []);
  }
  const isolated = await isolatedSource(t); await unlink(isolated.seedPath);
  await assert.rejects(isolated.module.createBootstrapProtocol({ driver: async () => assert.fail('must not run') }),
    error => FAILURE.test(error.message) && !error.message.includes(isolated.seedPath));
});

test('aggregate evidence excludes private binding/helper details and does not claim actual runtime or raw vote history', async t => {
  const f = await fresh(t); await f.instance.run(); const summary = f.instance.summary(); const text = JSON.stringify(summary);
  for (const value of [f.instance.privateDirectory, HELPER, IMAGE, CONVERSATION, ...fixedSeeds]) assert.equal(text.includes(value), false);
  assert.equal(summary.classification, 'INJECTED_PROTOCOL_ONLY'); assert.equal(summary.actualRuntime, 'NOT_RUN');
  assert.equal(summary.ordinaryImageApproval, 'NOT_ESTABLISHED'); assert.equal(summary.latestUniqueSeedOwnerVotes, 15);
  assert.equal(summary.rawVoteHistory, 'NOT_CHECKED'); assert.equal(summary.roundOpen, false); assert.equal(summary.activationGranted, false);
});
