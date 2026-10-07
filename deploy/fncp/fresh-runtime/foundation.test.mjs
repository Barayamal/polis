import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir, rm, chmod, writeFile, rename, symlink, link, unlink, lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { sign, verify as cryptoVerify } from 'node:crypto';
import { createFreshPolisFoundation, verifyFreshPolisRequest } from './foundation.mjs';

const BOUNDARY = /Fresh synthetic foundation boundary failed; new private state preserved\./u;
const bootstrapResult = () => ({ conversationId: '7InventedConversation',
  statementIds: [101, 110, 130, 199, 207, 220, 260, 271, 307, 318, 399, 402, 444, 500, 512] });
async function fresh(t) {
  const instance = await createFreshPolisFoundation();
  // This exact directory was created exclusively by this test's zero-argument
  // factory. No runtime/containers/volumes exist; never target retained paths.
  t.after(() => rm(instance.privateDirectory, { recursive: true, force: true }));
  return instance;
}
const readJson = (instance, name) => readFile(join(instance.privateDirectory, name), 'utf8').then(JSON.parse);
function successProbe(request) {
  return { context: request.context, running: true, images: request.images.map(item => ({ ...item })),
    ports: request.ports.map(item => ({ ...item, free: true })), resources: request.resources.map(item => ({ ...item, absent: true })) };
}
function successContainer(request, running = request.operation !== 'stop') {
  const r = request.resource;
  return { id: request.id ?? (r.role === 'postgres' ? 'a' : 'b').repeat(64), name: r.name, imageId: r.imageId,
    labels: { ...r.labels }, os: r.os, architecture: r.architecture, networkName: r.networkName,
    volumeName: r.volumeName, loopbackOnly: true, egressPolicyConfigured: true, running };
}
async function ready(t, driver = successContainer) {
  const instance = await fresh(t); await instance.preflight({ probe: successProbe }); await instance.start({ driver }); return instance;
}
async function ledger(instance) {
  const names = (await readdir(instance.privateDirectory)).filter(name => name.startsWith('ledger-')).sort();
  return Promise.all(names.map(name => readJson(instance, name)));
}

test('fresh factory is zero-argument and rejects attempted path, config or instance adoption', async () => {
  for (const input of [undefined, null, {}, '/tmp/old', { directory: '/tmp/old' }]) {
    await assert.rejects(createFreshPolisFoundation(input), BOUNDARY);
  }
});

test('explicit denial-only cancellation invalidates active requests without needing a stop driver', async t => {
  const instance = await fresh(t);
  assert.throws(() => instance.cancel(undefined), BOUNDARY);
  assert.equal(instance.summary().stopRequested, false);
  await assert.rejects(instance.preflight({ probe: async request => {
    assert.equal(instance.cancel().stopRequested, true);
    await assert.rejects(verifyFreshPolisRequest(request), BOUNDARY);
    return successProbe(request);
  } }), BOUNDARY);
  assert.equal(instance.cancel().stopRequested, true);
  assert.equal(instance.summary().containerAttempts, 0);
  await assert.rejects(instance.start({ driver: successContainer }), BOUNDARY);
});

test('new files and directories are exclusive, private, unrelated and independently keyed', async t => {
  const a = await fresh(t); const b = await fresh(t);
  assert.notEqual(a.privateDirectory, b.privateDirectory);
  const seen = new Set();
  for (const instance of [a, b]) {
    assert.equal((await lstat(instance.privateDirectory)).mode & 0o777, 0o700);
    const names = await readdir(instance.privateDirectory);
    assert.deepEqual(names.sort(), ['credentials.json', 'initial-config.json', 'jwt-private.pem', 'jwt-public.pem', 'ownership.json']);
    for (const name of names) {
      const info = await lstat(join(instance.privateDirectory, name));
      assert.equal(info.mode & 0o777, 0o600); assert.equal(info.nlink, 1); assert.ok(info.isFile());
    }
    const values = await readJson(instance, 'credentials.json');
    for (const key of ['databasePassword', 'gatewaySecret', 'providerCredential', 'loginCodePepper', 'encryptionPassword']) {
      assert.match(values[key], /^[a-f0-9]{64}$/u); assert.equal(seen.has(values[key]), false); seen.add(values[key]);
    }
    const privateKey = await readFile(join(instance.privateDirectory, 'jwt-private.pem'));
    const publicKey = await readFile(join(instance.privateDirectory, 'jwt-public.pem'));
    assert.equal(cryptoVerify('sha256', Buffer.from('synthetic-proof'), publicKey,
      sign('sha256', Buffer.from('synthetic-proof'), privateKey)), true);
    assert.equal(await instance.verifyIntegrity(), true);
  }
});

test('literal initial configuration pins closed dedicated gates to one absent conversation', async t => {
  const instance = await fresh(t); const initial = await readJson(instance, 'initial-config.json');
  assert.equal(initial.context, 'colima-fncp-c-20260913');
  const env = initial.environment;
  assert.match(env.FNCP_GATEWAY_CONVERSATION_ID, /^9fncpBootstrap[a-f0-9]{48}$/u);
  assert.equal(env.FNCP_GATEWAY_CONVERSATION_ID, env.FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID);
  assert.equal(env.FNCP_GATEWAY_ENFORCEMENT, 'true'); assert.equal(env.FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT, 'true');
  assert.equal(env.FNCP_OPTION_C_RELEASE_MODE, 'production'); assert.equal(env.FNCP_SYNTHETIC_BOOTSTRAP_COMPLETE, 'false');
  assert.equal(env.FNCP_FIXED_STATEMENT_IDS, ''); assert.equal(Object.hasOwn(env, 'SESSION_SECRET'), false);
  assert.equal(env.POLIS_JWT_ISSUER, 'http://127.0.0.1:5500/'); assert.equal(env.POLIS_JWT_AUDIENCE, 'fncp-fresh-synthetic-only');
  assert.equal(env.API_SERVER_PORT, '5000'); assert.equal(env.API_PROD_HOSTNAME, '127.0.0.1:5500');
  assert.equal(env.DOMAIN_OVERRIDE, '127.0.0.1:5500'); assert.equal(env.SHOULD_USE_TRANSLATION_API, 'false');
  assert.equal(env.EMAIL_TRANSPORT_TYPES, ''); assert.equal(env.RUN_PERIODIC_EXPORT_TESTS, 'false');
  assert.notEqual(env.LOGIN_CODE_PEPPER, env.ENCRYPTION_PASSWORD_00001);
  assert.equal(env.ENABLE_TELEMETRY, 'false'); assert.equal(initial.roundOpen, false); assert.equal(initial.activationGranted, false);
  assert.equal(initial.topology.additionalNetworksAllowed, false); assert.equal(initial.topology.egressImplementation, 'NOT_IMPLEMENTED');
  assert.doesNotMatch(JSON.stringify(initial), /\$\{|\.env\.staging|fncp-loopback/u);
  assert.notEqual(env.FNCP_GATEWAY_SHARED_SECRET, env.FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL);
});

test('aggregate summary hides names, paths, credentials, keys and all synthetic capabilities', async t => {
  const instance = await fresh(t); const values = await readJson(instance, 'credentials.json');
  const initial = await readJson(instance, 'initial-config.json'); const summary = instance.summary();
  assert.equal(summary.actualRuntime, 'NOT_RUN'); assert.equal(summary.dockerAdapter, 'NOT_IMPLEMENTED');
  assert.equal(summary.ordinaryBootstrapAdapter, 'NOT_IMPLEMENTED'); assert.equal(summary.sourceAcquisition, 'NOT_IMPLEMENTED');
  assert.equal(summary.actualEgressAssurance, 'NOT_RUN'); assert.equal(summary.activationGranted, false);
  for (const privateValue of [...Object.values(values), instance.privateDirectory, initial.names.run,
    initial.environment.FNCP_GATEWAY_CONVERSATION_ID]) assert.equal(JSON.stringify(summary).includes(privateValue), false);
  assert.equal(Object.isFrozen(summary), true);
});

test('method inputs reject extras, symbols, inheritance, accessors, proxies and coercion without invocation', async t => {
  const instance = await fresh(t); let reads = 0;
  const getter = { get probe() { reads++; throw new Error('private'); } };
  const proxy = new Proxy({}, { getPrototypeOf() { reads++; throw new Error('private'); } });
  for (const input of [undefined, {}, { probe: successProbe, path: '/tmp/old' }, getter, proxy,
    Object.assign(Object.create({ inherited: true }), { probe: successProbe }),
    { probe: successProbe, [Symbol('extra')]: 1 }, { probe: new Proxy(successProbe, {}) }, { probe: 'function' }]) {
    await assert.rejects(instance.preflight(input), BOUNDARY);
  }
  await assert.rejects(instance.preflight({ probe: successProbe }, 1), BOUNDARY);
  assert.throws(() => instance.summary(undefined), BOUNDARY);
  await assert.rejects(instance.verifyIntegrity(undefined), BOUNDARY);
  assert.equal(reads, 0);
});

test('preflight requests only exact context, pinned images, fixed loopback ports and new named resources', async t => {
  const instance = await fresh(t); let called = 0;
  const result = await instance.preflight({ probe(request) {
    called++; assert.equal(Object.isFrozen(request), true); assert.equal(Object.isFrozen(request.resources), true);
    assert.equal(request.context, 'colima-fncp-c-20260913');
    assert.deepEqual(request.ports, [5500, 8101, 8103, 33080].map(port => ({ host: '127.0.0.1', port })));
    assert.equal(request.images.every(item => item.os === 'linux' && item.architecture === 'arm64' && item.id.startsWith('sha256:')), true);
    assert.equal(request.resources.length, 4); assert.equal(request.pull, false); assert.equal(request.build, false); assert.equal(request.startVm, false);
    return successProbe(request);
  } });
  assert.equal(called, 1); assert.equal(result.preflight, 'INJECTED_PROBE_ACCEPTED'); assert.equal(result.actualRuntime, 'NOT_RUN');
});

test('preflight rejects unavailable runtime, image drift, wrong architecture, occupied ports and old resources', async t => {
  const instance = await fresh(t);
  for (const mutate of [result => { result.running = false; }, result => { result.context = 'another-context'; },
    result => { result.images[0].id = 'sha256:' + 'f'.repeat(64); }, result => { result.images[0].architecture = 'amd64'; },
    result => { result.images[0].os = 'darwin'; }, result => { result.images[0] = result.images[1]; },
    result => { result.ports[0].free = false; }, result => { result.ports[0].host = '0.0.0.0'; },
    result => { result.ports[0].port = 5501; }, result => { result.resources[0].absent = false; },
    result => { result.resources[0].name = 'retained'; }, result => { result.images.push(result.images[0]); },
    result => { result.resources[0].extra = true; }, result => { result.ports[0] = result.ports[1]; }]) {
    await assert.rejects(instance.preflight({ probe(request) { const result = successProbe(request); mutate(result); return result; } }), BOUNDARY);
    assert.equal(instance.summary().preflight, 'NOT_ACCEPTED');
  }
  let invoked = false; await assert.rejects(instance.start({ driver() { invoked = true; } }), BOUNDARY); assert.equal(invoked, false);
});

test('preflight data descriptors do not execute nested getters or proxy traps', async t => {
  const instance = await fresh(t); let reads = 0;
  for (const change of [result => { Object.defineProperty(result.images[0], 'id', { get() { reads++; } }); },
    result => { Object.defineProperty(result.ports, '0', { get() { reads++; } }); },
    result => { result.resources = new Proxy(result.resources, { get() { reads++; } }); }]) {
    await assert.rejects(instance.preflight({ probe(request) { const result = successProbe(request); change(result); return result; } }), BOUNDARY);
  }
  assert.equal(reads, 0);
});

test('integrity rejects content or mode drift before an injected operation', async t => {
  for (const change of [instance => writeFile(join(instance.privateDirectory, 'credentials.json'), '{}'),
    instance => chmod(join(instance.privateDirectory, 'credentials.json'), 0o644),
    instance => chmod(instance.privateDirectory, 0o755),
    instance => writeFile(join(instance.privateDirectory, 'unexpected.txt'), 'untracked')]) {
    const instance = await fresh(t); await change(instance); let calls = 0;
    await assert.rejects(instance.preflight({ probe() { calls++; } }), BOUNDARY); assert.equal(calls, 0);
  }
});

test('integrity rejects same-byte inode replacement, symlink and hard-link aliases', async t => {
  for (const change of [async (path, directory) => {
    const body = await readFile(path); await rename(path, join(directory, 'old-file')); await writeFile(path, body, { mode: 0o600 });
    await unlink(join(directory, 'old-file'));
  }, async (path, directory) => { await rename(path, join(directory, 'old-file')); await symlink(join(directory, 'old-file'), path); },
  async (path, directory) => { await link(path, join(directory, 'hard-alias')); }]) {
    const instance = await fresh(t); await change(join(instance.privateDirectory, 'credentials.json'), instance.privateDirectory);
    await assert.rejects(instance.verifyIntegrity(), BOUNDARY);
  }
});

test('callbacks mutating generated files fail after return and before subsequent startup', async t => {
  const instance = await fresh(t); await instance.preflight({ probe: successProbe }); let starts = 0;
  await assert.rejects(instance.start({ async driver(request) {
    starts++; await writeFile(join(instance.privateDirectory, 'credentials.json'), 'changed'); return successContainer(request);
  } }), BOUNDARY);
  assert.equal(starts, 1); assert.equal(instance.summary().startAttempted, true);
  await assert.rejects(instance.start({ driver: successContainer }), BOUNDARY);
});

test('start attempt is durably recorded before callback and dispatcher uses only exact names/images', async t => {
  const instance = await fresh(t); await instance.preflight({ probe: successProbe }); let calls = 0;
  await instance.start({ async driver(request) {
    calls++; const rows = await ledger(instance); const last = rows.at(-1);
    assert.equal(last.operation, 'start'); assert.equal(last.status, 'ATTEMPTED'); assert.equal(last.name, request.resource.name);
    assert.equal(request.resource.pull, false); assert.equal(request.resource.build, false); assert.equal(request.resource.restart, 'no');
    assert.equal(request.resource.egress, 'DENY_REQUIRED_NOT_IMPLEMENTED');
    assert.equal(request.resource.labels['org.barayamal.fncp.purpose'], 'fresh-synthetic-foundation-only');
    assert.equal(Object.isFrozen(request.resource.labels), true);
    return successContainer(request);
  } });
  assert.equal(calls, 2); assert.equal(instance.summary().verifiedContainers, 2); assert.equal(instance.summary().actualRuntime, 'NOT_RUN');
  await assert.rejects(instance.start({ driver: successContainer }), BOUNDARY);
  await assert.rejects(instance.preflight({ probe: successProbe }), BOUNDARY);
});

test('uncertain first start never retries, discovers, adopts or stops an unknown container', async t => {
  const instance = await fresh(t); await instance.preflight({ probe: successProbe }); let calls = 0;
  await assert.rejects(instance.start({ driver() { calls++; throw new Error('private-credential-not-for-output'); } }), error => {
    assert.match(error.message, BOUNDARY); assert.doesNotMatch(error.message, /private-credential/u); return true;
  });
  assert.equal(instance.summary().uncertainContainers, 1);
  await assert.rejects(instance.start({ driver() { calls++; } }), BOUNDARY);
  await assert.rejects(instance.stop({ driver() { calls++; } }), BOUNDARY);
  assert.equal(calls, 1); assert.equal(instance.summary().filesPreserved, true);
});

test('invalid returned container identity is not adopted despite successful callback return', async t => {
  for (const mutate of [result => { result.name = 'retained'; }, result => { result.imageId = 'sha256:' + 'f'.repeat(64); },
    result => { result.labels['org.barayamal.fncp.fresh-run'] = 'other'; }, result => { result.id = 'short'; },
    result => { result.networkName = 'retained'; }, result => { result.volumeName = 'retained'; },
    result => { result.loopbackOnly = false; }, result => { result.egressPolicyConfigured = false; },
    result => { result.architecture = 'amd64'; }, result => { result.running = false; }]) {
    const instance = await fresh(t); await instance.preflight({ probe: successProbe });
    await assert.rejects(instance.start({ driver(request) { const result = successContainer(request); mutate(result); return result; } }), BOUNDARY);
    assert.equal(instance.summary().verifiedContainers, 0); assert.equal(instance.summary().uncertainContainers, 1);
  }
});

test('two names cannot be validated against the same concrete container ID', async t => {
  const instance = await fresh(t); await instance.preflight({ probe: successProbe });
  await assert.rejects(instance.start({ driver(request) { const result = successContainer(request); result.id = 'a'.repeat(64); return result; } }), BOUNDARY);
  assert.equal(instance.summary().verifiedContainers, 1); assert.equal(instance.summary().uncertainContainers, 1);
});

test('bootstrap rejects before complete owned startup and records its attempt before callback', async t => {
  const notStarted = await fresh(t); let calls = 0;
  await assert.rejects(notStarted.bootstrap({ driver() { calls++; } }), BOUNDARY); assert.equal(calls, 0);
  const instance = await ready(t);
  await instance.bootstrap({ async driver(request) {
    const rows = await ledger(instance); assert.deepEqual(rows.at(-1), { operation: 'bootstrap', status: 'ATTEMPTED' });
    assert.equal(request.ordinaryBootstrapImage, 'NOT_PINNED'); assert.equal(request.runtimeAdapter, 'NOT_IMPLEMENTED');
    assert.equal(request.launchAuthority, false); assert.equal(request.databaseContainer, 'a'.repeat(64));
    return bootstrapResult();
  } });
  assert.equal(instance.summary().bootstrapAttempted, true); assert.equal(instance.summary().conversationBound, true);
});

test('binding atomically writes matching gates and actual nonsequential IDs without applying or opening', async t => {
  const instance = await ready(t); const before = await readFile(join(instance.privateDirectory, 'initial-config.json'));
  await instance.bootstrap({ driver: bootstrapResult });
  const config = await readJson(instance, 'bound-config.json'); const actual = bootstrapResult();
  assert.equal(config.environment.FNCP_GATEWAY_CONVERSATION_ID, actual.conversationId);
  assert.equal(config.environment.FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID, actual.conversationId);
  assert.equal(config.environment.FNCP_FIXED_STATEMENT_IDS, actual.statementIds.join(','));
  assert.deepEqual(config.observedStatementIds, actual.statementIds);
  assert.equal(config.environment.FNCP_GATEWAY_ENFORCEMENT, 'true'); assert.equal(config.environment.FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT, 'true');
  assert.equal(config.roundOpen, false); assert.equal(config.activationGranted, false); assert.equal(config.appliedToRuntime, false);
  assert.equal(config.bootstrapHelperClosure, 'NOT_VERIFIED'); assert.equal(config.status, 'VALIDATED_INJECTED_RESULT_ONLY');
  assert.deepEqual(await readFile(join(instance.privateDirectory, 'initial-config.json')), before);
  assert.equal((await readdir(instance.privateDirectory)).includes('bound-config.pending.json'), false);
  assert.equal(await instance.verifyIntegrity(), true); assert.equal(instance.summary().actualRuntime, 'NOT_RUN');
  let calls = 0; await assert.rejects(instance.bootstrap({ driver() { calls++; } }), BOUNDARY); assert.equal(calls, 0);
});

test('failed or invalid bootstrap cannot replay, manufacture IDs or write a bound file', async t => {
  for (const driver of [() => { throw new Error('uncertain'); }, () => ({ conversationId: '7ValidConversation', statementIds: [0] }),
    () => ({ ...bootstrapResult(), statementIds: Array(15).fill(1) }),
    () => ({ ...bootstrapResult(), conversationId: '9fncpBootstrap' + 'a'.repeat(48) }),
    () => ({ ...bootstrapResult(), statementIds: [...bootstrapResult().statementIds.slice(0, 14), 2147483648] })]) {
    const instance = await ready(t); await assert.rejects(instance.bootstrap({ driver }), BOUNDARY);
    assert.equal(instance.summary().bootstrapAttempted, true); assert.equal(instance.summary().conversationBound, false);
    assert.equal((await readdir(instance.privateDirectory)).includes('bound-config.json'), false);
    await assert.rejects(instance.bootstrap({ driver: bootstrapResult }), BOUNDARY);
  }
});

test('a preexisting bound file or mutation during bootstrap is never overwritten or adopted', async t => {
  const instance = await ready(t);
  await assert.rejects(instance.bootstrap({ async driver() {
    await writeFile(join(instance.privateDirectory, 'bound-config.json'), 'untrusted', { flag: 'wx', mode: 0o600 });
    return bootstrapResult();
  } }), BOUNDARY);
  assert.equal(await readFile(join(instance.privateDirectory, 'bound-config.json'), 'utf8'), 'untrusted');
  assert.equal(instance.summary().conversationBound, false);
});

test('stop verifies concrete ID/name/labels/image and records attempts before exact stop', async t => {
  const instance = await ready(t); const operations = [];
  await instance.stop({ async driver(request) {
    operations.push(`${request.resource.role}:${request.operation}`);
    const rows = await ledger(instance); assert.equal(rows.at(-1).operation, 'stop'); assert.equal(rows.at(-1).status, 'ATTEMPTED');
    assert.equal(rows.at(-1).id, request.id); return successContainer(request);
  } });
  assert.deepEqual(operations, ['server:inspect-before-stop', 'server:stop', 'postgres:inspect-before-stop', 'postgres:stop']);
  const result = await instance.stop({ driver() { throw new Error('idempotent means not called'); } });
  assert.equal(result.stoppedContainers, 2); assert.equal(result.uncertainContainers, 0); assert.equal(result.filesPreserved, true);
  await assert.rejects(instance.bootstrap({ driver: bootstrapResult }), BOUNDARY);
  assert.equal(await instance.verifyIntegrity(), true);
});

test('stop identity mismatch prevents stopping that subject but still attempts the other owned resource', async t => {
  const instance = await ready(t); const operations = [];
  await assert.rejects(instance.stop({ driver(request) {
    operations.push(`${request.resource.role}:${request.operation}`); const result = successContainer(request);
    if (request.resource.role === 'server') result.id = 'c'.repeat(64); return result;
  } }), BOUNDARY);
  assert.deepEqual(operations, ['server:inspect-before-stop', 'postgres:inspect-before-stop', 'postgres:stop']);
  assert.equal(instance.summary().stoppedContainers, 1); assert.equal(instance.summary().uncertainContainers, 1);
  await assert.rejects(instance.stop({ driver() { throw new Error('must not replay uncertain stop'); } }), BOUNDARY);
});

test('uncertain stop failure preserves evidence, continues remaining stops and never retries', async t => {
  const instance = await ready(t); const calls = [];
  await assert.rejects(instance.stop({ driver(request) {
    calls.push(`${request.resource.role}:${request.operation}`);
    if (request.resource.role === 'server' && request.operation === 'stop') throw new Error('private-uncertain');
    return successContainer(request);
  } }), BOUNDARY);
  assert.deepEqual(calls, ['server:inspect-before-stop', 'server:stop', 'postgres:inspect-before-stop', 'postgres:stop']);
  assert.equal(instance.summary().stoppedContainers, 1);
  await assert.rejects(instance.stop({ driver() { calls.push('unexpected'); } }), BOUNDARY);
  assert.equal(calls.length, 4); assert.equal(await instance.verifyIntegrity(), true);
});

test('partial startup cleanup stops only the validated attempted container, preserving the unknown attempt', async t => {
  const instance = await fresh(t); await instance.preflight({ probe: successProbe });
  await assert.rejects(instance.start({ driver(request) {
    if (request.resource.role === 'server') throw new Error('uncertain'); return successContainer(request);
  } }), BOUNDARY);
  const calls = []; await assert.rejects(instance.stop({ driver(request) { calls.push(request.resource.role); return successContainer(request); } }), BOUNDARY);
  assert.deepEqual(calls, ['postgres', 'postgres']); assert.equal(instance.summary().stoppedContainers, 1);
  assert.equal(instance.summary().uncertainContainers, 1);
});

test('concurrent and reentrant lifecycle calls are rejected before a second callback', async t => {
  const instance = await fresh(t); let unblock; const wait = new Promise(resolve => { unblock = resolve; }); let entered;
  const started = new Promise(resolve => { entered = resolve; });
  const pending = instance.preflight({ async probe(request) { entered(); await wait; return successProbe(request); } });
  await started;
  await assert.rejects(instance.preflight({ probe: successProbe }), BOUNDARY);
  await assert.rejects(instance.verifyIntegrity(), BOUNDARY);
  unblock(); await pending;
  await instance.start({ async driver(request) {
    await assert.rejects(instance.start({ driver: successContainer }), BOUNDARY); return successContainer(request);
  } });
});

test('stale accepted preflight is rechecked immediately before any mutating dispatch', async t => {
  for (const invalidate of [result => { result.running = false; }, result => { result.ports[0].free = false; },
    result => { result.resources[0].absent = false; }, result => { result.images[1].architecture = 'amd64'; }]) {
    const instance = await fresh(t); let checks = 0; let mutations = 0;
    await instance.preflight({ probe(request) {
      const result = successProbe(request); if (++checks > 1) invalidate(result); return result;
    } });
    await assert.rejects(instance.start({ driver() { mutations++; } }), BOUNDARY);
    assert.equal(checks, 2); assert.equal(mutations, 0); assert.equal(instance.summary().startAttempted, false);
  }
});

test('stop during a pending start latches closure, tracks a late exact ID and prevents the second start', async t => {
  const instance = await fresh(t); await instance.preflight({ probe: successProbe });
  let unblock; const wait = new Promise(resolve => { unblock = resolve; }); let entered; const running = new Promise(resolve => { entered = resolve; });
  const starts = [];
  const pending = instance.start({ async driver(request) { starts.push(request.resource.role); entered(); await wait; return successContainer(request); } });
  await running;
  await assert.rejects(instance.stop({ driver: successContainer }), BOUNDARY);
  assert.equal(instance.summary().stopRequested, true);
  unblock(); await assert.rejects(pending, BOUNDARY);
  assert.deepEqual(starts, ['postgres']); assert.equal(instance.summary().verifiedContainers, 1);
  const calls = []; await instance.stop({ driver(request) { calls.push(request.resource.role); return successContainer(request); } });
  assert.deepEqual(calls, ['postgres', 'postgres']); assert.equal(instance.summary().stoppedContainers, 1);
});

test('stop during pending bootstrap discards late result without binding or repeating bootstrap', async t => {
  const instance = await ready(t); let unblock; const wait = new Promise(resolve => { unblock = resolve; });
  let entered; const running = new Promise(resolve => { entered = resolve; });
  const pending = instance.bootstrap({ async driver() { entered(); await wait; return bootstrapResult(); } });
  await running; await assert.rejects(instance.stop({ driver: successContainer }), BOUNDARY);
  unblock(); await assert.rejects(pending, BOUNDARY);
  assert.equal(instance.summary().conversationBound, false);
  assert.equal((await readdir(instance.privateDirectory)).includes('bound-config.json'), false);
  await instance.stop({ driver: successContainer }); assert.equal(instance.summary().stoppedContainers, 2);
  await assert.rejects(instance.bootstrap({ driver: bootstrapResult }), BOUNDARY);
});

test('reentrant stop does not deadlock and invalid closure inputs cannot latch state', async t => {
  const instance = await fresh(t); await instance.preflight({ probe: successProbe });
  await assert.rejects(instance.stop({ driver: 'not-a-driver' }), BOUNDARY);
  assert.equal(instance.summary().stopRequested, false);
  await assert.rejects(instance.start({ async driver(request) {
    await assert.rejects(instance.stop({ driver: successContainer }), BOUNDARY); return successContainer(request);
  } }), BOUNDARY);
  assert.equal(instance.summary().stopRequested, true); assert.equal(instance.summary().verifiedContainers, 1);
  await instance.stop({ driver: successContainer }); assert.equal(instance.summary().stoppedContainers, 1);
});

test('stop during pending preflight prevents accepting its late positive result', async t => {
  const instance = await fresh(t); let unblock; const wait = new Promise(resolve => { unblock = resolve; });
  let entered; const running = new Promise(resolve => { entered = resolve; });
  const pending = instance.preflight({ async probe(request) { entered(); await wait; return successProbe(request); } });
  await running; await assert.rejects(instance.stop({ driver: successContainer }), BOUNDARY);
  unblock(); await assert.rejects(pending, BOUNDARY);
  assert.equal(instance.summary().preflight, 'NOT_ACCEPTED'); await instance.stop({ driver: successContainer });
});

test('stopping a never-started foundation is idempotent and permanently prevents later startup', async t => {
  const instance = await fresh(t); const result = await instance.stop({ driver() { throw new Error('must not run'); } });
  assert.equal(result.containerAttempts, 0); assert.equal(result.stopRequested, true);
  await instance.stop({ driver() { throw new Error('must not run'); } });
  await assert.rejects(instance.preflight({ probe: successProbe }), BOUNDARY);
});

test('source closure has no Docker, process execution, network, retention or environment-reading implementation', async () => {
  const source = await readFile(new URL('./foundation.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /from ['"]node:(?:child_process|https?|net|tls)['"]|\bfetch\s*\(|process\.env|\.env\.staging|readFile\([^)]*archive|\brm\s*\(/u);
  assert.match(source, /ordinaryBootstrapImage: 'NOT_PINNED'/u);
  assert.match(source, /actualRuntime: 'NOT_RUN'/u);
  assert.match(source, /O_CREAT \| constants\.O_EXCL/u);
});

test('active request verifier rejects fabricated, copied, stale and proxy capabilities without access', async t => {
  let reads = 0;
  for (const request of [undefined, null, {}, new Proxy({}, { get() { reads++; }, getPrototypeOf() { reads++; } })]) {
    await assert.rejects(verifyFreshPolisRequest(request), BOUNDARY);
  }
  const instance = await fresh(t); let captured;
  await instance.preflight({ async probe(request) {
    captured = request; assert.equal(await verifyFreshPolisRequest(request), undefined);
    await assert.rejects(verifyFreshPolisRequest({ ...request }), BOUNDARY);
    await assert.rejects(verifyFreshPolisRequest(request, undefined), BOUNDARY);
    return successProbe(request);
  } });
  await assert.rejects(verifyFreshPolisRequest(captured), BOUNDARY); assert.equal(reads, 0);
});

test('every lifecycle callback is branded only for its own active lifetime, including cleanup', async t => {
  const instance = await fresh(t); const captured = [];
  await instance.preflight({ async probe(request) {
    await verifyFreshPolisRequest(request); captured.push(request); return successProbe(request);
  } });
  await instance.start({ async driver(request) {
    await verifyFreshPolisRequest(request); captured.push(request); return successContainer(request);
  } });
  await instance.bootstrap({ async driver(request) {
    await verifyFreshPolisRequest(request); captured.push(request); return bootstrapResult();
  } });
  await instance.stop({ async driver(request) {
    await verifyFreshPolisRequest(request); captured.push(request); return successContainer(request);
  } });
  assert.equal(captured.length, 9);
  for (const request of captured) await assert.rejects(verifyFreshPolisRequest(request), BOUNDARY);
});

test('active request verifier checks owned integrity and does not leak private mutation errors', async t => {
  const instance = await fresh(t);
  await assert.rejects(instance.preflight({ async probe(request) {
    await verifyFreshPolisRequest(request);
    await writeFile(join(instance.privateDirectory, 'credentials.json'), 'private-corruption');
    await assert.rejects(verifyFreshPolisRequest(request), BOUNDARY);
    return successProbe(request);
  } }), BOUNDARY);
});

test('stop latch revokes active new-work request capability but permits exact cleanup callbacks', async t => {
  const instance = await fresh(t); await instance.preflight({ probe: successProbe });
  let release; const wait = new Promise(resolve => { release = resolve; }); let entered;
  const started = new Promise(resolve => { entered = resolve; }); let captured;
  const pending = instance.start({ async driver(request) {
    captured = request; await verifyFreshPolisRequest(request); entered(); await wait; return successContainer(request);
  } });
  await started; await assert.rejects(instance.stop({ driver: successContainer }), BOUNDARY);
  await assert.rejects(verifyFreshPolisRequest(captured), BOUNDARY);
  release(); await assert.rejects(pending, BOUNDARY);
  await instance.stop({ async driver(request) { await verifyFreshPolisRequest(request); return successContainer(request); } });
  assert.equal(instance.summary().stoppedContainers, 1);
});
