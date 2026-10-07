import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createDockerPreflight } from './docker-preflight.mjs';
import { createFreshPolisFoundation } from './foundation.mjs';

const PREFLIGHT_FAILURE = /Fresh Docker preflight failed; no runtime mutation was requested\./u;
const FOUNDATION_FAILURE = /Fresh synthetic foundation boundary failed; new private state preserved\./u;
const ok = object => ({ exitCode: 0, stdout: JSON.stringify(object) + '\n', stderr: '' });
const engine = () => ({ os: 'linux', architecture: 'arm64', version: '28.5.1' });
function fakeExecutor(args) {
  assert.equal(Object.isFrozen(args), true);
  if (args[0] === 'version') return ok(engine());
  if (args[0] === 'image') return ok({ id: args[2], os: 'linux', architecture: 'arm64' });
  const [kind, operation, name] = args;
  assert.equal(operation, 'inspect');
  if (kind === 'container') return { exitCode: 1, stdout: '', stderr: `Error: No such container: ${name}\n` };
  if (kind === 'network') return { exitCode: 1, stdout: '', stderr: `Error response from daemon: network ${name} not found\n` };
  if (kind === 'volume') return { exitCode: 1, stdout: '', stderr: `Error response from daemon: get ${name}: no such volume\n` };
  throw new Error('unexpected command');
}
function syntheticProbe(request) {
  return { context: request.context, running: true, images: request.images.map(item => ({ ...item })),
    ports: request.ports.map(item => ({ ...item, free: true })), resources: request.resources.map(item => ({ ...item, absent: true })) };
}
async function fresh(t) {
  const instance = await createFreshPolisFoundation();
  t.after(() => rm(instance.privateDirectory, { recursive: true, force: true }));
  return instance;
}
function adapter(execute = fakeExecutor, probePort = () => true) { return createDockerPreflight({ execute, probePort }); }

test('constructing either default or injected adapter performs no Docker or port operation', () => {
  let calls = 0;
  assert.equal(typeof createDockerPreflight(), 'function');
  assert.equal(typeof adapter(() => { calls++; }, () => { calls++; }), 'function'); assert.equal(calls, 0);
});

test('adapter requires both trusted injections and rejects accessors, proxies, extras and ambiguous options', () => {
  let reads = 0;
  const getter = { execute: fakeExecutor, get probePort() { reads++; } };
  for (const input of [undefined, null, {}, { execute: fakeExecutor }, { probePort: () => true }, getter,
    { execute: fakeExecutor, probePort: () => true, host: 'remote' },
    { execute: new Proxy(fakeExecutor, {}), probePort: () => true },
    new Proxy({}, { getPrototypeOf() { reads++; } }),
    Object.assign(Object.create({ inherited: true }), { execute: fakeExecutor, probePort: () => true }),
    { execute: fakeExecutor, probePort: () => true, [Symbol('extra')]: 1 }]) {
    assert.throws(() => createDockerPreflight(input), PREFLIGHT_FAILURE);
  }
  assert.throws(() => createDockerPreflight({ execute: fakeExecutor, probePort: () => true }, undefined), PREFLIGHT_FAILURE);
  assert.equal(reads, 0);
});

test('unbranded and fabricated fresh-looking requests fail before any concrete or injected I/O', async () => {
  let calls = 0; const probe = adapter(() => { calls++; }, () => { calls++; });
  for (const request of [undefined, null, {}, { context: 'colima-fncp-c-20260913',
    resources: [{ kind: 'container', name: 'fncp-fresh-pg-' + 'a'.repeat(24) }] }, new Proxy({}, {})]) {
    await assert.rejects(probe(request), PREFLIGHT_FAILURE);
    await assert.rejects(createDockerPreflight()(request), PREFLIGHT_FAILURE);
  }
  await assert.rejects(probe({}, undefined), PREFLIGHT_FAILURE); assert.equal(calls, 0);
});

test('injected successful metadata preflight uses only exact scoped projections and fixed bind probes', async t => {
  const instance = await fresh(t); const commands = []; const ports = []; let snapshot;
  const probe = adapter(args => { commands.push([...args]); return fakeExecutor(args); }, input => {
    assert.equal(Object.isFrozen(input), true); ports.push({ ...input }); return true;
  });
  const result = await instance.preflight({ async probe(request) { snapshot = await probe(request); return snapshot; } });
  assert.equal(result.preflight, 'INJECTED_PROBE_ACCEPTED'); assert.equal(result.actualRuntime, 'NOT_RUN');
  assert.equal(commands.length, 7); assert.deepEqual(commands.map(args => args[0]), ['version', 'image', 'image', 'container', 'container', 'network', 'volume']);
  assert.deepEqual(commands[0], ['version', '--format', '{"os":{{json .Server.Os}},"architecture":{{json .Server.Arch}},"version":{{json .Server.Version}}}']);
  for (const command of commands.slice(1)) {
    assert.equal(command.length, 5); assert.equal(command[1], 'inspect'); assert.equal(command[3], '--format');
    assert.doesNotMatch(command[4], /Config|Env|Mounts|Logs|State|json \.\}\}/u);
  }
  assert.deepEqual(ports, [5500, 8101, 8103, 33080].map(port => ({ host: '127.0.0.1', port })));
  assert.equal(snapshot.context, 'colima-fncp-c-20260913'); assert.equal(snapshot.running, true);
  assert.equal(Object.isFrozen(snapshot), true); assert.equal(Object.isFrozen(snapshot.images[0]), true);
  assert.equal(snapshot.images.length, 2); assert.equal(snapshot.resources.length, 4); assert.equal(snapshot.ports.length, 4);
  assert.equal(snapshot.resources.every(resource => resource.absent === true), true);
});

test('shape-copies, field substitutions, and later request replay cannot inspect caller-selected names', async t => {
  const instance = await fresh(t); let calls = 0; const probe = adapter(() => { calls++; }, () => { calls++; }); let stale;
  await instance.preflight({ async probe(request) {
    stale = request;
    for (const copy of [{ ...request }, { ...request, context: 'remote' }, { ...request, startVm: true },
      { ...request, pull: true }, { ...request, build: true }, { ...request, images: [] },
      { ...request, ports: [{ host: '0.0.0.0', port: 5500 }] },
      { ...request, resources: [{ kind: 'container', name: 'retained' }] }]) await assert.rejects(probe(copy), PREFLIGHT_FAILURE);
    return syntheticProbe(request);
  } });
  await assert.rejects(probe(stale), PREFLIGHT_FAILURE); assert.equal(calls, 0);
});

test('unavailable Docker transport or daemon fails without inspecting images or probing ports', async t => {
  const instance = await fresh(t);
  for (const outcome of [() => { throw new Error('private daemon details'); },
    () => ({ exitCode: 1, stdout: '', stderr: 'Cannot connect to the Docker daemon' }),
    () => ({ exitCode: 125, stdout: '', stderr: 'context unavailable' })]) {
    let calls = 0; let portCalls = 0;
    await assert.rejects(instance.preflight({ probe: adapter(args => { calls++; return outcome(args); }, () => { portCalls++; }) }), FOUNDATION_FAILURE);
    assert.equal(calls, 1); assert.equal(portCalls, 0); assert.equal(instance.summary().preflight, 'NOT_ACCEPTED');
  }
});

test('Docker engine must be stable numeric version 28 or later on Linux ARM64', async t => {
  const instance = await fresh(t);
  for (const value of [{ ...engine(), version: '27.5.1' }, { ...engine(), version: '28' },
    { ...engine(), version: '28.0.0-rc.1' }, { ...engine(), version: '28.0.0+local' },
    { ...engine(), version: '028.0.0' }, { ...engine(), version: 28 }, { ...engine(), version: '99999.0.0' },
    { ...engine(), os: 'darwin' }, { ...engine(), architecture: 'amd64' }]) {
    let calls = 0;
    await assert.rejects(instance.preflight({ probe: adapter(args => { calls++; return args[0] === 'version' ? ok(value) : fakeExecutor(args); }) }), FOUNDATION_FAILURE);
    assert.equal(calls, 1);
  }
  for (const version of ['28.0.0', '28.5.1', '29.1.4']) {
    await instance.preflight({ probe: adapter(args => args[0] === 'version' ? ok({ ...engine(), version }) : fakeExecutor(args)) });
  }
});

test('engine output rejects unknown fields, duplicate keys, malformed JSON and mixed output', async t => {
  const instance = await fresh(t);
  const outputs = ['not json', '[]', '{}', '{"os":"darwin","os":"linux","architecture":"arm64","version":"28.5.1"}',
    JSON.stringify({ ...engine(), private: 'unexpected' }), JSON.stringify(engine()) + '\n' + JSON.stringify(engine()),
    '{ "os":"linux","architecture":"arm64","version":"28.5.1"}', JSON.stringify(engine()) + '\nprivate log'];
  for (const stdout of outputs) {
    await assert.rejects(instance.preflight({ probe: adapter(args => args[0] === 'version' ? { exitCode: 0, stdout, stderr: '' } : fakeExecutor(args)) }), FOUNDATION_FAILURE);
  }
});

test('bounded transport results reject oversized data, getters, buffers, NULs, signals and extra properties', async t => {
  const instance = await fresh(t); let reads = 0;
  for (const value of [{ exitCode: 0, stdout: 'x'.repeat(4097), stderr: '' },
    { exitCode: 0, stdout: JSON.stringify(engine()), stderr: 'x'.repeat(4097) },
    { exitCode: 0, stdout: JSON.stringify(engine()), stderr: 'unexpected warning' },
    { exitCode: 0, stdout: JSON.stringify(engine()) + '\0', stderr: '' },
    { exitCode: 0, stdout: Buffer.from('{}'), stderr: '' },
    { exitCode: null, stdout: '', stderr: '' }, { exitCode: -1, stdout: '', stderr: '' },
    { exitCode: 256, stdout: '', stderr: '' }, { exitCode: 0, stdout: '{}', stderr: '', killed: false },
    { exitCode: 0, get stdout() { reads++; }, stderr: '' }, new Proxy({}, { getPrototypeOf() { reads++; } })]) {
    await assert.rejects(instance.preflight({ probe: adapter(() => value) }), FOUNDATION_FAILURE);
  }
  assert.equal(reads, 0);
});

test('missing or drifted pinned images stop before resource checks and never trigger pull or build', async t => {
  const instance = await fresh(t);
  for (const imageResult of [() => ({ exitCode: 1, stdout: '', stderr: 'No such image' }),
    args => ok({ id: 'sha256:' + 'f'.repeat(64), os: 'linux', architecture: 'arm64' }),
    args => ok({ id: args[2], os: 'linux', architecture: 'amd64' }),
    args => ok({ id: args[2], os: 'windows', architecture: 'arm64' }),
    args => ok({ id: args[2], os: 'linux', architecture: 'arm64', env: [] })]) {
    const calls = [];
    await assert.rejects(instance.preflight({ probe: adapter(args => {
      calls.push([...args]); return args[0] === 'image' ? imageResult(args) : fakeExecutor(args);
    }) }), FOUNDATION_FAILURE);
    assert.equal(calls.length, 2); assert.deepEqual(calls.map(args => args[0]), ['version', 'image']);
  }
});

test('existing exact-name containers, networks or volumes are never adopted', async t => {
  const instance = await fresh(t);
  for (const kind of ['container', 'network', 'volume']) {
    let portCalls = 0;
    await assert.rejects(instance.preflight({ probe: adapter(args => {
      if (args[0] !== kind) return fakeExecutor(args);
      return ok(kind === 'volume' ? { name: args[2] } : { name: kind === 'container' ? '/' + args[2] : args[2], id: 'a'.repeat(64) });
    }, () => { portCalls++; return true; }) }), FOUNDATION_FAILURE);
    assert.equal(portCalls, 0);
  }
});

test('absence requires exact name-bound diagnostics rather than arbitrary errors, substrings or mixed output', async t => {
  const instance = await fresh(t);
  for (const mutate of [result => ({ ...result, exitCode: 2 }), result => ({ ...result, stderr: 'permission denied' }),
    result => ({ ...result, stderr: 'Error: No such container: retained' }),
    result => ({ ...result, stderr: result.stderr + 'connection failed' }),
    result => ({ ...result, stdout: '[]' }), result => ({ ...result, stdout: '\n' }),
    result => ({ ...result, stderr: 'prefix ' + result.stderr })]) {
    await assert.rejects(instance.preflight({ probe: adapter(args => {
      const result = fakeExecutor(args); return args[0] === 'container' ? mutate(result) : result;
    }) }), FOUNDATION_FAILURE);
  }
});

test('supported absent-object diagnostic variants remain strictly scoped to the same new name', async t => {
  const instance = await fresh(t);
  for (const mode of ['generic', 'typed', 'daemon-container']) {
    await instance.preflight({ probe: adapter(args => {
      const result = fakeExecutor(args); if (result.exitCode === 0) return result;
      if (mode === 'generic') return { ...result, stderr: `Error: No such object: ${args[2]}\n` };
      if (mode === 'typed') return { ...result, stderr: `Error: No such ${args[0]}: ${args[2]}\n` };
      if (args[0] === 'container') return { ...result, stderr: `Error response from daemon: No such container: ${args[2]}\n` };
      return result;
    }) });
  }
});

test('occupied or uncertain loopback bind probes fail closed without querying the owning service', async t => {
  const instance = await fresh(t);
  for (const unavailable of [5500, 8101, 8103, 33080]) {
    const ports = [];
    await assert.rejects(instance.preflight({ probe: adapter(fakeExecutor, input => {
      ports.push(input.port); return input.port !== unavailable;
    }) }), FOUNDATION_FAILURE);
    assert.equal(ports.at(-1), unavailable);
  }
  for (const value of [undefined, null, 1, 'true', { free: true }]) {
    await assert.rejects(instance.preflight({ probe: adapter(fakeExecutor, () => value) }), FOUNDATION_FAILURE);
  }
  await assert.rejects(instance.preflight({ probe: adapter(fakeExecutor, () => { throw new Error('private owner data'); }) }), FOUNDATION_FAILURE);
});

test('successful preflight is repeated by foundation immediately before startup rather than cached', async t => {
  const instance = await fresh(t); let versionCalls = 0; let mutations = 0;
  const probe = adapter(args => {
    if (args[0] === 'version' && ++versionCalls === 2) return { exitCode: 1, stdout: '', stderr: 'daemon unavailable now' };
    return fakeExecutor(args);
  });
  await instance.preflight({ probe });
  await assert.rejects(instance.start({ driver() { mutations++; } }), FOUNDATION_FAILURE);
  assert.equal(versionCalls, 2); assert.equal(mutations, 0); assert.equal(instance.summary().startAttempted, false);
});

test('owned-file drift during a metadata callback invalidates the brand before subsequent commands', async t => {
  const instance = await fresh(t); let calls = 0;
  await assert.rejects(instance.preflight({ probe: adapter(async args => {
    calls++; await writeFile(join(instance.privateDirectory, 'credentials.json'), 'changed'); return fakeExecutor(args);
  }) }), FOUNDATION_FAILURE);
  assert.equal(calls, 1);
});

test('stop during pending metadata invalidates authority before any next command or port check', async t => {
  const instance = await fresh(t); let release; const wait = new Promise(resolve => { release = resolve; });
  let entered; const active = new Promise(resolve => { entered = resolve; }); let calls = 0; let portCalls = 0;
  const pending = instance.preflight({ probe: adapter(async args => {
    calls++; entered(); await wait; return fakeExecutor(args);
  }, () => { portCalls++; return true; }) });
  await active; await assert.rejects(instance.stop({ driver() { throw new Error('not called'); } }), FOUNDATION_FAILURE);
  release(); await assert.rejects(pending, FOUNDATION_FAILURE);
  assert.equal(calls, 1); assert.equal(portCalls, 0); assert.equal(instance.summary().preflight, 'NOT_ACCEPTED');
  await instance.stop({ driver() { throw new Error('not called'); } });
});

test('reentrant adapter invocation fails before a second metadata command', async t => {
  const instance = await fresh(t); let current; let calls = 0; let probe;
  probe = adapter(async args => { calls++; await assert.rejects(probe(current), PREFLIGHT_FAILURE); return fakeExecutor(args); });
  await instance.preflight({ async probe(request) { current = request; return probe(request); } }); assert.equal(calls, 7);
});

test('adapter errors remain aggregate-only and never forward raw CLI output or private resource names', async t => {
  const instance = await fresh(t);
  await assert.rejects(instance.preflight({ async probe(request) {
    await assert.rejects(adapter(() => { throw new Error('SUPER_PRIVATE_RAW_CLI_OUTPUT ' + request.resources[0].name); })(request), error => {
      assert.match(error.message, PREFLIGHT_FAILURE); assert.doesNotMatch(error.message, /SUPER_PRIVATE|fncp-fresh-/u); return true;
    });
    throw new Error('stop outer test');
  } }), FOUNDATION_FAILURE);
});

test('source contract excludes broad listing, mutation, configuration reads, remote fetches and environment overrides', async () => {
  const source = await readFile(new URL('./docker-preflight.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /command\(\[['"](?:ps|ls|pull|build|run|start|create|context|logs|exec|stop|rm|prune)['"]|process\.env|readFile|\bfetch\s*\(|\.connect\(/u);
  assert.match(source, /verifyFreshPolisRequest\(request\)/u);
  assert.match(source, /Number\(engine\.version\.split\('\.'\)\[0\]\) < 28/u);
  assert.match(source, /exclusive: true, signal: controller\.signal/u);
});
