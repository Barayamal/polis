import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, readdir, rm, lstat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { EventEmitter } from 'node:events';
import { createFreshPolisFoundation } from './foundation.mjs';
import { createDockerLifecycle } from './docker-lifecycle.mjs';
import { createDockerTransport } from './docker-cli.mjs';

const FAILURE = /Fresh (?:Docker lifecycle|synthetic foundation boundary) failed; new private state preserved\./u;
const PG = 'sha256:9d9684f7a95e94c9eb370212edea832e7b9916b7bd96b2821c5bc9cf63a0e8b3';
const API = 'sha256:07f8a21105ed90963ccdf0981d884323116187583a464bb581db14c621d33a98';
const ids = { network: 'c'.repeat(64), postgres: 'a'.repeat(64), server: 'b'.repeat(64) };
const copy = value => JSON.parse(JSON.stringify(value));
const result = stdout => ({ exitCode: 0, stdout: typeof stdout === 'string' ? stdout : JSON.stringify(stdout), stderr: '' });
const successProbe = request => ({ context: request.context, running: true, images: request.images.map(item => ({ ...item })),
  ports: request.ports.map(item => ({ ...item, free: true })), resources: request.resources.map(item => ({ ...item, absent: true })) });
const matches = (args, prefix) => prefix.every((value, index) => args[index] === value);
function options(args, key) {
  return args.flatMap((arg, index) => arg === key ? [args[index + 1]] : arg.startsWith(key + '=') ? [arg.slice(key.length + 1)] : []);
}
const option = (args, key) => options(args, key)[0];
const labels = args => Object.fromEntries(options(args, '--label').map(value => [value.slice(0, value.indexOf('=')), value.slice(value.indexOf('=') + 1)]));

/** No Docker or network operations. Metadata is built from the actual command
 * argv, so positive tests do not simply return the driver's desired response. */
function fakeDocker(hooks = {}) {
  const state = { calls: [], containers: new Map(), network: null, volume: null };
  async function execute(args) {
    state.calls.push([...args]);
    if (hooks.before) { const override = await hooks.before(args, state); if (override !== undefined) return override; }
    let output;
    if (matches(args, ['image', 'inspect'])) {
      output = { id: args[2], os: 'linux', architecture: 'arm64', volumes: args[2] === PG ? { '/var/lib/postgresql/data': {} } : null };
    } else if (matches(args, ['network', 'create'])) {
      assert.equal(option(args, '--driver'), 'bridge'); assert.equal(args.includes('--internal'), true);
      state.network = { id: ids.network, name: args.at(-1), driver: option(args, '--driver'), scope: 'local',
        internal: args.includes('--internal'), ipv6: option(args, '--ipv6') === 'true', labels: labels(args),
        options: Object.fromEntries(options(args, '--opt').map(value => [value.slice(0, value.indexOf('=')), value.slice(value.indexOf('=') + 1)])), containers: {} };
      output = state.network.id;
    } else if (matches(args, ['network', 'inspect'])) {
      assert.equal(args[2], ids.network); output = copy(state.network);
    } else if (matches(args, ['volume', 'create'])) {
      state.volume = { name: args.at(-1), driver: option(args, '--driver'), scope: 'local', labels: labels(args), options: null,
        createdAt: '2026-09-13T00:00:00Z' }; output = state.volume.name;
    } else if (matches(args, ['volume', 'inspect'])) {
      assert.equal(args[2], state.volume.name); output = copy(state.volume);
    } else if (matches(args, ['container', 'create'])) {
      const image = args.at(-1); assert.ok([PG, API].includes(image));
      const role = image === PG ? 'postgres' : 'server';
      const mounts = options(args, '--mount').map(text => {
        const fields = Object.fromEntries(text.split(',').map(part => part.includes('=') ? part.split('=') : [part, true]));
        return { Type: fields.type, ...(fields.type === 'volume' ? { Name: fields.src } : { Source: fields.src }),
          Destination: fields.dst, RW: !fields.readonly };
      });
      const ports = {};
      for (const published of options(args, '--publish')) {
        const match = /^(127\.0\.0\.1):(\d+):(\d+)\/tcp$/u.exec(published); assert.ok(match);
        ports[match[3] + '/tcp'] = [{ HostIp: match[1], HostPort: match[2] }];
      }
      const item = { id: ids[role], name: '/' + option(args, '--name'), image, labels: labels(args), state: 'created', running: false,
        networkMode: option(args, '--network'), networks: { [state.network.name]: { NetworkID: hooks.createdEndpointUnresolved ? '' : state.network.id } },
        ports, mounts, privileged: args.includes('--privileged'), readonly: args.includes('--read-only'), capAdd: options(args, '--cap-add'),
        capDrop: options(args, '--cap-drop'), security: options(args, '--security-opt'), restart: { Name: option(args, '--restart'), MaximumRetryCount: 0 },
        user: option(args, '--user'), pidMode: '', ipcMode: 'private', devices: [], extraHosts: [], dns: [],
        tmpfs: Object.fromEntries(options(args, '--tmpfs').map(value => [value.slice(0, value.indexOf(':')), value.slice(value.indexOf(':') + 1)])),
        memory: Number.parseInt(option(args, '--memory'), 10) * 1024 * 1024, pidsLimit: Number(option(args, '--pids-limit')) };
      state.containers.set(item.id, item); output = item.id;
    } else if (matches(args, ['container', 'inspect'])) {
      assert.match(args[2], /^[a-f0-9]{64}$/u); output = copy(state.containers.get(args[2]));
    } else if (matches(args, ['container', 'start'])) {
      const item = state.containers.get(args[2]); assert.ok(item); item.running = true; item.state = 'running';
      item.networks[state.network.name].NetworkID = state.network.id;
      state.network.containers[item.id] = { Name: item.name.slice(1) }; output = item.id;
    } else if (matches(args, ['container', 'stop'])) {
      assert.deepEqual(args.slice(0, 4), ['container', 'stop', '--time', '10']);
      const item = state.containers.get(args[4]); assert.ok(item); item.running = false; item.state = 'exited';
      delete state.network.containers[item.id]; output = item.id;
    } else assert.fail('Unexpected fake Docker command');
    if (hooks.inspect && typeof output === 'object') await hooks.inspect(args, output, state);
    const response = result(output);
    return hooks.after ? await hooks.after(args, response, state) ?? response : response;
  }
  return { execute, state, commands: prefix => state.calls.filter(args => matches(args, prefix)) };
}

async function own(t, factory) {
  const value = await factory();
  // Factories create only this test's exclusive private files. Every executor
  // here is fake; cleanup cannot target a container, retained store or volume.
  t.after(() => rm(value.privateDirectory, { recursive: true, force: true })); return value;
}

/** Model a future complete local input in a newly owned isolated module copy.
 * Only the three fixed missing AUTH/JWKS literals are substituted. Production
 * source, source guards, request branding and validators stay unchanged. The
 * stub transport throws if accidentally selected; no actual issuer exists. */
async function fixture(t, hooks = {}, wrapExecute = execute => execute) {
  const directory = await mkdtemp(join(tmpdir(), 'fncp-docker-lifecycle-model-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const runtime = join(directory, 'fresh-runtime'); await mkdir(runtime);
  let foundation = await readFile(new URL('./foundation.mjs', import.meta.url), 'utf8');
  for (const [before, after] of [["AUTH_ISSUER: ''", "AUTH_ISSUER: 'https://127.0.0.1:49199/'"],
    ["AUTH_AUDIENCE: ''", "AUTH_AUDIENCE: 'fncp-fresh-synthetic'"],
    ["JWKS_URI: ''", "JWKS_URI: 'https://127.0.0.1:49199/.well-known/jwks.json'"]]) {
    assert.equal(foundation.split(before).length, 2); foundation = foundation.replace(before, after);
  }
  await writeFile(join(runtime, 'foundation.mjs'), foundation, { flag: 'wx' });
  await writeFile(join(runtime, 'docker-lifecycle.mjs'), await readFile(new URL('./docker-lifecycle.mjs', import.meta.url)), { flag: 'wx' });
  await writeFile(join(directory, 'fresh-bootstrap-result.mjs'), await readFile(new URL('../fresh-bootstrap-result.mjs', import.meta.url)), { flag: 'wx' });
  await writeFile(join(runtime, 'docker-cli.mjs'), 'export async function runDocker() { throw new Error("Real Docker forbidden in model fixture"); }\n', { flag: 'wx' });
  const factories = await import(pathToFileURL(join(runtime, 'foundation.mjs')).href);
  const lifecycle = await import(pathToFileURL(join(runtime, 'docker-lifecycle.mjs')).href);
  const model = fakeDocker(hooks);
  const instance = await own(t, factories.createFreshPolisFoundation);
  const adapter = await own(t, () => lifecycle.createDockerLifecycle({ execute: wrapExecute(model.execute) }));
  await instance.preflight({ probe: successProbe });
  return { instance, adapter, model, makeFoundation: () => own(t, factories.createFreshPolisFoundation) };
}
const start = fixture => fixture.instance.start({ driver: fixture.adapter.driver });
async function journal(adapter) {
  const files = (await readdir(adapter.privateDirectory)).filter(name => name.startsWith('ledger-')).sort();
  return Promise.all(files.map(name => readFile(join(adapter.privateDirectory, name), 'utf8').then(JSON.parse)));
}
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };

test('real foundation missing AUTH/JWKS is rejected before any injected Docker command', async t => {
  const instance = await own(t, createFreshPolisFoundation); const model = fakeDocker();
  const adapter = await own(t, () => createDockerLifecycle({ execute: model.execute }));
  await instance.preflight({ probe: successProbe });
  await assert.rejects(instance.start({ driver: adapter.driver }), FAILURE);
  assert.equal(model.state.calls.length, 0); assert.equal(adapter.summary().networkCreateAttempted, false);
  assert.equal((await adapter.close()).stoppedContainers, 0);
});

test('constructor forbids arbitrary path/config adoption and inert inputs never invoke getters', async () => {
  let reads = 0;
  for (const value of [undefined, null, {}, { execute: async () => {}, path: '/tmp/retained' },
    { get execute() { reads++; } }, { execute: new Proxy(() => {}, {}) }, new Proxy({}, { get() { reads++; } })]) {
    await assert.rejects(createDockerLifecycle(value), FAILURE);
  }
  assert.equal(reads, 0);
});

test('only active authentic foundation requests work; copies, replay and second-instance adoption fail', async t => {
  const f = await fixture(t); let saved;
  await f.instance.start({ driver: async request => {
    saved = request; const before = f.model.state.calls.length;
    await assert.rejects(f.adapter.driver({ ...request }), FAILURE);
    assert.equal(f.model.state.calls.length, before); return f.adapter.driver(request);
  } });
  const before = f.model.state.calls.length; await assert.rejects(f.adapter.driver(saved), FAILURE);
  const other = await f.makeFoundation(); await other.preflight({ probe: successProbe });
  await assert.rejects(other.start({ driver: f.adapter.driver }), FAILURE);
  assert.equal(f.model.state.calls.length, before); await f.adapter.close();
});

test('successful model creation records owned IDs before start and closes exact IDs in reverse order', async t => {
  const mutationRecords = [];
  const f = await fixture(t, { async before(args) {
    const expected = matches(args, ['network', 'create']) ? 'NETWORK_CREATE_ATTEMPTED'
      : matches(args, ['volume', 'create']) ? 'VOLUME_CREATE_ATTEMPTED'
        : matches(args, ['container', 'create']) ? 'CONTAINER_CREATE_ATTEMPTED'
          : matches(args, ['container', 'start']) ? 'CONTAINER_START_ATTEMPTED'
            : matches(args, ['container', 'stop']) ? 'CONTAINER_STOP_ATTEMPTED' : null;
    if (expected) { assert.equal((await journal(f.adapter)).at(-1).event, expected); mutationRecords.push(expected); }
  } });
  await start(f);
  assert.equal(f.adapter.summary().containerIdentitiesCaptured, 2);
  const entries = await journal(f.adapter);
  for (const role of ['postgres', 'server']) {
    const captured = entries.findIndex(e => e.event === 'CONTAINER_ID_CAPTURED' && e.role === role);
    const started = entries.findIndex(e => e.event === 'CONTAINER_START_ATTEMPTED' && e.role === role);
    assert.ok(captured >= 0); assert.ok(started > captured);
  }
  assert.equal(f.model.commands(['network', 'create']).length, 1); assert.equal(f.model.commands(['volume', 'create']).length, 1);
  const closed = await f.adapter.close(); assert.equal(closed.stoppedContainers, 2);
  assert.deepEqual(f.model.commands(['container', 'stop']).map(args => args.at(-1)), [ids.server, ids.postgres]);
  const commands = f.model.state.calls.length; assert.deepEqual(await f.adapter.close(), closed);
  assert.equal(f.model.state.calls.length, commands);
  assert.equal(mutationRecords.length, 8);
  assert.equal(f.model.state.calls.some(args => args.some(part => ['rm', 'prune', 'down', 'pull', 'build'].includes(part))), false);
});

test('complete fake lifecycle also crosses the real fixed Docker transport argv grammar without Docker execution', async t => {
  let spawnCalls = 0;
  const f = await fixture(t, {}, execute => createDockerTransport({ spawnProcess(executable, args, configuration) {
    spawnCalls++; assert.equal(executable, '/opt/homebrew/bin/docker');
    assert.deepEqual(args.slice(0, 3), ['--host', 'unix:///Users/deansosupremo/.colima/fncp-c-20260913/docker.sock', '--config']);
    assert.equal(configuration.shell, false); assert.equal(configuration.cwd, args[3]);
    const child = new EventEmitter(); child.stdout = new EventEmitter(); child.stderr = new EventEmitter(); child.kill = () => true;
    queueMicrotask(async () => {
      try {
        const response = await execute(args.slice(4));
        child.stdout.emit('data', Buffer.from(response.stdout)); child.stderr.emit('data', Buffer.from(response.stderr));
        child.emit('close', response.exitCode, null);
      } catch { child.emit('close', 1, null); }
    });
    return child;
  } }));
  await start(f); await f.adapter.close();
  assert.equal(spawnCalls, f.model.state.calls.length); assert.ok(spawnCalls > 20);
  assert.equal(f.model.commands(['container', 'create']).length, 2); assert.equal(f.model.commands(['container', 'stop']).length, 2);
});

test('created exact-name unresolved endpoint is verified before start then resolves to the owned network ID', async t => {
  const f = await fixture(t, { createdEndpointUnresolved: true });
  await start(f); assert.equal(f.model.commands(['container', 'start']).length, 2); await f.adapter.close();
});

test('already-exited owned containers are independent-close no-ops without another stop dispatch', async t => {
  const f = await fixture(t); await start(f);
  for (const item of f.model.state.containers.values()) { item.running = false; item.state = 'exited'; }
  f.model.state.network.containers = {};
  assert.equal((await f.adapter.close()).stoppedContainers, 2);
  assert.equal(f.model.commands(['container', 'stop']).length, 0);
});

test('create success followed by uncertain start keeps exact ID available to independent cleanup', async t => {
  let failOnce = true;
  const f = await fixture(t, { after(args) { if (failOnce && matches(args, ['container', 'start'])) { failOnce = false; throw new Error('private-start-details'); } } });
  await assert.rejects(start(f), FAILURE);
  assert.equal(f.instance.summary().verifiedContainers, 0); assert.equal(f.adapter.summary().containerIdentitiesCaptured, 1);
  assert.equal((await f.adapter.close()).stoppedContainers, 1);
  assert.deepEqual(f.model.commands(['container', 'stop']).map(args => args.at(-1)), [ids.postgres]);
  assert.equal(f.model.commands(['container', 'create']).length, 1);
});

test('uncertain create is preserved and never rediscovered or automatically replayed by name', async t => {
  const f = await fixture(t, { after(args) { if (matches(args, ['container', 'create'])) throw new Error('private-create-details'); } });
  await assert.rejects(start(f), FAILURE); assert.equal(f.adapter.summary().uncertainContainerCreates, 1);
  await assert.rejects(f.adapter.close(), FAILURE); const count = f.model.state.calls.length;
  await assert.rejects(f.adapter.close(), FAILURE); assert.equal(f.model.state.calls.length, count);
  assert.equal(f.model.commands(['container', 'create']).length, 1); assert.equal(f.model.commands(['container', 'inspect']).length, 0);
});

test('unknown network or volume create results remain uncertain and never trigger adoption or mutation replay', async t => {
  for (const kind of ['network', 'volume']) {
    const f = await fixture(t, { after(args) { if (matches(args, [kind, 'create'])) throw new Error('private-infrastructure-details'); } });
    await assert.rejects(start(f), FAILURE); assert.equal(f.adapter.summary().uncertainInfrastructureCreates, 1);
    assert.equal(f.model.commands(['container', 'create']).length, 0);
    await assert.rejects(f.adapter.close(), FAILURE); const count = f.model.state.calls.length;
    await assert.rejects(f.adapter.close(), FAILURE); assert.equal(f.model.state.calls.length, count);
    assert.equal(f.model.commands([kind, 'create']).length, 1);
    assert.equal(f.model.commands([kind, 'inspect']).length, 0);
  }
});

test('read-only cleanup inspection failure can be retried while other owned stops still complete', async t => {
  let closing = false; let failed = false;
  const f = await fixture(t, { before(args) {
    if (closing && !failed && matches(args, ['container', 'inspect', ids.server])) { failed = true; throw new Error('private-inspect-details'); }
  } });
  await start(f); closing = true; await assert.rejects(f.adapter.close(), FAILURE);
  assert.deepEqual(f.model.commands(['container', 'stop']).map(args => args.at(-1)), [ids.postgres]);
  assert.equal((await f.adapter.close()).stoppedContainers, 2);
  assert.deepEqual(f.model.commands(['container', 'stop']).map(args => args.at(-1)), [ids.postgres, ids.server]);
});

test('uncertain dispatched stop is not repeated even when the underlying model stopped successfully', async t => {
  let failed = false;
  const f = await fixture(t, { after(args) {
    if (!failed && matches(args, ['container', 'stop']) && args.at(-1) === ids.server) { failed = true; throw new Error('private-stop-details'); }
  } });
  await start(f); await assert.rejects(f.adapter.close(), FAILURE);
  assert.equal(f.adapter.summary().uncertainStopDispatches, 1); assert.equal(f.adapter.summary().stoppedContainers, 1);
  const count = f.model.state.calls.length; await assert.rejects(f.adapter.close(), FAILURE);
  assert.equal(f.model.state.calls.length, count); assert.equal(f.model.commands(['container', 'stop']).length, 2);
});

test('close latches during pending create and captures late ID without later start or second-container creation', async t => {
  const entered = deferred(); const release = deferred();
  const f = await fixture(t, { async after(args, response) {
    if (matches(args, ['container', 'create'])) { entered.resolve(); await release.promise; } return response;
  } });
  const running = start(f); const rejected = assert.rejects(running, FAILURE);
  await entered.promise; await assert.rejects(f.adapter.close(), FAILURE); release.resolve(); await rejected;
  assert.equal(f.adapter.summary().containerIdentitiesCaptured, 1);
  assert.equal(f.model.commands(['container', 'start']).length, 0); assert.equal(f.model.commands(['container', 'create']).length, 1);
  assert.equal((await f.adapter.close()).stoppedContainers, 1);
});

test('unexpected image-declared volumes are rejected before network creation', async t => {
  const f = await fixture(t, { inspect(args, item) { if (matches(args, ['image', 'inspect'])) item.volumes['/unexpected-retained-data'] = {}; } });
  await assert.rejects(start(f), FAILURE); assert.equal(f.model.commands(['network', 'create']).length, 0); await f.adapter.close();
});

test('network nonce, exact ID, isolation options and foreign membership are independently required', async t => {
  for (const mutate of [item => { item.labels['org.barayamal.fncp.adapter'] = 'wrong'; }, item => { item.id = 'd'.repeat(64); },
    item => { item.internal = false; }, item => { item.options['com.docker.network.bridge.gateway_mode_ipv4'] = 'nat'; },
    item => { item.containers['f'.repeat(64)] = { Name: 'unowned' }; }]) {
    const f = await fixture(t, { inspect(args, item) { if (matches(args, ['network', 'inspect'])) mutate(item); } });
    await assert.rejects(start(f), FAILURE); assert.equal(f.model.commands(['container', 'create']).length, 0);
    assert.equal(f.adapter.summary().networkIdentityCaptured, true); await f.adapter.close();
  }
});

test('volume nonce, local driver, options and creation identity cannot be substituted', async t => {
  for (const mutate of [item => { item.labels['org.barayamal.fncp.adapter'] = 'wrong'; }, item => { item.driver = 'nfs'; },
    item => { item.options = { type: 'none', device: '/retained', o: 'bind' }; }, item => { item.createdAt = 'invalid'; }]) {
    const f = await fixture(t, { inspect(args, item) { if (matches(args, ['volume', 'inspect'])) mutate(item); } });
    await assert.rejects(start(f), FAILURE); assert.equal(f.model.commands(['container', 'create']).length, 0);
    assert.equal(f.adapter.summary().uncertainInfrastructureCreates, 1); await assert.rejects(f.adapter.close(), FAILURE);
  }
});

test('captured volume creation identity is rechecked and changed identity cannot authorize process start or cleanup', async t => {
  let checks = 0; let drift = true;
  const f = await fixture(t, { inspect(args, item) {
    if (matches(args, ['volume', 'inspect']) && ++checks > 1 && drift) item.createdAt = '2026-09-14T00:00:00Z';
  } });
  await assert.rejects(start(f), FAILURE); assert.equal(f.model.commands(['container', 'start']).length, 0);
  await assert.rejects(f.adapter.close(), FAILURE); assert.equal(f.model.commands(['container', 'stop']).length, 0);
  drift = false; assert.equal((await f.adapter.close()).stoppedContainers, 1);
});

test('container image, nonce, network, ports, mounts and security drift fail before process start', async t => {
  for (const mutate of [item => { item.image = 'sha256:' + 'f'.repeat(64); }, item => { item.labels['org.barayamal.fncp.adapter'] = 'wrong'; },
    item => { item.networkMode = 'host'; }, item => { item.networks.extra = { NetworkID: 'f'.repeat(64) }; },
    item => { item.ports = { '5432/tcp': [{ HostIp: '0.0.0.0', HostPort: '5432' }] }; },
    item => { item.mounts[0].Name = 'retained'; }, item => { item.privileged = true; }, item => { item.readonly = false; },
    item => { item.capAdd = ['SYS_ADMIN']; }, item => { item.security = []; }, item => { item.restart.Name = 'always'; }]) {
    let drift = true;
    const f = await fixture(t, { inspect(args, item) { if (drift && matches(args, ['container', 'inspect'])) mutate(item); } });
    await assert.rejects(start(f), FAILURE); assert.equal(f.model.commands(['container', 'start']).length, 0);
    drift = false; assert.equal((await f.adapter.close()).stoppedContainers, 1);
  }
});

test('duplicate JSON keys and extra projected container fields cannot conceal security state', async t => {
  for (const change of [text => text.replace('"privileged":false', '"privileged":true,"privileged":false'),
    text => JSON.stringify({ ...JSON.parse(text), unexpectedProjection: true })]) {
    let drift = true;
    const f = await fixture(t, { after(args, response) {
      if (drift && matches(args, ['container', 'inspect'])) return { ...response, stdout: change(response.stdout) };
      return response;
    } });
    await assert.rejects(start(f), FAILURE);
    assert.equal(f.model.commands(['container', 'start']).length, 0);
    await assert.rejects(f.adapter.close(), FAILURE);
    assert.equal(f.model.commands(['container', 'stop']).length, 0);
    drift = false; assert.equal((await f.adapter.close()).stoppedContainers, 1);
  }
});

test('adapter private-file tampering blocks subsequent commands and never adopts replacement state', async t => {
  const f = await fixture(t); const path = join(f.adapter.privateDirectory, 'ownership.json');
  assert.equal((await lstat(path)).mode & 0o777, 0o600);
  await writeFile(path, 'tampered private fixture'); await assert.rejects(start(f), FAILURE);
  assert.equal(f.model.state.calls.length, 0); await assert.rejects(f.adapter.close(), FAILURE);
});

test('untrusted executor responses and diagnostics cannot escape the bounded lifecycle error', async t => {
  const marker = 'PRIVATE_DIAGNOSTIC_MUST_NOT_LEAK';
  for (const response of [{ exitCode: 0, stdout: '{}', stderr: marker }, { exitCode: 1, stdout: marker, stderr: '' },
    { exitCode: 0, stdout: marker.repeat(4000), stderr: '' }, { exitCode: 0, stdout: '{}', stderr: '', extra: marker }]) {
    const f = await fixture(t, { before() { return response; } });
    await assert.rejects(start(f), error => FAILURE.test(error.message) && !error.message.includes(marker));
    assert.equal(f.model.commands(['network', 'create']).length, 0); await f.adapter.close();
  }
});

test('aggregate evidence does not expose generated paths, names, nonce or credentials or claim real assurance', async t => {
  const f = await fixture(t); await start(f);
  const config = JSON.parse(await readFile(join(f.instance.privateDirectory, 'initial-config.json'), 'utf8'));
  const ownership = JSON.parse(await readFile(join(f.adapter.privateDirectory, 'ownership.json'), 'utf8'));
  const summary = f.adapter.summary(); const serialized = JSON.stringify(summary);
  for (const value of [f.instance.privateDirectory, f.adapter.privateDirectory, ownership.nonce, ...Object.values(config.names),
    config.environment.DATABASE_URL, config.environment.FNCP_GATEWAY_SHARED_SECRET]) assert.equal(serialized.includes(value), false);
  assert.equal(summary.transport, 'INJECTED_MODEL'); assert.equal(summary.actualNegativeEgressVerified, false);
  assert.equal(summary.applicationHealthVerified, false); assert.equal(summary.bootstrapImplemented, false); assert.equal(summary.activationGranted, false);
  assert.equal(summary.networkAndVolumePreserved, true); await f.adapter.close();
});
