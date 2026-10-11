import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { lstat, readdir, readFile, realpath, rename, rm, symlink, unlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createDockerTransport } from './docker-cli.mjs';

const ERROR = 'Fresh Docker transport failed; private process details withheld.';
const engine = '{"os":{{json .Server.Os}},"architecture":{{json .Server.Arch}},"version":{{json .Server.Version}}}';
const image = '{"id":{{json .Id}},"os":{{json .Os}},"architecture":{{json .Architecture}}}';
const named = '{"name":{{json .Name}},"id":{{json .Id}}}';
const version = ['version', '--format', engine];
const run = 'a'.repeat(24);
const id = 'b'.repeat(64);
const pins = ['sha256:9d9684f7a95e94c9eb370212edea832e7b9916b7bd96b2821c5bc9cf63a0e8b3',
  'sha256:07f8a21105ed90963ccdf0981d884323116187583a464bb581db14c621d33a98'];

// Every process in this file is invented. The actual Docker executable/socket is
// never invoked; real filesystem work is limited to new transport-owned configs.
function fixture() {
  let dispatch;
  const spawned = new Promise(resolve => { dispatch = resolve; });
  const child = new EventEmitter(); child.stdout = new PassThrough(); child.stderr = new PassThrough();
  const signals = []; let closed = false;
  child.kill = signal => { signals.push(signal); return true; };
  const transport = createDockerTransport({ spawnProcess(executable, args, options) {
    dispatch({ executable, args, options, directory: options.cwd }); return child;
  } });
  return { transport, spawned, child, signals, close(code = 0, signal = null) {
    closed = true; child.stdout.end(); child.stderr.end(); child.emit('close', code, signal);
  }, get closed() { return closed; } };
}
async function missing(path) { await assert.rejects(lstat(path), { code: 'ENOENT' }); }
async function rejected(promise) {
  await assert.rejects(promise, error => error.message === ERROR && error.cause === undefined &&
    !Object.hasOwn(error, 'stdout') && !Object.hasOwn(error, 'stderr') && !Object.hasOwn(error, 'args'));
}

test('fixed transport uses a fresh empty private Docker config and no ambient account/context environment', async () => {
  const f = fixture(); const promise = f.transport(Object.freeze(version));
  const call = await f.spawned;
  assert.equal(call.executable, '/opt/homebrew/bin/docker');
  assert.deepEqual(call.args, ['--host', 'unix:///Users/deansosupremo/.colima/fncp-c-20260913/docker.sock',
    '--config', call.directory, ...version]);
  assert.match(call.directory, /\/fncp-docker-cli-[a-zA-Z0-9]+$/u);
  assert.equal((await lstat(call.directory)).mode & 0o777, 0o700);
  assert.deepEqual(await readdir(call.directory), []);
  assert.deepEqual(call.options, { cwd: call.directory,
    env: { PATH: '/opt/homebrew/bin:/usr/bin:/bin', LANG: 'C', LC_ALL: 'C', DOCKER_CLI_HINTS: 'false' },
    shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
  f.child.stdout.write('model-only'); f.close();
  const result = await promise;
  assert.deepEqual(result, { exitCode: 0, stdout: 'model-only', stderr: '' });
  assert.equal(Object.isFrozen(result), true); await missing(call.directory);
});

test('separate concurrent commands never share config directories and cleanup waits for actual close', async () => {
  const a = fixture(); const b = fixture(); const pa = a.transport(version); const pb = b.transport(version);
  const ca = await a.spawned; const cb = await b.spawned;
  assert.notEqual(ca.directory, cb.directory);
  await writeFile(join(ca.directory, 'new-model-only-config'), 'model-only', { flag: 'wx', mode: 0o600 });
  a.child.emit('exit', 0, null);
  assert.equal((await lstat(ca.directory)).isDirectory(), true);
  a.close(); await pa; await missing(ca.directory);
  assert.equal((await lstat(cb.directory)).isDirectory(), true);
  b.close(); await pb; await missing(cb.directory);
});

test('normal bounded nonzero exit returns private output for exact absence classification', async () => {
  const f = fixture(); const promise = f.transport(['container', 'inspect', `fncp-fresh-pg-${run}`, '--format', named]);
  const call = await f.spawned;
  f.child.stderr.write(`Error: No such container: fncp-fresh-pg-${run}\n`); f.close(1);
  assert.deepEqual(await promise, { exitCode: 1, stdout: '', stderr: `Error: No such container: fncp-fresh-pg-${run}\n` });
  await missing(call.directory);
});

test('allowlisted read-only projections and exact pinned start/stop arguments reach only the fake process', async () => {
  const commands = [version, ...pins.map(pin => ['image', 'inspect', pin, '--format', image]),
    ['container', 'inspect', `fncp-fresh-api-${run}`, '--format', named],
    ['network', 'inspect', `fncp-fresh-net-${run}`, '--format', named],
    ['volume', 'inspect', `fncp-fresh-data-${run}`, '--format', '{"name":{{json .Name}}}'],
    ['container', 'start', id], ['container', 'stop', '--time', '10', id]];
  for (const command of commands) {
    const f = fixture(); const promise = f.transport(command); const call = await f.spawned;
    assert.deepEqual(call.args.slice(4), command); f.close(); await promise; await missing(call.directory);
  }
});

function labels() { return ['--label', 'org.barayamal.fncp.purpose=fresh-synthetic-foundation-only',
  '--label', `org.barayamal.fncp.fresh-run=${run}`, '--label', 'org.barayamal.fncp.adapter=' + 'c'.repeat(48)]; }
function create(role, parent) {
  return ['container', 'create', '--name', `fncp-fresh-${role}-${run}`, ...labels(), '--pull=never', '--platform',
    'linux/arm64', '--network', id, '--restart=no', '--cap-drop=ALL', '--security-opt', 'no-new-privileges:true',
    '--pids-limit', '128', '--memory', '768m', '--user', role === 'pg' ? '70:70' : '501:20',
    '--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
    ...(role === 'pg' ? ['--tmpfs', '/var/run/postgresql:rw,nosuid,size=16m'] : []),
    '--env-file', join(parent, 'fncp-fresh-docker-MODEL1', role === 'pg' ? 'postgres.env' : 'server.env'),
    ...(role === 'pg' ? ['--mount', `type=volume,src=fncp-fresh-data-${run},dst=/var/lib/postgresql/data`]
      : ['--publish', '127.0.0.1:5500:5000/tcp',
        ...['private', 'public'].flatMap(key => ['--mount',
          `type=bind,src=${join(parent, 'fncp-fresh-polis-MODEL2', `jwt-${key}.pem`)},dst=/run/fncp/jwt-${key}.pem,readonly`])]),
    role === 'pg' ? pins[0] : pins[1]];
}
test('exact internal network, private volume and constrained per-role container grammar is accepted by fake spawn only', async () => {
  const parent = await realpath(tmpdir());
  const commands = [
    ['network', 'create', '--driver', 'bridge', '--internal', '--ipv6=false', '--opt',
      'com.docker.network.bridge.gateway_mode_ipv4=isolated', '--opt',
      'com.docker.network.bridge.enable_ip_masquerade=false', ...labels(), `fncp-fresh-net-${run}`],
    ['volume', 'create', '--driver', 'local', ...labels(), `fncp-fresh-data-${run}`],
    create('pg', parent), create('api', parent),
  ];
  for (const command of commands) {
    const f = fixture(); const promise = f.transport(command); const call = await f.spawned;
    assert.deepEqual(call.args.slice(4), command); f.close(); await promise; await missing(call.directory);
  }
});

test('all concrete lifecycle metadata projections match the transport allowlist without exposing env or keys', async () => {
  const source = await readFile(new URL('./docker-lifecycle.mjs', import.meta.url), 'utf8');
  for (const [constant, kind, subject] of [['IMAGE', 'image', pins[0]], ['NETWORK', 'network', id],
    ['VOLUME', 'volume', `fncp-fresh-data-${run}`], ['CONTAINER', 'container', id]]) {
    const format = new RegExp(`const ${constant}_FORMAT = '([^']+)';`, 'u').exec(source)?.[1];
    assert.equal(typeof format, 'string'); assert.doesNotMatch(format, /\.Env|PrivateKey|Credential/u);
    const f = fixture(); const command = [kind, 'inspect', subject, '--format', format];
    const promise = f.transport(command); const call = await f.spawned;
    assert.deepEqual(call.args.slice(4), command); f.close(); await promise; await missing(call.directory);
  }
});

test('container grammar rejects broad paths, root users, mismatched ownership, extra commands and weakened isolation', async () => {
  let calls = 0; const parent = await realpath(tmpdir());
  const execute = createDockerTransport({ spawnProcess() { calls++; throw new Error('must-not-spawn'); } });
  const model = create('api', parent);
  const change = (from, to) => model.map(item => item === from ? to : item);
  const bad = [
    change('fncp-fresh-api-' + run, 'fncp-fresh-api-' + 'd'.repeat(24)),
    change('org.barayamal.fncp.fresh-run=' + run, 'org.barayamal.fncp.fresh-run=' + 'd'.repeat(24)),
    change('org.barayamal.fncp.adapter=' + 'c'.repeat(48), 'org.barayamal.fncp.adapter=short'),
    change('--pull=never', '--pull=always'), change('linux/arm64', 'linux/amd64'), change(id, 'bridge'),
    change('--restart=no', '--restart=always'), change('--cap-drop=ALL', '--cap-add=ALL'),
    change('no-new-privileges:true', 'no-new-privileges:false'), change('128', '0'), change('768m', '8g'),
    change('501:20', '0:0'), change('501:20', 'root'), change('501:20', '4294967295:20'),
    change('--read-only', '--privileged'), change('/tmp:rw,noexec,nosuid,size=64m', '/tmp:rw,exec,suid'),
    change('127.0.0.1:5500:5000/tcp', '0.0.0.0:5500:5000/tcp'),
    change(join(parent, 'fncp-fresh-docker-MODEL1', 'server.env'), '/Users/private/.env.staging'),
    change(join(parent, 'fncp-fresh-docker-MODEL1', 'server.env'), join(parent, 'retained', 'server.env')),
    change(join(parent, 'fncp-fresh-docker-MODEL1', 'server.env'), join(parent, 'fncp-fresh-docker-MODEL1', 'other.env')),
    change(pins[1], pins[0]), [...model, 'sh'], [...model.slice(0, -1), '--entrypoint', 'sh', pins[1]],
    model.map(item => item.replace('fncp-fresh-polis-MODEL2/jwt-public.pem', 'fncp-fresh-polis-MODEL3/jwt-public.pem')),
    model.map(item => item.replace(',readonly', '')),
  ];
  const pg = create('pg', parent);
  bad.push(pg.map(item => item === '70:70' ? '501:20' : item));
  bad.push(pg.map(item => item.replace('src=fncp-fresh-data-' + run, 'src=fncp-fresh-data-' + 'd'.repeat(24))));
  for (const command of bad) await rejected(execute(command)); assert.equal(calls, 0);
});

test('network and volume creation reject omitted isolation, remote drivers, altered options and uncorrelated names', async () => {
  let calls = 0;
  const execute = createDockerTransport({ spawnProcess() { calls++; throw new Error('must-not-spawn'); } });
  const network = ['network', 'create', '--driver', 'bridge', '--internal', '--ipv6=false', '--opt',
    'com.docker.network.bridge.gateway_mode_ipv4=isolated', '--opt',
    'com.docker.network.bridge.enable_ip_masquerade=false', ...labels(), `fncp-fresh-net-${run}`];
  const volume = ['volume', 'create', '--driver', 'local', ...labels(), `fncp-fresh-data-${run}`];
  for (const command of [network.filter(item => item !== '--internal'), network.map(item => item === 'bridge' ? 'host' : item),
    network.map(item => item === '--ipv6=false' ? '--ipv6=true' : item),
    network.map(item => item.replace('gateway_mode_ipv4=isolated', 'gateway_mode_ipv4=nat')),
    network.map(item => item.replace('enable_ip_masquerade=false', 'enable_ip_masquerade=true')),
    [...network.slice(0, -1), 'bridge'], volume.map(item => item === 'local' ? 'nfs' : item),
    [...volume, '--opt', 'device=/'], [...volume.slice(0, -1), `fncp-fresh-data-${'d'.repeat(24)}`]]) await rejected(execute(command));
  assert.equal(calls, 0);
});

test('broad operations, global overrides, arbitrary images/names/formats and launch overrides are rejected before spawn', async () => {
  let calls = 0;
  const execute = createDockerTransport({ spawnProcess() { calls++; throw new Error('must-not-spawn'); } });
  const bad = [[], ['ps'], ['rm', id], ['container', 'rm', id], ['system', 'prune'], ['volume', 'prune'],
    ['context', 'use', 'default'], ['compose', 'up'], ['build', '.'], ['pull', 'postgres'], ['exec', id, 'sh'],
    ['--host', 'unix:///tmp/other', ...version], ['--config', '/tmp/other', ...version],
    ['version'], ['version', '--format', '{{json .}}'], ['image', 'inspect', 'postgres:latest', '--format', image],
    ['image', 'inspect', 'sha256:' + '0'.repeat(64), '--format', image],
    ['container', 'inspect', 'existing', '--format', named], ['network', 'inspect', 'bridge', '--format', named],
    ['volume', 'inspect', `fncp-fresh-pg-${run}`, '--format', '{"name":{{json .Name}}}'],
    ['container', 'start', `fncp-fresh-pg-${run}`], ['container', 'stop', '--time', '0', id],
    ['container', 'start', id, '--attach'], ['container', 'create', '--privileged', pins[0]],
    ['network', 'connect', id, id], ['container', 'inspect', id, '--format', '{{json .Config.Env}}'],
  ];
  for (const args of bad) await rejected(execute(args));
  assert.equal(calls, 0);
});

test('argument arrays reject holes, extra fields, symbols, subclasses, accessors and proxies without invoking getters', async () => {
  let calls = 0; let reads = 0;
  const execute = createDockerTransport({ spawnProcess() { calls++; throw new Error('must-not-spawn'); } });
  const getter = [...version]; Object.defineProperty(getter, '0', { get() { reads++; return 'version'; } });
  const extra = [...version]; extra.extra = 'private';
  const symbol = [...version]; symbol[Symbol('private')] = true;
  const sparse = [...version]; delete sparse[1];
  class CustomArray extends Array {}
  const proxy = new Proxy(version, { get() { reads++; throw new Error('private'); }, ownKeys() { reads++; return []; } });
  const nullPrototype = [...version]; Object.setPrototypeOf(nullPrototype, null);
  for (const args of [undefined, null, {}, getter, extra, symbol, sparse, new CustomArray(...version), proxy,
    nullPrototype, ['version', '--format', new String(engine)], ['version', '--format', engine + '\n'],
    ['version', '--format', engine + '\r'], ['version', '--format', engine + '\0'],
    ['version', '--format', 'x'.repeat(4097)], Array(129).fill('x')]) await rejected(execute(args));
  await rejected(execute(version, 'private-extra'));
  assert.equal(reads, 0); assert.equal(calls, 0);
});

test('factory accepts only one exact trusted function data property and no override options', () => {
  let reads = 0;
  const getter = { get spawnProcess() { reads++; return () => {}; } };
  const proxy = new Proxy({ spawnProcess() {} }, { ownKeys() { reads++; return []; } });
  const symbol = { spawnProcess() {}, [Symbol('extra')]: true };
  const fnProxy = new Proxy(() => {}, {});
  for (const input of [undefined, null, {}, getter, proxy, symbol, Object.create(null),
    { spawnProcess() {}, executable: '/tmp/other' }, { spawnProcess() {}, env: {} },
    { spawnProcess() {}, timeout: 1 }, { spawnProcess: fnProxy }, { spawnProcess: 'no' }]) {
    assert.throws(() => createDockerTransport(input), { message: ERROR });
  }
  assert.throws(() => createDockerTransport({ spawnProcess() {} }, {}), { message: ERROR });
  assert.equal(reads, 0);
});

test('argument snapshot cannot be changed after asynchronous private setup begins', async () => {
  const f = fixture(); const args = [...version]; const promise = f.transport(args);
  args.splice(0, args.length, 'system', 'prune');
  const call = await f.spawned; assert.deepEqual(call.args.slice(4), version);
  f.close(); await promise; await missing(call.directory);
});

test('exact 32 KiB combined output is accepted and split UTF-8 bytes reconstruct without replacement', async () => {
  const f = fixture(); const promise = f.transport(version); const call = await f.spawned;
  f.child.stdout.write(Buffer.from([0xef, 0xbb, 0xbf]));
  f.child.stdout.write(Buffer.from([0xe2])); f.child.stdout.write(Buffer.from([0x82, 0xac]));
  f.child.stderr.write('x'.repeat(32762)); f.close();
  const result = await promise;
  assert.equal(result.stdout, '\ufeff€'); assert.equal(Buffer.byteLength(result.stdout + result.stderr), 32768);
  await missing(call.directory);
});

test('combined output overflow terminates, suppresses details and removes config only after close', async () => {
  const f = fixture(); const promise = f.transport(version); const result = rejected(promise); const call = await f.spawned;
  f.child.stdout.write('x'.repeat(32768)); f.child.stderr.write('PRIVATE-OVERFLOW');
  assert.deepEqual(f.signals, ['SIGTERM']);
  assert.equal((await lstat(call.directory)).isDirectory(), true);
  f.close(null, 'SIGTERM'); await result; await missing(call.directory);
});

test('invalid UTF-8 fails closed without output details', async () => {
  const f = fixture(); const promise = f.transport(version); const result = rejected(promise); const call = await f.spawned;
  f.child.stdout.write(Buffer.from([0xff])); f.close(); await result; await missing(call.directory);
});

test('synchronous spawn errors are sanitized and the never-spawned private config is removed', async () => {
  let directory;
  const execute = createDockerTransport({ spawnProcess(_file, args, options) {
    directory = options.cwd; throw new Error('PRIVATE ' + args.join(' '));
  } });
  await rejected(execute(version)); assert.ok(directory); await missing(directory);
});

test('asynchronous process and stream errors never reveal details and wait for close', async () => {
  for (const target of ['child', 'stdout', 'stderr']) {
    const f = fixture(); const promise = f.transport(version); const result = rejected(promise); const call = await f.spawned;
    (target === 'child' ? f.child : f.child[target]).emit('error', new Error('PRIVATE ' + call.directory));
    assert.deepEqual(f.signals, ['SIGTERM']); assert.equal((await lstat(call.directory)).isDirectory(), true);
    f.close(1); await result; await missing(call.directory);
  }
});

test('signal exits and invalid exit codes fail rather than claiming completed commands', async () => {
  for (const [code, signal] of [[null, 'SIGKILL'], [null, null], [-1, null], [256, null], ['0', null]]) {
    const f = fixture(); const promise = f.transport(version); const result = rejected(promise); const call = await f.spawned;
    f.close(code, signal); await result; await missing(call.directory);
  }
});

test('30-second deadline sends TERM then bounded KILL and cleans only after independent close', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const f = fixture(); const promise = f.transport(version); const result = rejected(promise); const call = await f.spawned;
  t.mock.timers.tick(29_999); assert.deepEqual(f.signals, []);
  t.mock.timers.tick(1); assert.deepEqual(f.signals, ['SIGTERM']);
  t.mock.timers.tick(999); assert.deepEqual(f.signals, ['SIGTERM']);
  t.mock.timers.tick(1); assert.deepEqual(f.signals, ['SIGTERM', 'SIGKILL']);
  assert.equal((await lstat(call.directory)).isDirectory(), true);
  f.close(null, 'SIGKILL'); await result; await missing(call.directory);
});

test('deadline with unknown process state preserves its exact private config instead of deleting it', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const f = fixture(); const promise = f.transport(version); const result = rejected(promise); const call = await f.spawned;
  t.mock.timers.tick(30_000); t.mock.timers.tick(1000); t.mock.timers.tick(1000);
  await result;
  assert.deepEqual(f.signals, ['SIGTERM', 'SIGKILL']);
  assert.equal((await lstat(call.directory)).mode & 0o777, 0o700);
  // Only this test's new directory is cleaned, after the invented process has
  // separately confirmed close. The transport intentionally cannot assume it.
  f.close(null, 'SIGKILL'); assert.equal(f.closed, true);
  await rm(call.directory, { recursive: true, force: false });
});

test('a stopped timeout process requires no KILL and cancels all remaining deadline work', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const f = fixture(); const promise = f.transport(version); const result = rejected(promise); const call = await f.spawned;
  f.child.kill = signal => { f.signals.push(signal); f.close(null, signal); return true; };
  t.mock.timers.tick(30_000); await result;
  t.mock.timers.tick(10_000); assert.deepEqual(f.signals, ['SIGTERM']); await missing(call.directory);
});

test('failed termination preserves uncertain config without surfacing kill errors', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const f = fixture(); const promise = f.transport(version); const result = rejected(promise); const call = await f.spawned;
  f.child.kill = signal => { f.signals.push(signal); throw new Error('PRIVATE kill ' + call.directory); };
  t.mock.timers.tick(30_000); t.mock.timers.tick(1000); t.mock.timers.tick(1000); await result;
  assert.deepEqual(f.signals, ['SIGTERM', 'SIGKILL']); assert.equal((await lstat(call.directory)).isDirectory(), true);
  f.close(null, 'SIGKILL'); await rm(call.directory, { recursive: true, force: false });
});

test('cleanup refuses a substituted config symlink and never follows it into another directory', async () => {
  const a = fixture(); const b = fixture(); const pa = a.transport(version); const pb = b.transport(version);
  const failure = rejected(pa); const ca = await a.spawned; const cb = await b.spawned;
  const moved = ca.directory + '-moved';
  await writeFile(join(cb.directory, 'private-model-marker'), 'model-only', { flag: 'wx', mode: 0o600 });
  await rename(ca.directory, moved); await symlink(cb.directory, ca.directory, 'dir');
  a.close(); await failure;
  assert.equal((await lstat(ca.directory)).isSymbolicLink(), true);
  assert.equal(await readFile(join(cb.directory, 'private-model-marker'), 'utf8'), 'model-only');
  // Both exact paths originate in these two fake-spawn calls, and a has closed.
  await unlink(ca.directory); await rm(moved, { recursive: true, force: false });
  b.close(); await pb; await missing(cb.directory);
});

test('source pins default execution and exposes no environment/socket/timeout path override', async () => {
  const source = await readFile(new URL('./docker-cli.mjs', import.meta.url), 'utf8');
  assert.match(source, /const defaultTransport = createDockerTransport\(\{ spawnProcess: spawn \}\)/u);
  assert.doesNotMatch(source, /process\.env|execFile|execSync|spawnSync|shell:\s*true/u);
});
