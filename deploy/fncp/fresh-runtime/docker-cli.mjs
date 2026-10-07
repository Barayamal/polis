/** Fixed, private Docker CLI transport. Import/creation performs no I/O. The
 * default executable, socket, environment and deadlines cannot be overridden.
 * This transport is an argv boundary, not resource ownership or launch authority:
 * the fresh lifecycle driver must independently verify its branded requests.
 * stdout/stderr are PRIVATE; callers must not log them or include them in errors.
 */
import { spawn } from 'node:child_process';
import { mkdtemp, chmod, realpath, lstat, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, basename, dirname } from 'node:path';
import { isProxy } from 'node:util/types';

const EXECUTABLE = '/opt/homebrew/bin/docker';
const SOCKET = 'unix:///Users/deansosupremo/.colima/fncp-c-20260913/docker.sock';
const ENVIRONMENT = Object.freeze({ PATH: '/opt/homebrew/bin:/usr/bin:/bin', LANG: 'C',
  LC_ALL: 'C', DOCKER_CLI_HINTS: 'false' });
const LIMIT = 32 * 1024;
const IMAGES = Object.freeze({
  pg: 'sha256:9d9684f7a95e94c9eb370212edea832e7b9916b7bd96b2821c5bc9cf63a0e8b3',
  api: 'sha256:07f8a21105ed90963ccdf0981d884323116187583a464bb581db14c621d33a98',
});
const FORMATS = Object.freeze({
  engine: '{"os":{{json .Server.Os}},"architecture":{{json .Server.Arch}},"version":{{json .Server.Version}}}',
  image: '{"id":{{json .Id}},"os":{{json .Os}},"architecture":{{json .Architecture}}}',
  named: '{"name":{{json .Name}},"id":{{json .Id}}}',
  volume: '{"name":{{json .Name}}}',
  lifecycleImage: '{"id":{{json .Id}},"os":{{json .Os}},"architecture":{{json .Architecture}},"volumes":{{json .Config.Volumes}}}',
  lifecycleNetwork: '{"id":{{json .Id}},"name":{{json .Name}},"driver":{{json .Driver}},"scope":{{json .Scope}},"internal":{{json .Internal}},"ipv6":{{json .EnableIPv6}},"labels":{{json .Labels}},"options":{{json .Options}},"containers":{{json .Containers}}}',
  lifecycleVolume: '{"name":{{json .Name}},"driver":{{json .Driver}},"scope":{{json .Scope}},"labels":{{json .Labels}},"options":{{json .Options}},"createdAt":{{json .CreatedAt}}}',
  lifecycleContainer: '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"labels":{{json .Config.Labels}},"state":{{json .State.Status}},"running":{{json .State.Running}},"networkMode":{{json .HostConfig.NetworkMode}},"networks":{{json .NetworkSettings.Networks}},"ports":{{json .HostConfig.PortBindings}},"mounts":{{json .Mounts}},"privileged":{{json .HostConfig.Privileged}},"readonly":{{json .HostConfig.ReadonlyRootfs}},"capAdd":{{json .HostConfig.CapAdd}},"capDrop":{{json .HostConfig.CapDrop}},"security":{{json .HostConfig.SecurityOpt}},"restart":{{json .HostConfig.RestartPolicy}},"user":{{json .Config.User}},"pidMode":{{json .HostConfig.PidMode}},"ipcMode":{{json .HostConfig.IpcMode}},"devices":{{json .HostConfig.Devices}},"extraHosts":{{json .HostConfig.ExtraHosts}},"dns":{{json .HostConfig.Dns}},"tmpfs":{{json .HostConfig.Tmpfs}},"memory":{{json .HostConfig.Memory}},"pidsLimit":{{json .HostConfig.PidsLimit}}}',
});
const ID = /^[a-f0-9]{64}$/u;
const NAME = /^fncp-fresh-(pg|api|net|data)-([a-f0-9]{24})$/u;
const fail = () => new Error('Fresh Docker transport failed; private process details withheld.');

function strings(value) {
  if (!Array.isArray(value) || isProxy(value) || Object.getPrototypeOf(value) !== Array.prototype) throw fail();
  const fields = Object.getOwnPropertyDescriptors(value);
  const length = fields.length?.value;
  if (!Number.isInteger(length) || length < 1 || length > 128 || Reflect.ownKeys(fields).length !== length + 1) throw fail();
  const result = [];
  for (let i = 0; i < length; i++) {
    const field = fields[i];
    if (!field || !Object.hasOwn(field, 'value') || typeof field.value !== 'string' ||
        field.value.length === 0 || field.value.length > 4096 || /[\0\r\n]/u.test(field.value)) throw fail();
    result.push(field.value);
  }
  return result;
}
function equal(actual, expected) {
  return actual.length === expected.length && actual.every((item, i) => item === expected[i]);
}
function freshName(value, prefixes) {
  const match = NAME.exec(value);
  return match && prefixes.includes(match[1]) ? match : null;
}
function freshFile(value, parent, kind, file) {
  const directory = basename(dirname(value));
  return new RegExp(`^fncp-fresh-${kind}-[a-zA-Z0-9]{6}$`, 'u').test(directory) &&
    value === join(parent, directory, file);
}
function createCommand(args, parent) {
  let index = 2;
  const take = expected => { if (args[index++] !== expected) throw fail(); };
  const value = pattern => { const current = args[index++]; if (typeof current !== 'string' || !pattern.test(current)) throw fail(); return current; };
  const labels = () => {
    take('--label'); take('org.barayamal.fncp.purpose=fresh-synthetic-foundation-only');
    take('--label'); const run = value(/^org\.barayamal\.fncp\.fresh-run=[a-f0-9]{24}$/u).split('=')[1];
    take('--label'); value(/^org\.barayamal\.fncp\.adapter=[a-f0-9]{48}$/u);
    return run;
  };
  if (args[0] === 'network') {
    for (const part of ['--driver', 'bridge', '--internal', '--ipv6=false', '--opt',
      'com.docker.network.bridge.gateway_mode_ipv4=isolated', '--opt',
      'com.docker.network.bridge.enable_ip_masquerade=false']) take(part);
    take(`fncp-fresh-net-${labels()}`);
  } else if (args[0] === 'volume') {
    take('--driver'); take('local'); take(`fncp-fresh-data-${labels()}`);
  } else if (args[0] === 'container') {
    take('--name'); const name = value(NAME); const match = freshName(name, ['pg', 'api']);
    if (!match || labels() !== match[2]) throw fail();
    const role = match[1];
    for (const part of ['--pull=never', '--platform', 'linux/arm64', '--network']) take(part);
    value(ID);
    for (const part of ['--restart=no', '--cap-drop=ALL', '--security-opt', 'no-new-privileges:true',
      '--pids-limit', '128', '--memory', '768m', '--user']) take(part);
    if (role === 'pg') take('70:70');
    else {
      const user = value(/^[1-9][0-9]{0,9}:(0|[1-9][0-9]{0,9})$/u);
      if (user.split(':').some(item => Number(item) > 4294967294)) throw fail();
    }
    for (const part of ['--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m']) take(part);
    if (role === 'pg') { take('--tmpfs'); take('/var/run/postgresql:rw,nosuid,size=16m'); }
    take('--env-file');
    const envFile = args[index++];
    if (typeof envFile !== 'string' || !freshFile(envFile, parent, 'docker', role === 'pg' ? 'postgres.env' : 'server.env')) throw fail();
    if (role === 'pg') {
      take('--mount'); take(`type=volume,src=fncp-fresh-data-${match[2]},dst=/var/lib/postgresql/data`);
    } else {
      take('--publish'); take('127.0.0.1:5500:5000/tcp');
      let foundation;
      for (const key of ['private', 'public']) {
        take('--mount'); const mount = args[index++];
        const suffix = `,dst=/run/fncp/jwt-${key}.pem,readonly`;
        if (!mount?.startsWith('type=bind,src=') || !mount.endsWith(suffix)) throw fail();
        const file = mount.slice('type=bind,src='.length, -suffix.length);
        if (!freshFile(file, parent, 'polis', `jwt-${key}.pem`) ||
            (foundation && dirname(file) !== foundation)) throw fail();
        foundation = dirname(file);
      }
    }
    take(IMAGES[role]);
  } else throw fail();
  if (index !== args.length) throw fail();
}

// Mutating command grammars are intentionally separate from inspection and are
// extended only alongside the reviewed fresh driver, never by a denylist alone.
function validate(args, parent) {
  if (equal(args, ['version', '--format', FORMATS.engine])) return;
  if (args.length === 5 && args[0] === 'image' && args[1] === 'inspect' &&
      Object.values(IMAGES).includes(args[2]) && args[3] === '--format' && [FORMATS.image, FORMATS.lifecycleImage].includes(args[4])) return;
  if (args.length === 5 && args[1] === 'inspect' && args[3] === '--format') {
    if (args[0] === 'container' && freshName(args[2], ['pg', 'api']) && args[4] === FORMATS.named) return;
    if (args[0] === 'network' && freshName(args[2], ['net']) && args[4] === FORMATS.named) return;
    if (args[0] === 'volume' && freshName(args[2], ['data']) && args[4] === FORMATS.volume) return;
    if (args[0] === 'container' && ID.test(args[2]) && args[4] === FORMATS.lifecycleContainer) return;
    if (args[0] === 'network' && ID.test(args[2]) && args[4] === FORMATS.lifecycleNetwork) return;
    if (args[0] === 'volume' && freshName(args[2], ['data']) && args[4] === FORMATS.lifecycleVolume) return;
  }
  if (args[1] === 'create') { createCommand(args, parent); return; }
  if (args.length === 3 && args[0] === 'container' && args[1] === 'start' && ID.test(args[2])) return;
  if (args.length === 5 && equal(args.slice(0, 4), ['container', 'stop', '--time', '10']) && ID.test(args[4])) return;
  throw fail();
}

async function privateDirectory(parent) {
  const path = await mkdtemp(join(parent, 'fncp-docker-cli-'));
  await chmod(path, 0o700);
  const info = await lstat(path);
  if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o777) !== 0o700 || await realpath(path) !== path) throw fail();
  return { path, dev: info.dev, ino: info.ino, uid: info.uid };
}
async function removeClosedDirectory(directory) {
  // Delete only this call's exact new directory, never an ambient Docker config.
  const info = await lstat(directory.path);
  if (!info.isDirectory() || info.isSymbolicLink() || info.dev !== directory.dev ||
      info.ino !== directory.ino || info.uid !== directory.uid ||
      (info.mode & 0o777) !== 0o700 || await realpath(directory.path) !== directory.path) throw fail();
  await rm(directory.path, { recursive: true, force: false });
}

function collect(spawnProcess, args, directory) {
  return new Promise(resolve => {
    let child; let finished = false; let failed = false; let terminating = false; let bytes = 0;
    const stdout = []; const stderr = []; const timers = new Set();
    const later = (callback, ms) => { const timer = setTimeout(callback, ms); timers.add(timer); };
    const finish = (closed, exitCode) => {
      if (finished) return; finished = true;
      for (const timer of timers) clearTimeout(timer);
      let result;
      if (closed && !failed && Number.isInteger(exitCode) && exitCode >= 0 && exitCode <= 255) {
        try {
          // Invalid UTF-8 is rejected rather than expanding beyond the byte cap
          // through replacement characters or returning an ambiguous projection.
          const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
          result = Object.freeze({ exitCode, stdout: decoder.decode(Buffer.concat(stdout)),
            stderr: decoder.decode(Buffer.concat(stderr)) });
        } catch { failed = true; }
      }
      resolve({ closed, result });
    };
    const kill = signal => { try { child?.kill(signal); } catch { /* Never surface child/argv details. */ } };
    const terminate = () => {
      failed = true;
      if (finished || terminating) return; terminating = true;
      later(() => { if (!finished) { later(() => finish(false), 1000); kill('SIGKILL'); } }, 1000);
      kill('SIGTERM');
    };
    const data = (parts, chunk) => {
      if (finished || failed) return;
      if (!Buffer.isBuffer(chunk) && typeof chunk !== 'string') { terminate(); return; }
      const size = typeof chunk === 'string' ? Buffer.byteLength(chunk, 'utf8') : chunk.length;
      if (bytes + size > LIMIT) { terminate(); return; }
      bytes += size; parts.push(Buffer.from(chunk));
    };
    try {
      child = spawnProcess(EXECUTABLE, ['--host', SOCKET, '--config', directory.path, ...args], {
        cwd: directory.path, env: { ...ENVIRONMENT }, shell: false, stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch {
      // Synchronous node:child_process.spawn validation failure creates no child.
      // The injected equivalent is a trusted test boundary with the same contract.
      failed = true; finish(true); return;
    }
    try {
      child.once('close', (code, signal) => { if (signal !== null && signal !== undefined) failed = true; finish(true, code); });
      child.on('error', terminate);
      child.stdout.on('data', chunk => data(stdout, chunk));
      child.stderr.on('data', chunk => data(stderr, chunk));
      child.stdout.on('error', terminate); child.stderr.on('error', terminate);
      later(terminate, 30_000);
    } catch {
      // An invalid injected process is not evidence that it stopped. Preserve its
      // private directory unless a close event independently arrives.
      terminate();
    }
  });
}

/** Trusted fake-spawn injection only. No path, socket, env or timeout injection.
 * The returned callable has the same single-argument contract as runDocker. */
export function createDockerTransport(options) {
  if (arguments.length !== 1 || !options || typeof options !== 'object' || isProxy(options) ||
      Object.getPrototypeOf(options) !== Object.prototype || Reflect.ownKeys(options).length !== 1) throw fail();
  const field = Object.getOwnPropertyDescriptor(options, 'spawnProcess');
  if (!field || !Object.hasOwn(field, 'value') || typeof field.value !== 'function' || isProxy(field.value)) throw fail();
  const spawnProcess = field.value;
  return async function execute(args) {
    let directory;
    try {
      if (arguments.length !== 1) throw fail();
      const values = strings(args); const parent = await realpath(tmpdir()); validate(values, parent);
      directory = await privateDirectory(parent);
      const outcome = await collect(spawnProcess, values, directory);
      if (outcome.closed) await removeClosedDirectory(directory);
      if (!outcome.result) throw fail();
      return outcome.result;
    } catch { throw fail(); }
  };
}

const defaultTransport = createDockerTransport({ spawnProcess: spawn });
export async function runDocker(args) {
  if (arguments.length !== 1) throw fail();
  return defaultTransport(args);
}
