/** Concrete, opt-in, fresh-only Docker lifecycle. Import performs no I/O.
 * Not a bootstrapper or deployment launcher. Current foundation configuration
 * lacks local AUTH/JWKS inputs and is rejected before any Docker mutation.
 * Call close() even when foundation.start() fails. Private files and resources
 * are preserved, never adopted, removed, pruned or recovered by guessed names.
 */
import { mkdtemp, chmod, realpath, lstat, open, readdir, readFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
import { isProxy } from 'node:util/types';
import { verifyFreshPolisRequest } from './foundation.mjs';
import { runDocker } from './docker-cli.mjs';

const CONTEXT = 'colima-fncp-c-20260913';
const PG = 'sha256:9d9684f7a95e94c9eb370212edea832e7b9916b7bd96b2821c5bc9cf63a0e8b3';
const API = 'sha256:07f8a21105ed90963ccdf0981d884323116187583a464bb581db14c621d33a98';
const ID = /^[a-f0-9]{64}$/u;
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = () => new Error('Fresh Docker lifecycle failed; new private state preserved.');
const freeze = value => { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; };
const plain = value => value && typeof value === 'object' && !isProxy(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
function exact(value, keys) {
  if (!plain(value) || Reflect.ownKeys(value).length !== keys.length) throw fail();
  const fields = Object.getOwnPropertyDescriptors(value);
  if (keys.some(key => !fields[key] || !Object.hasOwn(fields[key], 'value'))) throw fail();
  return Object.fromEntries(keys.map(key => [key, fields[key].value]));
}
const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const mapEqual = (a, b) => plain(a) && Object.keys(a).length === Object.keys(b).length && Object.keys(b).every(key => a[key] === b[key]);
const empty = value => value === null || (plain(value) && Object.keys(value).length === 0) || (Array.isArray(value) && value.length === 0);
const stamp = info => ({ dev: info.dev, ino: info.ino, uid: info.uid, mode: info.mode, size: info.size });
const same = (a, b) => ['dev', 'ino', 'uid', 'mode', 'size'].every(key => a[key] === b[key]);
const regular = info => info.isFile() && !info.isSymbolicLink() && info.nlink === 1 && (info.mode & 0o777) === 0o600;

const IMAGE_FORMAT = '{"id":{{json .Id}},"os":{{json .Os}},"architecture":{{json .Architecture}},"volumes":{{json .Config.Volumes}}}';
const NETWORK_FORMAT = '{"id":{{json .Id}},"name":{{json .Name}},"driver":{{json .Driver}},"scope":{{json .Scope}},"internal":{{json .Internal}},"ipv6":{{json .EnableIPv6}},"labels":{{json .Labels}},"options":{{json .Options}},"containers":{{json .Containers}}}';
const VOLUME_FORMAT = '{"name":{{json .Name}},"driver":{{json .Driver}},"scope":{{json .Scope}},"labels":{{json .Labels}},"options":{{json .Options}},"createdAt":{{json .CreatedAt}}}';
const CONTAINER_FORMAT = '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"labels":{{json .Config.Labels}},"state":{{json .State.Status}},"running":{{json .State.Running}},"networkMode":{{json .HostConfig.NetworkMode}},"networks":{{json .NetworkSettings.Networks}},"ports":{{json .HostConfig.PortBindings}},"mounts":{{json .Mounts}},"privileged":{{json .HostConfig.Privileged}},"readonly":{{json .HostConfig.ReadonlyRootfs}},"capAdd":{{json .HostConfig.CapAdd}},"capDrop":{{json .HostConfig.CapDrop}},"security":{{json .HostConfig.SecurityOpt}},"restart":{{json .HostConfig.RestartPolicy}},"user":{{json .Config.User}},"pidMode":{{json .HostConfig.PidMode}},"ipcMode":{{json .HostConfig.IpcMode}},"devices":{{json .HostConfig.Devices}},"extraHosts":{{json .HostConfig.ExtraHosts}},"dns":{{json .HostConfig.Dns}},"tmpfs":{{json .HostConfig.Tmpfs}},"memory":{{json .HostConfig.Memory}},"pidsLimit":{{json .HostConfig.PidsLimit}}}';
const NET_OPTIONS = {
  'com.docker.network.bridge.gateway_mode_ipv4': 'isolated',
  'com.docker.network.bridge.enable_ip_masquerade': 'false',
};

async function write(state, name, value) {
  const bytes = typeof value === 'string' ? value : JSON.stringify(value, null, 2) + '\n';
  const file = await open(join(state.directory, name), constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  try { await file.writeFile(bytes); await file.sync(); const info = await file.stat(); if (!regular(info)) throw fail(); state.files.set(name, { ...stamp(info), sha: sha(bytes) }); }
  finally { await file.close(); }
}
async function integrity(state) {
  const info = await lstat(state.directory);
  if (!info.isDirectory() || info.isSymbolicLink() || info.dev !== state.directoryIdentity.dev || info.ino !== state.directoryIdentity.ino ||
      info.uid !== state.directoryIdentity.uid || (info.mode & 0o777) !== 0o700 || await realpath(state.directory) !== state.directory) throw fail();
  const names = await readdir(state.directory);
  if (names.length !== state.files.size || names.some(name => !state.files.has(name))) throw fail();
  for (const [name, expected] of state.files) {
    const path = join(state.directory, name); const before = await lstat(path);
    if (!regular(before) || !same(before, expected)) throw fail();
    const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try { const opened = await file.stat(); if (!regular(opened) || !same(opened, expected) || sha(await file.readFile()) !== expected.sha || !same(await lstat(path), expected)) throw fail(); }
    finally { await file.close(); }
  }
}
async function record(state, event, detail = {}) {
  await integrity(state); const next = state.sequence + 1;
  await write(state, `ledger-${String(next).padStart(4, '0')}.json`, { event, ...detail }); state.sequence = next;
}
async function command(state, args, request, closing = false) {
  await integrity(state);
  if (request) await verifyFreshPolisRequest(request);
  if (state.closing && !closing) throw fail();
  state.commandCount++;
  const result = exact(await state.execute(Object.freeze(args)), ['exitCode', 'stdout', 'stderr']);
  if (!Number.isInteger(result.exitCode) || result.exitCode < 0 || result.exitCode > 255 || typeof result.stdout !== 'string' || typeof result.stderr !== 'string' ||
      Buffer.byteLength(result.stdout) + Buffer.byteLength(result.stderr) > 32768 || result.exitCode !== 0 || result.stderr !== '') throw fail();
  return result.stdout.trim();
}
async function json(state, args, request, closing = false) {
  const text = await command(state, args, request, closing);
  const result = JSON.parse(text);
  if (!plain(result) || JSON.stringify(result) !== text) throw fail(); return result;
}
function checkRuntimeInput(config, request) {
  if (config.context !== CONTEXT || config.classification !== 'SYNTHETIC_ONLY_NOT_RUN' || config.roundOpen !== false || config.activationGranted !== false || config.appliedToRuntime !== false ||
      config.names[request.resource.role] !== request.resource.name || config.names.network !== request.resource.networkName ||
      config.environment.FNCP_GATEWAY_ENFORCEMENT !== 'true' || config.environment.FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT !== 'true' ||
      config.environment.FNCP_GATEWAY_CONVERSATION_ID !== config.environment.FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID ||
      !/^9fncpBootstrap[a-f0-9]{48}$/u.test(config.environment.FNCP_GATEWAY_CONVERSATION_ID)) throw fail();
  // Current foundation leaves these blank: reject before network/volume/create.
  // This check is necessary, not complete ordinary-bootstrap/issuer assurance.
  const env = config.environment;
  if (typeof env.AUTH_AUDIENCE !== 'string' || !/^[A-Za-z0-9_-]{8,100}$/u.test(env.AUTH_AUDIENCE)) throw fail();
  const issuer = new URL(env.AUTH_ISSUER); const jwks = new URL(env.JWKS_URI);
  if (issuer.protocol !== 'https:' || issuer.hostname !== '127.0.0.1' || !issuer.port || issuer.pathname !== '/' || issuer.username || issuer.password || issuer.search || issuer.hash ||
      jwks.origin !== issuer.origin || jwks.pathname !== '/.well-known/jwks.json' || jwks.username || jwks.password || jwks.search || jwks.hash) throw fail();
  for (const [key, value] of Object.entries(env)) if (!/^[A-Z][A-Z0-9_]*$/u.test(key) || typeof value !== 'string' || /[\r\n\0]/u.test(value) || value.length > 4096) throw fail();
}
async function bind(state, request) {
  await verifyFreshPolisRequest(request);
  if (request.context !== CONTEXT || request.operation !== 'start' || !['postgres', 'server'].includes(request.resource.role)) throw fail();
  if (state.foundationDirectory && state.foundationDirectory !== request.privateDirectory) throw fail();
  const config = JSON.parse(await readFile(request.configurationFile, 'utf8'));
  await verifyFreshPolisRequest(request); checkRuntimeInput(config, request);
  if (!state.foundationDirectory) {
    state.foundationDirectory = request.privateDirectory; state.config = config;
    state.labels = { ...config.labels, 'org.barayamal.fncp.adapter': state.nonce };
    await record(state, 'FOUNDATION_BOUND', { run: config.names.run });
    await write(state, 'server.env', Object.entries(config.environment).map(([key, value]) => `${key}=${value}`).join('\n') + '\n');
    const url = new URL(config.environment.DATABASE_URL);
    if (url.protocol !== 'postgres:' || url.hostname !== config.names.postgres || url.port !== '5432' ||
        !/^synthetic_[a-f0-9]{24}$/u.test(url.username) || !/^[a-f0-9]{64}$/u.test(url.password) || !/^\/synthetic_[a-f0-9]{24}$/u.test(url.pathname)) throw fail();
    await write(state, 'postgres.env', `POSTGRES_USER=${url.username}\nPOSTGRES_PASSWORD=${url.password}\nPOSTGRES_DB=${url.pathname.slice(1)}\n`);
  }
}
const labelArgs = labels => Object.entries(labels).flatMap(([key, value]) => ['--label', `${key}=${value}`]);
async function imageCheck(state, imageId, role, request) {
  const item = exact(await json(state, ['image', 'inspect', imageId, '--format', IMAGE_FORMAT], request), ['id', 'os', 'architecture', 'volumes']);
  const expectedPgVolume = plain(item.volumes) && Object.keys(item.volumes).length === 1 &&
    plain(item.volumes['/var/lib/postgresql/data']) && Object.keys(item.volumes['/var/lib/postgresql/data']).length === 0;
  if (item.id !== imageId || item.os !== 'linux' || item.architecture !== 'arm64' ||
      (role === 'postgres' ? !expectedPgVolume : !empty(item.volumes))) throw fail();
}
async function networkCheck(state, request, closing = false) {
  if (!state.network.id) throw fail();
  const item = exact(await json(state, ['network', 'inspect', state.network.id, '--format', NETWORK_FORMAT], request, closing), ['id', 'name', 'driver', 'scope', 'internal', 'ipv6', 'labels', 'options', 'containers']);
  if (item.id !== state.network.id || item.name !== state.config.names.network || item.driver !== 'bridge' || item.scope !== 'local' || item.internal !== true || item.ipv6 !== false ||
      !mapEqual(item.labels, state.labels) || !mapEqual(item.options, NET_OPTIONS) || !plain(item.containers)) throw fail();
  const known = [...state.containers.values()].map(item => item.id).filter(Boolean);
  if (Object.keys(item.containers).some(id => !known.includes(id))) throw fail();
}
async function volumeCheck(state, request, closing = false) {
  const item = exact(await json(state, ['volume', 'inspect', state.config.names.volume, '--format', VOLUME_FORMAT], request, closing), ['name', 'driver', 'scope', 'labels', 'options', 'createdAt']);
  if (item.name !== state.config.names.volume || item.driver !== 'local' || item.scope !== 'local' || !mapEqual(item.labels, state.labels) || !empty(item.options) ||
      typeof item.createdAt !== 'string' || !/^\d{4}-\d{2}-\d{2}T/u.test(item.createdAt) || !Number.isFinite(Date.parse(item.createdAt)) ||
      (state.volume.createdAt && state.volume.createdAt !== item.createdAt)) throw fail();
  return item.createdAt;
}
async function infrastructure(state, request) {
  if (state.network.attempted || state.volume.attempted) throw fail();
  state.network.attempted = true; await record(state, 'NETWORK_CREATE_ATTEMPTED');
  const networkId = await command(state, ['network', 'create', '--driver', 'bridge', '--internal', '--ipv6=false', ...Object.entries(NET_OPTIONS).flatMap(([key, value]) => ['--opt', `${key}=${value}`]), ...labelArgs(state.labels), state.config.names.network], request);
  if (!ID.test(networkId)) throw fail(); state.network.id = networkId;
  await record(state, 'NETWORK_ID_CAPTURED', { id: networkId });
  await networkCheck(state, request);
  state.volume.attempted = true; await record(state, 'VOLUME_CREATE_ATTEMPTED');
  const name = await command(state, ['volume', 'create', '--driver', 'local', ...labelArgs(state.labels), state.config.names.volume], request);
  if (name !== state.config.names.volume) throw fail(); state.volume.name = name;
  state.volume.createdAt = await volumeCheck(state, request);
  await record(state, 'VOLUME_IDENTITY_CAPTURED', { name, createdAt: state.volume.createdAt });
}
function resourceSpec(state, role) {
  const postgres = role === 'postgres';
  const uid = process.getuid?.(); const gid = process.getgid?.();
  if (!Number.isSafeInteger(uid) || uid <= 0 || !Number.isSafeInteger(gid) || gid < 0) throw fail();
  return { role, name: state.config.names[role], image: postgres ? PG : API, user: postgres ? '70:70' : `${uid}:${gid}`,
    envFile: join(state.directory, postgres ? 'postgres.env' : 'server.env'),
    tmpfs: postgres ? { '/tmp': 'rw,noexec,nosuid,size=64m', '/var/run/postgresql': 'rw,nosuid,size=16m' } : { '/tmp': 'rw,noexec,nosuid,size=64m' },
    ports: postgres ? {} : { '5000/tcp': [{ HostIp: '127.0.0.1', HostPort: '5500' }] },
    mounts: postgres ? [{ Type: 'volume', Name: state.config.names.volume, Destination: '/var/lib/postgresql/data', RW: true }]
      : ['private', 'public'].map(kind => ({ Type: 'bind', Source: join(state.foundationDirectory, `jwt-${kind}.pem`), Destination: `/run/fncp/jwt-${kind}.pem`, RW: false })),
  };
}
function createArgs(state, spec) {
  const mounts = spec.mounts.flatMap(item => ['--mount', item.Type === 'volume' ? `type=volume,src=${item.Name},dst=${item.Destination}` : `type=bind,src=${item.Source},dst=${item.Destination},readonly`]);
  return ['container', 'create', '--name', spec.name, ...labelArgs(state.labels), '--pull=never', '--platform', 'linux/arm64', '--network', state.network.id,
    '--restart=no', '--cap-drop=ALL', '--security-opt', 'no-new-privileges:true', '--pids-limit', '128', '--memory', '768m', '--user', spec.user,
    '--read-only', ...Object.entries(spec.tmpfs).flatMap(([path, options]) => ['--tmpfs', `${path}:${options}`]), '--env-file', spec.envFile,
    ...(spec.role === 'server' ? ['--publish', '127.0.0.1:5500:5000/tcp'] : []), ...mounts, spec.image];
}
async function containerCheck(state, entry, request, closing = false) {
  await networkCheck(state, request, closing); await volumeCheck(state, request, closing);
  const item = exact(await json(state, ['container', 'inspect', entry.id, '--format', CONTAINER_FORMAT], request, closing),
    ['id', 'name', 'image', 'labels', 'state', 'running', 'networkMode', 'networks', 'ports', 'mounts',
      'privileged', 'readonly', 'capAdd', 'capDrop', 'security', 'restart', 'user', 'pidMode', 'ipcMode',
      'devices', 'extraHosts', 'dns', 'tmpfs', 'memory', 'pidsLimit']); const spec = entry.spec;
  const endpointId = item.networks?.[state.config.names.network]?.NetworkID;
  // Docker may not resolve the endpoint on a never-started container. Its
  // configured network is still pinned to the owned ID and independently read.
  const endpointMatches = endpointId === state.network.id || (item.state === 'created' && item.running === false && endpointId === '');
  if (item.id !== entry.id || item.name !== '/' + spec.name || item.image !== spec.image || !mapEqual(item.labels, state.labels) ||
      typeof item.running !== 'boolean' || !['created', 'running', 'exited'].includes(item.state) || (item.running !== (item.state === 'running')) ||
      item.networkMode !== state.network.id || !plain(item.networks) || Object.keys(item.networks).length !== 1 ||
      !endpointMatches ||
      !(empty(item.ports) && empty(spec.ports)) && !equal(item.ports, spec.ports)) throw fail();
  if (item.privileged !== false || item.readonly !== true || !empty(item.capAdd) || !equal(item.capDrop, ['ALL']) ||
      !equal(item.security, ['no-new-privileges:true']) || !mapEqual(item.restart, { Name: 'no', MaximumRetryCount: 0 }) ||
      item.user !== spec.user || item.pidMode !== '' || !['', 'private'].includes(item.ipcMode) || !empty(item.devices) || !empty(item.extraHosts) || !empty(item.dns) ||
      !mapEqual(item.tmpfs, spec.tmpfs) || item.memory !== 805306368 || item.pidsLimit !== 128 || !Array.isArray(item.mounts)) throw fail();
  const nonTmp = item.mounts.filter(mount => mount.Type !== 'tmpfs');
  if (nonTmp.length !== spec.mounts.length || spec.mounts.some(expected => !nonTmp.some(actual => Object.entries(expected).every(([key, value]) => actual[key] === value))) ||
      item.mounts.filter(mount => mount.Type === 'tmpfs').some(mount => !Object.hasOwn(spec.tmpfs, mount.Destination))) throw fail();
  return item.running;
}
async function start(state, request) {
  await bind(state, request); const role = request.resource.role;
  if (state.containers.has(role) || (role === 'server' && !state.containers.get('postgres')?.running)) throw fail();
  await imageCheck(state, role === 'postgres' ? PG : API, role, request);
  if (role === 'postgres') await infrastructure(state, request);
  else { await networkCheck(state, request); await volumeCheck(state, request); }
  const entry = { id: null, spec: resourceSpec(state, role), createAttempted: true, running: false, startDispatched: false, stopDispatched: false, stopped: false };
  state.containers.set(role, entry); await record(state, 'CONTAINER_CREATE_ATTEMPTED', { role });
  const id = await command(state, createArgs(state, entry.spec), request);
  if (!ID.test(id) || [...state.containers.values()].some(other => other.id === id)) throw fail();
  entry.id = id; await record(state, 'CONTAINER_ID_CAPTURED', { role, id });
  if (await containerCheck(state, entry, request)) throw fail();
  await record(state, 'CONTAINER_START_ATTEMPTED', { role, id }); entry.startDispatched = true;
  if (await command(state, ['container', 'start', id], request) !== id) throw fail();
  if (!await containerCheck(state, entry, request)) throw fail(); entry.running = true;
  await record(state, 'CONTAINER_RUNNING_METADATA_VERIFIED', { role, id });
  await verifyFreshPolisRequest(request); if (state.closing) throw fail();
  return freeze({ id, name: entry.spec.name, imageId: entry.spec.image, labels: { ...state.config.labels }, os: 'linux', architecture: 'arm64',
    networkName: state.config.names.network, volumeName: role === 'postgres' ? state.config.names.volume : null,
    loopbackOnly: true, egressPolicyConfigured: true, running: true });
}

/** Trusted executor injection is for model testing, not runtime authorization. */
export async function createDockerLifecycle(options) {
  if (arguments.length > 1) throw fail();
  const execute = arguments.length === 0 ? runDocker : exact(options, ['execute']).execute;
  if (typeof execute !== 'function' || isProxy(execute)) throw fail();
  const directory = await mkdtemp(join(await realpath(tmpdir()), 'fncp-fresh-docker-')); await chmod(directory, 0o700);
  const state = { directory, directoryIdentity: await lstat(directory), files: new Map(), execute, injected: execute !== runDocker,
    nonce: randomBytes(24).toString('hex'), sequence: 0, commandCount: 0, closing: false, busy: false,
    network: { attempted: false, id: null }, volume: { attempted: false, name: null, createdAt: null }, containers: new Map() };
  await write(state, 'ownership.json', { classification: 'FRESH_SYNTHETIC_DOCKER_ONLY', nonce: state.nonce, context: CONTEXT, deletionPermitted: false });
  const summary = () => freeze({ classification: 'KEEP_CLOSED', transport: state.injected ? 'INJECTED_MODEL' : 'FIXED_LOCAL_DOCKER_CLI', commandsDispatched: state.commandCount,
    networkCreateAttempted: state.network.attempted, networkIdentityCaptured: !!state.network.id, volumeCreateAttempted: state.volume.attempted, volumeIdentityCaptured: !!state.volume.createdAt,
    containerCreateAttempts: state.containers.size, containerIdentitiesCaptured: [...state.containers.values()].filter(item => item.id).length,
    stoppedContainers: [...state.containers.values()].filter(item => item.stopped).length, uncertainContainerCreates: [...state.containers.values()].filter(item => !item.id).length,
    uncertainInfrastructureCreates: Number(state.network.attempted && !state.network.id) + Number(state.volume.attempted && !state.volume.createdAt),
    uncertainStopDispatches: [...state.containers.values()].filter(item => item.stopDispatched && !item.stopped).length, closing: state.closing,
    privateFilesPreserved: true, networkAndVolumePreserved: true, actualNegativeEgressVerified: false, applicationHealthVerified: false, bootstrapImplemented: false, activationGranted: false });
  return Object.freeze({ privateDirectory: directory,
    summary() { if (arguments.length) throw fail(); return summary(); },
    async driver(request) {
      if (arguments.length !== 1 || state.busy || state.closing) throw fail();
      state.busy = true;
      try { await integrity(state); await verifyFreshPolisRequest(request); if (request.operation !== 'start') throw fail(); return await start(state, request); }
      catch { throw fail(); } finally { state.busy = false; }
    },
    async close() {
      if (arguments.length) throw fail(); state.closing = true;
      if (state.busy) throw fail(); state.busy = true; let failed = false;
      try {
        await integrity(state);
        for (const role of ['server', 'postgres']) {
          const entry = state.containers.get(role); if (!entry || entry.stopped) continue;
          if (!entry.id || entry.stopDispatched) { failed = true; continue; }
          try {
            const running = await containerCheck(state, entry, undefined, true);
            if (running) {
              await record(state, 'CONTAINER_STOP_ATTEMPTED', { role, id: entry.id });
              entry.stopDispatched = true;
              if (await command(state, ['container', 'stop', '--time', '10', entry.id], undefined, true) !== entry.id) throw fail();
              if (await containerCheck(state, entry, undefined, true)) throw fail();
            }
            entry.running = false; entry.stopped = true;
            await record(state, 'CONTAINER_STOPPED_VERIFIED', { role, id: entry.id });
          } catch { failed = true; }
        }
        if (failed || (state.network.attempted && !state.network.id) || (state.volume.attempted && !state.volume.createdAt)) throw fail(); return summary();
      } catch { throw fail(); } finally { state.busy = false; }
    },
  });
}
