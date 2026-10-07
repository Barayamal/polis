/** Read-only Docker metadata adapter for an actively branded fresh foundation
 * request. Importing/constructing performs no I/O. No VM/context mutation,
 * pull/build/start, arbitrary name inspection, log/database/config read, or
 * participant request is implemented here. Tests inject both capabilities.
 */
import { createServer } from 'node:net';
import { isProxy } from 'node:util/types';
import { runDocker } from './docker-cli.mjs';
import { verifyFreshPolisRequest } from './foundation.mjs';

const CONTEXT = 'colima-fncp-c-20260913';
const IMAGES = Object.freeze({
  postgres: 'sha256:9d9684f7a95e94c9eb370212edea832e7b9916b7bd96b2821c5bc9cf63a0e8b3',
  server: 'sha256:07f8a21105ed90963ccdf0981d884323116187583a464bb581db14c621d33a98',
});
const PORTS = [5500, 8101, 8103, 33080];
const FORMATS = Object.freeze({
  engine: '{"os":{{json .Server.Os}},"architecture":{{json .Server.Arch}},"version":{{json .Server.Version}}}',
  image: '{"id":{{json .Id}},"os":{{json .Os}},"architecture":{{json .Architecture}}}',
  container: '{"name":{{json .Name}},"id":{{json .Id}}}',
  network: '{"name":{{json .Name}},"id":{{json .Id}}}',
  volume: '{"name":{{json .Name}}}',
});
const fail = () => new Error('Fresh Docker preflight failed; no runtime mutation was requested.');
function exact(value, keys) {
  if (!value || typeof value !== 'object' || isProxy(value) || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value)) || Reflect.ownKeys(value).length !== keys.length) throw fail();
  const fields = Object.getOwnPropertyDescriptors(value);
  for (const key of keys) if (!fields[key] || !Object.hasOwn(fields[key], 'value')) throw fail();
  return Object.fromEntries(keys.map(key => [key, fields[key].value]));
}
function array(value, length) {
  if (!Array.isArray(value) || isProxy(value) || Object.getPrototypeOf(value) !== Array.prototype ||
      value.length !== length || Reflect.ownKeys(value).length !== length + 1) throw fail();
  const fields = Object.getOwnPropertyDescriptors(value);
  return Array.from({ length }, (_, i) => {
    if (!fields[i] || !Object.hasOwn(fields[i], 'value')) throw fail(); return fields[i].value;
  });
}
function validateRequest(value) {
  const request = exact(value, ['context', 'startVm', 'pull', 'build', 'images', 'ports', 'resources']);
  if (request.context !== CONTEXT || request.startVm !== false || request.pull !== false || request.build !== false) throw fail();
  const images = array(request.images, 2).map(item => exact(item, ['role', 'id', 'os', 'architecture']));
  for (const [role, id] of Object.entries(IMAGES)) {
    if (images.filter(item => item.role === role && item.id === id && item.os === 'linux' && item.architecture === 'arm64').length !== 1) throw fail();
  }
  const ports = array(request.ports, 4).map(item => exact(item, ['host', 'port']));
  for (const port of PORTS) if (ports.filter(item => item.host === '127.0.0.1' && item.port === port).length !== 1) throw fail();
  const resources = array(request.resources, 4).map(item => exact(item, ['kind', 'name']));
  const definitions = [['container', 'pg'], ['container', 'api'], ['network', 'net'], ['volume', 'data']];
  let suffix;
  for (const [kind, prefix] of definitions) {
    const matches = resources.filter(item => item.kind === kind && typeof item.name === 'string' &&
      new RegExp(`^fncp-fresh-${prefix}-[a-f0-9]{24}$`, 'u').test(item.name));
    if (matches.length !== 1) throw fail();
    const current = matches[0].name.slice(-24);
    if (suffix !== undefined && suffix !== current) throw fail(); suffix = current;
  }
  return { images, ports, resources };
}
function transportResult(value) {
  const result = exact(value, ['exitCode', 'stdout', 'stderr']);
  if (!Number.isInteger(result.exitCode) || result.exitCode < 0 || result.exitCode > 255 ||
      typeof result.stdout !== 'string' || typeof result.stderr !== 'string' ||
      Buffer.byteLength(result.stdout, 'utf8') > 4096 || Buffer.byteLength(result.stderr, 'utf8') > 4096 ||
      result.stdout.includes('\0') || result.stderr.includes('\0')) throw fail();
  return result;
}
function metadata(result, keys) {
  if (result.exitCode !== 0 || result.stderr !== '') throw fail();
  const text = result.stdout.trim(); const data = exact(JSON.parse(text), keys);
  // Fixed format projections produce compact, ordered JSON. Canonical equality
  // rejects duplicate keys, multiple results, injected fields or mixed log text.
  if (JSON.stringify(data) !== text) throw fail(); return data;
}
function requireAbsent(result, resource) {
  const { kind, name } = resource;
  if (result.exitCode === 0) {
    // Existing exact-name metadata is never adopted, even if it looks plausible.
    const item = metadata(result, kind === 'volume' ? ['name'] : ['name', 'id']);
    if (item.name !== name && !(kind === 'container' && item.name === '/' + name)) throw fail();
    throw fail();
  }
  const allowed = {
    container: [`Error: No such container: ${name}`, `Error response from daemon: No such container: ${name}`, `Error: No such object: ${name}`],
    network: [`Error response from daemon: network ${name} not found`, `Error: No such network: ${name}`, `Error: No such object: ${name}`],
    volume: [`Error response from daemon: get ${name}: no such volume`, `Error: No such volume: ${name}`, `Error: No such object: ${name}`],
  };
  if (result.exitCode !== 1 || result.stdout !== '' || !allowed[kind].includes(result.stderr.trim())) throw fail();
}
async function probeFixedLoopbackPort(value) {
  const input = exact(value, ['host', 'port']);
  if (input.host !== '127.0.0.1' || !PORTS.includes(input.port)) throw fail();
  const server = createServer({ pauseOnConnect: true }, socket => socket.destroy());
  const controller = new AbortController();
  let listened = false; let closed = false;
  // Aborting a Node listen operation closes that same server, including a pending
  // listen. No connection is made to or read from an already occupied service.
  const timer = setTimeout(() => controller.abort(), 1000);
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.once('close', () => { closed = true; resolve(); });
      server.listen({ host: input.host, port: input.port, exclusive: true, signal: controller.signal }, () => {
        listened = true; server.close();
      });
    });
    return listened && closed && !controller.signal.aborted;
  } finally { clearTimeout(timer); controller.abort(); }
}

/** Zero arguments selects the bounded concrete transport and local bind probes.
 * Tests must supply exactly {execute, probePort}; partial injection is rejected.
 * A completed result is only a point-in-time prerequisite check, not a lock,
 * exclusive resource creation, bootstrap, network assurance or launch authority. */
export function createDockerPreflight(options) {
  let execute = runDocker; let probePort = probeFixedLoopbackPort;
  if (arguments.length !== 0) {
    if (arguments.length !== 1) throw fail();
    const input = exact(options, ['execute', 'probePort']);
    if (typeof input.execute !== 'function' || isProxy(input.execute) ||
        typeof input.probePort !== 'function' || isProxy(input.probePort)) throw fail();
    ({ execute, probePort } = input);
  }
  let busy = false;
  return async function probe(request) {
    if (arguments.length !== 1 || busy) throw fail(); busy = true;
    try {
      await verifyFreshPolisRequest(request);
      const subjects = validateRequest(request);
      const command = async args => {
        await verifyFreshPolisRequest(request);
        const result = await execute(Object.freeze(args));
        await verifyFreshPolisRequest(request); return transportResult(result);
      };
      const engine = metadata(await command(['version', '--format', FORMATS.engine]), ['os', 'architecture', 'version']);
      if (engine.os !== 'linux' || engine.architecture !== 'arm64' || typeof engine.version !== 'string' ||
          !/^(0|[1-9]\d{0,3})\.(0|[1-9]\d{0,3})\.(0|[1-9]\d{0,3})$/u.test(engine.version) ||
          Number(engine.version.split('.')[0]) < 28) throw fail();
      for (const image of subjects.images) {
        const actual = metadata(await command(['image', 'inspect', image.id, '--format', FORMATS.image]), ['id', 'os', 'architecture']);
        if (actual.id !== image.id || actual.os !== 'linux' || actual.architecture !== 'arm64') throw fail();
      }
      for (const resource of subjects.resources) {
        requireAbsent(await command([resource.kind, 'inspect', resource.name, '--format', FORMATS[resource.kind]]), resource);
      }
      for (const port of subjects.ports) {
        await verifyFreshPolisRequest(request);
        const free = await probePort(Object.freeze({ ...port }));
        await verifyFreshPolisRequest(request); if (free !== true) throw fail();
      }
      return Object.freeze({ context: CONTEXT, running: true,
        images: Object.freeze(subjects.images.map(image => Object.freeze({ ...image }))),
        ports: Object.freeze(subjects.ports.map(port => Object.freeze({ ...port, free: true }))),
        resources: Object.freeze(subjects.resources.map(resource => Object.freeze({ ...resource, absent: true }))),
      });
    } catch { throw fail(); } finally { busy = false; }
  };
}
