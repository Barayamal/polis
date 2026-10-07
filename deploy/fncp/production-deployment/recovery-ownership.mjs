import { canonical, exact } from '../production-service/contracts.mjs';
import { renderProductionCompose, validateProductionConfiguration, validateProductionImageLock, imageRoles } from './compose.mjs';
import { volumeRoles, failure } from './recovery-archive.mjs';

const equal = (a, b) => canonical(a) === canonical(b);
export const CORE_FILES = Object.freeze({ 'api.env': 0o600, 'database-ca.pem': 0o644,
  'database-math-password': 0o644, 'database-migration-password': 0o644, 'database-owner-password': 0o644,
  'database-runtime-password': 0o644, 'database-server.key': 0o644, 'database-server.pem': 0o644,
  'jwt-private.pem': 0o644, 'jwt-public.pem': 0o644, 'math.env': 0o600, 'migration.env': 0o600 });
export const EXTRA_CORE_FILES = Object.freeze({ 'local-ca.key': [0o600], 'database-ca.srl': [0o600, 0o644], 'database-server.csr': [0o600, 0o644], 'database-server.ext': [0o600, 0o644] });
export function environment(lines) {
  if (!Array.isArray(lines)) throw failure(); const value = {};
  for (const line of lines) { if (typeof line !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]*=[^\0\r\n]*$/u.test(line)) throw failure();
    const i = line.indexOf('='), key = line.slice(0, i); if (Object.hasOwn(value, key)) throw failure(); value[key] = line.slice(i + 1); }
  return value;
}
export function fileEnvironment(bytes) {
  const text = bytes.toString('utf8');
  if (!Buffer.from(text).equals(bytes) || !text.endsWith('\n') || /[\0\r$"'\\]/u.test(text)) throw failure();
  return environment(text.slice(0, -1).split('\n'));
}
function memory(value) { const m = /^([0-9]+)m$/u.exec(value); if (!m) throw failure(); return Number(m[1]) * 1024 * 1024; }
const ownerLabels = (row, labels) => Object.entries(labels).every(([k, v]) => row?.[k] === v);

/** Pure validation of fresh engine observations against the exact fixed normal
 * Compose recipe. The orchestrator obtains these observations itself; no caller
 * callback or serialized claim replaces a live engine inspection.
 */
export function validateStoppedProductionSnapshot(input) { return validateProductionSnapshot(input, false); }
/** Exact effective runtime check; health is required where the recipe defines a
 * health probe. This never treats running observations as stopped evidence. */
export function validateRunningProductionSnapshot(input) { return validateProductionSnapshot(input, true); }
function validateProductionSnapshot({ configuration, imageLock, ownerToken, rows, images, volumes, networks, coreMaterial }, running) {
  try {
    const c = validateProductionConfiguration(configuration), lock = validateProductionImageLock(imageLock), compose = renderProductionCompose(c, lock, ownerToken);
    const rolesExpected = imageRoles(c.version), durable = volumeRoles(c.version);
    if (!Array.isArray(rows) || rows.length < rolesExpected.length - 1 || rows.length > rolesExpected.length || running && rows.length !== rolesExpected.length - 1 || !Array.isArray(volumes) || volumes.length !== durable.length + 1) throw failure();
    const roles = new Set();
    for (const role of rolesExpected) {
      const image = images[role];
      if (!image || image.Id !== lock.images[role] || image.Os !== 'linux' || image.Architecture !== 'arm64'
        || image.Config?.Labels?.['org.opencontainers.image.revision'] !== lock.sourceRevision) throw failure();
    }
    for (const row of rows) {
      const role = row.Config?.Labels?.['com.docker.compose.service'], service = compose.services[role];
      if (!service || roles.has(role) || row.Id === undefined || !/^[a-f0-9]{64}$/u.test(row.Id)
        || !ownerLabels(row.Config.Labels, service.labels) || row.Config.Labels['com.docker.compose.project'] !== c.deployment
        || row.Image !== lock.images[role] || row.State?.Running !== running || row.State?.Paused || row.State?.Restarting || row.State?.Dead
        || row.State?.OOMKilled || row.State?.Error || row.State?.Status !== (running ? 'running' : 'exited')
        || running && (role === 'migration' || service.healthcheck && row.State.Health?.Status !== 'healthy')
        || !running && ['postgres', 'mariadb', 'participant'].includes(role) && row.State.ExitCode !== 0) throw failure();
      roles.add(role);
      const h = row.HostConfig;
      const expectedPorts = Object.fromEntries((service.ports ?? []).map(port => [port.target + '/' + port.protocol,
        [{ HostIp: port.host_ip, HostPort: String(port.published) }]]));
      const expectedRuntimePorts = running ? expectedPorts : {};
      const actualHostPorts = Object.fromEntries(Object.entries(h?.PortBindings ?? {}).filter(([,value]) => value !== null));
      const actualRuntimePorts = Object.fromEntries(Object.entries(row.NetworkSettings?.Ports ?? {}).filter(([,value]) => value !== null));
      if (!h || row.Config.User !== service.user || !h.ReadonlyRootfs || h.Privileged || h.PublishAllPorts || h.AutoRemove
        || h.RestartPolicy?.Name !== 'no' || !equal(h.CapDrop, ['ALL']) || (h.CapAdd ?? []).length
        || !equal(h.SecurityOpt, service.security_opt) || h.PidsLimit !== service.pids_limit || h.Memory !== memory(service.mem_limit)
        || h.NanoCpus !== Number(service.cpus) * 1e9 || h.PidMode || h.IpcMode !== 'private'
        || (h.Devices ?? []).length || (h.DeviceRequests ?? []).length || (h.ExtraHosts ?? []).length
        || !equal(actualHostPorts, expectedPorts) || !equal(actualRuntimePorts, expectedRuntimePorts)) throw failure();
      const expectedNetworks = Object.keys(service.networks ?? {}).map(n => compose.networks[n].name).sort();
      const actualNetworks = Object.keys(row.NetworkSettings?.Networks ?? {}).filter(n => n !== 'none').sort();
      if (!equal(expectedNetworks, actualNetworks) || h.NetworkMode !== (role === 'mariadb' ? 'none' : compose.networks[Object.keys(service.networks)[0]].name)) throw failure();
      const expectedMounts = service.volumes ?? [];
      if (!Array.isArray(row.Mounts) || row.Mounts.length !== expectedMounts.length) throw failure();
      for (const mount of expectedMounts) {
        const actual = row.Mounts.filter(m => m.Destination === mount.target);
        if (actual.length !== 1 || actual[0].Type !== mount.type || actual[0].RW !== !mount.read_only
          || mount.type === 'volume' && actual[0].Name !== compose.volumes[mount.source].name
          || mount.type === 'bind' && actual[0].Source !== mount.source) throw failure();
      }
      const tmpfs = Object.fromEntries(service.tmpfs.map(s => { const i = s.indexOf(':'); return [s.slice(0, i), s.slice(i + 1)]; }));
      if (!equal(h.Tmpfs ?? {}, tmpfs) || !equal(row.Config.Entrypoint ?? [], service.entrypoint ?? images[role].Config.Entrypoint ?? [])
        || !equal(row.Config.Cmd ?? [], service.command ?? images[role].Config.Cmd ?? [])
        || row.Config.WorkingDir !== (service.working_dir ?? images[role].Config.WorkingDir ?? '')) throw failure();
      let expectedEnv = environment(images[role].Config.Env ?? []);
      for (const path of service.env_file ?? []) {
        const name = path.slice(path.lastIndexOf('/') + 1), entry = coreMaterial[name]; if (!entry) throw failure();
        expectedEnv = { ...expectedEnv, ...fileEnvironment(Buffer.from(entry.data, 'base64')) };
      }
      expectedEnv = { ...expectedEnv, ...(service.environment ?? {}) };
      if (!equal(environment(row.Config.Env ?? []), expectedEnv)) throw failure();
    }
    if (rolesExpected.filter(role => role !== 'migration').some(role => !roles.has(role))) throw failure();
    for (const [role, expected] of Object.entries(compose.volumes)) {
      const matches = volumes.filter(v => v.Name === expected.name); if (matches.length !== 1) throw failure(); const v = matches[0];
      if (v.Driver !== 'local' || !ownerLabels(v.Labels, expected.labels) || v.Labels['com.docker.compose.project'] !== c.deployment
        || v.Labels['com.docker.compose.volume'] !== role || !equal(v.Options ?? {}, expected.driver_opts ?? {})) throw failure();
    }
    if (!Array.isArray(networks) || networks.length !== Object.keys(compose.networks).length) throw failure();
    for (const [role, expected] of Object.entries(compose.networks)) {
      const matches = networks.filter(n => n.Name === expected.name); if (matches.length !== 1) throw failure(); const n = matches[0];
      if (n.Driver !== 'bridge' || n.Internal !== expected.internal || n.Scope !== 'local'
        || !ownerLabels(n.Labels, expected.labels) || n.Labels['com.docker.compose.project'] !== c.deployment
        || n.Labels['com.docker.compose.network'] !== role || Object.keys(n.Options ?? {}).length) throw failure();
    }
    return Object.freeze({ ...(running ? { running: true } : { stopped: true }), services: rows.length, durableVolumes: durable.length, sourceRevision: lock.sourceRevision });
  } catch { throw failure(); }
}
