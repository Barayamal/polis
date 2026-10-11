import { fail } from './configuration.mjs';

/** Match observed storage and isolation to the reviewed rendered service.
 * Ownership labels alone cannot bind a process to its intended database volume
 * or certificate files, and an attached second network can bypass isolation. */
export function assertContainerProfile(row, service, configuration) {
  const reject = () => { throw fail('CONTAINER_PROFILE'); };
  if (!row || row.Config?.User !== service.user || !row.HostConfig?.ReadonlyRootfs
    || row.HostConfig.Privileged || row.HostConfig.PublishAllPorts
    || row.HostConfig.RestartPolicy?.Name !== service.restart
    || !row.HostConfig.CapDrop?.includes('ALL') || row.HostConfig.CapAdd?.length
    || !Array.isArray(row.HostConfig.SecurityOpt)
    || row.HostConfig.SecurityOpt.length !== service.security_opt.length
    || service.security_opt.some(option => !row.HostConfig.SecurityOpt.includes(option))
    || Object.keys(row.HostConfig.PortBindings ?? {}).length
    || Object.values(row.NetworkSettings?.Ports ?? {}).some(value => value !== null && (!Array.isArray(value) || value.length))) reject();
  const network = `${configuration.deployment}_private`;
  const networks = Object.keys(row.NetworkSettings?.Networks ?? {});
  if (row.HostConfig.NetworkMode !== network || networks.length !== 1 || networks[0] !== network) reject();
  const expected = service.volumes ?? [];
  if (!Array.isArray(row.Mounts) || row.Mounts.length !== expected.length) reject();
  for (const volume of expected) {
    const actual = row.Mounts.filter(mount => mount.Destination === volume.target);
    if (actual.length !== 1 || actual[0].Type !== volume.type || actual[0].RW !== !volume.read_only) reject();
    if (volume.type === 'bind' && actual[0].Source !== volume.source) reject();
    if (volume.type === 'volume' && actual[0].Name !== `${configuration.deployment}_${volume.source}`) reject();
  }
  const tmpfs = Object.fromEntries((service.tmpfs ?? []).map(entry => {
    const separator = entry.indexOf(':'); return [entry.slice(0, separator), entry.slice(separator + 1)];
  }));
  const actualTmpfs = row.HostConfig.Tmpfs ?? {};
  if (Object.keys(actualTmpfs).length !== Object.keys(tmpfs).length
    || Object.entries(tmpfs).some(([path, options]) => actualTmpfs[path] !== options)) reject();
  return true;
}
