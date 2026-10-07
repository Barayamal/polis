#!/usr/bin/env node
// Local WIP provenance, not a release attestation or vulnerability clearance.
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { readStagingProvider } from './local-access/staging-config.mjs';

process.umask(0o077);
const root = fileURLToPath(new URL('../../', import.meta.url));
const context = 'colima-fncp-c-20260913';
const services = ['postgres', 'oidc-simulator', 'server', 'math', 'client-participation-alpha', 'nginx-proxy'];
const run = (command, args) => execFileSync(command, args, { cwd: root, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });

try {
  const closed = process.argv.length === 3 && process.argv[2] === '--closed';
  if (process.argv.length !== 2 && !closed) throw new Error('Unknown capture mode.');
  readStagingProvider(process.env.FNCP_LOCAL_SYNTHETIC_MODE);
  const manifest = JSON.parse(run(process.execPath, ['deploy/fncp/image-security-evidence.mjs', 'source-manifest']));
  const images = services.map((service) => {
    const name = `fncp-polis-staging-${service}-1`;
    const [container] = JSON.parse(run('docker', ['--context', context, 'inspect', name]));
    if (container.Config.Labels?.['com.docker.compose.project'] !== 'fncp-polis-staging' ||
        container.Config.Labels?.['com.docker.compose.service'] !== service || container.State.Running !== !closed) {
      throw new Error('Expected local service state does not match.');
    }
    const ports = container.HostConfig.PortBindings ?? {};
    if (Object.values(ports).flat().some((binding) => binding?.HostIp !== '127.0.0.1')) {
      throw new Error('Non-loopback listener rejected.');
    }
    const [image] = JSON.parse(run('docker', ['--context', context, 'image', 'inspect', container.Image]));
    return { service, imageId: image.Id, architecture: image.Architecture,
      os: image.Os, sourceRevisionLabel: image.Config.Labels?.['org.opencontainers.image.revision'] ?? null,
      configuredPublishedPorts: ports, running: container.State.Running };
  });
  const generatedAt = new Date().toISOString();
  const folder = new URL(`./evidence/local-wip-${generatedAt.replace(/[:.]/g, '-')}/`, import.meta.url);
  mkdirSync(folder, { recursive: true, mode: 0o700 });
  writeFileSync(new URL('source-manifest.json', folder), JSON.stringify(manifest, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  writeFileSync(new URL('runtime.json', folder), JSON.stringify({ generatedAt, context, runtimeState: closed ? 'CLOSED' : 'RUNNING',
    classification: 'LOCAL_SYNTHETIC_WIP_NOT_RELEASE_ATTESTATION',
    note: 'Source includes uncommitted local changes; baseline revision labels alone do not identify the patched build. No full image vulnerability scan is claimed.',
    sourceAggregateSha256: manifest.source.aggregateSha256, images }, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  console.log(`Local WIP provenance saved: ${fileURLToPath(folder)}`);
  console.log('No credentials, participant identifiers, environment values or database contents exported.');
} catch {
  console.error('Local provenance capture failed; no release assurance claimed.');
  process.exitCode = 1;
}
