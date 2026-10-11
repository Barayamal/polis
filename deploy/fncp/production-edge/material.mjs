import { dirname, join } from 'node:path';
import { readdirSync } from 'node:fs';
import { createMaterialCustody } from '../production-service/custody.mjs';
import { canonical, exact } from '../production-service/contracts.mjs';
import { CONTAINER_PROFILE, createContainerParticipantTransport } from './edge.mjs';

export const MATERIAL_FILES = Object.freeze(['config.json', 'server.pem', 'server-key.pem', 'upstream-ca.pem']);
const fail = () => new Error('Participant edge material rejected.');
/** Load only four canonical private files. No environment values or request data
 * can replace the fixed service endpoint, TLS material or authority. */
export function createContainerParticipantEdge({ configurationPath }) {
  const custody = createMaterialCustody(); let edge, closed = false;
  try {
    const directory = dirname(configurationPath);
    if (join(directory, 'config.json') !== configurationPath
      || canonical(readdirSync(directory).sort()) !== canonical([...MATERIAL_FILES].sort())) throw fail();
    const bytes = custody.read(configurationPath, 8192), config = JSON.parse(bytes.toString('utf8'));
    if (canonical(config) + '\n' !== bytes.toString('utf8')) throw fail();
    exact(config, ['version', 'profile', 'publicOrigin', 'discardCookies']);
    if (config.version !== 1 || config.profile !== CONTAINER_PROFILE) throw fail();
    edge = createContainerParticipantTransport({ publicOrigin: config.publicOrigin,
      listen: { host: '0.0.0.0', port: 8443 },
      upstream: { address: 'participant-edge-upstream', port: 8443, ca: custody.read(join(directory, 'upstream-ca.pem')) },
      tls: { key: custody.read(join(directory, 'server-key.pem')), cert: custody.read(join(directory, 'server.pem')) },
      discardCookies: config.discardCookies });
    const verify = () => {
      if (closed || canonical(readdirSync(directory).sort()) !== canonical([...MATERIAL_FILES].sort())) throw fail();
      return custody.verify();
    };
    return Object.freeze({
      async start() { verify(); return edge.start(); },
      verify,
      snapshot: edge.snapshot,
      fingerprints: custody.fingerprints,
      async close() { closed = true; try { return await edge.close(); } finally { custody.close(); } },
    });
  } catch { custody.close(); if (edge) void edge.close(); throw fail(); }
}
