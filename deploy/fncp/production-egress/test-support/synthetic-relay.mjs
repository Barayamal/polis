import { isIP } from 'node:net';
import { exactData, freeze, hashPolicy } from '../policy.mjs';
import { createRelayRuntime } from '../relay-runtime.mjs';

const policies = new WeakSet();
const deny = () => new Error('Synthetic relay policy rejected.');
export function createSyntheticEgressPolicy(options) {
  try {
    exactData(options, ['tokenEndpoint', 'jwksUri', 'targets']); exactData(options.targets, ['token', 'jwks']);
    const routes = {};
    for (const name of ['token', 'jwks']) {
      const target = options.targets[name]; exactData(target, ['address', 'port']);
      const url = new URL(options[name === 'token' ? 'tokenEndpoint' : 'jwksUri']);
      if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash
        || url.href !== options[name === 'token' ? 'tokenEndpoint' : 'jwksUri']
        || !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)
        || !['127.0.0.1', '::1'].includes(target.address) || !isIP(target.address)
        || !Number.isSafeInteger(target.port) || target.port < 1 || target.port > 65535) throw deny();
      routes[name] = { endpoint: url.href, listenPort: 0, targetAddress: target.address, targetPort: target.port };
    }
    if (routes.token.endpoint === routes.jwks.endpoint) throw deny();
    const descriptor = { version: 1, profile: 'FNCP_SYNTHETIC_OIDC_RELAY_V1', routes };
    const policy = freeze({ ...descriptor, policySha256: hashPolicy(descriptor) }); policies.add(policy); return policy;
  } catch { throw deny(); }
}
export function createSyntheticFixedOidcRelay(options) {
  try {
    exactData(options, ['policy', 'listenHost'], ['timeoutMs']);
    if (!policies.has(options.policy) || !['127.0.0.1', '::1'].includes(options.listenHost)) throw deny();
    return createRelayRuntime(options);
  } catch { throw deny(); }
}
