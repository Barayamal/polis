import { exactData, isPrivateListenAddress, isProductionEgressPolicy } from './policy.mjs';
import { createRelayRuntime } from './relay-runtime.mjs';

export function createFixedOidcRelay(options) {
  try {
    exactData(options, ['policy', 'listenHost'], ['timeoutMs']);
    if (!isProductionEgressPolicy(options.policy) || !isPrivateListenAddress(options.listenHost)) throw new Error();
    return createRelayRuntime(options);
  } catch { throw new Error('OIDC relay unavailable.'); }
}
