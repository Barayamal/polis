import { readFileSync } from 'node:fs';
import { parseEnv } from 'node:util';
import { LocalPolisProvider, MODE } from './access-server.mjs';

export function readStagingProvider(mode) {
  if (mode !== MODE) throw new Error('Set FNCP_LOCAL_SYNTHETIC_MODE=fixture-only explicitly.');
  const env = parseEnv(readFileSync(new URL('../.env.staging', import.meta.url), 'utf8'));
  if (env.FNCP_SYNTHETIC_BOOTSTRAP_COMPLETE !== 'true' ||
      env.FNCP_GATEWAY_ENFORCEMENT !== 'true' ||
      env.FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT !== 'true' ||
      env.FNCP_GATEWAY_CONVERSATION_ID !== env.FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID ||
      env.FNCP_GATEWAY_CONVERSATION_ID?.startsWith('9fncpBootstrap')) {
    throw new Error('Synthetic conversation must be bootstrapped and both policies enabled.');
  }
  const provider = new LocalPolisProvider({
    conversationId: env.FNCP_GATEWAY_CONVERSATION_ID,
    gatewaySecret: env.FNCP_GATEWAY_SHARED_SECRET,
    providerSecret: env.FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL,
  });
  return { provider, conversationId: provider.conversationId };
}
