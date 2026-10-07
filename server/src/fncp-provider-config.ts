/** Pure provider configuration shared by startup admission and runtime policy.
 * Importing this module must not load the application or database clients.
 */
const CONVERSATION_ID = /^[0-9][0-9A-Za-z]{1,99}$/u;
const CREDENTIAL = /^[A-Za-z0-9_-]{32,512}$/u;

export interface FncpProviderAllowlistConfig {
  enabled: boolean;
  activationValid: boolean;
  conversationId: string;
  bearerCredential: string;
}

export function loadFncpProviderAllowlistConfig(
  // Read for every decision so a dedicated release remains fail-closed if its
  // configuration changes unexpectedly. Do not disable this switch as an
  // emergency action: deny ingress and revoke invitations instead.
  // eslint-disable-next-line no-restricted-properties
  env: NodeJS.ProcessEnv = process.env
): FncpProviderAllowlistConfig {
  const activation = env.FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT;
  const dedicatedReleaseConfigured =
    env.FNCP_OPTION_C_RELEASE_MODE !== undefined;
  const dedicatedProduction = env.FNCP_OPTION_C_RELEASE_MODE === "production";
  return {
    enabled: dedicatedReleaseConfigured || activation === "true",
    activationValid:
      (activation === undefined ||
        activation === "false" ||
        activation === "true") &&
      (!dedicatedReleaseConfigured ||
        (dedicatedProduction && activation === "true")),
    conversationId: env.FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID || "",
    bearerCredential: env.FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL || "",
  };
}

export function isFncpProviderAllowlistConfigReady(
  config: FncpProviderAllowlistConfig
): boolean {
  return (
    config.enabled &&
    config.activationValid &&
    CONVERSATION_ID.test(config.conversationId) &&
    CREDENTIAL.test(config.bearerCredential)
  );
}
