/**
 * Startup admission for the dedicated First Nations Community Pulse release.
 *
 * Ordinary upstream Pol.is deployments remain unchanged while
 * FNCP_OPTION_C_RELEASE_MODE is absent. Once that variable is present, only the
 * exact production contract is accepted; a typo must not silently select the
 * ordinary Pol.is path.
 */

import crypto from "node:crypto";

import { loadFncpProviderAllowlistConfig } from "../fncp-provider-policy";
import { loadFncpGatewayConfig } from "./fncp-gateway";

const DEDICATED_RELEASE_MODE = "production";
const CONVERSATION_ID = /^[0-9][0-9A-Za-z]{5,99}$/u;
const CREDENTIAL = /^[A-Za-z0-9_-]{32,512}$/u;

export type FncpProductionAdmissionFailure =
  | "release-mode"
  | "node-environment"
  | "gateway-enforcement"
  | "provider-enforcement"
  | "conversation-binding"
  | "gateway-credential"
  | "provider-credential"
  | "credential-separation";

export type FncpProductionAdmission =
  | { dedicated: false }
  | { dedicated: true; conversationId: string };

export class FncpProductionAdmissionError extends Error {
  readonly failure: FncpProductionAdmissionFailure;

  constructor(failure: FncpProductionAdmissionFailure) {
    super(`FNCP dedicated production admission failed (${failure}).`);
    this.name = "FncpProductionAdmissionError";
    this.failure = failure;
  }
}

/**
 * Refuse startup unless the complete dedicated release boundary is present.
 *
 * This function deliberately reports only the failed field class. It never
 * includes a conversation identifier or credential value in its error.
 */
export function assertFncpProductionAdmission(
  // eslint-disable-next-line no-restricted-properties
  env: NodeJS.ProcessEnv = process.env
): FncpProductionAdmission {
  const releaseMode = env.FNCP_OPTION_C_RELEASE_MODE;
  if (releaseMode === undefined) {
    return { dedicated: false };
  }
  if (releaseMode !== DEDICATED_RELEASE_MODE) {
    throw new FncpProductionAdmissionError("release-mode");
  }
  if (env.NODE_ENV !== "production") {
    throw new FncpProductionAdmissionError("node-environment");
  }
  if (env.FNCP_GATEWAY_ENFORCEMENT !== "true") {
    throw new FncpProductionAdmissionError("gateway-enforcement");
  }
  if (env.FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT !== "true") {
    throw new FncpProductionAdmissionError("provider-enforcement");
  }

  const gateway = loadFncpGatewayConfig(env);
  const provider = loadFncpProviderAllowlistConfig(env);
  if (
    !gateway.activationValid ||
    !CONVERSATION_ID.test(gateway.conversationId)
  ) {
    throw new FncpProductionAdmissionError("conversation-binding");
  }
  if (
    !provider.activationValid ||
    !CONVERSATION_ID.test(provider.conversationId) ||
    provider.conversationId !== gateway.conversationId
  ) {
    throw new FncpProductionAdmissionError("conversation-binding");
  }
  if (!CREDENTIAL.test(gateway.sharedSecret)) {
    throw new FncpProductionAdmissionError("gateway-credential");
  }
  if (!CREDENTIAL.test(provider.bearerCredential)) {
    throw new FncpProductionAdmissionError("provider-credential");
  }
  if (sameCredential(gateway.sharedSecret, provider.bearerCredential)) {
    throw new FncpProductionAdmissionError("credential-separation");
  }

  return { dedicated: true, conversationId: gateway.conversationId };
}

function sameCredential(left: string, right: string): boolean {
  const leftDigest = crypto.createHash("sha256").update(left).digest();
  const rightDigest = crypto.createHash("sha256").update(right).digest();
  return crypto.timingSafeEqual(leftDigest, rightDigest);
}
