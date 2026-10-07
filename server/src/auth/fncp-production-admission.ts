/**
 * Startup admission for the dedicated First Nations Community Pulse release.
 *
 * Ordinary upstream Pol.is deployments remain unchanged while
 * FNCP_OPTION_C_RELEASE_MODE is absent. Once that variable is present, only the
 * exact production contract is accepted; a typo must not silently select the
 * ordinary Pol.is path.
 */

import crypto from "node:crypto";
import { isAbsolute } from "node:path";

import { loadFncpProviderAllowlistConfig } from "../fncp-provider-config";
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
  | "credential-separation"
  | "fixed-statements"
  | "database-tls"
  | "runtime-profile";

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
  if (!gateway.fixedStatementIds || gateway.fixedStatementIds.size !== 15) {
    throw new FncpProductionAdmissionError("fixed-statements");
  }
  // This check stays pure; the CA loader validates the actual file before any
  // Pool is created. Dedicated releases must never select the legacy insecure
  // DATABASE_SSL fallback or URL query options that replace pg's TLS object.
  const caPath = env.DATABASE_SSL_CA_FILE;
  if (env.DATABASE_SSL !== "true" || !caPath || !isAbsolute(caPath) ||
      /[\u0000-\u0020\u007f]/u.test(caPath) ||
      !validDatabaseUrl(env.DATABASE_URL) ||
      !validDatabaseUrl(env.READ_ONLY_DATABASE_URL ?? env.DATABASE_URL) ||
      (env.NODE_TLS_REJECT_UNAUTHORIZED !== undefined && env.NODE_TLS_REJECT_UNAUTHORIZED !== "1")) {
    throw new FncpProductionAdmissionError("database-tls");
  }
  const disabled = ["DEV_MODE", "TESTING", "ENABLE_TELEMETRY", "SHOULD_USE_TRANSLATION_API",
    "BACKFILL_COMMENT_LANG_DETECTION", "RUN_PERIODIC_EXPORT_TESTS", "SERVER_LOG_TO_FILE"];
  if (disabled.some(key => env[key] !== undefined && env[key] !== "false") ||
      env.FNCP_FRESH_BOOTSTRAP_LOCAL_ONLY !== undefined) {
    throw new FncpProductionAdmissionError("runtime-profile");
  }

  return { dedicated: true, conversationId: gateway.conversationId };
}

function validDatabaseUrl(value: string | undefined): boolean {
  try {
    if (!value || /[\u0000-\u0020\u007f]/u.test(value)) return false;
    const url = new URL(value);
    return ["postgres:", "postgresql:"].includes(url.protocol) && !!url.hostname &&
      !!url.username && !!url.password && /^\/[^/]+$/u.test(url.pathname) && !url.search && !url.hash;
  } catch { return false; }
}

function sameCredential(left: string, right: string): boolean {
  const leftDigest = crypto.createHash("sha256").update(left).digest();
  const rightDigest = crypto.createHash("sha256").update(right).digest();
  return crypto.timingSafeEqual(leftDigest, rightDigest);
}
