/**
 * Shared fail-closed policy for the single conversation managed by the FNCP
 * provider allowlist adapter.
 *
 * The public moderator allowlist API predates the provider operation ledger.
 * Once provider enforcement is enabled, the configured conversation must use
 * the exact conversation-scoped row and the accepted v1 provider operation;
 * legacy owner-scoped rows are deliberately not authoritative.
 */

import pg from "./db/pg-query";
import {
  type FncpProviderAllowlistConfig,
  loadFncpProviderAllowlistConfig,
  isFncpProviderAllowlistConfigReady,
} from "./fncp-provider-config";
export {
  type FncpProviderAllowlistConfig,
  loadFncpProviderAllowlistConfig,
  isFncpProviderAllowlistConfigReady,
} from "./fncp-provider-config";

export interface FncpManagedConversationPolicy {
  enforcementEnabled: boolean;
  managed: boolean;
}

export interface FncpManagedConversationStore {
  getConfiguredConversationZid(conversationId: string): Promise<number | null>;
  isExactProviderAuthorized(zid: number, xid: string): Promise<boolean>;
}

export class FncpProviderPolicyUnavailableError extends Error {
  constructor() {
    super("FNCP provider policy is unavailable.");
    this.name = "FncpProviderPolicyUnavailableError";
  }
}

export function isFncpProviderPolicyUnavailable(
  error: unknown
): error is FncpProviderPolicyUnavailableError {
  return error instanceof FncpProviderPolicyUnavailableError;
}

export const postgresFncpManagedConversationStore: FncpManagedConversationStore =
  {
    async getConfiguredConversationZid(conversationId) {
      const rows = (await pg.queryP<{ zid: number }>(
        `SELECT c.zid
           FROM zinvites z
           INNER JOIN conversations c ON c.zid = z.zid
          WHERE z.zinvite = $1;`,
        [conversationId]
      )) as { zid: number }[];
      if (
        rows.length !== 1 ||
        !Number.isSafeInteger(rows[0]?.zid) ||
        (rows[0]?.zid ?? 0) <= 0
      ) {
        return null;
      }
      return rows[0].zid;
    },

    async isExactProviderAuthorized(zid, xid) {
      const rows = (await pg.queryP<{ allowed: boolean }>(
        `SELECT EXISTS (
           SELECT 1
             FROM xid_whitelist allowed
             INNER JOIN conversations c
               ON c.zid = allowed.zid
              AND c.owner = allowed.owner
             INNER JOIN fncp_provider_allowlist_operations operation
               ON operation.zid = allowed.zid
              AND operation.xid = allowed.xid
            WHERE allowed.zid = $1
              AND allowed.xid = $2
              AND operation.operation_version = 1
              AND operation.desired_present IS TRUE
        ) AS allowed;`,
        [zid, xid]
      )) as { allowed: boolean }[];
      if (rows.length !== 1 || typeof rows[0]?.allowed !== "boolean") {
        throw new FncpProviderPolicyUnavailableError();
      }
      return rows[0].allowed;
    },
  };

interface FncpProviderPolicyDependencies {
  config?: FncpProviderAllowlistConfig;
  store?: FncpManagedConversationStore;
}

/**
 * Resolves the configured public conversation id to its immutable internal
 * zid. Any enabled-but-invalid configuration, missing target or database
 * uncertainty is an error rather than an implicit policy disable.
 */
export async function resolveFncpManagedConversation(
  zid: number,
  dependencies: FncpProviderPolicyDependencies = {}
): Promise<FncpManagedConversationPolicy> {
  const config = dependencies.config ?? loadFncpProviderAllowlistConfig();
  if (!config.activationValid) {
    throw new FncpProviderPolicyUnavailableError();
  }
  if (!config.enabled) {
    return { enforcementEnabled: false, managed: false };
  }
  if (
    !Number.isSafeInteger(zid) ||
    zid <= 0 ||
    !isFncpProviderAllowlistConfigReady(config)
  ) {
    throw new FncpProviderPolicyUnavailableError();
  }

  const store = dependencies.store ?? postgresFncpManagedConversationStore;
  let configuredZid: number | null;
  try {
    configuredZid = await store.getConfiguredConversationZid(
      config.conversationId
    );
  } catch {
    throw new FncpProviderPolicyUnavailableError();
  }
  if (configuredZid === null) {
    throw new FncpProviderPolicyUnavailableError();
  }
  return {
    enforcementEnabled: true,
    managed: configuredZid === zid,
  };
}

/**
 * Returns undefined when the conversation is outside provider management so
 * the caller can retain normal Pol.is allowlist behaviour.
 */
export async function getFncpManagedXidDecision(
  zid: number,
  xid: string,
  dependencies: FncpProviderPolicyDependencies = {}
): Promise<boolean | undefined> {
  const policy = await resolveFncpManagedConversation(zid, dependencies);
  if (!policy.managed) {
    return undefined;
  }
  const store = dependencies.store ?? postgresFncpManagedConversationStore;
  try {
    return await store.isExactProviderAuthorized(zid, xid);
  } catch {
    throw new FncpProviderPolicyUnavailableError();
  }
}
