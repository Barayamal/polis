import { beforeEach, describe, expect, jest, test } from "@jest/globals";

jest.mock("../../src/db/pg-query", () => ({
  __esModule: true,
  default: { queryP: jest.fn() },
}));

import pg from "../../src/db/pg-query";
import {
  FncpProviderPolicyUnavailableError,
  getFncpManagedXidDecision,
  postgresFncpManagedConversationStore,
  resolveFncpManagedConversation,
  type FncpManagedConversationStore,
} from "../../src/fncp-provider-policy";

const config = {
  enabled: true,
  activationValid: true,
  conversationId: "9fncppolicyqa",
  bearerCredential: "p".repeat(48),
};

function store(
  configuredZid: number | null = 71,
  exactAllowed = true
): FncpManagedConversationStore {
  return {
    getConfiguredConversationZid: jest
      .fn<FncpManagedConversationStore["getConfiguredConversationZid"]>()
      .mockResolvedValue(configuredZid),
    isExactProviderAuthorized: jest
      .fn<FncpManagedConversationStore["isExactProviderAuthorized"]>()
      .mockResolvedValue(exactAllowed),
  };
}

describe("FNCP provider-managed conversation policy", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test("preserves ordinary Pol.is behaviour while enforcement is disabled", async () => {
    const policyStore = store();
    await expect(
      resolveFncpManagedConversation(71, {
        config: { ...config, enabled: false },
        store: policyStore,
      })
    ).resolves.toEqual({
      enforcementEnabled: false,
      managed: false,
    });
    expect(policyStore.getConfiguredConversationZid).not.toHaveBeenCalled();
  });

  test("distinguishes the exact configured conversation from other conversations", async () => {
    const policyStore = store(71);
    await expect(
      resolveFncpManagedConversation(71, {
        config,
        store: policyStore,
      })
    ).resolves.toEqual({ enforcementEnabled: true, managed: true });
    await expect(
      resolveFncpManagedConversation(72, {
        config,
        store: policyStore,
      })
    ).resolves.toEqual({ enforcementEnabled: true, managed: false });
  });

  test.each([
    [{ ...config, enabled: false, activationValid: false }, store()],
    [{ ...config, conversationId: "" }, store()],
    [{ ...config, bearerCredential: "short" }, store()],
    [config, store(null)],
  ])(
    "fails closed when enabled policy configuration or target resolution is uncertain",
    async (inputConfig, policyStore) => {
      await expect(
        resolveFncpManagedConversation(71, {
          config: inputConfig,
          store: policyStore,
        })
      ).rejects.toBeInstanceOf(FncpProviderPolicyUnavailableError);
    }
  );

  test("requires the exact provider operation decision for the managed conversation", async () => {
    await expect(
      getFncpManagedXidDecision(71, "fncp_exact-xid-0001", {
        config,
        store: store(71, true),
      })
    ).resolves.toBe(true);
    await expect(
      getFncpManagedXidDecision(71, "fncp_raw-or-removed-xid", {
        config,
        store: store(71, false),
      })
    ).resolves.toBe(false);
    await expect(
      getFncpManagedXidDecision(72, "ordinary-polis-xid", {
        config,
        store: store(71, false),
      })
    ).resolves.toBeUndefined();
  });

  test("the PostgreSQL authorization query requires exact zid, XID and accepted v1 state", async () => {
    (pg.queryP as jest.Mock).mockResolvedValue([{ allowed: false }]);

    await expect(
      postgresFncpManagedConversationStore.isExactProviderAuthorized(
        71,
        "fncp_readded-after-remove"
      )
    ).resolves.toBe(false);

    const [sql, values] = (pg.queryP as jest.Mock).mock.calls[0];
    expect(sql).toContain("allowed.zid = $1");
    expect(sql).toContain("allowed.xid = $2");
    expect(sql).toContain("fncp_provider_allowlist_operations");
    expect(sql).toContain("operation.operation_version = 1");
    expect(sql).toContain("operation.desired_present IS TRUE");
    expect(sql).not.toContain("zid IS NULL");
    expect(values).toEqual([71, "fncp_readded-after-remove"]);
  });
});
