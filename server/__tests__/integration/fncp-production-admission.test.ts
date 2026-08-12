import { describe, expect, jest, test } from "@jest/globals";

jest.mock("../../src/db/pg-query", () => ({
  __esModule: true,
  default: { queryP: jest.fn() },
}));

import {
  assertFncpProductionAdmission,
  FncpProductionAdmissionError,
} from "../../src/auth/fncp-production-admission";
import {
  evaluateFncpGatewayRequest,
  loadFncpGatewayConfig,
} from "../../src/auth/fncp-gateway";
import {
  FncpProviderPolicyUnavailableError,
  loadFncpProviderAllowlistConfig,
  resolveFncpManagedConversation,
  type FncpManagedConversationStore,
} from "../../src/fncp-provider-policy";

const conversationId = "4fncpintegration";

function productionEnv(overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    NODE_ENV: "production",
    FNCP_OPTION_C_RELEASE_MODE: "production",
    FNCP_GATEWAY_ENFORCEMENT: "true",
    FNCP_GATEWAY_CONVERSATION_ID: conversationId,
    FNCP_GATEWAY_SHARED_SECRET: "g".repeat(48),
    FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT: "true",
    FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID: conversationId,
    FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL: "p".repeat(48),
    ...overrides,
  };
}

function unusedStore(): FncpManagedConversationStore {
  return {
    getConfiguredConversationZid: jest.fn(),
    isExactProviderAuthorized: jest.fn(),
  };
}

describe("FNCP production admission integration", () => {
  test("binds the actual gateway and provider loaders to one admitted conversation", () => {
    const env = productionEnv();
    expect(assertFncpProductionAdmission(env)).toEqual({
      dedicated: true,
      conversationId,
    });
    expect(loadFncpGatewayConfig(env)).toMatchObject({
      enabled: true,
      activationValid: true,
      conversationId,
    });
    expect(loadFncpProviderAllowlistConfig(env)).toMatchObject({
      enabled: true,
      activationValid: true,
      conversationId,
    });
  });

  test("a disabled gateway flag remains enforced and unavailable at request time", () => {
    const env = productionEnv({ FNCP_GATEWAY_ENFORCEMENT: "false" });
    expect(() => assertFncpProductionAdmission(env)).toThrow(
      FncpProductionAdmissionError
    );

    const config = loadFncpGatewayConfig(env);
    expect(config).toMatchObject({
      enabled: true,
      activationValid: false,
    });
    expect(
      evaluateFncpGatewayRequest(
        {
          method: "GET",
          path: "/api/v3/participationInit",
          headers: {},
          query: { conversation_id: conversationId },
        },
        config
      )
    ).toEqual({
      enforce: true,
      status: 503,
      error: "FNCP gateway is not configured.",
    });
  });

  test("a disabled provider flag remains managed and unavailable at request time", async () => {
    const env = productionEnv({
      FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT: "false",
    });
    expect(() => assertFncpProductionAdmission(env)).toThrow(
      FncpProductionAdmissionError
    );

    const config = loadFncpProviderAllowlistConfig(env);
    expect(config).toMatchObject({
      enabled: true,
      activationValid: false,
    });
    const store = unusedStore();
    await expect(
      resolveFncpManagedConversation(71, { config, store })
    ).rejects.toBeInstanceOf(FncpProviderPolicyUnavailableError);
    expect(store.getConfiguredConversationZid).not.toHaveBeenCalled();
  });

  test("a misspelled dedicated release mode cannot fall back to ordinary policy", async () => {
    const env = productionEnv({ FNCP_OPTION_C_RELEASE_MODE: "prod" });
    expect(() => assertFncpProductionAdmission(env)).toThrow(
      FncpProductionAdmissionError
    );

    const gateway = loadFncpGatewayConfig(env);
    expect(gateway).toMatchObject({ enabled: true, activationValid: false });
    expect(
      evaluateFncpGatewayRequest(
        {
          method: "GET",
          path: "/api/v3/participationInit",
          headers: {},
          query: { conversation_id: conversationId },
        },
        gateway
      ).status
    ).toBe(503);

    const provider = loadFncpProviderAllowlistConfig(env);
    expect(provider).toMatchObject({ enabled: true, activationValid: false });
    await expect(
      resolveFncpManagedConversation(71, {
        config: provider,
        store: unusedStore(),
      })
    ).rejects.toBeInstanceOf(FncpProviderPolicyUnavailableError);
  });
});
