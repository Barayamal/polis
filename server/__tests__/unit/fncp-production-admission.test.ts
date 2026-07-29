import { describe, expect, jest, test } from "@jest/globals";

jest.mock("../../src/db/pg-query", () => ({
  __esModule: true,
  default: { queryP: jest.fn() },
}));

import {
  assertFncpProductionAdmission,
  FncpProductionAdmissionError,
  type FncpProductionAdmissionFailure,
} from "../../src/auth/fncp-production-admission";

const conversationId = "4fncpproduction";
const gatewayCredential = "g".repeat(48);
const providerCredential = "p".repeat(48);

function productionEnv(overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    NODE_ENV: "production",
    FNCP_OPTION_C_RELEASE_MODE: "production",
    FNCP_GATEWAY_ENFORCEMENT: "true",
    FNCP_GATEWAY_CONVERSATION_ID: conversationId,
    FNCP_GATEWAY_SHARED_SECRET: gatewayCredential,
    FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT: "true",
    FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID: conversationId,
    FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL: providerCredential,
    ...overrides,
  };
}

function expectFailure(
  env: NodeJS.ProcessEnv,
  failure: FncpProductionAdmissionFailure
): void {
  try {
    assertFncpProductionAdmission(env);
    throw new Error("Expected production admission to fail.");
  } catch (error) {
    expect(error).toBeInstanceOf(FncpProductionAdmissionError);
    expect((error as FncpProductionAdmissionError).failure).toBe(failure);
    expect(String(error)).not.toContain(conversationId);
    expect(String(error)).not.toContain(gatewayCredential);
    expect(String(error)).not.toContain(providerCredential);
  }
}

describe("FNCP dedicated production startup admission", () => {
  test("preserves ordinary upstream Pol.is while release mode is absent", () => {
    expect(
      assertFncpProductionAdmission({
        NODE_ENV: "production",
        FNCP_GATEWAY_ENFORCEMENT: "false",
        FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT: "false",
      })
    ).toEqual({ dedicated: false });
  });

  test("admits only the complete exact production contract", () => {
    expect(assertFncpProductionAdmission(productionEnv())).toEqual({
      dedicated: true,
      conversationId,
    });
  });

  test.each(["", "prod", "true", "false"])(
    "rejects present but invalid release mode %p",
    (releaseMode) => {
      expectFailure(
        productionEnv({ FNCP_OPTION_C_RELEASE_MODE: releaseMode }),
        "release-mode"
      );
    }
  );

  test("requires the Node production runtime", () => {
    expectFailure(
      productionEnv({ NODE_ENV: "development" }),
      "node-environment"
    );
  });

  test.each([undefined, "false", "TRUE", "1"])(
    "rejects missing, false or malformed gateway enforcement %p",
    (activation) => {
      expectFailure(
        productionEnv({ FNCP_GATEWAY_ENFORCEMENT: activation }),
        "gateway-enforcement"
      );
    }
  );

  test.each([undefined, "false", "TRUE", "1"])(
    "rejects missing, false or malformed provider enforcement %p",
    (activation) => {
      expectFailure(
        productionEnv({
          FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT: activation,
        }),
        "provider-enforcement"
      );
    }
  );

  test.each([
    {
      FNCP_GATEWAY_CONVERSATION_ID: "4differentconversation",
    },
    {
      FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID: "4differentconversation",
    },
    {
      FNCP_GATEWAY_CONVERSATION_ID: "invalid conversation",
      FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID: "invalid conversation",
    },
  ])("rejects mismatched or invalid conversation binding", (overrides) => {
    expectFailure(productionEnv(overrides), "conversation-binding");
  });

  test("requires a valid gateway credential", () => {
    expectFailure(
      productionEnv({ FNCP_GATEWAY_SHARED_SECRET: "short" }),
      "gateway-credential"
    );
  });

  test("requires a valid provider credential", () => {
    expectFailure(
      productionEnv({
        FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL: "not valid because spaces",
      }),
      "provider-credential"
    );
  });

  test("requires independent gateway and provider credentials", () => {
    expectFailure(
      productionEnv({
        FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL: gatewayCredential,
      }),
      "credential-separation"
    );
  });
});
