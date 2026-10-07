import { beforeEach, describe, expect, jest, test } from "@jest/globals";

jest.mock("../../src/db/pg-query", () => ({
  __esModule: true,
  default: {
    query: jest.fn(),
    queryP: jest.fn(),
    queryP_readOnly: jest.fn(),
  },
}));
jest.mock("../../src/fncp-provider-policy", () => ({
  resolveFncpManagedConversation: jest.fn(),
  isFncpProviderPolicyUnavailable: jest.fn(
    (error: unknown) =>
      error instanceof Error &&
      error.name === "FncpProviderPolicyUnavailableError"
  ),
}));
jest.mock("../../src/utils/common", () => ({
  ifDefinedSet: jest.fn(),
  isDuplicateKey: jest.fn(),
  isModerator: jest.fn(),
  isPolisDev: jest.fn(),
  isUserAllowedToCreateConversations: jest.fn(),
}));
jest.mock("../../src/utils/fail", () => ({
  failJson: jest.fn(),
}));
jest.mock("../../src/utils/logger", () => ({
  __esModule: true,
  default: {
    debug: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
  },
}));

import { resolveFncpManagedConversation } from "../../src/fncp-provider-policy";
import { handle_PUT_conversations } from "../../src/routes/conversations";
import { failJson } from "../../src/utils/fail";
import { isModerator } from "../../src/utils/common";

function response() {
  return {
    set: jest.fn(),
    status: jest.fn(() => ({ json: jest.fn() })),
  } as any;
}

function request(update: Record<string, unknown>) {
  return {
    p: {
      uid: 42,
      zid: 71,
      conversation_id: "9fncppolicyqa",
      ...update,
    },
  } as any;
}

describe("FNCP managed conversation mutation lock", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (isModerator as jest.Mock).mockResolvedValue(true);
    (resolveFncpManagedConversation as jest.Mock).mockResolvedValue({
      enforcementEnabled: true,
      managed: true,
    });
  });

  test.each([
    ["XID gate disable", { use_xid_whitelist: false }],
    ["XID requirement disable", { xid_required: false }],
    ["public conversation-id rotation", { short_url: true }],
  ])("rejects %s", async (_name, update) => {
    const res = response();

    await handle_PUT_conversations(request(update), res);

    expect(res.set).toHaveBeenCalledWith({ "Cache-Control": "no-store" });
    expect(failJson).toHaveBeenCalledWith(
      res,
      409,
      "polis_err_fncp_provider_managed_conversation"
    );
  });

  test("fails closed when the enabled provider target cannot be resolved", async () => {
    const unavailable = new Error("private detail");
    unavailable.name = "FncpProviderPolicyUnavailableError";
    (resolveFncpManagedConversation as jest.Mock).mockRejectedValue(unavailable);
    const res = response();

    await handle_PUT_conversations(request({ strict_moderation: true }), res);

    expect(res.set).toHaveBeenCalledWith({ "Cache-Control": "no-store" });
    expect(failJson).toHaveBeenCalledWith(
      res,
      503,
      "polis_err_fncp_provider_policy_unavailable"
    );
  });
});
