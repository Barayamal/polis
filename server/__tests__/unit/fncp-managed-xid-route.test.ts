import { beforeEach, describe, expect, jest, test } from "@jest/globals";

jest.mock("../../src/db/pg-query", () => ({
  __esModule: true,
  default: {
    queryP: jest.fn(),
    queryP_readOnly: jest.fn(),
  },
}));
jest.mock("../../src/conversation", () => ({
  getConversationInfo: jest.fn(),
}));
jest.mock("../../src/fncp-provider-policy", () => ({
  resolveFncpManagedConversation: jest.fn(),
  isFncpProviderPolicyUnavailable: jest.fn(
    (error: unknown) =>
      error instanceof Error &&
      error.name === "FncpProviderPolicyUnavailableError"
  ),
}));
jest.mock("../../src/xids", () => ({
  getXids: jest.fn(),
}));
jest.mock("../../src/utils/common", () => ({
  __esModule: true,
  default: {
    isModerator: jest.fn(),
    escapeLiteral: jest.fn((value: string) => `'${value}'`),
  },
}));
jest.mock("../../src/utils/logger", () => ({
  __esModule: true,
  default: {
    debug: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
  },
}));
jest.mock("../../src/utils/fail", () => ({
  failJson: jest.fn(),
}));

import { getConversationInfo } from "../../src/conversation";
import pg from "../../src/db/pg-query";
import { resolveFncpManagedConversation } from "../../src/fncp-provider-policy";
import { handle_POST_xidAllowList } from "../../src/routes/xids";
import { failJson } from "../../src/utils/fail";
import Utils from "../../src/utils/common";

function response() {
  const json = jest.fn();
  const status = jest.fn(() => ({ json }));
  const set = jest.fn();
  return { status, json, set } as any;
}

function request() {
  return {
    p: {
      uid: 42,
      zid: 71,
      xid_allow_list: ["fncp_standard-route-attempt"],
      replace_all: false,
    },
  } as any;
}

describe("FNCP standard moderator XID route lock", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (Utils.isModerator as jest.Mock).mockResolvedValue(true);
    (getConversationInfo as jest.Mock).mockResolvedValue({ owner: 42 });
  });

  test("rejects standard allowlist mutation for the managed conversation", async () => {
    (resolveFncpManagedConversation as jest.Mock).mockResolvedValue({
      enforcementEnabled: true,
      managed: true,
    });
    const res = response();

    await handle_POST_xidAllowList(request(), res);

    expect(res.set).toHaveBeenCalledWith({ "Cache-Control": "no-store" });
    expect(failJson).toHaveBeenCalledWith(
      res,
      409,
      "polis_err_fncp_provider_managed_allowlist"
    );
    expect(pg.queryP).not.toHaveBeenCalled();
  });

  test("preserves the ordinary moderator allowlist path for other conversations", async () => {
    (resolveFncpManagedConversation as jest.Mock).mockResolvedValue({
      enforcementEnabled: true,
      managed: false,
    });
    (pg.queryP as jest.Mock).mockResolvedValue([]);
    const res = response();

    await handle_POST_xidAllowList(request(), res);

    expect(failJson).not.toHaveBeenCalled();
    expect(pg.queryP).toHaveBeenCalledWith(
      expect.stringContaining("insert into xid_whitelist"),
      []
    );
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({});
  });

  test("does not mutate when enabled provider policy is uncertain", async () => {
    const unavailable = new Error("private detail");
    unavailable.name = "FncpProviderPolicyUnavailableError";
    (resolveFncpManagedConversation as jest.Mock).mockRejectedValue(unavailable);
    const res = response();

    await handle_POST_xidAllowList(request(), res);

    expect(res.set).toHaveBeenCalledWith({ "Cache-Control": "no-store" });
    expect(failJson).toHaveBeenCalledWith(
      res,
      503,
      "polis_err_fncp_provider_policy_unavailable"
    );
    expect(pg.queryP).not.toHaveBeenCalled();
  });
});
