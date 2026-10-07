import { beforeEach, describe, expect, jest, test } from "@jest/globals";

jest.mock("../../src/auth/create-user", () => ({
  createAnonUser: jest.fn(),
}));
jest.mock("../../src/xids", () => ({
  createXidRecord: jest.fn(),
  isXidAllowed: jest.fn(),
  xidExists: jest.fn(),
}));
jest.mock("../../src/auth/auth", () => ({
  deleteSuzinvite: jest.fn(),
}));
jest.mock("../../src/utils/fail", () => ({
  failJson: jest.fn(),
}));
jest.mock("../../src/conversation", () => ({
  getConversationInfo: jest.fn(),
}));
jest.mock("../../src/fncp-provider-policy", () => ({
  getFncpManagedXidDecision: jest.fn(),
  resolveFncpManagedConversation: jest.fn(),
  isFncpProviderPolicyUnavailable: jest.fn(
    (error: unknown) =>
      error instanceof Error &&
      error.name === "FncpProviderPolicyUnavailableError"
  ),
}));
jest.mock("../../src/invites/suzinvites", () => ({
  getSUZinviteInfo: jest.fn(),
}));
jest.mock("../../src/user", () => ({
  getUserInfoForUid2: jest.fn(),
}));
jest.mock("../../src/auth/anonymous-jwt", () => ({
  issueAnonymousJWT: jest.fn(() => "anonymous-jwt"),
}));
jest.mock("../../src/participant", () => ({
  joinConversation: jest.fn(),
}));
jest.mock("../../src/server-helpers", () => ({
  userHasAnsweredZeQuestions: jest.fn(),
}));

import { createAnonUser } from "../../src/auth/create-user";
import { handle_POST_joinWithInvite } from "../../src/auth/routes";
import { getConversationInfo } from "../../src/conversation";
import {
  getFncpManagedXidDecision,
  resolveFncpManagedConversation,
} from "../../src/fncp-provider-policy";
import { joinConversation } from "../../src/participant";
import { userHasAnsweredZeQuestions } from "../../src/server-helpers";
import { failJson } from "../../src/utils/fail";
import { isXidAllowed, xidExists } from "../../src/xids";

const xid = "fncp_0123456789abcdef0123456789";

function req(xidValue?: string) {
  return {
    p: {
      answers: [],
      parent_url: "",
      referrer: "",
      suzinvite: "",
      xid: xidValue,
      zid: 71,
    },
  } as any;
}

function res() {
  const json = jest.fn();
  const status = jest.fn(() => ({ json }));
  return { status, json } as any;
}

describe("managed join XID pre-validation", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (getConversationInfo as jest.Mock).mockResolvedValue({
      org_id: 8,
      owner: 9,
      use_xid_whitelist: true,
      xid_required: true,
    });
    (resolveFncpManagedConversation as jest.Mock).mockResolvedValue({
      enforcementEnabled: true,
      managed: true,
    });
  });

  test("missing XID fails before anonymous-user or participant mutation", async () => {
    const response = res();

    await handle_POST_joinWithInvite(req(), response);

    expect(failJson).toHaveBeenCalledWith(
      response,
      403,
      "polis_err_xid_required",
      expect.any(Error)
    );
    expect(getFncpManagedXidDecision).not.toHaveBeenCalled();
    expect(createAnonUser).not.toHaveBeenCalled();
    expect(userHasAnsweredZeQuestions).not.toHaveBeenCalled();
    expect(joinConversation).not.toHaveBeenCalled();
    expect(xidExists).not.toHaveBeenCalled();
  });

  test.each(["invalid", "removed"])(
    "%s provider XID fails before any participant mutation",
    async () => {
      (getFncpManagedXidDecision as jest.Mock).mockResolvedValue(false);
      const response = res();

      await handle_POST_joinWithInvite(req(xid), response);

      expect(getFncpManagedXidDecision).toHaveBeenCalledWith(71, xid);
      expect(isXidAllowed).not.toHaveBeenCalled();
      expect(failJson).toHaveBeenCalledWith(
        response,
        403,
        "polis_err_xid_not_allowed",
        expect.any(Error)
      );
      expect(createAnonUser).not.toHaveBeenCalled();
      expect(userHasAnsweredZeQuestions).not.toHaveBeenCalled();
      expect(joinConversation).not.toHaveBeenCalled();
      expect(xidExists).not.toHaveBeenCalled();
    }
  );

  test("provider uncertainty fails closed before any participant mutation", async () => {
    const unavailable = new Error("private provider detail");
    unavailable.name = "FncpProviderPolicyUnavailableError";
    (getFncpManagedXidDecision as jest.Mock).mockRejectedValue(unavailable);
    const response = res();

    await handle_POST_joinWithInvite(req(xid), response);

    expect(failJson).toHaveBeenCalledWith(
      response,
      503,
      "polis_err_fncp_provider_policy_unavailable",
      unavailable
    );
    expect(createAnonUser).not.toHaveBeenCalled();
    expect(userHasAnsweredZeQuestions).not.toHaveBeenCalled();
    expect(joinConversation).not.toHaveBeenCalled();
    expect(xidExists).not.toHaveBeenCalled();
  });

  test("a managed-policy transition never falls back to the legacy allowlist", async () => {
    (getFncpManagedXidDecision as jest.Mock).mockResolvedValue(undefined);
    const response = res();

    await handle_POST_joinWithInvite(req(xid), response);

    expect(isXidAllowed).not.toHaveBeenCalled();
    expect(failJson).toHaveBeenCalledWith(
      response,
      503,
      "polis_err_fncp_provider_policy_unavailable",
      expect.any(Error)
    );
    expect(createAnonUser).not.toHaveBeenCalled();
    expect(userHasAnsweredZeQuestions).not.toHaveBeenCalled();
    expect(joinConversation).not.toHaveBeenCalled();
  });

  test("an exact provider-authorized XID is checked before mutation", async () => {
    (getFncpManagedXidDecision as jest.Mock).mockResolvedValue(true);
    (createAnonUser as jest.Mock).mockResolvedValue(77);
    (userHasAnsweredZeQuestions as jest.Mock).mockResolvedValue(undefined);
    (joinConversation as jest.Mock).mockResolvedValue({ pid: 88 });
    (xidExists as jest.Mock).mockResolvedValue(true);
    const response = res();

    await handle_POST_joinWithInvite(req(xid), response);

    expect(getFncpManagedXidDecision).toHaveBeenCalledWith(71, xid);
    expect(
      (getFncpManagedXidDecision as jest.Mock).mock.invocationCallOrder[0]
    ).toBeLessThan((createAnonUser as jest.Mock).mock.invocationCallOrder[0]);
    expect(createAnonUser).toHaveBeenCalledTimes(1);
    expect(joinConversation).toHaveBeenCalledWith(71, 77, {}, []);
    expect(response.status).toHaveBeenCalledWith(200);
    expect(response.json).toHaveBeenCalledWith({
      isAnonymous: true,
      pid: 88,
      token: "anonymous-jwt",
      uid: 77,
    });
  });

  test("preserves the ordinary owner-scoped allowlist path outside the managed conversation", async () => {
    (resolveFncpManagedConversation as jest.Mock).mockResolvedValue({
      enforcementEnabled: true,
      managed: false,
    });
    (isXidAllowed as jest.Mock).mockResolvedValue(true);
    (createAnonUser as jest.Mock).mockResolvedValue(77);
    (userHasAnsweredZeQuestions as jest.Mock).mockResolvedValue(undefined);
    (joinConversation as jest.Mock).mockResolvedValue({ pid: 88 });
    (xidExists as jest.Mock).mockResolvedValue(true);
    const response = res();

    await handle_POST_joinWithInvite(req(xid), response);

    expect(getFncpManagedXidDecision).not.toHaveBeenCalled();
    expect(isXidAllowed).toHaveBeenCalledWith(xid, 71, 9);
    expect(createAnonUser).toHaveBeenCalledTimes(1);
    expect(joinConversation).toHaveBeenCalledTimes(1);
    expect(response.status).toHaveBeenCalledWith(200);
  });
});
