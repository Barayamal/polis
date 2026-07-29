import { beforeEach, describe, expect, it, jest } from "@jest/globals";
import type { NextFunction, Response } from "express";

import { getConversationInfo } from "../../src/conversation";
import { resolveFncpManagedConversation } from "../../src/fncp-provider-policy";
import { isXidAllowed } from "../../src/xids";

jest.mock("../../src/conversation", () => ({
  getConversationInfo: jest.fn(),
  getZidFromConversationId: jest.fn(),
}));

jest.mock("../../src/xids", () => ({
  createXidRecord: jest.fn(),
  getXidRecord: jest.fn(),
  isXidAllowed: jest.fn(),
  xidExists: jest.fn(),
}));

jest.mock("../../src/fncp-provider-policy", () => ({
  resolveFncpManagedConversation: jest.fn(),
  isFncpProviderPolicyUnavailable: jest.fn(
    (error: unknown) =>
      error instanceof Error &&
      error.name === "FncpProviderPolicyUnavailableError"
  ),
}));

jest.mock("../../src/participant", () => ({
  addParticipantAndMetadata: jest.fn(),
}));

jest.mock("../../src/auth/legacyCookies", () => ({
  checkLegacyCookieAndIssueJWT: jest.fn(),
}));

jest.mock("../../src/auth/create-user", () => ({
  createAnonUser: jest.fn(),
}));

jest.mock("../../src/user", () => ({
  getPidPromise: jest.fn(),
}));

jest.mock("../../src/utils/zinvite", () => ({
  getZinvite: jest.fn(),
}));

jest.mock("../../src/utils/common", () => ({
  isDuplicateKey: jest.fn(),
}));

jest.mock("../../src/auth/anonymous-jwt", () => ({
  issueAnonymousJWT: jest.fn(),
}));

jest.mock("../../src/auth/standard-user-jwt", () => ({
  issueStandardUserJWT: jest.fn(),
}));

jest.mock("../../src/auth/xid-jwt", () => ({
  issueXidJWT: jest.fn(),
}));

jest.mock("../../src/db/pg-query", () => ({
  __esModule: true,
  default: {
    queryP_readOnly: jest.fn(),
  },
}));

jest.mock("../../src/utils/logger", () => ({
  __esModule: true,
  default: {
    debug: jest.fn(),
    error: jest.fn(),
    info: jest.fn(),
  },
}));

import {
  ensureParticipant,
  ensureParticipantOptional,
  revalidateConversationXidAllowlist,
} from "../../src/auth/ensure-participant";

type Middleware = ReturnType<typeof ensureParticipant>;

function createResponse() {
  const json = jest.fn();
  const status = jest.fn(() => ({ json }));
  const set = jest.fn();

  return {
    response: { set, status } as unknown as Response,
    set,
    status,
    json,
  };
}

async function runMiddleware(
  middleware: Middleware,
  p: Record<string, unknown>
) {
  const req = {
    p: { ...p },
    headers: {},
  } as any;
  const { response, set, status, json } = createResponse();
  const next = jest.fn() as unknown as NextFunction;

  await middleware(req, response, next);

  return { req, set, status, json, next };
}

describe("ensureParticipant XID allowlist revalidation", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (getConversationInfo as jest.Mock).mockResolvedValue({
      owner: 42,
      use_xid_whitelist: true,
    });
    (resolveFncpManagedConversation as jest.Mock).mockResolvedValue({
      enforcementEnabled: false,
      managed: false,
    });
  });

  it.each([
    ["ensureParticipant", ensureParticipant],
    ["ensureParticipantOptional", ensureParticipantOptional],
  ])(
    "allows an allowlisted XID through %s",
    async (_name, middlewareFactory) => {
      (isXidAllowed as jest.Mock).mockResolvedValue(true);

      const { next, status } = await runMiddleware(
        middlewareFactory({
          createIfMissing: false,
          issueJWT: false,
        }),
        {
          zid: 7,
          uid: 70,
          pid: 700,
          xid: "allowed-xid",
          jwt_xid: "allowed-xid",
          xid_participant: true,
        }
      );

      expect(isXidAllowed).toHaveBeenCalledWith("allowed-xid", 7, 42);
      expect(status).not.toHaveBeenCalled();
      expect(next).toHaveBeenCalledWith();
    }
  );

  it.each([
    ["ensureParticipant", ensureParticipant],
    ["ensureParticipantOptional", ensureParticipantOptional],
  ])(
    "rejects a removed XID with an existing JWT uid through %s",
    async (_name, middlewareFactory) => {
      (isXidAllowed as jest.Mock).mockResolvedValue(false);

      const { next, status, json } = await runMiddleware(
        middlewareFactory({
          createIfMissing: false,
          issueJWT: false,
        }),
        {
          zid: 7,
          uid: 70,
          pid: 700,
          xid: "removed-xid",
          jwt_xid: "removed-xid",
          xid_participant: true,
        }
      );

      expect(isXidAllowed).toHaveBeenCalledWith("removed-xid", 7, 42);
      expect(status).toHaveBeenCalledWith(403);
      expect(json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: "polis_err_xid_not_allowed",
          status: 403,
        })
      );
      expect(next).not.toHaveBeenCalled();
    }
  );

  it.each([
    ["ensureParticipant", ensureParticipant],
    ["ensureParticipantOptional", ensureParticipantOptional],
  ])("rejects a missing XID through %s", async (_name, middlewareFactory) => {
    const { next, status, json } = await runMiddleware(
      middlewareFactory({
        createIfMissing: false,
        issueJWT: false,
      }),
      {
        zid: 7,
      }
    );

    expect(isXidAllowed).not.toHaveBeenCalled();
    expect(status).toHaveBeenCalledWith(403);
    expect(json).toHaveBeenCalledWith(
      expect.objectContaining({
        error: "polis_err_xid_required",
        status: 403,
      })
    );
    expect(next).not.toHaveBeenCalled();
  });

  it("uses the authenticated JWT XID if a request parameter differs", async () => {
    (isXidAllowed as jest.Mock).mockResolvedValue(false);

    const { status } = await runMiddleware(
      ensureParticipant({
        createIfMissing: false,
        issueJWT: false,
      }),
      {
        zid: 7,
        uid: 70,
        pid: 700,
        xid: "replacement-request-xid",
        jwt_xid: "removed-authenticated-xid",
        xid_participant: true,
      }
    );

    expect(isXidAllowed).toHaveBeenCalledWith(
      "removed-authenticated-xid",
      7,
      42
    );
    expect(status).toHaveBeenCalledWith(403);
  });

  it("allows an allowlisted XID on the first unauthenticated request", async () => {
    (isXidAllowed as jest.Mock).mockResolvedValue(true);

    const { next, status } = await runMiddleware(
      ensureParticipant({
        createIfMissing: false,
        issueJWT: false,
      }),
      {
        zid: 7,
        xid: "first-request-xid",
      }
    );

    expect(isXidAllowed).toHaveBeenCalledWith("first-request-xid", 7, 42);
    expect(status).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalledWith();
  });

  it.each([
    ["anonymous", { anonymous_participant: true, uid: 80, pid: 800 }],
    [
      "OIDC",
      {
        standard_user_participant: true,
        oidc_sub: "oidc-user",
        uid: 90,
        pid: 900,
      },
    ],
  ])(
    "rejects an authenticated non-XID %s participant",
    async (_name, participant) => {
      const { next, status, json } = await runMiddleware(
        ensureParticipantOptional({
          createIfMissing: false,
          issueJWT: false,
        }),
        {
          zid: 7,
          ...participant,
        }
      );

      expect(isXidAllowed).not.toHaveBeenCalled();
      expect(status).toHaveBeenCalledWith(403);
      expect(json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: "polis_err_xid_required",
          status: 403,
        })
      );
      expect(next).not.toHaveBeenCalled();
    }
  );

  it("does not consult the allowlist for a non-whitelisted conversation", async () => {
    (getConversationInfo as jest.Mock).mockResolvedValue({
      owner: 42,
      use_xid_whitelist: false,
    });

    const { next, status } = await runMiddleware(
      ensureParticipantOptional({
        createIfMissing: false,
        issueJWT: false,
      }),
      {
        zid: 7,
        uid: 70,
        pid: 700,
        xid: "not-allowlisted",
        jwt_xid: "not-allowlisted",
        xid_participant: true,
      }
    );

    expect(isXidAllowed).not.toHaveBeenCalled();
    expect(status).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalledWith();
  });

  it("fails closed if the managed conversation gate is disabled", async () => {
    (resolveFncpManagedConversation as jest.Mock).mockResolvedValue({
      enforcementEnabled: true,
      managed: true,
    });
    (getConversationInfo as jest.Mock).mockResolvedValue({
      owner: 42,
      use_xid_whitelist: false,
    });

    const { next, set, status, json } = await runMiddleware(
      ensureParticipantOptional({
        createIfMissing: false,
        issueJWT: false,
      }),
      {
        zid: 7,
        xid: "raw-readded-xid",
      }
    );

    expect(isXidAllowed).not.toHaveBeenCalled();
    expect(set).toHaveBeenCalledWith("Cache-Control", "no-store");
    expect(status).toHaveBeenCalledWith(503);
    expect(json).toHaveBeenCalledWith(
      expect.objectContaining({
        error: "polis_err_fncp_provider_policy_unavailable",
        status: 503,
      })
    );
    expect(next).not.toHaveBeenCalled();
  });

  it("fails closed instead of continuing optional middleware on policy uncertainty", async () => {
    const unavailable = new Error("private detail");
    unavailable.name = "FncpProviderPolicyUnavailableError";
    (resolveFncpManagedConversation as jest.Mock).mockRejectedValue(unavailable);

    const { next, status, json } = await runMiddleware(
      ensureParticipantOptional({
        createIfMissing: false,
        issueJWT: false,
      }),
      {
        zid: 7,
        xid: "uncertain-xid",
      }
    );

    expect(status).toHaveBeenCalledWith(503);
    expect(json).toHaveBeenCalledWith(
      expect.objectContaining({
        error: "polis_err_fncp_provider_policy_unavailable",
        status: 503,
      })
    );
    expect(next).not.toHaveBeenCalled();
  });

  describe("explicit participant-route guard", () => {
    it("allows a fresh allowlisted XID and records the checked conversation", async () => {
      (isXidAllowed as jest.Mock).mockResolvedValue(true);

      const { req, next, status } = await runMiddleware(
        revalidateConversationXidAllowlist(),
        {
          zid: 7,
          xid: "fresh-allowlisted-xid",
        }
      );

      expect(isXidAllowed).toHaveBeenCalledWith("fresh-allowlisted-xid", 7, 42);
      expect(req.p.xid_allowlist_revalidated_for_zid).toBe(7);
      expect(status).not.toHaveBeenCalled();
      expect(next).toHaveBeenCalledWith();
    });

    it("rejects an already-warm participant after its JWT XID is removed", async () => {
      (isXidAllowed as jest.Mock).mockResolvedValue(false);

      const { next, set, status, json } = await runMiddleware(
        revalidateConversationXidAllowlist(),
        {
          zid: 7,
          uid: 70,
          pid: 700,
          xid: "request-xid-cannot-override-jwt",
          jwt_xid: "removed-warm-xid",
          xid_participant: true,
        }
      );

      expect(isXidAllowed).toHaveBeenCalledWith("removed-warm-xid", 7, 42);
      expect(set).toHaveBeenCalledWith("Cache-Control", "no-store");
      expect(status).toHaveBeenCalledWith(403);
      expect(json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: "polis_err_xid_not_allowed",
          status: 403,
        })
      );
      expect(next).not.toHaveBeenCalled();
    });

    it("rejects a missing XID before a protected route handler", async () => {
      const { next, status, json } = await runMiddleware(
        revalidateConversationXidAllowlist(),
        { zid: 7 }
      );

      expect(isXidAllowed).not.toHaveBeenCalled();
      expect(status).toHaveBeenCalledWith(403);
      expect(json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: "polis_err_xid_required",
          status: 403,
        })
      );
      expect(next).not.toHaveBeenCalled();
    });

    it("passes unexpected lookup failures to the global error handler", async () => {
      const lookupError = new Error("synthetic database failure");
      (getConversationInfo as jest.Mock).mockRejectedValue(lookupError);

      const { next, status } = await runMiddleware(
        revalidateConversationXidAllowlist(),
        {
          zid: 7,
          xid: "fresh-allowlisted-xid",
        }
      );

      expect(status).not.toHaveBeenCalled();
      expect(next).toHaveBeenCalledWith(lookupError);
    });

    it("does not repeat the database check in ensureParticipant after the route guard", async () => {
      (isXidAllowed as jest.Mock).mockResolvedValue(true);
      const req = {
        p: {
          zid: 7,
          uid: 70,
          pid: 700,
          xid: "warm-allowlisted-xid",
          jwt_xid: "warm-allowlisted-xid",
          xid_participant: true,
        },
        headers: {},
      } as any;
      const { response, status } = createResponse();
      const guardNext = jest.fn() as unknown as NextFunction;
      const participantNext = jest.fn() as unknown as NextFunction;

      await revalidateConversationXidAllowlist()(req, response, guardNext);
      await ensureParticipant({
        createIfMissing: false,
        issueJWT: false,
      })(req, response, participantNext);

      expect(getConversationInfo).toHaveBeenCalledTimes(1);
      expect(isXidAllowed).toHaveBeenCalledTimes(1);
      expect(status).not.toHaveBeenCalled();
      expect(guardNext).toHaveBeenCalledWith();
      expect(participantNext).toHaveBeenCalledWith();
    });
  });
});
