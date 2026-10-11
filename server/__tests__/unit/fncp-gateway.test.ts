import { describe, expect, test } from "@jest/globals";
import {
  evaluateFncpGatewayRequest,
  loadFncpGatewayConfig,
  type FncpGatewayConfig,
} from "../../src/auth/fncp-gateway";

const conversationId = "4optioncqa";
const sharedSecret = "gateway-test-secret-0123456789abcdef";
const xid = "fncp_0123456789abcdef0123456789";
const fixedIds = Array.from({ length: 15 }, (_, index) => 20 + index * 2);

const enabled: FncpGatewayConfig = {
  enabled: true,
  activationValid: true,
  conversationId,
  sharedSecret,
  fixedStatementIds: new Set(fixedIds),
};

function request(
  overrides: Partial<{
    method: string;
    path: string;
    headers: Record<string, unknown>;
    query: Record<string, unknown>;
    body: Record<string, unknown>;
  }> = {}
) {
  return {
    method: "GET",
    path: "/api/v3/participationInit",
    headers: {},
    query: { conversation_id: conversationId },
    ...overrides,
  };
}

function gatewayHeaders(extra: Record<string, unknown> = {}) {
  return {
    "x-fncp-gateway-key": sharedSecret,
    "x-fncp-conversation-id": conversationId,
    "x-fncp-participant-xid": xid,
    ...extra,
  };
}

describe("FNCP private-origin gateway enforcement", () => {
  test("is inert unless explicitly enabled", () => {
    expect(
      evaluateFncpGatewayRequest(request(), { ...enabled, enabled: false })
    ).toEqual({ enforce: false });
  });

  test("fails closed when enabled configuration is incomplete", () => {
    expect(
      evaluateFncpGatewayRequest(request(), {
        enabled: true,
        activationValid: true,
        conversationId,
        sharedSecret: "short",
      }).status
    ).toBe(503);
  });

  test("blocks direct access to the configured participant route", () => {
    expect(evaluateFncpGatewayRequest(request(), enabled).status).toBe(403);
  });

  test("allows an exact gateway assertion and returns trusted identity", () => {
    expect(
      evaluateFncpGatewayRequest(
        request({ headers: gatewayHeaders() }),
        enabled
      )
    ).toEqual({
      enforce: true,
      conversationId,
      participantXid: xid,
    });
  });

  test("rejects gateway assertions on every unused participant route", () => {
    for (const [method, path] of [
      ["GET", "/api/v3/conversations"],
      ["GET", "/api/v3/votes/famous"],
      ["GET", "/api/v3/bidToPid"],
      ["POST", "/api/v3/participants"],
      ["PUT", "/api/v3/participants_extended"],
      ["POST", "/api/v3/stars"],
      ["POST", "/api/v3/trashes"],
      ["POST", "/api/v3/tutorial"],
      ["POST", "/api/v3/ptptCommentMod"],
    ]) {
      expect(
        evaluateFncpGatewayRequest(
          request({ method, path, headers: gatewayHeaders() }),
          enabled
        )
      ).toEqual({
        enforce: true,
        status: 404,
        error: "Not found.",
      });
    }
  });

  test("globally disables joinWithInvite while FNCP enforcement is enabled", () => {
    for (const body of [
      {},
      { xid: "fncp_provider_authorized_0123456789" },
      { xid: "fncp_removed_0123456789abcdef" },
      { suzinvite: "synthetic-single-use-invitation" },
    ]) {
      expect(
        evaluateFncpGatewayRequest(
          request({
            method: "POST",
            path: "/api/v3/joinWithInvite",
            body,
          }),
          enabled
        )
      ).toEqual({
        enforce: true,
        status: 404,
        error: "Not found.",
      });
    }
  });

  test("rejects a wrong or missing gateway secret", () => {
    const headers = gatewayHeaders({
      "x-fncp-gateway-key": "wrong-secret-0123456789abcdefghij",
    });
    expect(
      evaluateFncpGatewayRequest(request({ headers }), enabled).status
    ).toBe(403);
  });

  test("rejects a wrong conversation assertion", () => {
    const headers = gatewayHeaders({
      "x-fncp-conversation-id": "4anotherqa",
    });
    expect(
      evaluateFncpGatewayRequest(request({ headers }), enabled).status
    ).toBe(403);
  });

  test("rejects conflicting query and body conversation identities", () => {
    for (const [queryConversation, bodyConversation] of [
      ["4otherconv", conversationId],
      [conversationId, "4otherconv"],
    ]) {
      expect(
        evaluateFncpGatewayRequest(
          request({
            method: "POST",
            path: "/api/v3/votes",
            query: { conversation_id: queryConversation },
            body: { conversation_id: bodyConversation },
          }),
          enabled
        )
      ).toEqual({
        enforce: true,
        status: 403,
        error: "Wrong conversation.",
      });
    }
  });

  test("rejects case and trailing-slash aliases of protected routes", () => {
    for (const path of [
      "/api/v3/participationInit/",
      "/API/V3/PARTICIPATIONINIT",
      "/api/v3/comments/",
    ]) {
      expect(evaluateFncpGatewayRequest(request({ path }), enabled)).toEqual({
        enforce: true,
        status: 404,
        error: "Not found.",
      });
    }
  });

  test("rejects HEAD aliases for protected GET participant paths", () => {
    for (const path of [
      "/api/v3/participationInit",
      "/api/v3/comments",
      "/api/v3/math/pca2",
    ]) {
      expect(
        evaluateFncpGatewayRequest(request({ method: "HEAD", path }), enabled)
      ).toEqual({
        enforce: true,
        status: 404,
        error: "Not found.",
      });
    }
  });

  test("rejects Authorization and browser cookies", () => {
    for (const conflicting of [
      { authorization: "Bearer browser-token" },
      { cookie: "participant=browser-cookie" },
    ]) {
      expect(
        evaluateFncpGatewayRequest(
          request({ headers: gatewayHeaders(conflicting) }),
          enabled
        ).status
      ).toBe(400);
    }
  });

  test("rejects direct and nested identity aliases", () => {
    for (const body of [
      { xid: "browser-xid" },
      { access_token: "browser-token" },
      { nested: { session: "browser-session" } },
    ]) {
      expect(
        evaluateFncpGatewayRequest(
          request({
            method: "POST",
            path: "/api/v3/votes",
            headers: gatewayHeaders(),
            body,
          }),
          enabled
        ).status
      ).toBe(400);
    }
  });

  test("rejects gateway assertions on non-participant routes", () => {
    expect(
      evaluateFncpGatewayRequest(
        request({
          path: "/api/v3/dataExport",
          headers: gatewayHeaders(),
        }),
        enabled
      ).status
    ).toBe(404);
  });

  test("does not affect another conversation without gateway headers", () => {
    expect(
      evaluateFncpGatewayRequest(
        request({ query: { conversation_id: "4otherconv" } }),
        enabled
      )
    ).toEqual({ enforce: false });
  });

  test("does not affect admin routes targeting the configured conversation", () => {
    expect(
      evaluateFncpGatewayRequest(
        request({
          method: "PUT",
          path: "/api/v3/conversations",
        }),
        enabled
      )
    ).toEqual({ enforce: false });
  });

  test("rejects an invalid trusted XID", () => {
    const headers = gatewayHeaders({
      "x-fncp-participant-xid": "short",
    });
    expect(
      evaluateFncpGatewayRequest(request({ headers }), enabled).status
    ).toBe(403);
  });

  test("denies fixed-round free text with or without trusted gateway assertions", () => {
    for (const path of [
      "/api/v3/comments",
      "/API/V3/COMMENTS",
      "/api/v3/comments/",
    ]) {
      for (const headers of [{}, gatewayHeaders()]) {
        expect(
          evaluateFncpGatewayRequest(
            request({
              method: "POST",
              path,
              headers,
              body: { txt: "Synthetic unapproved text" },
            }),
            enabled
          )
        ).toEqual({ enforce: true, status: 404, error: "Not found." });
      }
    }
  });

  test("preserves generic upstream statement submission", () => {
    const upstreamRequest = request({
      method: "POST",
      path: "/api/v3/comments",
      query: { conversation_id: "4otherconv" },
      body: { txt: "Synthetic upstream text" },
    });
    expect(evaluateFncpGatewayRequest(upstreamRequest, enabled)).toEqual({
      enforce: false,
    });
    expect(
      evaluateFncpGatewayRequest(
        request({ method: "POST", path: "/api/v3/comments" }),
        {
          ...enabled,
          enabled: false,
        }
      )
    ).toEqual({ enforce: false });
  });

  test.each([-1, 0, 1])(
    "accepts exact vote %s for each manifest TID",
    (vote) => {
      for (const tid of fixedIds) {
        expect(
          evaluateFncpGatewayRequest(
            request({
              method: "POST",
              path: "/api/v3/votes",
              headers: gatewayHeaders(),
              body: { conversation_id: conversationId, tid, vote, lang: "en" },
            }),
            enabled
          )
        ).toEqual({ enforce: true, conversationId, participantXid: xid });
      }
    }
  );

  test.each([
    { vote: 2 },
    { vote: -2 },
    { vote: 0.5 },
    { vote: "1" },
    { vote: true },
    { vote: null },
    { vote: NaN },
    { vote: Infinity },
    { vote: undefined },
    { tid: -1 },
    { tid: "20" },
    { tid: 20.1 },
    { tid: 21 },
    { tid: Number.MAX_SAFE_INTEGER + 1 },
    { txt: "Synthetic free text" },
    { is_seed: true },
    { starred: true },
    { high_priority: true },
    { nested: { comment: "Synthetic text" } },
    { lang: "free text is not a language" },
    { lang: { value: "en" } },
  ])("rejects invalid or extra fixed-vote input %p", (input) => {
    expect(
      evaluateFncpGatewayRequest(
        request({
          method: "POST",
          path: "/api/v3/votes",
          headers: gatewayHeaders(),
          body: { tid: fixedIds[0], vote: -1, ...input },
        }),
        enabled
      ).status
    ).toBe(400);
  });

  test("rejects extra query fields even when the JSON vote is valid", () => {
    for (const query of [
      { txt: "Synthetic free text" },
      { vote: "1" },
      { unknown: "value" },
    ]) {
      expect(
        evaluateFncpGatewayRequest(
          request({
            method: "POST",
            path: "/api/v3/votes",
            headers: gatewayHeaders(),
            query,
            body: { tid: fixedIds[0], vote: -1 },
          }),
          enabled
        ).status
      ).toBe(400);
    }
  });

  test("loads fifteen exact nonconsecutive IDs without assuming ordinal IDs", () => {
    const config = loadFncpGatewayConfig({
      FNCP_FIXED_STATEMENT_IDS: fixedIds.join(","),
    });
    expect([...config.fixedStatementIds!]).toEqual(fixedIds);
  });

  test.each([
    undefined,
    "",
    fixedIds.slice(1).join(","),
    [...fixedIds, 99].join(","),
    [...fixedIds.slice(1), fixedIds[1]].join(","),
    ["020", ...fixedIds.slice(1)].join(","),
    ["20 ", ...fixedIds.slice(1)].join(","),
    ["-1", ...fixedIds.slice(1)].join(","),
    ["1.5", ...fixedIds.slice(1)].join(","),
    ["1e1", ...fixedIds.slice(1)].join(","),
    ["9007199254740992", ...fixedIds.slice(1)].join(","),
  ])("keeps voting closed for missing/malformed manifest %p", (manifest) => {
    const loaded = loadFncpGatewayConfig({
      FNCP_FIXED_STATEMENT_IDS: manifest,
    });
    expect(loaded.fixedStatementIds).toBeUndefined();
    const config = { ...enabled, fixedStatementIds: loaded.fixedStatementIds };
    expect(
      evaluateFncpGatewayRequest(
        request({
          method: "POST",
          path: "/api/v3/votes",
          headers: gatewayHeaders(),
          body: { tid: fixedIds[0], vote: -1 },
        }),
        config
      ).status
    ).toBe(503);
    expect(
      evaluateFncpGatewayRequest(request({ headers: gatewayHeaders() }), config)
        .status
    ).toBeUndefined();
  });
});
