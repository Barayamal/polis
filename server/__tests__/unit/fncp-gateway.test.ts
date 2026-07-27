import { describe, expect, test } from "@jest/globals";
import {
  evaluateFncpGatewayRequest,
  type FncpGatewayConfig,
} from "../../src/auth/fncp-gateway";

const conversationId = "4optioncqa";
const sharedSecret = "gateway-test-secret-0123456789abcdef";
const xid = "fncp_0123456789abcdef0123456789";

const enabled: FncpGatewayConfig = {
  enabled: true,
  conversationId,
  sharedSecret,
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
});
