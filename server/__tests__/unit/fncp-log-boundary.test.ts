import { describe, expect, jest, test } from "@jest/globals";

import {
  fncpLogBoundaryMiddleware,
  isFncpLogBoundaryActive,
  isFncpSensitiveRequest,
  minimizeFncpLogInfo,
  runInFncpLogBoundary,
  shouldEnterFncpLogBoundary,
} from "../../src/auth/fncp-log-boundary";

const conversationId = "4optioncqa";

function request(
  overrides: Partial<{
    headers: Record<string, string>;
    method: string;
    path: string;
    query: Record<string, string>;
  }> = {}
) {
  return {
    headers: {},
    method: "GET",
    path: "/api/v3/participationInit",
    query: {},
    ...overrides,
  } as any;
}

describe("FNCP request logging boundary", () => {
  test("structurally omits body, query, req.p, error, XID and token material", () => {
    const sentinels = [
      "fncp_xid_0123456789abcdef",
      "jwt-xid-secret",
      "invitation-secret",
      "session-secret",
      "gateway-private-key",
      "participant-uid-77",
      "participant-pid-88",
    ];
    const info: Record<PropertyKey, unknown> & {
      level: string;
      message: unknown;
    } = {
      level: "error",
      message: `request failed for ${sentinels[0]}`,
      body: {
        invitation: sentinels[2],
        session: sentinels[3],
      },
      query: { xid: sentinels[0] },
      p: {
        jwt_xid: sentinels[1],
        uid: sentinels[5],
        pid: sentinels[6],
      },
      error: {
        message: sentinels[4],
        stack: `Error: ${sentinels.join(" ")}`,
      },
      [Symbol.for("splat")]: [{ authorization: sentinels[4] }],
      [Symbol.for("level")]: "error",
    };

    const minimized = runInFncpLogBoundary(() => minimizeFncpLogInfo(info));
    const serialized = JSON.stringify(
      Reflect.ownKeys(minimized).map((key) => [
        typeof key === "symbol" ? key.toString() : key,
        minimized[key],
      ])
    );

    expect(serialized).toContain("fncp_request_event");
    for (const sentinel of sentinels) {
      expect(serialized).not.toContain(sentinel);
    }
    expect(Reflect.ownKeys(minimized)).toEqual(
      expect.arrayContaining([
        "level",
        "message",
        "service",
        Symbol.for("level"),
      ])
    );
    expect(Reflect.ownKeys(minimized)).toHaveLength(4);
  });

  test("preserves ordinary Pol.is log information outside the boundary", () => {
    const info = {
      level: "debug",
      message: "ordinary upstream diagnostic",
      uid: 42,
      body: { topic: "ordinary conversation" },
    };

    expect(minimizeFncpLogInfo(info)).toBe(info);
    expect(info).toEqual({
      level: "debug",
      message: "ordinary upstream diagnostic",
      uid: 42,
      body: { topic: "ordinary conversation" },
    });
  });

  test("recognises private authority, gateway-header, configured-query and body routes", () => {
    const env = {
      FNCP_GATEWAY_ENFORCEMENT: "true",
      FNCP_GATEWAY_CONVERSATION_ID: conversationId,
    };

    expect(
      shouldEnterFncpLogBoundary(
        request({ path: "/fncp/private/xid-allowlist/upsert" }),
        env
      )
    ).toBe(true);
    expect(
      shouldEnterFncpLogBoundary(
        request({
          headers: { "x-fncp-participant-xid": "opaque" },
          path: "/api/v3/participationInit",
        }),
        env
      )
    ).toBe(true);
    expect(
      shouldEnterFncpLogBoundary(
        request({ query: { conversation_id: conversationId } }),
        env
      )
    ).toBe(true);
    expect(
      shouldEnterFncpLogBoundary(
        request({ method: "POST", path: "/api/v3/votes" }),
        env
      )
    ).toBe(true);
    expect(
      shouldEnterFncpLogBoundary(
        request({ query: { conversation_id: "4ordinary" } }),
        env
      )
    ).toBe(false);
  });

  test("documents the conservative P2 suppression for every protected POST only while enforcement is on", () => {
    const enabled = {
      FNCP_GATEWAY_ENFORCEMENT: "true",
      FNCP_GATEWAY_CONVERSATION_ID: conversationId,
    };
    const disabled = {
      ...enabled,
      FNCP_GATEWAY_ENFORCEMENT: "false",
    };

    for (const path of [
      "/api/v3/comments",
      "/api/v3/votes",
      "/api/v3/joinWithInvite",
    ]) {
      const ordinaryPost = request({
        method: "POST",
        path,
        query: { conversation_id: "4ordinary" },
      });
      expect(shouldEnterFncpLogBoundary(ordinaryPost, enabled)).toBe(true);
      expect(shouldEnterFncpLogBoundary(ordinaryPost, disabled)).toBe(false);
    }
  });

  test("marks the request and establishes an async-safe scope before next", () => {
    const req = request({
      path: "/fncp/private/xid-allowlist/readback",
    });
    const next = jest.fn(() => {
      expect(isFncpSensitiveRequest(req)).toBe(true);
      expect(isFncpLogBoundaryActive()).toBe(true);
    });

    fncpLogBoundaryMiddleware(req, {} as any, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(isFncpSensitiveRequest(req)).toBe(true);
    expect(isFncpLogBoundaryActive()).toBe(false);
  });
});
