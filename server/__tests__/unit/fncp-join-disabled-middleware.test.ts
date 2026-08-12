import {
  afterEach,
  beforeEach,
  describe,
  expect,
  jest,
  test,
} from "@jest/globals";
import express, {
  type NextFunction,
  type Request,
  type Response,
} from "express";
import request from "supertest";

import { fncpGatewayMiddleware } from "../../src/auth/fncp-gateway";
import {
  fncpLogBoundaryMiddleware,
  minimizeFncpLogInfo,
} from "../../src/auth/fncp-log-boundary";

const conversationId = "4optioncqa";
const sharedSecret = "gateway-test-secret-0123456789abcdef";
const sentinels = {
  allowedXid: "fncp_provider_authorized_0123456789",
  oidc: "valid-unseen-oidc-subject",
  removedXid: "fncp_removed_0123456789abcdef",
  session: "private-session-token",
  suzinvite: "synthetic-single-use-invitation",
};

const previous = {
  enabled: process.env.FNCP_GATEWAY_ENFORCEMENT,
  conversationId: process.env.FNCP_GATEWAY_CONVERSATION_ID,
  secret: process.env.FNCP_GATEWAY_SHARED_SECRET,
};

function setOrDelete(name: string, value: string | undefined) {
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
}

function createOrderedApp() {
  const authOrUserMapping = jest.fn(
    (_req: Request, _res: Response, next: NextFunction) => next()
  );
  const parameterMiddleware = jest.fn(
    (_req: Request, _res: Response, next: NextFunction) => next()
  );
  const participantMutation = jest.fn((_req: Request, res: Response) =>
    res.status(200).json({ mutated: true })
  );
  const serializedLogs: string[] = [];
  const app = express();

  // Match production order: logging boundary, parser, gateway, auth/parameter
  // middleware, then a mutating handler.
  app.use(fncpLogBoundaryMiddleware);
  app.use((req, res, next) => {
    res.once("finish", () => {
      const info: Record<PropertyKey, unknown> & {
        level: string;
        message: unknown;
      } = {
        level: "error",
        message: `request ${req.originalUrl}`,
        body: req.body,
        query: req.query,
        p: (req as Request & { p?: unknown }).p,
        headers: req.headers,
        error: (req as Request & { capturedError?: unknown }).capturedError,
        [Symbol.for("level")]: "error",
      };
      const minimized = minimizeFncpLogInfo(info);
      serializedLogs.push(
        JSON.stringify(
          Reflect.ownKeys(minimized).map((key) => [
            typeof key === "symbol" ? key.toString() : key,
            minimized[key],
          ])
        )
      );
    });
    next();
  });
  app.use(express.json());
  app.use(fncpGatewayMiddleware);
  app.post(
    "/api/v3/joinWithInvite",
    authOrUserMapping,
    parameterMiddleware,
    participantMutation
  );
  app.use(
    (error: unknown, req: Request, res: Response, _next: NextFunction) => {
      (req as Request & { capturedError?: unknown }).capturedError = error;
      res.status(400).json({ error: "invalid_json" });
    }
  );

  return {
    app,
    authOrUserMapping,
    parameterMiddleware,
    participantMutation,
    serializedLogs,
  };
}

describe("FNCP joinWithInvite middleware-order boundary", () => {
  beforeEach(() => {
    process.env.FNCP_GATEWAY_ENFORCEMENT = "true";
    process.env.FNCP_GATEWAY_CONVERSATION_ID = conversationId;
    process.env.FNCP_GATEWAY_SHARED_SECRET = sharedSecret;
  });

  afterEach(() => {
    setOrDelete("FNCP_GATEWAY_ENFORCEMENT", previous.enabled);
    setOrDelete("FNCP_GATEWAY_CONVERSATION_ID", previous.conversationId);
    setOrDelete("FNCP_GATEWAY_SHARED_SECRET", previous.secret);
  });

  test.each([
    [
      "valid unseen OIDC identity",
      {
        authorization: `Bearer ${sentinels.oidc}`,
        body: {
          conversation_id: conversationId,
          oidc_sub: sentinels.oidc,
          suzinvite: sentinels.suzinvite,
          xid: sentinels.allowedXid,
        },
      },
    ],
    [
      "direct provider-authorized XID",
      {
        body: {
          conversation_id: conversationId,
          xid: sentinels.allowedXid,
        },
      },
    ],
    [
      "missing XID",
      {
        body: {
          conversation_id: conversationId,
          session: sentinels.session,
        },
      },
    ],
    [
      "removed XID",
      {
        body: {
          conversation_id: conversationId,
          xid: sentinels.removedXid,
        },
      },
    ],
  ])(
    "denies %s before auth, parameters, mutation, or payload logging",
    async (_label, input) => {
      const ordered = createOrderedApp();
      let pending = request(ordered.app)
        .post("/api/v3/joinWithInvite")
        .send(input.body);
      if (input.authorization) {
        pending = pending.set("Authorization", input.authorization);
      }

      const response = await pending;

      expect(response.status).toBe(404);
      expect(response.body).toEqual({ error: "Not found." });
      expect(response.headers["cache-control"]).toBe("no-store");
      expect(ordered.authOrUserMapping).not.toHaveBeenCalled();
      expect(ordered.parameterMiddleware).not.toHaveBeenCalled();
      expect(ordered.participantMutation).not.toHaveBeenCalled();
      expect(ordered.serializedLogs).toHaveLength(1);
      expect(ordered.serializedLogs[0]).toContain("fncp_request_event");
      for (const sentinel of Object.values(sentinels)) {
        expect(ordered.serializedLogs[0]).not.toContain(sentinel);
      }
    }
  );

  test("malformed JSON is bounded before parsing and cannot retain its payload", async () => {
    const ordered = createOrderedApp();
    const malformed = `{"conversation_id":"${conversationId}","xid":"${sentinels.removedXid}",`;

    const response = await request(ordered.app)
      .post("/api/v3/joinWithInvite")
      .set("Content-Type", "application/json")
      .send(malformed);

    expect(response.status).toBe(400);
    expect(ordered.authOrUserMapping).not.toHaveBeenCalled();
    expect(ordered.parameterMiddleware).not.toHaveBeenCalled();
    expect(ordered.participantMutation).not.toHaveBeenCalled();
    expect(ordered.serializedLogs).toHaveLength(1);
    expect(ordered.serializedLogs[0]).toContain("fncp_request_event");
    expect(ordered.serializedLogs[0]).not.toContain(sentinels.removedXid);
  });

  test("preserves the ordinary upstream route only when enforcement is off", async () => {
    process.env.FNCP_GATEWAY_ENFORCEMENT = "false";
    const ordered = createOrderedApp();

    const response = await request(ordered.app)
      .post("/api/v3/joinWithInvite")
      .send({ conversation_id: "4ordinary" });

    expect(response.status).toBe(200);
    expect(ordered.authOrUserMapping).toHaveBeenCalledTimes(1);
    expect(ordered.parameterMiddleware).toHaveBeenCalledTimes(1);
    expect(ordered.participantMutation).toHaveBeenCalledTimes(1);
    expect(ordered.serializedLogs[0]).not.toContain("fncp_request_event");
  });
});
