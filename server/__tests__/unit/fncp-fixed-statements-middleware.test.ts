import {
  afterEach,
  beforeEach,
  describe,
  expect,
  jest,
  test,
} from "@jest/globals";
import express from "express";
import request from "supertest";
import { fncpGatewayMiddleware } from "../../src/auth/fncp-gateway";

const conversationId = "4fixedstatementqa";
const sharedSecret = "synthetic-fixed-statement-gateway-secret-0123456789";
const xid = "fncp_synthetic_fixed_statements_0123456789";
const fields = [
  "FNCP_GATEWAY_ENFORCEMENT",
  "FNCP_GATEWAY_CONVERSATION_ID",
  "FNCP_GATEWAY_SHARED_SECRET",
  "FNCP_FIXED_STATEMENT_IDS",
  "FNCP_OPTION_C_RELEASE_MODE",
] as const;
const previous = Object.fromEntries(
  fields.map((field) => [field, process.env[field]])
);

function createApp() {
  const handler = jest.fn((_req: express.Request, res: express.Response) => {
    res.status(200).json({ accepted: true });
  });
  const app = express();
  app.use(express.json());
  app.use(fncpGatewayMiddleware);
  app.post("/api/v3/comments", handler);
  app.post("/api/v3/votes", handler);
  return { app, handler };
}

describe("FNCP fixed-statement HTTP boundary", () => {
  beforeEach(() => {
    process.env.FNCP_OPTION_C_RELEASE_MODE = "production";
    process.env.FNCP_GATEWAY_ENFORCEMENT = "true";
    process.env.FNCP_GATEWAY_CONVERSATION_ID = conversationId;
    process.env.FNCP_GATEWAY_SHARED_SECRET = sharedSecret;
    process.env.FNCP_FIXED_STATEMENT_IDS = Array.from(
      { length: 15 },
      (_, index) => index + 100
    ).join(",");
  });

  afterEach(() => {
    for (const field of fields) {
      if (previous[field] === undefined) delete process.env[field];
      else process.env[field] = previous[field];
    }
  });

  test.each([false, true])(
    "blocks free text before its handler with trusted=%s",
    async (trusted) => {
      const { app, handler } = createApp();
      let pending = request(app).post("/api/v3/comments").send({
        conversation_id: conversationId,
        txt: "Synthetic free text must never be stored",
        is_seed: true,
      });
      if (trusted)
        pending = pending
          .set("X-FNCP-Gateway-Key", sharedSecret)
          .set("X-FNCP-Conversation-ID", conversationId)
          .set("X-FNCP-Participant-XID", xid);
      const response = await pending;
      expect(response.status).toBe(404);
      expect(response.body).toEqual({ error: "Not found." });
      expect(response.headers["cache-control"]).toBe("no-store");
      expect(handler).not.toHaveBeenCalled();
    }
  );

  test.each([
    { tid: 99999 },
    { vote: 2 },
    { vote: "1" },
    { txt: "Synthetic free text" },
    { unknown: true },
  ])("blocks invalid vote %p before mutation", async (input) => {
    const { app, handler } = createApp();
    const response = await request(app)
      .post("/api/v3/votes")
      .set("X-FNCP-Gateway-Key", sharedSecret)
      .set("X-FNCP-Conversation-ID", conversationId)
      .set("X-FNCP-Participant-XID", xid)
      .send({ tid: 100, vote: -1, ...input });
    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "Invalid fixed-statement vote." });
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(handler).not.toHaveBeenCalled();
  });

  test("missing manifest blocks votes before mutation", async () => {
    delete process.env.FNCP_FIXED_STATEMENT_IDS;
    const { app, handler } = createApp();
    const response = await request(app)
      .post("/api/v3/votes")
      .set("X-FNCP-Gateway-Key", sharedSecret)
      .set("X-FNCP-Conversation-ID", conversationId)
      .set("X-FNCP-Participant-XID", xid)
      .send({ tid: 100, vote: -1 });
    expect(response.status).toBe(503);
    expect(handler).not.toHaveBeenCalled();
  });

  test.each([-1, 0, 1])(
    "only exact vote %s reaches the next protected stage",
    async (vote) => {
      const { app, handler } = createApp();
      const response = await request(app)
        .post("/api/v3/votes")
        .set("X-FNCP-Gateway-Key", sharedSecret)
        .set("X-FNCP-Conversation-ID", conversationId)
        .set("X-FNCP-Participant-XID", xid)
        .send({ tid: 100, vote });
      expect(response.status).toBe(200);
      expect(handler).toHaveBeenCalledTimes(1);
    }
  );
});
