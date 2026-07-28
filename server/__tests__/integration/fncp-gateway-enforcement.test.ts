import { afterAll, beforeAll, describe, expect, test } from "@jest/globals";
import type { Agent, Test } from "supertest";
import {
  createConversation,
  getJwtAuthenticatedAgent,
  newAgent,
} from "../setup/api-test-helpers";
import { getPooledTestUser } from "../setup/test-user-helpers";

const sharedSecret = "integration-gateway-secret-0123456789abcdef";
const allowedXid = "fncp_allowed_0123456789abcdef";
const replacementXid = "fncp_replacement_0123456789abc";

describe("FNCP minimum-route gateway enforcement integration", () => {
  let admin: Agent;
  let conversationId = "";
  let seedTid = -1;
  const previous = {
    enabled: process.env.FNCP_GATEWAY_ENFORCEMENT,
    conversationId: process.env.FNCP_GATEWAY_CONVERSATION_ID,
    secret: process.env.FNCP_GATEWAY_SHARED_SECRET,
  };

  beforeAll(async () => {
    const pooledUser = getPooledTestUser(4);
    ({ agent: admin } = await getJwtAuthenticatedAgent({
      email: pooledUser.email,
      hname: pooledUser.name,
      password: pooledUser.password,
    }));

    conversationId = await createConversation(admin, {
      topic: "FNCP gateway integration QA",
      description: "Synthetic test only",
      is_active: true,
      is_draft: false,
      strict_moderation: true,
      treevite_enabled: false,
      topics_enabled: false,
    });

    const seed = await admin.post("/api/v3/comments").send({
      conversation_id: conversationId,
      txt: "Synthetic gateway test statement",
      is_seed: true,
    });
    expect(seed.status).toBe(200);
    seedTid = seed.body.tid;
    expect(Number.isInteger(seedTid)).toBe(true);

    const allowlist = await admin.post("/api/v3/xidAllowList").send({
      conversation_id: conversationId,
      xid_allow_list: [allowedXid, replacementXid],
      replace_all: true,
    });
    expect(allowlist.status).toBe(200);

    const gate = await admin.put("/api/v3/conversations").send({
      conversation_id: conversationId,
      use_xid_whitelist: true,
    });
    expect(gate.status).toBe(200);

    process.env.FNCP_GATEWAY_ENFORCEMENT = "true";
    process.env.FNCP_GATEWAY_CONVERSATION_ID = conversationId;
    process.env.FNCP_GATEWAY_SHARED_SECRET = sharedSecret;
  });

  afterAll(async () => {
    if (conversationId) {
      await admin.put("/api/v3/conversations").send({
        conversation_id: conversationId,
        is_active: false,
      });
    }
    setOrDelete("FNCP_GATEWAY_ENFORCEMENT", previous.enabled);
    setOrDelete("FNCP_GATEWAY_CONVERSATION_ID", previous.conversationId);
    setOrDelete("FNCP_GATEWAY_SHARED_SECRET", previous.secret);
  });

  test("direct participant access is rejected before Pol.is auth", async () => {
    const participant = await newAgent();
    const response = await participant.get("/api/v3/participationInit").query({
      conversation_id: conversationId,
      lang: "en",
    });
    expect(response.status).toBe(403);
    expect(response.body.error).toBe("Gateway access required.");
  });

  test("HEAD cannot alias a protected GET participant route", async () => {
    const participant = await newAgent();
    const response = await participant.head("/api/v3/participationInit").query({
      conversation_id: conversationId,
      lang: "en",
    });
    expect(response.status).toBe(404);
    expect(response.headers["cache-control"]).toBe("no-store");
  });

  test("trusted gateway headers load the allowlisted conversation", async () => {
    const participant = await newAgent();
    const response = await trusted(
      participant.get("/api/v3/participationInit"),
      allowedXid
    ).query({ conversation_id: conversationId, lang: "en" });
    expect(response.status).toBe(200);
    expect(response.body.conversation.conversation_id).toBe(conversationId);
    expect(response.body).not.toHaveProperty("auth");
  });

  test("all retained GET routes reach the exact stack", async () => {
    const routes = [
      ["/api/v3/nextComment", { conversation_id: conversationId, lang: "en" }],
      ["/api/v3/comments", { conversation_id: conversationId }],
      ["/api/v3/math/pca2", { conversation_id: conversationId }],
    ] as const;

    const participant = await newAgent();
    for (const [path, query] of routes) {
      const response = await trusted(participant.get(path), allowedXid).query(
        query
      );
      expect([200, 304]).toContain(response.status);
    }
  });

  test("trusted Agree/Disagree/Pass write creates the XID participant", async () => {
    const participant = await newAgent();
    const response = await trusted(
      participant.post("/api/v3/votes"),
      allowedXid
    ).send({
      conversation_id: conversationId,
      tid: seedTid,
      vote: -1,
      lang: "en",
    });
    expect(response.status).toBe(200);
    expect(response.body.currentPid).toEqual(expect.any(Number));
    expect(response.body).not.toHaveProperty("auth");
  });

  test("trusted statement submission uses the same established XID", async () => {
    const participant = await newAgent();
    const response = await trusted(
      participant.post("/api/v3/comments"),
      allowedXid
    ).send({
      conversation_id: conversationId,
      txt: "Synthetic participant statement for gateway QA",
    });
    expect(response.status).toBe(200);
    expect(response.body).not.toHaveProperty("auth");
  });

  test("unused and optional routes reject gateway assertions", async () => {
    const routes: Array<[string, string]> = [
      ["get", "/api/v3/conversations"],
      ["get", "/api/v3/votes/famous"],
      ["get", "/api/v3/bidToPid"],
      ["post", "/api/v3/participants"],
      ["put", "/api/v3/participants_extended"],
      ["post", "/api/v3/stars"],
      ["post", "/api/v3/trashes"],
      ["post", "/api/v3/tutorial"],
      ["post", "/api/v3/ptptCommentMod"],
      ["post", "/api/v3/notifications"],
    ];

    for (const [method, path] of routes) {
      const participant = await newAgent();
      const request = trusted(
        participant[method as "get" | "post" | "put"](path),
        allowedXid
      );
      const response =
        method === "get"
          ? await request.query({ conversation_id: conversationId })
          : await request.send({ conversation_id: conversationId });
      expect(response.status).toBe(404);
      expect(response.headers["cache-control"]).toBe("no-store");
    }
  });

  test("revocation blocks the next request while staff routes remain available", async () => {
    const replacement = await admin.post("/api/v3/xidAllowList").send({
      conversation_id: conversationId,
      xid_allow_list: [replacementXid],
      replace_all: true,
    });
    expect(replacement.status).toBe(200);

    const participant = await newAgent();
    const blocked = await trusted(
      participant.get("/api/v3/participationInit"),
      allowedXid
    ).query({ conversation_id: conversationId, lang: "en" });
    expect(blocked.status).toBe(403);

    const staff = await admin.get("/api/v3/conversations");
    expect(staff.status).toBe(200);
  });

  test("standard OIDC JWT responses remain unchanged while the gateway is enabled", async () => {
    const response = await admin.get("/api/v3/users");
    expect(response.status).toBe(200);
    expect(response.body).toEqual(
      expect.objectContaining({
        uid: expect.any(Number),
        email: getPooledTestUser(4).email,
      })
    );
  });

  function trusted(request: Test, xid: string): Test {
    return request
      .set("X-FNCP-Gateway-Key", sharedSecret)
      .set("X-FNCP-Conversation-ID", conversationId)
      .set("X-FNCP-Participant-XID", xid);
  }
});

function setOrDelete(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
}
