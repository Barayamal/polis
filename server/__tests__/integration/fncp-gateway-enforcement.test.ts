import { afterAll, beforeAll, describe, expect, test } from "@jest/globals";
import type { Agent } from "supertest";
import {
  createConversation,
  getJwtAuthenticatedAgent,
  newAgent,
} from "../setup/api-test-helpers";
import { getPooledTestUser } from "../setup/test-user-helpers";

const sharedSecret = "integration-gateway-secret-0123456789abcdef";
const allowedXid = "fncp_allowed_0123456789abcdef";
const replacementXid = "fncp_replacement_0123456789abc";

describe("FNCP gateway enforcement integration", () => {
  let admin: Agent;
  let conversationId = "";
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
    });

    const seed = await admin.post("/api/v3/comments").send({
      conversation_id: conversationId,
      txt: "Synthetic gateway test statement",
      is_seed: true,
    });
    expect(seed.status).toBe(200);

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

  test("trusted gateway headers inject the allowlisted XID", async () => {
    const participant = await newAgent();
    const response = await participant
      .get("/api/v3/participationInit")
      .set("X-FNCP-Gateway-Key", sharedSecret)
      .set("X-FNCP-Conversation-ID", conversationId)
      .set("X-FNCP-Participant-XID", allowedXid)
      .query({
        conversation_id: conversationId,
        lang: "en",
      });
    expect(response.status).toBe(200);
    expect(response.body.conversation.conversation_id).toBe(conversationId);
  });

  test("removing the XID blocks the next trusted gateway request", async () => {
    const replacement = await admin.post("/api/v3/xidAllowList").send({
      conversation_id: conversationId,
      xid_allow_list: [replacementXid],
      replace_all: true,
    });
    expect(replacement.status).toBe(200);

    const participant = await newAgent();
    const response = await participant
      .get("/api/v3/participationInit")
      .set("X-FNCP-Gateway-Key", sharedSecret)
      .set("X-FNCP-Conversation-ID", conversationId)
      .set("X-FNCP-Participant-XID", allowedXid)
      .query({
        conversation_id: conversationId,
        lang: "en",
      });
    expect(response.status).toBe(403);
  });

  test("admin-only routes reject gateway assertions and remain available to staff", async () => {
    const participant = await newAgent();
    const blocked = await participant
      .get("/api/v3/dataExport")
      .set("X-FNCP-Gateway-Key", sharedSecret)
      .set("X-FNCP-Conversation-ID", conversationId)
      .set("X-FNCP-Participant-XID", replacementXid)
      .query({ conversation_id: conversationId });
    expect(blocked.status).toBe(404);

    const staff = await admin.get("/api/v3/conversations");
    expect(staff.status).toBe(200);
  });
});

function setOrDelete(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
}
