import { afterAll, beforeAll, describe, expect, test } from "@jest/globals";
import type { Agent } from "supertest";

import { FNCP_PROVIDER_ALLOWLIST_PATHS } from "../../src/routes/fncp-provider-allowlist";
import {
  createConversation,
  getJwtAuthenticatedAgent,
  newAgent,
} from "../setup/api-test-helpers";
import { getPooledTestUser } from "../setup/test-user-helpers";

const credential = "provider-integration-credential-0123456789abcdef";
const participantXid = "fncp_disposable-provider-integration-001";
const allowKey = `allow-${"a".repeat(32)}`;
const removeKey = `remove-${"b".repeat(32)}`;

describe("FNCP provider allowlist database integration", () => {
  let admin: Agent;
  let privateClient: Agent;
  let conversationId = "";
  const previous = {
    enabled: process.env.FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT,
    conversationId: process.env.FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID,
    credential: process.env.FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL,
  };

  beforeAll(async () => {
    const pooledUser = getPooledTestUser(6);
    ({ agent: admin } = await getJwtAuthenticatedAgent({
      email: pooledUser.email,
      hname: pooledUser.name,
      password: pooledUser.password,
    }));
    privateClient = await newAgent();
    conversationId = await createConversation(admin, {
      topic: "FNCP disposable provider adapter QA",
      description: "Synthetic integration test only",
      is_active: true,
      is_draft: false,
      strict_moderation: true,
    });
    const gate = await admin.put("/api/v3/conversations").send({
      conversation_id: conversationId,
      use_xid_whitelist: true,
    });
    expect(gate.status).toBe(200);

    process.env.FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT = "true";
    process.env.FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID = conversationId;
    process.env.FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL = credential;
  });

  afterAll(async () => {
    if (conversationId) {
      await authority(FNCP_PROVIDER_ALLOWLIST_PATHS.remove, removeKey);
      await admin.put("/api/v3/conversations").send({
        conversation_id: conversationId,
        is_active: false,
      });
    }
    setOrDelete("FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT", previous.enabled);
    setOrDelete(
      "FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID",
      previous.conversationId
    );
    setOrDelete(
      "FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL",
      previous.credential
    );
  });

  test("unauthenticated access remains undiscoverable", async () => {
    const response = await privateClient
      .post(FNCP_PROVIDER_ALLOWLIST_PATHS.readback)
      .send({ conversationId, participantXid });
    expect(response.status).toBe(404);
    expect(response.body).toEqual({ error: "Not found." });
  });

  test("upsert and primary readback are exact and idempotent", async () => {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const upsert = await authority(
        FNCP_PROVIDER_ALLOWLIST_PATHS.upsert,
        allowKey
      );
      expect(upsert.status).toBe(204);
      expect(upsert.text).toBe("");
    }
    const readback = await authority(FNCP_PROVIDER_ALLOWLIST_PATHS.readback);
    expect(readback.status).toBe(200);
    expect(readback.body).toEqual({
      conversationId,
      participantXid,
      operationVersion: 1,
      present: true,
    });
  });

  test("remove is idempotent and readback confirms absence", async () => {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const remove = await authority(
        FNCP_PROVIDER_ALLOWLIST_PATHS.remove,
        removeKey
      );
      expect(remove.status).toBe(204);
      expect(remove.text).toBe("");
    }
    const readback = await authority(FNCP_PROVIDER_ALLOWLIST_PATHS.readback);
    expect(readback.status).toBe(200);
    expect(readback.body).toEqual({
      conversationId,
      participantXid,
      operationVersion: 2,
      present: false,
    });

    const delayedUpsert = await authority(
      FNCP_PROVIDER_ALLOWLIST_PATHS.upsert,
      allowKey
    );
    expect(delayedUpsert.status).toBe(503);
    const stillAbsent = await authority(
      FNCP_PROVIDER_ALLOWLIST_PATHS.readback
    );
    expect(stillAbsent.body).toEqual({
      conversationId,
      participantXid,
      operationVersion: 2,
      present: false,
    });
  });

  test("an authenticated cross-conversation body fails before storage", async () => {
    const response = await privateClient
      .post(FNCP_PROVIDER_ALLOWLIST_PATHS.upsert)
      .set("Authorization", `Bearer ${credential}`)
      .set("Idempotency-Key", allowKey)
      .send({
        conversationId: "8different",
        participantXid,
        operationVersion: 1,
      });
    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "Invalid request." });
  });

  function authority(path: string, idempotencyKey?: string) {
    const result = privateClient
      .post(path)
      .set("Authorization", `Bearer ${credential}`)
      .set("Accept", "application/json");
    if (idempotencyKey) {
      result.set("Idempotency-Key", idempotencyKey);
    }
    const operationVersion = path.endsWith("/upsert")
      ? 1
      : path.endsWith("/remove")
      ? 2
      : undefined;
    return result.send({
      conversationId,
      participantXid,
      ...(operationVersion === undefined ? {} : { operationVersion }),
    });
  }
});

function setOrDelete(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
}
