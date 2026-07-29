import { describe, expect, jest, test } from "@jest/globals";
import express from "express";
import request from "supertest";

jest.mock("../../src/db/pg-query", () => ({
  __esModule: true,
  default: { queryP: jest.fn() },
}));

import {
  createFncpProviderAllowlistHandlers,
  evaluateFncpProviderAllowlistRequest,
  FNCP_PROVIDER_ALLOWLIST_PATHS,
  type FncpProviderAllowlistStore,
} from "../../src/routes/fncp-provider-allowlist";

const conversationId = "9fncp2026qa";
const participantXid = "fncp_synthetic-provider-xid-001";
const credential = "q".repeat(48);
const allowKey = `allow-${"a".repeat(32)}`;
const removeKey = `remove-${"b".repeat(32)}`;
const config = {
  enabled: true,
  conversationId,
  bearerCredential: credential,
};

function headers(extra: Record<string, unknown> = {}) {
  return {
    authorization: `Bearer ${credential}`,
    "content-type": "application/json",
    ...extra,
  };
}

function body(extra: Record<string, unknown> = {}) {
  return {
    conversationId,
    participantXid,
    ...extra,
  };
}

describe("FNCP private provider allowlist request boundary", () => {
  test("is undiscoverable while disabled, misconfigured or unauthenticated", () => {
    for (const [requestHeaders, requestConfig] of [
      [headers(), { ...config, enabled: false }],
      [headers(), { ...config, bearerCredential: "short" }],
      [headers({ authorization: "Bearer wrong".padEnd(40, "x") }), config],
      [{}, config],
    ] as const) {
      expect(
        evaluateFncpProviderAllowlistRequest(
          { headers: requestHeaders, body: body() },
          "readback",
          requestConfig
        )
      ).toEqual({ authorized: false, status: 404 });
    }
  });

  test("accepts only the exact configured scope and operation key", () => {
    expect(
      evaluateFncpProviderAllowlistRequest(
        {
          headers: headers({ "idempotency-key": allowKey }),
          body: body({ operationVersion: 1 }),
        },
        "upsert",
        config
      )
    ).toEqual({
      authorized: true,
      conversationId,
      participantXid,
      operationVersion: 1,
    });

    for (const invalid of [
      {
        headers: headers({ "idempotency-key": removeKey }),
        body: body({ operationVersion: 1 }),
      },
      {
        headers: headers({ "idempotency-key": allowKey }),
        body: body({ conversationId: "8other", operationVersion: 1 }),
      },
      {
        headers: headers({ "idempotency-key": allowKey }),
        body: body({ extra: true, operationVersion: 1 }),
      },
      {
        headers: headers({ "idempotency-key": allowKey }),
        body: body({ participantXid: "short", operationVersion: 1 }),
      },
      {
        headers: headers({ "idempotency-key": allowKey }),
        body: body({ operationVersion: 2 }),
      },
      {
        headers: headers({
          "content-type": "application/x-www-form-urlencoded",
          "idempotency-key": allowKey,
        }),
        body: body({ operationVersion: 1 }),
      },
    ]) {
      expect(
        evaluateFncpProviderAllowlistRequest(invalid, "upsert", config)
      ).toEqual({ authorized: false, status: 400 });
    }
  });

  test("rejects browser, cookie, query and readback-idempotency inputs", () => {
    for (const invalid of [
      {
        headers: headers({ origin: "https://browser.example" }),
        body: body(),
      },
      {
        headers: headers({ cookie: "authority=browser" }),
        body: body(),
      },
      { headers: headers(), query: { xid: participantXid }, body: body() },
    ]) {
      expect(
        evaluateFncpProviderAllowlistRequest(invalid, "readback", config)
      ).toEqual({ authorized: false, status: 404 });
    }
    expect(
      evaluateFncpProviderAllowlistRequest(
        {
          headers: headers({ "idempotency-key": allowKey }),
          body: body(),
        },
        "readback",
        config
      )
    ).toEqual({ authorized: false, status: 400 });
  });
});

describe("FNCP private provider allowlist HTTP contract", () => {
  test("upsert, exact readback and removal are idempotent", async () => {
    const allowed = new Set<string>();
    const versions = new Map<string, number>();
    const calls: string[] = [];
    const store: FncpProviderAllowlistStore = {
      async upsert(inputConversationId, inputParticipantXid) {
        calls.push("upsert");
        expect(inputConversationId).toBe(conversationId);
        allowed.add(inputParticipantXid);
        versions.set(inputParticipantXid, 1);
        return {
          conversationReady: true,
          operationAccepted: true,
          operationVersion: 1,
          present: true,
        };
      },
      async readback(inputConversationId, inputParticipantXid) {
        calls.push("readback");
        expect(inputConversationId).toBe(conversationId);
        return {
          conversationReady: true,
          operationAccepted: true,
          operationVersion: versions.get(inputParticipantXid) ?? null,
          present: allowed.has(inputParticipantXid),
        };
      },
      async remove(inputConversationId, inputParticipantXid) {
        calls.push("remove");
        expect(inputConversationId).toBe(conversationId);
        allowed.delete(inputParticipantXid);
        versions.set(inputParticipantXid, 2);
        return {
          conversationReady: true,
          operationAccepted: true,
          operationVersion: 2,
          present: false,
        };
      },
    };
    const app = testApp(store);

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const upsert = await authorityRequest(
        app,
        FNCP_PROVIDER_ALLOWLIST_PATHS.upsert,
        allowKey
      );
      expect(upsert.status).toBe(204);
      expect(upsert.text).toBe("");
      expect(upsert.headers).not.toHaveProperty("set-cookie");
      expect(upsert.headers["cache-control"]).toContain("no-store");
    }

    const present = await authorityRequest(
      app,
      FNCP_PROVIDER_ALLOWLIST_PATHS.readback
    );
    expect(present.status).toBe(200);
    expect(present.body).toEqual({
      conversationId,
      participantXid,
      operationVersion: 1,
      present: true,
    });
    expect(Object.keys(present.body).sort()).toEqual([
      "conversationId",
      "operationVersion",
      "participantXid",
      "present",
    ]);
    expect(present.headers["content-type"]).toContain("application/json");
    expect(present.headers).not.toHaveProperty("set-cookie");

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const remove = await authorityRequest(
        app,
        FNCP_PROVIDER_ALLOWLIST_PATHS.remove,
        removeKey
      );
      expect(remove.status).toBe(204);
      expect(remove.text).toBe("");
    }

    const absent = await authorityRequest(
      app,
      FNCP_PROVIDER_ALLOWLIST_PATHS.readback
    );
    expect(absent.body).toEqual({
      conversationId,
      participantXid,
      operationVersion: 2,
      present: false,
    });
    expect(calls).toEqual([
      "upsert",
      "upsert",
      "readback",
      "remove",
      "remove",
      "readback",
    ]);
  });

  test("invalid authentication never reaches storage or echoes material", async () => {
    let called = false;
    const store: FncpProviderAllowlistStore = {
      async upsert() {
        called = true;
        throw new Error("not expected");
      },
      async readback() {
        called = true;
        throw new Error("not expected");
      },
      async remove() {
        called = true;
        throw new Error("not expected");
      },
    };
    const app = testApp(store);
    const response = await request(app)
      .post(FNCP_PROVIDER_ALLOWLIST_PATHS.readback)
      .set("Authorization", `Bearer ${"x".repeat(48)}`)
      .send(body());

    expect(response.status).toBe(404);
    expect(response.body).toEqual({ error: "Not found." });
    expect(response.text).not.toContain(credential);
    expect(response.text).not.toContain(participantXid);
    expect(called).toBe(false);
  });

  test("storage uncertainty fails closed without internal details", async () => {
    const store: FncpProviderAllowlistStore = {
      async upsert() {
        throw new Error(`database failure ${participantXid} ${credential}`);
      },
      async readback() {
        return {
          conversationReady: false,
          operationAccepted: true,
          operationVersion: null,
          present: false,
        };
      },
      async remove() {
        return {
          conversationReady: false,
          operationAccepted: false,
          operationVersion: null,
          present: false,
        };
      },
    };
    const app = testApp(store);

    for (const [path, key] of [
      [FNCP_PROVIDER_ALLOWLIST_PATHS.upsert, allowKey],
      [FNCP_PROVIDER_ALLOWLIST_PATHS.readback, undefined],
      [FNCP_PROVIDER_ALLOWLIST_PATHS.remove, removeKey],
    ] as const) {
      const response = await authorityRequest(app, path, key);
      expect(response.status).toBe(503);
      expect(response.body).toEqual({ error: "Provider unavailable." });
      expect(response.text).not.toContain(credential);
      expect(response.text).not.toContain(participantXid);
    }
  });
});

function testApp(store: FncpProviderAllowlistStore) {
  const app = express();
  app.use(express.json());
  const handlers = createFncpProviderAllowlistHandlers({
    store,
    loadConfig: () => config,
  });
  app.post(FNCP_PROVIDER_ALLOWLIST_PATHS.upsert, handlers.upsert);
  app.post(FNCP_PROVIDER_ALLOWLIST_PATHS.readback, handlers.readback);
  app.post(FNCP_PROVIDER_ALLOWLIST_PATHS.remove, handlers.remove);
  return app;
}

function authorityRequest(
  app: ReturnType<typeof express>,
  path: string,
  idempotencyKey?: string
) {
  const result = request(app)
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
  return result.send(
    operationVersion === undefined ? body() : body({ operationVersion })
  );
}
