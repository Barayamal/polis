import { afterAll, beforeAll, describe, expect, test } from "@jest/globals";

import pg from "../../src/db/pg-query";
import { postgresProviderAllowlistStore } from "../../src/routes/fncp-provider-allowlist";
import { isXidAllowed } from "../../src/xids";

const databaseUrl = process.env.DATABASE_URL || "";
const safeDatabase =
  /(?:127\.0\.0\.1|localhost|host\.docker\.internal|fncp-provider-api-postgres)/u.test(
    databaseUrl
  ) &&
  /(?:fncp_provider_api_test|fncp_query_builder_ci)/u.test(databaseUrl);

const conversationId = "9providerdbqa";
const otherConversationId = "8providerdbqa";
const participantXid = "fncp_disposable-provider-store-001";
const credential = "s".repeat(48);
const previous = {
  enabled: process.env.FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT,
  conversationId: process.env.FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID,
  credential: process.env.FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL,
};

describe("FNCP provider allowlist PostgreSQL store", () => {
  beforeAll(async () => {
    if (!safeDatabase) {
      throw new Error(
        "Refusing provider store integration test outside its disposable database."
      );
    }
    await pg.queryP(
      "DROP TABLE IF EXISTS fncp_provider_allowlist_operations;",
      []
    );
    await pg.queryP("DROP TABLE IF EXISTS xid_whitelist;", []);
    await pg.queryP("DROP TABLE IF EXISTS zinvites;", []);
    await pg.queryP("DROP TABLE IF EXISTS conversations;", []);
    await pg.queryP("DROP TABLE IF EXISTS users;", []);
    await pg.queryP("CREATE TABLE users (uid INTEGER PRIMARY KEY);", []);
    await pg.queryP(
      `CREATE TABLE conversations (
         zid INTEGER PRIMARY KEY,
         owner INTEGER NOT NULL REFERENCES users(uid),
         use_xid_whitelist BOOLEAN NOT NULL DEFAULT FALSE
       );`,
      []
    );
    await pg.queryP(
      `CREATE TABLE zinvites (
         zinvite TEXT PRIMARY KEY,
         zid INTEGER NOT NULL REFERENCES conversations(zid)
       );`,
      []
    );
    await pg.queryP(
      `CREATE TABLE xid_whitelist (
         owner INTEGER NOT NULL REFERENCES users(uid),
         xid TEXT NOT NULL,
         zid INTEGER REFERENCES conversations(zid),
         UNIQUE (owner, xid)
       );`,
      []
    );
    await pg.queryP(
      `CREATE TABLE fncp_provider_allowlist_operations (
         zid INTEGER NOT NULL REFERENCES conversations(zid) ON DELETE CASCADE,
         xid TEXT NOT NULL,
         operation_version SMALLINT NOT NULL CHECK (
           operation_version IN (1, 2)
         ),
         desired_present BOOLEAN NOT NULL,
         PRIMARY KEY (zid, xid),
         CHECK (
           (operation_version = 1 AND desired_present IS TRUE)
           OR (operation_version = 2 AND desired_present IS FALSE)
         )
       );`,
      []
    );
    await pg.queryP("INSERT INTO users (uid) VALUES ($1);", [101]);
    await pg.queryP(
      `INSERT INTO conversations (zid, owner, use_xid_whitelist)
       VALUES ($1, $2, TRUE), ($3, $2, TRUE);`,
      [201, 101, 202]
    );
    await pg.queryP(
      `INSERT INTO zinvites (zinvite, zid)
       VALUES ($1, $2), ($3, $4);`,
      [conversationId, 201, otherConversationId, 202]
    );
    process.env.FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT = "true";
    process.env.FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID = conversationId;
    process.env.FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL = credential;
  });

  afterAll(async () => {
    setOrDelete("FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT", previous.enabled);
    setOrDelete(
      "FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID",
      previous.conversationId
    );
    setOrDelete(
      "FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL",
      previous.credential
    );
    if (safeDatabase) {
      await pg.queryP(
        "DROP TABLE IF EXISTS fncp_provider_allowlist_operations;",
        []
      );
      await pg.queryP("DROP TABLE IF EXISTS xid_whitelist;", []);
      await pg.queryP("DROP TABLE IF EXISTS zinvites;", []);
      await pg.queryP("DROP TABLE IF EXISTS conversations;", []);
      await pg.queryP("DROP TABLE IF EXISTS users;", []);
    }
  });

  test("upsert and primary readback are exact and idempotent", async () => {
    expect(
      await postgresProviderAllowlistStore.upsert(
        conversationId,
        participantXid,
        1
      )
    ).toEqual({
      conversationReady: true,
      operationAccepted: true,
      operationVersion: 1,
      present: true,
    });
    expect(
      await postgresProviderAllowlistStore.upsert(
        conversationId,
        participantXid,
        1
      )
    ).toEqual({
      conversationReady: true,
      operationAccepted: true,
      operationVersion: 1,
      present: true,
    });
    expect(
      await postgresProviderAllowlistStore.readback(
        conversationId,
        participantXid
      )
    ).toEqual({
      conversationReady: true,
      operationAccepted: true,
      operationVersion: 1,
      present: true,
    });

    const count = await pg.queryP<{ count: string }>(
      "SELECT count(*) AS count FROM xid_whitelist WHERE xid = $1;",
      [participantXid]
    );
    expect(count[0]?.count).toBe("1");
  });

  test("an owner collision cannot move an XID to another conversation", async () => {
    expect(
      await postgresProviderAllowlistStore.upsert(
        otherConversationId,
        participantXid,
        1
      )
    ).toEqual({
      conversationReady: true,
      operationAccepted: true,
      operationVersion: 1,
      present: false,
    });
    expect(
      await postgresProviderAllowlistStore.readback(
        otherConversationId,
        participantXid
      )
    ).toEqual({
      conversationReady: true,
      operationAccepted: true,
      operationVersion: 1,
      present: false,
    });
    expect(
      await postgresProviderAllowlistStore.readback(
        conversationId,
        participantXid
      )
    ).toEqual({
      conversationReady: true,
      operationAccepted: true,
      operationVersion: 1,
      present: true,
    });
  });

  test("remove is exact and idempotent", async () => {
    expect(
      await postgresProviderAllowlistStore.remove(
        conversationId,
        participantXid,
        2
      )
    ).toEqual({
      conversationReady: true,
      operationAccepted: true,
      operationVersion: 2,
      present: false,
    });
    expect(
      await postgresProviderAllowlistStore.remove(
        conversationId,
        participantXid,
        2
      )
    ).toEqual({
      conversationReady: true,
      operationAccepted: true,
      operationVersion: 2,
      present: false,
    });
    expect(
      await postgresProviderAllowlistStore.readback(
        conversationId,
        participantXid
      )
    ).toEqual({
      conversationReady: true,
      operationAccepted: true,
      operationVersion: 2,
      present: false,
    });
  });

  test("a delayed version-1 upsert cannot cross a version-2 tombstone", async () => {
    expect(
      await postgresProviderAllowlistStore.upsert(
        conversationId,
        participantXid,
        1
      )
    ).toEqual({
      conversationReady: true,
      operationAccepted: false,
      operationVersion: 2,
      present: false,
    });
    expect(
      await postgresProviderAllowlistStore.readback(
        conversationId,
        participantXid
      )
    ).toEqual({
      conversationReady: true,
      operationAccepted: true,
      operationVersion: 2,
      present: false,
    });
  });

  test("authorization ignores raw re-adds and legacy owner rows after provider removal", async () => {
    await pg.queryP(
      `INSERT INTO xid_whitelist (xid, zid, owner)
       VALUES ($1, $2, $3);`,
      [participantXid, 201, 101]
    );
    await expect(isXidAllowed(participantXid, 201, 101)).resolves.toBe(false);

    const legacyXid = "fncp_legacy-owner-scope-bypass";
    await pg.queryP(
      `INSERT INTO xid_whitelist (xid, zid, owner)
       VALUES ($1, NULL, $2);`,
      [legacyXid, 101]
    );
    await expect(isXidAllowed(legacyXid, 201, 101)).resolves.toBe(false);

    // Other conversations retain upstream legacy behaviour.
    await expect(isXidAllowed(legacyXid, 202, 101)).resolves.toBe(true);
  });

  test("authorization accepts only an exact v1 provider-managed row", async () => {
    const authorizedXid = "fncp_exact-provider-authorized-001";
    expect(
      await postgresProviderAllowlistStore.upsert(
        conversationId,
        authorizedXid,
        1
      )
    ).toEqual({
      conversationReady: true,
      operationAccepted: true,
      operationVersion: 1,
      present: true,
    });
    await expect(isXidAllowed(authorizedXid, 201, 101)).resolves.toBe(true);
  });

  test("missing or disabled conversations fail closed", async () => {
    expect(
      await postgresProviderAllowlistStore.readback(
        "7missingdbqa",
        participantXid
      )
    ).toEqual({
      conversationReady: false,
      operationAccepted: true,
      operationVersion: null,
      present: false,
    });
    await pg.queryP(
      "UPDATE conversations SET use_xid_whitelist = FALSE WHERE zid = $1;",
      [201]
    );
    expect(
      await postgresProviderAllowlistStore.upsert(
        conversationId,
        participantXid,
        1
      )
    ).toEqual({
      conversationReady: false,
      operationAccepted: false,
      operationVersion: null,
      present: false,
    });
  });
});

function setOrDelete(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
}
