import { afterAll, beforeAll, describe, expect, test } from "@jest/globals";

import pg from "../../src/db/pg-query";
import { postgresProviderAllowlistStore } from "../../src/routes/fncp-provider-allowlist";

const databaseUrl = process.env.DATABASE_URL || "";
const safeDatabase =
  /(?:127\.0\.0\.1|localhost|host\.docker\.internal|fncp-provider-api-postgres)/u.test(
    databaseUrl
  ) && /fncp_provider_api_test/u.test(databaseUrl);

const conversationId = "9providerdbqa";
const otherConversationId = "8providerdbqa";
const participantXid = "fncp_disposable-provider-store-001";

describe("FNCP provider allowlist PostgreSQL store", () => {
  beforeAll(async () => {
    if (!safeDatabase) {
      throw new Error(
        "Refusing provider store integration test outside its disposable database."
      );
    }
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
  });

  afterAll(async () => {
    if (safeDatabase) {
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
        participantXid
      )
    ).toEqual({ conversationReady: true, present: true });
    expect(
      await postgresProviderAllowlistStore.upsert(
        conversationId,
        participantXid
      )
    ).toEqual({ conversationReady: true, present: true });
    expect(
      await postgresProviderAllowlistStore.readback(
        conversationId,
        participantXid
      )
    ).toEqual({ conversationReady: true, present: true });

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
        participantXid
      )
    ).toEqual({ conversationReady: true, present: false });
    expect(
      await postgresProviderAllowlistStore.readback(
        otherConversationId,
        participantXid
      )
    ).toEqual({ conversationReady: true, present: false });
    expect(
      await postgresProviderAllowlistStore.readback(
        conversationId,
        participantXid
      )
    ).toEqual({ conversationReady: true, present: true });
  });

  test("remove is exact and idempotent", async () => {
    expect(
      await postgresProviderAllowlistStore.remove(
        conversationId,
        participantXid
      )
    ).toEqual({ conversationReady: true });
    expect(
      await postgresProviderAllowlistStore.remove(
        conversationId,
        participantXid
      )
    ).toEqual({ conversationReady: true });
    expect(
      await postgresProviderAllowlistStore.readback(
        conversationId,
        participantXid
      )
    ).toEqual({ conversationReady: true, present: false });
  });

  test("missing or disabled conversations fail closed", async () => {
    expect(
      await postgresProviderAllowlistStore.readback(
        "7missingdbqa",
        participantXid
      )
    ).toEqual({ conversationReady: false, present: false });
    await pg.queryP(
      "UPDATE conversations SET use_xid_whitelist = FALSE WHERE zid = $1;",
      [201]
    );
    expect(
      await postgresProviderAllowlistStore.upsert(
        conversationId,
        participantXid
      )
    ).toEqual({ conversationReady: false, present: false });
  });
});
