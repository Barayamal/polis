import { afterAll, beforeAll, describe, expect, test } from "@jest/globals";
import { Client } from "pg";

import sql from "../../src/db/postgres-query-builder";

const databaseUrl = process.env.QUERY_BUILDER_DATABASE_URL;
const describeWithDatabase = databaseUrl ? describe : describe.skip;

describeWithDatabase("local query builder against PostgreSQL", () => {
  const client = new Client({ connectionString: databaseUrl });
  const rows: any = sql.define({
    name: "fncp_query_builder_fixture",
    columns: [
      "id",
      "zid",
      "tid",
      "pid",
      "active",
      "created",
      "txt",
      "tags",
      "nullable",
    ],
  });

  beforeAll(async () => {
    await client.connect();
    await client.query(`
      CREATE TEMP TABLE "fncp_query_builder_fixture" (
        "id" integer PRIMARY KEY,
        "zid" integer NOT NULL,
        "tid" integer NOT NULL,
        "pid" integer NOT NULL,
        "active" boolean NOT NULL,
        "created" timestamptz NOT NULL,
        "txt" text NOT NULL,
        "tags" text[],
        "nullable" integer
      )
    `);
  });

  afterAll(async () => {
    await client.end();
  });

  test("executes parameterized insert, update and returning queries", async () => {
    const inserted = await client.query(
      rows
        .insert({
          id: 1,
          zid: 7,
          tid: 11,
          pid: 3,
          active: true,
          created: new Date("2026-07-28T00:00:00.000Z"),
          txt: "O'Reilly",
          tags: ["one", "two"],
          nullable: null,
        })
        .returning("*")
        .toQuery()
    );
    expect(inserted.rows).toHaveLength(1);
    expect(inserted.rows[0]).toMatchObject({
      id: 1,
      txt: "O'Reilly",
      tags: ["one", "two"],
    });

    const updated = await client.query(
      rows
        .update({ active: false, txt: "updated" })
        .where(rows.zid.equals(7))
        .and(rows.id.equals(1))
        .returning("*")
        .toQuery()
    );
    expect(updated.rows[0]).toMatchObject({
      id: 1,
      active: false,
      txt: "updated",
    });
  });

  test("executes legacy inline quoting and repeated where semantics", async () => {
    const result = await client.query(
      rows
        .select(rows.star())
        .where(rows.zid.equals(7))
        .where(rows.id.equals(1))
        .where(rows.txt.equals("updated"))
        .toString()
    );
    expect(result.rows.map((row) => row.id)).toEqual([1]);
  });

  test("executes IN, NOT IN, subquery, ordering, limit and offset", async () => {
    await client.query(
      rows
        .insert({
          id: 2,
          zid: 7,
          tid: 12,
          pid: 3,
          active: true,
          created: new Date("2026-07-28T00:01:00.000Z"),
          txt: "second",
          tags: [],
          nullable: 5,
        })
        .toQuery()
    );
    await client.query(
      rows
        .insert({
          id: 3,
          zid: 8,
          tid: 13,
          pid: 4,
          active: true,
          created: new Date("2026-07-28T00:02:00.000Z"),
          txt: "third",
          tags: null,
          nullable: null,
        })
        .toQuery()
    );

    const result = await client.query(
      rows
        .select(rows.id, rows.tid)
        .where(rows.zid.in([7, 8]))
        .and(
          rows.tid.notIn(
            rows
              .subQuery()
              .select(rows.tid)
              .where(rows.zid.equals(8))
              .and(rows.pid.equals(4))
          )
        )
        .and(rows.id.notIn([null]))
        .order(rows.created.descending)
        .limit(1)
        .offset(0)
        .toQuery()
    );

    expect(result.rows).toEqual([{ id: 2, tid: 12 }]);
  });
});
