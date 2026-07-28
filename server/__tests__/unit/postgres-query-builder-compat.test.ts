import { describe, expect, test } from "@jest/globals";

import sql, { databaseNowAsMillis } from "../../src/db/postgres-query-builder";

const LEGACY_TABLE_NAME = "fncp_rows";
const LEGACY_COLUMNS = [
  "id",
  "zid",
  "tid",
  "pid",
  "active",
  "created",
  "txt",
  "tags",
  "nullable",
  "payload",
] as const;

function createTable(): any {
  return sql.define({
    name: LEGACY_TABLE_NAME,
    columns: LEGACY_COLUMNS,
  });
}

type LegacyFixture = {
  name: string;
  build: (table: any) => any;
  text: string;
  parameterizedText: string;
  values: unknown[];
};

// Frozen from sql@0.78.0's PostgreSQL dialect before removing that runtime
// dependency. These cover every non-experimental query-builder shape currently
// used by the server.
const LEGACY_FIXTURES: LegacyFixture[] = [
  {
    name: "select star and simple equality",
    build: (table) => table.select(table.star()).where(table.zid.equals(7)),
    text: 'SELECT "fncp_rows".* FROM "fncp_rows" WHERE ("fncp_rows"."zid" = 7)',
    parameterizedText:
      'SELECT "fncp_rows".* FROM "fncp_rows" WHERE ("fncp_rows"."zid" = $1)',
    values: [7],
  },
  {
    name: "repeated where calls become left-associated AND expressions",
    build: (table) =>
      table
        .select(table.star())
        .where(table.zid.equals(7))
        .where(table.pid.equals(3))
        .where(table.active.equals(true)),
    text: 'SELECT "fncp_rows".* FROM "fncp_rows" WHERE ((("fncp_rows"."zid" = 7) AND ("fncp_rows"."pid" = 3)) AND ("fncp_rows"."active" = TRUE))',
    parameterizedText:
      'SELECT "fncp_rows".* FROM "fncp_rows" WHERE ((("fncp_rows"."zid" = $1) AND ("fncp_rows"."pid" = $2)) AND ("fncp_rows"."active" = $3))',
    values: [7, 3, true],
  },
  {
    name: "OR, IN and IS NOT NULL",
    build: (table) =>
      table
        .select(table.star())
        .where(table.active.equals(true).or(table.zid.in([7, 8, 9])))
        .and(table.nullable.isNotNull()),
    text: 'SELECT "fncp_rows".* FROM "fncp_rows" WHERE ((("fncp_rows"."active" = TRUE) OR ("fncp_rows"."zid" IN (7, 8, 9))) AND ("fncp_rows"."nullable" IS NOT NULL))',
    parameterizedText:
      'SELECT "fncp_rows".* FROM "fncp_rows" WHERE ((("fncp_rows"."active" = $1) OR ("fncp_rows"."zid" IN ($2, $3, $4))) AND ("fncp_rows"."nullable" IS NOT NULL))',
    values: [true, 7, 8, 9],
  },
  {
    name: "empty IN fails closed",
    build: (table) => table.select(table.star()).where(table.tid.in([])),
    text: 'SELECT "fncp_rows".* FROM "fncp_rows" WHERE (1=0)',
    parameterizedText: 'SELECT "fncp_rows".* FROM "fncp_rows" WHERE (1=0)',
    values: [],
  },
  {
    name: "IN preserves SQL null semantics",
    build: (table) =>
      table.select(table.star()).where(table.tid.in([1, null, 3])),
    text: 'SELECT "fncp_rows".* FROM "fncp_rows" WHERE ("fncp_rows"."tid" IN (1, 3) OR "fncp_rows"."tid" IS NULL)',
    parameterizedText:
      'SELECT "fncp_rows".* FROM "fncp_rows" WHERE ("fncp_rows"."tid" IN ($1, $2) OR "fncp_rows"."tid" IS NULL)',
    values: [1, 3],
  },
  {
    name: "empty NOT IN succeeds",
    build: (table) => table.select(table.star()).where(table.tid.notIn([])),
    text: 'SELECT "fncp_rows".* FROM "fncp_rows" WHERE (1=1)',
    parameterizedText: 'SELECT "fncp_rows".* FROM "fncp_rows" WHERE (1=1)',
    values: [],
  },
  {
    name: "NOT IN preserves SQL null semantics",
    build: (table) =>
      table.select(table.star()).where(table.tid.notIn([1, null, 3])),
    text: 'SELECT "fncp_rows".* FROM "fncp_rows" WHERE (NOT ("fncp_rows"."tid" IN (1, 3) OR "fncp_rows"."tid" IS NULL))',
    parameterizedText:
      'SELECT "fncp_rows".* FROM "fncp_rows" WHERE (NOT ("fncp_rows"."tid" IN ($1, $2) OR "fncp_rows"."tid" IS NULL))',
    values: [1, 3],
  },
  {
    name: "NOT IN containing only null becomes IS NOT NULL",
    build: (table) => table.select(table.star()).where(table.tid.notIn([null])),
    text: 'SELECT "fncp_rows".* FROM "fncp_rows" WHERE ("fncp_rows"."tid" IS NOT NULL)',
    parameterizedText:
      'SELECT "fncp_rows".* FROM "fncp_rows" WHERE ("fncp_rows"."tid" IS NOT NULL)',
    values: [],
  },
  {
    name: "NOT IN accepts a table subquery",
    build: (table) =>
      table
        .select(table.star())
        .where(
          table.tid.notIn(
            table
              .subQuery()
              .select(table.tid)
              .where(table.zid.equals(7))
              .and(table.pid.equals(3))
          )
        ),
    text: 'SELECT "fncp_rows".* FROM "fncp_rows" WHERE ("fncp_rows"."tid" NOT IN (SELECT "fncp_rows"."tid" FROM "fncp_rows" WHERE (("fncp_rows"."zid" = 7) AND ("fncp_rows"."pid" = 3))))',
    parameterizedText:
      'SELECT "fncp_rows".* FROM "fncp_rows" WHERE ("fncp_rows"."tid" NOT IN (SELECT "fncp_rows"."tid" FROM "fncp_rows" WHERE (("fncp_rows"."zid" = $1) AND ("fncp_rows"."pid" = $2))))',
    values: [7, 3],
  },
  {
    name: "not-equal and greater-than comparisons",
    build: (table) =>
      table
        .select(table.star())
        .where(table.active.notEquals(false))
        .and(table.id.gt(0)),
    text: 'SELECT "fncp_rows".* FROM "fncp_rows" WHERE (("fncp_rows"."active" <> FALSE) AND ("fncp_rows"."id" > 0))',
    parameterizedText:
      'SELECT "fncp_rows".* FROM "fncp_rows" WHERE (("fncp_rows"."active" <> $1) AND ("fncp_rows"."id" > $2))',
    values: [false, 0],
  },
  {
    name: "raw, column and descending order with limit and offset",
    build: (table) =>
      table
        .select(table.star())
        .where(table.zid.equals(7))
        .order("is_seed desc, random()")
        .order(table.created)
        .order(table.id.descending)
        .limit(12)
        .offset(4),
    text: 'SELECT "fncp_rows".* FROM "fncp_rows" WHERE ("fncp_rows"."zid" = 7) ORDER BY is_seed desc, random(), "fncp_rows"."created", "fncp_rows"."id" DESC LIMIT 12 OFFSET 4',
    parameterizedText:
      'SELECT "fncp_rows".* FROM "fncp_rows" WHERE ("fncp_rows"."zid" = $1) ORDER BY is_seed desc, random(), "fncp_rows"."created", "fncp_rows"."id" DESC LIMIT 12 OFFSET 4',
    values: [7],
  },
  {
    name: "selected columns and quoted text",
    build: (table) =>
      table.select(table.id, table.txt).where(table.txt.equals("O'Reilly")),
    text: 'SELECT "fncp_rows"."id", "fncp_rows"."txt" FROM "fncp_rows" WHERE ("fncp_rows"."txt" = \'O\'\'Reilly\')',
    parameterizedText:
      'SELECT "fncp_rows"."id", "fncp_rows"."txt" FROM "fncp_rows" WHERE ("fncp_rows"."txt" = $1)',
    values: ["O'Reilly"],
  },
  {
    name: "update, returning, scalar values and a PostgreSQL array",
    build: (table) =>
      table
        .update({
          txt: "O'Reilly",
          active: false,
          nullable: null,
          tags: ["A", "B'c", 4, null],
        })
        .where(table.zid.equals(7))
        .returning("*"),
    text: 'UPDATE "fncp_rows" SET "txt" = \'O\'\'Reilly\', "active" = FALSE, "nullable" = NULL, "tags" = \'{"A","B\'c",4,NULL}\' WHERE ("fncp_rows"."zid" = 7) RETURNING *',
    parameterizedText:
      'UPDATE "fncp_rows" SET "txt" = $1, "active" = $2, "nullable" = $3, "tags" = $4 WHERE ("fncp_rows"."zid" = $5) RETURNING *',
    values: ["O'Reilly", false, null, ["A", "B'c", 4, null], 7],
  },
  {
    name: "PostgreSQL array text preserves double-quotes, commas and slashes",
    build: (table) =>
      table.update({ tags: ['A"B', "C,D", "E\\F"] }).where(table.id.equals(1)),
    text: 'UPDATE "fncp_rows" SET "tags" = \'{"A""B","C,D","E\\F"}\' WHERE ("fncp_rows"."id" = 1)',
    parameterizedText:
      'UPDATE "fncp_rows" SET "tags" = $1 WHERE ("fncp_rows"."id" = $2)',
    values: [['A"B', "C,D", "E\\F"], 1],
  },
  {
    name: "insert, returning, date, object and array values",
    build: (table) =>
      table
        .insert({
          zid: 7,
          txt: "O'Reilly",
          active: true,
          nullable: null,
          tags: ["A", "B'c", 4, null],
          created: new Date("2026-07-28T00:00:00.000Z"),
          payload: { a: "b'c" },
        })
        .returning("*"),
    text: 'INSERT INTO "fncp_rows" ("zid", "txt", "active", "nullable", "tags", "created", "payload") VALUES (7, \'O\'\'Reilly\', TRUE, NULL, \'{"A","B\'c",4,NULL}\', \'2026-07-28T00:00:00.000Z\', \'{"a":"b\'\'c"}\') RETURNING *',
    parameterizedText:
      'INSERT INTO "fncp_rows" ("zid", "txt", "active", "nullable", "tags", "created", "payload") VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
    values: [
      7,
      "O'Reilly",
      true,
      null,
      ["A", "B'c", 4, null],
      new Date("2026-07-28T00:00:00.000Z"),
      { a: "b'c" },
    ],
  },
];

describe("local PostgreSQL query builder compatibility", () => {
  test.each(LEGACY_FIXTURES)(
    "matches frozen sql@0.78.0 output: $name",
    ({ build, text, parameterizedText, values }) => {
      const query = build(createTable());
      expect(query.toString()).toBe(text);
      expect(query.toQuery()).toEqual({
        text: parameterizedText,
        values,
      });
    }
  );

  test("retains declared-column introspection used by report updates", () => {
    expect(createTable().columns.map((column: any) => column.name)).toEqual(
      LEGACY_COLUMNS
    );
  });

  test.each(["insert", "update"] as const)(
    "%s rejects columns outside the declared allowlist",
    (operation) => {
      const table = createTable();
      expect(() => table[operation]({ missing: 1 })).toThrow(
        "Table fncp_rows does not have a column or property named missing"
      );
    }
  );

  test("preserves the database-authoritative report timestamp without string replacement", () => {
    const table = createTable();
    const query = table
      .update({ txt: databaseNowAsMillis() })
      .where(table.id.equals(1))
      .toQuery();

    expect(query).toEqual({
      text: 'UPDATE "fncp_rows" SET "txt" = now_as_millis() WHERE ("fncp_rows"."id" = $1)',
      values: [1],
    });
  });

  test("quotes values while restricting identifiers to table definitions", () => {
    const table = createTable();
    expect(
      table
        .select(table.star())
        .where(table.txt.equals("x' OR TRUE; --"))
        .toString()
    ).toBe(
      'SELECT "fncp_rows".* FROM "fncp_rows" WHERE ("fncp_rows"."txt" = \'x\'\' OR TRUE; --\')'
    );
  });

  test.each(["random()", "is_seed desc, random()"])(
    "allows the current fixed raw ORDER BY value: %s",
    (orderValue) => {
      const table = createTable();
      expect(table.select(table.star()).order(orderValue).toString()).toBe(
        `SELECT "fncp_rows".* FROM "fncp_rows" ORDER BY ${orderValue}`
      );
    }
  );

  test.each([
    "",
    "RANDOM()",
    "random() ",
    "created desc",
    "random(); DROP TABLE fncp_rows",
  ])("rejects every unapproved raw ORDER BY value: %p", (orderValue) => {
    const table = createTable();
    expect(() => table.select(table.star()).order(orderValue)).toThrow(
      `Raw ORDER BY value is not allowed: ${orderValue}`
    );
  });

  test("raw ORDER BY validation is atomic", () => {
    const table = createTable();
    const query = table.select(table.star());

    expect(() => query.order("random()", "created desc")).toThrow(
      "Raw ORDER BY value is not allowed: created desc"
    );
    expect(query.order(table.created).toString()).toBe(
      'SELECT "fncp_rows".* FROM "fncp_rows" ORDER BY "fncp_rows"."created"'
    );
  });

  test.each(["limit", "offset"] as const)(
    "%s accepts zero and the largest safe integer",
    (operation) => {
      const table = createTable();
      const zeroQuery = table.select(table.star())[operation](0).toString();
      const maximumBaseQuery = table.select(table.star());
      const maximumQuery = maximumBaseQuery[operation](
        Number.MAX_SAFE_INTEGER
      ).toString();
      const clause = operation.toUpperCase();

      expect(zeroQuery).toBe(
        `SELECT "fncp_rows".* FROM "fncp_rows" ${clause} 0`
      );
      expect(maximumQuery).toBe(
        `SELECT "fncp_rows".* FROM "fncp_rows" ${clause} ${Number.MAX_SAFE_INTEGER}`
      );
    }
  );

  test.each(["limit", "offset"] as const)(
    "%s rejects non-integer, unsafe, negative and non-numeric values",
    (operation) => {
      const invalidValues: unknown[] = [
        -1,
        0.5,
        Number.NaN,
        Number.POSITIVE_INFINITY,
        Number.NEGATIVE_INFINITY,
        Number.MAX_SAFE_INTEGER + 1,
        "1",
        null,
        undefined,
      ];
      const clause = operation.toUpperCase();

      for (const value of invalidValues) {
        const table = createTable();
        expect(() =>
          table.select(table.star())[operation](value as number)
        ).toThrow(`${clause} must be a finite, safe, non-negative integer`);
      }
    }
  );
});
