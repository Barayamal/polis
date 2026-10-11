import { Readable } from "node:stream";
import { parse as parseSync } from "csv-parse/sync";
import { parse, Parser } from "csv-parse";
import {
  createTopicCsvParser,
  createVoteImportCsvParser,
  parseCsvRecords,
} from "../../src/utils/csv-records";

const collect = (parser: Parser, chunks: (string | Buffer)[]) =>
  new Promise<Record<string, string>[]>((resolve, reject) => {
    const rows: Record<string, string>[] = [];
    parser.on("data", (row) => rows.push(row));
    parser.on("error", reject);
    parser.on("end", () => resolve(rows));
    Readable.from(chunks).pipe(parser);
  });

describe("CSV 7 migration: actual shared consumer shapes", () => {
  test("bulk comments retain strings, Unicode, multiline text and escaped quotes", () => {
    expect(
      parseCsvRecords(
        'comment_text,original_id\r\n"Synthetic, café 😀\nsecond ""line""",0007\r\n\r\n'
      )
    ).toEqual([
      {
        comment_text: 'Synthetic, café 😀\nsecond "line"',
        original_id: "0007",
      },
    ]);
  });

  test("report columns keep hyphenated names and all values as strings", () => {
    expect(
      parseCsvRecords(
        "comment-id,comment,total-votes,group-a-votes\n0,Synthetic,12,5\n"
      )
    ).toEqual([
      {
        "comment-id": "0",
        comment: "Synthetic",
        "total-votes": "12",
        "group-a-votes": "5",
      },
    ]);
  });

  test("empty and header-only input remain empty", () => {
    expect(parseCsvRecords("")).toEqual([]);
    expect(parseCsvRecords("comment_text,original_id\n")).toEqual([]);
  });

  test("ordinary duplicate headers retain the last value without enabling grouping", () => {
    expect(parseCsvRecords("comment_text,comment_text\na,b\n")).toEqual([
      { comment_text: "b" },
    ]);
  });

  test.each([
    ["a,b\n1\n", "CSV_RECORD_INCONSISTENT_COLUMNS"],
    ['a\n"unfinished', "CSV_QUOTE_NOT_CLOSED"],
  ])("sync malformed input raises the existing error class/code", (input, code) => {
    expect(() => parseCsvRecords(input)).toThrow(expect.objectContaining({ code }));
  });

  test("worker stream trims ECMAScript whitespace but preserves quoted whitespace", async () => {
    const input = Buffer.from(
      'vote_id,user_id,vote_value,timestamp,comment_id\n\u00a0v1\u00a0, " u1 " , -1 , 2026-01-01 , c1\n'
    );
    // Split inside a multibyte non-breaking space; Node stream decoding must remain sound.
    const split = input.indexOf(0xc2) + 1;
    const rows = await collect(createVoteImportCsvParser(), [
      input.subarray(0, split),
      input.subarray(split),
    ]);
    expect(rows).toEqual([
      {
        vote_id: "v1",
        user_id: " u1 ",
        vote_value: "-1",
        timestamp: "2026-01-01",
        comment_id: "c1",
      },
    ]);
  });

  test("worker pause/resume keeps 1001 rows and emits end then close once", async () => {
    const parser = createVoteImportCsvParser();
    const input = Readable.from([
      "vote_id,user_id,vote_value,timestamp,comment_id\n",
      ...Array.from({ length: 1001 }, (_, n) => `v${n},u${n},0,,c1\n`),
    ]);
    const seen: string[] = [];
    const lifecycle: string[] = [];
    await new Promise<void>((resolve, reject) => {
      parser.on("data", (row) => {
        seen.push(row.vote_id);
        if (seen.length === 1000) {
          input.pause();
          parser.pause();
          setImmediate(() => {
            parser.resume();
            input.resume();
          });
        }
      });
      parser.on("error", reject);
      parser.on("end", () => lifecycle.push("end"));
      parser.on("close", () => {
        lifecycle.push("close");
        resolve();
      });
      input.pipe(parser);
    });
    expect(seen).toEqual(Array.from({ length: 1001 }, (_, n) => `v${n}`));
    expect(lifecycle).toEqual(["end", "close"]);
  });

  test("worker malformed input rejects rather than silently dropping rows", async () => {
    await expect(
      collect(createVoteImportCsvParser(), ["vote_id,user_id\nv1\n"])
    ).rejects.toMatchObject({ code: "CSV_RECORD_INCONSISTENT_COLUMNS" });
  });

  test("topics parser preserves its deliberate relaxed column count", async () => {
    expect(
      await collect(createTopicCsvParser(), [
        "comment-id,comment_text,moderated\n1,Synthetic,-1,extra\n2,Other\n",
      ])
    ).toEqual([
      { "comment-id": "1", comment_text: "Synthetic", moderated: "-1" },
      { "comment-id": "2", comment_text: "Other" },
    ]);
  });

  test("prototype-shaped columns are own data, not inherited record fields", () => {
    const [row] = parseCsvRecords("__proto__,constructor,toString\na,b,c\n");
    expect(Object.getPrototypeOf(row)).toBe(Object.prototype);
    expect(Object.hasOwn(row, "__proto__")).toBe(true);
    expect(row.__proto__).toBe("a");
    expect(row.constructor).toBe("b");
    expect(row.toString).toBe("c");
  });

  test("upstream advisory regression: grouped prototype columns cannot replace prototypes", async () => {
    const csv = "__proto__,__proto__,constructor,constructor\na,b,c,d\n";
    const options = { columns: true, group_columns_by_name: true };
    const syncRows = parseSync(csv, options);
    const streamRows = await collect(parse(options), [csv]);
    for (const rows of [syncRows, streamRows]) {
      const row = rows[0];
      expect(Object.getPrototypeOf(row)).toBe(Object.prototype);
      expect(Object.hasOwn(row, "__proto__")).toBe(true);
      expect(row.__proto__).toEqual(["a", "b"]);
      expect(row.constructor).toEqual(["c", "d"]);
    }
  });
});
