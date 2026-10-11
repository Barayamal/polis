import { assertFncpProductionDatabaseReady } from "../../src/auth/fncp-production-database";

const tids = Array.from({ length: 15 }, (_, id) => id);
const env = { DATABASE_URL: "postgres://scoped_runtime:invented_password@database.invalid:5432/new_database",
  FNCP_GATEWAY_CONVERSATION_ID: "4freshclosed", FNCP_FIXED_STATEMENT_IDS: tids.join(",") };
const closed = { is_active: false, use_xid_whitelist: true, is_data_open: false, seeds_ready: true, tids };
function fixture(metadata: unknown = [{ ready: true }], rows: unknown = [closed]) {
  const query = jest.fn().mockResolvedValueOnce(metadata).mockResolvedValueOnce(rows);
  return { query, ready: () => assertFncpProductionDatabaseReady(query, env) };
}
test("queries exact database/role and conversation with parameters before admitting closed seeds", async () => {
  const f = fixture();
  await expect(f.ready()).resolves.toBeUndefined();
  expect(f.query.mock.calls[0][1]).toEqual(["new_database", "scoped_runtime"]);
  expect(f.query.mock.calls[1][1]).toEqual(["4freshclosed"]);
  expect(f.query.mock.calls[0][0]).not.toContain("invented_password");
});
test.each([[{ ready: false }], [], [{ ready: true }, { ready: true }]])(
  "rejects failed or ambiguous role/TLS evidence before conversation access", async (...args) => {
    const rows = args.length === 1 ? [args[0]] : args;
    const f = fixture(rows);
    await expect(f.ready()).rejects.toThrow("FNCP_PRODUCTION_DATABASE_NOT_READY");
    expect(f.query).toHaveBeenCalledTimes(1);
  });
test.each([
  { is_active: true }, { use_xid_whitelist: false }, { is_data_open: true }, { seeds_ready: false },
  { tids: tids.slice(1) }, { tids: [...tids.slice(1), 14] }, { tids: [...tids.slice(1), 99] },
])("rejects an open, ungated, altered, or incomplete conversation", async override => {
  await expect(fixture([{ ready: true }], [{ ...closed, ...override }]).ready()).rejects.toThrow("FNCP_PRODUCTION_DATABASE_NOT_READY");
});
test("does not expose database exception details", async () => {
  const query = jest.fn().mockRejectedValue(new Error("private database or identity detail"));
  await expect(assertFncpProductionDatabaseReady(query, env)).rejects.toThrow(/^FNCP_PRODUCTION_DATABASE_NOT_READY$/);
});
