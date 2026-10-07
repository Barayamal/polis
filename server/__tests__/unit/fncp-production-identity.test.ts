const paths = ["../../src/config", "../../src/utils/logger", "../../src/db/pg-query", "../../src/auth/generate-token"];
afterEach(() => { jest.resetModules(); for (const path of paths) jest.dontMock(path); });
const claims = { email: "invented@example.invalid", email_verified: true, name: "Invented" };
function fixture(results: any[] = []) {
  const query = jest.fn();
  for (const result of results) query.mockResolvedValueOnce({ rows: result });
  const logger = { error: jest.fn(), warn: jest.fn() };
  const pg = { withTransaction: jest.fn(work => work(query)), transactionRolledBack: jest.fn(() => false), queryP: jest.fn() };
  jest.doMock("../../src/config", () => ({ __esModule: true, default: { fncpDedicatedProduction: true } }));
  jest.doMock("../../src/utils/logger", () => ({ __esModule: true, default: logger }));
  jest.doMock("../../src/db/pg-query", () => ({ __esModule: true, default: pg }));
  jest.doMock("../../src/auth/generate-token", () => ({ generateTokenP: jest.fn() }));
  return { create: require("../../src/auth/create-user").getOrCreateUserIDFromOidcSub, pg, query, logger };
}
test("existing verified subject retains its mapping without mutating email or subject", async () => {
  const f = fixture([[{ uid: 7 }]]);
  await expect(f.create("invented-subject", claims)).resolves.toBe(7);
  expect(f.query).toHaveBeenCalledTimes(1);
});
test("new identity gets one mapping and no automatic owner capability", async () => {
  const f = fixture([[], [{ uid: 8 }], []]);
  await expect(f.create("invented-subject", claims)).resolves.toBe(8);
  expect(f.query.mock.calls[1][0]).toContain("false, now_as_millis()");
  expect(f.query.mock.calls[2][1]).toEqual(["invented-subject", 8]);
});
test("email collision cannot overwrite or attach another subject", async () => {
  const f = fixture([[], []]);
  await expect(f.create("other-subject", claims)).rejects.toThrow(/^FNCP_PRODUCTION_OIDC_MAPPING_FAILED$/);
  expect(f.query).toHaveBeenCalledTimes(2);
  expect(f.query.mock.calls.some(call => /DELETE|DO UPDATE/.test(call[0]))).toBe(false);
  expect(JSON.stringify(f.logger.error.mock.calls)).not.toContain(claims.email);
  expect(JSON.stringify(f.logger.error.mock.calls)).not.toContain("other-subject");
});
test.each([undefined, false, "true"])("unverified email %p cannot enter the mapping transaction", async verified => {
  const f = fixture();
  await expect(f.create("invented-subject", { ...claims, email_verified: verified })).rejects.toThrow(/^FNCP_PRODUCTION_OIDC_MAPPING_FAILED$/);
  expect(f.pg.withTransaction).not.toHaveBeenCalled();
});
test("uncertain transaction outcome is not retried or recovered", async () => {
  const f = fixture();
  f.pg.withTransaction.mockRejectedValue(Object.assign(new Error("private failure"), { code: "23505", constraint: "oidc_user_mappings_pkey" }));
  await expect(f.create("invented-subject", claims)).rejects.toThrow(/^FNCP_PRODUCTION_OIDC_MAPPING_FAILED$/);
  expect(f.pg.queryP).not.toHaveBeenCalled();
});
