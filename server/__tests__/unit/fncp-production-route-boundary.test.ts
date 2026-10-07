import { expect, test, jest } from "@jest/globals";
import { createFncpProductionRouteBoundary } from "../../src/auth/fncp-production-route-boundary";

function exercise(method: string, path: string, mode = "production") {
  const next = jest.fn();
  const json = jest.fn();
  const status = jest.fn(() => ({ json }));
  createFncpProductionRouteBoundary({ FNCP_OPTION_C_RELEASE_MODE: mode })(
    { method, path } as any, { status } as any, next
  );
  return { next, json, status };
}

test.each([
  ["GET", "/api/v3/comments"], ["GET", "/api/v3/math/pca2"],
  ["GET", "/api/v3/nextComment"], ["GET", "/api/v3/participationInit"],
  ["POST", "/api/v3/votes"], ["POST", "/fncp/private/xid-allowlist/upsert"],
  ["POST", "/fncp/private/xid-allowlist/readback"], ["POST", "/fncp/private/xid-allowlist/remove"],
])("reviewed %s %s continues to its mandatory authentication", (method, path) => {
  const result = exercise(method, path);
  expect(result.next).toHaveBeenCalledTimes(1);
  expect(result.status).not.toHaveBeenCalled();
});

test.each([
  ["GET", "/api/v3/bidToPid"], ["GET", "/api/v3/reportExport/known-report/participant-votes.csv"],
  ["GET", "/api/v3/xid/known-report-xid.csv"], ["GET", "/api/v3/dataExport"],
  ["GET", "/api/v3/dataExport/results"], ["GET", "/api/v3/reports"],
  ["GET", "/api/v3/math/correlationMatrix"], ["GET", "/api/v3/conversations"],
  ["POST", "/api/v3/comments"], ["POST", "/api/v3/joinWithInvite"],
  ["HEAD", "/api/v3/math/pca2"], ["OPTIONS", "/api/v3/votes"],
  ["GET", "/API/v3/comments"], ["GET", "/api/v3/comments/"],
  ["GET", "/api/v3/%63omments"], ["PUT", "/api/v3/votes"],
  ["GET", "/fncp/private/xid-allowlist/readback"], ["GET", "/"],
])("dedicated %s %s denies before upstream effects or data lookup", (method, path) => {
  const result = exercise(method, path);
  expect(result.next).not.toHaveBeenCalled();
  expect(result.status).toHaveBeenCalledWith(404);
  expect(result.json).toHaveBeenCalledWith({ error: "Not found." });
});

test.each(["", "synthetic", "fresh-bootstrap"])("existing %s entrypoints retain their independent route policy", (mode) => {
  const result = exercise("GET", "/api/v3/bidToPid", mode);
  expect(result.next).toHaveBeenCalledTimes(1);
  expect(result.status).not.toHaveBeenCalled();
});

test("the dedicated decision is snapshotted rather than changed by a later environment mutation", () => {
  const env = { FNCP_OPTION_C_RELEASE_MODE: "production" };
  const boundary = createFncpProductionRouteBoundary(env);
  env.FNCP_OPTION_C_RELEASE_MODE = "synthetic";
  const next = jest.fn(); const json = jest.fn(); const status = jest.fn(() => ({ json }));
  boundary({ method: "GET", path: "/api/v3/bidToPid" } as any, { status } as any, next);
  expect(status).toHaveBeenCalledWith(404); expect(next).not.toHaveBeenCalled();
});
