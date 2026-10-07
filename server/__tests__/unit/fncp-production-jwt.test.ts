const paths = ["../../src/config", "../../src/utils/logger", "../../src/auth/create-user",
  "express-jwt", "jwks-rsa"];
afterEach(() => { jest.resetModules(); for (const path of paths) jest.dontMock(path); });
function fixture() {
  const secretOptions: any[] = [];
  const logger = { warn: jest.fn(), error: jest.fn() };
  const create = jest.fn().mockRejectedValue(new Error("invented-private-subject invented-private-email"));
  jest.doMock("../../src/config", () => ({ __esModule: true, default: { fncpDedicatedProduction: true } }));
  jest.doMock("../../src/utils/logger", () => ({ __esModule: true, default: logger }));
  jest.doMock("../../src/auth/create-user", () => ({ getOrCreateUserIDFromOidcSub: create }));
  jest.doMock("express-jwt", () => ({ expressjwt: jest.fn(() => jest.fn()) }));
  jest.doMock("jwks-rsa", () => ({ expressJwtSecret: (options: any) => { secretOptions.push(options); return jest.fn(); } }));
  return { logger, create, secretOptions, middleware: require("../../src/auth/jwt-middleware") };
}
test("dedicated mapping denial exposes no identity through catch logging or response outside request scope", async () => {
  const f = fixture();
  const response: any = { status: jest.fn(() => response), json: jest.fn() };
  const next = jest.fn();
  await f.middleware.extractUserFromJWT()({ jwtPayload: { sub: "invented-private-subject", email: "invented-private-email" } }, response, next);
  expect(response.status).toHaveBeenCalledWith(403);
  expect(next).not.toHaveBeenCalled();
  expect(f.logger.warn.mock.calls).toEqual([["fncp_production_oidc_mapping_rejected"]]);
  expect(JSON.stringify([f.logger.warn.mock.calls, f.logger.error.mock.calls, response.json.mock.calls])).not.toContain("invented-private");
});
test("both dedicated JWKS handlers omit upstream message and network metadata", () => {
  const f = fixture();
  expect(f.secretOptions).toHaveLength(2);
  for (const options of f.secretOptions) {
    const callback = jest.fn();
    options.handleSigningKeyError(new Error("invented-private-key-id"), callback);
    expect(callback.mock.calls[0][0].message).toBe("FNCP_PRODUCTION_JWKS_VERIFICATION_FAILED");
  }
  expect(f.logger.error.mock.calls).toEqual(Array(2).fill(["fncp_production_jwks_verification_failed"]));
});
