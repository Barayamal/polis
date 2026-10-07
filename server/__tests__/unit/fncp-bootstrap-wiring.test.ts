// No app/Config/DB startup: every consequential dependency is replaced before module loading.
const namespace = "a".repeat(24);
const fakeConfig = (fresh: boolean) => ({
  freshBootstrapLocalOnly: fresh, databaseURL: `postgres://fncp_fresh_${"b".repeat(24)}:${"c".repeat(64)}@fncp-fresh-pg-${namespace}:5432/fncp_fresh_${"d".repeat(24)}`,
  readOnlyDatabaseURL: `postgres://fncp_fresh_${"b".repeat(24)}:${"c".repeat(64)}@fncp-fresh-pg-${namespace}:5432/fncp_fresh_${"d".repeat(24)}`,
  jwksUri: `https://fncp-fresh-jwks-${namespace}:8444/.well-known/jwks.json`, authAudience: "invented", authIssuer: "invented",
  freshBootstrapDatabaseCertificateSha256: "e".repeat(64), freshBootstrapJwksCertificateSha256: "f".repeat(64),
  isDevMode: false, databaseSSL: true,
});
const paths = ["../../src/config", "../../src/utils/logger", "../../src/auth/create-user", "../../src/auth/fncp-bootstrap-tls",
  "express-jwt", "jwks-rsa", "pg", "pg-query-stream", "../../src/utils/metered"];
afterEach(() => { jest.resetModules(); for (const path of paths) jest.dontMock(path); });

test.each([true, false])("both JWT validators use the correct fresh=%s trust and logging branch", (fresh) => {
  const options: any[] = [];
  const middlewareOptions: any[] = [];
  const logger = { error: jest.fn() };
  const fetcher = jest.fn();
  const loader = jest.fn(() => ({ jwksFetcher: fetcher }));
  jest.doMock("../../src/config", () => ({ __esModule: true, default: fakeConfig(fresh) }));
  jest.doMock("../../src/utils/logger", () => ({ __esModule: true, default: logger }));
  jest.doMock("../../src/auth/create-user", () => ({ getOrCreateUserIDFromOidcSub: jest.fn() }));
  jest.doMock("../../src/auth/fncp-bootstrap-tls", () => ({ loadFreshBootstrapTls: loader }));
  jest.doMock("express-jwt", () => ({ expressjwt: (value: unknown) => { middlewareOptions.push(value); return () => {}; } }));
  jest.doMock("jwks-rsa", () => ({ expressJwtSecret: (value: unknown) => { options.push(value); return () => {}; } }));
  require("../../src/auth/jwt-middleware");
  expect(options).toHaveLength(2);
  expect(middlewareOptions).toHaveLength(2);
  expect(loader).toHaveBeenCalledTimes(fresh ? 1 : 0);
  expect(middlewareOptions[1].credentialsRequired).toBe(false);
  const upstream = Object.assign(new Error("private-upstream-value"), { code: "private-code" });
  for (const option of options) {
    expect(option.fetcher).toBe(fresh ? fetcher : undefined);
    const callback = jest.fn(); option.handleSigningKeyError(upstream, callback);
    if (fresh) expect(callback.mock.calls[0][0].message).toBe("Fresh bootstrap JWT verification failed");
    else expect(callback).toHaveBeenCalledWith(upstream);
  }
  if (fresh) expect(logger.error.mock.calls).toEqual([
    ["fncp_fresh_bootstrap_jwks_verification_failed"], ["fncp_fresh_bootstrap_jwks_verification_failed"],
  ]);
});

test("both fresh pools receive the exact guarded client and bounded acquisition", () => {
  const options: any[] = [];
  const GuardedClient = class {};
  const ssl = Object.freeze({ rejectUnauthorized: true });
  jest.doMock("../../src/config", () => ({ __esModule: true, default: fakeConfig(true) }));
  jest.doMock("../../src/utils/logger", () => ({ __esModule: true, default: { error: jest.fn() } }));
  jest.doMock("../../src/utils/metered", () => ({ MPromise: jest.fn() }));
  jest.doMock("../../src/auth/fncp-bootstrap-tls", () => ({ loadFreshBootstrapTls: () => ({ FreshBootstrapPgClient: GuardedClient, databaseSsl: ssl }) }));
  jest.doMock("pg", () => ({ Pool: class { constructor(value: unknown) { options.push(value); } } }));
  jest.doMock("pg-query-stream", () => ({ __esModule: true, default: class {} }));
  require("../../src/db/pg-query");
  expect(options).toHaveLength(2);
  for (const option of options) {
    expect(option.Client).toBe(GuardedClient);
    expect(option.ssl).toBe(ssl);
    expect(option.connectionTimeoutMillis).toBe(2000);
  }
});

test.each(["acquisition-without-release", "acquisition-with-release", "query-error", "success"])(
  "pool wrapper safely handles %s without duplicate release or unhandled rejection", async (mode) => {
    const release = jest.fn();
    const error = new Error("synthetic operation failure");
    jest.doMock("../../src/config", () => ({ __esModule: true, default: fakeConfig(true) }));
    jest.doMock("../../src/utils/logger", () => ({ __esModule: true, default: { error: jest.fn() } }));
    jest.doMock("../../src/utils/metered", () => ({ MPromise: jest.fn() }));
    jest.doMock("../../src/auth/fncp-bootstrap-tls", () => ({ loadFreshBootstrapTls: () => ({ FreshBootstrapPgClient: class {}, databaseSsl: {} }) }));
    jest.doMock("pg", () => ({ Pool: class {
      connect(callback: any) {
        setImmediate(() => {
          if (mode.startsWith("acquisition")) callback(error, undefined, mode.endsWith("without-release") ? undefined : release);
          else callback(null, { query: (_sql: unknown, _params: unknown, done: any) =>
            setImmediate(() => mode === "query-error" ? done(error) : done(null, { rows: [{ synthetic: true }] })) }, release);
        });
      }
    } }));
    jest.doMock("pg-query-stream", () => ({ __esModule: true, default: class {} }));
    const pg = require("../../src/db/pg-query").default;
    const unhandled: unknown[] = [];
    const capture = (reason: unknown) => unhandled.push(reason);
    process.on("unhandledRejection", capture);
    try {
      if (mode === "success") await expect(pg.queryP("SELECT synthetic", [])).resolves.toEqual([{ synthetic: true }]);
      else await expect(pg.queryP("SELECT synthetic", [])).rejects.toBe(error);
      await new Promise<void>((resolve) => setImmediate(resolve));
      expect(unhandled).toEqual([]);
      expect(release).toHaveBeenCalledTimes(mode === "acquisition-without-release" ? 0 : 1);
      if (mode === "success") expect(release).toHaveBeenCalledWith();
      else if (mode !== "acquisition-without-release") expect(release).toHaveBeenCalledWith(error);
    } finally { process.removeListener("unhandledRejection", capture); }
  }
);
