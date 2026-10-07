import { EventEmitter } from "node:events";

// Model-only Pool clients. No application, real Config, certificate, DB or store is opened.
const mockedPaths = ["../../src/config", "../../src/utils/logger", "../../src/utils/metered",
  "../../src/auth/fncp-bootstrap-tls", "../../src/auth/generate-token", "pg", "pg-query-stream"];
afterEach(() => { jest.resetModules(); for (const path of mockedPaths) jest.dontMock(path); });
const privateError = () => Object.assign(new Error("synthetic-private-upstream"), {
  code: "23505", constraint: "oidc_user_mappings_pkey", detail: "synthetic-private-detail",
});
const rows = (value: any[] = []) => ({ rows: value });

function fixture(options: {
  fresh?: boolean;
  acquireError?: Error;
  releaseError?: Error;
  handle?: (sql: string, params: any[], client: any, index: number) => any;
} = {}) {
  const clients: any[] = [];
  const calls: { sql: string; params: any[]; index: number }[] = [];
  const logger = { error: jest.fn(), warn: jest.fn(), info: jest.fn() };
  const pools: any[] = [];
  jest.doMock("../../src/config", () => ({ __esModule: true, default: {
    freshBootstrapLocalOnly: options.fresh ?? false, authNamespace: "",
    databaseURL: "postgres://invented:invented@127.0.0.1:5432/invented",
    readOnlyDatabaseURL: "postgres://invented:invented@127.0.0.1:5432/invented",
    isDevMode: false, databaseSSL: false,
  } }));
  jest.doMock("../../src/utils/logger", () => ({ __esModule: true, default: logger }));
  jest.doMock("../../src/utils/metered", () => ({ MPromise: jest.fn() }));
  jest.doMock("../../src/auth/fncp-bootstrap-tls", () => ({ loadFreshBootstrapTls: () => ({ FreshBootstrapPgClient: class {}, databaseSsl: {} }) }));
  jest.doMock("../../src/auth/generate-token", () => ({ generateTokenP: jest.fn() }));
  jest.doMock("pg-query-stream", () => ({ __esModule: true, default: class {} }));
  jest.doMock("pg", () => ({ Pool: class {
    connect = jest.fn(async () => {
      if (options.acquireError) throw options.acquireError;
      const index = clients.length;
      const client: any = new EventEmitter();
      client.release = jest.fn(() => { if (options.releaseError) throw options.releaseError; });
      client.query = jest.fn((sql: string, params: any[] = []) => {
        calls.push({ sql: sql.trim().replace(/\s+/g, " "), params, index });
        return Promise.resolve().then(() => options.handle?.(sql.trim().replace(/\s+/g, " "), params, client, index) ?? rows())
          .then((result) => ({ ...result, command: result.command ?? sql.split(" ")[0] }));
      });
      clients.push(client);
      return client;
    });
    constructor() { pools.push(this); }
  } }));
  const pg = require("../../src/db/pg-query").default;
  const create = require("../../src/auth/create-user").getOrCreateUserIDFromOidcSub;
  return { pg, create, clients, calls, logger, pools };
}
const identity = { email: "invented-bootstrap@example.invalid", name: "Invented bootstrap" };

test("BEGIN, all work and COMMIT share one checkout and one release", async () => {
  const f = fixture({ handle: (sql) => sql === "SELECT second" ? rows([{ uid: 7 }]) : rows() });
  await expect(f.pg.withTransaction(async (query: any) => {
    await query("SELECT first", [1]);
    return (await query("SELECT second", [2])).rows[0].uid;
  })).resolves.toBe(7);
  expect(f.calls.map((x) => [x.sql, x.index])).toEqual([["BEGIN", 0], ["SELECT first", 0], ["SELECT second", 0], ["COMMIT", 0]]);
  expect(f.pools[0].connect).toHaveBeenCalledTimes(1);
  expect(f.pools[1].connect).not.toHaveBeenCalled();
  expect(f.clients[0].release.mock.calls).toEqual([[]]);
  expect(f.clients[0].listenerCount("error")).toBe(0);
});

test("failed acquisition does not query or invent a release", async () => {
  const error = privateError(); const f = fixture({ acquireError: error });
  await expect(f.pg.withTransaction(jest.fn())).rejects.toBe(error);
  expect(f.calls).toEqual([]); expect(f.clients).toEqual([]);
  expect(f.pg.transactionRolledBack(error)).toBe(false);
});

test.each(["BEGIN", "COMMIT", "ROLLBACK"])("%s uncertainty discards once and is not retryable", async (stage) => {
  const error = privateError();
  const f = fixture({ handle: (sql) => { if (sql === stage || (stage === "ROLLBACK" && sql === "mutation")) throw error; return rows(); } });
  await expect(f.pg.withTransaction((query: any) => query("mutation"))).rejects.toBe(error);
  expect(f.pg.transactionRolledBack(error)).toBe(false);
  expect(f.clients[0].release).toHaveBeenCalledTimes(1);
  expect(f.clients[0].release.mock.calls[0][0]).toBeInstanceOf(Error);
  if (stage === "COMMIT") expect(f.calls.map((x) => x.sql)).toEqual(["BEGIN", "mutation", "COMMIT"]);
  if (stage === "BEGIN") expect(f.calls.map((x) => x.sql)).toEqual(["BEGIN"]);
});

test("work failure rolls back on the same client and confirms retry only after release", async () => {
  const error = privateError(); const f = fixture({ handle: (sql) => { if (sql === "mutation") throw error; return rows(); } });
  await expect(f.pg.withTransaction((query: any) => query("mutation"))).rejects.toBe(error);
  expect(f.calls.map((x) => [x.sql, x.index])).toEqual([["BEGIN", 0], ["mutation", 0], ["ROLLBACK", 0]]);
  expect(f.clients[0].release.mock.calls).toEqual([[]]);
  expect(f.pg.transactionRolledBack(error)).toBe(true);
});

test.each(["BEGIN", "COMMIT", "ROLLBACK"])("wrong %s command tag is not admitted as an acknowledged outcome", async (stage) => {
  const error = privateError();
  const f = fixture({ handle: (sql) => {
    if (stage === "ROLLBACK" && sql === "mutation") throw error;
    return sql === stage ? { rows: [], command: stage === "COMMIT" ? "ROLLBACK" : "SELECT" } : rows();
  } });
  const caught = await f.pg.withTransaction((query: any) => query("mutation")).catch((e: any) => e);
  expect(caught).toBeInstanceOf(Error); expect(f.pg.transactionRolledBack(caught)).toBe(false);
  expect(f.clients[0].release).toHaveBeenCalledTimes(1);
  expect(f.clients[0].release.mock.calls[0][0]).toBeInstanceOf(Error);
});

test("a swallowed statement error still forces rollback, never successful COMMIT", async () => {
  const error = privateError();
  const f = fixture({ handle: (sql) => { if (sql === "mutation") throw error; return rows(); } });
  await expect(f.pg.withTransaction(async (query: any) => { await query("mutation").catch(() => undefined); return 19; })).rejects.toBe(error);
  expect(f.calls.map((x) => x.sql)).toEqual(["BEGIN", "mutation", "ROLLBACK"]);
  expect(f.pg.transactionRolledBack(error)).toBe(true);
});

test.each(["success", "rollback"])("release failure after %s cannot report success or retry", async (mode) => {
  const releaseError = privateError(); const f = fixture({ releaseError });
  await expect(f.pg.withTransaction(async () => { if (mode === "rollback") throw privateError(); return 9; })).rejects.toBe(releaseError);
  expect(f.pg.transactionRolledBack(releaseError)).toBe(false);
  expect(f.clients[0].release).toHaveBeenCalledTimes(1);
});

test("idle client connection error prevents COMMIT and discards the owned client", async () => {
  const f = fixture();
  await expect(f.pg.withTransaction(async () => { f.clients[0].emit("error", privateError()); return 1; })).rejects.toThrow("connection failed");
  expect(f.calls.map((x) => x.sql)).toEqual(["BEGIN"]);
  expect(f.clients[0].release).toHaveBeenCalledTimes(1);
  expect(f.clients[0].release.mock.calls[0][0]).toBeInstanceOf(Error);
});

test("leased query cannot be used after completion", async () => {
  const f = fixture(); let escaped: any;
  await f.pg.withTransaction(async (query: any) => { escaped = query; return 1; });
  await expect(escaped("late mutation")).rejects.toThrow("lease is not active");
  expect(f.calls.map((x) => x.sql)).toEqual(["BEGIN", "COMMIT"]);
});

test("unawaited work is drained then rolled back, never committed", async () => {
  let complete: any;
  const f = fixture({ handle: (sql) => sql === "mutation" ? new Promise((resolve) => { complete = () => resolve(rows()); }) : rows() });
  const result = f.pg.withTransaction(async (query: any) => { void query("mutation"); return 1; });
  await new Promise((resolve) => setImmediate(resolve));
  expect(f.calls.map((x) => x.sql)).toEqual(["BEGIN", "mutation"]);
  complete();
  await expect(result).rejects.toThrow("not fully awaited");
  expect(f.calls.map((x) => x.sql)).toEqual(["BEGIN", "mutation", "ROLLBACK"]);
  expect(f.clients[0].release).toHaveBeenCalledTimes(1);
});

test("an old error object's rollback marker cannot authorize a later uncertain commit", async () => {
  const error = privateError(); let iteration = 0;
  const f = fixture({ handle: (sql) => { if ((iteration === 0 && sql === "mutation") || (iteration === 1 && sql === "COMMIT")) throw error; return rows(); } });
  await expect(f.pg.withTransaction((query: any) => query("mutation"))).rejects.toBe(error);
  expect(f.pg.transactionRolledBack(error)).toBe(true); iteration = 1;
  await expect(f.pg.withTransaction((query: any) => query("mutation"))).rejects.toBe(error);
  expect(f.pg.transactionRolledBack(error)).toBe(false);
});

test.each(["acquire", "work", "commit", "release"])("fresh %s failure has no raw error fields", async (stage) => {
  const error = privateError(); const f = fixture({ fresh: true,
    acquireError: stage === "acquire" ? error : undefined, releaseError: stage === "release" ? error : undefined,
    handle: (sql) => { if ((stage === "work" && sql === "mutation") || (stage === "commit" && sql === "COMMIT")) throw error; return rows(); },
  });
  const caught = await f.pg.withTransaction((query: any) => query("mutation")).catch((e: any) => e);
  expect(caught.message).toBe("FNCP_FRESH_BOOTSTRAP_TRANSACTION_FAILED");
  expect(caught.cause).toBeUndefined(); expect(caught.code).toBeUndefined(); expect(caught.detail).toBeUndefined();
});

test.each([false, true])("existing OIDC mapping returns the same uid on one client (fresh=%s)", async (fresh) => {
  const f = fixture({ fresh, handle: (sql) => sql.startsWith("SELECT uid FROM oidc") ? rows([{ uid: 11 }]) : rows() });
  await expect(f.create("invented-sub", identity)).resolves.toBe(11);
  expect(f.calls.map((x) => x.sql)).toEqual(["BEGIN", "SELECT uid FROM oidc_user_mappings WHERE oidc_sub = $1", "COMMIT"]);
  expect(f.clients).toHaveLength(1); expect(f.clients[0].release.mock.calls).toEqual([[]]);
});

test.each(["new", "same", "replace"])("OIDC %s mapping flow keeps every statement on its leased client", async (mode) => {
  const f = fixture({ handle: (sql) => {
    if (sql.startsWith("INSERT INTO users")) return rows([{ uid: 12 }]);
    if (sql.startsWith("SELECT oidc_sub")) return rows(mode === "new" ? [] : [{ oidc_sub: mode === "same" ? "invented-sub" : "old-invented-sub" }]);
    return rows();
  } });
  await expect(f.create("invented-sub", identity)).resolves.toBe(12);
  expect(new Set(f.calls.map((x) => x.index))).toEqual(new Set([0]));
  expect(f.calls.at(-1)!.sql).toBe("COMMIT");
  expect(f.calls.filter((x) => x.sql.startsWith("DELETE"))).toHaveLength(mode === "replace" ? 1 : 0);
  expect(f.calls.filter((x) => x.sql.startsWith("INSERT INTO oidc"))).toHaveLength(mode === "same" ? 0 : 1);
});

test("missing upsert uid rolls back and cannot report success", async () => {
  const f = fixture(); await expect(f.create("invented-sub", identity)).rejects.toThrow("Failed to create or find user");
  expect(f.calls.at(-1)!.sql).toBe("ROLLBACK"); expect(f.clients[0].release).toHaveBeenCalledTimes(1);
});

test("ordinary pkey retry uses a new transaction only after acknowledged rollback", async () => {
  const error = privateError();
  const f = fixture({ handle: (sql, _params, _client, index) => {
    if (sql.startsWith("SELECT uid FROM oidc")) { if (!index) throw error; return rows([{ uid: 13 }]); }
    return rows();
  } });
  await expect(f.create("invented-sub", identity)).resolves.toBe(13);
  expect(f.clients).toHaveLength(2);
  expect(f.calls.filter((x) => ["BEGIN", "ROLLBACK", "COMMIT"].includes(x.sql)).map((x) => [x.sql, x.index]))
    .toEqual([["BEGIN", 0], ["ROLLBACK", 0], ["BEGIN", 1], ["COMMIT", 1]]);
});

test.each(["commit", "rollback", "release"])("OIDC %s uncertainty never repeats a mutation", async (stage) => {
  const error = privateError(); const f = fixture({ releaseError: stage === "release" ? error : undefined,
    handle: (sql) => {
      if ((stage === "commit" && sql === "COMMIT") || (stage === "rollback" && (sql === "ROLLBACK" || sql.startsWith("SELECT uid")))) throw error;
      if (stage === "commit") return sql.startsWith("INSERT INTO users") ? rows([{ uid: 14 }]) : rows();
      return sql.startsWith("SELECT uid") ? rows([{ uid: 14 }]) : rows();
    },
  });
  await expect(f.create("invented-sub", identity)).rejects.toBe(error);
  expect(f.clients).toHaveLength(1); expect(f.clients[0].release).toHaveBeenCalledTimes(1);
  if (stage === "commit") {
    expect(f.calls.filter((x) => x.sql.startsWith("INSERT INTO users"))).toHaveLength(1);
    expect(f.calls.filter((x) => x.sql.startsWith("INSERT INTO oidc"))).toHaveLength(1);
  }
});

test("fresh OIDC error is sanitized and does not retry even a confirmed23505 rollback", async () => {
  const f = fixture({ fresh: true, handle: (sql) => { if (sql.startsWith("SELECT uid")) throw privateError(); return rows(); } });
  await expect(f.create("synthetic-private-sub", identity)).rejects.toThrow("FNCP_FRESH_BOOTSTRAP_OIDC_MAPPING_FAILED");
  expect(f.clients).toHaveLength(1);
  expect(f.logger.error.mock.calls).toEqual([["fncp_fresh_bootstrap_oidc_mapping_failed"]]);
  expect(f.logger.warn).not.toHaveBeenCalled();
});

test("ordinary constraint recovery reads and inserts on a separate single primary transaction", async () => {
  const error = Object.assign(privateError(), { constraint: "users_email_key" });
  const f = fixture({ handle: (sql, _params, _client, index) => {
    if (!index && sql.startsWith("SELECT uid")) throw error;
    if (index && sql.startsWith("SELECT uid FROM users")) return rows([{ uid: 15 }]);
    return rows();
  } });
  await expect(f.create("invented-sub", identity)).resolves.toBe(15);
  expect(f.clients).toHaveLength(2); expect(f.pools[1].connect).not.toHaveBeenCalled();
  expect(f.calls.filter((x) => x.index === 1).map((x) => x.sql)).toEqual([
    "BEGIN", "SELECT uid FROM users WHERE LOWER(email) = LOWER($1)",
    "SELECT oidc_sub FROM oidc_user_mappings WHERE uid = $1",
    "INSERT INTO oidc_user_mappings (oidc_sub, uid, created) VALUES ($1, $2, now_as_millis()) ON CONFLICT (oidc_sub) DO NOTHING", "COMMIT",
  ]);
});

test("fresh missing email rejects without checkout or private identity in error", async () => {
  const f = fixture({ fresh: true });
  await expect(f.create("synthetic-private-sub", {})).rejects.toThrow("FNCP_FRESH_BOOTSTRAP_OIDC_MAPPING_FAILED");
  expect(f.clients).toHaveLength(0); expect(f.logger.error).not.toHaveBeenCalled();
});

test.each(["null", "throwing-getter"])("fresh %s identity extraction failure is sanitized before any checkout", async (mode) => {
  const f = fixture({ fresh: true });
  const value = mode === "null" ? null : Object.defineProperty({}, "email", { get() { throw privateError(); } });
  const caught = await f.create("synthetic-private-sub", value).catch((error: unknown) => error);
  expect(caught.message).toBe("FNCP_FRESH_BOOTSTRAP_OIDC_MAPPING_FAILED");
  expect(caught.cause).toBeUndefined(); expect(caught.detail).toBeUndefined();
  expect(f.clients).toHaveLength(0); expect(f.logger.error).not.toHaveBeenCalled();
});
