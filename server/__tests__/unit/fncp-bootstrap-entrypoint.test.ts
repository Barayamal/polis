/** Actual fresh child + IPC/TLS with a separately compiled synthetic app.
 * The real Pol.is application is NOT imported or run by these tests. All
 * fixture sources are created under one new directory and removed exactly.
 */
import { fork, spawn, ChildProcess } from "node:child_process";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  unlinkSync,
  rmdirSync,
} from "node:fs";
import { join } from "node:path";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { request } from "node:https";
import { connect } from "node:net";
import ts from "typescript";

const root = join(__dirname, "../..");
const seedStatementsJson = readFileSync(
  join(root, "../deploy/fncp/seed-statements.json"),
  "utf8"
);
const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
const kid = createHash("sha256")
  .update(pair.publicKey.export({ type: "spki", format: "der" }))
  .digest("hex");
const publicJwk = {
  ...pair.publicKey.export({ format: "jwk" }),
  kid,
  alg: "RS256",
  use: "sig",
};
const issuer = "https://127.0.0.1:23456/";
const namespace = "a".repeat(24);
const files = [
  "src/bootstrap/https-entrypoint.ts",
  "src/bootstrap/https-runtime.ts",
  "src/auth/fncp-bootstrap-admission.ts",
  "src/auth/fncp-bootstrap-startup.ts",
  "src/auth/fncp-log-boundary.ts",
];
function profile() {
  const db = `postgres://fncp_fresh_${"b".repeat(24)}:${"c".repeat(
    64
  )}@fncp-fresh-pg-${namespace}:5432/fncp_fresh_${"d".repeat(24)}`;
  return {
    PATH: "/usr/bin:/bin",
    LANG: "C",
    LC_ALL: "C",
    FNCP_FRESH_BOOTSTRAP_LOCAL_ONLY: "true",
    NODE_ENV: "production",
    DEV_MODE: "false",
    TESTING: "false",
    ENABLE_TELEMETRY: "false",
    USE_NETWORK_HOST: "false",
    SHOULD_USE_TRANSLATION_API: "false",
    BACKFILL_COMMENT_LANG_DETECTION: "false",
    RUN_PERIODIC_EXPORT_TESTS: "false",
    SERVER_LOG_TO_FILE: "false",
    EMAIL_TRANSPORT_TYPES: "disabled",
    ADMIN_EMAILS: "[]",
    ADMIN_UIDS: "[]",
    API_SERVER_PORT: "5000",
    DATABASE_SSL: "true",
    AUTH_AUDIENCE: "fncp-fresh-synthetic-bootstrap",
    AUTH_ISSUER: issuer,
    FNCP_BOOTSTRAP_DATABASE_CERTIFICATE_SHA256: "e".repeat(64),
    FNCP_BOOTSTRAP_JWKS_CERTIFICATE_SHA256: "f".repeat(64),
    LOGIN_CODE_PEPPER: "1".repeat(64),
    ENCRYPTION_PASSWORD_00001: "2".repeat(64),
    DATABASE_URL: db,
    READ_ONLY_DATABASE_URL: db,
    JWKS_URI: `https://fncp-fresh-jwks-${namespace}:8444/.well-known/jwks.json`,
    API_PROD_HOSTNAME: `fncp-fresh-api-${namespace}:8443`,
    DOMAIN_OVERRIDE: `fncp-fresh-api-${namespace}:8443`,
    POLIS_JWT_ISSUER: `https://fncp-fresh-api-${namespace}:8443/`,
    POLIS_JWT_AUDIENCE: "fncp-fresh-synthetic-participants",
    JWT_PRIVATE_KEY_PATH: "/run/fncp/bootstrap/participant-private.pem",
    JWT_PUBLIC_KEY_PATH: "/run/fncp/bootstrap/participant-public.pem",
  };
}
const start = () => ({ type: "start", issuer, publicJwk, seedStatementsJson });
function fixture(mode = "ready") {
  // A sibling of src/node_modules resolves only the selected test dependency
  // installation. No NODE_PATH, symlink, retained .env or dependency copy.
  const dir = mkdtempSync(join(root, ".fncp-owned-entry-test-"));
  mkdirSync(join(dir, "src"));
  mkdirSync(join(dir, "src/auth"));
  mkdirSync(join(dir, "src/bootstrap"));
  for (const file of files) {
    const output = ts.transpileModule(readFileSync(join(root, file), "utf8"), {
      compilerOptions: {
        module: ts.ModuleKind.CommonJS,
        target: ts.ScriptTarget.ES2022,
        esModuleInterop: true,
      },
    }).outputText;
    writeFileSync(join(dir, file.replace(/\.ts$/, ".js")), output, {
      flag: "wx",
      mode: 0o600,
    });
  }
  const app = `const express=require('express');process.send({type:'FIXTURE_APP_IMPORTED'});${
    mode === "throws" ? "throw Error('invented-private-failure');" : ""
  }
const app=express();app.use(express.json());app.use((_req,res)=>{process.send({type:'FIXTURE_HANDLER_ENTERED'});res.json({conversation_id:'3SyntheticChild'})});
exports.default=app;exports.appReady=${
    mode === "held" ? "new Promise(()=>{})" : "Promise.resolve()"
  };`;
  writeFileSync(join(dir, "app.js"), app, { flag: "wx", mode: 0o600 });
  return {
    entry: join(dir, "src/bootstrap/https-entrypoint.js"),
    dir,
    remove() {
      for (const file of files)
        unlinkSync(join(dir, file.replace(/\.ts$/, ".js")));
      unlinkSync(join(dir, "app.js"));
      rmdirSync(join(dir, "src/bootstrap"));
      rmdirSync(join(dir, "src/auth"));
      rmdirSync(join(dir, "src"));
      rmdirSync(dir);
    },
  };
}
async function waitFor<T>(promise: Promise<T>, ms = 8500): Promise<T> {
  let timer: NodeJS.Timeout;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("child deadline")), ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}
function child(f: ReturnType<typeof fixture>, options: any = {}) {
  const p = fork(f.entry, [], {
    execPath: process.execPath,
    execArgv: [],
    cwd: f.dir,
    env: profile(),
    stdio: ["ignore", "ignore", "ignore", "ipc"],
    ...options,
  });
  const messages: any[] = [];
  p.on("message", (message) => messages.push(message));
  const exited = new Promise<{ code: number; signal: string }>(
    (resolve, reject) => {
      p.once("error", reject);
      p.once("exit", (code, signal) => resolve({ code, signal }));
    }
  );
  // With stdio ignored, observe both exact process exit and IPC disconnection.
  // Node does not consistently emit child "close" after parent disconnect().
  const disconnected = new Promise<void>((resolve) =>
    p.once("disconnect", () => resolve())
  );
  const closed = Promise.all([exited, disconnected]).then(() => {});
  async function message(type: string) {
    const existing = messages.find((item) => item.type === type);
    if (existing) return existing;
    return waitFor(
      new Promise<any>((resolve, reject) => {
        const onMessage = (value) => {
          if (value.type === type) {
            p.removeListener("message", onMessage);
            p.removeListener("exit", onExit);
            resolve(value);
          }
        };
        const onExit = () => {
          p.removeListener("message", onMessage);
          reject(new Error("child exited before expected message"));
        };
        p.on("message", onMessage);
        p.once("exit", onExit);
      })
    );
  }
  return {
    p,
    messages,
    exited,
    closed,
    message,
    async cleanup() {
      if (p.exitCode === null && p.signalCode === null) {
        if (p.connected) p.disconnect();
        p.kill("SIGTERM");
      }
      try {
        await waitFor(closed, 3000);
      } catch {
        p.kill("SIGKILL");
        await waitFor(closed, 1000);
      }
      f.remove();
    },
  };
}
const send = (p: ChildProcess, value: unknown) =>
  new Promise<void>((resolve, reject) =>
    p.send(value as any, (error) => (error ? reject(error) : resolve()))
  );
async function refused(origin: string) {
  const port = Number(new URL(origin).port);
  await new Promise<void>((resolve, reject) => {
    const socket = connect({ host: "127.0.0.1", port });
    socket.setTimeout(500);
    socket.once("connect", () => {
      socket.destroy();
      reject(new Error("listener still open"));
    });
    socket.once("timeout", () => {
      socket.destroy();
      reject(new Error("probe timeout"));
    });
    socket.once("error", (error: any) => {
      socket.destroy();
      error.code === "ECONNREFUSED" ? resolve() : reject(error);
    });
  });
}

test("fixed IPC child starts owned HTTPS fixture routes, closes listener, and exits exact child", async () => {
  const c = child(fixture());
  try {
    await send(c.p, start());
    const ready = await c.message("HOST_HTTPS_APP_ROUTES_READY");
    expect(Object.keys(ready).sort()).toEqual([
      "certificatePem",
      "certificateSha256",
      "origin",
      "type",
    ]);
    const now = Math.floor(Date.now() / 1000);
    const encode = (value) =>
      Buffer.from(JSON.stringify(value)).toString("base64url");
    const unsigned =
      encode({ alg: "RS256", typ: "JWT", kid }) +
      "." +
      encode({
        iss: issuer,
        aud: "fncp-fresh-synthetic-bootstrap",
        sub: "fncp-invented-bootstrap-admin-" + "a".repeat(48),
        email: "bootstrap-admin@bootstrap.example.invalid",
        email_verified: false,
        name: "Invented local bootstrap administrator",
        iat: now,
        nbf: now,
        exp: now + 100,
        jti: "b".repeat(48),
      });
    const token =
      unsigned +
      "." +
      sign("RSA-SHA256", Buffer.from(unsigned), pair.privateKey).toString(
        "base64url"
      );
    const body = JSON.stringify({
      topic: "FNCP Option C fresh disposable access QA",
      description: "Synthetic local test only. No genuine participant data.",
      is_active: true,
      is_anon: true,
      is_draft: false,
      is_data_open: false,
      topics_enabled: false,
      treevite_enabled: false,
      strict_moderation: true,
      profanity_filter: false,
      spam_filter: false,
    });
    const status = await waitFor(
      new Promise<number>((resolve, reject) => {
        const req = request(
          ready.origin + "/api/v3/conversations",
          {
            method: "POST",
            ca: ready.certificatePem,
            agent: false,
            headers: {
              accept: "application/json",
              "content-type": "application/json",
              "x-forwarded-proto": "https",
              connection: "close",
              authorization: "Bearer " + token,
              "content-length": Buffer.byteLength(body),
            },
          },
          (res) => {
            res.resume();
            res.on("end", () => resolve(res.statusCode));
          }
        );
        req.on("error", reject);
        req.end(body);
      })
    );
    expect(status).toBe(200);
    await c.message("FIXTURE_HANDLER_ENTERED");
    expect(
      c.messages.filter((m) => m.type === "FIXTURE_HANDLER_ENTERED")
    ).toHaveLength(1);
    await send(c.p, { type: "stop" });
    expect((await waitFor(c.exited)).code).toBe(0);
    await c.closed;
    expect(c.messages.find((m) => m.type === "closed").listenerVerified).toBe(
      true
    );
    await refused(ready.origin);
  } finally {
    await c.cleanup();
  }
});
test.each([
  "missing-profile",
  "partial-profile",
  "unsafe-environment",
  "visible-stdout",
  "extra-node-arg",
])("reject %s before fixed app import", async (mode) => {
  const env: any = profile();
  if (mode === "missing-profile") delete env.FNCP_FRESH_BOOTSTRAP_LOCAL_ONLY;
  if (mode === "partial-profile") delete env.DATABASE_URL;
  if (mode === "unsafe-environment")
    env.FNCP_OPTION_C_RELEASE_MODE = "dedicated";
  const c = child(fixture(), {
    env,
    ...(mode === "visible-stdout"
      ? { stdio: ["ignore", "pipe", "ignore", "ipc"] }
      : {}),
    ...(mode === "extra-node-arg" ? { execArgv: ["--no-warnings"] } : {}),
  });
  try {
    expect((await waitFor(c.exited)).code).toBe(1);
    expect(c.messages).toEqual([]);
  } finally {
    await c.cleanup();
  }
});
test("standalone invocation without private IPC fails with no application or diagnostic output", async () => {
  const f = fixture();
  const p = spawn(process.execPath, [f.entry], {
    cwd: f.dir,
    env: profile(),
    stdio: ["ignore", "pipe", "pipe"],
  });
  const stdout: Buffer[] = [],
    stderr: Buffer[] = [];
  p.stdout.on("data", (b) => stdout.push(b));
  p.stderr.on("data", (b) => stderr.push(b));
  const closed = new Promise((resolve) => p.once("close", resolve));
  try {
    const code = await waitFor(closed);
    expect(code).toBe(1);
    expect(Buffer.concat(stdout).length + Buffer.concat(stderr).length).toBe(0);
  } finally {
    if (p.exitCode === null && p.signalCode === null) p.kill("SIGKILL");
    await waitFor(closed, 1000);
    f.remove();
  }
});
test.each([
  "extra-field",
  "wrong-issuer",
  "wrong-key",
  "wrong-seeds",
  "null",
  "array",
])("reject %s IPC before app initialization", async (mode) => {
  const c = child(fixture());
  try {
    const msg =
      mode === "null"
        ? null
        : mode === "array"
        ? []
        : {
            ...start(),
            ...(mode === "extra-field"
              ? { appPath: "/ignored" }
              : mode === "wrong-issuer"
              ? { issuer: "https://127.0.0.1:23457/" }
              : mode === "wrong-key"
              ? { publicJwk: { ...publicJwk, d: "private" } }
              : { seedStatementsJson: "[]" }),
          };
    await send(c.p, msg);
    expect((await waitFor(c.exited)).code).toBe(1);
    expect(c.messages.some((m) => m.type === "FIXTURE_APP_IMPORTED")).toBe(
      false
    );
  } finally {
    await c.cleanup();
  }
});
test.each(["before-start", "during-ready", "after-ready"])(
  "parent disconnect %s terminates the exact owned child",
  async (mode) => {
    const c = child(fixture(mode === "during-ready" ? "held" : "ready"));
    let ready: any;
    try {
      if (mode !== "before-start") {
        await send(c.p, start());
        await c.message("FIXTURE_APP_IMPORTED");
      }
      if (mode === "after-ready")
        ready = await c.message("HOST_HTTPS_APP_ROUTES_READY");
      c.p.disconnect();
      expect((await waitFor(c.exited, 3000)).code).toBe(1);
      await waitFor(c.closed, 1000);
      if (ready) await refused(ready.origin);
      if (mode === "before-start") expect(c.messages).toEqual([]);
    } finally {
      await c.cleanup();
    }
  }
);
test.each(["throws", "held"])(
  "%s app fixture never reports routes ready and exits bounded",
  async (mode) => {
    const c = child(fixture(mode));
    try {
      await send(c.p, start());
      await c.message("FIXTURE_APP_IMPORTED");
      expect((await waitFor(c.exited)).code).toBe(1);
      expect(
        c.messages.some((m) => m.type === "HOST_HTTPS_APP_ROUTES_READY")
      ).toBe(false);
    } finally {
      await c.cleanup();
    }
  }
);
test("a second start message closes instead of importing another application", async () => {
  const c = child(fixture());
  try {
    await send(c.p, start());
    const ready = await c.message("HOST_HTTPS_APP_ROUTES_READY");
    await send(c.p, start());
    expect((await waitFor(c.exited)).code).toBe(1);
    await c.closed;
    await refused(ready.origin);
    expect(
      c.messages.filter((m) => m.type === "FIXTURE_APP_IMPORTED")
    ).toHaveLength(1);
  } finally {
    await c.cleanup();
  }
});
test("entrypoint source has one fixed app import; fresh app skips conflicting legacy global handlers", () => {
  const source = readFileSync(
    join(root, "src/bootstrap/https-entrypoint.ts"),
    "utf8"
  );
  expect(source.match(/require\("\.\.\/\.\.\/app"\)/g)).toHaveLength(1);
  expect(source).not.toContain("require(message");
  expect(readFileSync(join(root, "app.ts"), "utf8")).toContain(
    "if (!Config.freshBootstrapLocalOnly) setupGlobalProcessHandlers();"
  );
  expect(readFileSync(join(root, "src/server.ts"), "utf8")).toMatch(
    /if \(!Config.freshBootstrapLocalOnly\) \{\s+BluebirdPromise.onPossiblyUnhandledRejection/
  );
});
