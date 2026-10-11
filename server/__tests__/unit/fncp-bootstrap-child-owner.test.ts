/** Actual fresh parent/child processes and loopback TLS; the only application
 * loaded is authored inside this test's new private fixture directory. No real
 * Pol.is application, database, retained environment or runtime image is used.
 */
import { fork, ChildProcess } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  unlinkSync,
  rmdirSync,
} from "node:fs";
import { request } from "node:https";
import { connect } from "node:net";
import { join } from "node:path";
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
const trust = { issuer, publicJwk, seedStatementsJson };
const namespace = "a".repeat(24);
const sourceFiles = [
  "src/bootstrap/child-owner.ts",
  "src/bootstrap/child-profile.ts",
  "src/bootstrap/https-entrypoint.ts",
  "src/bootstrap/https-runtime.ts",
  "src/auth/fncp-bootstrap-admission.ts",
  "src/auth/fncp-bootstrap-startup.ts",
  "src/auth/fncp-log-boundary.ts",
];

function environment() {
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

const harnessSource = `"use strict";
const cp=require('node:child_process');
const realFork=cp.fork;let spawns=0;
cp.fork=function(...args){spawns++;const child=realFork(...args);process.send({type:'SPAWNED',spawns});return child;};
const {createBootstrapChildOwner}=require('./src/bootstrap/child-owner.js');
let owner,attempt,controller,started=false,ending=false;
const emit=value=>new Promise(resolve=>process.send(value,()=>resolve()));
async function finish(abort){if(ending)return;ending=true;if(abort)controller?.abort();
  try{owner=owner||await attempt;await owner.close();await emit({type:'SUMMARY',summary:owner.summary(),spawns});}
  catch{await emit({type:'FAILED',spawns});}process.exit(0);}
process.on('message',async m=>{
  if(m.type==='begin'&&!started){started=true;controller=new AbortController();if(m.abortBefore)controller.abort();
    attempt=createBootstrapChildOwner({environment:m.environment,trust:m.trust,signal:controller.signal});
    if(m.abortImmediate)controller.abort();
    try{owner=await attempt;if(!ending)await emit({type:'READY',configuration:owner.configuration(),summary:owner.summary(),spawns});}
    catch{if(!ending){ending=true;await emit({type:'FAILED',spawns});process.exit(0);}}return;}
  if(m.type==='close')return finish(false);
  if(m.type==='abort')return finish(true);
  if(m.type==='summary'&&owner)await emit({type:'SUMMARY',summary:owner.summary(),spawns});
});
process.once('disconnect',()=>{controller?.abort();Promise.resolve(attempt).then(x=>x.close(),()=>{}).finally(()=>process.exit(1));});
process.once('SIGTERM',()=>{controller?.abort();Promise.resolve(attempt).then(x=>x.close(),()=>{}).finally(()=>process.exit(1));});
`;

function alternateChild(mode: string) {
  return `"use strict";
const express=require('express');const {createBootstrapHttpsRuntime}=require('./https-runtime.js');
let runtime,started=false;const controller=new AbortController();
const exit=async()=>{controller.abort();try{await runtime?.close();if(process.connected)process.send({type:'closed',listenerVerified:!!runtime?.summary().listenerClosureVerified},()=>process.exit(0));else process.exit(0);}catch{process.exit(1);}};
process.on('disconnect',exit);process.on('SIGTERM',exit);
process.on('message',async m=>{if(m.type==='stop')return exit();if(started)return;started=true;
 const app=express();app.use(express.json());app.use((_req,res)=>res.json({conversation_id:'3SyntheticOwner'}));
 runtime=await createBootstrapHttpsRuntime({trust:{issuer:m.issuer,publicJwk:m.publicJwk,seedStatementsJson:m.seedStatementsJson},signal:controller.signal,initialize:async()=>({handler:app,ready:Promise.resolve()})});
 const message={type:'HOST_HTTPS_APP_ROUTES_READY',...runtime.configuration()};
 ${mode === "bad-pin" ? "message.certificateSha256='0'.repeat(64);" : ""}
 ${mode === "extra-ready" ? "message.unexpected=true;" : ""}
 ${
   mode === "wrong-origin"
     ? "message.origin=message.origin.replace('https:','http:');"
     : ""
 }
 ${
   mode === "bad-certificate"
     ? "message.certificatePem='not a certificate';"
     : ""
 }
 process.send(${
   mode === "wrong-message" ? "{type:'UNREVIEWED_READY'}" : "message"
 });
 ${mode === "duplicate" ? "setTimeout(()=>process.send(message),150);" : ""}
 ${mode === "unexpected-exit" ? "setTimeout(()=>process.exit(7),150);" : ""}
});`;
}

function fixture(mode = "normal") {
  const dir = mkdtempSync(join(root, ".fncp-child-owner-test-"));
  const written: string[] = [];
  mkdirSync(join(dir, "src"));
  mkdirSync(join(dir, "src/auth"));
  mkdirSync(join(dir, "src/bootstrap"));
  const write = (path: string, source: string) => {
    writeFileSync(join(dir, path), source, { flag: "wx", mode: 0o600 });
    written.push(path);
  };
  for (const path of sourceFiles) {
    if (mode === "missing-entry" && path.endsWith("https-entrypoint.ts"))
      continue;
    const output = path.replace(/\.ts$/, ".js");
    if (
      !["normal", "held", "missing-entry"].includes(mode) &&
      path.endsWith("https-entrypoint.ts")
    )
      write(output, alternateChild(mode));
    else
      write(
        output,
        ts.transpileModule(readFileSync(join(root, path), "utf8"), {
          compilerOptions: {
            module: ts.ModuleKind.CommonJS,
            target: ts.ScriptTarget.ES2022,
            esModuleInterop: true,
          },
        }).outputText
      );
  }
  write(
    "app.js",
    `const express=require('express');const app=express();app.use(express.json());app.use((_req,res)=>res.json({conversation_id:'3SyntheticOwner'}));exports.default=app;exports.appReady=${
      mode === "held" ? "new Promise(()=>{})" : "Promise.resolve()"
    };`
  );
  write("parent-harness.cjs", harnessSource);
  return {
    dir,
    remove() {
      for (const path of written) unlinkSync(join(dir, path));
      rmdirSync(join(dir, "src/bootstrap"));
      rmdirSync(join(dir, "src/auth"));
      rmdirSync(join(dir, "src"));
      rmdirSync(dir);
    },
  };
}

async function deadline<T>(promise: Promise<T>, ms = 12000): Promise<T> {
  let timer: NodeJS.Timeout;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new Error("owned parent harness deadline")),
          ms
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}
const send = (child: ChildProcess, value: unknown) =>
  new Promise<void>((resolve, reject) =>
    child.send(value as any, (error) => (error ? reject(error) : resolve()))
  );
function startHarness(mode = "normal") {
  const f = fixture(mode),
    child = fork(join(f.dir, "parent-harness.cjs"), [], {
      cwd: f.dir,
      execPath: process.execPath,
      execArgv: [],
      env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
      stdio: ["ignore", "ignore", "ignore", "ipc"],
    });
  const messages: any[] = [];
  child.on("message", (value) => messages.push(value));
  const exited = new Promise<void>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", () => resolve());
  });
  const disconnected = new Promise<void>((resolve) =>
    child.once("disconnect", () => resolve())
  );
  const ended = Promise.all([exited, disconnected]).then(() => {});
  async function message(type: string, after = 0) {
    const existing = messages.slice(after).find((value) => value.type === type);
    if (existing) return existing;
    return deadline(
      new Promise<any>((resolve, reject) => {
        const onMessage = (value) => {
          if (value.type === type) {
            child.removeListener("message", onMessage);
            child.removeListener("exit", onExit);
            resolve(value);
          }
        };
        const onExit = () => {
          child.removeListener("message", onMessage);
          reject(new Error("owned parent exited before message"));
        };
        child.on("message", onMessage);
        child.once("exit", onExit);
      })
    );
  }
  return {
    child,
    messages,
    ended,
    message,
    begin: (changes: any = {}) =>
      send(child, {
        type: "begin",
        environment: environment(),
        trust,
        ...changes,
      }),
    async cleanup() {
      if (
        child.exitCode === null &&
        child.signalCode === null &&
        child.connected
      )
        await send(child, { type: "abort" }).catch(() => {});
      try {
        await deadline(ended, 6000);
      } catch {
        child.kill("SIGTERM");
        await deadline(ended, 6000);
      }
      // Preserve the fixture if exact parent shutdown could not be observed.
      f.remove();
    },
  };
}
async function refused(origin: string) {
  await new Promise<void>((resolve, reject) => {
    const socket = connect({
      host: "127.0.0.1",
      port: Number(new URL(origin).port),
    });
    socket.setTimeout(750);
    socket.once("connect", () => {
      socket.destroy();
      reject(new Error("owned child listener still open"));
    });
    socket.once("timeout", () => {
      socket.destroy();
      reject(new Error("owned child refusal deadline"));
    });
    socket.once("error", (error) => {
      socket.destroy();
      error.code === "ECONNREFUSED"
        ? resolve()
        : reject(new Error("owned child refusal not verified"));
    });
  });
}
async function createRequest(config: any) {
  const now = Math.floor(Date.now() / 1000),
    encode = (value) =>
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
  return deadline(
    new Promise<{ status: number; body: string }>((resolve, reject) => {
      const req = request(
        config.origin + "/api/v3/conversations",
        {
          method: "POST",
          ca: config.certificatePem,
          rejectUnauthorized: true,
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
          let result = "";
          res.on("data", (data) => {
            result += data.toString();
            if (result.length > 2048) res.destroy();
          });
          res.on("end", () =>
            resolve({ status: res.statusCode, body: result })
          );
          res.on("error", reject);
        }
      );
      req.on("error", reject);
      req.setTimeout(2000, () =>
        req.destroy(new Error("owned request deadline"))
      );
      req.end(body);
    }),
    3000
  );
}

test("real owner starts one fixed synthetic child, admits a canonical request and verifies exact closure", async () => {
  const h = startHarness();
  try {
    await h.begin();
    const ready = await h.message("READY");
    expect(ready.spawns).toBe(1);
    expect(ready.summary).toMatchObject({
      spawnAttempted: true,
      ready: true,
      databaseOwnershipVerified: false,
      activationGranted: false,
    });
    expect(await createRequest(ready.configuration)).toEqual({
      status: 200,
      body: '{"conversation_id":"3SyntheticOwner"}',
    });
    await send(h.child, { type: "close" });
    const closed = await h.message("SUMMARY");
    await h.ended;
    expect(closed.summary).toMatchObject({
      closed: true,
      childExitVerified: true,
      ipcDisconnected: true,
      listenerClosureVerified: true,
      exitCode: 0,
      signalCode: null,
      databaseOwnershipVerified: false,
      activationGranted: false,
    });
    await refused(ready.configuration.origin);
  } finally {
    await h.cleanup();
  }
});

test("original owner signal already aborted performs zero child spawns", async () => {
  const h = startHarness();
  try {
    await h.begin({ abortBefore: true });
    expect((await h.message("FAILED")).spawns).toBe(0);
    await h.ended;
  } finally {
    await h.cleanup();
  }
});

test("original owner signal aborted immediately after factory call performs zero child spawns", async () => {
  const h = startHarness();
  try {
    await h.begin({ abortImmediate: true });
    expect((await h.message("FAILED")).spawns).toBe(0);
    await h.ended;
  } finally {
    await h.cleanup();
  }
});

test("original owner abort during held child startup never reports ready", async () => {
  const h = startHarness("held");
  try {
    await h.begin();
    await h.message("SPAWNED");
    await send(h.child, { type: "abort" });
    expect((await h.message("FAILED")).spawns).toBe(1);
    await h.ended;
    expect(h.messages.some((value) => value.type === "READY")).toBe(false);
  } finally {
    await h.cleanup();
  }
});

test("original owner abort after ready verifies child exit and listener refusal", async () => {
  const h = startHarness();
  try {
    await h.begin();
    const ready = await h.message("READY");
    await send(h.child, { type: "abort" });
    const closed = await h.message("SUMMARY");
    await h.ended;
    expect(closed.summary).toMatchObject({
      closed: true,
      childExitVerified: true,
      ipcDisconnected: true,
      listenerClosureVerified: true,
    });
    await refused(ready.configuration.origin);
  } finally {
    await h.cleanup();
  }
});

test.each([
  "missing-profile",
  "partial-profile",
  "node-options",
  "unrelated-environment",
  "wrong-trust",
])("%s is rejected before spawning a child", async (mode) => {
  const h = startHarness(),
    env: any = environment();
  if (mode === "missing-profile") delete env.FNCP_FRESH_BOOTSTRAP_LOCAL_ONLY;
  if (mode === "partial-profile") delete env.DATABASE_URL;
  if (mode === "node-options") env.NODE_OPTIONS = "--no-warnings";
  if (mode === "unrelated-environment") env.UNRELATED_TEST_VALUE = "unreviewed";
  try {
    await h.begin({
      environment: env,
      ...(mode === "wrong-trust"
        ? { trust: { ...trust, issuer: "http://127.0.0.1:23456/" } }
        : {}),
    });
    expect((await h.message("FAILED")).spawns).toBe(0);
    await h.ended;
  } finally {
    await h.cleanup();
  }
});

test.each([
  "missing-entry",
  "bad-pin",
  "extra-ready",
  "wrong-origin",
  "bad-certificate",
  "wrong-message",
])("%s cannot be adopted as a ready child", async (mode) => {
  const h = startHarness(mode);
  try {
    await h.begin();
    expect((await h.message("FAILED")).spawns).toBe(1);
    await h.ended;
    expect(h.messages.some((value) => value.type === "READY")).toBe(false);
  } finally {
    await h.cleanup();
  }
});

test.each(["unexpected-exit", "duplicate"])(
  "%s after readiness closes instead of adopting or restarting",
  async (mode) => {
    const h = startHarness(mode);
    try {
      await h.begin();
      const ready = await h.message("READY");
      let summary: any;
      for (let i = 0; i < 100; i++) {
        const offset = h.messages.length;
        await send(h.child, { type: "summary" });
        summary = (await h.message("SUMMARY", offset)).summary;
        if (summary.childExitVerified) break;
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
      expect(summary).toMatchObject({
        closed: true,
        childExitVerified: true,
        ipcDisconnected: true,
        listenerClosureVerified: true,
        databaseOwnershipVerified: false,
        activationGranted: false,
      });
      if (mode === "unexpected-exit") expect(summary.exitCode).toBe(7);
      expect(
        h.messages.filter((value) => value.type === "SPAWNED")
      ).toHaveLength(1);
      await refused(ready.configuration.origin);
    } finally {
      await h.cleanup();
    }
  }
);
