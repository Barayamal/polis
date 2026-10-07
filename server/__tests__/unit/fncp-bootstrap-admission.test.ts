// Real loopback TLS + installed Express parsers/router; invented handlers only.
// No application import, database, dotenv, Docker, identity service or account.
import express from "express";
import { createServer, request, Server } from "node:https";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import {
  mkdtempSync,
  readFileSync,
  chmodSync,
  unlinkSync,
  rmdirSync,
  realpathSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { createFreshBootstrapAdmission } from "../../src/auth/fncp-bootstrap-admission";
import {
  createJsonBodyParser,
  createUrlencodedBodyParser,
  createResponseCompression,
} from "../../src/http-middleware";
import {
  isFncpLogBoundaryActive,
  isFncpSensitiveRequest,
} from "../../src/auth/fncp-log-boundary";

const seedText = readFileSync(
  join(__dirname, "../../../deploy/fncp/seed-statements.json"),
  "utf8"
);
const seeds = JSON.parse(seedText);
const issuer = "https://127.0.0.1:23456/";
const keys = generateKeyPairSync("rsa", { modulusLength: 2048 });
const kid = createHash("sha256")
  .update(keys.publicKey.export({ type: "spki", format: "der" }))
  .digest("hex");
const jwk = {
  ...keys.publicKey.export({ format: "jwk" }),
  kid,
  use: "sig",
  alg: "RS256",
};
let tls: { key: Buffer; cert: Buffer };
beforeAll(() => {
  const dir = mkdtempSync(join(realpathSync(tmpdir()), "fncp-admission-test-"));
  chmodSync(dir, 0o700);
  const key = join(dir, "key.pem"),
    cert = join(dir, "cert.pem");
  try {
    const result = spawnSync(
      "/opt/homebrew/bin/openssl",
      [
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:prime256v1",
        "-noenc",
        "-days",
        "1",
        "-subj",
        "/CN=synthetic.invalid",
        "-addext",
        "subjectAltName=IP:127.0.0.1",
        "-keyout",
        key,
        "-out",
        cert,
      ],
      {
        cwd: dir,
        shell: false,
        timeout: 10000,
        maxBuffer: 8192,
        stdio: ["ignore", "pipe", "pipe"],
        env: {
          PATH: "/opt/homebrew/bin:/usr/bin:/bin",
          LANG: "C",
          OPENSSL_CONF: "/dev/null",
        },
      }
    );
    expect(result.status).toBe(0);
    tls = { key: readFileSync(key), cert: readFileSync(cert) };
  } finally {
    for (const file of [key, cert]) {
      try {
        unlinkSync(file);
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
    }
    rmdirSync(dir);
  }
});
afterAll(() => tls.key.fill(0));
const makeToken = (
  changes = {},
  headerChanges = {},
  signingKey = keys.privateKey
) => {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: issuer,
    aud: "fncp-fresh-synthetic-bootstrap",
    sub: "fncp-invented-bootstrap-admin-" + "a".repeat(48),
    email: "bootstrap-admin@bootstrap.example.invalid",
    email_verified: false,
    name: "Invented local bootstrap administrator",
    iat: now,
    nbf: now,
    exp: now + 110,
    jti: "b".repeat(48),
    ...changes,
  };
  const encode = (value: unknown) =>
    Buffer.from(JSON.stringify(value)).toString("base64url");
  const input =
    encode({ alg: "RS256", typ: "JWT", kid, ...headerChanges }) +
    "." +
    encode(payload);
  return (
    input +
    "." +
    sign("RSA-SHA256", Buffer.from(input), signingKey).toString("base64url")
  );
};
const createBody = {
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
};
const cid = "3SyntheticBootstrap";
function step(index: number): { method: string; path: string; body: unknown } {
  if (!index)
    return { method: "POST", path: "/api/v3/conversations", body: createBody };
  if (index < 16)
    return {
      method: "POST",
      path: "/api/v3/comments",
      body: { conversation_id: cid, txt: seeds[index - 1], is_seed: true },
    };
  if (index === 16)
    return {
      method: "GET",
      path: `/api/v3/comments?conversation_id=${cid}&moderation=true&include_voting_patterns=true`,
      body: null,
    };
  if (index === 17)
    return {
      method: "PUT",
      path: "/api/v3/conversations",
      body: {
        conversation_id: cid,
        is_active: false,
        use_xid_whitelist: true,
        xid_required: true,
        send_created_email: false,
      },
    };
  return {
    method: "GET",
    path: `/api/v3/conversations?conversation_id=${cid}`,
    body: null,
  };
}
function result(index: number): any {
  if (!index) return { conversation_id: cid };
  if (index < 16) return { tid: index - 1, currentPid: 0 };
  if (index === 16)
    return seeds.map((txt: string, tid: number) => ({
      conversation_id: cid,
      tid,
      txt,
      pid: 0,
      mod: 1,
      active: true,
      is_seed: true,
      agree_count: 0,
      disagree_count: 0,
      pass_count: 1,
      count: 1,
    }));
  return {
    conversation_id: cid,
    is_owner: true,
    ...createBody,
    is_active: false,
    use_xid_whitelist: true,
    xid_required: true,
  };
}
async function fixture(
  handler?: (req: any, res: any, index: number) => void,
  compression = false
) {
  const boundary = createFreshBootstrapAdmission({
    issuer,
    publicJwk: jwk,
    seedStatementsJson: seedText,
  });
  const app = express();
  let calls = 0;
  app.use(boundary.middleware);
  app.use(createJsonBodyParser());
  app.use(createUrlencodedBodyParser());
  if (compression) app.use(createResponseCompression());
  app.use((_req, res, next) => {
    res.setHeader("connection", "keep-alive");
    next();
  });
  app.use((req, res) => {
    const index = calls++;
    expect(isFncpSensitiveRequest(req)).toBe(true);
    expect(isFncpLogBoundaryActive()).toBe(true);
    if (handler) return handler(req, res, index);
    expect(req.method).toBe(step(index).method);
    expect(req.originalUrl).toBe(step(index).path);
    if (step(index).body) expect(req.body).toEqual(step(index).body);
    res.json(result(index));
  });
  const server: Server = createServer(
    { ...tls, minVersion: "TLSv1.2", maxHeaderSize: 8192 },
    app
  );
  const sockets = new Set<any>();
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as any).port;
  const token = makeToken();
  async function send(index = 0, changes: any = {}) {
    const selected = { ...step(index), ...changes };
    const body =
      changes.rawBody !== undefined
        ? changes.rawBody
        : selected.body
        ? JSON.stringify(selected.body)
        : null;
    const headers: any = {
      accept: "application/json",
      "content-type": "application/json",
      "x-forwarded-proto": "https",
      host: `127.0.0.1:${port}`,
      connection: "close",
      authorization: "Bearer " + token,
    };
    if (body !== null)
      headers["content-length"] = String(Buffer.byteLength(body));
    Object.assign(headers, changes.headers);
    return new Promise<{ ok: boolean; body?: string }>((resolve) => {
      const req = request(
        {
          hostname: "127.0.0.1",
          port,
          path: selected.path,
          method: selected.method,
          headers,
          ca: tls.cert,
          servername: "",
          agent: false,
          timeout: 4000,
        },
        (res) => {
          const data: Buffer[] = [];
          res.on("data", (part) => data.push(part));
          res.on("end", () =>
            resolve({
              ok: res.statusCode === 200,
              body: Buffer.concat(data).toString(),
            })
          );
          res.on("error", () => resolve({ ok: false }));
        }
      );
      req.on("error", () => resolve({ ok: false }));
      req.on("timeout", () => {
        req.destroy();
        resolve({ ok: false });
      });
      if (body !== null) req.write(body);
      req.end();
    });
  }
  return {
    boundary,
    send,
    token,
    get calls() {
      return calls;
    },
    async close() {
      boundary.close();
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve()))
      );
    },
  };
}

test("all 19 canonical requests pass actual nested Express parsers, bind real fixture IDs, and then stop", async () => {
  const f = await fixture();
  try {
    for (let i = 0; i < 19; i++) expect((await f.send(i)).ok).toBe(true);
    // Client EOF and the local response finish acknowledgement are separate
    // observations; only the latter advances the boundary's completion state.
    await new Promise((resolve) => setImmediate(resolve));
    expect(f.calls).toBe(19);
    expect(f.boundary.summary().completedRequests).toBe(19);
    expect(f.boundary.summary().complete).toBe(true);
    expect((await f.send(18)).ok).toBe(false);
    expect(f.calls).toBe(19);
    expect(f.boundary.summary().applicationDrain).toBe("NOT_VERIFIED");
  } finally {
    await f.close();
  }
});

test.each([
  ["wrong audience", { aud: "participants" }],
  ["ordinary sub", { sub: "real-user" }],
  ["verified email", { email_verified: true }],
  ["wrong email", { email: "other@example.invalid" }],
  ["expired", { exp: 1 }],
  ["future", { iat: 2147483600, nbf: 2147483600, exp: 2147483640 }],
  ["long lifetime", { exp: Math.floor(Date.now() / 1000) + 300 }],
  ["extra claim", { role: "admin" }],
  ["wrong issuer", { iss: "https://127.0.0.1:23457/" }],
  ["invalid jti", { jti: "1" }],
])("%s token cannot enter the application", async (_name, changes) => {
  const f = await fixture();
  try {
    expect(
      (
        await f.send(0, {
          headers: { authorization: "Bearer " + makeToken(changes) },
        })
      ).ok
    ).toBe(false);
    expect(f.calls).toBe(0);
    expect((await f.send()).ok).toBe(false);
  } finally {
    await f.close();
  }
});
test.each(["wrong-key", "none-alg", "absent", "malformed", "extra-header"])(
  "reject %s token",
  async (mode) => {
    const f = await fixture();
    try {
      const wrong = generateKeyPairSync("rsa", { modulusLength: 2048 });
      const auth =
        mode === "wrong-key"
          ? makeToken({}, {}, wrong.privateKey)
          : mode === "none-alg"
          ? makeToken({}, { alg: "none" })
          : mode === "extra-header"
          ? makeToken({}, { jku: "https://example.invalid/" })
          : mode === "absent"
          ? ""
          : "a.b.c";
      expect(
        (await f.send(0, { headers: { authorization: "Bearer " + auth } })).ok
      ).toBe(false);
      expect(f.calls).toBe(0);
    } finally {
      await f.close();
    }
  }
);

test.each([
  { path: "/api/v3/conversations/" },
  { path: "/API/v3/conversations" },
  { path: "/api/v3/%63onversations" },
  { path: "https://example.invalid/api/v3/conversations" },
  { path: "/api/v3/conversations?is_active=false" },
  { path: "/api/v3/conversation/close" },
  { method: "HEAD" },
  { method: "OPTIONS" },
  { headers: { cookie: "synthetic=1" } },
  { headers: { origin: "https://example.invalid" } },
  { headers: { "x-forwarded-for": "127.0.0.1" } },
  { headers: { "accept-encoding": "gzip" } },
  { headers: { "content-type": "application/problem+json" } },
  { headers: { "x-forwarded-proto": "http" } },
  { headers: { accept: ["application/json", "application/json"] } },
  { headers: { host: "localhost" } },
  { headers: { "content-length": "0" } },
  { body: { ...createBody, is_active: false } },
  { rawBody: JSON.stringify(createBody) + " " },
  {
    rawBody: JSON.stringify(createBody).replace(
      '"is_active":true',
      '"is_active":true,"is_active":true'
    ),
  },
])(
  "noncanonical request %j never reaches handler or permits retry",
  async (changes) => {
    const f = await fixture();
    try {
      expect((await f.send(0, changes)).ok).toBe(false);
      expect(f.calls).toBe(0);
      expect((await f.send()).ok).toBe(false);
    } finally {
      await f.close();
    }
  }
);

test("second otherwise-valid invented token is rejected after first actor is bound", async () => {
  const f = await fixture();
  try {
    expect((await f.send()).ok).toBe(true);
    expect(
      (
        await f.send(1, {
          headers: {
            authorization: "Bearer " + makeToken({ jti: "c".repeat(48) }),
          },
        })
      ).ok
    ).toBe(false);
    expect(f.calls).toBe(1);
  } finally {
    await f.close();
  }
});
test.each(["nan", "backward"])(
  "reject %s wall clock without entering application",
  async (mode) => {
    const f = await fixture();
    const clock = jest
      .spyOn(Date, "now")
      .mockReturnValue(mode === "nan" ? NaN : 0);
    try {
      expect((await f.send()).ok).toBe(false);
      expect(f.calls).toBe(0);
    } finally {
      clock.mockRestore();
      await f.close();
    }
  }
);
test.each([
  "seed-id",
  "seed-text",
  "out-of-order",
  "replay-create",
  "get-query",
  "close-id",
])("bind sequence: %s", async (mode) => {
  const f = await fixture();
  try {
    const limit = mode === "get-query" ? 16 : mode === "close-id" ? 17 : 1;
    for (let i = 0; i < limit; i++) expect((await f.send(i)).ok).toBe(true);
    const value = step(limit);
    const changes =
      mode === "seed-id" || mode === "close-id"
        ? {
            body: {
              ...(value.body as any),
              conversation_id: "3OtherSynthetic",
            },
          }
        : mode === "seed-text"
        ? { body: { ...(value.body as any), txt: "other" } }
        : mode === "get-query"
        ? { path: value.path + "&conversation_id=" + cid }
        : {};
    expect(
      (
        await f.send(
          mode === "replay-create" ? 0 : mode === "out-of-order" ? 17 : limit,
          changes
        )
      ).ok
    ).toBe(false);
    expect(f.calls).toBe(limit);
  } finally {
    await f.close();
  }
});
test.each([
  "missing-id",
  "oversize-id",
  "reserved-id",
  "duplicate-json",
  "wrong-type",
  "redirect",
  "error-status",
  "cookie",
  "oversize",
  "early-headers",
])("invalid response %s prevents advance", async (mode) => {
  const f = await fixture((_req, res) => {
    if (mode === "early-headers") {
      res.writeHead(200);
      return res.end("{}");
    }
    if (mode === "redirect") return res.redirect("https://example.invalid");
    if (mode === "error-status") return res.status(500).json(result(0));
    if (mode === "wrong-type")
      return res.type("text/plain").send(JSON.stringify(result(0)));
    if (mode === "cookie") res.setHeader("set-cookie", "invented=1");
    if (mode === "duplicate-json")
      return res
        .type("json")
        .send('{"conversation_id":"3FirstID","conversation_id":"3SecondID"}');
    res.json(
      mode === "missing-id"
        ? {}
        : mode === "oversize-id"
        ? { conversation_id: "3".repeat(101) }
        : mode === "reserved-id"
        ? { conversation_id: "9fncpBootstrap" + "a".repeat(48) }
        : mode === "oversize"
        ? { ...result(0), padding: "x".repeat(65536) }
        : result(0)
    );
  });
  try {
    expect((await f.send()).ok).toBe(false);
    expect(f.boundary.summary().completedRequests).toBe(0);
    expect((await f.send(1)).ok).toBe(false);
    expect(f.calls).toBe(1);
  } finally {
    await f.close();
  }
});
test("concurrent request closes first pending handler and late response cannot restore admission", async () => {
  let held: any;
  const f = await fixture((_req, res) => {
    held = res;
  });
  try {
    const first = f.send();
    while (!held) await new Promise((resolve) => setImmediate(resolve));
    expect((await f.send()).ok).toBe(false);
    expect((await first).ok).toBe(false);
    held.json(result(0));
    expect(f.boundary.summary().completedRequests).toBe(0);
    expect(f.calls).toBe(1);
  } finally {
    await f.close();
  }
});
test.each([
  "foreign-row",
  "wrong-count",
  "wrong-pid",
  "repeated-tid",
  "wrong-seed-text",
  "open-readback",
])("reject mismatched downstream evidence: %s", async (mode) => {
  const f = await fixture((_req, res, index) => {
    const value = result(index);
    if (index === 16 && mode !== "open-readback") {
      if (mode === "foreign-row") value[0].conversation_id = "3OtherSynthetic";
      if (mode === "wrong-count") value[0].count = 2;
      if (mode === "wrong-pid") value[0].pid = 1;
      if (mode === "repeated-tid") value[0].tid = 1;
      if (mode === "wrong-seed-text") value[0].txt = "other";
    }
    if (index === 18 && mode === "open-readback") value.is_active = true;
    res.json(value);
  });
  try {
    const stop = mode === "open-readback" ? 18 : 16;
    for (let i = 0; i < stop; i++) expect((await f.send(i)).ok).toBe(true);
    expect((await f.send(stop)).ok).toBe(false);
    expect(f.boundary.summary().completedRequests).toBe(stop);
  } finally {
    await f.close();
  }
});
test("held handler hits two-second deadline; boundary close is not application rollback", async () => {
  const f = await fixture(() => {});
  try {
    expect((await f.send()).ok).toBe(false);
    expect(f.calls).toBe(1);
    expect(f.boundary.summary().denied).toBe(true);
  } finally {
    await f.close();
  }
});
test("legacy compression would send headers too early and is skipped only in actual fresh app source", async () => {
  const f = await fixture(undefined, true);
  try {
    expect((await f.send()).ok).toBe(false);
    expect(f.calls).toBe(1);
  } finally {
    await f.close();
  }
  const source = readFileSync(join(__dirname, "../../app.ts"), "utf8");
  expect(source).toContain(
    "if (!Config.freshBootstrapLocalOnly) app.use(createResponseCompression());"
  );
});
test.each([
  { issuer: "http://127.0.0.1:23456/" },
  { issuer: "https://example.invalid/" },
  { seedStatementsJson: "[]" },
  { publicJwk: { ...jwk, d: "private" } },
  { publicJwk: { ...jwk, kid: "a".repeat(64) } },
  { extra: true },
])("factory refuses mismatched public source/trust input %j", (changes) => {
  expect(() =>
    createFreshBootstrapAdmission({
      issuer,
      publicJwk: jwk,
      seedStatementsJson: seedText,
      ...changes,
    })
  ).toThrow("Fresh bootstrap admission denied");
});
