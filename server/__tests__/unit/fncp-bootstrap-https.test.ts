// Actual fresh loopback TLS and Express parsers; no app, database, Config,
// retained environment, key files or runtime image is loaded by this test.
import express from "express";
import {
  createHash,
  generateKeyPairSync,
  sign,
  X509Certificate,
} from "node:crypto";
import { readFileSync } from "node:fs";
import fs from "node:fs";
import { request } from "node:https";
import * as net from "node:net";
import { basename, dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { connect as connectTls } from "node:tls";
import { createBootstrapHttpsRuntime } from "../../src/bootstrap/https-runtime";

const seedStatementsJson = readFileSync(
  join(__dirname, "../../../deploy/fncp/seed-statements.json"),
  "utf8"
);
const issuer = "https://127.0.0.1:23456/";
const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
const kid = createHash("sha256")
  .update(pair.publicKey.export({ type: "spki", format: "der" }))
  .digest("hex");
const publicJwk = {
  ...pair.publicKey.export({ format: "jwk" }),
  kid,
  use: "sig",
  alg: "RS256",
};
const trust = { issuer, publicJwk, seedStatementsJson };
const errorCode = "FNCP_FRESH_BOOTSTRAP_HTTPS_FAILED";
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
type Runtime = Awaited<ReturnType<typeof createBootstrapHttpsRuntime>>;
const owned = new Set<Runtime>();
const turn = () => new Promise<void>((resolve) => setImmediate(resolve));
function deferred<T>() {
  let resolve: (value: T) => void;
  let reject: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
function token() {
  const now = Math.floor(Date.now() / 1000);
  const encode = (value: unknown) =>
    Buffer.from(JSON.stringify(value)).toString("base64url");
  const body = {
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
  };
  const bytes = encode({ alg: "RS256", typ: "JWT", kid }) + "." + encode(body);
  return (
    bytes +
    "." +
    sign("RSA-SHA256", Buffer.from(bytes), pair.privateKey).toString(
      "base64url"
    )
  );
}
async function fixture(options: { status?: number; body?: unknown } = {}) {
  const signalOwner = new AbortController();
  const handler = jest.fn((req, res) => {
    expect(req.body).toEqual(createBody);
    res
      .status(options.status || 200)
      .json(options.body || { conversation_id: "3SyntheticBootstrap" });
  });
  const app = express();
  app.use(express.json());
  app.use(handler);
  const initialize = jest.fn(async () => ({
    handler: app,
    ready: Promise.resolve(),
  }));
  const runtime = await createBootstrapHttpsRuntime({
    trust,
    initialize,
    signal: signalOwner.signal,
  });
  owned.add(runtime);
  return {
    runtime,
    signalOwner,
    initialize,
    handler,
    config: runtime.configuration(),
  };
}
async function refused(origin: string) {
  const port = Number(new URL(origin).port);
  await new Promise<void>((resolve, reject) => {
    const socket = net.connect({ host: "127.0.0.1", port });
    socket.setTimeout(750);
    socket.once("connect", () => {
      socket.destroy();
      reject(new Error("owned test port is still open"));
    });
    socket.once("timeout", () => {
      socket.destroy();
      reject(new Error("owned test refusal deadline"));
    });
    socket.once("error", (error) => {
      socket.destroy();
      error.code === "ECONNREFUSED"
        ? resolve()
        : reject(new Error("owned test refusal not verified"));
    });
  });
}
async function closed(runtime: Runtime, origin: string) {
  for (let i = 0; i < 100 && !runtime.summary().closed; i++)
    await new Promise((resolve) => setTimeout(resolve, 10));
  expect(runtime.summary().closed).toBe(true);
  await runtime.close();
  expect(runtime.summary().listenerClosureVerified).toBe(true);
  await refused(origin);
}
async function send(
  config: ReturnType<Runtime["configuration"]>,
  path = "/api/v3/conversations"
) {
  const target = new URL(config.origin),
    body = JSON.stringify(createBody);
  return new Promise<{ status?: number; body: string }>((resolve) => {
    let done = false;
    const finish = (value: { status?: number; body: string }) => {
      if (!done) {
        done = true;
        resolve(value);
      }
    };
    const req = request(
      {
        hostname: "127.0.0.1",
        port: Number(target.port),
        path,
        method: "POST",
        ca: config.certificatePem,
        rejectUnauthorized: true,
        minVersion: "TLSv1.2",
        agent: false,
        headers: {
          accept: "application/json",
          "content-type": "application/json",
          "content-length": Buffer.byteLength(body),
          "x-forwarded-proto": "https",
          host: target.host,
          connection: "close",
          authorization: "Bearer " + token(),
        },
      },
      (res) => {
        let received = "";
        res.on("data", (data) => {
          received += data.toString();
          if (received.length > 2048) res.destroy();
        });
        res.on("end", () => finish({ status: res.statusCode, body: received }));
        res.on("error", () => finish({ body: "" }));
      }
    );
    req.on("error", () => finish({ body: "" }));
    req.setTimeout(1500, () => {
      req.destroy();
      finish({ body: "" });
    });
    req.end(body);
  });
}
async function raw(
  config: ReturnType<Runtime["configuration"]>,
  bytes: string,
  plaintext = false
) {
  const port = Number(new URL(config.origin).port);
  await new Promise<void>((resolve, reject) => {
    const socket = plaintext
      ? net.connect({ host: "127.0.0.1", port })
      : connectTls({
          host: "127.0.0.1",
          port,
          ca: config.certificatePem,
          rejectUnauthorized: true,
          minVersion: "TLSv1.2",
        });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("owned malformed request was not closed"));
    }, 3500);
    socket.once(plaintext ? "connect" : "secureConnect", () =>
      socket.write(bytes)
    );
    socket.on("data", () => {});
    socket.on("error", () => {});
    socket.once("close", () => {
      clearTimeout(timer);
      resolve();
    });
  });
}
afterEach(async () => {
  for (const runtime of owned) await runtime.close();
  owned.clear();
  jest.restoreAllMocks();
});

test("generated TLS cleanup failure denies startup before application initialization", async () => {
  const remove = fs.unlinkSync;
  let directory: string;
  const unlink = jest.spyOn(fs, "unlinkSync").mockImplementationOnce(path => {
    directory = dirname(String(path));
    remove(path);
    throw Object.assign(new Error("invented cleanup diagnostic"), { code: "EACCES" });
  });
  const initialize = jest.fn();
  try {
    await expect(createBootstrapHttpsRuntime({ trust, signal: new AbortController().signal, initialize }))
      .rejects.toThrow(errorCode);
    expect(initialize).not.toHaveBeenCalled();
  } finally {
    unlink.mockRestore();
    if (directory) {
      expect(dirname(directory)).toBe(fs.realpathSync(tmpdir()));
      expect(basename(directory).startsWith("fncp-owned-api-tls-")).toBe(true);
      fs.rmSync(directory, { recursive: true, force: false });
    }
  }
});

test("fresh kernel serves canonical create only after readiness, then closes its exact listener", async () => {
  const f = await fixture();
  expect(f.initialize).toHaveBeenCalledTimes(1);
  expect(Object.isFrozen(f.runtime)).toBe(true);
  expect(new URL(f.config.origin).hostname).toBe("127.0.0.1");
  const cert = new X509Certificate(f.config.certificatePem);
  expect(cert.checkIP("127.0.0.1")).toBe("127.0.0.1");
  expect(createHash("sha256").update(cert.raw).digest("hex")).toBe(
    f.config.certificateSha256
  );
  expect(Object.keys(f.config).sort()).toEqual([
    "certificatePem",
    "certificateSha256",
    "origin",
  ]);
  expect(await send(f.config)).toEqual({
    status: 200,
    body: '{"conversation_id":"3SyntheticBootstrap"}',
  });
  await turn();
  expect(f.handler).toHaveBeenCalledTimes(1);
  expect(f.runtime.summary()).toMatchObject({
    applicationReady: true,
    completedRequests: 1,
    activationGranted: false,
    containerOwnershipVerified: false,
    databaseShutdownVerified: false,
    applicationProcessExitVerified: false,
  });
  await f.runtime.close();
  await f.runtime.close();
  expect(() => f.runtime.configuration()).toThrow(errorCode);
  await closed(f.runtime, f.config.origin);
});

test.each([
  [
    "missing trust",
    (init: unknown, signal: AbortSignal) => ({ initialize: init, signal }),
  ],
  [
    "extra key",
    (init: unknown, signal: AbortSignal) => ({
      trust,
      initialize: init,
      signal,
      extra: true,
    }),
  ],
  ["array", () => []],
  [
    "prototype",
    (init: unknown, signal: AbortSignal) =>
      Object.assign(Object.create({ extra: true }), {
        trust,
        initialize: init,
        signal,
      }),
  ],
  ["fake signal", (init: unknown) => ({ trust, initialize: init, signal: {} })],
  [
    "inherited fake signal",
    (init: unknown) => ({
      trust,
      initialize: init,
      signal: Object.create(AbortSignal.prototype),
    }),
  ],
  [
    "proxy signal",
    (init: unknown, signal: AbortSignal) => ({
      trust,
      initialize: init,
      signal: new Proxy(signal, {}),
    }),
  ],
  [
    "invalid public trust",
    (init: unknown, signal: AbortSignal) => ({
      trust: { ...trust, issuer: "http://127.0.0.1:23456/" },
      initialize: init,
      signal,
    }),
  ],
  [
    "proxy initializer",
    (init: any, signal: AbortSignal) => ({
      trust,
      initialize: new Proxy(init, {}),
      signal,
    }),
  ],
] as const)(
  "rejects %s before initializer or listening",
  async (_name, shape) => {
    const initialize = jest.fn(async () => {
      throw new Error("must not initialize");
    });
    const listen = jest.spyOn(net.Server.prototype, "listen");
    await expect(
      createBootstrapHttpsRuntime(
        shape(initialize, new AbortController().signal) as any
      )
    ).rejects.toThrow(errorCode);
    expect(initialize).not.toHaveBeenCalled();
    expect(listen).not.toHaveBeenCalled();
  }
);

test("input accessors and extra arguments cannot invoke initializer", async () => {
  const initialize = jest.fn(),
    getter = jest.fn();
  const object = { initialize, signal: new AbortController().signal };
  Object.defineProperty(object, "trust", { get: getter, enumerable: true });
  await expect(createBootstrapHttpsRuntime(object as any)).rejects.toThrow(
    errorCode
  );
  await expect(
    (createBootstrapHttpsRuntime as any)(
      { trust, initialize, signal: new AbortController().signal },
      true
    )
  ).rejects.toThrow(errorCode);
  expect(getter).not.toHaveBeenCalled();
  expect(initialize).not.toHaveBeenCalled();
});

test("synchronous abort before the queued initializer prevents any application import", async () => {
  const owner = new AbortController();
  const initialize = jest.fn(async () => ({
    handler: express(),
    ready: Promise.resolve(),
  }));
  const pending = createBootstrapHttpsRuntime({
    trust,
    initialize,
    signal: owner.signal,
  });
  owner.abort();
  await expect(pending).rejects.toThrow(errorCode);
  await turn();
  expect(initialize).not.toHaveBeenCalled();
});

test("already aborted original signal performs no initialization or listen", async () => {
  const owner = new AbortController();
  owner.abort();
  const initialize = jest.fn(),
    listen = jest.spyOn(net.Server.prototype, "listen");
  await expect(
    createBootstrapHttpsRuntime({ trust, initialize, signal: owner.signal })
  ).rejects.toThrow(errorCode);
  expect(initialize).not.toHaveBeenCalled();
  expect(listen).not.toHaveBeenCalled();
});

test.each(["initializer", "readiness"])(
  "abort during held %s rejects promptly and cannot activate after late completion",
  async (stage) => {
    const owner = new AbortController(),
      held = deferred<any>(),
      entered = deferred<void>();
    const app = express(),
      listen = jest.spyOn(net.Server.prototype, "listen");
    const initialize = jest.fn(async () => {
      entered.resolve();
      return stage === "initializer"
        ? held.promise
        : { handler: app, ready: held.promise };
    });
    const pending = createBootstrapHttpsRuntime({
      trust,
      initialize,
      signal: owner.signal,
    });
    const rejection = expect(pending).rejects.toThrow(errorCode);
    await entered.promise;
    await turn();
    owner.abort();
    await rejection;
    held.resolve(
      stage === "initializer"
        ? { handler: app, ready: Promise.resolve() }
        : undefined
    );
    await turn();
    await turn();
    expect(initialize).toHaveBeenCalledTimes(1);
    expect(listen).not.toHaveBeenCalled();
  }
);

test("held readiness cannot open a listener until the original readiness promise resolves", async () => {
  const ready = deferred<void>(),
    entered = deferred<void>();
  const listen = jest.spyOn(net.Server.prototype, "listen"),
    owner = new AbortController();
  const pending = createBootstrapHttpsRuntime({
    trust,
    signal: owner.signal,
    initialize: async () => {
      entered.resolve();
      return { handler: express(), ready: ready.promise };
    },
  });
  await entered.promise;
  await turn();
  expect(listen).not.toHaveBeenCalled();
  ready.resolve();
  const runtime = await pending;
  owned.add(runtime);
  expect(runtime.summary().applicationReady).toBe(true);
  await runtime.close();
});

test.each(["initializer", "readiness"])(
  "rejected %s is sanitized and opens no listener",
  async (stage) => {
    const listen = jest.spyOn(net.Server.prototype, "listen");
    await expect(
      createBootstrapHttpsRuntime({
        trust,
        signal: new AbortController().signal,
        initialize: async () => {
          if (stage === "initializer")
            throw new Error("private fixture detail");
          return {
            handler: express(),
            ready: Promise.reject(new Error("private fixture detail")),
          };
        },
      })
    ).rejects.toThrow(errorCode);
    expect(listen).not.toHaveBeenCalled();
  }
);

test.each([undefined, null, true, 42, {}, { then: () => undefined }])(
  "non-Promise readiness %j never grants application readiness",
  async (ready) => {
    const listen = jest.spyOn(net.Server.prototype, "listen");
    await expect(
      createBootstrapHttpsRuntime({
        trust,
        signal: new AbortController().signal,
        initialize: async () => ({ handler: express(), ready } as any),
      })
    ).rejects.toThrow(errorCode);
    expect(listen).not.toHaveBeenCalled();
  }
);

test("a readiness accessor is not evaluated while checking initializer result", async () => {
  const getter = jest.fn(),
    result = { handler: express() };
  Object.defineProperty(result, "ready", { get: getter, enumerable: true });
  await expect(
    createBootstrapHttpsRuntime({
      trust,
      signal: new AbortController().signal,
      initialize: async () => result as any,
    })
  ).rejects.toThrow(errorCode);
  expect(getter).not.toHaveBeenCalled();
});

test.each([
  null,
  { handler: true, ready: Promise.resolve() },
  { handler: express(), ready: Promise.resolve(), extra: true },
])("invalid initializer result shape opens no listener: %j", async (result) => {
  const listen = jest.spyOn(net.Server.prototype, "listen");
  await expect(
    createBootstrapHttpsRuntime({
      trust,
      signal: new AbortController().signal,
      initialize: async () => result as any,
    })
  ).rejects.toThrow(errorCode);
  expect(listen).not.toHaveBeenCalled();
});

test("never-settling readiness hits the bounded startup deadline without listening", async () => {
  const listen = jest.spyOn(net.Server.prototype, "listen");
  await expect(
    createBootstrapHttpsRuntime({
      trust,
      signal: new AbortController().signal,
      initialize: async () => ({
        handler: express(),
        ready: new Promise<void>(() => {}),
      }),
    })
  ).rejects.toThrow(errorCode);
  expect(listen).not.toHaveBeenCalled();
}, 8000);

test("abort after ready closes the listener and denies configuration access", async () => {
  const f = await fixture();
  f.signalOwner.abort();
  await closed(f.runtime, f.config.origin);
  expect(f.handler).not.toHaveBeenCalled();
  expect(() => f.runtime.configuration()).toThrow(errorCode);
});

test.each([
  ["plaintext HTTP", "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", true],
  ["invalid HTTP method", "@ / HTTP/1.1\r\nHost: localhost\r\n\r\n", false],
  [
    "CONNECT",
    "CONNECT localhost:8443 HTTP/1.1\r\nHost: localhost\r\n\r\n",
    false,
  ],
  [
    "upgrade",
    "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
    false,
  ],
  [
    "100-continue",
    "POST /api/v3/conversations HTTP/1.1\r\nHost: localhost\r\nExpect: 100-continue\r\nContent-Length: 1\r\n\r\n",
    false,
  ],
  [
    "unsupported expectation",
    "POST /api/v3/conversations HTTP/1.1\r\nHost: localhost\r\nExpect: unrelated\r\nContent-Length: 1\r\n\r\n",
    false,
  ],
] as const)(
  "%s closes the kernel without reaching an application handler",
  async (_name, bytes, plaintext) => {
    const f = await fixture();
    await raw(f.config, bytes, plaintext);
    await closed(f.runtime, f.config.origin);
    expect(f.handler).not.toHaveBeenCalled();
  }
);

test.each([
  "/",
  "/api/v3/conversations/",
  "/api/v3/conversations?unexpected=true",
])(
  "malformed route %s cannot reach the handler and closes the listener",
  async (path) => {
    const f = await fixture();
    expect((await send(f.config, path)).status).not.toBe(200);
    await closed(f.runtime, f.config.origin);
    expect(f.handler).not.toHaveBeenCalled();
  }
);

test.each([{ status: 500 }, { body: { unexpected: true } }])(
  "invalid handler response cannot leave a reusable listener: %j",
  async (options) => {
    const f = await fixture(options);
    expect((await send(f.config)).status).not.toBe(200);
    await closed(f.runtime, f.config.origin);
    expect(f.handler).toHaveBeenCalledTimes(1);
    expect(f.runtime.summary().completedRequests).toBe(0);
  }
);

test("explicit close also destroys a held TLS connection and independently refuses its exact port", async () => {
  const f = await fixture(),
    target = new URL(f.config.origin);
  const socket = connectTls({
    host: "127.0.0.1",
    port: Number(target.port),
    ca: f.config.certificatePem,
    rejectUnauthorized: true,
  });
  const socketClosed = new Promise<void>((resolve) =>
    socket.once("close", () => resolve())
  );
  socket.on("error", () => {});
  try {
    await new Promise<void>((resolve, reject) => {
      socket.once("secureConnect", resolve);
      socket.once("error", reject);
    });
    await f.runtime.close();
    await socketClosed;
    await refused(f.config.origin);
    expect(f.runtime.summary().listenerClosureVerified).toBe(true);
  } finally {
    socket.destroy();
  }
});
