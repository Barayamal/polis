/** Owned host-loopback HTTPS listener. No I/O on import; not a Docker owner.
 * A trusted initializer is a test/composition seam, never a network-selected
 * module. The executable entrypoint always loads the fixed real application.
 * Listener closure is NOT application/DB shutdown: the dedicated child exits.
 */
import express, { RequestHandler } from "express";
import { createServer, Server } from "node:https";
import { connect } from "node:net";
import { Duplex } from "node:stream";
import { createHash, X509Certificate } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  closeSync,
  constants,
  fstatSync,
  mkdtempSync,
  openSync,
  readSync,
  realpathSync,
  rmdirSync,
  unlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isProxy, isPromise } from "node:util/types";
import { createFreshBootstrapAdmission } from "../auth/fncp-bootstrap-admission";

const failure = () => new Error("FNCP_FRESH_BOOTSTRAP_HTTPS_FAILED");
function fields(value: unknown, keys: string[]) {
  if (
    !value ||
    typeof value !== "object" ||
    isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  )
    throw failure();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    Reflect.ownKeys(descriptors).length !== keys.length ||
    keys.some(
      (key) => !descriptors[key] || !Object.hasOwn(descriptors[key], "value")
    )
  )
    throw failure();
  return Object.fromEntries(keys.map((key) => [key, descriptors[key].value]));
}
function readGenerated(path: string, limit: number) {
  const fd = openSync(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK
  );
  try {
    const before = fstatSync(fd);
    if (
      !before.isFile() ||
      before.nlink !== 1 ||
      before.size < 1 ||
      before.size > limit ||
      (before.mode & 0o777) !== 0o600
    )
      throw failure();
    const bytes = Buffer.alloc(limit + 1);
    let count = 0;
    while (count < bytes.length) {
      const n = readSync(fd, bytes, count, bytes.length - count, count);
      if (!n) break;
      count += n;
    }
    const after = fstatSync(fd);
    if (
      count !== before.size ||
      ["dev", "ino", "mode", "size", "mtimeMs", "ctimeMs"].some(
        (key) => before[key] !== after[key]
      )
    )
      throw failure();
    return Buffer.from(bytes.subarray(0, count));
  } finally {
    closeSync(fd);
  }
}
function generateTls() {
  const executable =
    process.platform === "darwin"
      ? "/opt/homebrew/bin/openssl"
      : process.platform === "linux"
      ? "/usr/bin/openssl"
      : undefined;
  if (!executable) throw failure();
  const directory = mkdtempSync(
    join(realpathSync(tmpdir()), "fncp-owned-api-tls-")
  );
  const keyPath = join(directory, "key.pem"),
    certPath = join(directory, "cert.pem");
  let key: Buffer;
  try {
    chmodSync(directory, 0o700);
    const result = spawnSync(
      executable,
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
        keyPath,
        "-out",
        certPath,
      ],
      {
        cwd: directory,
        shell: false,
        timeout: 5000,
        maxBuffer: 8192,
        stdio: ["ignore", "pipe", "pipe"],
        env: {
          PATH: "/usr/bin:/bin",
          LANG: "C",
          LC_ALL: "C",
          OPENSSL_CONF: "/dev/null",
        },
      }
    );
    if (result.error || result.status !== 0) throw failure();
    chmodSync(keyPath, 0o600);
    chmodSync(certPath, 0o600);
    key = readGenerated(keyPath, 4096);
    const cert = readGenerated(certPath, 8192);
    const certificate = new X509Certificate(cert);
    if (
      certificate.checkIP("127.0.0.1") !== "127.0.0.1" ||
      Date.parse(certificate.validFrom) > Date.now() ||
      Date.parse(certificate.validTo) <= Date.now()
    )
      throw failure();
    return {
      key,
      cert,
      certificateSha256: createHash("sha256")
        .update(certificate.raw)
        .digest("hex"),
    };
  } catch {
    key?.fill(0);
    throw failure();
  } finally {
    for (const path of [keyPath, certPath]) {
      try {
        unlinkSync(path);
      } catch (error) {
        if (error.code !== "ENOENT") throw failure();
      }
    }
    rmdirSync(directory);
  }
}
async function bounded<T>(
  promise: PromiseLike<T>,
  milliseconds: number
): Promise<T> {
  let timer: NodeJS.Timeout;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(failure()), milliseconds);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}
async function verifyRefused(port: number) {
  await new Promise<void>((resolve, reject) => {
    const socket = connect({ host: "127.0.0.1", port });
    socket.setTimeout(500);
    socket.once("connect", () => {
      socket.destroy();
      reject(failure());
    });
    socket.once("timeout", () => {
      socket.destroy();
      reject(failure());
    });
    socket.once("error", (error: NodeJS.ErrnoException) => {
      socket.destroy();
      error.code === "ECONNREFUSED" ? resolve() : reject(failure());
    });
  });
}

export async function createBootstrapHttpsRuntime(options: {
  trust: {
    issuer: string;
    publicJwk: Record<string, unknown>;
    seedStatementsJson: string;
  };
  initialize: () => Promise<{ handler: RequestHandler; ready: Promise<void> }>;
  signal: AbortSignal;
}) {
  let admission: ReturnType<typeof createFreshBootstrapAdmission>,
    credentials: ReturnType<typeof generateTls>,
    server: Server;
  let port: number,
    closed = false,
    closedVerified = false,
    closePromise: Promise<void>;
  let startupAttempted = false,
    applicationReady = false;
  const sockets = new Set<Duplex>(),
    timers = new Map<Duplex, NodeJS.Timeout>();
  let cancelStartup: (error: Error) => void;
  const cancelled = new Promise<never>((_resolve, reject) => {
    cancelStartup = reject;
  });
  void cancelled.catch(() => {});
  let listenOutcome: Promise<void>;
  const listenerAbort = new AbortController();
  const onAbort = () => {
    void close().catch(() => {});
  };
  const signalGet = Object.getOwnPropertyDescriptor(
    AbortSignal.prototype,
    "aborted"
  ).get;
  const signalAdd = EventTarget.prototype.addEventListener,
    signalRemove = EventTarget.prototype.removeEventListener;
  let signal: AbortSignal;
  const active = () => {
    if (closed || signalGet.call(signal)) throw failure();
  };
  function close(): Promise<void> {
    if (closePromise) return closePromise;
    closed = true;
    admission?.close();
    cancelStartup(failure());
    listenerAbort.abort();
    if (signal) signalRemove.call(signal, "abort", onAbort);
    closePromise = bounded(
      (async () => {
        if (listenOutcome) await listenOutcome.catch(() => {});
        const closing = server?.listening
          ? new Promise<void>((resolve, reject) =>
              server.close((error) => (error ? reject(failure()) : resolve()))
            )
          : Promise.resolve();
        for (const socket of sockets) socket.destroy();
        for (const timer of timers.values()) clearTimeout(timer);
        timers.clear();
        await closing;
        if (port !== undefined) await verifyRefused(port);
        closedVerified = true;
      })(),
      2000
    )
      .catch(() => {
        throw failure();
      })
      .finally(() => credentials?.key.fill(0));
    return closePromise;
  }
  try {
    if (arguments.length !== 1) throw failure();
    const input = fields(options, ["trust", "initialize", "signal"]);
    if (typeof input.initialize !== "function" || isProxy(input.initialize))
      throw failure();
    if (
      !input.signal ||
      typeof input.signal !== "object" ||
      isProxy(input.signal)
    )
      throw failure();
    signalGet.call(input.signal);
    signal = input.signal;
    active();
    admission = createFreshBootstrapAdmission(input.trust);
    signalAdd.call(signal, "abort", onAbort, { once: true });
    active();
    credentials = generateTls();
    active();
    startupAttempted = true;
    const application = fields(
      await bounded(
        Promise.race([
          Promise.resolve().then(() => {
            active();
            return input.initialize();
          }),
          cancelled,
        ]),
        5000
      ),
      ["handler", "ready"]
    );
    if (
      typeof application.handler !== "function" ||
      isProxy(application.handler) ||
      !isPromise(application.ready)
    )
      throw failure();
    active();
    await bounded(
      Promise.race([Promise.resolve(application.ready), cancelled]),
      5000
    );
    active();
    applicationReady = true;
    const app = express();
    app.disable("x-powered-by");
    app.disable("etag");
    app.use(admission.middleware);
    app.use(application.handler);
    server = createServer(
      {
        key: credentials.key,
        cert: credentials.cert,
        minVersion: "TLSv1.2",
        maxHeaderSize: 8192,
        handshakeTimeout: 1000,
      },
      (req, res) => {
        try {
          active();
        } catch {
          req.destroy();
          return;
        }
        req.on("error", onAbort);
        res.on("error", onAbort);
        res.once("close", () => {
          if (admission.summary().denied) onAbort();
        });
        app(req, res);
      }
    );
    server.requestTimeout = 2000;
    server.headersTimeout = 1000;
    server.keepAliveTimeout = 1;
    server.maxConnections = 8;
    server.maxRequestsPerSocket = 1;
    server.on("connection", (socket) => {
      sockets.add(socket);
      timers.set(
        socket,
        setTimeout(() => {
          socket.destroy();
          onAbort();
        }, 3000)
      );
      socket.once("close", () => {
        sockets.delete(socket);
        clearTimeout(timers.get(socket));
        timers.delete(socket);
      });
      if (closed) socket.destroy();
    });
    for (const event of [
      "upgrade",
      "connect",
      "clientError",
      "tlsClientError",
    ] as const)
      server.on(event, onAbort);
    for (const event of ["checkContinue", "checkExpectation"] as const)
      server.on(event, (req, res) => {
        req.destroy();
        res.destroy();
        onAbort();
      });
    server.on("error", onAbort);
    listenOutcome = bounded(
      new Promise<void>((resolve, reject) => {
        const error = () => reject(failure());
        server.once("error", error);
        server.listen(
          { port: 0, host: "127.0.0.1", signal: listenerAbort.signal },
          () => {
            server.removeListener("error", error);
            const address = server.address();
            if (!address || typeof address === "string")
              return reject(failure());
            port = address.port;
            resolve();
          }
        );
      }),
      2000
    );
    await Promise.race([listenOutcome, cancelled]);
    active();
    return Object.freeze({
      configuration() {
        active();
        return Object.freeze({
          origin: `https://127.0.0.1:${port}`,
          certificatePem: credentials.cert.toString("utf8"),
          certificateSha256: credentials.certificateSha256,
        });
      },
      close,
      summary() {
        return Object.freeze({
          classification: "OWNED_LOOPBACK_HTTPS_LISTENER",
          startupAttempted,
          applicationReady,
          closed,
          listenerClosureVerified: closedVerified,
          applicationProcessExitVerified: false,
          databaseShutdownVerified: false,
          containerOwnershipVerified: false,
          completedRequests: admission.summary().completedRequests,
          activationGranted: false,
        });
      },
    });
  } catch {
    await close().catch(() => {});
    throw failure();
  }
}
