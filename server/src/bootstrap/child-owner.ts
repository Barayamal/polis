/** Concrete owner of one fixed bootstrap Node child, not its database/container.
 * No I/O on import. The caller must attest fresh resources before invoking this
 * factory, and pass the ORIGINAL issuer signal. Shape checks are not ownership.
 * No environment inheritance, arbitrary executable, app path or trust fallback.
 */
import { fork, ChildProcess } from "node:child_process";
import { join } from "node:path";
import { connect as connectTcp } from "node:net";
import {
  connect as connectTls,
  checkServerIdentity,
  TLSSocket,
} from "node:tls";
import { createHash, X509Certificate } from "node:crypto";
import { isProxy } from "node:util/types";
import { createFreshBootstrapAdmission } from "../auth/fncp-bootstrap-admission";
import { copyFreshBootstrapChildEnvironment } from "./child-profile";

const failure = () => new Error("FNCP_FRESH_BOOTSTRAP_CHILD_OWNER_FAILED");
const sha = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");
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
async function bounded<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(failure()), ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}
type Configuration = Readonly<{
  origin: string;
  certificatePem: string;
  certificateSha256: string;
}>;
function configurationFrom(message: unknown): Configuration {
  const value = fields(message, [
    "type",
    "origin",
    "certificatePem",
    "certificateSha256",
  ]);
  if (
    value.type !== "HOST_HTTPS_APP_ROUTES_READY" ||
    typeof value.origin !== "string" ||
    !/^https:\/\/127\.0\.0\.1:[1-9][0-9]{3,4}$/u.test(value.origin) ||
    typeof value.certificatePem !== "string" ||
    Buffer.byteLength(value.certificatePem) > 8192 ||
    !/^-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+\n-----END CERTIFICATE-----\n?$/u.test(
      value.certificatePem
    ) ||
    typeof value.certificateSha256 !== "string" ||
    !/^[a-f0-9]{64}$/u.test(value.certificateSha256)
  )
    throw failure();
  const url = new URL(value.origin),
    cert = new X509Certificate(value.certificatePem);
  if (
    url.origin !== value.origin ||
    Number(url.port) < 1024 ||
    Number(url.port) > 65535 ||
    cert.checkIP("127.0.0.1") !== "127.0.0.1" ||
    sha(cert.raw) !== value.certificateSha256 ||
    !Number.isFinite(Date.parse(cert.validFrom)) ||
    !Number.isFinite(Date.parse(cert.validTo)) ||
    Date.parse(cert.validFrom) > Date.now() ||
    Date.parse(cert.validTo) <= Date.now() ||
    !cert.verify(cert.publicKey)
  )
    throw failure();
  return Object.freeze({
    origin: value.origin,
    certificatePem: value.certificatePem,
    certificateSha256: value.certificateSha256,
  });
}
async function verifyRefused(origin: string) {
  await new Promise<void>((resolve, reject) => {
    const socket = connectTcp({
      host: "127.0.0.1",
      port: Number(new URL(origin).port),
    });
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

export async function createBootstrapChildOwner(options: {
  environment: Readonly<Record<string, string>>;
  trust: {
    issuer: string;
    publicJwk: Record<string, unknown>;
    seedStatementsJson: string;
  };
  signal: AbortSignal;
}) {
  let child: ChildProcess, original: AbortSignal, configuration: Configuration;
  let closed = false,
    failed = false,
    ready = false,
    spawnAttempted = false,
    spawnFailed = false;
  let childExitVerified = false,
    ipcDisconnected = false,
    listenerClosureVerified = false;
  let exitCode: number | null = null,
    signalCode: NodeJS.Signals | null = null;
  let closePromise: Promise<void>,
    rejectReady: (error: Error) => void,
    resolveReady: (value: Configuration) => void;
  let resolveExited: () => void, resolveDisconnected: () => void;
  let maximumLifetime: NodeJS.Timeout,
    advertised = false,
    stopAcknowledged = false;
  const probes = new Set<TLSSocket>();
  const signalGet = Object.getOwnPropertyDescriptor(
    AbortSignal.prototype,
    "aborted"
  ).get;
  const signalAdd = EventTarget.prototype.addEventListener,
    signalRemove = EventTarget.prototype.removeEventListener;
  const readyPromise = new Promise<Configuration>((resolve, reject) => {
    resolveReady = resolve;
    rejectReady = reject;
  });
  void readyPromise.catch(() => {});
  const exited = new Promise<void>((resolve) => {
    resolveExited = resolve;
  });
  const disconnected = new Promise<void>((resolve) => {
    resolveDisconnected = resolve;
  });
  const active = () => {
    if (closed || failed || signalGet.call(original)) throw failure();
  };
  const failClosed = () => {
    failed = true;
    rejectReady(failure());
    void close().catch(() => {});
  };
  function sendStop() {
    if (!child?.connected) return;
    try {
      child.send({ type: "stop" }, (error) => {
        if (error) failed = true;
      });
    } catch {
      failed = true;
    }
  }
  function close(): Promise<void> {
    if (closePromise) return closePromise;
    closed = true;
    rejectReady(failure());
    clearTimeout(maximumLifetime);
    if (original) signalRemove.call(original, "abort", failClosed);
    for (const socket of probes) socket.destroy();
    probes.clear();
    closePromise = Promise.resolve()
      .then(async () => {
        if (!child) return;
        sendStop();
        const stopped = Promise.all([exited, disconnected]).then(() => {});
        try {
          await bounded(stopped, 2500);
        } catch {
          failed = true;
          if (
            !childExitVerified &&
            !spawnFailed &&
            child.pid &&
            child.exitCode === null &&
            child.signalCode === null
          )
            child.kill("SIGTERM");
          try {
            await bounded(stopped, 500);
          } catch {
            if (
              !childExitVerified &&
              !spawnFailed &&
              child.pid &&
              child.exitCode === null &&
              child.signalCode === null
            )
              child.kill("SIGKILL");
            await bounded(stopped, 500);
          }
        }
        if (!spawnFailed && (!childExitVerified || !ipcDisconnected))
          throw failure();
        if (configuration) {
          await verifyRefused(configuration.origin);
          listenerClosureVerified = true;
        }
      })
      .catch(() => {
        failed = true;
        throw failure();
      });
    return closePromise;
  }
  async function probe(config: Configuration) {
    await bounded(
      new Promise<void>((resolve, reject) => {
        const port = Number(new URL(config.origin).port);
        const socket = connectTls({
          host: "127.0.0.1",
          port,
          ca: config.certificatePem,
          rejectUnauthorized: true,
          minVersion: "TLSv1.2",
          checkServerIdentity: (_hostname, cert) =>
            checkServerIdentity("127.0.0.1", cert),
        });
        probes.add(socket);
        let verified = false;
        socket.once("secureConnect", () => {
          try {
            active();
            const cert = socket.getPeerCertificate();
            if (
              !socket.authorized ||
              !cert.raw ||
              sha(cert.raw) !== config.certificateSha256 ||
              socket.remoteAddress !== "127.0.0.1" ||
              socket.localAddress !== "127.0.0.1" ||
              socket.remotePort !== port
            )
              throw failure();
            verified = true;
            socket.end();
          } catch {
            socket.destroy();
            reject(failure());
          }
        });
        socket.once("error", () => {
          socket.destroy();
          reject(failure());
        });
        socket.once("close", () => {
          probes.delete(socket);
          verified ? resolve() : reject(failure());
        });
        socket.setTimeout(1000, () => {
          socket.destroy();
          reject(failure());
        });
      }),
      1500
    );
  }
  try {
    if (arguments.length !== 1) throw failure();
    const input = fields(options, ["environment", "trust", "signal"]);
    const environment = copyFreshBootstrapChildEnvironment(input.environment);
    const trust = fields(input.trust, [
      "issuer",
      "publicJwk",
      "seedStatementsJson",
    ]);
    trust.publicJwk = fields(trust.publicJwk, [
      "kty",
      "n",
      "e",
      "kid",
      "alg",
      "use",
    ]);
    const validator = createFreshBootstrapAdmission(trust as any);
    validator.close();
    if (
      trust.issuer !== environment.AUTH_ISSUER ||
      !input.signal ||
      typeof input.signal !== "object" ||
      isProxy(input.signal)
    )
      throw failure();
    signalGet.call(input.signal);
    original = input.signal;
    active();
    signalAdd.call(original, "abort", failClosed, { once: true });
    // Give a caller's immediate cancellation a zero-spawn outcome.
    await Promise.resolve();
    active();
    spawnAttempted = true;
    child = fork(join(__dirname, "https-entrypoint.js"), [], {
      execPath: process.execPath,
      execArgv: [],
      cwd: __dirname,
      env: environment,
      stdio: ["ignore", "ignore", "ignore", "ipc"],
      serialization: "json",
      detached: false,
    });
    child.on("error", () => {
      if (!child.pid) {
        spawnFailed = true;
        resolveExited();
        resolveDisconnected();
      }
      failClosed();
    });
    child.once("exit", (code, signal) => {
      childExitVerified = true;
      exitCode = code;
      signalCode = signal;
      resolveExited();
      if (!closed || code !== 0 || signal) failClosed();
    });
    child.once("disconnect", () => {
      ipcDisconnected = true;
      resolveDisconnected();
      if (!closed) failClosed();
    });
    child.on("message", (message) => {
      try {
        if (
          message &&
          typeof message === "object" &&
          message["type"] === "closed"
        ) {
          const ack = fields(message, ["type", "listenerVerified"]);
          if (
            !closed ||
            stopAcknowledged ||
            typeof ack.listenerVerified !== "boolean"
          )
            throw failure();
          stopAcknowledged = true;
          return;
        }
        if (closed || advertised) throw failure();
        advertised = true;
        configuration = configurationFrom(message);
        void probe(configuration)
          .then(() => {
            active();
            ready = true;
            resolveReady(configuration);
          })
          .catch(failClosed);
      } catch {
        failClosed();
      }
    });
    maximumLifetime = setTimeout(failClosed, 120000);
    maximumLifetime.unref();
    active();
    child.send({ type: "start", ...trust }, (error) => {
      if (error) failClosed();
    });
    await bounded(readyPromise, 8000);
    active();
    return Object.freeze({
      configuration() {
        if (arguments.length) throw failure();
        active();
        return configuration;
      },
      close,
      summary() {
        if (arguments.length) throw failure();
        return Object.freeze({
          spawnAttempted,
          ready,
          closed,
          failed,
          childExitVerified,
          ipcDisconnected,
          listenerClosureVerified,
          exitCode,
          signalCode,
          databaseOwnershipVerified: false,
          containerOwnershipVerified: false,
          activationGranted: false,
        });
      },
    });
  } catch {
    await close().catch(() => {});
    throw failure();
  }
}
