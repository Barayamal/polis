import { createHash, createPublicKey, X509Certificate } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import { request } from "node:https";
import { checkServerIdentity, PeerCertificate, TLSSocket } from "node:tls";
import { types } from "node:util";

// Deliberately select the reviewed JS client, never NODE_PG_FORCE_NATIVE.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const PgClient = require("pg/lib/client");
const DATABASE_CERTIFICATE_PATH = "/run/fncp/bootstrap/postgres-cert.pem";
const JWKS_CERTIFICATE_PATH = "/run/fncp/bootstrap/jwks-cert.pem";
const LIMIT = 8192;
const DEADLINE = 2000;
const failure = () => new Error("Fresh bootstrap TLS verification failed");
const sha256 = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");

function exactData(input: unknown, names: string[]): Record<string, any> {
  if (!input || typeof input !== "object" || types.isProxy(input) ||
      Object.getPrototypeOf(input) !== Object.prototype) throw failure();
  const descriptors = Object.getOwnPropertyDescriptors(input);
  if (Reflect.ownKeys(descriptors).length !== names.length ||
      names.some((name) => !descriptors[name] || !("value" in descriptors[name]))) throw failure();
  return Object.fromEntries(names.map((name) => [name, descriptors[name].value]));
}

function certificate(pem: unknown, host: string, pin: unknown) {
  if (typeof pem !== "string" || Buffer.byteLength(pem) > LIMIT ||
      !/^-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+\n-----END CERTIFICATE-----\n?$/.test(pem) ||
      typeof pin !== "string" || !/^[a-f0-9]{64}$/.test(pin)) throw failure();
  try {
    const cert = new X509Certificate(pem);
    if (sha256(cert.raw) !== pin || cert.checkHost(host, { subject: "never", wildcards: false }) !== host ||
        Date.parse(cert.validFrom) > Date.now() || Date.parse(cert.validTo) <= Date.now()) throw failure();
    const peerCheck = (_hostname: string, peer: PeerCertificate) => {
      try {
        if (checkServerIdentity(host, peer) || !peer.raw || sha256(peer.raw) !== pin) return failure();
      } catch { return failure(); }
      return undefined;
    };
    return Object.freeze({ ca: pem, rejectUnauthorized: true as const, minVersion: "TLSv1.2" as const,
      servername: host, checkServerIdentity: peerCheck });
  } catch { throw failure(); }
}

function publicJwks(bytes: Buffer): { keys: any[] } {
  try {
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    const document = JSON.parse(text);
    if (JSON.stringify(document) !== text || !document || Array.isArray(document) ||
        Object.keys(document).join() !== "keys" || !Array.isArray(document.keys) || document.keys.length !== 1) throw failure();
    const key = document.keys[0];
    if (!key || typeof key !== "object" || Array.isArray(key) ||
        Object.keys(key).sort().join() !== "alg,e,kid,kty,n,use" || key.kty !== "RSA" ||
        key.alg !== "RS256" || key.use !== "sig" || key.e !== "AQAB" ||
        typeof key.n !== "string" || !/^[A-Za-z0-9_-]{342}$/.test(key.n) ||
        typeof key.kid !== "string" || !/^[a-f0-9]{64}$/.test(key.kid)) throw failure();
    const modulus = Buffer.from(key.n, "base64url");
    if (modulus.length !== 256 || modulus.toString("base64url") !== key.n || (modulus[0] & 128) === 0) throw failure();
    const publicKey = createPublicKey({ key, format: "jwk" });
    if (sha256(publicKey.export({ type: "spki", format: "der" })) !== key.kid) throw failure();
    return { keys: [Object.freeze({ ...key })] };
  } catch { throw failure(); }
}

/** No I/O on import or construction. Only the fixed fresh-bootstrap DNS names are admitted. */
export function createFreshBootstrapTls(input: unknown) {
  const value = exactData(input, ["databaseHost", "jwksUri", "databaseCertificatePem", "jwksCertificatePem",
    "databaseCertificateSha256", "jwksCertificateSha256"]);
  if (typeof value.databaseHost !== "string" || !/^fncp-fresh-pg-[a-f0-9]{24}$/.test(value.databaseHost)) throw failure();
  const session = value.databaseHost.slice("fncp-fresh-pg-".length);
  const jwksHost = `fncp-fresh-jwks-${session}`;
  if (value.jwksUri !== `https://${jwksHost}:8444/.well-known/jwks.json`) throw failure();
  const databaseSsl = certificate(value.databaseCertificatePem, value.databaseHost, value.databaseCertificateSha256);
  const jwksSsl = certificate(value.jwksCertificatePem, jwksHost, value.jwksCertificateSha256);

  class FreshBootstrapPgClient extends PgClient {
    constructor(config: any) {
      // Pool supplies these parsed, explicit fields; prohibit transport/connection-string overrides.
      if (!config || typeof config !== "object" || types.isProxy(config) || Object.getPrototypeOf(config) !== Object.prototype ||
          Reflect.ownKeys(config).some((name) => typeof name !== "string" || !("value" in Object.getOwnPropertyDescriptor(config, name))) ||
          config.host !== value.databaseHost || ![5432, "5432"].includes(config.port) ||
          ["connectionString", "connection", "stream", "lookup"].some((name) => Object.hasOwn(config, name)) ||
          (config.ssl !== undefined && config.ssl !== databaseSsl) ||
          typeof config.user !== "string" || !/^fncp_fresh_[a-f0-9]{24}$/.test(config.user) ||
          typeof config.database !== "string" || !/^fncp_fresh_[a-f0-9]{24}$/.test(config.database) ||
          typeof config.password !== "string" || !/^[a-f0-9]{64}$/.test(config.password)) throw failure();
      // pg-pool deliberately makes its own password data property non-enumerable.
      // Preserve the validated value explicitly; object spread alone drops it.
      super({ ...config, password: config.password, ssl: databaseSsl, connectionTimeoutMillis: DEADLINE,
        query_timeout: 3000, statement_timeout: 2000, lock_timeout: 1000, idle_in_transaction_session_timeout: 2000,
        options: "-c statement_timeout=2000 -c lock_timeout=1000 -c idle_in_transaction_session_timeout=2000" });
      const connection = this.connection;
      const originalStartup = connection.startup.bind(connection);
      let started = false;
      // pg 8.16.3 emits sslconnect immediately after tls.connect(), before secureConnect.
      // Do not even queue database/user startup (or subsequent password auth) until the leaf is verified.
      connection.startup = (parameters: unknown) => {
        const stream: TLSSocket = connection.stream;
        const verifiedStartup = () => {
          if (started || stream.destroyed || stream.authorized !== true ||
              !["TLSv1.2", "TLSv1.3"].includes(stream.getProtocol()) ||
              databaseSsl.checkServerIdentity(value.databaseHost, stream.getPeerCertificate())) {
            stream.destroy(failure());
            return;
          }
          started = true;
          originalStartup(parameters);
        };
        stream.once("secureConnect", verifiedStartup);
      };
    }
  }

  let closed = false;
  const pending = new Set<() => void>();
  const jwksFetcher = (uri: string): Promise<{ keys: any[] }> => {
    if (closed || uri !== value.jwksUri || pending.size >= 2) return Promise.reject(failure());
    return new Promise((resolve, reject) => {
      let req: ReturnType<typeof request> | undefined;
      let response: import("node:http").IncomingMessage | undefined;
      let settled = false;
      const chunks: Buffer[] = [];
      let size = 0;
      const finish = (result?: { keys: any[] }) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        pending.delete(abort);
        response?.destroy();
        req?.destroy();
        if (result) resolve(result); else reject(failure());
      };
      const abort = () => finish();
      const timer = setTimeout(abort, DEADLINE);
      pending.add(abort);
      try {
        req = request(value.jwksUri, { ...jwksSsl, agent: false, method: "GET", maxHeaderSize: LIMIT,
          headers: { Accept: "application/json", "Accept-Encoding": "identity", Connection: "close" } }, (res) => {
          response = res;
          if (settled) { res.destroy(); return; }
          if (res.statusCode !== 200 || res.headers.location || res.headers["content-encoding"] ||
              !/^application\/json(?:; charset=utf-8)?$/i.test(String(res.headers["content-type"])) ||
              (res.headers["content-length"] !== undefined &&
                (!/^(0|[1-9][0-9]*)$/.test(res.headers["content-length"]) || Number(res.headers["content-length"]) > LIMIT))) {
            finish(); return;
          }
          res.on("data", (chunk: Buffer) => {
            size += chunk.length;
            if (size > LIMIT) { finish(); return; }
            chunks.push(Buffer.from(chunk));
          });
          res.once("error", abort);
          res.once("aborted", abort);
          res.once("end", () => {
            if (settled) return;
            try { if (!res.complete) throw failure(); finish(publicJwks(Buffer.concat(chunks))); } catch { finish(); }
          });
        });
        req.once("error", abort);
        req.end();
      } catch { finish(); }
    });
  };
  return Object.freeze({ databaseSsl, FreshBootstrapPgClient, jwksFetcher,
    close: () => { closed = true; for (const abort of [...pending]) abort(); } });
}

function readFixedCertificate(path: string): string {
  let fd: number | undefined;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size < 1 || stat.size > LIMIT) throw failure();
    const bytes = Buffer.alloc(LIMIT + 1);
    let length = 0;
    while (length < bytes.length) {
      const count = readSync(fd, bytes, length, bytes.length - length, length);
      if (count === 0) break;
      length += count;
    }
    const after = fstatSync(fd);
    if (length !== stat.size || length > LIMIT || !after.isFile() || after.dev !== stat.dev ||
        after.ino !== stat.ino || after.size !== stat.size || after.mtimeMs !== stat.mtimeMs || after.ctimeMs !== stat.ctimeMs) throw failure();
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes.subarray(0, length));
  } catch { throw failure(); } finally { if (fd !== undefined) closeSync(fd); }
}

/** Called only after the separately validated Config.freshBootstrapLocalOnly admission. */
export function loadFreshBootstrapTls(input: unknown) {
  const value = exactData(input, ["databaseUrl", "jwksUri", "databaseCertificateSha256", "jwksCertificateSha256"]);
  let databaseHost: string;
  try {
    if (typeof value.databaseUrl !== "string" || value.databaseUrl.length > 2048) throw failure();
    const database = new URL(value.databaseUrl);
    if (database.protocol !== "postgres:" || database.port !== "5432" || database.search || database.hash) throw failure();
    databaseHost = database.hostname;
  } catch { throw failure(); }
  return createFreshBootstrapTls({ databaseHost, jwksUri: value.jwksUri,
    databaseCertificateSha256: value.databaseCertificateSha256, jwksCertificateSha256: value.jwksCertificateSha256,
    databaseCertificatePem: readFixedCertificate(DATABASE_CERTIFICATE_PATH),
    jwksCertificatePem: readFixedCertificate(JWKS_CERTIFICATE_PATH) });
}
