import { createHash, generateKeyPairSync, X509Certificate } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import https = require("node:https");
import * as net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createSecureContext, TLSSocket } from "node:tls";
import { createFreshBootstrapTls, loadFreshBootstrapTls } from "../../src/auth/fncp-bootstrap-tls";

// Fresh synthetic TLS/wire fixtures only. Redirecting the test-owned socket below is NOT
// evidence of container DNS, Docker ownership, a running PostgreSQL server, or Pol.is startup.
const nonce = "a".repeat(24);
const databaseHost = `fncp-fresh-pg-${nonce}`;
const jwksHost = `fncp-fresh-jwks-${nonce}`;
const jwksUri = `https://${jwksHost}:8444/.well-known/jwks.json`;
const digest = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");
let folder: string;
let key: Buffer;
let cert: string;
let alternateCert: string;
let document: string;
const handles: Array<() => Promise<void> | void> = [];

beforeAll(() => {
  folder = mkdtempSync(join(tmpdir(), "fncp-bootstrap-tls-test-"));
  const openssl = (args: string[]) => execFileSync("/opt/homebrew/bin/openssl", args, {
    cwd: folder, env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C", OPENSSL_CONF: "/dev/null" },
    timeout: 10000, maxBuffer: 8192, stdio: "pipe",
  });
  openssl(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-noenc", "-days", "1",
    "-keyout", "key.pem", "-out", "cert.pem", "-subj", "/CN=synthetic.invalid", "-addext", "basicConstraints=critical,CA:TRUE",
    "-addext", `subjectAltName=DNS:${databaseHost},DNS:${jwksHost}`]);
  openssl(["req", "-new", "-key", "key.pem", "-out", "alternate.csr", "-subj", "/CN=synthetic.invalid"]);
  writeFileSync(join(folder, "extensions.txt"), `basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:${databaseHost},DNS:${jwksHost}\n`, { mode: 0o600 });
  openssl(["x509", "-req", "-in", "alternate.csr", "-CA", "cert.pem", "-CAkey", "key.pem", "-set_serial", "2", "-days", "1",
    "-extfile", "extensions.txt", "-out", "alternate.pem"]);
  key = readFileSync(join(folder, "key.pem"));
  cert = readFileSync(join(folder, "cert.pem"), "utf8");
  alternateCert = readFileSync(join(folder, "alternate.pem"), "utf8");
  const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
  document = JSON.stringify({ keys: [{ ...pair.publicKey.export({ format: "jwk" }),
    kid: digest(pair.publicKey.export({ format: "der", type: "spki" })), use: "sig", alg: "RS256" }] });
});
afterEach(async () => { jest.restoreAllMocks(); for (const close of handles.splice(0).reverse()) await close(); });
afterAll(() => { rmSync(folder, { recursive: true, force: false }); });

function input() {
  const pin = digest(new X509Certificate(cert).raw);
  return { databaseHost, jwksUri, databaseCertificatePem: cert, jwksCertificatePem: cert,
    databaseCertificateSha256: pin, jwksCertificateSha256: pin };
}
function boundary() {
  const result = createFreshBootstrapTls(input());
  handles.push(result.close);
  return result;
}
async function listen(server: net.Server) {
  const sockets = new Set<net.Socket>();
  server.on("connection", (socket) => { sockets.add(socket); socket.once("close", () => sockets.delete(socket)); });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as net.AddressInfo).port;
  handles.push(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await new Promise<void>((resolve, reject) => {
      const socket = net.connect({ host: "127.0.0.1", port });
      socket.once("connect", () => { socket.destroy(); reject(new Error("Fixture listener remained open")); });
      socket.once("error", (error: NodeJS.ErrnoException) => error.code === "ECONNREFUSED" ? resolve() : reject(error));
    });
  });
  return port;
}
async function httpsFixture(handler: (req: any, res: any) => void, presented = cert) {
  const server = https.createServer({ key, cert: presented }, handler);
  server.on("tlsClientError", () => {});
  const port = await listen(server);
  const actualRequest = https.request;
  const calls: any[] = [];
  jest.spyOn(https, "request").mockImplementation(((url: string, options: any, callback: any) => {
    calls.push({ url, options });
    // Test-only explicit DNS/port mapping. All production TLS/SAN/leaf checks remain intact.
    return actualRequest(new URL(url), { ...options, port,
      lookup: (_host: string, _options: unknown, cb: any) => cb(null, [{ address: "127.0.0.1", family: 4 }]) }, callback);
  }) as any);
  return calls;
}

test("pure factory validates the same fixed nonce and explicit CA/name/leaf binding", () => {
  const result = boundary();
  expect(result.databaseSsl.rejectUnauthorized).toBe(true);
  expect(result.databaseSsl.ca).toBe(cert);
  expect(result.databaseSsl.servername).toBe(databaseHost);
  expect(result.databaseSsl.minVersion).toBe("TLSv1.2");
  expect(Object.isFrozen(result.databaseSsl)).toBe(true);
  expect(() => createFreshBootstrapTls({ ...input(), jwksUri: jwksUri.replace(nonce, "b".repeat(24)) })).toThrow("Fresh bootstrap TLS verification failed");
});
test.each([undefined, null, {}, new Proxy({}, {}), Object.create(null)])("rejects forged factory inputs without I/O %#", (value) => {
  expect(() => createFreshBootstrapTls(value)).toThrow("Fresh bootstrap TLS verification failed");
});
test("rejects extra/symbol/accessor fields without reading accessor values", () => {
  let reads = 0;
  const accessor = { ...input() };
  Object.defineProperty(accessor, "databaseHost", { get: () => { reads++; return databaseHost; } });
  for (const value of [accessor, { ...input(), extra: true }, { ...input(), [Symbol("extra")]: true }]) {
    expect(() => createFreshBootstrapTls(value)).toThrow("Fresh bootstrap TLS verification failed");
  }
  expect(reads).toBe(0);
});
test("rejects mismatched pin, multiple PEMs, wrong host, and noncanonical JWKS URLs", () => {
  for (const patch of [{ databaseCertificateSha256: "0".repeat(64) }, { databaseCertificatePem: cert + cert },
    { databaseHost: "localhost" }, { jwksUri: jwksUri + "?next=https://outside.invalid" }, { jwksUri: jwksUri.replace("https:", "http:") }]) {
    expect(() => createFreshBootstrapTls({ ...input(), ...patch })).toThrow("Fresh bootstrap TLS verification failed");
  }
});
test("loader rejects malformed arguments before any fixed certificate read", () => {
  expect(() => loadFreshBootstrapTls(undefined)).toThrow("Fresh bootstrap TLS verification failed");
  expect(() => loadFreshBootstrapTls({ databaseUrl: "http://bad.invalid", jwksUri,
    databaseCertificateSha256: "0".repeat(64), jwksCertificateSha256: "0".repeat(64) })).toThrow("Fresh bootstrap TLS verification failed");
});
test("actual loopback HTTPS returns one bounded public RSA key", async () => {
  let requests = 0;
  const calls = await httpsFixture((req, res) => {
    requests++; expect(req.method).toBe("GET"); expect(req.url).toBe("/.well-known/jwks.json");
    expect(req.headers.authorization).toBeUndefined();
    res.writeHead(200, { "Content-Type": "application/json" }); res.end(document);
  });
  const result = await boundary().jwksFetcher(jwksUri);
  expect(result).toEqual(JSON.parse(document));
  expect(requests).toBe(1);
  expect(calls).toHaveLength(1);
  expect(calls[0].options.agent).toBe(false);
  expect(calls[0].options.rejectUnauthorized).toBe(true);
});
test("same-CA alternate leaf fails before an HTTP request is received", async () => {
  let requests = 0;
  await httpsFixture((_req, res) => { requests++; res.end(document); }, alternateCert);
  await expect(boundary().jwksFetcher(jwksUri)).rejects.toThrow("Fresh bootstrap TLS verification failed");
  expect(requests).toBe(0);
});
test.each([301, 302, 307, 308, 500])("does not follow redirect/retry status %i", async (status) => {
  const calls = await httpsFixture((_req, res) => {
    res.writeHead(status, { Location: "https://outside.invalid/", "Content-Type": "application/json" }); res.end(document);
  });
  await expect(boundary().jwksFetcher(jwksUri)).rejects.toThrow("Fresh bootstrap TLS verification failed");
  expect(calls).toHaveLength(1);
});
test.each(["private", "duplicate", "bom", "oversize", "wrong-type", "gzip"])("rejects malformed JWKS mode %s", async (mode) => {
  await httpsFixture((_req, res) => {
    const parsed = JSON.parse(document);
    parsed.keys[0].d = "private-field-must-never-be-accepted";
    const body = mode === "private" ? JSON.stringify(parsed) : mode === "duplicate" ? document.replace('"keys":', '"keys":[],"keys":') :
      mode === "bom" ? "\uFEFF" + document : mode === "oversize" ? "x".repeat(8193) : document;
    res.writeHead(200, { "Content-Type": mode === "wrong-type" ? "text/html" : "application/json",
      ...(mode === "gzip" ? { "Content-Encoding": "gzip" } : {}) }); res.end(body);
  });
  await expect(boundary().jwksFetcher(jwksUri)).rejects.toThrow("Fresh bootstrap TLS verification failed");
});
test("close aborts an owned hanging request and rejects further work", async () => {
  let arrived!: () => void;
  const arrival = new Promise<void>((resolve) => { arrived = resolve; });
  await httpsFixture(() => arrived());
  const result = boundary();
  const pending = result.jwksFetcher(jwksUri);
  const rejection = expect(pending).rejects.toThrow("Fresh bootstrap TLS verification failed");
  await arrival; result.close(); await rejection;
  await expect(result.jwksFetcher(jwksUri)).rejects.toThrow("Fresh bootstrap TLS verification failed");
});
test("whole request deadline bounds a silent HTTPS response", async () => {
  await httpsFixture(() => {});
  const started = Date.now();
  await expect(boundary().jwksFetcher(jwksUri)).rejects.toThrow("Fresh bootstrap TLS verification failed");
  expect(Date.now() - started).toBeGreaterThanOrEqual(1900);
  expect(Date.now() - started).toBeLessThan(4000);
});
test("fetcher rejects a changed target before creating a request", async () => {
  const calls = await httpsFixture((_req, res) => res.end(document));
  await expect(boundary().jwksFetcher(jwksUri + "?x=1")).rejects.toThrow("Fresh bootstrap TLS verification failed");
  expect(calls).toHaveLength(0);
});

async function pgFixture(presented: string, supportsSsl: boolean | null = true, ignoreQueries = false) {
  let sslRequests = 0;
  let startupBytes = 0;
  let startup!: Buffer;
  const secureContext = createSecureContext({ key, cert: presented });
  const server = net.createServer((raw) => {
    raw.once("data", (packet) => {
      expect(packet.equals(Buffer.from([0, 0, 0, 8, 4, 210, 22, 47]))).toBe(true);
      sslRequests++;
      if (supportsSsl === null) return;
      if (!supportsSsl) { raw.end("N"); return; }
      raw.write("S");
      const secure = new TLSSocket(raw, { isServer: true, secureContext });
      secure.on("error", () => {});
      secure.on("data", (bytes) => {
        if (startupBytes !== 0 && ignoreQueries) return;
        startupBytes += bytes.length; startup = Buffer.from(bytes);
        // AuthenticationOk + ReadyForQuery: protocol fixture only, no database/query execution.
        secure.write(Buffer.from([82, 0, 0, 0, 8, 0, 0, 0, 0, 90, 0, 0, 0, 5, 73]));
      });
    });
  });
  const port = await listen(server);
  const result = boundary();
  const client = new result.FreshBootstrapPgClient({ host: databaseHost, port: 5432,
    user: `fncp_fresh_${"b".repeat(24)}`, database: `fncp_fresh_${"c".repeat(24)}`, password: "d".repeat(64),
    options: "-c statement_timeout=0", statement_timeout: 0, query_timeout: 0 });
  client.on("error", () => {});
  const stream = client.connection.stream;
  const connect = stream.connect.bind(stream);
  // Only this newly owned client's TCP destination is mapped; SNI/CA/name/leaf remain original.
  stream.connect = () => connect(port, "127.0.0.1");
  handles.push(() => { client.connection.stream.destroy(); });
  return { client, snapshot: () => ({ sslRequests, startupBytes, startup }) };
}
test("installed pg JS client sends startup only after a verified native PostgreSQL TLS exchange", async () => {
  const fixture = await pgFixture(cert);
  await fixture.client.connect();
  expect(fixture.snapshot().sslRequests).toBe(1);
  expect(fixture.snapshot().startupBytes).toBeGreaterThan(0);
  expect(fixture.snapshot().startup.toString()).toContain(`fncp_fresh_${"b".repeat(24)}`);
  expect(fixture.snapshot().startup.toString()).not.toContain("d".repeat(64));
  expect(fixture.snapshot().startup.toString()).toContain("statement_timeout=2000");
  expect(fixture.snapshot().startup.toString()).not.toContain("statement_timeout=0");
  expect(fixture.client.connectionParameters.query_timeout).toBe(3000);
});
test("installed pg sends zero startup/credential bytes to a valid same-CA but unpinned leaf", async () => {
  const fixture = await pgFixture(alternateCert);
  await expect(fixture.client.connect()).rejects.toThrow();
  expect(fixture.snapshot().sslRequests).toBe(1);
  expect(fixture.snapshot().startupBytes).toBe(0);
});
test("installed pg refuses server SSL denial without plaintext fallback", async () => {
  const fixture = await pgFixture(cert, false);
  await expect(fixture.client.connect()).rejects.toThrow();
  expect(fixture.snapshot().sslRequests).toBe(1);
  expect(fixture.snapshot().startupBytes).toBe(0);
});
test("installed pg bounds a silent SSLRequest exchange without another socket", async () => {
  const fixture = await pgFixture(cert, null);
  const started = Date.now();
  await expect(fixture.client.connect()).rejects.toThrow();
  expect(Date.now() - started).toBeLessThan(4000);
  expect(fixture.snapshot().sslRequests).toBe(1);
  expect(fixture.snapshot().startupBytes).toBe(0);
});
test("installed pg bounds an unanswered query after verified startup", async () => {
  const fixture = await pgFixture(cert, true, true);
  await fixture.client.connect();
  const started = Date.now();
  await expect(fixture.client.query("SELECT 1")).rejects.toThrow("Query read timeout");
  expect(Date.now() - started).toBeGreaterThanOrEqual(2900);
  expect(Date.now() - started).toBeLessThan(4500);
  expect(fixture.snapshot().sslRequests).toBe(1);
});
test("fresh client rejects arbitrary host, port, connection and missing explicit password", () => {
  const Client = boundary().FreshBootstrapPgClient;
  const good = { host: databaseHost, port: 5432, user: `fncp_fresh_${"b".repeat(24)}`, database: `fncp_fresh_${"c".repeat(24)}`, password: "d".repeat(64) };
  for (const patch of [{ host: "127.0.0.1" }, { port: 443 }, { connectionString: "postgres://outside.invalid" },
    { stream: {} }, { connection: {} }, { password: "" }]) expect(() => new Client({ ...good, ...patch })).toThrow();
});
test.each([false, true])("real pg Pool hidden password survives guarded client construction (readOnly=%s)", async (isReadOnly) => {
  // Actual installed Pool options, not an approximation of its descriptors.
  // Construction alone opens no TCP connection and performs no database work.
  const Pool = require("pg-pool");
  const result = boundary();
  const password = "d".repeat(64);
  const pool = new Pool({ Client: result.FreshBootstrapPgClient, host: databaseHost, port: 5432,
    user: `fncp_fresh_${"b".repeat(24)}`, database: `fncp_fresh_${"c".repeat(24)}`, password,
    ssl: result.databaseSsl, isReadOnly });
  handles.push(() => pool.end());
  expect(Object.getOwnPropertyDescriptor(pool.options, "password")).toEqual({
    value: password, configurable: true, enumerable: false, writable: true,
  });
  const connect = jest.spyOn(net.Socket.prototype, "connect");
  const client = new pool.Client(pool.options);
  expect(client.connectionParameters.password).toBe(password);
  expect(client.password).toBe(password);
  expect(Object.keys(client.connectionParameters)).not.toContain("password");
  expect(Object.keys(client)).not.toContain("password");
  expect(connect).not.toHaveBeenCalled();
});
test("password preservation still rejects accessors before reading them", () => {
  const Client = boundary().FreshBootstrapPgClient;
  const config = { host: databaseHost, port: 5432,
    user: `fncp_fresh_${"b".repeat(24)}`, database: `fncp_fresh_${"c".repeat(24)}` };
  let reads = 0;
  Object.defineProperty(config, "password", { enumerable: false, get() { reads++; return "d".repeat(64); } });
  expect(() => new Client(config)).toThrow("Fresh bootstrap TLS verification failed");
  expect(reads).toBe(0);
});
test("source wiring applies the guarded client to both pools and the bounded fetcher to both JWT validators", () => {
  const pg = readFileSync(join(__dirname, "../../src/db/pg-query.ts"), "utf8");
  const jwt = readFileSync(join(__dirname, "../../src/auth/jwt-middleware.ts"), "utf8");
  expect(pg.match(/Client: freshBootstrapTls\.FreshBootstrapPgClient/g)).toHaveLength(2);
  expect(pg.match(/ssl: freshBootstrapTls \? freshBootstrapTls\.databaseSsl/g)).toHaveLength(2);
  expect(jwt.match(/\.\.\.freshJwksOptions/g)).toHaveLength(2);
  for (const source of [pg, jwt]) expect(source).toContain("Config.freshBootstrapLocalOnly ? loadFreshBootstrapTls(");
});
