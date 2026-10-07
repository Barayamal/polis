import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import * as tls from "node:tls";
import { AddressInfo } from "node:net";
import { loadDatabaseCaTls } from "../../src/auth/database-ca-tls";

let folder: string;
let certificateFile: string;
let key: Buffer;
let cert: Buffer;
let otherKey: Buffer;
let otherCert: Buffer;
beforeAll(() => {
  folder = mkdtempSync(join(tmpdir(), "database-ca-tls-test-"));
  const openssl = process.platform === "darwin" ? "/opt/homebrew/bin/openssl" : "/usr/bin/openssl";
  for (const name of ["known", "other"]) {
    execFileSync(openssl, ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
      "-noenc", "-days", "1", "-subj", "/CN=synthetic.invalid", "-addext", "subjectAltName=DNS:database.example.invalid",
      "-keyout", join(folder, name + ".key"), "-out", join(folder, name + ".pem")],
    { timeout: 10000, stdio: "ignore", env: { PATH: "/usr/bin:/bin", OPENSSL_CONF: "/dev/null" } });
  }
  certificateFile = join(folder, "known.pem");
  key = readFileSync(join(folder, "known.key")); cert = readFileSync(certificateFile);
  otherKey = readFileSync(join(folder, "other.key")); otherCert = readFileSync(join(folder, "other.pem"));
});
afterAll(() => rmSync(folder, { recursive: true, force: false }));
const options = () => ({ enabled: true, certificateFile, databaseUrl: "postgres://user:password@database.example.invalid:5432/fresh" });

test("absent CA opt-in keeps ordinary behavior and performs no URL/file validation", () => {
  expect(loadDatabaseCaTls({ enabled: false, databaseUrl: "not configured" })).toBeUndefined();
});
test.each([false, undefined])("CA opt-in cannot silently disable certificate verification (%s)", enabled => {
  expect(() => loadDatabaseCaTls({ ...options(), enabled: enabled as any })).toThrow("DATABASE_CA_TLS_CONFIGURATION_INVALID");
});
test.each(["", "relative.pem", "/tmp/unavailable ca.pem"])("invalid CA path fails closed (%s)", path => {
  expect(() => loadDatabaseCaTls({ ...options(), certificateFile: path })).toThrow("DATABASE_CA_TLS_CONFIGURATION_INVALID");
});
test.each(["postgres://u:p@database.example.invalid/db?sslmode=disable", "https://database.example.invalid/db", "postgres://u:p@database.example.invalid/db#override"])(
  "URL transport overrides are rejected (%s)", databaseUrl => {
    expect(() => loadDatabaseCaTls({ ...options(), databaseUrl })).toThrow("DATABASE_CA_TLS_CONFIGURATION_INVALID");
  });
test("symlink and malformed certificates fail closed", () => {
  const alias = join(folder, "alias.pem"); symlinkSync(certificateFile, alias);
  expect(() => loadDatabaseCaTls({ ...options(), certificateFile: alias })).toThrow("DATABASE_CA_TLS_CONFIGURATION_INVALID");
  const malformed = join(folder, "malformed.pem"); writeFileSync(malformed, "invented non-certificate");
  expect(() => loadDatabaseCaTls({ ...options(), certificateFile: malformed })).toThrow("DATABASE_CA_TLS_CONFIGURATION_INVALID");
});
async function handshake(tlsOptions: ReturnType<typeof loadDatabaseCaTls>, alternate = false) {
  const sockets = new Set<tls.TLSSocket>();
  const server = tls.createServer({ key: alternate ? otherKey : key, cert: alternate ? otherCert : cert }, socket => {
    sockets.add(socket); socket.once("close", () => sockets.delete(socket)); socket.end();
  });
  server.on("tlsClientError", () => {});
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  try {
    return await new Promise<boolean>(resolve => {
      const client = tls.connect({ ...tlsOptions, host: "127.0.0.1", port: (server.address() as AddressInfo).port });
      client.once("secureConnect", () => { const authorized = client.authorized; client.destroy(); resolve(authorized); });
      client.once("error", () => { client.destroy(); resolve(false); });
      client.setTimeout(2000, () => { client.destroy(); resolve(false); });
    });
  } finally {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>(resolve => server.close(() => resolve()));
  }
}
test("real TLS accepts the configured authority and matching hostname", async () => {
  expect(await handshake(loadDatabaseCaTls(options()))).toBe(true);
});
test("real TLS rejects an untrusted server with the same hostname", async () => {
  expect(await handshake(loadDatabaseCaTls(options()), true)).toBe(false);
});
test("real TLS rejects a trusted server with the wrong hostname", async () => {
  expect(await handshake(loadDatabaseCaTls({ ...options(), databaseUrl: "postgres://u:p@wrong.example.invalid/db" }))).toBe(false);
});
