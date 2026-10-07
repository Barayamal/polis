/** Explicit database CA trust. No file access when the option is absent.
 * Existing deployments keep their previous TLS behavior unless they opt in.
 */
import { constants, closeSync, fstatSync, openSync, readSync } from "node:fs";
import { isAbsolute } from "node:path";
import { X509Certificate } from "node:crypto";
import { checkServerIdentity } from "node:tls";

const fail = () => new Error("DATABASE_CA_TLS_CONFIGURATION_INVALID");
export function loadDatabaseCaTls(options: {
  certificateFile?: string;
  enabled: boolean;
  databaseUrl: string;
}) {
  if (options.certificateFile === undefined) return undefined;
  let fd: number | undefined;
  try {
    const path = options.certificateFile;
    if (!options.enabled || typeof path !== "string" || !isAbsolute(path) ||
        /[\u0000-\u0020\u007f]/u.test(path)) throw fail();
    const url = new URL(options.databaseUrl);
    if (!["postgres:", "postgresql:"].includes(url.protocol) || !url.hostname ||
        url.search || url.hash) throw fail();
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const before = fstatSync(fd);
    if (!before.isFile() || before.size < 1 || before.size > 8192 || before.nlink !== 1) throw fail();
    const bytes = Buffer.alloc(before.size + 1);
    let length = 0;
    while (length < bytes.length) {
      const count = readSync(fd, bytes, length, bytes.length - length, length);
      if (!count) break;
      length += count;
    }
    const after = fstatSync(fd);
    if (length !== before.size || ["dev", "ino", "size", "mtimeMs", "ctimeMs"].some(k => before[k] !== after[k])) throw fail();
    const ca = new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, length));
    if (!/^-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+\n-----END CERTIFICATE-----\n?$/u.test(ca)) throw fail();
    const certificate = new X509Certificate(ca);
    if (Date.parse(certificate.validFrom) > Date.now() || Date.parse(certificate.validTo) <= Date.now()) throw fail();
    return Object.freeze({ ca, rejectUnauthorized: true as const, minVersion: "TLSv1.2" as const,
      servername: url.hostname,
      checkServerIdentity: (_host: string, peer: import("node:tls").PeerCertificate) => checkServerIdentity(url.hostname, peer) });
  } catch { throw fail(); }
  finally { if (fd !== undefined) closeSync(fd); }
}
