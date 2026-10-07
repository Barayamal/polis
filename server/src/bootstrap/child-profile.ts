/** Pure environment-copy boundary for an independently owned fresh child.
 * This checks only the minimal configuration shape and its internal coherence.
 * It does not generate secrets, read process.env, inspect certificates, attest
 * resource ownership/isolation, choose a runtime, or authorize a launch.
 */
import { isProxy } from "node:util/types";
import { freshBootstrapStartup } from "../auth/fncp-bootstrap-startup";

const NAMES = Object.freeze([
  "PATH",
  "LANG",
  "LC_ALL",
  "FNCP_FRESH_BOOTSTRAP_LOCAL_ONLY",
  "NODE_ENV",
  "DEV_MODE",
  "TESTING",
  "ENABLE_TELEMETRY",
  "USE_NETWORK_HOST",
  "SHOULD_USE_TRANSLATION_API",
  "BACKFILL_COMMENT_LANG_DETECTION",
  "RUN_PERIODIC_EXPORT_TESTS",
  "SERVER_LOG_TO_FILE",
  "EMAIL_TRANSPORT_TYPES",
  "ADMIN_EMAILS",
  "ADMIN_UIDS",
  "API_SERVER_PORT",
  "DATABASE_SSL",
  "AUTH_AUDIENCE",
  "AUTH_ISSUER",
  "FNCP_BOOTSTRAP_DATABASE_CERTIFICATE_SHA256",
  "FNCP_BOOTSTRAP_JWKS_CERTIFICATE_SHA256",
  "LOGIN_CODE_PEPPER",
  "ENCRYPTION_PASSWORD_00001",
  "DATABASE_URL",
  "READ_ONLY_DATABASE_URL",
  "JWKS_URI",
  "API_PROD_HOSTNAME",
  "DOMAIN_OVERRIDE",
  "POLIS_JWT_ISSUER",
  "POLIS_JWT_AUDIENCE",
  "JWT_PRIVATE_KEY_PATH",
  "JWT_PUBLIC_KEY_PATH",
]);
const failure = () =>
  new Error("FNCP_FRESH_BOOTSTRAP_CHILD_ENVIRONMENT_INVALID");

export function copyFreshBootstrapChildEnvironment(
  input: unknown
): Readonly<Record<string, string>> {
  try {
    if (
      arguments.length !== 1 ||
      !input ||
      typeof input !== "object" ||
      isProxy(input) ||
      Object.getPrototypeOf(input) !== Object.prototype
    )
      throw failure();
    const descriptors = Object.getOwnPropertyDescriptors(input);
    if (Reflect.ownKeys(descriptors).length !== NAMES.length) throw failure();
    const copy: Record<string, string> = {};
    for (const name of NAMES) {
      if (!Object.hasOwn(descriptors, name)) throw failure();
      const descriptor = descriptors[name];
      if (
        !descriptor ||
        !Object.hasOwn(descriptor, "value") ||
        typeof descriptor.value !== "string" ||
        descriptor.value.length === 0 ||
        descriptor.value.length > 1024 ||
        /[\u0000\r\n]/u.test(descriptor.value)
      )
        throw failure();
      copy[name] = descriptor.value;
    }
    if (
      copy.PATH !== "/usr/bin:/bin" ||
      copy.LANG !== "C" ||
      copy.LC_ALL !== "C" ||
      !freshBootstrapStartup(copy)
    )
      throw failure();
    return Object.freeze(copy);
  } catch {
    throw failure();
  }
}
