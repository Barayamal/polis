import { describe, expect, test } from "@jest/globals";
import { copyFreshBootstrapChildEnvironment } from "../../src/bootstrap/child-profile";
import { freshBootstrapStartup } from "../../src/auth/fncp-bootstrap-startup";

const ERROR = "FNCP_FRESH_BOOTSTRAP_CHILD_ENVIRONMENT_INVALID";
const namespace = "a".repeat(24);
function profile(): Record<string, string> {
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
    AUTH_ISSUER: "https://127.0.0.1:23456/",
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
function rejected(value: unknown) {
  let error: Error;
  try {
    copyFreshBootstrapChildEnvironment(value);
  } catch (failure) {
    error = failure as Error;
  }
  expect(error).toBeInstanceOf(Error);
  expect(error.message).toBe(ERROR);
  expect(error.cause).toBeUndefined();
  expect(Object.keys(error)).toEqual([]);
}

describe("minimal fresh child environment boundary", () => {
  test("copies exactly the coherent 33-field profile without attesting resources", () => {
    const input = profile();
    const output = copyFreshBootstrapChildEnvironment(input);
    expect(Object.keys(output)).toHaveLength(33);
    expect(output).toEqual(input);
    expect(output).not.toBe(input);
    expect(Object.getPrototypeOf(output)).toBe(Object.prototype);
    expect(Object.isFrozen(output)).toBe(true);
    expect(freshBootstrapStartup(output)?.namespaceId).toBe(namespace);
    expect(output).not.toHaveProperty("owned");
    expect(output).not.toHaveProperty("productionReady");
    expect(output).not.toHaveProperty("runtimeVerified");
  });
  test("returns a frozen snapshot unaffected by later caller changes", () => {
    const input = profile();
    const output = copyFreshBootstrapChildEnvironment(input);
    input.DATABASE_URL = "private-sentinel-not-a-database";
    delete input.AUTH_ISSUER;
    input.NODE_OPTIONS = "--require /private/sentinel";
    expect(output).toEqual(profile());
    expect(() => {
      (output as Record<string, string>).NODE_OPTIONS = "--inspect";
    }).toThrow();
    expect(() => {
      delete (output as Record<string, string>).PATH;
    }).toThrow();
    expect(Object.isFrozen(input)).toBe(false);
  });
  test("accepts frozen caller data without modifying property descriptors", () => {
    const input = Object.freeze(profile());
    const before = Object.getOwnPropertyDescriptors(input);
    const output = copyFreshBootstrapChildEnvironment(input);
    expect(Object.getOwnPropertyDescriptors(input)).toEqual(before);
    expect(output).toEqual(input);
  });
  test("rejects primitives, arrays, class instances and inherited environment objects", () => {
    class Environment {
      constructor() {
        Object.assign(this, profile());
      }
    }
    for (const input of [
      undefined,
      null,
      false,
      "environment",
      0,
      [],
      Object.assign([], profile()),
      new Environment(),
      Object.assign(Object.create(null), profile()),
      Object.create(profile()),
    ])
      rejected(input);
  });
  test("rejects extra function arguments before examining their values", () => {
    expect(() =>
      (copyFreshBootstrapChildEnvironment as any)(profile(), undefined)
    ).toThrow(ERROR);
    expect(() => (copyFreshBootstrapChildEnvironment as any)()).toThrow(ERROR);
  });
  test("rejects live/revoked proxies without executing traps", () => {
    let touched = 0;
    const proxy = new Proxy(profile(), {
      get() {
        touched++;
        throw new Error("private-sentinel");
      },
      getPrototypeOf() {
        touched++;
        throw new Error("private-sentinel");
      },
      ownKeys() {
        touched++;
        throw new Error("private-sentinel");
      },
      getOwnPropertyDescriptor() {
        touched++;
        throw new Error("private-sentinel");
      },
    });
    rejected(proxy);
    const revoked = Proxy.revocable(profile(), {});
    revoked.revoke();
    rejected(revoked.proxy);
    expect(touched).toBe(0);
  });
  test("rejects every accessor field without invoking getters or setters", () => {
    let touched = 0;
    for (const key of Object.keys(profile())) {
      const input = profile();
      Object.defineProperty(input, key, {
        enumerable: true,
        get() {
          touched++;
          throw new Error("private-sentinel");
        },
        set() {
          touched++;
        },
      });
      rejected(input);
    }
    expect(touched).toBe(0);
  });
  test("rejects each missing required field, including opt-in and fixed locale", () => {
    for (const key of Object.keys(profile())) {
      const input = profile();
      delete input[key];
      rejected(input);
    }
  });
  test("rejects unknown, symbol and non-enumerable extra fields", () => {
    rejected({ ...profile(), OTHER: "private-sentinel" });
    rejected({ ...profile(), [Symbol("private-sentinel")]: "hidden" });
    const input = profile();
    Object.defineProperty(input, "hidden", { value: "private-sentinel" });
    rejected(input);
    const replacement = profile();
    delete replacement.PATH;
    Object.defineProperty(replacement, "OTHER", {
      value: "/usr/bin:/bin",
      enumerable: true,
    });
    rejected(replacement);
  });
  test("rejects all loader, dynamic-library, TLS and PostgreSQL ambient expansions", () => {
    for (const key of [
      "NODE_OPTIONS",
      "NODE_PATH",
      "NODE_EXTRA_CA_CERTS",
      "NODE_USE_SYSTEM_CA",
      "NODE_TLS_REJECT_UNAUTHORIZED",
      "LD_PRELOAD",
      "LD_LIBRARY_PATH",
      "LD_AUDIT",
      "DYLD_INSERT_LIBRARIES",
      "DYLD_LIBRARY_PATH",
      "DYLD_FRAMEWORK_PATH",
      "OPENSSL_CONF",
      "SSL_CERT_FILE",
      "SSL_CERT_DIR",
      "PGHOST",
      "PGPASSWORD",
      "PGSERVICEFILE",
      "PGOPTIONS",
      "PGPASSFILE",
      "NODE_CHANNEL_FD",
      "NODE_CHANNEL_SERIALIZATION_MODE",
      "NODE_UNIQUE_ID",
      "UV_THREADPOOL_SIZE",
      "HOME",
      "TMPDIR",
      "SHELL",
      "HTTP_PROXY",
      "HTTPS_PROXY",
      "ALL_PROXY",
      "NO_PROXY",
    ])
      rejected({ ...profile(), [key]: "private-sentinel" });
  });
  test("rejects unknown credentials, dedicated-profile fields and arbitrary resource hints", () => {
    for (const key of [
      "AUTH_CLIENT_SECRET",
      "AWS_ACCESS_KEY_ID",
      "GOOGLE_APPLICATION_CREDENTIALS",
      "MAILGUN_API_KEY",
      "OPENAI_API_KEY",
      "PORT",
      "JWT_PRIVATE_KEY",
      "JWT_PUBLIC_KEY",
      "FNCP_LOCAL_ONLY",
      "FNCP_DEDICATED_LOCAL_ONLY",
      "FNCP_PROVIDER_ALLOWLIST_PATH",
      "DOMAIN_WHITELIST_ITEM_1",
      "DOCKER_HOST",
      "DOCKER_CONFIG",
    ])
      rejected({ ...profile(), [key]: "private-sentinel" });
  });
  test("every field is a bounded primitive string, never coercible input", () => {
    let touched = 0;
    const object = {
      toString() {
        touched++;
        return "false";
      },
    };
    for (const key of Object.keys(profile())) {
      for (const value of [
        undefined,
        null,
        false,
        0,
        object,
        [],
        "",
        "x".repeat(1025),
      ])
        rejected({ ...profile(), [key]: value });
    }
    expect(touched).toBe(0);
  });
  test("rejects NUL, CR and LF in every value before any child spawn", () => {
    for (const key of Object.keys(profile())) {
      for (const ending of ["\u0000", "\r", "\n", "\r\n"])
        rejected({ ...profile(), [key]: profile()[key] + ending });
    }
  });
  test("accepts only fixed minimal executable path and C locale", () => {
    for (const key of ["PATH", "LANG", "LC_ALL"]) {
      for (const value of [
        "C.UTF-8",
        "en_AU.UTF-8",
        "/opt/homebrew/bin:/usr/bin:/bin",
        "/usr/bin:/bin:",
        " C",
      ])
        rejected({ ...profile(), [key]: value });
    }
  });
  test("requires exact true opt-in and production mode with no ordinary fallback", () => {
    for (const value of ["false", "TRUE", "1", " true", "undefined"])
      rejected({ ...profile(), FNCP_FRESH_BOOTSTRAP_LOCAL_ONLY: value });
    for (const value of ["development", "test", "production ", "PRODUCTION"])
      rejected({ ...profile(), NODE_ENV: value });
  });
  test("every side-effect feature must remain explicitly disabled", () => {
    for (const key of [
      "DEV_MODE",
      "TESTING",
      "ENABLE_TELEMETRY",
      "USE_NETWORK_HOST",
      "SHOULD_USE_TRANSLATION_API",
      "BACKFILL_COMMENT_LANG_DETECTION",
      "RUN_PERIODIC_EXPORT_TESTS",
      "SERVER_LOG_TO_FILE",
    ]) {
      for (const value of ["true", "0", "FALSE", " false"])
        rejected({ ...profile(), [key]: value });
    }
  });
  test("email, admin, port, database TLS and audience controls cannot be widened", () => {
    for (const [key, value] of [
      ["EMAIL_TRANSPORT_TYPES", "ses"],
      ["ADMIN_EMAILS", '["invented@example.invalid"]'],
      ["ADMIN_UIDS", "[1]"],
      ["API_SERVER_PORT", "8443"],
      ["DATABASE_SSL", "false"],
      ["AUTH_AUDIENCE", "another-audience"],
      ["POLIS_JWT_AUDIENCE", "another-audience"],
    ])
      rejected({ ...profile(), [key]: value });
  });
  test("issuer remains canonical literal-loopback HTTPS with a nonprivileged port", () => {
    for (const value of [
      "http://127.0.0.1:23456/",
      "https://localhost:23456/",
      "https://127.0.0.1:443/",
      "https://127.0.0.1:65536/",
      "https://127.0.0.1:23456",
      "https://127.0.0.1:23456/?x=1",
      "https://foreign.invalid:23456/",
    ])
      rejected({ ...profile(), AUTH_ISSUER: value });
  });
  test("database read-only URL and fresh DNS namespace must match the supplied profile", () => {
    rejected({
      ...profile(),
      READ_ONLY_DATABASE_URL: profile().DATABASE_URL + "?sslmode=disable",
    });
    rejected({
      ...profile(),
      JWKS_URI: profile().JWKS_URI.replace(namespace, "0".repeat(24)),
    });
    for (const key of [
      "API_PROD_HOSTNAME",
      "DOMAIN_OVERRIDE",
      "POLIS_JWT_ISSUER",
    ])
      rejected({
        ...profile(),
        [key]: profile()[key].replace(namespace, "0".repeat(24)),
      });
    const wrongDb = profile().DATABASE_URL.replace(
      `fncp-fresh-pg-${namespace}`,
      "127.0.0.1"
    );
    rejected({
      ...profile(),
      DATABASE_URL: wrongDb,
      READ_ONLY_DATABASE_URL: wrongDb,
    });
  });
  test("certificate pins and generated secret shapes stay distinct and never escape errors", () => {
    rejected({
      ...profile(),
      FNCP_BOOTSTRAP_DATABASE_CERTIFICATE_SHA256:
        profile().FNCP_BOOTSTRAP_JWKS_CERTIFICATE_SHA256,
    });
    rejected({
      ...profile(),
      LOGIN_CODE_PEPPER: profile().ENCRYPTION_PASSWORD_00001,
    });
    rejected({ ...profile(), LOGIN_CODE_PEPPER: "c".repeat(64) });
    for (const key of [
      "LOGIN_CODE_PEPPER",
      "ENCRYPTION_PASSWORD_00001",
      "FNCP_BOOTSTRAP_DATABASE_CERTIFICATE_SHA256",
      "FNCP_BOOTSTRAP_JWKS_CERTIFICATE_SHA256",
    ])
      rejected({ ...profile(), [key]: "private-sentinel-path-or-token" });
  });
  test("participant-key locations are fixed profile paths, not accepted caller file selectors", () => {
    for (const key of ["JWT_PRIVATE_KEY_PATH", "JWT_PUBLIC_KEY_PATH"])
      for (const value of [
        "/tmp/invented-key.pem",
        "../retained/key.pem",
        "inline:private-sentinel",
      ])
        rejected({ ...profile(), [key]: value });
  });
});
