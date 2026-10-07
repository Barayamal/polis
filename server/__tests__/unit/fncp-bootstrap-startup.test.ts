import { describe, test, expect } from "@jest/globals";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import ts from "typescript";
import {
  freshBootstrapStartup,
  assertOrdinaryHttpEntrypoint,
} from "../../src/auth/fncp-bootstrap-startup";

const id = "ab".repeat(12);
function environment(): Record<string, string> {
  const database = `postgres://fncp_fresh_${id}:${"c".repeat(
    64
  )}@fncp-fresh-pg-${id}:5432/fncp_fresh_${id}`;
  return {
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
    DATABASE_URL: database,
    READ_ONLY_DATABASE_URL: database,
    AUTH_AUDIENCE: "fncp-fresh-synthetic-bootstrap",
    AUTH_ISSUER: "https://127.0.0.1:23456/",
    JWKS_URI: `https://fncp-fresh-jwks-${id}:8444/.well-known/jwks.json`,
    FNCP_BOOTSTRAP_DATABASE_CERTIFICATE_SHA256: "a".repeat(64),
    FNCP_BOOTSTRAP_JWKS_CERTIFICATE_SHA256: "b".repeat(64),
    LOGIN_CODE_PEPPER: "d".repeat(64),
    ENCRYPTION_PASSWORD_00001: "e".repeat(64),
    API_PROD_HOSTNAME: `fncp-fresh-api-${id}:8443`,
    DOMAIN_OVERRIDE: `fncp-fresh-api-${id}:8443`,
    POLIS_JWT_ISSUER: `https://fncp-fresh-api-${id}:8443/`,
    POLIS_JWT_AUDIENCE: "fncp-fresh-synthetic-participants",
    JWT_PRIVATE_KEY_PATH: "/run/fncp/bootstrap/participant-private.pem",
    JWT_PUBLIC_KEY_PATH: "/run/fncp/bootstrap/participant-public.pem",
  };
}

describe("fresh synthetic bootstrap startup guard", () => {
  test("absent opt-in preserves ordinary upstream configuration", () => {
    expect(
      freshBootstrapStartup({ DATABASE_URL: "ordinary", DEV_MODE: "true" })
    ).toBeNull();
    expect(() => assertOrdinaryHttpEntrypoint({})).not.toThrow();
  });
  test("accepts only coherent generated configuration without I/O or exposing credentials", () => {
    const env = Object.freeze(environment());
    const result = freshBootstrapStartup(env);
    expect(result).toEqual({
      localOnly: true,
      namespaceId: id,
      databaseCertificateSha256: "a".repeat(64),
      jwksCertificateSha256: "b".repeat(64),
    });
    expect(Object.isFrozen(result)).toBe(true);
    expect(JSON.stringify(result)).not.toContain(env.DATABASE_URL);
    expect(JSON.stringify(result)).not.toContain(env.LOGIN_CODE_PEPPER);
  });
  test.each(
    Object.keys(environment()).filter(
      (key) => key !== "FNCP_FRESH_BOOTSTRAP_LOCAL_ONLY"
    )
  )("rejects missing required input %s", (key) => {
    const env = environment();
    delete env[key];
    expect(() => freshBootstrapStartup(env)).toThrow(
      "FNCP_FRESH_BOOTSTRAP_CONFIGURATION_INVALID"
    );
  });
  test.each([
    "AUTH_ISSUER",
    "DATABASE_URL",
    "LOGIN_CODE_PEPPER",
    "ENCRYPTION_PASSWORD_00001",
    "FNCP_BOOTSTRAP_DATABASE_CERTIFICATE_SHA256",
    "FNCP_BOOTSTRAP_JWKS_CERTIFICATE_SHA256",
  ])("rejects noncanonical line endings in %s", (key) => {
    for (const ending of ["\n", "\r", "\r\n"]) {
      const env = environment();
      env[key] += ending;
      if (key === "DATABASE_URL") env.READ_ONLY_DATABASE_URL = env.DATABASE_URL;
      expect(() => freshBootstrapStartup(env)).toThrow(
        "FNCP_FRESH_BOOTSTRAP_CONFIGURATION_INVALID"
      );
    }
  });
  test.each(["false", "TRUE", "1", "", " true", "true\n"])(
    "malformed opt-in %p never falls back",
    (value) => {
      expect(() =>
        freshBootstrapStartup({
          ...environment(),
          FNCP_FRESH_BOOTSTRAP_LOCAL_ONLY: value,
        })
      ).toThrow();
      expect(() =>
        assertOrdinaryHttpEntrypoint({ FNCP_FRESH_BOOTSTRAP_LOCAL_ONLY: value })
      ).toThrow();
    }
  );
  test.each([
    "FNCP_OPTION_C_RELEASE_MODE",
    "FNCP_GATEWAY_ENFORCEMENT",
    "FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT",
    "FNCP_UNREVIEWED_CONTROL",
    "DOMAIN_WHITELIST_ITEM_01",
    "AUTH_DOMAIN",
    "AUTH0_DOMAIN",
    "AUTH_CLIENT_ID",
    "AUTH0_CLIENT_SECRET",
    "AUTH_NAMESPACE",
    "AKISMET_ANTISPAM_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_CREDENTIALS_BASE64",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "MAILGUN_API_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_PROFILE",
    "AWS_CONFIG_FILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "SES_ENDPOINT",
    "DYNAMODB_ENDPOINT",
    "AWS_S3_ENDPOINT",
    "SQS_QUEUE_URL",
    "ADMIN_EMAIL_DATA_EXPORT",
    "POLIS_FROM_ADDRESS",
    "JWT_PRIVATE_KEY",
    "JWT_PUBLIC_KEY",
    "PORT",
    "NODE_OPTIONS",
    "NODE_PATH",
    "NODE_EXTRA_CA_CERTS",
    "NODE_USE_SYSTEM_CA",
    "NODE_TLS_REJECT_UNAUTHORIZED",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "PGHOST",
    "PGPORT",
    "PGPASSWORD",
    "PGPASSFILE",
    "PGSERVICE",
    "PGSSLROOTCERT",
    "PGSSLMODE",
    "PGOPTIONS",
    "PGCLIENT_ENCODING",
    "PGREPLICATION",
    "PGAPPNAME",
    "PGCONNECT_TIMEOUT",
    "PGBINARY",
    "NODE_PG_FORCE_NATIVE",
  ])(
    "rejects inherited or dedicated-release input %s even when blank",
    (key) => {
      for (const value of ["", "false", "sensitive-sentinel"]) {
        expect(() =>
          freshBootstrapStartup({ ...environment(), [key]: value })
        ).toThrow("FNCP_FRESH_BOOTSTRAP_CONFIGURATION_INVALID");
      }
    }
  );
  test.each([
    ["DATABASE_URL", "postgres://real:secret@example.invalid/real"],
    ["READ_ONLY_DATABASE_URL", "postgres://elsewhere.invalid"],
    ["DATABASE_SSL", "false"],
    ["DEV_MODE", "true"],
    ["NODE_ENV", "development"],
    ["AUTH_ISSUER", "https://127.0.0.1:999/"],
    ["AUTH_ISSUER", "https://127.0.0.1:65536/"],
    ["AUTH_ISSUER", "https://localhost:23456/"],
    ["AUTH_ISSUER", "https://127.0.0.1:02345/"],
    [
      "JWKS_URI",
      `https://fncp-fresh-jwks-${"f".repeat(24)}:8444/.well-known/jwks.json`,
    ],
    ["JWKS_URI", "http://example.invalid/jwks"],
    ["AUTH_AUDIENCE", "other"],
    ["EMAIL_TRANSPORT_TYPES", "ses"],
    ["ADMIN_EMAILS", '["nobody@example.invalid"]'],
    ["JWT_PRIVATE_KEY_PATH", "/app/keys/jwt-private.pem"],
    ["JWT_PUBLIC_KEY_PATH", "/app/keys/jwt-public.pem"],
    ["FNCP_BOOTSTRAP_DATABASE_CERTIFICATE_SHA256", "A".repeat(64)],
    ["FNCP_BOOTSTRAP_JWKS_CERTIFICATE_SHA256", "a".repeat(64)],
    ["LOGIN_CODE_PEPPER", "e".repeat(64)],
    ["LOGIN_CODE_PEPPER", "c".repeat(64)],
    ["DOMAIN_OVERRIDE", "pol.is"],
    ["API_PROD_HOSTNAME", "localhost:5000"],
  ])("rejects unsafe %s override", (key, value) => {
    expect(() =>
      freshBootstrapStartup({ ...environment(), [key]: value })
    ).toThrow("FNCP_FRESH_BOOTSTRAP_CONFIGURATION_INVALID");
  });
  test("errors never disclose rejected values", () => {
    const secret = "sensitive-sentinel";
    try {
      freshBootstrapStartup({ ...environment(), DATABASE_URL: secret });
    } catch (error) {
      expect(String(error)).not.toContain(secret);
      return;
    }
    throw new Error("expected rejection");
  });
  test("preserves independent fresh database/user names without treating them as ownership proof", () => {
    const env = environment();
    env.DATABASE_URL = `postgres://fncp_fresh_${"1".repeat(24)}:${"c".repeat(
      64
    )}@fncp-fresh-pg-${id}:5432/fncp_fresh_${"2".repeat(24)}`;
    env.READ_ONLY_DATABASE_URL = env.DATABASE_URL;
    expect(freshBootstrapStartup(env)?.namespaceId).toBe(id);
  });
  test("compiled ordinary entrypoint refuses opt-in before importing app or logger", () => {
    const source = fs.readFileSync(
      path.resolve(__dirname, "../../index.ts"),
      "utf8"
    );
    const compiled = ts.transpileModule(source, {
      compilerOptions: { module: ts.ModuleKind.CommonJS },
    }).outputText;
    const imports: string[] = [];
    expect(() =>
      vm.runInNewContext(compiled, {
        exports: {},
        process: { env: environment() },
        require(name: string) {
          imports.push(name);
          if (name === "./src/auth/fncp-bootstrap-startup")
            return { assertOrdinaryHttpEntrypoint };
          throw new Error("unexpected import");
        },
      })
    ).toThrow("FNCP_FRESH_BOOTSTRAP_REQUIRES_OWNED_HTTPS_ENTRYPOINT");
    expect(imports).toEqual(["./src/auth/fncp-bootstrap-startup"]);
  });
  test("compiled app opt-in bypasses dotenv and validates before application imports", () => {
    const source = fs.readFileSync(
      path.resolve(__dirname, "../../app.ts"),
      "utf8"
    );
    const compiled = ts.transpileModule(source, {
      compilerOptions: { module: ts.ModuleKind.CommonJS },
    }).outputText;
    const actions: string[] = [];
    expect(() =>
      vm.runInNewContext(compiled, {
        exports: {},
        process: { env: environment() },
        require(name: string) {
          if (name === "dotenv")
            return {
              config() {
                actions.push("dotenv-read");
              },
            };
          if (name === "./src/auth/fncp-bootstrap-startup")
            return {
              freshBootstrapStartup(env: Record<string, string>) {
                actions.push("validated");
                return freshBootstrapStartup(env);
              },
            };
          actions.push("next-import");
          throw new Error("test-stop-before-app-imports");
        },
      })
    ).toThrow("test-stop-before-app-imports");
    expect(actions).toEqual(["validated", "next-import"]);
  });
});
