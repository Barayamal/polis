import { afterAll, beforeAll, describe, expect, test } from "@jest/globals";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import ts from "typescript";

// Execute the entrypoint and its actual policy dependencies in fresh processes
// using the repository's CommonJS compiler options. Application/database stubs
// record observable module side effects; there is no database, dotenv, network
// client, global Jest setup or mocked admission implementation in this test.
const serverRoot = path.resolve(__dirname, "../..");
const actualModules = [
  "index.ts",
  "src/auth/fncp-bootstrap-startup.ts",
  "src/auth/fncp-production-admission.ts",
  "src/auth/fncp-gateway.ts",
  "src/auth/fncp-log-boundary.ts",
  "src/fncp-provider-config.ts",
  // Include the former transitive dependency so restoring the unsafe import
  // reproduces the database side effect instead of just a missing module.
  "src/fncp-provider-policy.ts",
];
const conversationId = "4fncpentrypoint";
const gatewayCredential = "g".repeat(48);
const providerCredential = "p".repeat(48);
function validEnvironment(
  overrides: NodeJS.ProcessEnv = {}
): NodeJS.ProcessEnv {
  return {
    NODE_ENV: "production",
    FNCP_FIXED_STATEMENT_IDS: Array.from({ length: 15 }, (_, i) => i).join(","),
    DATABASE_URL: "postgres://runtime:invented@database.invalid:5432/polis",
    DATABASE_SSL: "true",
    DATABASE_SSL_CA_FILE: "/run/fncp/ca.pem",
    FNCP_OPTION_C_RELEASE_MODE: "production",
    FNCP_GATEWAY_ENFORCEMENT: "true",
    FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT: "true",
    FNCP_GATEWAY_CONVERSATION_ID: conversationId,
    FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID: conversationId,
    FNCP_GATEWAY_SHARED_SECRET: gatewayCredential,
    FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL: providerCredential,
    ...overrides,
  };
}
let fixture: string;

beforeAll(() => {
  fixture = fs.mkdtempSync(path.join(os.tmpdir(), "fncp-entrypoint-test-"));
  const configPath = path.join(serverRoot, "tsconfig.json");
  const config = ts.readConfigFile(configPath, ts.sys.readFile);
  expect(config.error).toBeUndefined();
  const parsed = ts.parseJsonConfigFileContent(
    config.config,
    ts.sys,
    serverRoot
  );
  expect(parsed.errors).toEqual([]);
  expect(parsed.options.module).toBe(ts.ModuleKind.CommonJS);
  const write = (relative: string, source: string) => {
    const file = path.join(fixture, relative);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, source, { flag: "wx", mode: 0o600 });
  };
  for (const relative of actualModules) {
    const source = fs.readFileSync(path.join(serverRoot, relative), "utf8");
    const compiled = ts.transpileModule(source, {
      compilerOptions: { ...parsed.options, sourceMap: false },
      fileName: path.join(serverRoot, relative),
      reportDiagnostics: true,
    });
    expect(compiled.diagnostics).toEqual([]);
    write(relative.replace(/\.ts$/u, ".js"), compiled.outputText);
  }
  write(
    "app.js",
    `global.events.push('app'); module.exports = { listen(port, callback) {
      global.events.push('listen:' + port);
      const listener = new (require('node:events').EventEmitter)();
      listener.close = cb => cb(); listener.closeIdleConnections = () => {};
      if (callback) setImmediate(callback); return listener; } };
      module.exports.appReady = Promise.resolve().then(() => { global.events.push('routes');
        if (process.env.FIXTURE_FAIL === 'routes') throw Error('private fixture route failure'); });`
  );
  write(
    "src/config.js",
    `global.events.push('config'); module.exports = {
      nodeEnv: 'production', enableTelemetry: true, serverPort: 5915 };`
  );
  write(
    "src/utils/logger.js",
    `global.events.push('logger'); module.exports = {
      info() { global.events.push('log'); }, error() { global.events.push('error-log'); } };`
  );
  write(
    "node_modules/dd-trace/index.js",
    `global.events.push('telemetry-import'); module.exports = {
      init() { global.events.push('telemetry-init'); } };`
  );
  write(
    "src/auth/fncp-production-runtime.js",
    `global.events.push('runtime-import'); module.exports = {
      async prepareFncpProductionRuntime() { global.events.push('runtime-ready');
        if (process.env.FIXTURE_FAIL === 'database') throw Error('private fixture database failure'); },
      async closeFncpProductionRuntime() { global.events.push('runtime-close'); } };`
  );
  write(
    "src/db/pg-query.js",
    `global.events.push('database'); throw Error('DATABASE_SIDE_EFFECT_LOADED');`
  );
  write(
    "probe.cjs",
    `global.events = [];
    (async () => { try {
      const entry = require('./index.js');
      await entry.serverStartup;
      process.stdout.write(JSON.stringify({ outcome: 'STARTED', events: global.events }));
    } catch (error) {
      process.stdout.write(JSON.stringify({ outcome: 'REJECTED', events: global.events,
        name: error.name, failure: error.failure, message: error.message }));
      process.exitCode = 1;
    } })();`
  );
});

afterAll(() => {
  if (fixture) fs.rmSync(fixture, { recursive: true, force: true });
});

function run(env: NodeJS.ProcessEnv) {
  const result = spawnSync(
    process.execPath,
    [path.join(fixture, "probe.cjs")],
    {
      cwd: fixture,
      env,
      encoding: "utf8",
      timeout: 5000,
      maxBuffer: 16384,
    }
  );
  expect(result.error).toBeUndefined();
  expect(result.signal).toBeNull();
  expect(result.stderr).toBe("");
  expect(result.stdout).not.toContain(conversationId);
  expect(result.stdout).not.toContain(gatewayCredential);
  expect(result.stdout).not.toContain(providerCredential);
  return { status: result.status, body: JSON.parse(result.stdout) };
}

describe("compiled dedicated production entrypoint admission", () => {
  test.each(["routes", "database"])("never listens after failed %s readiness and closes runtime", failure => {
    const result = run(validEnvironment({ FIXTURE_FAIL: failure }));
    expect(result.status).toBe(1);
    expect(result.body.outcome).toBe("REJECTED");
    expect(result.body.message).toBe("FNCP_PRODUCTION_STARTUP_FAILED");
    expect(result.body.events).toContain("runtime-close");
    expect(result.body.events).not.toContain("listen:5915");
    expect(JSON.stringify(result)).not.toContain("private fixture");
  });
  test("an otherwise empty dedicated image fails at admission before all application side effects", () => {
    expect(
      run({ NODE_ENV: "production", FNCP_OPTION_C_RELEASE_MODE: "production" })
    ).toEqual({
      status: 1,
      body: {
        outcome: "REJECTED",
        events: [],
        name: "FncpProductionAdmissionError",
        failure: "gateway-enforcement",
        message:
          "FNCP dedicated production admission failed (gateway-enforcement).",
      },
    });
  });

  test.each([
    ["release-mode", { FNCP_OPTION_C_RELEASE_MODE: "prod" }],
    ["node-environment", { NODE_ENV: "development" }],
    ["gateway-enforcement", { FNCP_GATEWAY_ENFORCEMENT: "false" }],
    ["provider-enforcement", { FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT: "false" }],
    [
      "conversation-binding",
      { FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID: "4different" },
    ],
    ["gateway-credential", { FNCP_GATEWAY_SHARED_SECRET: "short" }],
    [
      "provider-credential",
      { FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL: "short" },
    ],
    [
      "credential-separation",
      { FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL: gatewayCredential },
    ],
  ] as const)(
    "rejects %s without initializing application modules",
    (failure, overrides) => {
      const result = run(validEnvironment(overrides));
      expect(result.status).toBe(1);
      expect(result.body).toEqual({
        outcome: "REJECTED",
        events: [],
        name: "FncpProductionAdmissionError",
        failure,
        message: `FNCP dedicated production admission failed (${failure}).`,
      });
    }
  );

  test.each([undefined, "production"])(
    "preserves admitted startup when dedicated mode is %p",
    (releaseMode) => {
      const env = releaseMode === undefined ? {} : validEnvironment();
      const result = run(env);
      expect(result).toEqual({
        status: 0,
        body: {
          outcome: "STARTED",
          events: [
            "app",
            "config",
            "logger",
            "telemetry-import",
            "telemetry-init",
            ...(releaseMode === undefined ? ["listen:5915", "log", "routes"] :
              ["routes", "runtime-import", "runtime-ready", "listen:5915", "log"]),
          ],
        },
      });
    }
  );

  test.each(["true", "false", ""])(
    "the ordinary HTTP entrypoint still refuses bootstrap opt-in %p before dedicated admission",
    (bootstrapMode) => {
      const result = run({
        NODE_ENV: "production",
        FNCP_OPTION_C_RELEASE_MODE: "production",
        FNCP_FRESH_BOOTSTRAP_LOCAL_ONLY: bootstrapMode,
      });
      expect(result).toEqual({
        status: 1,
        body: {
          outcome: "REJECTED",
          events: [],
          name: "Error",
          message: "FNCP_FRESH_BOOTSTRAP_REQUIRES_OWNED_HTTPS_ENTRYPOINT",
        },
      });
    }
  );
});
