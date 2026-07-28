import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, test } from "@jest/globals";

const packageJson = JSON.parse(
  readFileSync(resolve(__dirname, "../../package.json"), "utf8")
) as {
  dependencies: Record<string, string>;
  devDependencies: Record<string, string>;
};
const appSource = readFileSync(resolve(__dirname, "../../app.ts"), "utf8");
const fileFetcherSource = readFileSync(
  resolve(__dirname, "../../src/utils/file-fetcher.ts"),
  "utf8"
);
const moderationSource = readFileSync(
  resolve(__dirname, "../../src/utils/moderation.ts"),
  "utf8"
);
const serverMiddlewareSource = readFileSync(
  resolve(__dirname, "../../src/server-middleware.ts"),
  "utf8"
);

describe("minimal FNCP production dependency contract", () => {
  test("test and development HTTP clients stay outside production dependencies", () => {
    expect(packageJson.dependencies).not.toHaveProperty("axios");
    expect(packageJson.dependencies).not.toHaveProperty("morgan");
    expect(packageJson.devDependencies.axios).toBe("1.18.1");
    expect(packageJson.devDependencies.morgan).toBe("1.11.0");
    expect(appSource).not.toMatch(/import\s+morgan\s+from\s+"morgan"/);
    expect(appSource).toContain('const morgan = require("morgan")');
  });

  test("unused mail and CLI packages are absent", () => {
    for (const unused of [
      "nodemailer",
      "nodemailer-mailgun-transport",
      "optimist",
    ]) {
      expect(packageJson.dependencies).not.toHaveProperty(unused);
      expect(packageJson.devDependencies).not.toHaveProperty(unused);
    }
  });

  test("bounded compatible production upgrades are pinned", () => {
    expect(packageJson.dependencies["dd-trace"]).toBe("5.118.0");
    expect(packageJson.dependencies.underscore).toBe("1.13.8");
  });

  test("deprecated request clients are absent from the server runtime", () => {
    for (const dependency of [
      "request",
      "request-promise",
      "simple-oauth2",
    ]) {
      expect(packageJson.dependencies).not.toHaveProperty(dependency);
    }
    expect(packageJson.devDependencies).not.toHaveProperty(
      "@types/request-promise"
    );
    expect(fileFetcherSource).not.toMatch(
      /from\s+["']request(?:-promise)?["']|require\(["']request/u
    );
    expect(moderationSource).not.toMatch(
      /from\s+["']request(?:-promise)?["']|require\(["']request/u
    );
    expect(fileFetcherSource).toContain('redirect: "follow"');
    expect(moderationSource).toContain(
      "AbortSignal.timeout(IP_LOOKUP_TIMEOUT_MS)"
    );
  });

  test("unused direct middleware packages are absent without changing legacy Express semantics", () => {
    for (const dependency of [
      "body-parser",
      "compression",
      "connect-timeout",
    ]) {
      expect(packageJson.dependencies).not.toHaveProperty(dependency);
    }
    expect(packageJson.devDependencies).not.toHaveProperty(
      "@types/connect-timeout"
    );

    // Express 3 remains deliberately pinned: a major migration is outside the
    // bounded dependency-hardening work and needs its own compatibility plan.
    expect(packageJson.dependencies.express).toBe("~3.21.2");

    // Preserve the existing body limit, cookies, compression, proxy handling
    // and FNCP fail-closed middleware order while only replacing the one
    // direct connect-timeout call.
    expect(appSource).toContain('app.set("trust proxy", 1)');
    expect(appSource).toContain('express.bodyParser({ limit: "50mb" })');
    expect(appSource).toContain("express.cookieParser()");
    expect(appSource).toContain("express.compress()");
    expect(appSource).toMatch(
      /app\.use\(express\.cookieParser\(\)\);[\s\S]*app\.use\(fncpGatewayMiddleware\);[\s\S]*app\.use\(writeDefaultHead\);[\s\S]*app\.use\(express\.compress\(\)\);/
    );
    expect(appSource).toContain("requestTimeout(15_000)");
    expect(appSource).not.toMatch(/from\s+["']connect-timeout["']/u);
    expect(serverMiddlewareSource).toContain('error.code = "ETIMEDOUT"');
    expect(serverMiddlewareSource).toContain("error.timeout = delayMs");
  });
});
