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

  test("deprecated request packages remain until both runtime callers migrate", () => {
    expect(packageJson.dependencies.request).toBe("~2.88.2");
    expect(packageJson.dependencies["request-promise"]).toBe("~4.2.6");
    expect(fileFetcherSource).toMatch(/import request from "request-promise"/);
    expect(moderationSource).toMatch(/import request from "request-promise"/);
  });
});
