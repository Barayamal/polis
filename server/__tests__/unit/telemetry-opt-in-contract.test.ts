import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, test } from "@jest/globals";

describe("production telemetry opt-in contract", () => {
  test("dd-trace cannot initialize from production mode alone", () => {
    const indexSource = readFileSync(
      resolve(__dirname, "../../index.ts"),
      "utf8"
    );
    const configSource = readFileSync(
      resolve(__dirname, "../../src/config.ts"),
      "utf8"
    );

    expect(configSource).toContain(
      "enableTelemetry: isTrue(process.env.ENABLE_TELEMETRY)"
    );
    expect(indexSource).toContain(
      'if (Config.nodeEnv === "production" && Config.enableTelemetry)'
    );
    expect(indexSource).not.toMatch(
      /if \(Config\.nodeEnv === "production"\) \{\s*[\s\S]{0,160}require\("dd-trace"\)/
    );
  });
});
