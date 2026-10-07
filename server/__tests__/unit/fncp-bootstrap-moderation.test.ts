/** Subject module with explicit doubles; no real config, prompts, SDK/network. */
import { afterEach, beforeEach, expect, jest, test } from "@jest/globals";

function fixture(fresh: boolean) {
  const readFile: any = jest.fn(async () => "synthetic XML");
  const convertXML: any = jest.fn(async () => ({}));
  const sdk = jest.fn();
  const logger = { error: jest.fn(), debug: jest.fn() };
  jest.doMock("../../src/config", () => ({
    __esModule: true,
    default: { freshBootstrapLocalOnly: fresh },
  }));
  jest.doMock("fs/promises", () => ({
    __esModule: true,
    default: { readFile },
  }));
  jest.doMock("simple-xml-to-json", () => ({ convertXML }));
  jest.doMock("@google/genai", () => ({ GoogleGenAI: sdk }));
  jest.doMock("js2xmlparser", () => ({ parse: jest.fn() }));
  jest.doMock("../../src/utils/logger", () => ({
    __esModule: true,
    default: logger,
  }));
  const module = require("../../src/utils/moderation");
  return { module, readFile, convertXML, sdk, logger };
}

beforeEach(() => jest.resetModules());
afterEach(() => {
  jest.restoreAllMocks();
  jest.resetModules();
});

test("fresh module import reads no prompts and starts no moderation work", async () => {
  const h = fixture(true);
  await Promise.resolve();
  expect(h.readFile).not.toHaveBeenCalled();
  expect(h.convertXML).not.toHaveBeenCalled();
  expect(h.sdk).not.toHaveBeenCalled();
});

test.each([undefined, "", "192.0.2.1"])(
  "fresh analysis rejects before prompt/geolocation/SDK work (%s)",
  async (ip) => {
    const h = fixture(true);
    const fetch = jest.spyOn(globalThis, "fetch");
    await expect(h.module.default("invented", "synthetic", ip)).rejects.toThrow(
      "FNCP_FRESH_BOOTSTRAP_MODERATION_DISABLED"
    );
    expect(h.readFile).not.toHaveBeenCalled();
    expect(h.convertXML).not.toHaveBeenCalled();
    expect(h.sdk).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
    expect(h.logger.error).not.toHaveBeenCalled();
    expect(h.logger.debug).not.toHaveBeenCalled();
  }
);

test.each(["", "192.0.2.1", "127.0.0.1"])(
  "fresh geolocation rejects without fetch (%s)",
  async (ip) => {
    const h = fixture(true);
    const fetch = jest.spyOn(globalThis, "fetch");
    await expect(h.module.getRegionFromIP(ip)).rejects.toThrow(
      "FNCP_FRESH_BOOTSTRAP_MODERATION_DISABLED"
    );
    expect(fetch).not.toHaveBeenCalled();
    expect(h.logger.error).not.toHaveBeenCalled();
  }
);

test("ordinary import still loads the two existing prompts", async () => {
  const h = fixture(false);
  await Promise.resolve();
  await Promise.resolve();
  expect(h.readFile.mock.calls).toEqual([
    ["src/prompts/moderation/script.xml", "utf8"],
    ["src/prompts/report_experimental/system.xml", "utf8"],
  ]);
});

test("ordinary absent IP retains its no-fetch regional fallback", async () => {
  const h = fixture(false);
  const fetch = jest.spyOn(globalThis, "fetch");
  await expect(h.module.getRegionFromIP("")).resolves.toBe("US or Europe (EU)");
  expect(fetch).not.toHaveBeenCalled();
});
