import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../../", import.meta.url);
const json = async (path) => JSON.parse(await readFile(new URL(path, root), "utf8"));

test("server keeps the reviewed scoped production security patches", async () => {
  const manifest = await json("server/package.json");
  const lock = await json("server/package-lock.json");
  assert.equal(manifest.overrides["brace-expansion@^5.0.2"], "5.0.9");
  assert.equal(manifest.overrides["js-yaml@4.3.0"], "4.3.2");
  assert.equal(manifest.overrides["qs@^6"], "6.16.0");
  for (const [path, version] of [
    ["node_modules/@google-cloud/translate/node_modules/brace-expansion", "5.0.9"],
    ["node_modules/@datadog/wasm-js-rewriter/node_modules/js-yaml", "4.3.2"],
    ["node_modules/qs", "6.16.0"],
  ]) {
    const entry = lock.packages[path];
    assert.ok(entry, path);
    assert.equal(entry.version, version, path);
    assert.notEqual(entry.dev, true, `${path} is part of the production closure`);
    assert.match(entry.integrity, /^sha512-/u);
  }
});

test("server retains reviewed same-major development patches", async () => {
  const manifest = await json("server/package.json");
  const lock = await json("server/package-lock.json");
  for (const [selector, version] of Object.entries({
    "@babel/core@^7": "7.29.6",
    "@babel/plugin-transform-modules-systemjs@^7": "7.29.4",
    "ajv@^6": "6.14.0",
    "brace-expansion@^1": "1.1.18",
    "brace-expansion@^2": "2.1.4",
    "browserslist@^4": "4.28.7",
    "diff@^4": "4.0.4",
    "flatted@^3": "3.4.2",
    "js-yaml@^3": "3.15.2",
    "minimatch@^5": "5.1.8",
  })) {
    assert.equal(manifest.overrides[selector], version, selector);
    const name = selector.slice(0, selector.lastIndexOf("@"));
    assert.ok(Object.entries(lock.packages).some(([path, entry]) =>
      path.endsWith(`/node_modules/${name}`) || path === `node_modules/${name}`
        ? entry.version === version && entry.dev === true
        : false), `${name} ${version} must resolve in the development closure`);
  }
  assert.equal(manifest.devDependencies.morgan, "1.12.1");
  assert.equal(lock.packages["node_modules/morgan"].version, "1.12.1");
});

test("server locks the separately tested CSV and Nodemon major-line migrations", async () => {
  const manifest = await json("server/package.json");
  const lock = await json("server/package-lock.json");
  assert.equal(manifest.dependencies["csv-parse"], "7.0.2");
  assert.equal(manifest.devDependencies.nodemon, "3.1.14");
  assert.equal(lock.packages["node_modules/csv-parse"].version, "7.0.2");
  assert.notEqual(lock.packages["node_modules/csv-parse"].dev, true);
  assert.equal(lock.packages["node_modules/nodemon"].version, "3.1.14");
  assert.equal(lock.packages["node_modules/nodemon"].dev, true);
  assert.equal(lock.packages["node_modules/simple-update-notifier"].version, "2.0.0");
  assert.equal(lock.packages["node_modules/simple-update-notifier"].dependencies.semver, "^7.5.3");
  assert.equal(lock.packages["node_modules/simple-update-notifier/node_modules/semver"].version, "7.8.5");
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (path === "node_modules/semver" || path.endsWith("/node_modules/semver")) {
      const [major, minor, patch] = entry.version.split(".").map(Number);
      assert.ok(major !== 7 || minor > 5 || (minor === 5 && patch >= 2), path);
    }
  }
});

test("alpha pins reviewed build-tool patches without flattening incompatible major lines", async () => {
  const manifest = await json("client-participation-alpha/package.json");
  const lock = await json("client-participation-alpha/package-lock.json");
  for (const [selector, version] of Object.entries({
    "@humanfs/node@^0.16": "0.16.8",
    "ajv@^6": "6.14.0",
    "brace-expansion@^1": "1.1.18",
    "brace-expansion@^5": "5.0.9",
    "diff@^4": "4.0.4",
    "flatted@^3": "3.4.2",
    "handlebars@^4": "4.7.9",
    "minimatch@^3": "3.1.4",
    "minimatch@^9": "9.0.7",
    "nanoid@^3": "3.3.18",
    "postcss-selector-parser@^7": "7.1.3",
    "ws@^8": "8.21.1",
  })) {
    assert.equal(manifest.overrides[selector], version, selector);
    const name = selector.slice(0, selector.lastIndexOf("@"));
    assert.ok(Object.entries(lock.packages).some(([path, entry]) =>
      path.endsWith(`/node_modules/${name}`) || path === `node_modules/${name}`
        ? entry.version === version && entry.dev === true
        : false), `${name} ${version} must resolve in the development closure`);
  }
  assert.equal(lock.packages["node_modules/anymatch/node_modules/picomatch"].version, "2.3.2");
  assert.equal(lock.packages["node_modules/picomatch"].version, "4.0.5");
});

test("alpha locks the reviewed Astro and adapter security upgrade", async () => {
  const manifest = await json("client-participation-alpha/package.json");
  const lock = await json("client-participation-alpha/package-lock.json");
  for (const [name, version] of [
    ["astro", "7.3.2"],
    ["@astrojs/node", "11.1.5"],
    ["@astrojs/react", "6.0.5"],
  ]) {
    assert.equal(manifest.devDependencies[name], version);
    assert.equal(lock.packages[`node_modules/${name}`].version, version);
    assert.equal(lock.packages[""].devDependencies[name], version);
  }
  assert.equal(manifest.overrides["js-yaml"], "4.3.2");
  assert.equal(lock.packages["node_modules/js-yaml"].version, "4.3.2");
});

test("security upgrade retains passthrough images and reviewed output boundary checks", async () => {
  const config = await readFile(new URL("client-participation-alpha/astro.config.mjs", root), "utf8");
  const checks = await readFile(new URL("client-participation-alpha/scripts/fncp-built-boundaries.test.mjs", root), "utf8");
  assert.match(config, /service:\s*passthroughImageService\(\)/u);
  assert.match(checks, /astro\\\/assets\\\/services\\\/sharp/u);
  assert.match(checks, /built SSR output uses Astro passthrough images/u);
});
