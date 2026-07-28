import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const deployDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(deployDirectory, "../..");
const evidenceTool = join(deployDirectory, "image-security-evidence.mjs");
const collector = readFileSync(
  join(deployDirectory, "collect-image-security-evidence.sh"),
  "utf8",
);
const serverDockerignore = readFileSync(
  join(repositoryRoot, "server", ".dockerignore"),
  "utf8",
);
const serverDockerfile = readFileSync(
  join(repositoryRoot, "server", "Dockerfile"),
  "utf8",
);
const alphaDockerfile = readFileSync(
  join(repositoryRoot, "client-participation-alpha", "Dockerfile"),
  "utf8",
);
const mathDockerfile = readFileSync(
  join(repositoryRoot, "math", "Dockerfile"),
  "utf8",
);
const oidcDockerfile = readFileSync(
  join(repositoryRoot, "oidc-simulator", "Dockerfile"),
  "utf8",
);
const alphaDockerignore = readFileSync(
  join(repositoryRoot, "client-participation-alpha", ".dockerignore"),
  "utf8",
);
const mathDockerignore = readFileSync(
  join(repositoryRoot, "math", ".dockerignore"),
  "utf8",
);
const oidcDockerignore = readFileSync(
  join(repositoryRoot, "oidc-simulator", ".dockerignore"),
  "utf8",
);
const proxyDockerignore = readFileSync(
  join(deployDirectory, ".dockerignore"),
  "utf8",
);
const proxyDockerfile = readFileSync(
  join(deployDirectory, "nginx", "Dockerfile"),
  "utf8",
);
const imageSecurityLock = JSON.parse(
  readFileSync(join(deployDirectory, "image-security.lock.json"), "utf8"),
);

function runTool(...args) {
  return JSON.parse(
    execFileSync("node", [evidenceTool, ...args], {
      cwd: repositoryRoot,
      encoding: "utf8",
    }),
  );
}

test("all application base images and scanners are locked by digest", () => {
  const result = runTool("validate-lock");
  assert.deepEqual(result, {
    status: "pass",
    baseImages: 6,
    scannerImages: 2,
    buildPlatform: "linux/arm64",
  });
});

test("source manifest covers the complete non-ignored working tree", () => {
  const result = runTool("source-manifest");
  assert.match(result.source.commit, /^[a-f0-9]{40}$/u);
  assert.match(result.source.aggregateSha256, /^[a-f0-9]{64}$/u);
  assert.ok(result.source.fileCount > 100);
  assert.equal(result.source.files.length, result.source.fileCount);
  assert.ok(
    result.source.files.some(
      ({ path }) => path === "deploy/fncp/image-security.lock.json",
    ),
  );
});

test("collector is local-only, immutable-tooling and no-overwrite", () => {
  assert.match(collector, /Refusing to overwrite existing evidence/u);
  assert.match(collector, /docker compose[\s\S]+build --pull/u);
  assert.match(collector, /FNCP_SKIP_SCAN_BUILD/u);
  assert.match(collector, /docker run --rm/u);
  assert.match(collector, /scanner-ref syft/u);
  assert.match(collector, /scanner-ref grype/u);
  assert.match(collector, /GRYPE_DB_CACHE_DIR=\/grype-cache/u);
  assert.match(
    collector,
    /\$OUTPUT_DIR\/grype-cache:\/grype-cache/u,
  );
  assert.match(collector, /runtime-assertions\/\$service\.json/u);
  assert.match(collector, /generatedKeysDirectoryPresent/u);
  assert.match(collector, /developmentPackageSentinelsPresent/u);
  assert.match(collector, /TREE_STATE[\s\S]+FNCP_ALLOW_DIRTY_SOURCE/u);
  assert.doesNotMatch(collector, /\bdocker\s+(?:push|login)\b/u);
  assert.doesNotMatch(collector, /\b(?:aws|gcloud|az)\b/u);
});

test("generated participant JWT keys cannot enter the server build context", () => {
  assert.match(serverDockerignore, /^keys\/$/mu);
});

test("server final runtime prunes direct development dependencies", () => {
  const buildIndex = serverDockerfile.indexOf("RUN npm run build");
  const pruneIndex = serverDockerfile.indexOf("RUN npm prune --omit=dev");
  const removeNpmIndex = serverDockerfile.indexOf(
    "rm -rf /usr/local/lib/node_modules/npm",
  );
  const commandIndex = serverDockerfile.indexOf(
    'CMD ["node", "--max_old_space_size=2048", "--gc_interval=100", "dist/index.js"]',
  );
  assert.ok(buildIndex >= 0);
  assert.ok(pruneIndex > buildIndex);
  assert.ok(removeNpmIndex > pruneIndex);
  assert.ok(commandIndex > removeNpmIndex);
});

test("participant image build does not submit Astro telemetry", () => {
  assert.match(alphaDockerfile, /^ENV ASTRO_TELEMETRY_DISABLED=1$/mu);
});

test("other Node final runtimes prune direct development dependencies", () => {
  for (const dockerfile of [alphaDockerfile, oidcDockerfile]) {
    const buildIndex = dockerfile.indexOf("RUN npm run build");
    const pruneIndex = dockerfile.indexOf("RUN npm prune --omit=dev");
    const commandIndex = dockerfile.indexOf("CMD ");
    assert.ok(buildIndex >= 0);
    assert.ok(pruneIndex > buildIndex);
    assert.ok(commandIndex > pruneIndex);
  }
});

test("participant-facing Node runtimes remove the global npm CLI", () => {
  for (const dockerfile of [serverDockerfile, alphaDockerfile]) {
    assert.match(
      dockerfile,
      /rm -rf \/usr\/local\/lib\/node_modules\/npm \/usr\/local\/bin\/npm \/usr\/local\/bin\/npx/u,
    );
  }
  assert.match(collector, /globalNpmRuntimePresent/u);
});

test("math worker resolves only its runtime alias", () => {
  assert.match(mathDockerfile, /RUN clojure -P -M:run$/mu);
  assert.doesNotMatch(mathDockerfile, /-M:dev/u);
});

test("participant build context excludes local dependencies and output", () => {
  assert.match(alphaDockerignore, /^node_modules\/$/mu);
  assert.match(alphaDockerignore, /^dist\/$/mu);
  assert.match(alphaDockerignore, /^\.env\.\*$/mu);
});

test("every broad-copy build context excludes generated secrets", () => {
  for (const ignore of [
    serverDockerignore,
    alphaDockerignore,
    mathDockerignore,
    oidcDockerignore,
  ]) {
    assert.match(ignore, /^\.env\.\*$/mu);
    assert.match(ignore, /^keys\/$/mu);
  }
  assert.match(mathDockerignore, /^certs\/$/mu);
  assert.match(oidcDockerignore, /^certs\/$/mu);
});

test("proxy build context is deny-all with two exact source allows", () => {
  const rules = proxyDockerignore.trim().split("\n");
  assert.deepEqual(rules, [
    "**",
    "!nginx/",
    "!nginx/Dockerfile",
    "!nginx/fncp-staging.conf",
  ]);
});

test("proxy uses an exact supported nginx stable release on current Alpine", () => {
  const proxyLock = imageSecurityLock.baseImages.find(
    ({ component }) => component === "nginx-proxy",
  );
  assert.ok(proxyLock);
  assert.match(
    proxyLock.tag,
    /^docker\.io\/library\/nginx:\d+\.\d+\.\d+-alpine3\.24-slim$/u,
  );
  assert.doesNotMatch(proxyLock.tag, /(?:latest|stable|mainline)/u);
  assert.match(
    proxyDockerfile,
    new RegExp(
      `^FROM ${proxyLock.tag.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}@${proxyLock.indexDigest}$`,
      "mu",
    ),
  );
});
