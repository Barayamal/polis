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
const mathRunScript = readFileSync(
  join(repositoryRoot, "math", "bin", "run"),
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
const nginxSlimEvidence = JSON.parse(
  readFileSync(
    join(
      deployDirectory,
      "D8-NGINX-SLIM-IMAGE-EVIDENCE-2026-07-28.json",
    ),
    "utf8",
  ),
);
const alphaRuntimeEvidence = JSON.parse(
  readFileSync(
    join(
      deployDirectory,
      "D9-ALPHA-RUNTIME-SPLIT-EVIDENCE-2026-07-28.json",
    ),
    "utf8",
  ),
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

test("participant runtime crosses only reviewed build output into a fresh stage", () => {
  const buildStageIndex = alphaDockerfile.indexOf(" AS build");
  const buildIndex = alphaDockerfile.indexOf("RUN npm run build");
  const pruneIndex = alphaDockerfile.indexOf("RUN npm prune --omit=dev");
  const runtimeStageIndex = alphaDockerfile.indexOf(" AS runtime");
  const copyDistIndex = alphaDockerfile.indexOf(
    "COPY --from=build /app/dist ./dist",
  );
  const copyModulesIndex = alphaDockerfile.indexOf(
    "COPY --from=build /app/node_modules ./node_modules",
  );
  const commandIndex = alphaDockerfile.indexOf(
    'CMD ["node", "dist/server/entry.mjs"]',
  );

  assert.ok(buildStageIndex >= 0);
  assert.ok(buildIndex > buildStageIndex);
  assert.ok(pruneIndex > buildIndex);
  assert.ok(runtimeStageIndex > pruneIndex);
  assert.ok(copyDistIndex > runtimeStageIndex);
  assert.ok(copyModulesIndex > copyDistIndex);
  assert.ok(commandIndex > copyModulesIndex);
  assert.doesNotMatch(
    alphaDockerfile.slice(runtimeStageIndex),
    /^COPY (?!-{2}from=build\b)/mu,
  );

  for (const buildOnlyPath of [
    "node_modules/@esbuild",
    "node_modules/@img",
    "node_modules/astro/node_modules/@esbuild",
    "node_modules/astro/node_modules/esbuild",
    "node_modules/esbuild",
    "node_modules/sharp",
  ]) {
    assert.ok(
      alphaDockerfile.includes(buildOnlyPath),
      `missing build-only removal: ${buildOnlyPath}`,
    );
  }
  assert.match(alphaDockerfile, /find node_modules -type d/u);
  assert.match(alphaDockerfile, /-name '@esbuild'/u);
  assert.match(alphaDockerfile, /-name 'esbuild'/u);
  assert.match(alphaDockerfile, /-name 'sharp'/u);
  assert.match(alphaDockerfile, /-path '\*\/@img\/sharp-\*'/u);
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

test("participant runtime evidence rejects Sharp and esbuild package families", () => {
  assert.match(collector, /FNCP_CHECK_ALPHA_BUILD_TOOLS/u);
  assert.match(collector, /buildOnlyPackagePathsPresent/u);
  assert.match(collector, /entry\.name === "@esbuild"/u);
  assert.match(collector, /entry\.name === "esbuild"/u);
  assert.match(collector, /entry\.name === "sharp"/u);
  assert.match(collector, /entry\.name\.startsWith\("sharp-"\)/u);
});

test("math worker crosses only its runtime closure into a non-root stage", () => {
  const buildStageIndex = mathDockerfile.indexOf(" AS build");
  const dependencyIndex = mathDockerfile.indexOf("clojure -P -M:run");
  const runtimeStageIndex = mathDockerfile.indexOf(" AS runtime");
  const copyIndex = mathDockerfile.indexOf(
    "COPY --from=build --chown=65532:65532 /runtime/app ./",
  );
  const commandIndex = mathDockerfile.indexOf('CMD ["./bin/run"]');

  assert.ok(buildStageIndex >= 0);
  assert.ok(dependencyIndex > buildStageIndex);
  assert.ok(runtimeStageIndex > dependencyIndex);
  assert.ok(copyIndex > runtimeStageIndex);
  assert.ok(commandIndex > copyIndex);
  assert.match(mathDockerfile, /clojure -Spath -M:run/u);
  assert.match(
    mathDockerfile,
    /target="\/runtime\/app\/lib\/\$\(basename "\$artifact"\)"/u,
  );
  assert.match(mathDockerfile, /cmp -s "\$artifact" "\$target"/u);
  assert.match(
    mathDockerfile,
    /printf '%s' '\/app\/src:\/app\/resources' > \/runtime\/app\/classpath/u,
  );
  assert.match(
    mathDockerfile,
    /printf ':\/app\/lib\/%s' "\$\(basename "\$artifact"\)"/u,
  );
  assert.match(
    mathDockerfile,
    /Class\/forName "clojure\.core\.matrix\.random\.RandomSeq"/u,
  );
  assert.match(
    mathDockerfile,
    /file:\/app\/lib\/core\.matrix-0\.63\.0\.jar/u,
  );
  assert.doesNotMatch(mathDockerfile, /sha256sum/u);
  assert.match(mathDockerfile, /rm -rf \/usr\/local\/lib\/clojure/u);
  assert.match(mathDockerfile, /^USER 65532:65532$/mu);
  assert.doesNotMatch(mathDockerfile, /-M:dev/u);
});

test("math runtime bypasses the removed Clojure CLI and preserves restart bounds", () => {
  assert.match(mathRunScript, /trap stop_worker TERM INT/u);
  assert.match(mathRunScript, /kill -TERM "\$worker_pid"/u);
  assert.match(mathRunScript, /wait "\$worker_pid"/u);
  assert.match(mathRunScript, /timeout -s KILL 14400/u);
  assert.match(mathRunScript, /\/opt\/java\/openjdk\/bin\/java/u);
  assert.match(mathRunScript, /-Xmx4g/u);
  assert.match(
    mathRunScript,
    /classpath=\$\(cat \/app\/classpath\)/u,
  );
  assert.match(mathRunScript, /-cp "\$classpath"/u);
  assert.doesNotMatch(mathRunScript, /\/app\/lib\/\*/u);
  assert.match(mathRunScript, /clojure\.main/u);
  assert.match(mathRunScript, /-m polismath\.runner/u);
  assert.match(mathRunScript, /\n    full &\n/u);
  assert.match(mathRunScript, /worker_pid=\$!/u);
  assert.match(mathRunScript, /worker_status=\$\?/u);
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

test("nginx slim evidence is internally consistent and preserves the wider no-go", () => {
  const proxyLock = imageSecurityLock.baseImages.find(
    ({ component }) => component === "nginx-proxy",
  );
  const severityTotal = Object.values(nginxSlimEvidence.scan.severities).reduce(
    (sum, count) => sum + count,
    0,
  );
  const criticalOrHigh =
    nginxSlimEvidence.scan.severities.Critical +
    nginxSlimEvidence.scan.severities.High;

  assert.match(nginxSlimEvidence.source.imageCommit, /^[a-f0-9]{40}$/u);
  assert.equal(nginxSlimEvidence.source.treeState, "clean");
  assert.equal(nginxSlimEvidence.source.platform, imageSecurityLock.buildPlatform);
  assert.equal(nginxSlimEvidence.candidate.baseTag, proxyLock.tag);
  assert.equal(
    nginxSlimEvidence.candidate.baseIndexDigest,
    proxyLock.indexDigest,
  );
  assert.equal(
    nginxSlimEvidence.candidate.baseArm64Digest,
    proxyLock.arm64Digest,
  );
  assert.equal(
    nginxSlimEvidence.tooling.syft.version,
    imageSecurityLock.scannerImages.find(({ name }) => name === "syft").version,
  );
  assert.equal(
    nginxSlimEvidence.tooling.grype.version,
    imageSecurityLock.scannerImages.find(({ name }) => name === "grype").version,
  );
  assert.equal(severityTotal, nginxSlimEvidence.scan.total);
  assert.equal(
    nginxSlimEvidence.scan.findings.length,
    nginxSlimEvidence.scan.total,
  );
  assert.equal(criticalOrHigh, 0);
  assert.equal(nginxSlimEvidence.scan.imageCandidateGate, "pass");
  assert.equal(nginxSlimEvidence.runtimeChecks.configuration, "pass");
  assert.equal(
    nginxSlimEvidence.runtimeChecks.unknownRouteStatus,
    nginxSlimEvidence.runtimeChecks.expectedUnknownRouteStatus,
  );
  assert.equal(
    nginxSlimEvidence.runtimeChecks.disallowedMethodStatus,
    nginxSlimEvidence.runtimeChecks.expectedDisallowedMethodStatus,
  );
  assert.equal(nginxSlimEvidence.boundaries.productionDeployed, false);
  assert.equal(nginxSlimEvidence.overallOptionCGate, "fail");
});

test("alpha runtime evidence is internally consistent and preserves the wider no-go", () => {
  const alphaLock = imageSecurityLock.baseImages.find(
    ({ component }) => component === "client-participation-alpha",
  );
  const severityTotal = Object.values(
    alphaRuntimeEvidence.scan.severities,
  ).reduce((sum, count) => sum + count, 0);
  const findingOccurrences = alphaRuntimeEvidence.scan.findings.reduce(
    (sum, finding) => sum + finding.occurrences,
    0,
  );
  const criticalOrHigh =
    alphaRuntimeEvidence.scan.severities.Critical +
    alphaRuntimeEvidence.scan.severities.High;

  assert.match(alphaRuntimeEvidence.source.imageCommit, /^[a-f0-9]{40}$/u);
  assert.equal(alphaRuntimeEvidence.source.treeState, "clean");
  assert.equal(
    alphaRuntimeEvidence.source.platform,
    imageSecurityLock.buildPlatform,
  );
  assert.equal(alphaRuntimeEvidence.candidate.baseTag, alphaLock.tag);
  assert.equal(
    alphaRuntimeEvidence.candidate.baseIndexDigest,
    alphaLock.indexDigest,
  );
  assert.equal(
    alphaRuntimeEvidence.candidate.baseArm64Digest,
    alphaLock.arm64Digest,
  );
  assert.equal(
    alphaRuntimeEvidence.tooling.syft.version,
    imageSecurityLock.scannerImages.find(({ name }) => name === "syft").version,
  );
  assert.equal(
    alphaRuntimeEvidence.tooling.grype.version,
    imageSecurityLock.scannerImages.find(({ name }) => name === "grype").version,
  );
  assert.equal(severityTotal, alphaRuntimeEvidence.scan.total);
  assert.equal(findingOccurrences, alphaRuntimeEvidence.scan.total);
  assert.equal(criticalOrHigh, 5);
  assert.equal(alphaRuntimeEvidence.scan.imageCandidateGate, "fail");
  assert.equal(alphaRuntimeEvidence.runtimeChecks.packageBoundary, "pass");
  assert.deepEqual(alphaRuntimeEvidence.runtimeChecks.forbiddenPackagePaths, []);
  assert.equal(
    alphaRuntimeEvidence.runtimeChecks.globalNpmRuntimePresent,
    false,
  );
  assert.equal(alphaRuntimeEvidence.runtimeChecks.defaultCommandBoot, "pass");
  assert.equal(alphaRuntimeEvidence.runtimeChecks.proxyConfiguration, "pass");
  assert.equal(alphaRuntimeEvidence.runtimeChecks.directAstroImageStatus, 404);
  assert.equal(
    alphaRuntimeEvidence.runtimeChecks.alphaMountedAstroImageStatus,
    404,
  );
  assert.equal(alphaRuntimeEvidence.runtimeChecks.allowedApiStatus, 204);
  assert.equal(alphaRuntimeEvidence.runtimeChecks.disallowedMethodStatus, 405);
  assert.equal(alphaRuntimeEvidence.runtimeChecks.unknownRouteStatus, 404);
  assert.equal(alphaRuntimeEvidence.boundaries.productionDeployed, false);
  assert.equal(alphaRuntimeEvidence.overallOptionCGate, "fail");
});
