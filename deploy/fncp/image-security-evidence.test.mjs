import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { validateDockerfileBaseReferences } from "./image-security-evidence.mjs";

const deployDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(deployDirectory, "../..");
const evidenceTool = join(deployDirectory, "image-security-evidence.mjs");
const evidenceToolSource = readFileSync(evidenceTool, "utf8");
const ciWorkflow = readFileSync(
  join(repositoryRoot, ".github", "workflows", "fncp-option-c-ci.yml"),
  "utf8",
);
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

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function createSyntheticEvidenceDirectory() {
  const directory = mkdtempSync(join(tmpdir(), "fncp-image-evidence-"));
  mkdirSync(join(directory, "sbom"));
  mkdirSync(join(directory, "scan"));
  mkdirSync(join(directory, "runtime-assertions"));
  const services = [
    "server",
    "math",
    "client-participation-alpha",
    "nginx-proxy",
    "polis-migration",
  ];
  const images = services.map((service, index) => ({
    service,
    reference: `fncp-${service}:latest`,
    imageId: `sha256:${String(index + 1).padStart(64, "0")}`,
    repoDigests: [],
    architecture: "arm64",
    os: "linux",
    created: "2026-07-28T00:00:00.000Z",
    size: 1,
    rootFsLayers: ["sha256:layer"],
  }));
  writeJson(join(directory, "image-index.json"), {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    projectName: "fncp-synthetic",
    scanScope: "arm64-candidate-five",
    images,
  });
  const database = {
    status: {
      schemaVersion: "v6.1.9",
      from: "https://grype.anchore.io/databases/reviewed",
      built: new Date().toISOString(),
      valid: true,
    },
    providers: { synthetic: { captured: "reviewed" } },
  };
  for (const image of images) {
    const digest = image.imageId.slice("sha256:".length);
    writeJson(join(directory, "sbom", `${image.service}.cdx.json`), {
      bomFormat: "CycloneDX",
      specVersion: "1.7",
      metadata: {
        tools: {
          components: [
            {
              name: "syft",
              version: imageSecurityLock.scannerImages.find(
                ({ name }) => name === "syft",
              ).version,
            },
          ],
        },
        component: { type: "container", version: digest },
        properties: [
          {
            name: "syft:image:labels:com.docker.compose.service",
            value: image.service,
          },
        ],
      },
      components: [],
    });
    writeJson(join(directory, "scan", `${image.service}.grype.json`), {
      descriptor: {
        name: "grype",
        version: imageSecurityLock.scannerImages.find(
          ({ name }) => name === "grype",
        ).version,
        configuration: {
          "check-for-app-update": false,
          db: { "auto-update": false },
        },
        db: database,
      },
      source: {
        type: "image",
        target: {
          manifestDigest: digest,
          labels: {
            "com.docker.compose.service": image.service,
          },
        },
      },
      matches: [],
    });
    const assertion = {
      status: "pass",
      artifact: image.service,
      effectiveUser: "non-root",
    };
    if (["server", "client-participation-alpha"].includes(image.service)) {
      Object.assign(assertion, {
        developmentPackageSentinelsPresent: [],
        generatedKeysDirectoryPresent: false,
        globalNpmRuntimePresent: false,
        packageManagerRuntimePathsPresent: [],
        buildOnlyPackagePathsPresent: [],
        expectedAlpinePackages: [],
        alpinePackageMismatches: [],
      });
    } else if (image.service === "math") {
      assertion.clojureBuildToolPresent = false;
    } else if (image.service === "nginx-proxy") {
      assertion.reviewedConfigPresent = true;
    } else {
      Object.assign(assertion, {
        migrationRunner: "/usr/local/bin/fncp-run-migrations",
        migrationRunnerPresent: true,
        requiredToolsPresent: true,
        serverAndLifecycleToolsPresent: false,
        initdbHooksPresent: false,
        topLevelMigrationsOnly: true,
        psqlPresent: true,
        postgresServerPresent: false,
      });
    }
    writeJson(
      join(directory, "runtime-assertions", `${image.service}.json`),
      assertion,
    );
  }
  return { directory, images };
}

test("all application base images and scanners are locked by digest", () => {
  const result = runTool("validate-lock");
  assert.deepEqual(result, {
    status: "pass",
    baseImages: 11,
    scannerImages: 2,
    buildPlatform: "linux/arm64",
  });
  assert.match(
    imageSecurityLock.dockerfileFrontend.indexDigest,
    /^sha256:[a-f0-9]{64}$/u,
  );
  assert.match(
    serverDockerfile,
    new RegExp(
      `^# syntax=${imageSecurityLock.dockerfileFrontend.tag.replace(
        /[.*+?^${}()|[\]\\]/gu,
        "\\$&",
      )}@${imageSecurityLock.dockerfileFrontend.indexDigest}$`,
      "mu",
    ),
  );
});

test("Dockerfile policy rejects malformed, missing and extra external FROM instructions", () => {
  const reviewed =
    "docker.io/library/node:24-alpine@" +
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  assert.doesNotThrow(() =>
    validateDockerfileBaseReferences(
      "Dockerfile",
      [
        `FROM ${reviewed} AS build`,
        "FROM build AS pruned",
        `FROM --platform=linux/arm64 ${reviewed} AS runtime`,
      ].join("\n"),
      new Set([reviewed]),
    ),
  );

  for (const [label, dockerfile, expected] of [
    [
      "malformed trailing tokens",
      `FROM ${reviewed} AS build unexpected`,
      /malformed or unsupported FROM instruction/u,
    ],
    [
      "unreviewed extra image",
      `FROM ${reviewed} AS build\nFROM docker.io/library/busybox:latest AS extra`,
      /uses unreviewed external base image/u,
    ],
    [
      "reviewed image only in a comment",
      `# ${reviewed}\nFROM scratch AS runtime`,
      /uses unreviewed external base image scratch/u,
    ],
    [
      "forward stage reference",
      `FROM build AS runtime\nFROM ${reviewed} AS build`,
      /uses unreviewed external base image build/u,
    ],
    [
      "duplicate stage alias",
      `FROM ${reviewed} AS build\nFROM build AS BUILD`,
      /redefines build stage BUILD/u,
    ],
    [
      "missing FROM",
      `# FROM ${reviewed} AS build`,
      /has no FROM instruction/u,
    ],
  ]) {
    assert.throws(
      () =>
        validateDockerfileBaseReferences(
          `${label}.Dockerfile`,
          dockerfile,
          new Set([reviewed]),
        ),
      expected,
      label,
    );
  }
});

test("release scope separates five fork artifacts from QA infrastructure", () => {
  assert.deepEqual(runTool("service-scope", "arm64-candidate-five"), {
    schemaVersion: 1,
    evidenceClass: "arm64-candidate-not-release-attestation",
    selectedScope: "arm64-candidate-five",
    selectedServices: [
      "server",
      "math",
      "client-participation-alpha",
      "nginx-proxy",
      "polis-migration",
    ],
    productionArtifacts: [
      "server",
      "math",
      "client-participation-alpha",
      "nginx-proxy",
      "polis-migration",
    ],
    qaInfrastructure: ["postgres", "oidc-simulator"],
    allStaging: [
      "postgres",
      "oidc-simulator",
      "server",
      "math",
      "client-participation-alpha",
      "nginx-proxy",
      "polis-migration",
    ],
  });
});

test("scan gate requires the complete exact service and scanner provenance set", () => {
  const { directory, images } = createSyntheticEvidenceDirectory();
  try {
    const complete = runTool("scan-summary", directory);
    assert.equal(complete.arm64CandidateGate.status, "pass");
    assert.equal(complete.releaseAttestation.status, "not-created");
    assert.deepEqual(
      complete.images.map(({ service }) => service),
      images.map(({ service }) => service),
    );
    for (const image of complete.images) {
      assert.match(image.runtimeAssertionSha256, /^[a-f0-9]{64}$/u);
    }

    writeJson(join(directory, "image-index.json"), {
      schemaVersion: 1,
      generatedAt: new Date().toISOString(),
      projectName: "fncp-synthetic",
      scanScope: "arm64-candidate-five",
      images: images.slice(1),
    });
    assert.throws(
      () =>
        execFileSync("node", [evidenceTool, "scan-summary", directory], {
          cwd: repositoryRoot,
          stdio: "pipe",
        }),
      /Command failed/u,
    );

    const restored = {
      schemaVersion: 1,
      generatedAt: new Date().toISOString(),
      projectName: "fncp-synthetic",
      scanScope: "arm64-candidate-five",
      images,
    };
    writeJson(join(directory, "image-index.json"), restored);
    const tamperedPath = join(
      directory,
      "scan",
      "client-participation-alpha.grype.json",
    );
    const tampered = JSON.parse(readFileSync(tamperedPath, "utf8"));
    tampered.descriptor.db.status.from =
      "https://grype.anchore.io/databases/different";
    writeJson(tamperedPath, tampered);
    assert.throws(
      () =>
        execFileSync("node", [evidenceTool, "scan-summary", directory], {
          cwd: repositoryRoot,
          stdio: "pipe",
        }),
      /Command failed/u,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("production runtime assertions are required, exact and tamper-evident", () => {
  for (const [service, mutate, message] of [
    [
      "server",
      (assertion) => {
        assertion.status = "fail";
      },
      /server runtime assertion is missing or failed/u,
    ],
    [
      "client-participation-alpha",
      (assertion) => {
        assertion.buildOnlyPackagePathsPresent = ["/app/node_modules/vite"];
      },
      /client-participation-alpha runtime closure assertion is invalid/u,
    ],
    [
      "math",
      (assertion) => {
        assertion.clojureBuildToolPresent = true;
      },
      /math runtime closure assertion is invalid/u,
    ],
    [
      "nginx-proxy",
      (assertion) => {
        assertion.reviewedConfigPresent = false;
      },
      /nginx-proxy runtime configuration assertion is invalid/u,
    ],
    [
      "polis-migration",
      (assertion) => {
        assertion.psqlPresent = false;
      },
      /polis-migration runtime assertion is invalid/u,
    ],
  ]) {
    const { directory } = createSyntheticEvidenceDirectory();
    try {
      const assertionPath = join(
        directory,
        "runtime-assertions",
        `${service}.json`,
      );
      const assertion = JSON.parse(readFileSync(assertionPath, "utf8"));
      mutate(assertion);
      writeJson(assertionPath, assertion);
      const result = spawnSync(
        "node",
        [evidenceTool, "scan-summary", directory],
        { cwd: repositoryRoot, encoding: "utf8" },
      );
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, message);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }

  const { directory } = createSyntheticEvidenceDirectory();
  try {
    rmSync(join(directory, "runtime-assertions", "polis-migration.json"));
    const result = spawnSync(
      "node",
      [evidenceTool, "scan-summary", directory],
      { cwd: repositoryRoot, encoding: "utf8" },
    );
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /ENOENT/u);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
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
  assert.match(
    collector,
    /PRODUCTION_SERVICES="server math client-participation-alpha nginx-proxy polis-migration"/u,
  );
  assert.match(
    collector,
    /QA_INFRASTRUCTURE_SERVICES="postgres oidc-simulator"/u,
  );
  assert.match(collector, /FNCP_SCAN_SCOPE/u);
  assert.match(collector, /arm64-candidate-five/u);
  assert.match(collector, /staging-seven/u);
  assert.match(collector, /runtime-assertions\/polis-migration\.json/u);
  assert.match(collector, /org\.opencontainers\.image\.revision/u);
  assert.match(collector, /org\.opencontainers\.image\.source/u);
  assert.match(collector, /org\.opencontainers\.image\.base\.digest/u);
  assert.match(collector, /org\.opencontainers\.image\.base\.name/u);
  assert.match(collector, /configured_entrypoint/u);
  assert.match(collector, /configured_command/u);
  assert.match(collector, /\$configured_command" != 'null'/u);
  assert.match(collector, /configured_user/u);
  assert.match(
    collector,
    /cat find mktemp psql rm sha256sum sh sort tr wc/u,
  );
  for (const command of [
    "docker-enforce-initdb.sh",
    "docker-ensure-initdb.sh",
    "docker-entrypoint.sh",
    "pg_createsubscriber",
    "pg_walsummary",
    "postmaster",
  ]) {
    assert.match(
      collector,
      new RegExp(`\\b${command.replace(".", "\\.")}\\b`, "u"),
      command,
    );
  }
  assert.match(collector, /DOCKER_DEFAULT_PLATFORM="\$PLATFORM"/u);
  assert.match(evidenceToolSource, /inspection\.Architecture/u);
  assert.match(evidenceToolSource, /expected \$\{lock\.buildPlatform\}/u);
  assert.match(collector, /build --pull --no-cache/u);
  assert.match(
    collector,
    /ARM64 candidate evidence cannot use FNCP_SKIP_SCAN_BUILD=1/u,
  );
  assert.match(collector, /scope\.json/u);
  assert.match(collector, /build\.log/u);
  assert.match(collector, /FNCP_SKIP_SCAN_BUILD/u);
  assert.match(collector, /docker run --rm/u);
  assert.match(collector, /scanner-ref syft/u);
  assert.match(collector, /scanner-ref grype/u);
  assert.match(collector, /GRYPE_DB_CACHE_DIR=\/grype-cache/u);
  assert.match(collector, /GRYPE_DB_AUTO_UPDATE=false/u);
  assert.match(collector, /GRYPE_CHECK_FOR_APP_UPDATE=false/u);
  assert.match(collector, /SYFT_CHECK_FOR_APP_UPDATE=false/u);
  assert.match(collector, /grype-db-cache\.tar\.gz/u);
  assert.match(
    collector,
    /\$OUTPUT_DIR\/grype-cache:\/grype-cache/u,
  );
  assert.match(collector, /runtime-assertions\/\$service\.json/u);
  assert.match(evidenceToolSource, /runtimeAssertionSha256/u);
  for (const option of [
    "--network none",
    "--read-only",
    "--cap-drop ALL",
    "--security-opt no-new-privileges",
  ]) {
    assert.equal(
      [...collector.matchAll(new RegExp(option, "gu"))].length,
      4,
      `${option} must isolate every runtime assertion family`,
    );
  }
  assert.match(collector, /generatedKeysDirectoryPresent/u);
  assert.match(collector, /developmentPackageSentinelsPresent/u);
  assert.match(collector, /TREE_STATE[\s\S]+FNCP_ALLOW_DIRTY_SOURCE/u);
  assert.doesNotMatch(collector, /\bdocker\s+(?:push|login)\b/u);
  assert.doesNotMatch(collector, /\b(?:aws|gcloud|az)\b/u);
});

test("PR gate builds and inspects every runtime image without publication actions", () => {
  const runtimeJob = ciWorkflow.match(
    /^  runtime-images:\n([\s\S]*?)(?=^  fncp-pr-gate:)/mu,
  )?.[0];
  assert.ok(runtimeJob, "missing runtime-images CI job");
  for (const service of [
    "server",
    "math",
    "client-participation-alpha",
    "nginx-proxy",
    "polis-migration",
  ]) {
    assert.match(runtimeJob, new RegExp(`          - ${service}$`, "mu"));
  }
  assert.match(runtimeJob, /--target prod/u);
  assert.match(runtimeJob, /--no-cache/u);
  assert.equal(
    [...runtimeJob.matchAll(/--no-cache/gu)].length,
    5,
    "every release artifact build must be cold",
  );
  assert.match(runtimeJob, /configured_user/u);
  assert.match(runtimeJob, /test "\$\(id -u\)" -ne 0/u);
  assert.match(runtimeJob, /src\/prompts\/moderation\/script\.xml/u);
  assert.match(runtimeJob, /dist\/server\/entry\.mjs/u);
  assert.match(
    runtimeJob,
    /--publish 127\.0\.0\.1:14321:4321/u,
  );
  assert.match(
    runtimeJob,
    /http:\/\/127\.0\.0\.1:14321\/[\s\S]{0,500}test "\$status" = 404/u,
  );
  assert.match(runtimeJob, /--publish 127\.0\.0\.1:18080:8080/u);
  assert.match(runtimeJob, /test "\$status" = 404/u);
  assert.doesNotMatch(
    runtimeJob,
    /\bdocker\s+(?:login|push)\b|\baws\b|\bgcloud\b|\bkubectl\b|\bhelm\b/u,
  );
  assert.match(
    ciWorkflow,
    /needs: \[contracts, server, participant-alpha, math, runtime-images\]/u,
  );
  assert.equal(
    [...ciWorkflow.matchAll(/persist-credentials: false/gu)].length,
    5,
    "every checkout must keep its GitHub credential out of build contexts",
  );
});

test("generated participant JWT keys cannot enter the server build context", () => {
  assert.match(serverDockerignore, /^keys\/$/mu);
});

test("server final runtime prunes direct development dependencies", () => {
  const buildIndex = serverDockerfile.indexOf("RUN npm run build");
  const pruneIndex = serverDockerfile.indexOf("RUN npm prune --omit=dev");
  const runtimeStageIndex = serverDockerfile.indexOf(" AS prod");
  const removeNpmIndex = serverDockerfile.indexOf(
    "/usr/local/lib/node_modules/npm",
    runtimeStageIndex,
  );
  const copyDistIndex = serverDockerfile.indexOf(
    "COPY --from=build --chown=node:node /app/dist ./dist",
  );
  const moderationAssetIndex = serverDockerfile.indexOf(
    "/app/src/prompts/moderation/script.xml",
  );
  const reportSystemAssetIndex = serverDockerfile.indexOf(
    "/app/src/prompts/report_experimental/system.xml",
  );
  const userIndex = serverDockerfile.indexOf("USER node");
  const commandIndex = serverDockerfile.indexOf(
    'CMD ["node", "--max_old_space_size=2048", "--gc_interval=100", "dist/index.js"]',
  );
  assert.ok(buildIndex >= 0);
  assert.ok(pruneIndex > buildIndex);
  assert.ok(runtimeStageIndex > pruneIndex);
  assert.ok(removeNpmIndex > runtimeStageIndex);
  assert.ok(copyDistIndex > removeNpmIndex);
  assert.ok(moderationAssetIndex > copyDistIndex);
  assert.ok(reportSystemAssetIndex > moderationAssetIndex);
  assert.ok(userIndex > reportSystemAssetIndex);
  assert.ok(commandIndex > userIndex);
  assert.doesNotMatch(
    serverDockerfile.slice(runtimeStageIndex),
    /^COPY (?!-{2}from=(?:build|fncp-busybox-fixed)\b)/mu,
  );
  assert.doesNotMatch(serverDockerfile.slice(runtimeStageIndex), /COPY \. \./u);
  assert.doesNotMatch(
    serverDockerfile.slice(runtimeStageIndex),
    /package-lock\.json/u,
  );
  assert.match(serverDockerfile, /find dist -type f -name '\*\.map' -delete/u);
});

test("server Alpine packages are exact-version pinned in every stage", () => {
  for (const [specification, expectedOccurrences] of [
    ["libpq-dev=18.4-r0", 2],
    ["g++=15.2.0-r5", 2],
    ["make=4.4.1-r4", 2],
    ["python3=3.14.5-r0", 2],
    ["libpq=18.4-r0", 1],
    ["openssl=3.5.7-r0", 1],
    ["ca-certificates=20260611-r0", 1],
  ]) {
    assert.equal(
      serverDockerfile.split(specification).length - 1,
      expectedOccurrences,
      `${specification} must have the reviewed occurrence count`,
    );
  }
  assert.doesNotMatch(
    serverDockerfile,
    /(?:^|\s)(?:libpq-dev|g\+\+|make|python3|libpq|openssl|ca-certificates)(?=\s|\\)/mu,
  );
  assert.match(ciWorkflow, /apk info --exists "libpq=18\.4-r0"/u);
  assert.match(ciWorkflow, /apk info --exists "openssl=3\.5\.7-r0"/u);
  assert.match(
    ciWorkflow,
    /apk info --exists "ca-certificates=20260611-r0"/u,
  );
});

test("production Node dependency installs use no persistent build cache", () => {
  const serverBuildStart = serverDockerfile.indexOf("FROM base as build");
  const serverRuntimeStart = serverDockerfile.indexOf(" AS prod");
  const serverProductionBuild = serverDockerfile.slice(
    serverBuildStart,
    serverRuntimeStart,
  );
  assert.ok(serverBuildStart >= 0);
  assert.ok(serverRuntimeStart > serverBuildStart);
  assert.match(serverProductionBuild, /RUN npm ci --production=false/u);
  assert.doesNotMatch(serverProductionBuild, /--mount=type=cache/u);
  assert.match(serverProductionBuild, /npm cache clean --force/u);

  const alphaBuildStart = alphaDockerfile.indexOf(" AS build");
  const alphaRuntimeStart = alphaDockerfile.indexOf(" AS runtime");
  const alphaProductionBuild = alphaDockerfile.slice(
    alphaBuildStart,
    alphaRuntimeStart,
  );
  assert.ok(alphaBuildStart >= 0);
  assert.ok(alphaRuntimeStart > alphaBuildStart);
  assert.match(alphaProductionBuild, /RUN npm ci\n/u);
  assert.doesNotMatch(alphaProductionBuild, /--mount=type=cache/u);
  assert.match(alphaProductionBuild, /npm cache clean --force/u);
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
    /^COPY (?!-{2}from=(?:build|fncp-busybox-fixed)\b)/mu,
  );

  for (const buildOnlyPath of [
    "node_modules/@astrojs",
    "node_modules/@esbuild",
    "node_modules/@img",
    "node_modules/@oxc-project",
    "node_modules/@rolldown",
    "node_modules/@types",
    "node_modules/@visx/vendor/node_modules/@types",
    "node_modules/@vitejs",
    "node_modules/astro",
    "node_modules/astro/node_modules/@esbuild",
    "node_modules/astro/node_modules/esbuild",
    "node_modules/esbuild",
    "node_modules/lightningcss",
    "node_modules/rolldown",
    "node_modules/sharp",
    "node_modules/vite",
  ]) {
    assert.ok(
      alphaDockerfile.includes(buildOnlyPath),
      `missing build-only removal: ${buildOnlyPath}`,
    );
  }
  assert.match(alphaDockerfile, /find node_modules -type d/u);
  assert.match(alphaDockerfile, /-name '@astrojs'/u);
  assert.match(alphaDockerfile, /-name '@esbuild'/u);
  assert.match(alphaDockerfile, /-name '@oxc-project'/u);
  assert.match(alphaDockerfile, /-name '@rolldown'/u);
  assert.match(alphaDockerfile, /-name '@types'/u);
  assert.match(alphaDockerfile, /-name '@vitejs'/u);
  assert.match(alphaDockerfile, /-name 'astro'/u);
  assert.match(alphaDockerfile, /-name 'esbuild'/u);
  assert.match(alphaDockerfile, /-name 'lightningcss'/u);
  assert.match(alphaDockerfile, /-name 'rolldown'/u);
  assert.match(alphaDockerfile, /-name 'sharp'/u);
  assert.match(alphaDockerfile, /-name 'vite'/u);
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
    for (const path of [
      "/usr/local/lib/node_modules/npm",
      "/usr/local/bin/npm",
      "/usr/local/bin/npx",
    ]) {
      assert.match(dockerfile, new RegExp(path, "u"));
    }
  }
  assert.match(collector, /globalNpmRuntimePresent/u);
  assert.match(collector, /packageManagerRuntimePathsPresent/u);
  for (const binary of ["corepack", "pnpm", "pnpx", "yarn", "yarnpkg"]) {
    assert.match(serverDockerfile, new RegExp(`/usr/local/bin/${binary}`, "u"));
    assert.match(alphaDockerfile, new RegExp(`/usr/local/bin/${binary}`, "u"));
  }
});

test("participant-facing Node runtimes execute as non-root users", () => {
  const serverRuntimeStage = serverDockerfile.indexOf(" AS prod");
  const alphaRuntimeStage = alphaDockerfile.indexOf(" AS runtime");
  assert.ok(serverRuntimeStage >= 0);
  assert.ok(alphaRuntimeStage >= 0);
  assert.match(serverDockerfile.slice(serverRuntimeStage), /^USER node$/mu);
  assert.match(alphaDockerfile.slice(alphaRuntimeStage), /^USER node$/mu);
});

test("participant runtime evidence rejects Sharp and esbuild package families", () => {
  assert.match(collector, /FNCP_CHECK_ALPHA_BUILD_TOOLS/u);
  assert.match(collector, /buildOnlyPackagePathsPresent/u);
  assert.match(collector, /FNCP_EXPECTED_ALPINE_PACKAGES/u);
  assert.match(
    collector,
    /libpq=18\.4-r0,openssl=3\.5\.7-r0,ca-certificates=20260611-r0/u,
  );
  assert.match(collector, /\/lib\/apk\/db\/installed/u);
  assert.match(collector, /alpinePackageMismatches/u);
  assert.match(collector, /entry\.name === "@esbuild"/u);
  assert.match(collector, /entry\.name === "@astrojs"/u);
  assert.match(collector, /entry\.name === "@oxc-project"/u);
  assert.match(collector, /entry\.name === "@rolldown"/u);
  assert.match(collector, /entry\.name === "@types"/u);
  assert.match(collector, /entry\.name === "@vitejs"/u);
  assert.match(collector, /entry\.name === "astro"/u);
  assert.match(collector, /entry\.name === "esbuild"/u);
  assert.match(collector, /entry\.name === "lightningcss"/u);
  assert.match(collector, /entry\.name === "rolldown"/u);
  assert.match(collector, /entry\.name === "sharp"/u);
  assert.match(collector, /entry\.name === "vite"/u);
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
  assert.match(
    mathDockerfile,
    /FROM docker\.io\/library\/eclipse-temurin:17-jre-noble@sha256:[a-f0-9]{64} AS runtime/u,
  );
  assert.match(mathDockerfile, /^ENTRYPOINT \[\]$/mu);
  assert.doesNotMatch(
    mathDockerfile.slice(runtimeStageIndex),
    /\/usr\/local\/(?:lib\/clojure|bin\/clj|bin\/clojure)/u,
  );
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

test("proxy build context is deny-all with exact reviewed source allows", () => {
  const rules = proxyDockerignore.trim().split("\n");
  assert.deepEqual(rules, [
    "**",
    "!nginx/",
    "!nginx/Dockerfile",
    "!nginx/fncp-staging.conf",
    "!busybox-fixed/",
    "!busybox-fixed/CVE-2025-60876.patch",
    "!busybox-fixed/build-fixed-busybox.sh",
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
