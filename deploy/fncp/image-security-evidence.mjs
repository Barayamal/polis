#!/usr/bin/env node

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  lstatSync,
  readFileSync,
  readlinkSync,
} from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const deployDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(deployDirectory, "../..");
const lockPath = join(deployDirectory, "image-security.lock.json");
const lock = JSON.parse(readFileSync(lockPath, "utf8"));
const digestPattern = /^sha256:[a-f0-9]{64}$/u;
const productionServiceNames = [
  "server",
  "math",
  "client-participation-alpha",
  "nginx-proxy",
];
const qaInfrastructureServiceNames = ["postgres", "oidc-simulator"];
const serviceNames = [
  "postgres",
  "oidc-simulator",
  "server",
  "math",
  "client-participation-alpha",
  "nginx-proxy",
];
const scanScopes = {
  "arm64-candidate-four": productionServiceNames,
  "staging-six": serviceNames,
};
const forbiddenDevelopmentPackageSentinels = {
  server: ["jest", "nodemon", "prettier", "supertest", "ts-jest"],
  "client-participation-alpha": [
    "eslint",
    "jest",
    "prettier",
    "ts-jest",
    "ts-node",
  ],
  "oidc-simulator": ["nodemon"],
};

function fail(message) {
  throw new Error(message);
}

function sha256(input) {
  return createHash("sha256").update(input).digest("hex");
}

function run(command, args) {
  return execFileSync(command, args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  }).trim();
}

export function validateDockerfileBaseReferences(
  dockerfilePath,
  dockerfile,
  reviewedReferences,
) {
  const reviewed = new Set(reviewedReferences);
  const observedExternal = new Set();
  const stageAliases = new Set();
  let fromCount = 0;

  for (const [index, line] of dockerfile.split(/\r?\n/u).entries()) {
    if (!/^\s*FROM\b/iu.test(line)) continue;
    fromCount += 1;
    const match = line.match(
      /^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+([A-Za-z][A-Za-z0-9_.-]*))?\s*$/iu,
    );
    if (!match) {
      fail(
        `${dockerfilePath}:${index + 1} has a malformed or unsupported FROM instruction`,
      );
    }

    const [, reference, alias] = match;
    const normalizedReference = reference.toLowerCase();
    if (!stageAliases.has(normalizedReference)) {
      if (!reviewed.has(reference)) {
        fail(
          `${dockerfilePath}:${index + 1} uses unreviewed external base image ${reference}`,
        );
      }
      observedExternal.add(reference);
    }

    if (alias) {
      const normalizedAlias = alias.toLowerCase();
      if (stageAliases.has(normalizedAlias)) {
        fail(
          `${dockerfilePath}:${index + 1} redefines build stage ${alias}`,
        );
      }
      stageAliases.add(normalizedAlias);
    }
  }

  if (fromCount === 0) {
    fail(`${dockerfilePath} has no FROM instruction`);
  }
  for (const reference of reviewed) {
    if (!observedExternal.has(reference)) {
      fail(`${dockerfilePath} does not use reviewed base image ${reference}`);
    }
  }
}

function validateLock() {
  if (lock.schemaVersion !== 1) {
    fail("image-security.lock.json must use schemaVersion 1");
  }
  if (lock.registry !== "docker.io") {
    fail("Only the reviewed docker.io registry is permitted");
  }
  if (lock.buildPlatform !== "linux/arm64") {
    fail("The recorded local evidence platform must be linux/arm64");
  }
  if (lock.baseImages.length !== 6 || lock.scannerImages.length !== 2) {
    fail("The lock must contain six base images and two scanner images");
  }
  if (
    lock.dockerfileFrontend?.tag !== "docker.io/docker/dockerfile:1.4" ||
    !digestPattern.test(lock.dockerfileFrontend?.indexDigest ?? "") ||
    !digestPattern.test(lock.dockerfileFrontend?.arm64Digest ?? "")
  ) {
    fail("The reviewed Dockerfile frontend must be locked by digest");
  }

  const componentNames = new Set();
  const reviewedReferencesByDockerfile = new Map();
  for (const image of lock.baseImages) {
    if (componentNames.has(image.component)) {
      fail(`Duplicate base-image component: ${image.component}`);
    }
    componentNames.add(image.component);
    if (!digestPattern.test(image.indexDigest)) {
      fail(`Invalid index digest for ${image.component}`);
    }
    if (!digestPattern.test(image.arm64Digest)) {
      fail(`Invalid arm64 digest for ${image.component}`);
    }

    const exactReference = `${image.tag}@${image.indexDigest}`;
    const reviewedReferences =
      reviewedReferencesByDockerfile.get(image.dockerfile) ?? new Set();
    reviewedReferences.add(exactReference);
    reviewedReferencesByDockerfile.set(image.dockerfile, reviewedReferences);
  }
  for (const [dockerfilePath, reviewedReferences] of
    reviewedReferencesByDockerfile) {
    const dockerfile = readFileSync(
      resolve(repositoryRoot, dockerfilePath),
      "utf8",
    );
    validateDockerfileBaseReferences(
      relative(repositoryRoot, resolve(repositoryRoot, dockerfilePath)),
      dockerfile,
      reviewedReferences,
    );
  }
  const exactFrontendReference =
    `# syntax=${lock.dockerfileFrontend.tag}` +
    `@${lock.dockerfileFrontend.indexDigest}`;
  for (const path of [
    "server/Dockerfile",
    "client-participation-alpha/Dockerfile",
    "oidc-simulator/Dockerfile",
  ]) {
    const dockerfile = readFileSync(resolve(repositoryRoot, path), "utf8");
    if (!dockerfile.startsWith(exactFrontendReference)) {
      fail(`${path} does not pin ${exactFrontendReference}`);
    }
  }

  const scannerNames = new Set();
  for (const image of lock.scannerImages) {
    if (scannerNames.has(image.name)) {
      fail(`Duplicate scanner: ${image.name}`);
    }
    scannerNames.add(image.name);
    if (!digestPattern.test(image.indexDigest)) {
      fail(`Invalid scanner index digest for ${image.name}`);
    }
    if (!digestPattern.test(image.arm64Digest)) {
      fail(`Invalid scanner arm64 digest for ${image.name}`);
    }
    if (!image.release.startsWith("https://github.com/anchore/")) {
      fail(`Unexpected scanner release source for ${image.name}`);
    }
  }

  return {
    status: "pass",
    baseImages: lock.baseImages.length,
    scannerImages: lock.scannerImages.length,
    buildPlatform: lock.buildPlatform,
  };
}

function scannerReference(name) {
  validateLock();
  const image = lock.scannerImages.find((entry) => entry.name === name);
  if (!image) {
    fail(`Unknown scanner: ${name}`);
  }
  return `${image.tag}@${image.indexDigest}`;
}

function servicesForScanScope(scopeName) {
  const services = scanScopes[scopeName];
  if (!services) {
    fail(
      `Unknown scan scope: ${scopeName}. Expected one of ` +
        Object.keys(scanScopes).join(", "),
    );
  }
  return services;
}

function serviceScope(scopeName = "arm64-candidate-four") {
  const selectedServices = servicesForScanScope(scopeName);
  return {
    schemaVersion: 1,
    evidenceClass: "arm64-candidate-not-release-attestation",
    selectedScope: scopeName,
    selectedServices,
    productionRuntime: productionServiceNames,
    qaInfrastructure: qaInfrastructureServiceNames,
    allStaging: serviceNames,
  };
}

function sourceFiles() {
  const output = execFileSync(
    "git",
    ["ls-files", "--cached", "--others", "--exclude-standard", "-z"],
    { cwd: repositoryRoot },
  );
  return output
    .toString("utf8")
    .split("\0")
    .filter(Boolean)
    .sort((left, right) => left.localeCompare(right, "en"));
}

function sourceManifest() {
  validateLock();
  const files = sourceFiles().map((path) => {
    const absolutePath = join(repositoryRoot, path);
    const stat = lstatSync(absolutePath);
    const content = stat.isSymbolicLink()
      ? Buffer.from(readlinkSync(absolutePath), "utf8")
      : readFileSync(absolutePath);
    return {
      path,
      bytes: content.byteLength,
      sha256: sha256(content),
      type: stat.isSymbolicLink() ? "symlink" : "file",
    };
  });
  const aggregate = files
    .map(
      ({ path, bytes, sha256: digest, type }) =>
        `${type}\0${path}\0${bytes}\0${digest}\n`,
    )
    .join("");
  const status = run("git", ["status", "--porcelain=v1", "--untracked-files=all"]);
  const commit = run("git", ["rev-parse", "HEAD"]);

  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    source: {
      commit,
      treeState: status ? "dirty" : "clean",
      status: status ? status.split("\n") : [],
      fileCount: files.length,
      aggregateSha256: sha256(aggregate),
      files,
    },
    lockedImages: lock,
    runtime: {
      node: process.version,
      platform: process.platform,
      architecture: process.arch,
    },
  };
}

function imageIndex(projectName, scopeName = "arm64-candidate-four") {
  validateLock();
  const selectedServices = servicesForScanScope(scopeName);
  const expectedArchitecture = lock.buildPlatform.split("/")[1];
  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    projectName,
    scanScope: scopeName,
    images: selectedServices.map((service) => {
      const reference = `${projectName}-${service}:latest`;
      const [inspection] = JSON.parse(
        run("docker", ["image", "inspect", reference]),
      );
      if (
        inspection.Architecture !== expectedArchitecture ||
        inspection.Os !== "linux"
      ) {
        fail(
          `${service} is ${inspection.Os}/${inspection.Architecture}; ` +
            `expected ${lock.buildPlatform}`,
        );
      }
      return {
        service,
        reference,
        imageId: inspection.Id,
        repoDigests: inspection.RepoDigests ?? [],
        architecture: inspection.Architecture,
        os: inspection.Os,
        created: inspection.Created,
        size: inspection.Size,
        rootFsLayers: inspection.RootFS?.Layers ?? [],
      };
    }),
  };
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function severityCounts(matches) {
  const counts = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
    Negligible: 0,
    Unknown: 0,
  };
  for (const match of matches) {
    const severity = match.vulnerability?.severity ?? "Unknown";
    counts[severity] = (counts[severity] ?? 0) + 1;
  }
  return counts;
}

function fixedCounts(matches) {
  return matches.reduce(
    (counts, match) => {
      const versions = match.vulnerability?.fix?.versions ?? [];
      if (versions.length > 0) {
        counts.available += 1;
      } else {
        counts.unavailable += 1;
      }
      return counts;
    },
    { available: 0, unavailable: 0 },
  );
}

function emptyTotals() {
  return {
    components: 0,
    matches: 0,
    severities: {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0,
      Negligible: 0,
      Unknown: 0,
    },
  };
}

function summariseImages(images) {
  return images.reduce((summary, image) => {
    summary.components += image.sbom.components;
    summary.matches += image.vulnerabilityScan.matches;
    for (const [severity, count] of Object.entries(
      image.vulnerabilityScan.severities,
    )) {
      summary.severities[severity] =
        (summary.severities[severity] ?? 0) + count;
    }
    return summary;
  }, emptyTotals());
}

function scanSummary(evidenceDirectory) {
  validateLock();
  const imageIndexPath = join(evidenceDirectory, "image-index.json");
  const index = readJson(imageIndexPath);
  if (index.schemaVersion !== 1) {
    fail("image-index.json must use schemaVersion 1");
  }
  const expectedServices = servicesForScanScope(index.scanScope);
  const actualServices = (index.images ?? []).map(({ service }) => service);
  if (
    actualServices.length !== new Set(actualServices).size ||
    JSON.stringify(actualServices) !== JSON.stringify(expectedServices)
  ) {
    fail(
      `image-index.json must contain the exact ${index.scanScope} service set`,
    );
  }
  const syftVersion = lock.scannerImages.find(
    ({ name }) => name === "syft",
  )?.version;
  const grypeVersion = lock.scannerImages.find(
    ({ name }) => name === "grype",
  )?.version;
  const grypeDatabaseFingerprints = new Set();
  const generatedAt = Date.now();
  const images = index.images.map((image) => {
    if (
      !digestPattern.test(image.imageId) ||
      image.architecture !== lock.buildPlatform.split("/")[1] ||
      image.os !== "linux"
    ) {
      fail(`${image.service} image metadata does not match the locked platform`);
    }
    const sbomPath = join(
      evidenceDirectory,
      "sbom",
      `${image.service}.cdx.json`,
    );
    const scanPath = join(
      evidenceDirectory,
      "scan",
      `${image.service}.grype.json`,
    );
    const sbom = readJson(sbomPath);
    const scan = readJson(scanPath);
    const syft = sbom.metadata?.tools?.components?.find(
      ({ name }) => name === "syft",
    );
    if (
      sbom.bomFormat !== "CycloneDX" ||
      syft?.version !== syftVersion ||
      sbom.metadata?.component?.type !== "container" ||
      `sha256:${sbom.metadata?.component?.version}` !== image.imageId
    ) {
      fail(`${image.service} SBOM is not bound to the locked Syft/image subject`);
    }
    const sbomService = sbom.metadata?.properties?.find(
      ({ name }) => name === "syft:image:labels:com.docker.compose.service",
    )?.value;
    if (sbomService !== image.service) {
      fail(`${image.service} SBOM has the wrong Compose service label`);
    }
    const database = scan.descriptor?.db;
    const databaseStatus = database?.status;
    const databaseBuilt = Date.parse(databaseStatus?.built ?? "");
    if (
      scan.descriptor?.name !== "grype" ||
      scan.descriptor?.version !== grypeVersion ||
      scan.descriptor?.configuration?.["check-for-app-update"] !== false ||
      scan.descriptor?.configuration?.db?.["auto-update"] !== false ||
      scan.source?.type !== "image" ||
      `sha256:${scan.source?.target?.manifestDigest}` !== image.imageId ||
      scan.source?.target?.labels?.["com.docker.compose.service"] !==
        image.service ||
      databaseStatus?.valid !== true ||
      !databaseStatus?.schemaVersion ||
      !databaseStatus?.from ||
      !Number.isFinite(databaseBuilt) ||
      databaseBuilt > generatedAt + 5 * 60 * 1000 ||
      generatedAt - databaseBuilt > 5 * 24 * 60 * 60 * 1000
    ) {
      fail(
        `${image.service} scan is not bound to the locked Grype/image/database subject`,
      );
    }
    grypeDatabaseFingerprints.add(sha256(JSON.stringify(database)));
    const matches = scan.matches ?? [];
    const componentNames = new Set(
      (sbom.components ?? []).map(({ name }) => name),
    );
    const sentinels =
      forbiddenDevelopmentPackageSentinels[image.service] ?? [];
    const developmentPackageSentinelsPresent = sentinels.filter((name) =>
      componentNames.has(name),
    );
    return {
      service: image.service,
      releaseScope: productionServiceNames.includes(image.service)
        ? "production-runtime"
        : "qa-infrastructure",
      localImageId: image.imageId,
      architecture: image.architecture,
      os: image.os,
      bytes: image.size,
      rootFsLayers: image.rootFsLayers.length,
      sbom: {
        format: sbom.bomFormat,
        specificationVersion: sbom.specVersion,
        components: sbom.components?.length ?? 0,
        developmentPackageSentinelsPresent,
        sha256: sha256(readFileSync(sbomPath)),
      },
      vulnerabilityScan: {
        matches: matches.length,
        severities: severityCounts(matches),
        fixes: fixedCounts(matches),
        sha256: sha256(readFileSync(scanPath)),
      },
    };
  });
  if (grypeDatabaseFingerprints.size !== 1) {
    fail("Every image scan must use the exact same Grype database");
  }

  const productionImages = images.filter(
    ({ releaseScope }) => releaseScope === "production-runtime",
  );
  const qaOnlyImages = images.filter(
    ({ releaseScope }) => releaseScope === "qa-infrastructure",
  );
  const totals = summariseImages(images);
  const productionTotals = summariseImages(productionImages);
  const qaOnlyTotals = summariseImages(qaOnlyImages);
  const firstScan = readJson(
    join(evidenceDirectory, "scan", `${images[0].service}.grype.json`),
  );
  const database = firstScan.descriptor?.db?.status ?? null;
  const developmentPackageSentinelsPresent = images.flatMap((image) =>
    image.sbom.developmentPackageSentinelsPresent.map((packageName) => ({
      service: image.service,
      package: packageName,
    })),
  );
  const productionDevelopmentPackageSentinelsPresent =
    developmentPackageSentinelsPresent.filter(({ service }) =>
      productionServiceNames.includes(service),
    );
  const gate =
    productionTotals.severities.Critical === 0 &&
    productionTotals.severities.High === 0 &&
    productionDevelopmentPackageSentinelsPresent.length === 0
      ? "pass"
      : "fail";

  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    sourceManifest: "source-manifest.json",
    imageIndex: "image-index.json",
    scannerLock: "image-security.lock.json",
    scannerProvenance: {
      syftVersion,
      grypeVersion,
      grypeDatabaseSha256: [...grypeDatabaseFingerprints][0],
    },
    grypeDatabase: database,
    images,
    totals,
    releaseScopes: {
      productionRuntime: {
        services: productionServiceNames,
        totals: productionTotals,
      },
      qaInfrastructure: {
        services: qaInfrastructureServiceNames,
        totals: qaOnlyTotals,
      },
    },
    arm64CandidateGate: {
      status: gate,
      policy:
        "Zero Critical and zero High matches across the four Pol.is " +
        "ARM64 runtime candidates, with no Node runtime development-package " +
        "sentinels. Managed RDS is infrastructure rather than an image; the " +
        "disposable PostgreSQL and OIDC simulator images are QA-only.",
      developmentPackageSentinels:
        forbiddenDevelopmentPackageSentinels,
      developmentPackageSentinelsPresent:
        productionDevelopmentPackageSentinelsPresent,
    },
    releaseAttestation: {
      status: "not-created",
      reasons: [
        "deployment architecture and release digests are not bound",
        "images are local and not published to an immutable registry",
        "multi-architecture verification is incomplete",
      ],
    },
  };
}

function main() {
  const [command, argument, secondary] = process.argv.slice(2);
  switch (command) {
    case "validate-lock":
      console.log(JSON.stringify(validateLock(), null, 2));
      return;
    case "scanner-ref":
      console.log(scannerReference(argument));
      return;
    case "service-scope":
      console.log(JSON.stringify(serviceScope(argument), null, 2));
      return;
    case "source-manifest":
      console.log(JSON.stringify(sourceManifest(), null, 2));
      return;
    case "image-index":
      if (!argument) {
        fail("image-index requires a Compose project name");
      }
      console.log(JSON.stringify(imageIndex(argument, secondary), null, 2));
      return;
    case "scan-summary":
      if (!argument) {
        fail("scan-summary requires an evidence directory");
      }
      console.log(JSON.stringify(scanSummary(resolve(argument)), null, 2));
      return;
    case "image-id": {
      const service = process.argv[4];
      if (!argument || !service) {
        fail("image-id requires an image-index path and service");
      }
      const index = readJson(resolve(argument));
      const image = index.images.find((entry) => entry.service === service);
      if (!image) {
        fail(`Unknown service in image index: ${service}`);
      }
      console.log(image.imageId);
      return;
    }
    default:
      fail(
        "Usage: image-security-evidence.mjs " +
          "{validate-lock|scanner-ref|service-scope|source-manifest|image-index|" +
          "scan-summary|image-id}",
      );
  }
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  main();
}
