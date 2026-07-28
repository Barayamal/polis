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
const serviceNames = [
  "postgres",
  "oidc-simulator",
  "server",
  "math",
  "client-participation-alpha",
  "nginx-proxy",
];
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

  const componentNames = new Set();
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

    const dockerfilePath = resolve(repositoryRoot, image.dockerfile);
    const dockerfile = readFileSync(dockerfilePath, "utf8");
    const exactReference = `${image.tag}@${image.indexDigest}`;
    if (!dockerfile.includes(exactReference)) {
      fail(
        `${relative(repositoryRoot, dockerfilePath)} does not pin ${exactReference}`,
      );
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

function imageIndex(projectName) {
  validateLock();
  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    projectName,
    images: serviceNames.map((service) => {
      const reference = `${projectName}-${service}:latest`;
      const [inspection] = JSON.parse(
        run("docker", ["image", "inspect", reference]),
      );
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

function scanSummary(evidenceDirectory) {
  const imageIndexPath = join(evidenceDirectory, "image-index.json");
  const index = readJson(imageIndexPath);
  const images = index.images.map((image) => {
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

  const totals = images.reduce(
    (summary, image) => {
      summary.components += image.sbom.components;
      summary.matches += image.vulnerabilityScan.matches;
      for (const [severity, count] of Object.entries(
        image.vulnerabilityScan.severities,
      )) {
        summary.severities[severity] =
          (summary.severities[severity] ?? 0) + count;
      }
      return summary;
    },
    {
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
    },
  );
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
  const gate =
    totals.severities.Critical === 0 &&
    totals.severities.High === 0 &&
    developmentPackageSentinelsPresent.length === 0
      ? "pass"
      : "fail";

  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    sourceManifest: "source-manifest.json",
    imageIndex: "image-index.json",
    scannerLock: "image-security.lock.json",
    grypeDatabase: database,
    images,
    totals,
    productionGate: {
      status: gate,
      policy:
        "Zero Critical and zero High matches across all six images, " +
        "with no Node runtime development-package sentinels",
      developmentPackageSentinels:
        forbiddenDevelopmentPackageSentinels,
      developmentPackageSentinelsPresent,
    },
  };
}

function main() {
  const [command, argument] = process.argv.slice(2);
  switch (command) {
    case "validate-lock":
      console.log(JSON.stringify(validateLock(), null, 2));
      return;
    case "scanner-ref":
      console.log(scannerReference(argument));
      return;
    case "source-manifest":
      console.log(JSON.stringify(sourceManifest(), null, 2));
      return;
    case "image-index":
      if (!argument) {
        fail("image-index requires a Compose project name");
      }
      console.log(JSON.stringify(imageIndex(argument), null, 2));
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
          "{validate-lock|scanner-ref|source-manifest|image-index|" +
          "scan-summary|image-id}",
      );
  }
}

main();
