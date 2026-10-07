#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const severityOrder = ["info", "low", "moderate", "high", "critical"];
const dependencyCountKeys = [
  "prod",
  "dev",
  "optional",
  "peer",
  "peerOptional",
  "total",
];
const componentDirectories = Object.freeze({
  server: "server",
  alpha: "client-participation-alpha",
  "file-server": "file-server",
  admin: "client-admin",
  "legacy-participant": "client-participation",
  report: "client-report",
});

function emptySeverityCounts() {
  return Object.fromEntries(severityOrder.map((severity) => [severity, 0]));
}

function fixShape(fixAvailable) {
  if (fixAvailable === false) return "none";
  if (fixAvailable === true) return "available";
  if (
    fixAvailable &&
    typeof fixAvailable === "object" &&
    !Array.isArray(fixAvailable) &&
    typeof fixAvailable.name === "string" &&
    typeof fixAvailable.version === "string" &&
    typeof fixAvailable.isSemVerMajor === "boolean"
  ) {
    return fixAvailable.isSemVerMajor ? "semver-major" : "available";
  }
  throw new TypeError("Invalid npm audit fixAvailable value.");
}

function nonNegativeInteger(value, label) {
  if (!Number.isInteger(value) || value < 0) {
    throw new TypeError(`Invalid ${label}.`);
  }
  return value;
}

function severityMetadata(report) {
  const metadata = report.metadata?.vulnerabilities;
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
    throw new TypeError("Expected npm audit vulnerability metadata.");
  }

  const counts = Object.fromEntries(
    severityOrder.map((severity) => [
      severity,
      nonNegativeInteger(
        metadata[severity],
        `npm audit metadata ${severity} count`,
      ),
    ]),
  );
  const total = nonNegativeInteger(
    metadata.total,
    "npm audit metadata total",
  );
  const summedTotal = Object.values(counts).reduce(
    (sum, count) => sum + count,
    0,
  );
  if (summedTotal !== total) {
    throw new Error(
      `npm audit metadata severity counts total ${summedTotal} does not match ${total}.`,
    );
  }
  return { counts, total };
}

function safeDependencyCounts(report) {
  const dependencies = report.metadata?.dependencies;
  if (
    !dependencies ||
    typeof dependencies !== "object" ||
    Array.isArray(dependencies)
  ) {
    throw new TypeError("Expected npm audit dependency metadata.");
  }

  return Object.fromEntries(
    dependencyCountKeys.map((key) => [
      key,
      nonNegativeInteger(
        dependencies[key],
        `npm audit dependency ${key} count`,
      ),
    ]),
  );
}

export function summarizeAudit(report) {
  if (
    !report ||
    typeof report !== "object" ||
    Array.isArray(report) ||
    report.auditReportVersion !== 2 ||
    !report.vulnerabilities ||
    typeof report.vulnerabilities !== "object" ||
    Array.isArray(report.vulnerabilities)
  ) {
    throw new TypeError("Expected an npm audit v2 report.");
  }

  const metadata = severityMetadata(report);
  const dependencies = safeDependencyCounts(report);
  const direct = emptySeverityCounts();
  const transitive = emptySeverityCounts();
  const directHighOrCritical = [];
  const noAutomaticFix = [];
  let semverMajorFixes = 0;

  for (const [packageName, finding] of Object.entries(
    report.vulnerabilities,
  )) {
    if (
      !finding ||
      typeof finding !== "object" ||
      Array.isArray(finding) ||
      !severityOrder.includes(finding.severity) ||
      typeof finding.isDirect !== "boolean" ||
      typeof finding.range !== "string"
    ) {
      throw new TypeError(`Invalid finding for ${packageName}.`);
    }

    const bucket = finding.isDirect ? direct : transitive;
    bucket[finding.severity] += 1;
    const shape = fixShape(finding.fixAvailable);

    if (shape === "semver-major") semverMajorFixes += 1;
    if (shape === "none") {
      noAutomaticFix.push({
        package: packageName,
        severity: finding.severity,
        range: finding.range,
      });
    }
    if (
      finding.isDirect &&
      (finding.severity === "critical" || finding.severity === "high")
    ) {
      directHighOrCritical.push({
        package: packageName,
        severity: finding.severity,
        range: finding.range,
        fix: shape,
      });
    }
  }

  const total = Object.values(report.vulnerabilities).length;
  if (metadata.total !== total) {
    throw new Error(
      `npm audit metadata total ${metadata.total} does not match ${total} package findings.`,
    );
  }

  const bySeverity = Object.fromEntries(
    severityOrder.map((severity) => [
      severity,
      direct[severity] + transitive[severity],
    ]),
  );
  for (const severity of severityOrder) {
    if (metadata.counts[severity] !== bySeverity[severity]) {
      throw new Error(
        `npm audit metadata ${severity} count ${metadata.counts[severity]} does not match ${bySeverity[severity]} package findings.`,
      );
    }
  }

  return {
    auditReportVersion: report.auditReportVersion,
    dependencies,
    packageFindings: {
      total,
      bySeverity,
      direct,
      transitive,
      semverMajorFixes,
      noAutomaticFix: noAutomaticFix.sort((a, b) =>
        a.package.localeCompare(b.package),
      ),
      directHighOrCritical: directHighOrCritical.sort((a, b) =>
        a.package.localeCompare(b.package),
      ),
    },
    productionGate: {
      pass:
        bySeverity.critical === 0 &&
        bySeverity.high === 0 &&
        noAutomaticFix.length === 0,
      rule:
        "No critical/high production package findings and no unreviewed no-fix package findings.",
    },
  };
}

export function auditProcessCompleted(audit) {
  return (
    !!audit &&
    !audit.error &&
    !audit.signal &&
    (audit.status === 0 || audit.status === 1)
  );
}

export function resolveAuditComponent(args) {
  if (args.length === 0) {
    return { name: "server", directory: componentDirectories.server };
  }
  if (args.length !== 1 || !args[0].startsWith("--component=")) {
    throw new TypeError(
      "Use one optional --component=server|alpha|file-server|admin|legacy-participant|report argument.",
    );
  }
  const name = args[0].slice("--component=".length);
  const directory = componentDirectories[name];
  if (!directory) {
    throw new TypeError("Unknown production dependency component.");
  }
  return { name, directory };
}

function run() {
  const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
  let component;
  try {
    component = resolveAuditComponent(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(
      `${error instanceof Error ? error.message : "Invalid component."}\n`,
    );
    process.exitCode = 2;
    return;
  }
  const componentDirectory = path.resolve(
    scriptDirectory,
    "../..",
    component.directory,
  );
  const audit = spawnSync("npm", ["audit", "--omit=dev", "--json"], {
    cwd: componentDirectory,
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
    timeout: 120_000,
  });

  if (!auditProcessCompleted(audit)) {
    process.stderr.write(
      "Unable to complete npm audit. Check npm availability, registry access and the server lockfile.\n",
    );
    process.exitCode = 2;
    return;
  }

  if (!audit.stdout) {
    process.stderr.write(
      "Unable to read npm audit output. Check registry access and the server lockfile.\n",
    );
    process.exitCode = 2;
    return;
  }

  try {
    const summary = summarizeAudit(JSON.parse(audit.stdout));
    process.stdout.write(
      `${JSON.stringify({ component: component.name, ...summary }, null, 2)}\n`,
    );
    process.exitCode = summary.productionGate.pass ? 0 : 1;
  } catch (error) {
    process.stderr.write(
      `Unable to summarize npm audit output: ${
        error instanceof Error ? error.message : "unknown error"
      }\n`,
    );
    process.exitCode = 2;
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  run();
}
