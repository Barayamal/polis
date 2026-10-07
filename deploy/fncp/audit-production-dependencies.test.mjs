import assert from "node:assert/strict";
import test from "node:test";
import {
  auditProcessCompleted,
  resolveAuditComponent,
  summarizeAudit,
} from "./audit-production-dependencies.mjs";

function metadata(
  vulnerabilities,
  dependencies = {
    prod: 50,
    dev: 0,
    optional: 0,
    peer: 0,
    peerOptional: 0,
    total: 50,
  },
) {
  return {
    vulnerabilities: {
      info: 0,
      low: 0,
      moderate: 0,
      high: 0,
      critical: 0,
      ...vulnerabilities,
    },
    dependencies,
  };
}

test("summarizes direct, transitive and fix-shape evidence", () => {
  const summary = summarizeAudit({
    auditReportVersion: 2,
    vulnerabilities: {
      express: {
        severity: "critical",
        isDirect: true,
        range: "<5",
        fixAvailable: {
          name: "express",
          version: "5.2.1",
          isSemVerMajor: true,
        },
      },
      nested: {
        severity: "high",
        isDirect: false,
        range: "<2",
        fixAvailable: true,
      },
      legacy: {
        severity: "moderate",
        isDirect: true,
        range: "*",
        fixAvailable: false,
      },
    },
    metadata: metadata({
      moderate: 1,
      high: 1,
      critical: 1,
      total: 3,
    }),
  });

  assert.deepEqual(summary.packageFindings.bySeverity, {
    info: 0,
    low: 0,
    moderate: 1,
    high: 1,
    critical: 1,
  });
  assert.equal(summary.packageFindings.direct.critical, 1);
  assert.equal(summary.packageFindings.transitive.high, 1);
  assert.equal(summary.packageFindings.semverMajorFixes, 1);
  assert.deepEqual(summary.packageFindings.noAutomaticFix, [
    { package: "legacy", severity: "moderate", range: "*" },
  ]);
  assert.deepEqual(summary.dependencies, {
    prod: 50,
    dev: 0,
    optional: 0,
    peer: 0,
    peerOptional: 0,
    total: 50,
  });
  assert.equal(summary.productionGate.pass, false);
});

test("passes only when no critical, high or no-fix findings remain", () => {
  const summary = summarizeAudit({
    auditReportVersion: 2,
    vulnerabilities: {
      patched: {
        severity: "moderate",
        isDirect: false,
        range: "<2",
        fixAvailable: true,
      },
    },
    metadata: metadata({ moderate: 1, total: 1 }),
  });

  assert.equal(summary.productionGate.pass, true);
});

test("emits only expected numeric dependency counts", () => {
  const summary = summarizeAudit({
    auditReportVersion: 2,
    vulnerabilities: {},
    metadata: metadata(
      { total: 0 },
      {
        prod: 10,
        dev: 20,
        optional: 0,
        peer: 0,
        peerOptional: 0,
        total: 30,
        unexpectedRegistryToken: "must-not-be-reflected",
      },
    ),
  });

  assert.deepEqual(summary.dependencies, {
    prod: 10,
    dev: 20,
    optional: 0,
    peer: 0,
    peerOptional: 0,
    total: 30,
  });
  assert.doesNotMatch(JSON.stringify(summary), /must-not-be-reflected/);
});

test("accepts only completed npm audit process results", () => {
  assert.equal(auditProcessCompleted({ status: 0 }), true);
  assert.equal(auditProcessCompleted({ status: 1 }), true);
  assert.equal(auditProcessCompleted({ status: 2 }), false);
  assert.equal(
    auditProcessCompleted({
      status: null,
      error: Object.assign(new Error("timed out"), { code: "ETIMEDOUT" }),
    }),
    false,
  );
  assert.equal(
    auditProcessCompleted({ status: null, signal: "SIGTERM" }),
    false,
  );
});

test("selects only the six reviewed production component trees", () => {
  assert.deepEqual(resolveAuditComponent([]), {
    name: "server",
    directory: "server",
  });
  assert.deepEqual(resolveAuditComponent(["--component=alpha"]), {
    name: "alpha",
    directory: "client-participation-alpha",
  });
  assert.deepEqual(resolveAuditComponent(["--component=report"]), {
    name: "report",
    directory: "client-report",
  });
  assert.throws(
    () => resolveAuditComponent(["--component=../../private"]),
    /Unknown production dependency component/,
  );
  assert.throws(
    () => resolveAuditComponent(["--component=alpha", "--component=server"]),
    /Use one optional/,
  );
});

test("rejects malformed or internally inconsistent reports", () => {
  assert.throws(() => summarizeAudit(null), /Expected an npm audit v2 report/);
  assert.throws(
    () =>
      summarizeAudit({
        auditReportVersion: 1,
        vulnerabilities: {},
        metadata: metadata({ total: 0 }),
      }),
    /Expected an npm audit v2 report/,
  );
  assert.throws(
    () =>
      summarizeAudit({
        auditReportVersion: 2,
        vulnerabilities: {
          package: {
            severity: "unexpected",
            isDirect: true,
            range: "*",
            fixAvailable: false,
          },
        },
        metadata: metadata({ low: 1, total: 1 }),
      }),
    /Invalid finding/,
  );
  assert.throws(
    () =>
      summarizeAudit({
        auditReportVersion: 2,
        vulnerabilities: {
          package: {
            severity: "low",
            isDirect: true,
            range: "*",
            fixAvailable: true,
          },
        },
        metadata: metadata({ low: 1, total: 2 }),
      }),
    /does not match/,
  );
  assert.throws(
    () =>
      summarizeAudit({
        auditReportVersion: 2,
        vulnerabilities: {
          package: {
            severity: "low",
            isDirect: "yes",
            range: "*",
            fixAvailable: true,
          },
        },
        metadata: metadata({ low: 1, total: 1 }),
      }),
    /Invalid finding/,
  );
  assert.throws(
    () =>
      summarizeAudit({
        auditReportVersion: 2,
        vulnerabilities: {
          package: {
            severity: "low",
            isDirect: true,
            range: "*",
            fixAvailable: undefined,
          },
        },
        metadata: metadata({ low: 1, total: 1 }),
      }),
    /Invalid npm audit fixAvailable/,
  );
  assert.throws(
    () =>
      summarizeAudit({
        auditReportVersion: 2,
        vulnerabilities: {
          package: {
            severity: "low",
            isDirect: true,
            range: "*",
            fixAvailable: true,
          },
        },
        metadata: metadata({ moderate: 1, total: 1 }),
      }),
    /metadata low count 0 does not match 1/,
  );
  assert.throws(
    () =>
      summarizeAudit({
        auditReportVersion: 2,
        vulnerabilities: {},
        metadata: metadata(
          { total: 0 },
          {
            prod: "10",
            dev: 0,
            optional: 0,
            peer: 0,
            peerOptional: 0,
            total: 10,
          },
        ),
      }),
    /Invalid npm audit dependency prod count/,
  );
});
