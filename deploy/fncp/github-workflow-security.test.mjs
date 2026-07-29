import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import test from "node:test";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../..",
);
const workflowDirectory = join(repositoryRoot, ".github", "workflows");
const workflowFiles = readdirSync(workflowDirectory)
  .filter((name) => name.endsWith(".yml") || name.endsWith(".yaml"))
  .sort();
const workflows = Object.fromEntries(
  workflowFiles.map((name) => [
    name,
    readFileSync(join(workflowDirectory, name), "utf8"),
  ]),
);

const expectedWorkflowFiles = [
  "client-participation-alpha-ci.yml",
  "cypress-tests.yml",
  "deploy-alpha-aws.yml",
  "deploy-preprod.yml",
  "deploy-prod.yml",
  "fncp-option-c-ci.yml",
  "jest-client-admin-test.yml",
  "jest-client-report-test.yml",
  "jest-server-test.yml",
  "lint.yml",
  "python-ci.yml",
  "sensemaker-cron.yml",
  "test-clojure.yml",
];

// Each commit and release was resolved from the action's official GitHub
// repository on 29 July 2026. "composite-node24-reviewed" means the composite
// action itself has no JavaScript runtime and any nested JavaScript action was
// inspected at this exact commit and found to use Node 24.
const reviewedActions = {
  "DeLaGuardo/setup-clojure": {
    sha: "4c7a6f613e5089821bb3bb2a33a3ee115578580d",
    version: "v13.6.1",
    runtime: "node24",
  },
  "actions/cache": {
    sha: "55cc8345863c7cc4c66a329aec7e433d2d1c52a9",
    version: "v6.1.0",
    runtime: "node24",
  },
  "actions/checkout": {
    sha: "3d3c42e5aac5ba805825da76410c181273ba90b1",
    version: "v7.0.1",
    runtime: "node24",
  },
  "actions/download-artifact": {
    sha: "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    version: "v8.0.1",
    runtime: "node24",
  },
  "actions/github-script": {
    sha: "3a2844b7e9c422d3c10d287c895573f7108da1b3",
    version: "v9.0.0",
    runtime: "node24",
  },
  "actions/setup-java": {
    sha: "03ad4de0992f5dab5e18fcb136590ce7c4a0ac95",
    version: "v5.6.0",
    runtime: "node24",
  },
  "actions/setup-node": {
    sha: "820762786026740c76f36085b0efc47a31fe5020",
    version: "v7.0.0",
    runtime: "node24",
  },
  "actions/setup-python": {
    sha: "5fda3b95a4ea91299a34e894583c3862153e4b97",
    version: "v7.0.0",
    runtime: "node24",
  },
  "actions/upload-artifact": {
    sha: "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    version: "v7.0.1",
    runtime: "node24",
  },
  "aws-actions/amazon-ecr-login": {
    sha: "d539f0932e70871a027e9d5a9d8fc38589180a64",
    version: "v2.1.6",
    runtime: "node24",
  },
  "aws-actions/configure-aws-credentials": {
    sha: "e6de054238d6b7531b4efff3b6587d9aade6a06c",
    version: "v6.2.3",
    runtime: "node24",
  },
  "codecov/codecov-action": {
    sha: "fb8b3582c8e4def4969c97caa2f19720cb33a72f",
    version: "v7.0.0",
    runtime: "composite-node24-reviewed",
  },
  "docker/setup-buildx-action": {
    sha: "bb05f3f5519dd87d3ba754cc423b652a5edd6d2c",
    version: "v4.2.0",
    runtime: "node24",
  },
  "google-github-actions/auth": {
    sha: "7c6bc770dae815cd3e89ee6cdf493a5fab2cc093",
    version: "v3",
    runtime: "node24",
  },
};

const expectedJobPermissions = {
  "client-participation-alpha-ci.yml": {
    verify: { contents: "read" },
  },
  "cypress-tests.yml": {
    "cypress-run": { contents: "read" },
  },
  "deploy-alpha-aws.yml": {
    "build-and-push-images": { contents: "read" },
    "deploy-us": { contents: "read" },
    "deploy-euro": { contents: "read" },
  },
  "deploy-preprod.yml": {
    "deploy-static": { contents: "read", "id-token": "write" },
  },
  "deploy-prod.yml": {
    "deploy-static-us": { contents: "read", "id-token": "write" },
    "deploy-static-euro": { contents: "read", "id-token": "write" },
  },
  "fncp-option-c-ci.yml": {
    contracts: { contents: "read" },
    server: { contents: "read" },
    "participant-alpha": { contents: "read" },
    math: { contents: "read" },
    "runtime-images": { contents: "read" },
    "fncp-pr-gate": {},
  },
  "jest-client-admin-test.yml": {
    test: { contents: "read" },
  },
  "jest-client-report-test.yml": {
    test: { contents: "read" },
  },
  "jest-server-test.yml": {
    "server-integration-tests": { contents: "read" },
  },
  "lint.yml": {
    eslint: { contents: "read" },
  },
  "python-ci.yml": {
    test: { contents: "read" },
    "comment-coverage": { "pull-requests": "write" },
  },
  "sensemaker-cron.yml": {
    "generate-summary": { contents: "read" },
    use_html: {},
  },
  "test-clojure.yml": {
    "test-clj": { contents: "read" },
  },
};

const reviewedDownloads = {
  codecovCli: {
    version: "v11.3.1",
  },
  dockerCompose: {
    version: "v5.3.1",
    sha256:
      "f9ebc6ebdb19d769b793c245a736caaeb198c62587f13b25c660c13b4987f959",
  },
  mkcert: {
    version: "v1.4.4",
    sha256:
      "6d31c65b03972c6dc4a14ab429f2928300518b26503f58723e532d1b0a3bbb52",
  },
};

function normalizePermissions(value) {
  return Object.fromEntries(
    Object.entries(value).sort(([left], [right]) =>
      left.localeCompare(right, "en"),
    ),
  );
}

function jobPermissionMap(source) {
  const lines = source.split(/\r?\n/u);
  const jobsIndex = lines.findIndex((line) => line === "jobs:");
  assert.notEqual(jobsIndex, -1, "workflow must contain jobs");
  const starts = [];
  for (let index = jobsIndex + 1; index < lines.length; index += 1) {
    const match = lines[index].match(/^  ([A-Za-z0-9_-]+):\s*$/u);
    if (match) starts.push({ index, name: match[1] });
  }
  return Object.fromEntries(
    starts.map(({ index: start, name }, jobIndex) => {
      const end = starts[jobIndex + 1]?.index ?? lines.length;
      const block = lines.slice(start + 1, end);
      const permissionIndex = block.findIndex((line) =>
        /^    permissions:(?: \{\})?\s*$/u.test(line),
      );
      assert.notEqual(
        permissionIndex,
        -1,
        `job ${name} must declare explicit permissions`,
      );
      if (/permissions: \{\}/u.test(block[permissionIndex])) {
        return [name, {}];
      }
      const permissions = {};
      for (
        let index = permissionIndex + 1;
        index < block.length;
        index += 1
      ) {
        const match = block[index].match(
          /^      ([a-z-]+): (read|write|none)\s*$/u,
        );
        if (match) {
          permissions[match[1]] = match[2];
          continue;
        }
        if (/^\s*$/u.test(block[index])) continue;
        if (!/^      /u.test(block[index])) break;
      }
      return [name, normalizePermissions(permissions)];
    }),
  );
}

test("the reviewed workflow inventory is complete", () => {
  assert.deepEqual(workflowFiles, expectedWorkflowFiles);
  assert.deepEqual(
    Object.keys(expectedJobPermissions).sort(),
    expectedWorkflowFiles,
  );
});

test("every external action is source-pinned to its reviewed release", () => {
  const observedActions = new Set();
  for (const [workflow, source] of Object.entries(workflows)) {
    for (const [index, line] of source.split(/\r?\n/u).entries()) {
      if (!/^\s*(?:-\s*)?uses:/u.test(line)) continue;
      const match = line.match(
        /^\s*(?:-\s*)?uses:\s*([^@\s'"]+)@([a-f0-9]{40})\s+#\s+(\S+)\s*$/u,
      );
      assert.ok(
        match,
        `${workflow}:${index + 1} must pin an action by full SHA with a release comment`,
      );
      const [, action, sha, version] = match;
      const reviewed = reviewedActions[action];
      assert.ok(reviewed, `${workflow}:${index + 1} uses unreviewed ${action}`);
      assert.equal(sha, reviewed.sha, `${action} SHA differs from review`);
      assert.equal(
        version,
        reviewed.version,
        `${action} release comment differs from review`,
      );
      assert.ok(
        ["node24", "composite-node24-reviewed"].includes(reviewed.runtime),
        `${action} does not have a reviewed Node 24-compatible runtime`,
      );
      observedActions.add(action);
    }
  }
  assert.deepEqual(
    [...observedActions].sort(),
    Object.keys(reviewedActions).sort(),
  );
});

test("checkout never persists the workflow token", () => {
  for (const [workflow, source] of Object.entries(workflows)) {
    const lines = source.split(/\r?\n/u);
    for (const [index, line] of lines.entries()) {
      if (!/uses: actions\/checkout@/u.test(line)) continue;
      const indentation = line.match(/^(\s*)/u)?.[1].length ?? 0;
      const remainder = lines.slice(index + 1);
      const nextStepOffset = remainder.findIndex((candidate) => {
        const nextIndentation =
          candidate.match(/^(\s*)/u)?.[1].length ?? 0;
        return (
          candidate.trim() !== "" &&
          nextIndentation <= indentation &&
          /^\s*-\s+/u.test(candidate)
        );
      });
      const block =
        nextStepOffset === -1
          ? remainder
          : remainder.slice(0, nextStepOffset);
      assert.ok(
        block.some((candidate) =>
          /^\s*persist-credentials: false\s*$/u.test(candidate),
        ),
        `${workflow}:${index + 1} must disable persisted checkout credentials`,
      );
    }
  }
});

test("every workflow and job has the minimum reviewed token permissions", () => {
  for (const [workflow, source] of Object.entries(workflows)) {
    assert.match(
      source,
      /^permissions: \{\}$/mu,
      `${workflow} must deny token permissions by default`,
    );
    assert.doesNotMatch(source, /^\s*permissions:\s+write-all\s*$/mu);
    assert.deepEqual(
      jobPermissionMap(source),
      Object.fromEntries(
        Object.entries(expectedJobPermissions[workflow]).map(
          ([job, permissions]) => [
            job,
            normalizePermissions(permissions),
          ],
        ),
      ),
      `${workflow} job permissions differ from the reviewed minimum`,
    );
  }
});

test("every job uses the explicit reviewed runner image", () => {
  for (const [workflow, source] of Object.entries(workflows)) {
    const runsOn = source.match(/^    runs-on: (\S+)\s*$/gmu) ?? [];
    assert.equal(
      runsOn.length,
      Object.keys(expectedJobPermissions[workflow]).length,
      `${workflow} must declare one runner for every job`,
    );
    for (const declaration of runsOn) {
      assert.equal(declaration.trim(), "runs-on: ubuntu-24.04");
    }
  }
});

test("dangerous workflow triggers and legacy action references are absent", () => {
  const combined = Object.values(workflows).join("\n");
  assert.doesNotMatch(combined, /^\s*pull_request_target:/mu);
  assert.doesNotMatch(combined, /^\s*workflow_run:/mu);
  assert.doesNotMatch(combined, /uses:\s*[^\s]+@(v\d+|main|master)\b/u);
  assert.doesNotMatch(combined, /::set-output\b/u);
  assert.doesNotMatch(combined, /exuanbo\/actions-deploy-gist/u);
  assert.doesNotMatch(combined, /valitydev\/action-download-file/u);
  assert.doesNotMatch(combined, /runs-on: [^\n]*latest/u);
  assert.doesNotMatch(combined, /releases\/latest/u);
  assert.doesNotMatch(combined, /mkcert\/latest/u);
  assert.doesNotMatch(combined, /\bnpm install(?:\s|$)/u);
});

test("downloaded executables are versioned and checksum-verified", () => {
  for (const workflow of ["cypress-tests.yml", "jest-server-test.yml"]) {
    const source = workflows[workflow];
    assert.match(
      source,
      new RegExp(`MKCERT_VERSION: ${reviewedDownloads.mkcert.version}`, "u"),
    );
    assert.match(source, new RegExp(reviewedDownloads.mkcert.sha256, "u"));
    assert.match(
      source,
      /FiloSottile\/mkcert\/releases\/download\/\$\{MKCERT_VERSION\}\/mkcert-\$\{MKCERT_VERSION\}-linux-amd64/u,
    );
    assert.match(source, /--proto '=https'/u);
    assert.match(source, /--proto-redir '=https'/u);
    assert.match(source, /sha256sum --check -/u);
    assert.match(source, /install -m 0755/u);
  }

  const compose = workflows["deploy-alpha-aws.yml"];
  assert.match(
    compose,
    new RegExp(
      `DOCKER_COMPOSE_VERSION: ${reviewedDownloads.dockerCompose.version}`,
      "u",
    ),
  );
  assert.match(
    compose,
    new RegExp(reviewedDownloads.dockerCompose.sha256, "u"),
  );
  assert.match(
    compose,
    /docker\/compose\/releases\/download\/\$\{DOCKER_COMPOSE_VERSION\}\/docker-compose-linux-x86_64/u,
  );
  assert.match(compose, /--proto '=https'/u);
  assert.match(compose, /--proto-redir '=https'/u);
  assert.match(compose, /sha256sum --check -/u);
  assert.match(compose, /install -m 0755/u);
  assert.match(compose, /docker-compose version/u);
});

test("Node dependency installs are frozen to committed lockfiles", () => {
  for (const directory of [
    "client-admin",
    "client-report",
    "e2e",
    "server",
  ]) {
    const packagePath = join(repositoryRoot, directory, "package.json");
    const lockPath = join(repositoryRoot, directory, "package-lock.json");
    assert.ok(
      existsSync(lockPath),
      `${directory} must retain the lockfile required by npm ci`,
    );
    const packageJson = JSON.parse(readFileSync(packagePath, "utf8"));
    const packageLock = JSON.parse(readFileSync(lockPath, "utf8"));
    assert.equal(packageLock.lockfileVersion, 3);
    assert.ok(packageLock.packages?.[""]);
    for (const section of [
      "dependencies",
      "devDependencies",
      "optionalDependencies",
      "peerDependencies",
    ]) {
      assert.deepEqual(
        packageLock.packages[""][section] ?? {},
        packageJson[section] ?? {},
        `${directory} ${section} must match its lockfile root`,
      );
    }
  }

  const combined = Object.values(workflows).join("\n");
  assert.doesNotMatch(combined, /\bnpm install(?:\s|$)/u);
  assert.match(workflows["jest-client-report-test.yml"], /run: npm ci/u);
  assert.equal(
    workflows["lint.yml"].match(/run: npm ci/gu)?.length,
    4,
  );
  assert.match(
    workflows["cypress-tests.yml"],
    /name: Run auth setup test[\s\S]*?npm ci/u,
  );
});

test("Codecov uses the fixed reviewed CLI with integrity checks enabled", () => {
  for (const workflow of [
    "client-participation-alpha-ci.yml",
    "jest-client-admin-test.yml",
  ]) {
    const source = workflows[workflow];
    assert.match(
      source,
      new RegExp(`version: ${reviewedDownloads.codecovCli.version}`, "u"),
    );
    assert.doesNotMatch(source, /skip_validation:\s*true/u);
  }
});

test("deployment triggers, repository guards and environments are preserved", () => {
  const alpha = workflows["deploy-alpha-aws.yml"];
  assert.match(alpha, /^on: workflow_dispatch$/mu);
  assert.equal(
    alpha.match(/if: github\.repository == 'compdemocracy\/polis'/gu)?.length,
    3,
  );
  assert.equal(alpha.match(/environment: production/gu)?.length, 2);
  assert.equal(alpha.match(/environment: europe/gu)?.length, 1);
  assert.match(alpha, /aws-region: us-east-1/u);
  assert.match(alpha, /aws-region: eu-central-1/u);

  const preprod = workflows["deploy-preprod.yml"];
  assert.match(preprod, /push:\n    branches:\n      - edge/u);
  assert.match(preprod, /if: github\.repository == 'compdemocracy\/polis'/u);
  assert.match(preprod, /role-session-name: GitHubActionsDeployPreprod/u);
  assert.match(preprod, /aws-region: us-east-1/u);

  const prod = workflows["deploy-prod.yml"];
  assert.match(prod, /push:\n    branches:\n      - stable/u);
  assert.equal(
    prod.match(/if: github\.repository == 'compdemocracy\/polis'/gu)?.length,
    2,
  );
  assert.match(prod, /environment: production/u);
  assert.match(prod, /GitHubActionsDeployProdUS/u);
  assert.match(prod, /GitHubActionsDeployProdEuro/u);
  assert.match(prod, /aws-region: us-east-1/u);
  assert.match(prod, /aws-region: eu-central-1/u);
});

test("manual sensemaker behavior is reproducible without legacy actions", () => {
  const source = workflows["sensemaker-cron.yml"];
  assert.match(source, /^on: workflow_dispatch$/mu);
  assert.match(
    source,
    /ref: 988ad3547a9b5c3fe92fa6cd2bbff9837795fb6b/u,
  );
  assert.match(source, /run: npm ci/u);
  assert.match(source, /--proto '=https'/u);
  assert.match(source, /gh api[\s\S]*--method PATCH[\s\S]*"gists\/\$GIST_ID"/u);
  assert.match(source, /GIST_TOKEN/u);
});

test("PR comment permission is isolated from the test workload", () => {
  const permissions = jobPermissionMap(workflows["python-ci.yml"]);
  assert.deepEqual(permissions.test, { contents: "read" });
  assert.deepEqual(permissions["comment-coverage"], {
    "pull-requests": "write",
  });
  assert.match(
    workflows["python-ci.yml"],
    /if: github\.event_name == 'pull_request' && needs\.test\.result == 'success'/u,
  );
});
