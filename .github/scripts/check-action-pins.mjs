import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

const workflowDirectory = new URL("../workflows/", import.meta.url);
const allowedActions = new Set([
  "DeLaGuardo/setup-clojure",
  "actions/cache",
  "actions/checkout",
  "actions/download-artifact",
  "actions/github-script",
  "actions/setup-java",
  "actions/setup-node",
  "actions/setup-python",
  "actions/upload-artifact",
  "aws-actions/amazon-ecr-login",
  "aws-actions/configure-aws-credentials",
  "codecov/codecov-action",
  "docker/setup-buildx-action",
  "exuanbo/actions-deploy-gist",
  "google-github-actions/auth",
  "valitydev/action-download-file",
]);

const failures = [];
let referencesChecked = 0;

for (const filename of await readdir(workflowDirectory)) {
  if (!/\.ya?ml$/u.test(filename)) continue;

  const path = join(workflowDirectory.pathname, filename);
  const contents = await readFile(path, "utf8");

  for (const [lineIndex, line] of contents.split("\n").entries()) {
    if (/^\s*#/u.test(line)) continue;

    const match = line.match(
      /^\s*(?:-\s*)?uses:\s*["']?([^@\s"']+)@([^\s"'#]+)["']?/u
    );
    if (!match || match[1].startsWith("./")) continue;

    const [, action, reference] = match;
    referencesChecked += 1;

    if (!allowedActions.has(action)) {
      failures.push(`${filename}:${lineIndex + 1}: ${action} is not allowlisted`);
    }
    if (!/^[0-9a-f]{40}$/u.test(reference)) {
      failures.push(
        `${filename}:${lineIndex + 1}: ${action}@${reference} is not a full commit SHA`
      );
    }
  }
}

if (failures.length > 0) {
  console.error(failures.join("\n"));
  process.exitCode = 1;
} else {
  console.log(
    `Verified ${referencesChecked} external action references against the pinned allowlist.`
  );
}
