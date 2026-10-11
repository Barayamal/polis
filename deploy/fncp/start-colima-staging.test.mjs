import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { access, chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const deployDir = dirname(fileURLToPath(import.meta.url));
const source = await readFile(join(deployDir, "start-colima-staging.sh"), "utf8");
const revision = "a".repeat(40);
const services = ["server", "math", "client-participation-alpha", "nginx-proxy"];

// Every Docker/Git command is intercepted in a disposable source-shaped tree.
// No existing env file, credential, Docker context, container or VM is read.
const mockDocker = `#!${process.execPath}
import { appendFileSync } from "node:fs";
const args = process.argv.slice(2);
appendFileSync(process.env.FNCP_TEST_LOG, JSON.stringify(["docker", ...args]) + "\\n");
const scenario = process.env.FNCP_TEST_SCENARIO;
const service = process.env.FNCP_TEST_SERVICE;
const expected = ${JSON.stringify(revision)};
if (args[0] === "compose") {
  const operation = args[7];
  const target = args.at(-1);
  if (operation === "ps" && args.includes("-aq")) {
    process.stdout.write(target + "-fixture\\n");
  } else if (operation === "images") {
    if (scenario === "image-command-failure" && target === service) process.exit(2);
    if (!(scenario === "missing-image" && target === service)) process.stdout.write(target + "-image\\n");
  }
  process.exit(0);
}
if (args[0] === "image" && args[1] === "inspect") {
  const target = args[2].replace(/-image$/, "");
  const isRelease = args.at(-1).includes("release-mode");
  // A failed command that emitted a plausible label must still be rejected.
  if (isRelease) {
    process.stdout.write(scenario === "wrong-release" ? "upstream\\n" : "production\\n");
    if (scenario === "release-inspect-failure") process.exit(2);
  } else {
    process.stdout.write(scenario === "wrong-revision" && target === service ? "b".repeat(40) + "\\n" : expected + "\\n");
    if (scenario === "revision-inspect-failure" && target === service) process.exit(2);
  }
  process.exit(0);
}
if (args[0] === "cp") process.exit(0);
process.exit(3);
`;

const mockGit = `#!${process.execPath}
import { appendFileSync } from "node:fs";
const args = process.argv.slice(2);
appendFileSync(process.env.FNCP_TEST_LOG, JSON.stringify(["git", ...args]) + "\\n");
if (JSON.stringify(args) !== JSON.stringify(["rev-parse", "HEAD"])) process.exit(3);
if (process.env.FNCP_TEST_SCENARIO === "git-failure") process.exit(2);
process.stdout.write(${JSON.stringify(revision + "\n")});
`;

async function runFixture(scenario = "pass", service = "server") {
  const root = await mkdtemp(join(tmpdir(), "fncp-staging-admission-"));
  try {
    const staging = join(root, "deploy", "fncp");
    const bin = join(root, "bin");
    const log = join(root, "commands.jsonl");
    await Promise.all([
      mkdir(join(staging, "certs"), { recursive: true }),
      mkdir(join(root, "server", "keys"), { recursive: true }),
      mkdir(bin),
    ]);
    await Promise.all([
      writeFile(join(staging, "start-colima-staging.sh"), source),
      writeFile(join(staging, ".env.staging"), "# synthetic test placeholder only\n"),
      ...["localhost.pem", "localhost-key.pem", "rootCA.pem"].map((name) =>
        writeFile(join(staging, "certs", name), "not-a-real-certificate\n")),
      ...["jwt-private.pem", "jwt-public.pem"].map((name) =>
        writeFile(join(root, "server", "keys", name), "not-a-real-key\n")),
      writeFile(join(bin, "docker"), mockDocker),
      writeFile(join(bin, "git"), mockGit),
      // Force ESM independently of the host/ancestor package.json.
      writeFile(join(bin, "package.json"), '{"type":"module"}\n'),
      writeFile(log, ""),
    ]);
    await Promise.all([chmod(join(bin, "docker"), 0o700), chmod(join(bin, "git"), 0o700)]);
    const result = spawnSync("/bin/sh", [join(staging, "start-colima-staging.sh")], {
      cwd: root,
      encoding: "utf8",
      timeout: 15_000,
      env: {
        PATH: `${bin}:/usr/bin:/bin`,
        FNCP_TEST_LOG: log,
        FNCP_TEST_SCENARIO: scenario,
        FNCP_TEST_SERVICE: service,
      },
    });
    assert.ifError(result.error);
    assert.equal(result.signal, null);
    const commands = (await readFile(log, "utf8")).trim().split("\n").filter(Boolean).map(JSON.parse);
    const marker = await readFile(join(staging, ".colima-staging"), "utf8").catch((error) => {
      if (error.code !== "ENOENT") throw error;
      return null;
    });
    // The script may stop failed fixtures, but must never remove their store.
    await access(join(staging, ".env.staging"));
    return { status: result.status, stderr: result.stderr, commands, marker };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

function composeOperation(command) {
  return command[0] === "docker" && command[1] === "compose" ? command[8] : null;
}

test("valid created images are all admitted before exactly one start", async () => {
  const result = await runFixture();
  assert.equal(result.status, 0, result.stderr);
  const starts = result.commands.map((command, index) => composeOperation(command) === "start" ? index : -1).filter((index) => index >= 0);
  assert.equal(starts.length, 1);
  const inspections = result.commands.map((command, index) => command[0] === "docker" && command[1] === "image" && command[2] === "inspect" ? index : -1).filter((index) => index >= 0);
  assert.equal(inspections.length, 5);
  assert.ok(inspections.every((index) => index < starts[0]));
  const copies = result.commands.map((command, index) => command[0] === "docker" && command[1] === "cp" ? index : -1).filter((index) => index >= 0);
  assert.equal(copies.length, 3);
  assert.ok(copies.every((index) => index > inspections.at(-1) && index < starts[0]));
  const create = result.commands.findIndex((command) => composeOperation(command) === "create");
  assert.ok(create >= 0 && inspections.every((index) => index > create));
  assert.deepEqual(result.commands.filter((command) => command[0] === "docker" && command[1] === "image").map((command) => command[3]), [...services.map((name) => `${name}-image`), "server-image"]);
  assert.equal(result.marker, "compose-override=docker-compose.colima.yml\n");
});

for (const service of services) {
  for (const scenario of ["wrong-revision", "revision-inspect-failure"]) {
    test(`${service}: ${scenario} cannot start any service or write admission marker`, async () => {
      const result = await runFixture(scenario, service);
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /Disposable image source verification failed/);
      assert.equal(result.commands.some((command) => composeOperation(command) === "start"), false);
      assert.equal(result.commands.some((command) => command[0] === "docker" && command[1] === "cp"), false);
      assert.equal(result.marker, null);
    });
  }
}

for (const scenario of ["wrong-release", "release-inspect-failure", "missing-image", "image-command-failure", "git-failure"]) {
  test(`${scenario} cannot start any service or write admission marker`, async () => {
    const result = await runFixture(scenario);
    assert.notEqual(result.status, 0);
    assert.equal(result.commands.some((command) => composeOperation(command) === "start"), false);
    assert.equal(result.commands.some((command) => command[0] === "docker" && command[1] === "cp"), false);
    assert.equal(result.marker, null);
  });
}
