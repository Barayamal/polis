import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

// Run this installed-tool smoke in the pinned server Node 22 container with
// the repository mounted at /repo and a clean /repo/server/node_modules volume.
const server = fileURLToPath(new URL("../../server/", import.meta.url));
const requireServer = createRequire(path.join(server, "package.json"));
const cli = requireServer("nodemon/lib/cli");
const nodemonBin = requireServer.resolve("nodemon/bin/nodemon.js");

test("Nodemon 3 preserves the server debug/build-watch argument shape without opening a debugger", async () => {
  const manifest = JSON.parse(await readFile(path.join(server, "package.json"), "utf8"));
  for (const name of ["debug", "build:watch"]) {
    assert.match(manifest.scripts[name], /nodemon --inspect=0\.0\.0\.0:9229 dist\/index\.js/u);
  }
  const parsed = cli.parse([
    process.execPath,
    nodemonBin,
    "--inspect=0.0.0.0:9229",
    "dist/index.js",
  ]);
  assert.equal(parsed.script, "dist/index.js");
  assert.deepEqual(parsed.args, ["--inspect=0.0.0.0:9229"]);
  assert.equal(parsed.scriptPosition, 1);
});

test("Nodemon 3 starts, reloads a changed synthetic file, preserves env and shuts down", { timeout: 25_000 }, async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "fncp-nodemon-compat-"));
  const fixture = path.join(directory, "fixture.js");
  const fixtureSource = (version) =>
    `console.log(JSON.stringify({fncpFixture:${version},level:process.env.SERVER_LOG_LEVEL})); setInterval(() => {}, 1000);`;
  await writeFile(fixture, fixtureSource(1), { mode: 0o600 });
  const child = spawn(process.execPath, [
    nodemonBin, "--no-update-notifier", "--no-stdin", "--no-colours",
    "--legacy-watch", "--polling-interval", "100", "--delay", "100ms",
    "--watch", directory, "--ext", "js", fixture,
  ], {
    cwd: directory,
    env: { ...process.env, SERVER_LOG_LEVEL: "debug", NO_UPDATE_NOTIFIER: "1" },
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const exit = once(child, "exit");
  let output = "";
  child.stdout.on("data", (chunk) => { output += chunk.toString(); });
  child.stderr.on("data", (chunk) => { output += chunk.toString(); });
  const waitFor = async (value) => {
    const deadline = Date.now() + 10_000;
    while (!output.includes(value)) {
      if (child.exitCode !== null || child.signalCode !== null) {
        throw new Error(`Synthetic watcher exited early: ${output}`);
      }
      if (Date.now() >= deadline) throw new Error(`Synthetic watcher timed out: ${output}`);
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  };
  try {
    await waitFor('"fncpFixture":1,"level":"debug"');
    await writeFile(fixture, fixtureSource(2));
    await waitFor('"fncpFixture":2,"level":"debug"');
    assert.match(output, /restarting due to changes/u);
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      // Only the process group created above is stopped; no global process search.
      process.kill(-child.pid, "SIGTERM");
    }
    const deadline = new Promise((_, reject) => {
      const timer = setTimeout(() => reject(new Error("Synthetic watcher did not stop")), 3000);
      timer.unref();
    });
    try { await Promise.race([exit, deadline]); }
    finally { await rm(directory, { recursive: true, force: true }); }
  }
});
