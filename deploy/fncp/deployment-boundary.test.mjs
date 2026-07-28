import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const deployDir = dirname(fileURLToPath(import.meta.url));
const compose = await readFile(
  join(deployDir, "docker-compose.staging.yml"),
  "utf8"
);
const dockerignore = await readFile(join(deployDir, ".dockerignore"), "utf8");
const proxyDockerfile = await readFile(
  join(deployDir, "nginx", "Dockerfile"),
  "utf8"
);
const proxyConfig = await readFile(
  join(deployDir, "nginx", "fncp-staging.conf"),
  "utf8"
);

function composeServiceBlock(serviceName) {
  const match = compose.match(
    new RegExp(
      `^  ${serviceName}:\\n([\\s\\S]*?)(?=^  [a-z0-9-]+:\\n|^networks:)`,
      "m"
    )
  );
  assert.ok(match, `missing Compose service ${serviceName}`);
  return match[0];
}

test("staging Compose declares a synthetic loopback-only, non-internet boundary", () => {
  assert.match(compose, /classification: synthetic-loopback-only/);
  assert.match(compose, /genuine-data: prohibited/);
  assert.match(compose, /internet-ready: "false"/);
  assert.match(compose, /fncp-internal:\n {4}internal: true/);
  assert.doesNotMatch(compose, /\b0\.0\.0\.0:/);

  const publishedPorts = [
    ...compose.matchAll(/"([^"\n]+:\d+:\d+)"/g),
  ].map((match) => match[1]);
  assert.deepEqual(publishedPorts.sort(), [
    "127.0.0.1:3000:3000",
    "127.0.0.1:5500:5000",
    "127.0.0.1:8088:80",
  ]);

  assert.match(compose, /DEV_MODE: "false"/);
  assert.match(compose, /ENABLE_TELEMETRY: "false"/);
  for (const nodeService of [
    "client-participation-alpha",
    "oidc-simulator",
    "server",
  ]) {
    assert.match(composeServiceBlock(nodeService), /NODE_ENV: production/);
  }
  assert.match(compose, /oidc-simulator:/);
});

test("minimal FNCP path ships alpha assets without full legacy bundles", () => {
  assert.doesNotMatch(compose, /^\s{2}file-server:/m);
  assert.doesNotMatch(compose, /file-server\/Dockerfile/);
  assert.match(compose, /dockerfile: nginx\/Dockerfile/);
  assert.match(compose, /STATIC_FILES_HOST: client-participation-alpha/);
  assert.deepEqual(dockerignore.trim().split("\n"), [
    "**",
    "!nginx/",
    "!nginx/Dockerfile",
    "!nginx/fncp-staging.conf",
  ]);

  const minimalPath = `${compose}\n${proxyDockerfile}\n${proxyConfig}`;
  for (const excludedBundle of [
    "client-admin",
    "client-participation/",
    "client-report",
    "admin_bundle",
    "report_bundle",
  ]) {
    assert.doesNotMatch(minimalPath, new RegExp(excludedBundle));
  }

  assert.match(proxyConfig, /proxy_pass http:\/\/client-participation-alpha:4321/);
  assert.match(proxyConfig, /client_max_body_size 8k/);
});

test("public QA proxy exposes only alpha assets and six method-route capabilities", () => {
  const exactApiLocations = [
    ...proxyConfig.matchAll(/location = (\/api\/v3\/[A-Za-z0-9/]+) \{/g),
  ].map((match) => match[1]);

  assert.deepEqual(exactApiLocations.sort(), [
    "/api/v3/comments",
    "/api/v3/math/pca2",
    "/api/v3/nextComment",
    "/api/v3/participationInit",
    "/api/v3/votes",
  ]);

  const expectedMethodGuards = new Map([
    ["/api/v3/comments", "GET|POST"],
    ["/api/v3/math/pca2", "GET"],
    ["/api/v3/nextComment", "GET"],
    ["/api/v3/participationInit", "GET"],
    ["/api/v3/votes", "POST"],
  ]);
  for (const [path, methods] of expectedMethodGuards) {
    assert.ok(
      proxyConfig.includes(
        `location = ${path} {\n` +
          `        if ($request_method !~ ^(${methods})$) { return 405; }`
      ),
      `${path} must allow only ${methods}`
    );
  }
  for (const deniedMethod of ["HEAD", "OPTIONS", "PUT", "DELETE", "PATCH"]) {
    for (const methods of expectedMethodGuards.values()) {
      assert.equal(
        new RegExp(`^(${methods})$`).test(deniedMethod),
        false,
        `${deniedMethod} must not match ${methods}`
      );
    }
  }

  assert.match(proxyConfig, /location \^~ \/_astro\//);
  assert.match(proxyConfig, /location \^~ \/alpha\//);
  assert.match(proxyConfig, /location \/ \{\n {8}return 404;/);
  assert.doesNotMatch(
    proxyConfig,
    /location \/ \{[\s\S]*proxy_pass http:\/\/server:5000/
  );
  assert.doesNotMatch(proxyConfig, /\blisten\s+443\b|\bssl_certificate\b/);
});
