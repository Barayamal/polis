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
const colimaStart = await readFile(
  join(deployDir, "start-colima-staging.sh"),
  "utf8"
);
const prepare = await readFile(join(deployDir, "prepare-staging.sh"), "utf8");
const stagingEnvironment = await readFile(
  join(deployDir, "staging.env.example"),
  "utf8"
);
const smoke = await readFile(join(deployDir, "smoke-test.sh"), "utf8");
const serverApp = await readFile(
  join(deployDir, "..", "..", "server", "app.ts"),
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
    "127.0.0.1:8088:8080",
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

  const server = composeServiceBlock("server");
  assert.match(server, /user: "\$\{SERVER_RUNTIME_UID\}:\$\{SERVER_RUNTIME_GID\}"/);
  assert.match(server, /NODE_EXTRA_CA_CERTS: \/run\/fncp-ca\/rootCA\.pem/);
  assert.match(server, /\.\/certs:\/run\/fncp-ca:ro/);
  assert.match(stagingEnvironment, /SERVER_RUNTIME_UID=REPLACE_WITH_LOCAL_UID/);
  assert.match(stagingEnvironment, /SERVER_RUNTIME_GID=REPLACE_WITH_LOCAL_GID/);
  assert.match(prepare, /server_runtime_uid=\$\(id -u\)/);
  assert.match(prepare, /server_runtime_gid=\$\(id -g\)/);
});

test("SSR and browser API requests traverse the same HTTPS-shaped boundary", () => {
  assert.match(
    stagingEnvironment,
    /^INTERNAL_SERVICE_URL=http:\/\/nginx-proxy:8080\/api\/v3$/m
  );
  assert.doesNotMatch(
    stagingEnvironment,
    /^INTERNAL_SERVICE_URL=http:\/\/server:5000\/api\/v3$/m
  );

  const forwardedProtoHeaders =
    proxyConfig.match(/proxy_set_header X-Forwarded-Proto https;/g) ?? [];
  assert.equal(forwardedProtoHeaders.length, 7);
  assert.doesNotMatch(
    proxyConfig,
    /proxy_set_header X-Forwarded-Proto \$scheme;/
  );
});

test("minimal FNCP path ships alpha assets without full legacy bundles", () => {
  assert.doesNotMatch(compose, /^\s{2}file-server:/m);
  assert.doesNotMatch(compose, /file-server\/Dockerfile/);
  assert.match(compose, /dockerfile: nginx\/Dockerfile/);
  assert.match(compose, /STATIC_FILES_HOST: client-participation-alpha/);
  const alpha = composeServiceBlock("client-participation-alpha");
  assert.match(alpha, /PUBLIC_AUTH_NAMESPACE: \$\{AUTH_NAMESPACE\}/);
  assert.doesNotMatch(alpha, /^\s+AUTH_NAMESPACE:/mu);
  assert.deepEqual(dockerignore.trim().split("\n"), [
    "**",
    "!nginx/",
    "!nginx/Dockerfile",
    "!nginx/fncp-staging.conf",
    "!busybox-fixed/",
    "!busybox-fixed/CVE-2025-60876.patch",
    "!busybox-fixed/build-fixed-busybox.sh",
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
  for (const imagePath of ["/_image", "/alpha/_image"]) {
    assert.ok(
      proxyConfig.includes(
        `location = ${imagePath} {\n` +
          "        return 404;\n" +
          "    }"
      ),
      `${imagePath} must not reach Astro's generated image endpoint`
    );
  }
  assert.match(proxyConfig, /location \/ \{\n {8}return 404;/);
  assert.doesNotMatch(
    proxyConfig,
    /location \/ \{[\s\S]*proxy_pass http:\/\/server:5000/
  );
  assert.doesNotMatch(proxyConfig, /\blisten\s+443\b|\bssl_certificate\b/);
  assert.match(proxyConfig, /\blisten\s+8080\s+default_server\b/);
  assert.match(proxyDockerfile, /^USER nginx$/mu);
});

test("all six retained participant capabilities explicitly revalidate the conversation XID allowlist", () => {
  const routeDefinitions = [
    ["get", "/api/v3/comments", "handle_GET_comments"],
    ["get", "/api/v3/math/pca2", "handle_GET_math_pca2"],
    ["get", "/api/v3/nextComment", "handle_GET_nextComment"],
    ["get", "/api/v3/participationInit", "handle_GET_participationInit"],
    ["post", "/api/v3/comments", "handle_POST_comments"],
    ["post", "/api/v3/votes", "handle_POST_votes"],
  ];

  for (const [method, path, handler] of routeDefinitions) {
    const escapedPath = path.replaceAll("/", "\\/");
    const route = serverApp.match(
      new RegExp(
        `app\\.${method}\\(\\s*"${escapedPath}"([\\s\\S]*?)${handler}`
      )
    );
    assert.ok(route, `missing ${method.toUpperCase()} ${path}`);
    assert.match(route[1], /hybridAuthOptional\(assignToP\)/);
    assert.match(
      route[1],
      /want\("xid", getStringLimitLength\(1, 999\), assignToP\)[\s\S]*revalidateConversationXidAllowlist\(\)/
    );
  }

  assert.equal(
    (
      serverApp.match(
        /^\s+revalidateConversationXidAllowlist\(\),$/gmu
      ) ?? []
    ).length,
    6
  );
});

test("cold-start helper validates and transfers disposable participant keys", () => {
  assert.match(colimaStart, /keys_dir="server\/keys"/);
  assert.match(
    colimaStart,
    /for signing_key in jwt-private\.pem jwt-public\.pem; do/
  );
  assert.match(
    colimaStart,
    /if \[ ! -s "\$keys_dir\/\$signing_key" \]; then/
  );
  assert.match(
    colimaStart,
    /docker cp -a "\$keys_dir" "\$server_container:\/app\/keys"/
  );
});

test("disposable smoke is readiness-bounded and models secure proxy requests", () => {
  assert.match(smoke, /while \[ "\$attempts" -lt 45 \]; do/);
  assert.match(smoke, /did not become ready within 45 seconds/);

  const apiRequests = [
    "conversation",
    "comment",
    "allowlist",
    "gate",
    "allowed",
    "vote",
    "warm",
    "missing",
    "invalid",
    "oidc_bypass",
    "revoke",
    "revoked",
    "warm_revoked",
    "close",
  ];
  for (const requestName of apiRequests) {
    const block = smoke.match(
      new RegExp(
        `${requestName}_status="\\$\\(request[\\s\\S]*?` +
          `\\n  "\\$api_origin\\/api\\/v3\\/[A-Za-z]+"\\)"`
      )
    );
    assert.ok(block, `missing smoke request block: ${requestName}`);
    assert.match(
      block[0],
      /--header "X-Forwarded-Proto: https"/,
      `${requestName} must model the reviewed HTTPS proxy signal`
    );
  }

  assert.match(
    smoke,
    /participant_origin="http:\/\/127\.0\.0\.1:8088"/
  );
  assert.match(smoke, /Allowlisted participant SSR/);
  assert.match(smoke, /Missing-XID participant SSR/);
  assert.match(
    smoke,
    /This conversation requires an XID \(external identifier\) to participate\./
  );
});
