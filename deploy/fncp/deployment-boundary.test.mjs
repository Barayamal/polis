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
const sourceBoundDockerfiles = new Map(
  await Promise.all(
    [
      ["server", join(deployDir, "..", "..", "server", "Dockerfile")],
      ["math", join(deployDir, "..", "..", "math", "Dockerfile")],
      [
        "client-participation-alpha",
        join(
          deployDir,
          "..",
          "..",
          "client-participation-alpha",
          "Dockerfile"
        )
      ],
      ["nginx-proxy", join(deployDir, "nginx", "Dockerfile")]
    ].map(async ([service, path]) => [service, await readFile(path, "utf8")])
  )
);

const repositoryRoot = join(deployDir, "..", "..");
const [ciCompose, ciProxyRecipe, ciProxyIgnore, legacyProxyConfig, developmentCompose] =
  await Promise.all([
    "docker-compose.test.yml",
    "file-server/nginx.test.Dockerfile",
    "file-server/nginx.test.Dockerfile.dockerignore",
    "file-server/nginx/nginx-ssl.site.default.conf",
    "docker-compose.yml",
  ].map((path) => readFile(join(repositoryRoot, path), "utf8")));

function ciProxyBlock() {
  const match = ciCompose.match(/^  nginx-proxy:\n[\s\S]*?(?=^  file-server:)/mu);
  assert.ok(match, "missing disposable CI proxy");
  return match[0];
}

test("legacy CI proxy receives credentials only at runtime, never in its image", () => {
  assert.match(ciProxyRecipe,
    /^FROM docker\.io\/library\/nginx:1\.21\.5-alpine@sha256:eb05700fe7baa6890b74278e39b66b2ed1326831f9ec3ed4bdc6361a4ac2f333$/mu);
  assert.deepEqual(ciProxyRecipe.split("\n").filter((line) => /^COPY\b/u.test(line)), [
    "COPY nginx/nginx-ssl.site.default.conf /etc/nginx/conf.d/default.conf.template",
    "COPY nginx/docker-entrypoint.sh /docker-entrypoint.sh",
  ]);
  assert.doesNotMatch(ciProxyRecipe, /^ADD\b|^(?:COPY|RUN).*\.(?:pem|key)|^RUN.*(?:mkcert|openssl)/mu);
  assert.match(ciProxyRecipe, /mkdir -p \/etc\/nginx\/certs/u);
  assert.match(ciProxyRecipe, /not an FNCP production release candidate/u);
});

test("CI proxy build context denies certificate, key and unrelated source submission", () => {
  assert.deepEqual(ciProxyIgnore.trim().split("\n"), [
    "**",
    "!nginx",
    "!nginx/nginx-ssl.site.default.conf",
    "!nginx/docker-entrypoint.sh",
    "!nginx.test.Dockerfile",
    "!nginx.test.Dockerfile.dockerignore",
  ]);
  assert.doesNotMatch(ciProxyIgnore, /!.*(?:certs|\.pem|\.key|\*)/u);
});

test("CI proxy maps the generated leaf and key to exact readonly TLS paths", () => {
  const block = ciProxyBlock();
  assert.match(block, /context: \.\/file-server\n\s+dockerfile: nginx\.test\.Dockerfile/u);
  const mounts = [...block.matchAll(/      - type: bind\n([\s\S]*?)(?=      - type: bind|    labels:)/gu)];
  assert.equal(mounts.length, 2);
  for (const [index, [source, target]] of [
    ["localhost.pem", "snakeoil.cert.pem"],
    ["localhost-key.pem", "snakeoil.key.pem"],
  ].entries()) {
    const mount = mounts[index][1];
    assert.ok(mount.includes('source: "${AUTH_CERTS_PATH:?AUTH_CERTS_PATH is required for disposable CI certificates}/' + source + '"'));
    assert.ok(mount.includes("target: /etc/nginx/certs/" + target));
    assert.match(mount, /read_only: true\n\s+bind:\n\s+create_host_path: false/u);
    assert.ok(legacyProxyConfig.includes("/etc/nginx/certs/" + target + ";"));
  }
  assert.doesNotMatch(block, /rootCA\.pem|:rw\b|build:\n[\s\S]*?secrets:/u);
  assert.match(developmentCompose, /context: \.\/file-server\n\s+dockerfile: nginx\.Dockerfile/u);
  assert.doesNotMatch(developmentCompose, /nginx\.test\.Dockerfile/u);
});

test("all three legacy CI workflows generate the mounted certificate pair before building", async () => {
  for (const name of ["python-ci.yml", "cypress-tests.yml", "jest-server-test.yml"]) {
    const workflow = await readFile(join(repositoryRoot, ".github/workflows", name), "utf8");
    const generation = workflow.indexOf("mkcert -cert-file localhost.pem -key-file localhost-key.pem");
    assert.ok(generation >= 0, name + " must generate the exact disposable leaf/key pair");
    assert.ok(workflow.indexOf("mkdir -p ./.simulacrum/certs") < generation);
    assert.match(workflow, /localhost 127\.0\.0\.1 ::1 oidc-simulator host\.docker\.internal/u);
    assert.match(workflow, /AUTH_CERTS_PATH=.*AUTH_CERTS_PATH=\.\/\.simulacrum\/certs/u);
    assert.ok(workflow.indexOf("docker compose -f docker-compose.test.yml", generation) > generation);
    assert.doesNotMatch(workflow, /cp .*snakeoil|COPY .*snakeoil/u);
  }
});

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
    "127.0.0.1:5501:5000",
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

test("every participant-path image is bound to the exact Pol.is source", () => {
  assert.match(
    stagingEnvironment,
    /^FNCP_SERVER_BUILD_TARGET=fncp-production$/m
  );
  for (const [service, dockerfile] of sourceBoundDockerfiles) {
    const block = composeServiceBlock(service);
    assert.match(
      block,
      /SOURCE_REVISION: \$\{FNCP_SOURCE_REVISION\}/,
      `${service} must receive the exact source revision`
    );
    assert.match(dockerfile, /^ARG SOURCE_REVISION$/mu, service);
    assert.match(
      dockerfile,
      /org\.opencontainers\.image\.source="https:\/\/github\.com\/Barayamal\/polis"/u,
      service
    );
    assert.match(
      dockerfile,
      /org\.opencontainers\.image\.revision="\$\{SOURCE_REVISION\}"/u,
      service
    );
    assert.match(
      dockerfile,
      /test "\$\{#SOURCE_REVISION\}" -eq 40/u,
      service
    );
  }
  assert.match(
    sourceBoundDockerfiles.get("server"),
    /FROM prod AS fncp-production[\s\S]*org\.barayamal\.fncp\.release-mode="production"/u
  );
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

test("public QA proxy exposes only alpha assets and five fixed-statement capabilities", () => {
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
    ["/api/v3/comments", "GET"],
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

test("five retained capabilities and the upstream comment route retain XID revalidation", () => {
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
    "allowed",
    "vote",
    "warm",
    "missing",
    "invalid",
    "oidc_bypass",
    "revoked",
    "warm_revoked",
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
  assert.match(smoke, /Direct participant SSR with bare XID/);
  assert.match(smoke, /Direct participant SSR without XID/);
  assert.match(
    smoke,
    /Gateway access required\./
  );
});
