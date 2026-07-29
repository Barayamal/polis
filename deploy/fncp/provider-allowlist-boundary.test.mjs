import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const deployDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(deployDir, "..", "..");
const [
  serverApp,
  adapter,
  proxy,
  compose,
  stagingEnvironment,
  prepare,
  requestLogger,
  domain,
  workflow,
  managedPolicy,
  xidRoutes,
  conversations,
  participantAccess,
] = await Promise.all([
  readFile(join(repoRoot, "server", "app.ts"), "utf8"),
  readFile(
    join(
      repoRoot,
      "server",
      "src",
      "routes",
      "fncp-provider-allowlist.ts"
    ),
    "utf8"
  ),
  readFile(join(deployDir, "nginx", "fncp-staging.conf"), "utf8"),
  readFile(join(deployDir, "docker-compose.staging.yml"), "utf8"),
  readFile(join(deployDir, "staging.env.example"), "utf8"),
  readFile(join(deployDir, "prepare-staging.sh"), "utf8"),
  readFile(join(repoRoot, "server", "src", "server-middleware.ts"), "utf8"),
  readFile(join(repoRoot, "server", "src", "utils", "domain.ts"), "utf8"),
  readFile(
    join(repoRoot, ".github", "workflows", "fncp-option-c-ci.yml"),
    "utf8"
  ),
  readFile(
    join(repoRoot, "server", "src", "fncp-provider-policy.ts"),
    "utf8"
  ),
  readFile(join(repoRoot, "server", "src", "routes", "xids.ts"), "utf8"),
  readFile(
    join(repoRoot, "server", "src", "routes", "conversations.ts"),
    "utf8"
  ),
  readFile(
    join(repoRoot, "server", "src", "auth", "ensure-participant.ts"),
    "utf8"
  ),
]);

const privatePaths = [
  "/fncp/private/xid-allowlist/upsert",
  "/fncp/private/xid-allowlist/readback",
  "/fncp/private/xid-allowlist/remove",
];

test("the authority adapter exposes only three fixed POST operations", () => {
  for (const [operation, path] of [
    ["upsert", privatePaths[0]],
    ["readback", privatePaths[1]],
    ["remove", privatePaths[2]],
  ]) {
    assert.match(adapter, new RegExp(`${operation}: "${path}"`));
    assert.match(
      serverApp,
      new RegExp(
        `app\\.post\\(\\s*FNCP_PROVIDER_ALLOWLIST_PATHS\\.${operation},` +
          `[\\s\\S]*?fncpProviderAllowlistHandlers\\.${operation}`
      )
    );
  }
  assert.equal(
    [...serverApp.matchAll(/FNCP_PROVIDER_ALLOWLIST_PATHS\./g)].length,
    3
  );
  assert.doesNotMatch(serverApp, /app\.(?:get|put|delete)\(\s*FNCP_PROVIDER/);
});

test("the private operations are absent from the public participant proxy", () => {
  for (const path of privatePaths) {
    assert.doesNotMatch(proxy, new RegExp(path.replaceAll("/", "\\/")));
  }
  assert.match(proxy, /location \/ \{\n {8}return 404;/);
  assert.match(compose, /networks: \[fncp-internal, fncp-loopback\]/);
});

test("scope changes are parameterised and require an exact conversation gate", () => {
  assert.match(adapter, /c\.use_xid_whitelist IS TRUE/g);
  assert.match(
    adapter,
    /ON CONFLICT \(owner, xid\) DO UPDATE[\s\S]*WHERE xid_whitelist\.zid = EXCLUDED\.zid/
  );
  assert.match(
    adapter,
    /allowed\.zid = target\.zid[\s\S]*allowed\.owner = target\.owner[\s\S]*allowed\.xid = \$2/
  );
  assert.match(
    adapter,
    /fncp_provider_allowlist_operations\.operation_version\s*<[\s\S]*EXCLUDED\.operation_version/
  );
  assert.match(adapter, /operationVersion: 1 \| 2 \| null/);
  assert.doesNotMatch(adapter, /escapeLiteral|queryP_readOnly/);
  assert.equal(
    (adapter.match(/\[conversationId, participantXid, operationVersion\]/g) ??
      []).length,
    2
  );
  assert.equal(
    (adapter.match(/\[conversationId, participantXid\]/g) ?? []).length,
    1
  );
});

test("the managed conversation has one authoritative mutation and authorization path", () => {
  assert.match(
    managedPolicy,
    /FROM xid_whitelist allowed[\s\S]*INNER JOIN fncp_provider_allowlist_operations operation/
  );
  assert.match(
    managedPolicy,
    /allowed\.zid = \$1[\s\S]*allowed\.xid = \$2[\s\S]*operation\.operation_version = 1[\s\S]*operation\.desired_present IS TRUE/
  );
  assert.doesNotMatch(
    managedPolicy.match(
      /async isExactProviderAuthorized[\s\S]*?^\s{4}\},/m
    )?.[0] ?? "",
    /zid IS NULL/
  );
  assert.match(
    xidRoutes,
    /handle_POST_xidAllowList[\s\S]*resolveFncpManagedConversation\(zid\)[\s\S]*providerPolicy\.managed[\s\S]*polis_err_fncp_provider_managed_allowlist[\s\S]*insert into xid_whitelist/
  );
  assert.match(
    conversations,
    /providerPolicy\.managed[\s\S]*generateShortUrl === true[\s\S]*use_xid_whitelist === false[\s\S]*xid_required === false[\s\S]*polis_err_fncp_provider_managed_conversation/
  );
  assert.match(
    participantAccess,
    /resolveFncpManagedConversation\(zid\)[\s\S]*!conv\.use_xid_whitelist[\s\S]*providerPolicy\.managed[\s\S]*polis_err_fncp_provider_gate_unavailable/
  );
});

test("credentials are generated locally and never flow to participant runtime", () => {
  assert.match(
    stagingEnvironment,
    /^FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT=false$/m
  );
  assert.match(
    stagingEnvironment,
    /^FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID=$/m
  );
  assert.match(
    stagingEnvironment,
    /^FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL=REPLACE_WITH_RANDOM_VALUE$/m
  );
  assert.match(prepare, /provider_allowlist_credential=\$\(openssl rand -hex 32\)/);

  const alphaBlock = compose.match(
    /^  client-participation-alpha:\n([\s\S]*?)(?=^  nginx-proxy:)/m
  );
  assert.ok(alphaBlock);
  assert.doesNotMatch(alphaBlock[0], /FNCP_PROVIDER_ALLOWLIST/);
});

test("private body and header-bearing failures cannot enter application logs", () => {
  assert.doesNotMatch(adapter, /logger\.|console\./);
  assert.match(
    requestLogger,
    /req\.path\.startsWith\("\/fncp\/private\/"\)[\s\S]*private authority body redacted/
  );
  assert.doesNotMatch(domain, /redirecting to https", \{ headers:/);
  assert.doesNotMatch(
    domain,
    /CORS: domain not whitelisted"[\s\S]{0,160}headers:/
  );
});

test("the PR gate executes both source-boundary and PostgreSQL store tests", () => {
  assert.match(
    workflow,
    /deploy\/fncp\/provider-allowlist-boundary\.test\.mjs/
  );
  assert.match(
    workflow,
    /__tests__\/integration\/fncp-provider-allowlist-store\.test\.ts/
  );
});
