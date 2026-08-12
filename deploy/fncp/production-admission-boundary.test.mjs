import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const deployDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(deployDir, "..", "..");
const [
  admission,
  index,
  gateway,
  provider,
  staging,
  prepare,
  bootstrap,
  activate,
  compose,
  collector,
  docs,
  workflow,
  dockerfile,
] = await Promise.all([
  readFile(
    join(repoRoot, "server", "src", "auth", "fncp-production-admission.ts"),
    "utf8",
  ),
  readFile(join(repoRoot, "server", "index.ts"), "utf8"),
  readFile(join(repoRoot, "server", "src", "auth", "fncp-gateway.ts"), "utf8"),
  readFile(join(repoRoot, "server", "src", "fncp-provider-policy.ts"), "utf8"),
  readFile(join(deployDir, "staging.env.example"), "utf8"),
  readFile(join(deployDir, "prepare-staging.sh"), "utf8"),
  readFile(
    join(deployDir, "bootstrap-synthetic-conversation.sh"),
    "utf8",
  ),
  readFile(join(deployDir, "activate-synthetic-binding.sh"), "utf8"),
  readFile(join(deployDir, "docker-compose.staging.yml"), "utf8"),
  readFile(join(deployDir, "collect-image-security-evidence.sh"), "utf8"),
  readFile(
    join(repoRoot, "server", "docs", "FNCP_PRODUCTION_ADMISSION.md"),
    "utf8",
  ),
  readFile(
    join(repoRoot, ".github", "workflows", "fncp-option-c-ci.yml"),
    "utf8",
  ),
  readFile(join(repoRoot, "server", "Dockerfile"), "utf8"),
]);

test("the production entrypoint admits before opening a socket", () => {
  assert.match(index, /assertFncpProductionAdmission\(\);[\s\S]*app\.listen/u);
  assert.match(dockerfile, /CMD \["node",[\s\S]*"dist\/index\.js"\]/u);
});

test("the dedicated image cannot omit the release mode into ordinary Pol.is", () => {
  assert.match(
    dockerfile,
    /FROM prod AS fncp-production[\s\S]*?ENV FNCP_OPTION_C_RELEASE_MODE=production/u,
  );
  assert.match(
    dockerfile,
    /LABEL org\.barayamal\.fncp\.release-mode="production"/u,
  );
  assert.match(dockerfile, /FROM prod AS upstream-production/u);
  assert.match(workflow, /--target fncp-production/u);
  assert.match(workflow, /test "\$FNCP_OPTION_C_RELEASE_MODE" = production/u);
  assert.match(
    collector,
    /FNCP_SERVER_BUILD_TARGET=fncp-production docker compose/u,
  );
  assert.match(collector, /fncpReleaseMode === "production"/u);
  assert.match(compose, /target: \$\{FNCP_SERVER_BUILD_TARGET:-prod\}/u);
});

test("dedicated admission requires exact dual enforcement and one conversation", () => {
  assert.match(admission, /FNCP_OPTION_C_RELEASE_MODE/u);
  assert.match(admission, /releaseMode === undefined/u);
  assert.match(admission, /releaseMode !== DEDICATED_RELEASE_MODE/u);
  assert.match(admission, /env\.NODE_ENV !== "production"/u);
  assert.match(admission, /env\.FNCP_GATEWAY_ENFORCEMENT !== "true"/u);
  assert.match(
    admission,
    /env\.FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT !== "true"/u,
  );
  assert.match(
    admission,
    /provider\.conversationId !== gateway\.conversationId/u,
  );
  assert.match(
    admission,
    /sameCredential\(gateway\.sharedSecret, provider\.bearerCredential\)/u,
  );
  assert.doesNotMatch(admission, /console\.|logger\./u);
});

test("dedicated request-time loaders fail closed instead of disabling policy", () => {
  for (const source of [gateway, provider]) {
    assert.match(source, /env\.FNCP_OPTION_C_RELEASE_MODE !== undefined/u);
    assert.match(source, /enabled: dedicatedReleaseConfigured \|\|/u);
    assert.match(
      source,
      /!dedicatedReleaseConfigured \|\|[\s\S]*dedicatedProduction &&[\s\S]*activation === "true"/u,
    );
  }
  assert.match(gateway, /!config\.activationValid/u);
  assert.match(provider, /if \(!config\.activationValid\)/u);
});

test("synthetic staging starts the dedicated contract on an absent generated binding", () => {
  assert.match(staging, /^FNCP_SERVER_BUILD_TARGET=fncp-production$/mu);
  assert.doesNotMatch(staging, /^FNCP_OPTION_C_RELEASE_MODE=/mu);
  assert.match(staging, /^FNCP_GATEWAY_ENFORCEMENT=true$/mu);
  assert.match(staging, /^FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT=true$/mu);
  assert.match(
    staging,
    /^FNCP_GATEWAY_CONVERSATION_ID=REPLACE_WITH_BOOTSTRAP_CONVERSATION_ID$/mu,
  );
  assert.match(
    staging,
    /^FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID=REPLACE_WITH_BOOTSTRAP_CONVERSATION_ID$/mu,
  );
  assert.match(
    prepare,
    /bootstrap_conversation_id="9fncpBootstrap\$\(openssl rand -hex 24\)"/u,
  );
  assert.match(
    prepare,
    /while \[ "\$provider_allowlist_credential" = "\$gateway_shared_secret" \]/u,
  );
  assert.match(
    bootstrap,
    /profiles?: synthetic-bootstrap-only|--profile synthetic-bootstrap-only/u,
  );
  assert.match(activate, /--force-recreate server/u);
  assert.match(activate, /--force-recreate client-participation-alpha/u);
});

test("the operator guidance forbids enforcement-disable emergency handling", () => {
  assert.match(docs, /Never set either enforcement switch to `false`/u);
  assert.match(docs, /deny public ingress/u);
  assert.match(docs, /revoke active invitations/u);
});

test("the PR gate runs this production admission boundary", () => {
  assert.match(workflow, /production-admission-boundary\.test\.mjs/u);
});
