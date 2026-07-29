import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmod,
  mkdtemp,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const deployDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(deployDir, "..", "..");
const [
  prepare,
  bootstrap,
  activate,
  rewrite,
  smoke,
  staging,
  compose,
  colimaCompose,
  colimaStart,
  readme,
  workflow,
  ignore,
] = await Promise.all([
  readFile(join(deployDir, "prepare-staging.sh"), "utf8"),
  readFile(join(deployDir, "bootstrap-synthetic-conversation.sh"), "utf8"),
  readFile(join(deployDir, "activate-synthetic-binding.sh"), "utf8"),
  readFile(
    join(deployDir, "rewrite-synthetic-bootstrap-binding.mjs"),
    "utf8"
  ),
  readFile(join(deployDir, "smoke-test.sh"), "utf8"),
  readFile(join(deployDir, "staging.env.example"), "utf8"),
  readFile(join(deployDir, "docker-compose.staging.yml"), "utf8"),
  readFile(join(deployDir, "docker-compose.colima.yml"), "utf8"),
  readFile(join(deployDir, "start-colima-staging.sh"), "utf8"),
  readFile(join(deployDir, "README.md"), "utf8"),
  readFile(
    join(repoRoot, ".github", "workflows", "fncp-option-c-ci.yml"),
    "utf8"
  ),
  readFile(join(repoRoot, ".gitignore"), "utf8"),
]);

test("prepare creates a guarded absent binding and two distinct credentials", () => {
  assert.match(staging, /^FNCP_SERVER_BUILD_TARGET=fncp-production$/mu);
  assert.match(staging, /^FNCP_SYNTHETIC_BOOTSTRAP_COMPLETE=false$/mu);
  assert.match(staging, /^FNCP_GATEWAY_ENFORCEMENT=true$/mu);
  assert.match(staging, /^FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT=true$/mu);
  assert.equal(
    (
      staging.match(
        /=REPLACE_WITH_BOOTSTRAP_CONVERSATION_ID$/gmu
      ) ?? []
    ).length,
    2
  );
  assert.match(
    prepare,
    /gateway_shared_secret=\$\(openssl rand -hex 32\)/u
  );
  assert.match(
    prepare,
    /provider_allowlist_credential=\$\(openssl rand -hex 32\)/u
  );
  assert.match(
    prepare,
    /while \[ "\$provider_allowlist_credential" = "\$gateway_shared_secret" \]/u
  );
  assert.match(
    prepare,
    /bootstrap_conversation_id="9fncpBootstrap\$\(openssl rand -hex 24\)"/u
  );
  assert.doesNotMatch(prepare, /4bumwmv4zf/u);
});

test("bootstrap API is profile-gated, ordinary, loopback-only and synthetic", () => {
  const block = compose.match(
    /^  server-bootstrap:\n([\s\S]*?)(?=^  [a-z0-9-]+:\n|^networks:)/mu
  );
  assert.ok(block);
  assert.match(block[0], /profiles: \[synthetic-bootstrap-only\]/u);
  assert.match(block[0], /target: prod/u);
  assert.match(block[0], /FNCP_GATEWAY_ENFORCEMENT: "false"/u);
  assert.match(
    block[0],
    /FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT: "false"/u
  );
  assert.match(block[0], /"127\.0\.0\.1:5501:5000"/u);
  assert.match(block[0], /restart: "no"/u);
  assert.doesNotMatch(block[0], /FNCP_OPTION_C_RELEASE_MODE/u);
  assert.doesNotMatch(block[0], /\b0\.0\.0\.0:/u);
});

test("one-shot bootstrap uses only the local OIDC fixture and writes no identifier", () => {
  assert.match(bootstrap, /api_origin="http:\/\/127\.0\.0\.1:5501"/u);
  assert.match(
    bootstrap,
    /oidc_origin="https:\/\/oidc-simulator:3000"/u
  );
  assert.match(bootstrap, /username: "admin@polis\.test"/u);
  assert.equal((bootstrap.match(/conversation_status=\$\(request/g) ?? []).length, 1);
  assert.equal((bootstrap.match(/comment_status=\$\(request/g) ?? []).length, 1);
  assert.equal((bootstrap.match(/gate_status=\$\(request/g) ?? []).length, 1);
  assert.match(bootstrap, /is_seed: true/u);
  assert.match(bootstrap, /use_xid_whitelist: true/u);
  assert.match(
    bootstrap,
    /rewrite-synthetic-bootstrap-binding\.mjs/u
  );
  assert.match(bootstrap, /bootstrap_compose rm -sf server-bootstrap/u);
  assert.match(
    bootstrap,
    /A protected synthetic bootstrap transition is already pending\./u
  );
  assert.match(bootstrap, /Do not run the trace yet\./u);
  assert.match(bootstrap, /activate-synthetic-binding\.sh/u);
  assert.doesNotMatch(bootstrap, /https:\/\/pol\.is|barayamal\.com/u);
  assert.doesNotMatch(
    bootstrap,
    /echo .*conversation_id|printf .*conversation_id/u
  );
  assert.ok(
    bootstrap.indexOf('mv "$marker_temp" "$restart_marker"') <
      bootstrap.indexOf(
        'conversation_status=$(request "$work_dir/conversation.json"'
      )
  );
  assert.ok(
    bootstrap.indexOf('mv "$marker_temp" "$restart_marker"') <
      bootstrap.indexOf(
        'node "$deploy_dir/rewrite-synthetic-bootstrap-binding.mjs"'
      )
  );
});

test("binding update replaces both IDs and completion state through one rename", async () => {
  const directory = await mkdtemp(join(tmpdir(), "fncp-bootstrap-contract-"));
  try {
    const environmentPath = join(directory, ".env.staging");
    const responsePath = join(directory, "conversation.json");
    const bootstrapId = `9fncpBootstrap${"a".repeat(48)}`;
    const createdId = "4syntheticConversation2026";
    const original = [
      "FNCP_SYNTHETIC_BOOTSTRAP_COMPLETE=false",
      `FNCP_GATEWAY_CONVERSATION_ID=${bootstrapId}`,
      `FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID=${bootstrapId}`,
      "UNRELATED_SECRET=do-not-change",
      "",
    ].join("\n");
    await writeFile(environmentPath, original, "utf8");
    await chmod(environmentPath, 0o600);
    await writeFile(
      responsePath,
      JSON.stringify({ conversation_id: createdId }),
      "utf8"
    );

    const result = spawnSync(
      process.execPath,
      [
        join(deployDir, "rewrite-synthetic-bootstrap-binding.mjs"),
        environmentPath,
        responsePath,
      ],
      { encoding: "utf8" }
    );
    assert.equal(result.status, 0);
    assert.equal(result.stdout, "");
    assert.equal(result.stderr, "");
    const updated = await readFile(environmentPath, "utf8");
    assert.match(updated, /^FNCP_SYNTHETIC_BOOTSTRAP_COMPLETE=true$/mu);
    assert.match(
      updated,
      new RegExp(`^FNCP_GATEWAY_CONVERSATION_ID=${createdId}$`, "mu")
    );
    assert.match(
      updated,
      new RegExp(
        `^FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID=${createdId}$`,
        "mu"
      )
    );
    assert.match(updated, /^UNRELATED_SECRET=do-not-change$/mu);
    assert.equal((await stat(environmentPath)).mode & 0o777, 0o600);
    assert.match(rewrite, /await rename\(temporaryPath, environmentPath\)/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("activation proves fresh dedicated containers and exact live binding", () => {
  for (const service of [
    "server",
    "client-participation-alpha",
    "nginx-proxy",
  ]) {
    assert.match(
      activate,
      new RegExp(
        `compose up -d --no-deps --force-recreate ${service.replaceAll(
          "-",
          "\\-"
        )}`
      )
    );
  }
  assert.match(activate, /\[ "\$server_before" = "\$server_after" \]/u);
  assert.match(activate, /\[ "\$alpha_before" = "\$alpha_after" \]/u);
  assert.match(
    activate,
    /fncp\/private\/xid-allowlist\/readback/u
  );
  assert.match(activate, /X-Forwarded-Proto: https/u);
  assert.match(activate, /\.operationVersion == null/u);
  assert.match(activate, /\.present == false/u);
  assert.match(activate, /bootstrap_compose rm -sf server-bootstrap/u);
  assert.match(activate, /\[ -n "\$bootstrap_after" \]/u);
  const markerRemoval = activate.indexOf('rm -f "$restart_marker"');
  const providerProof = activate.indexOf(".operationVersion == null");
  const participantProof = activate.indexOf(
    "Gateway access required."
  );
  assert.ok(markerRemoval > providerProof);
  assert.ok(markerRemoval > participantProof);
});

test("macOS tmp compatibility preserves stopped-copy-start bootstrap semantics", () => {
  const bootstrapOverride = colimaCompose.match(
    /^  server-bootstrap:\n([\s\S]*?)(?=^  [a-z0-9-]+:\n|(?![\s\S]))/mu
  );
  assert.ok(bootstrapOverride);
  assert.match(
    bootstrapOverride[0],
    /NODE_EXTRA_CA_CERTS: \/tmp\/fncp-rootCA\.pem/u
  );
  assert.match(bootstrapOverride[0], /volumes: !reset \[\]/u);

  assert.match(
    colimaStart,
    /printf '%s\\n' "compose-override=docker-compose\.colima\.yml"/u
  );
  const exactBuild = colimaStart.indexOf("compose build --pull");
  const containerCreate = colimaStart.indexOf("compose create");
  const markerWrite = colimaStart.indexOf(
    'printf \'%s\\n\' "compose-override=docker-compose.colima.yml"'
  );
  assert.ok(exactBuild >= 0);
  assert.ok(containerCreate > exactBuild);
  assert.ok(markerWrite > containerCreate);
  assert.match(
    colimaStart,
    /org\.opencontainers\.image\.revision/u
  );
  assert.match(
    colimaStart,
    /org\.barayamal\.fncp\.release-mode/u
  );
  assert.match(colimaStart, /compose stop >\/dev\/null 2>&1 \|\| true/u);
  assert.match(ignore, /^deploy\/fncp\/\.colima-staging$/mu);

  for (const helper of [bootstrap, activate]) {
    assert.match(
      helper,
      /"compose-override=docker-compose\.colima\.yml"/u
    );
    assert.match(helper, /-f "\$compose_override"/u);
  }

  const bootstrapCreate = bootstrap.indexOf(
    "bootstrap_compose up --no-start --no-deps --force-recreate"
  );
  const bootstrapCopyCa = bootstrap.indexOf(
    'docker cp -a "$ca_file" "$bootstrap_container:/tmp/fncp-rootCA.pem"'
  );
  const bootstrapCopyKeys = bootstrap.indexOf(
    'docker cp -a "$keys_dir" "$bootstrap_container:/app/keys"'
  );
  const bootstrapStart = bootstrap.indexOf(
    "bootstrap_compose start server-bootstrap"
  );
  assert.ok(bootstrapCreate >= 0);
  assert.ok(bootstrapCopyCa > bootstrapCreate);
  assert.ok(bootstrapCopyKeys > bootstrapCopyCa);
  assert.ok(bootstrapStart > bootstrapCopyKeys);

  const serverCreate = activate.indexOf(
    "compose up --no-start --no-deps --force-recreate server"
  );
  const serverCopyCa = activate.indexOf(
    'docker cp -a "$ca_file" "$server_container:/tmp/fncp-rootCA.pem"'
  );
  const serverCopyKeys = activate.indexOf(
    'docker cp -a "$keys_dir" "$server_container:/app/keys"'
  );
  const serverStart = activate.indexOf("compose start server");
  assert.ok(serverCreate >= 0);
  assert.ok(serverCopyCa > serverCreate);
  assert.ok(serverCopyKeys > serverCopyCa);
  assert.ok(serverStart > serverCopyKeys);
});

test("trace consumes only the activated conversation and provider API", () => {
  assert.match(smoke, /FNCP_SYNTHETIC_BOOTSTRAP_COMPLETE.*"true"/su);
  assert.match(smoke, /\[ -e "\$restart_marker" \]/u);
  assert.doesNotMatch(smoke, /conversation_status=\$\(request/u);
  assert.doesNotMatch(smoke, /comment_status=\$\(request/u);
  assert.doesNotMatch(smoke, /gate_status=\$\(request/u);
  for (const operation of ["upsert", "readback", "remove"]) {
    assert.match(
      smoke,
      new RegExp(`fncp/private/xid-allowlist/${operation}`)
    );
  }
  assert.ok(
    (smoke.match(/X-Forwarded-Proto: https/gu) ?? []).length >= 4
  );
  assert.match(smoke, /conversation_id="\$FNCP_GATEWAY_CONVERSATION_ID"/u);
  assert.match(smoke, /X-FNCP-Gateway-Key/u);
  assert.match(smoke, /X-FNCP-Conversation-ID/u);
  assert.match(smoke, /X-FNCP-Participant-XID/u);
});

test("documentation and CI lock the ordered local-only flow", () => {
  const prepareIndex = readme.indexOf("./deploy/fncp/prepare-staging.sh");
  const bootstrapIndex = readme.indexOf(
    "./deploy/fncp/bootstrap-synthetic-conversation.sh"
  );
  const activateIndex = readme.indexOf(
    "./deploy/fncp/activate-synthetic-binding.sh"
  );
  const smokeIndex = readme.indexOf("./deploy/fncp/smoke-test.sh");
  assert.ok(prepareIndex >= 0);
  assert.ok(bootstrapIndex > prepareIndex);
  assert.ok(activateIndex > bootstrapIndex);
  assert.ok(smokeIndex > activateIndex);
  assert.match(readme, /`docker compose restart` is insufficient/u);
  assert.doesNotMatch(readme, /Disposable staging explicitly builds `prod`/u);

  for (const shellScript of [
    "activate-synthetic-binding.sh",
    "bootstrap-synthetic-conversation.sh",
  ]) {
    assert.match(workflow, new RegExp(`sh -n deploy/fncp/${shellScript}`));
  }
  assert.match(
    workflow,
    /deploy\/fncp\/synthetic-bootstrap-boundary\.test\.mjs/u
  );
});
