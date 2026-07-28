import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const deployDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(deployDirectory, "../..");
const dockerfile = readFileSync(
  join(repositoryRoot, "server", "Dockerfile-migrate"),
  "utf8",
);
const runnerPath = join(
  repositoryRoot,
  "server",
  "bin",
  "fncp-run-migrations.sh",
);
const runner = readFileSync(runnerPath, "utf8");
const compose = readFileSync(
  join(deployDirectory, "docker-compose.staging.yml"),
  "utf8",
);
const workflow = readFileSync(
  join(repositoryRoot, ".github", "workflows", "fncp-option-c-ci.yml"),
  "utf8",
);
const migrationsDirectory = join(
  repositoryRoot,
  "server",
  "postgres",
  "migrations",
);

function composeServiceBlock(serviceName) {
  const match = compose.match(
    new RegExp(
      `^  ${serviceName}:\\n([\\s\\S]*?)(?=^  [a-z0-9-]+:\\n|^networks:)`,
      "m",
    ),
  );
  assert.ok(match, `missing Compose service ${serviceName}`);
  return match[0];
}

test("migration image is digest-pinned, source-bound and non-root by default", () => {
  assert.match(
    dockerfile,
    /^FROM docker\.io\/library\/postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193$/mu,
  );
  assert.match(dockerfile, /^ARG SOURCE_REVISION$/mu);
  assert.match(dockerfile, /test "\$\{#SOURCE_REVISION\}" -eq 40/u);
  assert.match(
    dockerfile,
    /org\.opencontainers\.image\.source="https:\/\/github\.com\/Barayamal\/polis"/u,
  );
  assert.match(
    dockerfile,
    /org\.opencontainers\.image\.revision="\$\{SOURCE_REVISION\}"/u,
  );
  assert.match(
    dockerfile,
    /org\.opencontainers\.image\.base\.digest="sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193"/u,
  );
  assert.match(
    dockerfile,
    /org\.opencontainers\.image\.base\.name="docker\.io\/library\/postgres:17-alpine"/u,
  );
  assert.match(dockerfile, /^USER postgres$/mu);
  assert.match(
    dockerfile,
    /^ENTRYPOINT \["\/usr\/local\/bin\/fncp-run-migrations"\]$/mu,
  );
  assert.match(dockerfile, /^CMD \[\]$/mu);
  for (const forbiddenTool of [
    "clusterdb",
    "createdb",
    "createuser",
    "docker-enforce-initdb.sh",
    "docker-ensure-initdb.sh",
    "docker-entrypoint.sh",
    "dropdb",
    "dropuser",
    "ecpg",
    "gosu",
    "initdb",
    "oid2name",
    "pg_amcheck",
    "pg_archivecleanup",
    "pg_basebackup",
    "pgbench",
    "pg_checksums",
    "pg_combinebackup",
    "pg_config",
    "pg_controldata",
    "pg_createsubscriber",
    "pg_ctl",
    "pg_dump",
    "pg_dumpall",
    "pg_isready",
    "pg_receivewal",
    "pg_recvlogical",
    "pg_resetwal",
    "pg_restore",
    "pg_rewind",
    "pg_test_fsync",
    "pg_test_timing",
    "pg_upgrade",
    "pg_verifybackup",
    "pg_waldump",
    "pg_walsummary",
    "postmaster",
    "postgres",
    "reindexdb",
    "vacuumdb",
    "vacuumlo",
  ]) {
    assert.ok(
      dockerfile.includes(`/usr/local/bin/${forbiddenTool}`),
      `${forbiddenTool} must be removed`,
    );
  }
  assert.match(dockerfile, /test -x \/usr\/local\/bin\/psql/u);
  assert.doesNotMatch(dockerfile, /\bapk add\b/u);
});

test("image includes only immutable top-level migrations", () => {
  const topLevelMigrations = readdirSync(migrationsDirectory, {
    withFileTypes: true,
  })
    .filter((entry) => entry.isFile() && entry.name.endsWith(".sql"))
    .map(({ name }) => name)
    .sort();
  assert.equal(topLevelMigrations.length, 19);
  for (const filename of topLevelMigrations) {
    assert.match(filename, /^[0-9]{6}_[a-z0-9_]+[.]sql$/u);
  }
  assert.match(
    dockerfile,
    /COPY --chown=postgres:postgres \.\/postgres\/migrations\/\*\.sql \/opt\/fncp\/migrations\//u,
  );
  assert.doesNotMatch(dockerfile, /migrations\/archived/u);
  assert.match(runner, /MIGRATIONS_DIR=\/opt\/fncp\/migrations/u);
  assert.match(runner, /-mindepth 1[\s\S]*-maxdepth 1[\s\S]*-type f/u);
  assert.match(runner, /LC_ALL=C sort "\$migration_unsorted"/u);
  assert.match(runner, /Unsafe migration filename/u);
  assert.match(runner, /\[ -L "\$migration_path" \]/u);
});

test("runner is fail-closed and never accepts or prints connection secrets", () => {
  assert.match(runner, /^set -eu$/mu);
  assert.doesNotMatch(runner, /\bset -x\b/u);
  assert.doesNotMatch(runner, /\beval\b/u);
  assert.match(runner, /The migration task accepts no arguments/u);
  assert.match(runner, /DATABASE_URL must use a postgresql:\/\/ connection URI/u);
  assert.match(runner, /DATABASE_URL query parameters are prohibited/u);
  assert.match(runner, /PGSSLMODE must be verify-full/u);
  assert.match(runner, /PGSSLROOTCERT must name a readable, non-empty CA bundle/u);
  assert.match(runner, /pg_catalog\.pg_stat_ssl/u);
  assert.match(runner, /tls_session_active/u);
  assert.match(runner, /pg_catalog\.pg_is_in_recovery/u);
  assert.match(runner, /PGTARGETSESSIONATTRS=read-write/u);
  assert.match(runner, /PGDATABASE=\$DATABASE_URL/u);
  assert.match(runner, /DATABASE_URL[\s\S]*PGPASSWORD[\s\S]*PGOPTIONS[\s\S]*PGSERVICE/u);
  assert.doesNotMatch(runner, /echo\s+["']?\$DATABASE_URL/u);
  assert.doesNotMatch(runner, /\b(?:env|printenv)\b/u);
  assert.doesNotMatch(runner, /psql[\s\S]{0,200}\$DATABASE_URL/u);

  const argumentFailure = spawnSync(
    "sh",
    [runnerPath, "postgresql://should-not-appear.invalid/secret"],
    { encoding: "utf8", env: { PATH: process.env.PATH } },
  );
  assert.equal(argumentFailure.status, 2);
  assert.doesNotMatch(
    `${argumentFailure.stdout}${argumentFailure.stderr}`,
    /should-not-appear/u,
  );

  const missingConfiguration = spawnSync("sh", [runnerPath], {
    encoding: "utf8",
    env: { PATH: process.env.PATH },
  });
  assert.equal(missingConfiguration.status, 2);
  assert.match(missingConfiguration.stderr, /DATABASE_URL/u);
});

test("one psql session locks, tracks checksums and stops on every SQL error", () => {
  assert.match(runner, /\\set ON_ERROR_STOP on/u);
  assert.match(runner, /--set=ON_ERROR_STOP=1/u);
  assert.match(runner, /psql[\s\S]*-X[\s\S]*--no-psqlrc/u);
  assert.match(runner, /pg_advisory_lock\(1179537232, 1\)/u);
  assert.match(runner, /pg_advisory_unlock\(1179537232, 1\)/u);
  assert.match(runner, /kill -TERM "\$psql_pid"/u);
  assert.match(runner, /trap terminate HUP INT TERM/u);
  assert.match(runner, /CREATE TABLE IF NOT EXISTS fncp_deploy\.schema_migrations/u);
  assert.match(runner, /filename text PRIMARY KEY/u);
  assert.match(runner, /sha256 character\(64\) NOT NULL/u);
  assert.match(runner, /migration_sha=\$\(sha256sum "\$migration_path"\)/u);
  assert.match(runner, /Migration checksum mismatch/u);
  assert.match(runner, /\\quit 3/u);
  assert.match(runner, /BEGIN;[\s\S]*\\ir '%s'[\s\S]*COMMIT;/u);
});

test("migration role is dedicated and least privilege before any mutation", () => {
  for (const marker of [
    "migration.rolcanlogin",
    "NOT migration.rolsuper",
    "NOT migration.rolinherit",
    "NOT migration.rolcreatedb",
    "NOT migration.rolcreaterole",
    "NOT migration.rolreplication",
    "NOT migration.rolbypassrls",
    "migration.rolname = :'expected_migration_role'",
    "migration.rolname <> :'runtime_role'",
    "membership.member = migration.oid",
    "database.datdba = migration.oid",
    "'CONNECT'",
    "'CREATE'",
    "'TEMPORARY'",
    "'public'",
    "'USAGE'",
    "migration_role_is_dedicated_and_least_privilege",
  ]) {
    assert.match(
      runner,
      new RegExp(marker.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"),
    );
  }

  const migrationRoleGate = runner.indexOf(
    "\\if :migration_role_is_dedicated_and_least_privilege",
  );
  const firstTrackingMutation = runner.indexOf(
    "CREATE SCHEMA IF NOT EXISTS fncp_deploy",
  );
  const firstMigrationInclude = runner.indexOf('printf "\\\\ir');
  assert.ok(migrationRoleGate >= 0);
  assert.ok(firstTrackingMutation > migrationRoleGate);
  assert.ok(firstMigrationInclude > migrationRoleGate);
  assert.match(
    runner.slice(migrationRoleGate, firstTrackingMutation),
    /\\quit 2/u,
  );
});

test("runtime role must pre-exist without elevation, ownership or DDL", () => {
  for (const marker of [
    "runtime.rolcanlogin",
    "NOT runtime.rolsuper",
    "NOT runtime.rolcreatedb",
    "NOT runtime.rolcreaterole",
    "NOT runtime.rolreplication",
    "NOT runtime.rolbypassrls",
    "pg_catalog.pg_auth_members",
    "database.datdba = runtime.oid",
    "namespace.nspowner = runtime.oid",
    "relation.relowner = runtime.oid",
    "function.proowner = runtime.oid",
    "'CREATE'",
  ]) {
    assert.match(runner, new RegExp(marker.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));
  }
  assert.match(
    runner,
    /GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public/u,
  );
  assert.match(
    runner,
    /GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public/u,
  );
  assert.match(runner, /GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public/u);
  assert.match(runner, /public_functions_are_invoker_security/u);
  assert.match(runner, /function\.prosecdef/u);
  assert.match(runner, /REVOKE CREATE ON SCHEMA public FROM PUBLIC/u);
  assert.match(runner, /REVOKE TEMPORARY, CREATE ON DATABASE/u);
  assert.match(
    runner,
    /REVOKE TRUNCATE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA public/u,
  );
  assert.match(runner, /runtime_role_has_no_ddl_or_tracking_access/u);
});

test("Compose and CI include migration as an isolated fifth release artifact", () => {
  const service = composeServiceBlock("polis-migration");
  assert.match(service, /profiles: \[release-assurance-build-only\]/u);
  assert.match(service, /dockerfile: Dockerfile-migrate/u);
  assert.match(service, /SOURCE_REVISION: \$\{FNCP_SOURCE_REVISION\}/u);
  assert.match(service, /network_mode: none/u);
  assert.match(service, /read_only: true/u);
  assert.match(service, /restart: "no"/u);
  assert.match(service, /no-new-privileges:true/u);
  assert.match(service, /cap_drop: \[ALL\]/u);
  assert.doesNotMatch(service, /\bports:/u);
  assert.doesNotMatch(service, /\benvironment:/u);

  const runtimeJob = workflow.match(
    /^  runtime-images:\n([\s\S]*?)(?=^  fncp-pr-gate:)/mu,
  )?.[0];
  assert.ok(runtimeJob);
  assert.match(runtimeJob, /^          - polis-migration$/mu);
  assert.match(runtimeJob, /--file server\/Dockerfile-migrate/u);
  assert.match(runtimeJob, /SOURCE_REVISION=\$\{GITHUB_SHA\}/u);
  assert.match(runtimeJob, /--format '\{\{json \.Config\.Cmd\}\}'/u);
  assert.match(runtimeJob, /\.Config\.Cmd[\s\S]{0,120}= '\[\]'/u);
  assert.match(
    runtimeJob,
    /\["\/usr\/local\/bin\/fncp-run-migrations"\]/u,
  );
  assert.match(runtimeJob, /org\.opencontainers\.image\.revision/u);
  assert.match(runtimeJob, /org\.opencontainers\.image\.source/u);
  assert.match(runtimeJob, /org\.opencontainers\.image\.base\.digest/u);
  assert.match(runtimeJob, /org\.opencontainers\.image\.base\.name/u);
  for (const command of [
    "cat",
    "find",
    "mktemp",
    "psql",
    "rm",
    "sha256sum",
    "sh",
    "sort",
    "tr",
    "wc",
  ]) {
    assert.match(runtimeJob, new RegExp(`\\b${command}\\b`, "u"));
  }
  assert.match(runtimeJob, /clusterdb createdb createuser/u);
  assert.match(
    runtimeJob,
    /docker-enforce-initdb\.sh[\s\S]{0,120}docker-ensure-initdb\.sh/u,
  );
  assert.match(runtimeJob, /\bgosu\b/u);
  assert.match(runtimeJob, /\bpg_createsubscriber\b/u);
  assert.match(runtimeJob, /\bpg_walsummary\b/u);
  assert.match(runtimeJob, /\bpostmaster\b/u);
  assert.match(
    runtimeJob,
    /pg_waldump[\s\S]{0,120}postgres[\s\S]{0,120}reindexdb[\s\S]{0,120}vacuumdb vacuumlo/u,
  );
  assert.match(
    runtimeJob,
    /grep -q "listen 8080 default_server;"/u,
  );
});
