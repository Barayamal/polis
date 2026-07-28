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
const migrationSmoke = readFileSync(
  join(deployDirectory, "boot-migration-image-smoke.sh"),
  "utf8",
);
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
  assert.match(dockerfile, /rm -rf \/docker-entrypoint-initdb\.d/u);
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
  assert.match(runner, /FNCP_DATABASE_HOST must be one exact DNS hostname/u);
  assert.match(runner, /FNCP_DATABASE_PORT must be an integer from 1 through 65535/u);
  assert.match(runner, /FNCP_DATABASE_PASSWORD must be a base64url secret/u);
  assert.match(runner, /32 through 128 characters/u);
  assert.match(runner, /PGSSLMODE must be verify-full/u);
  assert.match(runner, /PGSSLROOTCERT must name a readable, non-empty CA bundle/u);
  assert.match(runner, /pg_catalog\.pg_stat_ssl/u);
  assert.match(runner, /tls_session_active/u);
  assert.match(runner, /pg_catalog\.pg_is_in_recovery/u);
  assert.match(runner, /PGTARGETSESSIONATTRS=read-write/u);
  assert.match(runner, /PGHOST=\$FNCP_DATABASE_HOST/u);
  assert.match(runner, /PGPORT=\$FNCP_DATABASE_PORT/u);
  assert.match(runner, /PGDATABASE=\$FNCP_EXPECTED_DATABASE/u);
  assert.match(runner, /PGUSER=\$FNCP_EXPECTED_MIGRATION_ROLE/u);
  assert.match(runner, /PGPASSFILE=\$password_file/u);
  assert.match(
    runner,
    /FNCP_DATABASE_PASSWORD[\s\S]*DATABASE_URL[\s\S]*PGPASSWORD[\s\S]*PGOPTIONS[\s\S]*PGSERVICE/u,
  );
  assert.match(runner, /rm -f[\s\S]*"\$password_file"/u);
  assert.doesNotMatch(
    runner,
    /echo\s+["']?\$FNCP_DATABASE_PASSWORD/u,
  );
  assert.doesNotMatch(runner, /\b(?:env|printenv)\b/u);
  assert.doesNotMatch(
    runner,
    /psql[\s\S]{0,200}\$FNCP_DATABASE_PASSWORD/u,
  );

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
  assert.match(missingConfiguration.stderr, /FNCP_DATABASE_HOST/u);
});

test("disposable TLS migration smoke covers failure, lock, receipt and runtime ACL paths", () => {
  assert.match(migrationSmoke, /^set -eu$/mu);
  assert.match(
    migrationSmoke,
    /usage: sh deploy\/fncp\/boot-migration-image-smoke\.sh <40-char-source-revision>/u,
  );
  assert.match(
    migrationSmoke,
    /postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193/u,
  );
  assert.match(
    migrationSmoke,
    /fncp-option-c-polis-migration:synthetic-\$\{revision\}/u,
  );
  assert.match(migrationSmoke, /PGSSLMODE=verify-full/u);
  assert.equal(
    (migrationSmoke.match(/--init/gu) ?? []).length,
    3,
    "every short-lived migration and runtime probe must have an init process",
  );
  assert.equal(
    (migrationSmoke.match(/--stop-timeout 5/gu) ?? []).length,
    3,
    "every short-lived migration and runtime probe must have a bounded stop timeout",
  );
  assert.match(migrationSmoke, /FNCP_DATABASE_HOST=\$postgres_container/u);
  assert.match(migrationSmoke, /FNCP_DATABASE_PASSWORD=/u);
  assert.match(
    migrationSmoke,
    /Migration unexpectedly accepted missing owner bootstrap ACLs/u,
  );
  assert.match(migrationSmoke, /migration_pid_one=\$!/u);
  assert.match(migrationSmoke, /migration_pid_two=\$!/u);
  assert.match(migrationSmoke, /receipt_state[\s\S]*19:19/u);
  assert.match(migrationSmoke, /Migration unexpectedly accepted checksum drift/u);
  assert.match(migrationSmoke, /Already applied:[\s\S]*-ne 19/u);
  assert.match(migrationSmoke, /runtime_acl_state/u);
  assert.match(migrationSmoke, /runtime-tracking-access\.log/u);
  assert.match(migrationSmoke, /docker network rm/u);
  assert.match(migrationSmoke, /docker volume rm/u);
  assert.doesNotMatch(
    migrationSmoke,
    /\b(?:push|login|aws|terraform|kubectl)\b/u,
  );
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
  assert.doesNotMatch(runner, /\\(?:q|quit)\s+\d/u);
  assert.equal(
    (runner.match(/SELECT 1 \/ 0 AS fncp_fail_closed;/gu) ?? []).length,
    13,
  );
  assert.doesNotMatch(runner, /\bAS constraint\b/iu);
  assert.equal(
    (runner.match(/pg_constraint AS constraint_record/gu) ?? []).length,
    2,
  );
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
    /SELECT 1 \/ 0 AS fncp_fail_closed;/u,
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
  assert.match(runner, /database_owner_bootstrap_is_least_privilege/u);
  assert.match(runner, /pg_catalog\.aclexplode/u);
  assert.match(runner, /acl\.grantee = 0/u);
  assert.match(
    runner,
    /Database-owner bootstrap ACLs are incomplete or too broad/u,
  );
  assert.doesNotMatch(
    runner,
    /^REVOKE CREATE ON SCHEMA public FROM PUBLIC;$/mu,
  );
  assert.doesNotMatch(
    runner,
    /^REVOKE TEMPORARY, CREATE ON DATABASE/mu,
  );
  assert.doesNotMatch(
    runner,
    /GRANT USAGE ON SCHEMA public TO %I/u,
  );
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
  assert.match(runtimeJob, /\.Config\.Cmd[\s\S]{0,120}= 'null'/u);
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
  assert.match(runtimeJob, /test ! -e \/docker-entrypoint-initdb\.d/u);
  assert.match(
    runtimeJob,
    /pg_waldump[\s\S]{0,120}postgres[\s\S]{0,120}reindexdb[\s\S]{0,120}vacuumdb vacuumlo/u,
  );
  assert.match(
    runtimeJob,
    /grep -q "listen 8080 default_server;"/u,
  );
});
