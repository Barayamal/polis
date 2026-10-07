#!/bin/sh
set -eu

# Production migration entrypoint for the FNCP Pol.is release. This script
# deliberately accepts no command-line connection string: credentials stay in
# the task environment and are never printed or placed in the process argv.
if [ "$#" -ne 0 ]; then
  echo "The migration task accepts no arguments." >&2
  exit 2
fi

required_environment="
FNCP_DATABASE_HOST
FNCP_DATABASE_PASSWORD
FNCP_DATABASE_PORT
FNCP_EXPECTED_DATABASE
FNCP_EXPECTED_MIGRATION_ROLE
FNCP_RUNTIME_DB_ROLE
PGSSLROOTCERT
"
for variable_name in $required_environment; do
  case "$variable_name" in
    FNCP_DATABASE_HOST) variable_value=${FNCP_DATABASE_HOST-} ;;
    FNCP_DATABASE_PASSWORD) variable_value=${FNCP_DATABASE_PASSWORD-} ;;
    FNCP_DATABASE_PORT) variable_value=${FNCP_DATABASE_PORT-} ;;
    FNCP_EXPECTED_DATABASE) variable_value=${FNCP_EXPECTED_DATABASE-} ;;
    FNCP_EXPECTED_MIGRATION_ROLE)
      variable_value=${FNCP_EXPECTED_MIGRATION_ROLE-}
      ;;
    FNCP_RUNTIME_DB_ROLE) variable_value=${FNCP_RUNTIME_DB_ROLE-} ;;
    PGSSLROOTCERT) variable_value=${PGSSLROOTCERT-} ;;
    *)
      echo "Internal migration configuration error." >&2
      exit 2
      ;;
  esac
  if [ -z "$variable_value" ]; then
    echo "Missing required migration configuration: $variable_name" >&2
    exit 2
  fi
done
unset variable_value

case "$FNCP_DATABASE_HOST" in
  "" | .* | -* | *. | *..* | *[!A-Za-z0-9.-]*)
    echo "FNCP_DATABASE_HOST must be one exact DNS hostname." >&2
    exit 2
    ;;
esac
case "$FNCP_DATABASE_PORT" in
  "" | *[!0-9]*)
    echo "FNCP_DATABASE_PORT must be an integer from 1 through 65535." >&2
    exit 2
    ;;
esac
if [ "$FNCP_DATABASE_PORT" -lt 1 ] ||
  [ "$FNCP_DATABASE_PORT" -gt 65535 ]; then
  echo "FNCP_DATABASE_PORT must be an integer from 1 through 65535." >&2
  exit 2
fi
case "$FNCP_DATABASE_PASSWORD" in
  "" | *[!A-Za-z0-9_-]*)
    echo "FNCP_DATABASE_PASSWORD must be a base64url secret." >&2
    exit 2
    ;;
esac
if [ "${#FNCP_DATABASE_PASSWORD}" -lt 32 ] ||
  [ "${#FNCP_DATABASE_PASSWORD}" -gt 128 ]; then
  echo "FNCP_DATABASE_PASSWORD must contain 32 through 128 characters." >&2
  exit 2
fi

for identifier_name in \
  FNCP_EXPECTED_DATABASE \
  FNCP_EXPECTED_MIGRATION_ROLE \
  FNCP_RUNTIME_DB_ROLE
do
  case "$identifier_name" in
    FNCP_EXPECTED_DATABASE) identifier_value=$FNCP_EXPECTED_DATABASE ;;
    FNCP_EXPECTED_MIGRATION_ROLE)
      identifier_value=$FNCP_EXPECTED_MIGRATION_ROLE
      ;;
    FNCP_RUNTIME_DB_ROLE) identifier_value=$FNCP_RUNTIME_DB_ROLE ;;
    *)
      echo "Internal migration identifier error." >&2
      exit 2
      ;;
  esac
  case "$identifier_value" in
    [a-z_]*)
      case "$identifier_value" in
        *[!a-z0-9_]*)
          echo "$identifier_name must be a lowercase PostgreSQL identifier." >&2
          exit 2
          ;;
      esac
      ;;
    *)
      echo "$identifier_name must be a lowercase PostgreSQL identifier." >&2
      exit 2
      ;;
  esac
  if [ "${#identifier_value}" -gt 63 ]; then
    echo "$identifier_name exceeds PostgreSQL's identifier limit." >&2
    exit 2
  fi
done
unset identifier_value

if [ "$FNCP_EXPECTED_MIGRATION_ROLE" = "$FNCP_RUNTIME_DB_ROLE" ]; then
  echo "Migration and runtime database roles must be distinct." >&2
  exit 2
fi
if [ "${PGSSLMODE-}" != "verify-full" ]; then
  echo "PGSSLMODE must be verify-full." >&2
  exit 2
fi
case "$PGSSLROOTCERT" in
  /*) ;;
  *)
    echo "PGSSLROOTCERT must be an absolute path." >&2
    exit 2
    ;;
esac
if [ ! -r "$PGSSLROOTCERT" ] || [ ! -s "$PGSSLROOTCERT" ]; then
  echo "PGSSLROOTCERT must name a readable, non-empty CA bundle." >&2
  exit 2
fi

MIGRATIONS_DIR=/opt/fncp/migrations
if [ ! -d "$MIGRATIONS_DIR" ]; then
  echo "The immutable migration directory is missing." >&2
  exit 2
fi
unexpected_migration_entry=$(
  find "$MIGRATIONS_DIR" \
    -mindepth 1 \
    -maxdepth 1 \
    \( ! -type f -o ! -name '*.sql' \) \
    -print -quit
)
if [ -n "$unexpected_migration_entry" ]; then
  echo "The immutable migration directory contains an unexpected entry." >&2
  exit 2
fi
unset unexpected_migration_entry

umask 077
migration_unsorted=$(mktemp /tmp/fncp-migrations-unsorted.XXXXXX)
migration_list=$(mktemp /tmp/fncp-migrations.XXXXXX)
psql_script=$(mktemp /tmp/fncp-migration-run.XXXXXX)
password_file=$(mktemp /tmp/fncp-pgpass.XXXXXX)
psql_pid=
cleanup() {
  rm -f \
    "$migration_unsorted" \
    "$migration_list" \
    "$psql_script" \
    "$password_file"
}
terminate() {
  if [ -n "$psql_pid" ]; then
    kill -TERM "$psql_pid" 2>/dev/null || true
    wait "$psql_pid" 2>/dev/null || true
  fi
  exit 143
}
trap cleanup EXIT
trap terminate HUP INT TERM

find "$MIGRATIONS_DIR" \
  -mindepth 1 \
  -maxdepth 1 \
  -type f \
  -name '*.sql' \
  -print >"$migration_unsorted"
LC_ALL=C sort "$migration_unsorted" >"$migration_list"

if [ ! -s "$migration_list" ]; then
  echo "No top-level SQL migrations were found." >&2
  exit 2
fi

while IFS= read -r migration_path; do
  migration_name=${migration_path##*/}
  case "$migration_name" in
    [0-9][0-9][0-9][0-9][0-9][0-9]_[a-z0-9_]*.sql) ;;
    *)
      echo "Unsafe migration filename: $migration_name" >&2
      exit 2
      ;;
  esac
  if [ -L "$migration_path" ] || [ ! -f "$migration_path" ]; then
    echo "Migration must be a regular, non-symlink file: $migration_name" >&2
    exit 2
  fi
done <"$migration_list"

cat >"$psql_script" <<'PSQL'
\set ON_ERROR_STOP on
\set QUIET on
SET application_name = 'fncp-polis-migration';
SET client_min_messages = warning;
SET search_path = public, pg_catalog;
SET statement_timeout = '30s';
SELECT pg_advisory_lock(1179537232, 1);
SET statement_timeout = 0;

SELECT current_database() = :'expected_database' AS expected_database_matches,
       current_user = :'expected_migration_role' AS expected_migration_role_matches,
       COALESCE(
         (
           SELECT ssl
             FROM pg_catalog.pg_stat_ssl
            WHERE pid = pg_catalog.pg_backend_pid()
         ),
         false
       ) AS tls_session_active,
       NOT pg_catalog.pg_is_in_recovery()
         AND pg_catalog.current_setting('transaction_read_only') = 'off'
         AS primary_session_is_writable
\gset
\if :expected_database_matches
\else
  \echo 'Connected database does not match FNCP_EXPECTED_DATABASE.'
  SELECT 1 / 0 AS fncp_fail_closed;
\endif
\if :expected_migration_role_matches
\else
  \echo 'Connected role does not match FNCP_EXPECTED_MIGRATION_ROLE.'
  SELECT 1 / 0 AS fncp_fail_closed;
\endif
\if :tls_session_active
\else
  \echo 'The database session is not protected by TLS.'
  SELECT 1 / 0 AS fncp_fail_closed;
\endif
\if :primary_session_is_writable
\else
  \echo 'The database target is not the writable primary.'
  SELECT 1 / 0 AS fncp_fail_closed;
\endif

SELECT (
         pg_catalog.count(*) = 1
         AND pg_catalog.bool_and(migration.rolcanlogin)
         AND pg_catalog.bool_and(NOT migration.rolsuper)
         AND pg_catalog.bool_and(NOT migration.rolinherit)
         AND pg_catalog.bool_and(NOT migration.rolcreatedb)
         AND pg_catalog.bool_and(NOT migration.rolcreaterole)
         AND pg_catalog.bool_and(NOT migration.rolreplication)
         AND pg_catalog.bool_and(NOT migration.rolbypassrls)
         AND pg_catalog.bool_and(
           migration.rolname = :'expected_migration_role'
         )
         AND pg_catalog.bool_and(migration.rolname <> :'runtime_role')
         AND pg_catalog.bool_and(NOT EXISTS (
           SELECT 1
             FROM pg_catalog.pg_auth_members AS membership
            WHERE membership.member = migration.oid
         ))
         AND pg_catalog.bool_and(NOT EXISTS (
           SELECT 1
             FROM pg_catalog.pg_database AS database
            WHERE database.datname = current_database()
              AND database.datdba = migration.oid
         ))
         AND pg_catalog.bool_and(pg_catalog.has_database_privilege(
           migration.rolname,
           current_database(),
           'CONNECT'
         ))
         AND pg_catalog.bool_and(pg_catalog.has_database_privilege(
           migration.rolname,
           current_database(),
           'CREATE'
         ))
         AND pg_catalog.bool_and(NOT pg_catalog.has_database_privilege(
           migration.rolname,
           current_database(),
           'TEMPORARY'
         ))
         AND pg_catalog.bool_and(pg_catalog.has_schema_privilege(
           migration.rolname,
           'public',
           'USAGE'
         ))
         AND pg_catalog.bool_and(pg_catalog.has_schema_privilege(
           migration.rolname,
           'public',
           'CREATE'
         ))
       ) AS migration_role_is_dedicated_and_least_privilege
  FROM pg_catalog.pg_roles AS migration
 WHERE migration.rolname = current_user
\gset
\if :migration_role_is_dedicated_and_least_privilege
\else
  \echo 'Migration role is missing, elevated, inheriting, a member, the database owner, incorrectly privileged, or not dedicated.'
  SELECT 1 / 0 AS fncp_fail_closed;
\endif

SELECT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_roles AS runtime
          WHERE runtime.rolname = :'runtime_role'
            AND runtime.rolcanlogin
            AND NOT runtime.rolsuper
            AND NOT runtime.rolcreatedb
            AND NOT runtime.rolcreaterole
            AND NOT runtime.rolreplication
            AND NOT runtime.rolbypassrls
            AND runtime.oid <> (
              SELECT oid
                FROM pg_catalog.pg_roles
               WHERE rolname = current_user
            )
            AND NOT EXISTS (
              SELECT 1
                FROM pg_catalog.pg_auth_members AS membership
               WHERE membership.member = runtime.oid
            )
            AND NOT EXISTS (
              SELECT 1
                FROM pg_catalog.pg_database AS database
               WHERE database.datname = current_database()
                 AND database.datdba = runtime.oid
            )
            AND NOT EXISTS (
              SELECT 1
                FROM pg_catalog.pg_namespace AS namespace
               WHERE namespace.nspowner = runtime.oid
            )
            AND NOT EXISTS (
              SELECT 1
                FROM pg_catalog.pg_class AS relation
               WHERE relation.relowner = runtime.oid
            )
            AND NOT EXISTS (
              SELECT 1
                FROM pg_catalog.pg_proc AS function
               WHERE function.proowner = runtime.oid
            )
            AND NOT EXISTS (
              SELECT 1
                FROM pg_catalog.pg_type AS type
               WHERE type.typowner = runtime.oid
            )
            AND NOT pg_catalog.has_database_privilege(
              runtime.rolname,
              current_database(),
              'CREATE'
            )
            AND NOT EXISTS (
              SELECT 1
                FROM pg_catalog.pg_namespace AS namespace
               WHERE namespace.nspname !~ '^pg_(toast|temp)'
                 AND pg_catalog.has_schema_privilege(
                   runtime.rolname,
                   namespace.oid,
                   'CREATE'
                 )
            )
       ) AS runtime_role_is_preexisting_and_least_privilege
\gset
\if :runtime_role_is_preexisting_and_least_privilege
\else
  \echo 'Runtime role is missing, elevated, a member, an owner, or DDL-capable.'
  SELECT 1 / 0 AS fncp_fail_closed;
\endif

-- The database owner must establish database-wide and public-schema ACLs
-- before this deliberately non-owner migration role runs. Refuse to mutate
-- application objects unless PUBLIC has no ambient privileges and both
-- dedicated roles have only their reviewed direct access.
SELECT NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_database AS database
           CROSS JOIN LATERAL pg_catalog.aclexplode(
             COALESCE(
               database.datacl,
               pg_catalog.acldefault('d', database.datdba)
             )
           ) AS acl
          WHERE database.datname = current_database()
            AND acl.grantee = 0
            AND acl.privilege_type IN (
              'CONNECT',
              'CREATE',
              'TEMPORARY'
            )
       )
       AND NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_namespace AS namespace
           CROSS JOIN LATERAL pg_catalog.aclexplode(
             COALESCE(
               namespace.nspacl,
               pg_catalog.acldefault('n', namespace.nspowner)
             )
           ) AS acl
          WHERE namespace.nspname = 'public'
            AND acl.grantee = 0
            AND acl.privilege_type IN ('USAGE', 'CREATE')
       )
       AND pg_catalog.has_database_privilege(
         current_user,
         current_database(),
         'CONNECT'
       )
       AND pg_catalog.has_database_privilege(
         current_user,
         current_database(),
         'CREATE'
       )
       AND NOT pg_catalog.has_database_privilege(
         current_user,
         current_database(),
         'TEMPORARY'
       )
       AND pg_catalog.has_schema_privilege(
         current_user,
         'public',
         'USAGE'
       )
       AND pg_catalog.has_schema_privilege(
         current_user,
         'public',
         'CREATE'
       )
       AND pg_catalog.has_database_privilege(
         :'runtime_role',
         current_database(),
         'CONNECT'
       )
       AND NOT pg_catalog.has_database_privilege(
         :'runtime_role',
         current_database(),
         'CREATE'
       )
       AND NOT pg_catalog.has_database_privilege(
         :'runtime_role',
         current_database(),
         'TEMPORARY'
       )
       AND pg_catalog.has_schema_privilege(
         :'runtime_role',
         'public',
         'USAGE'
       )
       AND NOT pg_catalog.has_schema_privilege(
         :'runtime_role',
         'public',
         'CREATE'
       ) AS database_owner_bootstrap_is_least_privilege
\gset
\if :database_owner_bootstrap_is_least_privilege
\else
  \echo 'Database-owner bootstrap ACLs are incomplete or too broad.'
  SELECT 1 / 0 AS fncp_fail_closed;
\endif

CREATE SCHEMA IF NOT EXISTS fncp_deploy AUTHORIZATION CURRENT_USER;
SELECT namespace.nspowner = (
         SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user
       ) AS tracking_schema_owned_by_migration_role
  FROM pg_catalog.pg_namespace AS namespace
 WHERE namespace.nspname = 'fncp_deploy'
\gset
\if :tracking_schema_owned_by_migration_role
\else
  \echo 'fncp_deploy is not owned by the migration role.'
  SELECT 1 / 0 AS fncp_fail_closed;
\endif

REVOKE ALL ON SCHEMA fncp_deploy FROM PUBLIC;
SELECT format(
         'REVOKE ALL ON SCHEMA fncp_deploy FROM %I',
         :'runtime_role'
       )
\gexec

CREATE TABLE IF NOT EXISTS fncp_deploy.schema_migrations (
  filename text PRIMARY KEY
    CHECK (filename ~ '^[0-9]{6}_[a-z0-9_]+[.]sql$'),
  sha256 character(64) NOT NULL
    CHECK (sha256 ~ '^[a-f0-9]{64}$'),
  applied_at timestamp with time zone NOT NULL DEFAULT clock_timestamp(),
  applied_by name NOT NULL DEFAULT session_user
);
SELECT relation.relowner = (
         SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user
       )
       AND (
         SELECT count(*)
           FROM pg_catalog.pg_attribute AS attribute
          WHERE attribute.attrelid = relation.oid
            AND attribute.attnum > 0
            AND NOT attribute.attisdropped
       ) = 4
       AND EXISTS (
         SELECT 1
           FROM pg_catalog.pg_constraint AS constraint_record
          WHERE constraint_record.conrelid = relation.oid
            AND constraint_record.contype = 'p'
       )
       AND (
         SELECT count(*)
           FROM pg_catalog.pg_constraint AS constraint_record
          WHERE constraint_record.conrelid = relation.oid
            AND constraint_record.contype = 'c'
       ) = 2 AS tracking_table_is_owned_and_shaped
  FROM pg_catalog.pg_class AS relation
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = relation.relnamespace
 WHERE namespace.nspname = 'fncp_deploy'
   AND relation.relname = 'schema_migrations'
   AND relation.relkind = 'r'
\gset
\if :tracking_table_is_owned_and_shaped
\else
  \echo 'Migration tracking table is not owned or shaped as expected.'
  SELECT 1 / 0 AS fncp_fail_closed;
\endif
REVOKE ALL ON fncp_deploy.schema_migrations FROM PUBLIC;
SELECT format(
         'REVOKE ALL ON fncp_deploy.schema_migrations FROM %I',
         :'runtime_role'
       )
\gexec
PSQL

while IFS= read -r migration_path; do
  migration_name=${migration_path##*/}
  migration_sha=$(sha256sum "$migration_path")
  migration_sha=${migration_sha%% *}
  case "$migration_sha" in
    ""|*[!a-f0-9]*)
      echo "Could not calculate migration SHA-256: $migration_name" >&2
      exit 2
      ;;
  esac
  if [ "${#migration_sha}" -ne 64 ]; then
    echo "Could not calculate migration SHA-256: $migration_name" >&2
    exit 2
  fi

  {
    printf "\\set migration_name '%s'\n" "$migration_name"
    printf "\\set migration_sha '%s'\n" "$migration_sha"
    cat <<'PSQL'
SELECT EXISTS (
         SELECT 1
           FROM fncp_deploy.schema_migrations
          WHERE filename = :'migration_name'
       ) AS migration_seen,
       COALESCE(
         (
           SELECT sha256 = :'migration_sha'
             FROM fncp_deploy.schema_migrations
            WHERE filename = :'migration_name'
         ),
         false
       ) AS migration_sha_matches
\gset
\if :migration_seen
  \if :migration_sha_matches
    \echo 'Already applied:' :migration_name
  \else
    \echo 'Migration checksum mismatch:' :migration_name
    SELECT 1 / 0 AS fncp_fail_closed;
  \endif
\else
  \echo 'Applying:' :migration_name
  BEGIN;
PSQL
    printf "\\ir '%s'\n" "$migration_path"
    cat <<'PSQL'
  INSERT INTO fncp_deploy.schema_migrations (filename, sha256)
  VALUES (:'migration_name', :'migration_sha');
  COMMIT;
\endif
PSQL
  } >>"$psql_script"
done <"$migration_list"

cat >>"$psql_script" <<'PSQL'
BEGIN;

SELECT NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_proc AS function
           JOIN pg_catalog.pg_namespace AS namespace
             ON namespace.oid = function.pronamespace
          WHERE namespace.nspname = 'public'
            AND function.prosecdef
       ) AS public_functions_are_invoker_security
\gset
\if :public_functions_are_invoker_security
\else
  \echo 'A public SECURITY DEFINER function prevents least-privilege grants.'
  SELECT 1 / 0 AS fncp_fail_closed;
\endif

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
SELECT format(
         'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO %I',
         :'runtime_role'
       )
\gexec
SELECT format(
         'REVOKE TRUNCATE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA public FROM %I',
         :'runtime_role'
       )
\gexec
SELECT format(
         'GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO %I',
         :'runtime_role'
       )
\gexec
SELECT format(
         'GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO %I',
         :'runtime_role'
       )
\gexec
SELECT format(
         'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I',
         :'runtime_role'
       )
\gexec
SELECT format(
         'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO %I',
         :'runtime_role'
       )
\gexec
SELECT format(
         'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO %I',
         :'runtime_role'
       )
\gexec

SELECT NOT pg_catalog.has_database_privilege(
         :'runtime_role',
         current_database(),
         'CREATE'
       )
       AND NOT pg_catalog.has_database_privilege(
         :'runtime_role',
         current_database(),
         'TEMPORARY'
       )
       AND NOT pg_catalog.has_schema_privilege(
         :'runtime_role',
         'public',
         'CREATE'
       )
       AND NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_namespace AS namespace
          WHERE namespace.nspname !~ '^pg_(toast|temp)'
            AND pg_catalog.has_schema_privilege(
              :'runtime_role',
              namespace.oid,
              'CREATE'
            )
       )
       AND NOT pg_catalog.has_schema_privilege(
         :'runtime_role',
         'fncp_deploy',
         'USAGE'
       )
       AND NOT pg_catalog.has_table_privilege(
         :'runtime_role', 'fncp_deploy.schema_migrations', 'SELECT'
       )
       AND NOT pg_catalog.has_table_privilege(
         :'runtime_role', 'fncp_deploy.schema_migrations', 'INSERT'
       )
       AND NOT pg_catalog.has_table_privilege(
         :'runtime_role', 'fncp_deploy.schema_migrations', 'UPDATE'
       )
       AND NOT pg_catalog.has_table_privilege(
         :'runtime_role', 'fncp_deploy.schema_migrations', 'DELETE'
       )
       AND NOT pg_catalog.has_table_privilege(
         :'runtime_role', 'fncp_deploy.schema_migrations', 'TRUNCATE'
       )
       AND NOT pg_catalog.has_table_privilege(
         :'runtime_role', 'fncp_deploy.schema_migrations', 'REFERENCES'
       )
       AND NOT pg_catalog.has_table_privilege(
         :'runtime_role', 'fncp_deploy.schema_migrations', 'TRIGGER'
       ) AS runtime_role_has_no_ddl_or_tracking_access
\gset
\if :runtime_role_has_no_ddl_or_tracking_access
\else
  \echo 'Runtime role retained DDL or migration-tracking access.'
  SELECT 1 / 0 AS fncp_fail_closed;
\endif
COMMIT;

SELECT pg_advisory_unlock(1179537232, 1) AS migration_lock_released
\gset
\if :migration_lock_released
\else
  \echo 'Migration advisory lock was not released.'
  SELECT 1 / 0 AS fncp_fail_closed;
\endif
\echo 'FNCP Pol.is migrations completed.'
PSQL

# Keep the synthetic or task-injected password out of psql's argv and child
# environment. The reviewed base64url alphabet is directly safe in pgpass.
printf '%s:%s:%s:%s:%s\n' \
  "$FNCP_DATABASE_HOST" \
  "$FNCP_DATABASE_PORT" \
  "$FNCP_EXPECTED_DATABASE" \
  "$FNCP_EXPECTED_MIGRATION_ROLE" \
  "$FNCP_DATABASE_PASSWORD" >"$password_file"
PGHOST=$FNCP_DATABASE_HOST
PGPORT=$FNCP_DATABASE_PORT
PGDATABASE=$FNCP_EXPECTED_DATABASE
PGUSER=$FNCP_EXPECTED_MIGRATION_ROLE
PGPASSFILE=$password_file
export PGHOST PGPORT PGDATABASE PGUSER PGPASSFILE
unset \
  FNCP_DATABASE_HOST \
  FNCP_DATABASE_PASSWORD \
  FNCP_DATABASE_PORT \
  DATABASE_URL \
  PGPASSWORD \
  PGOPTIONS \
  PGSERVICE \
  PGSERVICEFILE
export PGAPPNAME=fncp-polis-migration
export PGCONNECT_TIMEOUT=10
export PGTARGETSESSIONATTRS=read-write

psql \
  -X \
  --no-psqlrc \
  --quiet \
  --set=ON_ERROR_STOP=1 \
  --set="expected_database=$FNCP_EXPECTED_DATABASE" \
  --set="expected_migration_role=$FNCP_EXPECTED_MIGRATION_ROLE" \
  --set="runtime_role=$FNCP_RUNTIME_DB_ROLE" \
  --file="$psql_script" &
psql_pid=$!
if wait "$psql_pid"; then
  psql_status=0
else
  psql_status=$?
fi
psql_pid=
exit "$psql_status"
