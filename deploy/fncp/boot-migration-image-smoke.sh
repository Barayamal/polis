#!/bin/sh
set -eu

usage="usage: sh deploy/fncp/boot-migration-image-smoke.sh <40-char-source-revision>"
if [ "$#" -ne 1 ]; then
  printf '%s\n' "$usage" >&2
  exit 64
fi
revision=$1
case "$revision" in
  "" | *[!0-9a-f]*)
    printf '%s\n' "$usage" >&2
    exit 64
    ;;
esac
if [ "${#revision}" -ne 40 ]; then
  printf '%s\n' "$usage" >&2
  exit 64
fi

postgres_image="docker.io/library/postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193"
migration_image="fncp-option-c-polis-migration:synthetic-${revision}"
short_revision=$(printf '%s' "$revision" | cut -c1-12)
suffix="$short_revision-$$"
network="fncp-polis-migration-smoke-$suffix"
postgres_container="fncp-polis-postgres-$suffix"
certificate_seed_container="fncp-polis-cert-seed-$suffix"
missing_bootstrap_container="fncp-polis-migration-missing-bootstrap-$suffix"
migration_container_one="fncp-polis-migration-one-$suffix"
migration_container_two="fncp-polis-migration-two-$suffix"
drift_container="fncp-polis-migration-drift-$suffix"
idempotent_container="fncp-polis-migration-idempotent-$suffix"
runtime_client_container="fncp-polis-runtime-client-$suffix"
runtime_denied_container="fncp-polis-runtime-denied-$suffix"
certificate_volume="fncp-polis-certs-$suffix"
temporary_directory=$(
  mktemp -d "${TMPDIR:-/tmp}/fncp-polis-migration-smoke.XXXXXX"
)
postgres_environment="$temporary_directory/postgres.env"
migration_environment="$temporary_directory/migration.env"
runtime_environment="$temporary_directory/runtime.env"
migration_pid_one=
migration_pid_two=

cleanup() {
  for background_pid in "$migration_pid_one" "$migration_pid_two"; do
    if [ -n "$background_pid" ]; then
      kill -TERM "$background_pid" >/dev/null 2>&1 || true
      wait "$background_pid" >/dev/null 2>&1 || true
    fi
  done
  docker rm -f -v \
    "$runtime_denied_container" \
    "$runtime_client_container" \
    "$idempotent_container" \
    "$drift_container" \
    "$migration_container_two" \
    "$migration_container_one" \
    "$missing_bootstrap_container" \
    "$certificate_seed_container" \
    "$postgres_container" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$certificate_volume" >/dev/null 2>&1 || true
  rm -rf "$temporary_directory"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

owner_psql() {
  docker exec "$postgres_container" \
    psql \
      -X \
      -A \
      -t \
      -v ON_ERROR_STOP=1 \
      -U fncp_polis_owner \
      -d fncp_polis_smoke \
      "$@"
}

wait_for_postgres() {
  wait_attempt=0
  while [ "$wait_attempt" -lt 30 ]; do
    if owner_psql -c "SELECT 1" >/dev/null 2>&1; then
      return 0
    fi
    wait_attempt=$((wait_attempt + 1))
    sleep 1
  done
  docker logs --tail 80 "$postgres_container" >&2 || true
  return 1
}

run_migration() {
  migration_container_name=$1
  docker run --rm \
    --init \
    --stop-timeout 5 \
    --name "$migration_container_name" \
    --network "$network" \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
    --volume "$certificate_volume:/run/fncp-certs:ro" \
    --env-file "$migration_environment" \
    "$migration_image"
}

image_revision=$(
  docker image inspect \
    --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' \
    "$migration_image"
)
image_artifact=$(
  docker image inspect \
    --format '{{index .Config.Labels "org.barayamal.fncp.artifact"}}' \
    "$migration_image"
)
if [ "$image_revision" != "$revision" ]; then
  printf '%s\n' "The local migration image is not bound to the requested revision." >&2
  exit 1
fi
if [ "$image_artifact" != "polis-migration" ]; then
  printf '%s\n' "The local image is not the Pol.is migration artifact." >&2
  exit 1
fi

chmod 0700 "$temporary_directory"
umask 077
cat >"$postgres_environment" <<'EOF'
POSTGRES_USER=fncp_polis_owner
POSTGRES_PASSWORD=fncp_polis_owner_synthetic_only
POSTGRES_DB=fncp_polis_smoke
EOF
cat >"$migration_environment" <<EOF
FNCP_DATABASE_HOST=$postgres_container
FNCP_DATABASE_PASSWORD=fncp_polis_migration_synthetic_only
FNCP_DATABASE_PORT=5432
PGSSLMODE=verify-full
PGSSLROOTCERT=/run/fncp-certs/server.crt
FNCP_EXPECTED_DATABASE=fncp_polis_smoke
FNCP_EXPECTED_MIGRATION_ROLE=fncp_polis_migration
FNCP_RUNTIME_DB_ROLE=fncp_polis_runtime
EOF
cat >"$runtime_environment" <<EOF
PGHOST=$postgres_container
PGPORT=5432
PGDATABASE=fncp_polis_smoke
PGUSER=fncp_polis_runtime
PGPASSWORD=fncp_polis_runtime_synthetic_only
PGSSLMODE=verify-full
PGSSLROOTCERT=/run/fncp-certs/server.crt
EOF
chmod 0600 \
  "$postgres_environment" \
  "$migration_environment" \
  "$runtime_environment"

openssl req \
  -x509 \
  -newkey rsa:2048 \
  -sha256 \
  -nodes \
  -days 1 \
  -subj "/CN=$postgres_container" \
  -addext "subjectAltName=DNS:$postgres_container" \
  -keyout "$temporary_directory/server.key" \
  -out "$temporary_directory/server.crt" >/dev/null 2>&1

docker network create --internal "$network" >/dev/null
docker volume create "$certificate_volume" >/dev/null
docker create \
  --name "$certificate_seed_container" \
  --volume "$certificate_volume:/certs" \
  --entrypoint sh \
  "$postgres_image" \
  -c 'cp /tmp/server.crt /certs/server.crt &&
      cp /tmp/server.key /certs/server.key &&
      chown 70:70 /certs/server.crt /certs/server.key &&
      chmod 0644 /certs/server.crt &&
      chmod 0600 /certs/server.key' >/dev/null
docker cp \
  "$temporary_directory/server.crt" \
  "$certificate_seed_container:/tmp/server.crt"
docker cp \
  "$temporary_directory/server.key" \
  "$certificate_seed_container:/tmp/server.key"
docker start --attach "$certificate_seed_container" >/dev/null
if [ "$(
  docker inspect --format '{{.State.ExitCode}}' "$certificate_seed_container"
)" -ne 0 ]; then
  printf '%s\n' "The disposable TLS certificate volume could not be seeded." >&2
  exit 1
fi
docker rm -v "$certificate_seed_container" >/dev/null

docker run --detach \
  --name "$postgres_container" \
  --network "$network" \
  --env-file "$postgres_environment" \
  --volume "$certificate_volume:/certs:ro" \
  "$postgres_image" \
  -c ssl=on \
  -c ssl_cert_file=/certs/server.crt \
  -c ssl_key_file=/certs/server.key >/dev/null
wait_for_postgres

owner_psql -c \
  "CREATE ROLE fncp_polis_migration
     LOGIN PASSWORD 'fncp_polis_migration_synthetic_only'
     NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
     NOREPLICATION NOBYPASSRLS;
   CREATE ROLE fncp_polis_runtime
     LOGIN PASSWORD 'fncp_polis_runtime_synthetic_only'
     NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
     NOREPLICATION NOBYPASSRLS" >/dev/null

public_object_count_before=$(
  owner_psql -c \
    "SELECT
       (SELECT count(*)
          FROM pg_catalog.pg_class AS relation
          JOIN pg_catalog.pg_namespace AS namespace
            ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'public')
       +
       (SELECT count(*)
          FROM pg_catalog.pg_proc AS function
          JOIN pg_catalog.pg_namespace AS namespace
            ON namespace.oid = function.pronamespace
         WHERE namespace.nspname = 'public')"
)

# The unbootstrapped roles still inherit PostgreSQL's ambient PUBLIC access.
# The migration image must reject this state before creating tracking or
# application objects.
if run_migration "$missing_bootstrap_container" \
  >"$temporary_directory/missing-bootstrap.log" 2>&1
then
  printf '%s\n' "Migration unexpectedly accepted missing owner bootstrap ACLs." >&2
  exit 1
fi
if ! grep -Fq \
  "Migration role is missing, elevated, inheriting, a member, the database owner, incorrectly privileged, or not dedicated." \
  "$temporary_directory/missing-bootstrap.log"
then
  cat "$temporary_directory/missing-bootstrap.log" >&2
  printf '%s\n' "The missing-bootstrap check failed for an unexpected reason." >&2
  exit 1
fi
if [ "$(owner_psql -c "SELECT to_regnamespace('fncp_deploy') IS NULL")" != "t" ]; then
  printf '%s\n' "Failed bootstrap left migration tracking residue." >&2
  exit 1
fi
public_object_count_after=$(
  owner_psql -c \
    "SELECT
       (SELECT count(*)
          FROM pg_catalog.pg_class AS relation
          JOIN pg_catalog.pg_namespace AS namespace
            ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'public')
       +
       (SELECT count(*)
          FROM pg_catalog.pg_proc AS function
          JOIN pg_catalog.pg_namespace AS namespace
            ON namespace.oid = function.pronamespace
         WHERE namespace.nspname = 'public')"
)
if [ "$public_object_count_after" != "$public_object_count_before" ]; then
  printf '%s\n' "Failed bootstrap changed public-schema objects." >&2
  exit 1
fi

# Model the production database-owner bootstrap explicitly. PUBLIC receives
# no ambient database or public-schema access; each dedicated, non-owner role
# receives only the direct ACLs checked by fncp-run-migrations.
owner_psql -c \
  "REVOKE CONNECT, CREATE, TEMPORARY
      ON DATABASE fncp_polis_smoke FROM PUBLIC;
   REVOKE USAGE, CREATE ON SCHEMA public FROM PUBLIC;
   GRANT CONNECT, CREATE
      ON DATABASE fncp_polis_smoke TO fncp_polis_migration;
   REVOKE TEMPORARY
      ON DATABASE fncp_polis_smoke FROM fncp_polis_migration;
   GRANT USAGE, CREATE ON SCHEMA public TO fncp_polis_migration;
   GRANT CONNECT ON DATABASE fncp_polis_smoke TO fncp_polis_runtime;
   REVOKE CREATE, TEMPORARY
      ON DATABASE fncp_polis_smoke FROM fncp_polis_runtime;
   GRANT USAGE ON SCHEMA public TO fncp_polis_runtime;
   REVOKE CREATE ON SCHEMA public FROM fncp_polis_runtime" >/dev/null

# Two simultaneous first runs prove that the image's session advisory lock
# serializes the baseline: exactly one applies each migration and the other
# observes the same immutable receipts.
run_migration "$migration_container_one" \
  >"$temporary_directory/migration-one.log" 2>&1 &
migration_pid_one=$!
run_migration "$migration_container_two" \
  >"$temporary_directory/migration-two.log" 2>&1 &
migration_pid_two=$!

if ! wait "$migration_pid_one"; then
  cat "$temporary_directory/migration-one.log" >&2
  migration_pid_one=
  exit 1
fi
migration_pid_one=
if ! wait "$migration_pid_two"; then
  cat "$temporary_directory/migration-two.log" >&2
  migration_pid_two=
  exit 1
fi
migration_pid_two=

for migration_log in \
  "$temporary_directory/migration-one.log" \
  "$temporary_directory/migration-two.log"
do
  if ! grep -q "FNCP Pol.is migrations completed." "$migration_log"; then
    cat "$migration_log" >&2
    printf '%s\n' "A concurrent migration did not reach a clean completion." >&2
    exit 1
  fi
done
applied_count=$(
  awk '
    /^Applying:/ { total += 1 }
    END { print total + 0 }
  ' \
    "$temporary_directory/migration-one.log" \
    "$temporary_directory/migration-two.log"
)
already_applied_count=$(
  awk '
    /^Already applied:/ { total += 1 }
    END { print total + 0 }
  ' \
    "$temporary_directory/migration-one.log" \
    "$temporary_directory/migration-two.log"
)
if [ "$applied_count" -ne 19 ] || [ "$already_applied_count" -ne 19 ]; then
  printf '%s\n' "Concurrent runs did not produce one apply and one replay per migration." >&2
  exit 1
fi

receipt_state=$(
  owner_psql -c \
    "SELECT count(*)::text || ':' ||
            count(*) FILTER (WHERE sha256 ~ '^[a-f0-9]{64}$')::text
       FROM fncp_deploy.schema_migrations"
)
if [ "$receipt_state" != "19:19" ]; then
  printf '%s\n' "The migration image did not record 19 validated receipts." >&2
  exit 1
fi

receipt_filename=$(
  owner_psql -c \
    "SELECT filename
       FROM fncp_deploy.schema_migrations
      ORDER BY filename
      LIMIT 1"
)
receipt_sha=$(
  owner_psql -c \
    "SELECT sha256
       FROM fncp_deploy.schema_migrations
      WHERE filename = '$receipt_filename'"
)
case "$receipt_filename" in
  [0-9][0-9][0-9][0-9][0-9][0-9]_[a-z0-9_]*.sql) ;;
  *)
    printf '%s\n' "The selected receipt filename is unsafe." >&2
    exit 1
    ;;
esac
case "$receipt_sha" in
  "" | *[!a-f0-9]*)
    printf '%s\n' "The selected receipt SHA-256 is invalid." >&2
    exit 1
    ;;
esac
if [ "${#receipt_sha}" -ne 64 ]; then
  printf '%s\n' "The selected receipt SHA-256 is invalid." >&2
  exit 1
fi
drift_sha="0000000000000000000000000000000000000000000000000000000000000000"
if [ "$receipt_sha" = "$drift_sha" ]; then
  drift_sha="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
fi
owner_psql -c \
  "UPDATE fncp_deploy.schema_migrations
      SET sha256 = '$drift_sha'
    WHERE filename = '$receipt_filename'" >/dev/null
if run_migration "$drift_container" \
  >"$temporary_directory/checksum-drift.log" 2>&1
then
  printf '%s\n' "Migration unexpectedly accepted checksum drift." >&2
  exit 1
fi
if ! grep -q "Migration checksum mismatch:" \
  "$temporary_directory/checksum-drift.log"
then
  cat "$temporary_directory/checksum-drift.log" >&2
  printf '%s\n' "Checksum drift failed for an unexpected reason." >&2
  exit 1
fi
owner_psql -c \
  "UPDATE fncp_deploy.schema_migrations
      SET sha256 = '$receipt_sha'
    WHERE filename = '$receipt_filename'" >/dev/null

run_migration "$idempotent_container" \
  >"$temporary_directory/idempotent.log" 2>&1
if [ "$(grep -c "^Already applied:" "$temporary_directory/idempotent.log")" -ne 19 ]; then
  cat "$temporary_directory/idempotent.log" >&2
  printf '%s\n' "The restored migration state was not fully idempotent." >&2
  exit 1
fi
if [ "$(
  owner_psql -c "SELECT count(*) FROM fncp_deploy.schema_migrations"
)" -ne 19 ]; then
  printf '%s\n' "The idempotent run changed the receipt count." >&2
  exit 1
fi

runtime_acl_state=$(
  owner_psql -c \
    "SELECT
       pg_catalog.has_database_privilege(
         'fncp_polis_runtime', current_database(), 'CONNECT'
       )::int::text ||
       pg_catalog.has_database_privilege(
         'fncp_polis_runtime', current_database(), 'CREATE'
       )::int::text ||
       pg_catalog.has_database_privilege(
         'fncp_polis_runtime', current_database(), 'TEMPORARY'
       )::int::text ||
       pg_catalog.has_schema_privilege(
         'fncp_polis_runtime', 'public', 'USAGE'
       )::int::text ||
       pg_catalog.has_schema_privilege(
         'fncp_polis_runtime', 'public', 'CREATE'
       )::int::text ||
       pg_catalog.has_schema_privilege(
         'fncp_polis_runtime', 'fncp_deploy', 'USAGE'
       )::int::text ||
       pg_catalog.has_table_privilege(
         'fncp_polis_runtime',
         'fncp_deploy.schema_migrations',
         'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
       )::int::text"
)
if [ "$runtime_acl_state" != "1001000" ]; then
  printf '%s\n' "The runtime role retained unexpected database, schema, or tracking ACLs." >&2
  exit 1
fi
runtime_role_state=$(
  owner_psql -c \
    "SELECT
       (role.rolcanlogin
        AND NOT role.rolinherit
        AND NOT role.rolsuper
        AND NOT role.rolcreatedb
        AND NOT role.rolcreaterole
        AND NOT role.rolreplication
        AND NOT role.rolbypassrls
        AND NOT EXISTS (
          SELECT 1
            FROM pg_catalog.pg_auth_members AS membership
           WHERE membership.member = role.oid
        ))::int
       FROM pg_catalog.pg_roles AS role
      WHERE role.rolname = 'fncp_polis_runtime'"
)
if [ "$runtime_role_state" != "1" ]; then
  printf '%s\n' "The runtime role is not a dedicated NOINHERIT role." >&2
  exit 1
fi

docker run --rm \
  --init \
  --stop-timeout 5 \
  --name "$runtime_client_container" \
  --network "$network" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8m \
  --volume "$certificate_volume:/run/fncp-certs:ro" \
  --env-file "$runtime_environment" \
  --entrypoint psql \
  "$postgres_image" \
  -X -A -t -v ON_ERROR_STOP=1 \
  -c "SELECT current_user = 'fncp_polis_runtime'" |
  grep -qx "t"

if docker run --rm \
  --init \
  --stop-timeout 5 \
  --name "$runtime_denied_container" \
  --network "$network" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8m \
  --volume "$certificate_volume:/run/fncp-certs:ro" \
  --env-file "$runtime_environment" \
  --entrypoint psql \
  "$postgres_image" \
  -X -A -t -v ON_ERROR_STOP=1 \
  -c "SELECT count(*) FROM fncp_deploy.schema_migrations" \
  >"$temporary_directory/runtime-tracking-access.log" 2>&1
then
  printf '%s\n' "The runtime role unexpectedly read migration tracking data." >&2
  exit 1
fi

printf '%s\n' "Pol.is migration exact-image lifecycle smoke: PASS"
