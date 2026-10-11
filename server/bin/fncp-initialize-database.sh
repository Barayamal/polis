#!/bin/sh
# Fresh database preparation and normal PostgreSQL start are separate actions.
# The launcher owns the volume, network, certificates and all role material.
set -eu
umask 077
fail() { printf '%s\n' 'FNCP_DATABASE_INITIALIZATION_FAILED' >&2; exit 1; }
[ "$#" -eq 1 ] || fail
[ "$(id -u)" = 70 ] || fail
[ "${PGDATA-}" = /var/lib/postgresql/data/pgdata ] || fail
case "$1" in initialize|start) ;; *) fail ;; esac
if [ "$1" = initialize ] && [ ! -e "$PGDATA" ]; then
  [ -d /var/lib/postgresql/data ] && [ ! -L /var/lib/postgresql/data ] || fail
  mkdir -m 0700 "$PGDATA" || fail
fi
[ -d "$PGDATA" ] && [ ! -L "$PGDATA" ] && [ -w "$PGDATA" ] || fail
if [ "$1" = start ]; then
  [ -s "$PGDATA/PG_VERSION" ] && [ -s "$PGDATA/fncp-initialized" ] || fail
  [ -s "$PGDATA/fncp.conf" ] && [ -s "$PGDATA/server.key" ] || fail
  exec postgres -D "$PGDATA" -c config_file="$PGDATA/fncp.conf"
fi
[ -z "$(find "$PGDATA" -mindepth 1 -maxdepth 1 -print -quit)" ] || fail
for key in FNCP_DATABASE_NAME FNCP_OWNER_ROLE FNCP_MIGRATION_ROLE FNCP_RUNTIME_ROLE FNCP_MATH_ROLE; do
  case "$key" in
    FNCP_DATABASE_NAME) value=${FNCP_DATABASE_NAME-} ;;
    FNCP_OWNER_ROLE) value=${FNCP_OWNER_ROLE-} ;;
    FNCP_MIGRATION_ROLE) value=${FNCP_MIGRATION_ROLE-} ;;
    FNCP_RUNTIME_ROLE) value=${FNCP_RUNTIME_ROLE-} ;;
    FNCP_MATH_ROLE) value=${FNCP_MATH_ROLE-} ;;
  esac
  case "$value" in [a-z_]*) ;; *) fail ;; esac
  case "$value" in *[!a-z0-9_]*|postgres|template0|template1) fail ;; esac
  [ "${#value}" -le 63 ] || fail
done
[ "$FNCP_OWNER_ROLE" != "$FNCP_MIGRATION_ROLE" ] &&
  [ "$FNCP_OWNER_ROLE" != "$FNCP_RUNTIME_ROLE" ] &&
  [ "$FNCP_MIGRATION_ROLE" != "$FNCP_RUNTIME_ROLE" ] &&
  [ "$FNCP_MATH_ROLE" != "$FNCP_OWNER_ROLE" ] && [ "$FNCP_MATH_ROLE" != "$FNCP_MIGRATION_ROLE" ] &&
  [ "$FNCP_MATH_ROLE" != "$FNCP_RUNTIME_ROLE" ] || fail
read_password() {
  password_path=/run/fncp/database-$1-password
  [ -f "$password_path" ] && [ ! -L "$password_path" ] || fail
  password_value=$(cat "$password_path")
  case "$password_value" in ''|*[!A-Za-z0-9_-]*) fail ;; esac
  [ "${#password_value}" -ge 32 ] && [ "${#password_value}" -le 128 ] || fail
  password_size=$(wc -c < "$password_path" | tr -d ' ')
  [ "$password_size" -eq "${#password_value}" ] ||
    [ "$password_size" -eq "$(( ${#password_value} + 1 ))" ] || fail
  printf '%s' "$password_value"
}
owner_password=$(read_password owner) || fail
migration_password=$(read_password migration) || fail
runtime_password=$(read_password runtime) || fail
math_password=$(read_password math) || fail
[ "$owner_password" != "$migration_password" ] && [ "$owner_password" != "$runtime_password" ] &&
  [ "$migration_password" != "$runtime_password" ] && [ "$math_password" != "$owner_password" ] &&
  [ "$math_password" != "$migration_password" ] && [ "$math_password" != "$runtime_password" ] || fail
for material in database-server.pem database-server.key; do
  [ -f "/run/fncp/$material" ] && [ ! -L "/run/fncp/$material" ] && [ -s "/run/fncp/$material" ] || fail
done
# Never import an existing cluster or run SQL migrations as the owner.
initdb -D "$PGDATA" --username=postgres --auth-local=peer --auth-host=scram-sha-256 --encoding=UTF8 --locale=C >/dev/null
mkdir "$PGDATA/socket"
temporary_started=false
cleanup() {
  if [ "$temporary_started" = true ]; then pg_ctl -D "$PGDATA" -m fast -w stop >/dev/null 2>&1 || true; fi
  rm -f "$PGDATA/fncp-owner-bootstrap.sql"
}
trap cleanup EXIT
trap 'exit 143' HUP INT TERM
pg_ctl -D "$PGDATA" -o "-c listen_addresses='' -c unix_socket_directories='$PGDATA/socket' -c unix_socket_permissions=0700 -c log_statement=none -c log_min_error_statement=panic" -w start >/dev/null
temporary_started=true
cat > "$PGDATA/fncp-owner-bootstrap.sql" <<SQL
CREATE ROLE $FNCP_OWNER_ROLE LOGIN PASSWORD '$owner_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE $FNCP_MIGRATION_ROLE LOGIN PASSWORD '$migration_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE $FNCP_RUNTIME_ROLE LOGIN PASSWORD '$runtime_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE $FNCP_MATH_ROLE LOGIN PASSWORD '$math_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE DATABASE $FNCP_DATABASE_NAME OWNER $FNCP_OWNER_ROLE;
REVOKE CONNECT, CREATE, TEMPORARY ON DATABASE $FNCP_DATABASE_NAME FROM PUBLIC;
GRANT CONNECT, CREATE ON DATABASE $FNCP_DATABASE_NAME TO $FNCP_MIGRATION_ROLE;
REVOKE TEMPORARY ON DATABASE $FNCP_DATABASE_NAME FROM $FNCP_MIGRATION_ROLE;
GRANT CONNECT ON DATABASE $FNCP_DATABASE_NAME TO $FNCP_RUNTIME_ROLE;
REVOKE CREATE, TEMPORARY ON DATABASE $FNCP_DATABASE_NAME FROM $FNCP_RUNTIME_ROLE;
GRANT CONNECT ON DATABASE $FNCP_DATABASE_NAME TO $FNCP_MATH_ROLE;
REVOKE CREATE, TEMPORARY ON DATABASE $FNCP_DATABASE_NAME FROM $FNCP_MATH_ROLE;
\connect $FNCP_DATABASE_NAME
REVOKE USAGE, CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO $FNCP_MIGRATION_ROLE;
GRANT USAGE ON SCHEMA public TO $FNCP_RUNTIME_ROLE;
REVOKE CREATE ON SCHEMA public FROM $FNCP_RUNTIME_ROLE;
GRANT USAGE ON SCHEMA public TO $FNCP_MATH_ROLE;
REVOKE CREATE ON SCHEMA public FROM $FNCP_MATH_ROLE;
SQL
unset owner_password migration_password runtime_password math_password password_value
psql -X --no-psqlrc -q -v ON_ERROR_STOP=1 -h "$PGDATA/socket" -U postgres -d postgres -f "$PGDATA/fncp-owner-bootstrap.sql" >/dev/null
rm "$PGDATA/fncp-owner-bootstrap.sql"
pg_ctl -D "$PGDATA" -m fast -w stop >/dev/null
temporary_started=false
cp /run/fncp/database-server.pem "$PGDATA/server.crt"
cp /run/fncp/database-server.key "$PGDATA/server.key"
chmod 0600 "$PGDATA/server.crt" "$PGDATA/server.key"
cat > "$PGDATA/pg_hba.conf" <<HBA
local all postgres peer
local all all reject
hostssl $FNCP_DATABASE_NAME $FNCP_OWNER_ROLE,$FNCP_MIGRATION_ROLE,$FNCP_RUNTIME_ROLE,$FNCP_MATH_ROLE 0.0.0.0/0 scram-sha-256
hostssl $FNCP_DATABASE_NAME $FNCP_OWNER_ROLE,$FNCP_MIGRATION_ROLE,$FNCP_RUNTIME_ROLE,$FNCP_MATH_ROLE ::/0 scram-sha-256
host all all 0.0.0.0/0 reject
host all all ::/0 reject
HBA
cat > "$PGDATA/fncp.conf" <<CONF
data_directory = '$PGDATA'
hba_file = '$PGDATA/pg_hba.conf'
ident_file = '$PGDATA/pg_ident.conf'
listen_addresses = '*'
port = 5432
unix_socket_directories = '$PGDATA/socket'
unix_socket_permissions = 0700
ssl = on
ssl_min_protocol_version = 'TLSv1.2'
ssl_cert_file = '$PGDATA/server.crt'
ssl_key_file = '$PGDATA/server.key'
password_encryption = 'scram-sha-256'
log_statement = 'none'
log_min_error_statement = 'panic'
CONF
printf '%s\n' 'fresh initialization complete; public migrations have not run' > "$PGDATA/fncp-initialized"
printf '%s\n' '{"freshDatabaseInitialized":true,"applicationMigrationsApplied":false}'
