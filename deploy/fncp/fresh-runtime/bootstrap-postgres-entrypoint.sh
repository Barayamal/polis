#!/bin/sh
# Fresh-only PG17 recipe. Source/model tests are not evidence of database startup.
# Material must be copied into the exact new stopped container as UID/GID 70.
# No adoption, restart, root delegation, external network, or destructive reset.
set -eu
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
umask 077
fail() { printf '%s\n' 'Fresh PostgreSQL initialization rejected; details withheld.' >&2; exit 1; }
[ "$#" -eq 0 ] || fail
[ "$(id -u)" = 70 ] && [ "$(id -g)" = 70 ] || fail
material=/run/fncp/postgres-material
root=/var/lib/postgresql/data
data=/var/lib/postgresql/data/pgdata
socket=/var/lib/postgresql/data/socket
migrations=/opt/fncp/migrations
started=no
cleanup() {
  if [ "$started" = yes ]; then
    env -i PATH="$PATH" LC_ALL=C /usr/local/bin/pg_ctl -D "$data" -m immediate -w -t 10 stop >/dev/null 2>&1 || :
  fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
private_directory() {
  [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%g:%a' "$1")" = 70:70:700 ] || fail
}
private_directory "$material"
private_directory "$root"
[ ! -e "$data" ] && [ ! -L "$data" ] || fail
[ ! -e "$root/.fncp-initialization-attempted" ] && [ ! -L "$root/.fncp-initialization-attempted" ] || fail
[ -z "$(find "$root" -mindepth 1 -maxdepth 1 -print -quit)" ] || fail
[ -d "$migrations" ] && [ ! -L "$migrations" ] || fail
# Fixed inventory only; never source a material file or accept command options.
set -- namespace database user password postgres-cert.pem postgres-key.pem postgresql.conf pg_hba.conf
[ "$(find "$material" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" = 8 ] || fail
for file do
  [ -f "$material/$file" ] && [ ! -L "$material/$file" ] || fail
  [ "$(stat -c '%u:%g:%a:%h' "$material/$file")" = 70:70:600:1 ] || fail
  size=$(wc -c < "$material/$file" | tr -d ' ')
  [ "$size" -gt 0 ] && [ "$size" -le 8192 ] || fail
done
IFS= read -r namespace < "$material/namespace" || fail
IFS= read -r database < "$material/database" || fail
IFS= read -r user < "$material/user" || fail
IFS= read -r password < "$material/password" || fail
case "$namespace" in *[!a-f0-9]*|'') fail ;; esac
[ "${#namespace}" = 24 ] && [ "$(wc -c < "$material/namespace" | tr -d ' ')" = 25 ] || fail
for identity in "$database" "$user"; do
  case "$identity" in fncp_fresh_*) suffix=${identity#fncp_fresh_} ;; *) fail ;; esac
  case "$suffix" in *[!a-f0-9]*|'') fail ;; esac
  [ "${#suffix}" = 24 ] && [ "$suffix" != "$namespace" ] || fail
done
[ "$database" != "$user" ] || fail
[ "$(wc -c < "$material/database" | tr -d ' ')" = 36 ] || fail
[ "$(wc -c < "$material/user" | tr -d ' ')" = 36 ] || fail
case "$password" in *[!a-f0-9]*|'') fail ;; esac
[ "${#password}" = 64 ] && [ "$(wc -c < "$material/password" | tr -d ' ')" = 65 ] || fail
cmp -s "$material/postgresql.conf" - <<'CONFIG' || fail
listen_addresses = '127.0.0.1'
port = 5432
ssl = on
ssl_min_protocol_version = 'TLSv1.2'
ssl_cert_file = '/run/fncp/postgres-material/postgres-cert.pem'
ssl_key_file = '/run/fncp/postgres-material/postgres-key.pem'
hba_file = '/run/fncp/postgres-material/pg_hba.conf'
unix_socket_directories = '/var/lib/postgresql/data/socket'
unix_socket_permissions = 0700
password_encryption = 'scram-sha-256'
max_connections = 32
shared_buffers = '16MB'
shared_preload_libraries = ''
search_path = 'public'
archive_mode = off
archive_command = ''
ssl_passphrase_command = ''
logging_collector = off
log_destination = 'stderr'
log_statement = 'none'
log_min_error_statement = 'panic'
log_min_messages = 'panic'
log_connections = off
log_disconnections = off
log_duration = off
log_parameter_max_length = 0
log_parameter_max_length_on_error = 0
track_activities = off
CONFIG
cmp -s "$material/pg_hba.conf" - <<HBA || fail
local all postgres peer
local $database $user trust
local all all reject
hostssl $database $user 127.0.0.1/32 scram-sha-256
host all all 0.0.0.0/0 reject
host all all ::0/0 reject
HBA
# Pin the complete public migration chain before any database operation.
[ "$(find "$migrations" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" = 20 ] || fail
while read -r expected file; do
  [ -f "$migrations/$file" ] && [ ! -L "$migrations/$file" ] || fail
  actual=$(sha256sum "$migrations/$file") || fail
  [ "${actual%% *}" = "$expected" ] || fail
done <<'HASHES'
2652134140cd8796ee3ab64995d509206bab3ebe8a03bba0cf48038a32dc6cea 000000_initial.sql
cb21278194c4b7db510c12bf1a7761b3a905410a7b3769edeb0d1865b6ec047b 000001_update_pwreset_table.sql
a27a8e63c79cd055198fa201b1745c85e0cd0e0b75f228b7153571631e529c07 000002_add_xid_constraint.sql
0d7f27facfecff1327573d3e1a5f65a3277ea94a30bcd8692606f00a7e496d3d 000003_add_origin_permanent_cookie_columns.sql
f2fc4184a965ffad01913d0e71a806c6f7e2aecc5f59279c11b0cd3ed3a77528 000004_drop_waitinglist_table.sql
392e5b8aadb7a85767820ec97fcfb0853821d35089be3e8c3dfe70df24782839 000005_drop_slack_stripe_canvas.sql
8fb05b7b1b6a8b123cea6b2680054d8da2fe48585c51a2f9f108b8b174d85c60 000006_update_votes_rule.sql
f68b69b86112ad52e2cb79a9b631ea77a0285b24201b41c15d9c13257f7cd9cc 000007_drop_geolocation_fields.sql
c867b53be3cca6bce059b19ea9eb3950120fb5840a1476af409924ca55905261 000008_add_comment_priority.sql
43f36fe0b8578bc4b32761a2b9d7a5181a8159ff8b0c7bb0a1a73f802ec5f670 000009_add_uuid_to_zinvites.sql
450a3f69883aa56c3bc85994ab1baf5e208634d88435a156fe2a22738b1d9f9a 000010_create_oidc_user_mappings.sql
00a1eb2d9604804a56705eaac92bb6d37b6c696abdfd9bb079d4a1c494ff0ab6 000011_alter_suzinvites_xid_to_text.sql
cc513693124f031ce1d55e7e73b14b4e3c40a4070e65465adbc621e63b1008cf 000012_create_topic_agenda_selections.sql
4b8334f73246c69bc9ecadd4a2dc00c8cfb642351ba70ed4a9a58b882a4ac53f 000013_create_treevite.sql
c2af6d57af2866f1f259bb41b94dbf730eca499a4b18f092c4aeeebce5a95025 000014_alter_reports_modlevel.sql
186c904addd0c8a42c10057e6ae362fe2799cc076e877bef3ffa14e9852184e7 000015_add_xid_requirements.sql
6cdc0588c000fbbe89d578bc2f0aa60422b92b5320aba737d6d83f89d8d990db 000016_add_orig_id.sql
f27c03a1229f296fab21cee059b743c7137bf502e4178854e596a8efa4808b55 000017_create_byod_job_table.sql
a1e1c0572064d88877d87142bc4e40132b84672bbe84392e99f9f6f4c2ea107e 000018_add_topics_enabled.sql
bb0b8e035d41563fdf73cda33956030eb9209a47b503cd5a1216ed6886a6dcbd 000019_add_fncp_provider_allowlist_operations.sql
HASHES
# An attempted initialization is irreversible in this private tmpfs. Never retry.
mkdir -m 700 "$root/.fncp-initialization-attempted" || fail
mkdir -m 700 "$data" "$socket" || fail
env -i PATH="$PATH" LC_ALL=C timeout 30 /usr/local/bin/initdb -D "$data" --username=postgres --auth-local=peer --auth-host=reject --encoding=UTF8 --locale=C >/dev/null 2>&1 || fail
# Set before start: an uncertain start still receives one bounded cleanup attempt.
started=yes
env -i PATH="$PATH" LC_ALL=C /usr/local/bin/pg_ctl -D "$data" -l /dev/null -w -t 20 -o "-c config_file=$material/postgresql.conf -c ssl=off -c listen_addresses=" start >/dev/null 2>&1 || fail
env -i PATH="$PATH" LC_ALL=C PGCONNECT_TIMEOUT=3 PGOPTIONS='-c statement_timeout=10000 -c lock_timeout=2000' timeout 30 /usr/local/bin/psql --no-psqlrc --no-password --set=ON_ERROR_STOP=on --set=VERBOSITY=terse -h "$socket" -p 5432 -U postgres -d postgres >/dev/null 2>&1 <<SQL || fail
CREATE ROLE "$user" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '$password';
CREATE DATABASE "$database" OWNER "$user";
SQL
unset password
for file in "$migrations"/*.sql; do
  env -i PATH="$PATH" LC_ALL=C PGCONNECT_TIMEOUT=3 PGOPTIONS='-c statement_timeout=10000 -c lock_timeout=2000' timeout 30 /usr/local/bin/psql --no-psqlrc --no-password --set=ON_ERROR_STOP=on --set=VERBOSITY=terse -h "$socket" -p 5432 -U "$user" -d "$database" --file="$file" >/dev/null 2>&1 || fail
done
env -i PATH="$PATH" LC_ALL=C /usr/local/bin/pg_ctl -D "$data" -m fast -w -t 20 stop >/dev/null 2>&1 || fail
started=no
# Readiness only means this initialization chain completed, not API assurance.
(set -C; printf '%s\n' 'PUBLIC_MIGRATIONS_APPLIED_20' > "$root/.fncp-schema-ready") || fail
trap - EXIT HUP INT TERM
exec env -i PATH="$PATH" LC_ALL=C /usr/local/bin/postgres -D "$data" -c "config_file=$material/postgresql.conf"
