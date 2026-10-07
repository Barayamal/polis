#!/bin/sh
# Actual disposable PostgreSQL17 logical recovery. Run only in the current
# freshly owned PG container after every participant/bootstrap client stopped.
# Reads only the two named current-attempt material files; no caller inputs,
# credentials, database names, identifiers or row content are printed.
# Preserves both databases and all private recovery files on every outcome.
set -eu
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
umask 077
stage=PLATFORM
watchdog=
cleanup() {
  if [ -n "$watchdog" ]; then kill "$watchdog" 2>/dev/null || :; wait "$watchdog" 2>/dev/null || :; fi
}
fail() {
  printf '{"classification":"FRESH_POSTGRES_LOGICAL_RESTORE","outcome":"FAIL","failurePhase":"%s","productionRecoveryProven":false,"databasesPreserved":true}\n' "$stage"
  exit 1
}
trap cleanup EXIT
trap 'stage=INTERRUPTED; fail' HUP INT TERM
[ "$#" -eq 0 ] || fail
[ "$(id -u)" = 70 ] && [ "$(id -g)" = 70 ] || fail
material=/run/fncp/postgres-material
root=/var/lib/postgresql/data
socket=/var/lib/postgresql/data/socket
recovery=/var/lib/postgresql/data/fncp-recovery
for directory in "$material" "$root" "$socket"; do
  [ -d "$directory" ] && [ ! -L "$directory" ] && [ "$(stat -c '%u:%g:%a' "$directory")" = 70:70:700 ] || fail
done
stage=MATERIAL
for file in database user; do
  [ -f "$material/$file" ] && [ ! -L "$material/$file" ] || fail
  [ "$(stat -c '%u:%g:%a:%h:%s' "$material/$file")" = 70:70:600:1:36 ] || fail
done
IFS= read -r source_db < "$material/database" || fail
IFS= read -r app_user < "$material/user" || fail
for identity in "$source_db" "$app_user"; do
  case "$identity" in fncp_fresh_*) suffix=${identity#fncp_fresh_} ;; *) fail ;; esac
  case "$suffix" in *[!a-f0-9]*|'') fail ;; esac
  [ "${#suffix}" = 24 ] || fail
done
[ "$source_db" != "$app_user" ] || fail
restore_db=fncp_restore_${source_db#fncp_fresh_}
[ ! -e "$recovery" ] && [ ! -L "$recovery" ] || fail
mkdir -m 700 "$recovery" || fail
printf '%s\n' 'ONE_FRESH_LOGICAL_RESTORE_ATTEMPT_NO_RESUME' > "$recovery/attempt"
owner_pid=$$
(
  sleep 180 & sleeper=$!
  trap 'kill "$sleeper" 2>/dev/null || :; wait "$sleeper" 2>/dev/null || :; exit 0' HUP INT TERM
  wait "$sleeper"; kill -TERM "$owner_pid" 2>/dev/null || :
) &
watchdog=$!
start_time=$(date +%s)

# Every database process is independently bounded and ignores ambient libpq
# configuration. Peer authentication is only the exact private Unix socket.
psql_db() {
  env -i PATH="$PATH" LC_ALL=C PGCONNECT_TIMEOUT=3 PGOPTIONS='-c statement_timeout=12000 -c lock_timeout=2000 -c timezone=UTC -c DateStyle=ISO,YMD -c extra_float_digits=3' \
    timeout 15 /usr/local/bin/psql --no-psqlrc --no-password --quiet --tuples-only --no-align \
    --set=ON_ERROR_STOP=on --set=VERBOSITY=terse -h "$socket" -p 5432 -U postgres -d "$1" 2>/dev/null
}
dump_db() {
  env -i PATH="$PATH" LC_ALL=C PGCONNECT_TIMEOUT=3 PGOPTIONS='-c statement_timeout=20000 -c lock_timeout=2000 -c timezone=UTC' \
    timeout 30 /usr/local/bin/pg_dump --no-password -h "$socket" -p 5432 -U postgres -d "$1" \
    --format=custom --no-owner --no-privileges --file="$2" >/dev/null 2>&1
}
schema_db() {
  env -i PATH="$PATH" LC_ALL=C PGCONNECT_TIMEOUT=3 PGOPTIONS='-c statement_timeout=12000 -c lock_timeout=2000 -c timezone=UTC' \
    timeout 20 /usr/local/bin/pg_dump --no-password -h "$socket" -p 5432 -U postgres -d "$1" \
    --schema-only --schema=public --no-owner --no-privileges --file="$2.raw" >/dev/null 2>&1 || return 1
  # PG17 security backports use a new random psql restriction key per dump.
  # Removing only those generated command lines makes structural text comparable.
  sed '/^\\restrict /d; /^\\unrestrict /d' "$2.raw" > "$2"
}
safe_name() {
  case "$1" in ''|*[!a-z0-9_]*) return 1 ;; esac
  case "$1" in [a-z_]*) ;; *) return 1 ;; esac
  [ "${#1}" -le 63 ]
}
number() { case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }

cat > "$recovery/closed.sql" <<'SQL'
BEGIN READ ONLY ISOLATION LEVEL REPEATABLE READ;
SELECT CASE WHEN
 current_setting('server_version_num')::integer BETWEEN 170000 AND 179999
 AND (SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND backend_type='client backend')=0
 AND (SELECT count(*) FROM public.conversations)=1
 AND (SELECT count(*) FROM public.zinvites)=1
 AND (SELECT count(*) FROM public.conversations WHERE is_active IS FALSE AND use_xid_whitelist IS TRUE AND xid_required IS TRUE
   AND is_data_open IS FALSE AND is_anon IS TRUE AND is_draft IS FALSE AND strict_moderation IS TRUE
   AND topics_enabled IS FALSE AND treevite_enabled IS FALSE AND profanity_filter IS FALSE AND spam_filter IS FALSE)=1
 AND (SELECT count(*) FROM public.comments)=15
 AND (SELECT count(*) FROM public.comments c JOIN public.conversations t USING(zid)
   WHERE c.is_seed AND c.active AND c.mod=1 AND c.uid=t.owner)=15
 AND (SELECT count(DISTINCT pid) FROM public.comments)=1
 AND (SELECT count(*) FROM public.votes)=16
 AND (SELECT count(*) FROM public.votes_latest_unique)=16
 AND (SELECT count(*) FROM public.votes v JOIN public.comments c USING(zid,tid) WHERE v.pid=c.pid AND v.vote=0)=15
 AND (SELECT count(*) FROM public.votes_latest_unique v JOIN public.comments c USING(zid,tid) WHERE v.pid=c.pid AND v.vote=0)=15
 AND (SELECT count(*) FROM public.votes v JOIN public.comments c USING(zid,tid) WHERE v.pid<>c.pid AND v.vote IN(-1,0,1))=1
 AND (SELECT count(*) FROM public.xid_whitelist)=0
 AND (SELECT count(*) FROM public.fncp_provider_allowlist_operations)=2
 AND (SELECT count(*) FROM public.fncp_provider_allowlist_operations WHERE operation_version=2 AND desired_present IS FALSE)=2
 THEN 'CLOSED_BASELINE_OK' ELSE 'CLOSED_BASELINE_REJECTED' END;
ROLLBACK;
SQL

# Canonical private inventory: relation name, row count, SHA256 of sorted JSON
# rows. Column order is compared in the schema dump. C collation, UTF8, UTC and
# fixed DateStyle make equal restored SQL values deterministic. No row is public.
inventory_db() {
  current_db=$1
  target=$2
  mkdir -m 700 "$target" || return 1
  psql_db "$current_db" > "$target/tables" <<'SQL' || return 1
SELECT c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relkind='r' ORDER BY c.relname COLLATE "C";
SQL
  table_count=$(wc -l < "$target/tables" | tr -d ' ')
  number "$table_count" && [ "$table_count" -gt 0 ] && [ "$table_count" -le 128 ] || return 1
  : > "$target/table-manifest"
  while IFS= read -r table; do
    safe_name "$table" || return 1
    psql_db "$current_db" > "$target/$table.rows" <<SQL || return 1
BEGIN READ ONLY ISOLATION LEVEL REPEATABLE READ;
COPY (SELECT row_to_json(t)::text FROM public."$table" t ORDER BY row_to_json(t)::text COLLATE "C") TO STDOUT;
ROLLBACK;
SQL
    bytes=$(wc -c < "$target/$table.rows" | tr -d ' ')
    number "$bytes" && [ "$bytes" -le 67108864 ] || return 1
    rows=$(wc -l < "$target/$table.rows" | tr -d ' ')
    number "$rows" || return 1
    digest=$(sha256sum "$target/$table.rows") || return 1
    printf '%s\t%s\t%s\n' "$table" "$rows" "${digest%% *}" >> "$target/table-manifest"
  done < "$target/tables"
  psql_db "$current_db" > "$target/sequences" <<'SQL' || return 1
SELECT c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relkind='S' ORDER BY c.relname COLLATE "C";
SQL
  : > "$target/sequence-manifest"
  while IFS= read -r sequence; do
    safe_name "$sequence" || return 1
    state=$(psql_db "$current_db" <<SQL
SELECT last_value::text || ':' || is_called::text FROM public."$sequence";
SQL
    ) || return 1
    case "$state" in *:true|*:false) ;; *) return 1 ;; esac
    printf '%s\t%s\n' "$sequence" "$state" >> "$target/sequence-manifest"
  done < "$target/sequences"
  schema_db "$current_db" "$target/schema.sql" || return 1
}

stage=SOURCE_ADMISSION
admission=$(psql_db postgres <<SQL
SELECT CASE WHEN
 (SELECT count(*) FROM pg_catalog.pg_database d JOIN pg_catalog.pg_roles r ON r.oid=d.datdba
   WHERE d.datname='$source_db' AND r.rolname='$app_user' AND NOT d.datistemplate
   AND NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolreplication
   AND NOT r.rolbypassrls AND pg_catalog.pg_database_size(d.oid)<67108864)=1
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database WHERE datname='$restore_db')
 THEN 'FRESH_SOURCE_AND_ABSENT_TARGET' ELSE 'REJECTED' END;
SQL
) || fail
[ "$admission" = FRESH_SOURCE_AND_ABSENT_TARGET ] || fail
baseline=$(psql_db "$source_db" < "$recovery/closed.sql") || fail
[ "$baseline" = CLOSED_BASELINE_OK ] || fail
stage=SOURCE_INVENTORY
inventory_db "$source_db" "$recovery/source-before" || fail
stage=DUMP
dump_db "$source_db" "$recovery/source.dump" || fail
dump_bytes=$(wc -c < "$recovery/source.dump" | tr -d ' ')
number "$dump_bytes" && [ "$dump_bytes" -gt 0 ] && [ "$dump_bytes" -le 67108864 ] || fail
stage=CREATE_NEW_RESTORE_DATABASE
psql_db postgres > /dev/null <<SQL || fail
CREATE DATABASE "$restore_db" OWNER "$app_user" TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C';
SQL
# Preserve the new template's empty public schema. Full PG17 pg_dump deliberately
# omits CREATE SCHEMA for the default public namespace; the new database owner
# is its implicit owner through pg_database_owner and can restore its objects.
stage=RESTORE
env -i PATH="$PATH" LC_ALL=C PGCONNECT_TIMEOUT=3 PGOPTIONS='-c statement_timeout=20000 -c lock_timeout=2000 -c timezone=UTC' \
  timeout 45 /usr/local/bin/pg_restore --no-password -h "$socket" -p 5432 -U postgres -d "$restore_db" \
  --role="$app_user" --no-owner --no-privileges --exit-on-error --single-transaction "$recovery/source.dump" >/dev/null 2>&1 || fail
stage=RESTORED_INVENTORY
baseline=$(psql_db "$restore_db" < "$recovery/closed.sql") || fail
[ "$baseline" = CLOSED_BASELINE_OK ] || fail
inventory_db "$restore_db" "$recovery/restored" || fail
for part in tables table-manifest sequences sequence-manifest schema.sql; do
  cmp -s "$recovery/source-before/$part" "$recovery/restored/$part" || fail
done
stage=SOURCE_UNCHANGED
baseline=$(psql_db "$source_db" < "$recovery/closed.sql") || fail
[ "$baseline" = CLOSED_BASELINE_OK ] || fail
inventory_db "$source_db" "$recovery/source-after" || fail
for part in tables table-manifest sequences sequence-manifest schema.sql; do
  cmp -s "$recovery/source-before/$part" "$recovery/source-after/$part" || fail
done
tables=$(wc -l < "$recovery/source-before/tables" | tr -d ' ')
sequences=$(wc -l < "$recovery/source-before/sequences" | tr -d ' ')
rows=$(awk -F '\t' '{ sum += $2 } END { printf "%.0f", sum }' "$recovery/source-before/table-manifest")
elapsed=$(( $(date +%s) - start_time ))
for value in "$tables" "$sequences" "$rows" "$elapsed"; do number "$value" || fail; done
stage=COMPLETE
printf '{"classification":"FRESH_POSTGRES_LOGICAL_RESTORE","outcome":"PASS","newDatabaseRestored":true,"publicTables":%s,"publicRows":%s,"publicSequences":%s,"canonicalRowsMatch":true,"publicSchemaMatch":true,"sequenceValuesMatch":true,"sourceUnchanged":true,"sourceAndRestoreClosed":true,"scopedConversations":1,"seedStatements":15,"rawVotes":16,"latestVotes":16,"whitelistRows":0,"terminalIdentities":2,"dumpBytes":%s,"elapsedSeconds":%s,"ownershipAndAclCompared":false,"applicationRestartTested":false,"productionRecoveryProven":false,"databasesPreserved":true}\n' \
  "$tables" "$rows" "$sequences" "$dump_bytes" "$elapsed"
