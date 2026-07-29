#!/bin/sh
set -eu

# Applies the already-written synthetic binding to fresh dedicated containers.
# This is a loopback-only force-recreation, not a deployment. The protected
# marker is removed only after the actual provider binding and participant
# fail-closed page have both been read back successfully.

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
deploy_dir="$repo_root/deploy/fncp"
env_file="$deploy_dir/.env.staging"
compose_file="$deploy_dir/docker-compose.staging.yml"
compose_override="$deploy_dir/docker-compose.colima.yml"
ca_file="$deploy_dir/certs/rootCA.pem"
keys_dir="$repo_root/server/keys"
colima_marker="$deploy_dir/.colima-staging"
restart_marker="$deploy_dir/.synthetic-bootstrap-restart"
api_origin="http://127.0.0.1:5500"
participant_origin="http://127.0.0.1:8088"

if [ ! -s "$env_file" ] || [ ! -s "$restart_marker" ]; then
  echo "Complete the one-shot synthetic bootstrap first." >&2
  exit 1
fi

# shellcheck disable=SC1090
. "$env_file"

if [ "$FNCP_SYNTHETIC_BOOTSTRAP_COMPLETE" != "true" ] ||
  [ "$FNCP_GATEWAY_ENFORCEMENT" != "true" ] ||
  [ "$FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT" != "true" ] ||
  [ "$FNCP_GATEWAY_CONVERSATION_ID" != \
    "$FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID" ]
then
  echo "The synthetic binding is incomplete." >&2
  exit 1
fi

use_colima=false
if [ -e "$colima_marker" ]; then
  if [ "$(cat "$colima_marker")" != \
    "compose-override=docker-compose.colima.yml" ]; then
    echo "The disposable Colima marker is invalid." >&2
    exit 1
  fi
  use_colima=true
fi

if [ "$use_colima" = "true" ]; then
  compose() {
    docker compose \
      --env-file "$env_file" \
      -f "$compose_file" \
      -f "$compose_override" \
      "$@"
  }
  bootstrap_compose() {
    docker compose \
      --profile synthetic-bootstrap-only \
      --env-file "$env_file" \
      -f "$compose_file" \
      -f "$compose_override" \
      "$@"
  }
else
  compose() {
    docker compose \
      --env-file "$env_file" \
      -f "$compose_file" \
      "$@"
  }
  bootstrap_compose() {
    docker compose \
      --profile synthetic-bootstrap-only \
      --env-file "$env_file" \
      -f "$compose_file" \
      "$@"
  }
fi

server_before=$(sed -n 's/^server=//p' "$restart_marker")
alpha_before=$(sed -n 's/^alpha=//p' "$restart_marker")
if [ -z "$server_before" ] || [ -z "$alpha_before" ]; then
  echo "The protected restart marker is invalid." >&2
  exit 1
fi

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/fncp-polis-activate.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT INT TERM

request() {
  output=$1
  shift
  curl --silent --show-error --output "$output" \
    --connect-timeout 3 --max-time 15 --write-out "%{http_code}" "$@"
}

wait_for_origin() {
  origin=$1
  attempts=0
  while [ "$attempts" -lt 45 ]; do
    if status=$(curl --silent --output /dev/null \
      --connect-timeout 1 --max-time 2 --write-out "%{http_code}" \
      "$origin/api/v3/conversations"); then
      case "$status" in
        [1-5][0-9][0-9]) return 0 ;;
      esac
    fi
    attempts=$((attempts + 1))
    sleep 1
  done
  echo "A dedicated local service did not become ready in time." >&2
  return 1
}

# Ensure the ordinary bootstrap process cannot survive into trace execution.
bootstrap_compose rm -sf server-bootstrap >/dev/null 2>&1 || true

if [ "$use_colima" = "true" ]; then
  # Recreate the stopped server under the same /tmp compatibility override,
  # then copy only the disposable CA and signing keys before it can start.
  compose create --no-deps --force-recreate server >/dev/null
  server_container=$(compose ps -aq server)
  if [ -z "$server_container" ]; then
    echo "The dedicated local server container was not recreated." >&2
    exit 1
  fi
  docker cp -a "$ca_file" "$server_container:/tmp/fncp-rootCA.pem"
  docker cp -a "$keys_dir" "$server_container:/app/keys"
  compose start server >/dev/null
else
  compose up -d --no-deps --force-recreate server >/dev/null
fi
wait_for_origin "$api_origin"

probe_xid="fncp_probe_$(openssl rand -hex 24)"
readback_status=$(request "$work_dir/readback.json" \
  --header "Authorization: Bearer $FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL" \
  --header "Content-Type: application/json" \
  --data "$(jq -nc \
    --arg conversation_id "$FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID" \
    --arg participant_xid "$probe_xid" \
    '{
      conversationId: $conversation_id,
      participantXid: $participant_xid
    }')" \
  "$api_origin/fncp/private/xid-allowlist/readback")
if [ "$readback_status" != "200" ]; then
  echo "Dedicated provider binding readback failed." >&2
  exit 1
fi
jq -e \
  --arg conversation_id "$FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID" \
  --arg participant_xid "$probe_xid" \
  '.conversationId == $conversation_id and
   .participantXid == $participant_xid and
   .operationVersion == null and
   .present == false' \
  "$work_dir/readback.json" >/dev/null

compose up -d --no-deps --force-recreate client-participation-alpha \
  >/dev/null
compose up -d --no-deps --force-recreate nginx-proxy >/dev/null

attempts=0
while [ "$attempts" -lt 45 ]; do
  participant_status=$(request "$work_dir/participant.html" \
    "$participant_origin/alpha/$FNCP_GATEWAY_CONVERSATION_ID" || true)
  if [ "$participant_status" = "200" ] &&
    grep -Fq \
      "This conversation requires an XID (external identifier) to participate." \
      "$work_dir/participant.html"
  then
    break
  fi
  attempts=$((attempts + 1))
  sleep 1
done
if [ "$attempts" -ge 45 ]; then
  echo "Dedicated participant binding did not become ready in time." >&2
  exit 1
fi

server_after=$(compose ps -q server)
alpha_after=$(compose ps -q client-participation-alpha)
bootstrap_after=$(bootstrap_compose ps -q server-bootstrap)
if [ -z "$server_after" ] || [ -z "$alpha_after" ] ||
  [ "$server_before" = "$server_after" ] ||
  [ "$alpha_before" = "$alpha_after" ] ||
  [ -n "$bootstrap_after" ]
then
  echo "Dedicated container replacement verification failed." >&2
  exit 1
fi

rm -f "$restart_marker"
echo "Synthetic binding activated and verified."
echo "The disposable trace may now run."
