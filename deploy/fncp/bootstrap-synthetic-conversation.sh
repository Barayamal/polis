#!/bin/sh
set -eu

# One-shot local bootstrap for the disposable FNCP stack. It uses only the
# documented OIDC simulator administrator, creates exactly one synthetic
# conversation and seed statement, enables its XID gate, and atomically binds
# both dedicated services to that created conversation. It never contacts a
# public service, emits an identifier/credential, restarts a service or deploys.

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
deploy_dir="$repo_root/deploy/fncp"
env_file="$deploy_dir/.env.staging"
compose_file="$deploy_dir/docker-compose.staging.yml"
compose_override="$deploy_dir/docker-compose.colima.yml"
ca_file="$deploy_dir/certs/rootCA.pem"
keys_dir="$repo_root/server/keys"
colima_marker="$deploy_dir/.colima-staging"
restart_marker="$deploy_dir/.synthetic-bootstrap-restart"
api_origin="http://127.0.0.1:5501"
dedicated_api_origin="http://127.0.0.1:5500"
oidc_origin="https://oidc-simulator:3000"

if [ ! -s "$env_file" ] || [ ! -s "$ca_file" ]; then
  echo "Prepare the disposable staging environment first." >&2
  exit 1
fi
if [ -e "$restart_marker" ]; then
  echo "A protected synthetic bootstrap transition is already pending." >&2
  exit 1
fi

# shellcheck disable=SC1090
. "$env_file"

if ! printf '%s\n' "$FNCP_GATEWAY_CONVERSATION_ID" |
  grep -Eq '^9fncpBootstrap[0-9a-f]{48}$'
then
  echo "Synthetic bootstrap binding is not in its initial state." >&2
  exit 1
fi
valid_credential() {
  value=$1
  [ "${#value}" -ge 32 ] &&
    [ "${#value}" -le 512 ] &&
    ! printf '%s\n' "$value" | grep -Eq '[^A-Za-z0-9_-]'
}
if [ "$FNCP_GATEWAY_CONVERSATION_ID" != \
  "$FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID" ] ||
  [ "$FNCP_SYNTHETIC_BOOTSTRAP_COMPLETE" != "false" ] ||
  [ "$FNCP_GATEWAY_ENFORCEMENT" != "true" ] ||
  [ "$FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT" != "true" ] ||
  ! valid_credential "$FNCP_GATEWAY_SHARED_SECRET" ||
  ! valid_credential "$FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL" ||
  [ "$FNCP_GATEWAY_SHARED_SECRET" = \
    "$FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL" ]
then
  echo "Synthetic bootstrap boundary is invalid." >&2
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

server_before=$(compose ps -q server)
alpha_before=$(compose ps -q client-participation-alpha)
if [ -z "$server_before" ] || [ -z "$alpha_before" ]; then
  echo "Start the dedicated disposable stack before bootstrapping." >&2
  exit 1
fi

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/fncp-polis-bootstrap.XXXXXX")
marker_temp=
cleanup() {
  bootstrap_compose rm -sf server-bootstrap >/dev/null 2>&1 || true
  if [ -n "$marker_temp" ]; then
    rm -f "$marker_temp"
  fi
  rm -rf "$work_dir"
}
trap cleanup EXIT INT TERM

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
  echo "A local synthetic API did not become ready in time." >&2
  return 1
}

expect_status() {
  actual=$1
  expected=$2
  label=$3
  if [ "$actual" != "$expected" ]; then
    echo "$label failed." >&2
    exit 1
  fi
}

# First prove the guarded dedicated process is alive on the absent binding.
wait_for_origin "$dedicated_api_origin"

# The profile service is an ordinary, loopback-only Pol.is API with both FNCP
# policies explicitly disabled. It exists only for this OIDC fixture action.
bootstrap_compose build server-bootstrap >/dev/null
if [ "$use_colima" = "true" ]; then
  # A clone below macOS /tmp cannot bind-mount these ignored files into Colima.
  # Create the stopped container with the reviewed override, copy only the
  # disposable CA/signing keys, then start it.
  bootstrap_compose up --no-start --no-deps --force-recreate \
    server-bootstrap \
    >/dev/null
  bootstrap_container=$(bootstrap_compose ps -aq server-bootstrap)
  if [ -z "$bootstrap_container" ]; then
    echo "The local synthetic bootstrap container was not created." >&2
    exit 1
  fi
  docker cp -a "$ca_file" "$bootstrap_container:/tmp/fncp-rootCA.pem"
  docker cp -a "$keys_dir" "$bootstrap_container:/app/keys"
  bootstrap_compose start server-bootstrap >/dev/null
else
  bootstrap_compose up -d --no-deps --force-recreate server-bootstrap \
    >/dev/null
fi
wait_for_origin "$api_origin"

token_status=$(request "$work_dir/token.json" \
  --cacert "$ca_file" \
  --resolve "oidc-simulator:3000:127.0.0.1" \
  --header "Content-Type: application/json" \
  --data "$(jq -nc \
    --arg audience "$AUTH_AUDIENCE" \
    --arg client_id "$AUTH_CLIENT_ID" \
    '{
      grant_type: "password",
      username: "admin@polis.test",
      password: "Te$tP@ssw0rd*",
      audience: $audience,
      client_id: $client_id,
      scope: "openid profile email"
    }')" \
  "$oidc_origin/oauth/token")
expect_status "$token_status" "200" "OIDC fixture login"
admin_token=$(jq -er '.access_token' "$work_dir/token.json")

# Install the trace-blocking marker before the first mutating request. If the
# host stops or a successful response is lost, the helper cannot be replayed
# into a second synthetic conversation: activation rejects the incomplete
# environment and the disposable stack must be inspected or purged.
marker_temp=$(mktemp "$deploy_dir/.synthetic-bootstrap-restart.XXXXXX")
chmod 600 "$marker_temp"
printf 'server=%s\nalpha=%s\n' "$server_before" "$alpha_before" \
  >"$marker_temp"
mv "$marker_temp" "$restart_marker"
marker_temp=

conversation_status=$(request "$work_dir/conversation.json" \
  --header "Authorization: Bearer $admin_token" \
  --header "X-Forwarded-Proto: https" \
  --header "Content-Type: application/json" \
  --data '{
    "topic": "FNCP Option C disposable access QA",
    "description": "Synthetic local staging only. No genuine participant data.",
    "is_active": true,
    "is_anon": true,
    "is_draft": false,
    "strict_moderation": true,
    "profanity_filter": false
  }' \
  "$api_origin/api/v3/conversations")
expect_status "$conversation_status" "200" "Synthetic conversation creation"
conversation_id=$(jq -er '.conversation_id' "$work_dir/conversation.json")

comment_status=$(request "$work_dir/comment.json" \
  --header "Authorization: Bearer $admin_token" \
  --header "X-Forwarded-Proto: https" \
  --header "Content-Type: application/json" \
  --data "$(jq -nc \
    --arg conversation_id "$conversation_id" \
    '{
      conversation_id: $conversation_id,
      txt: "Community-controlled decisions should include transparent follow-through.",
      is_seed: true
    }')" \
  "$api_origin/api/v3/comments")
expect_status "$comment_status" "200" "Synthetic seed creation"

gate_status=$(request "$work_dir/gate.json" \
  --request PUT \
  --header "Authorization: Bearer $admin_token" \
  --header "X-Forwarded-Proto: https" \
  --header "Content-Type: application/json" \
  --data "$(jq -nc \
    --arg conversation_id "$conversation_id" \
    '{
      conversation_id: $conversation_id,
      use_xid_whitelist: true
    }')" \
  "$api_origin/api/v3/conversations")
expect_status "$gate_status" "200" "Synthetic XID gate activation"

node "$deploy_dir/rewrite-synthetic-bootstrap-binding.mjs" \
  "$env_file" "$work_dir/conversation.json"

echo "Synthetic conversation prepared without exposing its identifier."
echo "Do not run the trace yet."
echo "Run deploy/fncp/activate-synthetic-binding.sh before the trace."
