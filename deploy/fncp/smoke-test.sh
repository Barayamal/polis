#!/bin/sh
set -eu

# Disposable API-level QA for the loopback-only FNCP staging stack. The script
# uses only the OIDC simulator's documented fixture account and generated XIDs.
# It never imports or emits genuine registration, eligibility or vote data.

root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$root_dir"

env_file="deploy/fncp/.env.staging"
ca_file="deploy/fncp/certs/rootCA.pem"
api_origin="http://127.0.0.1:5500"
oidc_origin="https://oidc-simulator:3000"

if [ ! -f "$env_file" ] || [ ! -s "$ca_file" ]; then
  echo "Prepare the disposable staging environment first." >&2
  exit 1
fi

# shellcheck disable=SC1090
. "$env_file"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/fncp-polis-smoke.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT INT TERM

request() {
  output="$1"
  shift
  curl --silent --show-error --output "$output" \
    --connect-timeout 3 --max-time 15 --write-out "%{http_code}" "$@"
}

wait_for_server() {
  attempts=0
  while [ "$attempts" -lt 45 ]; do
    if status="$(curl --silent --output /dev/null \
      --connect-timeout 1 --max-time 2 --write-out "%{http_code}" \
      "$api_origin/api/v3/conversations")"; then
      case "$status" in
        [1-5][0-9][0-9])
          return 0
          ;;
      esac
    fi
    attempts=$((attempts + 1))
    sleep 1
  done

  echo "Pol.is server did not become ready within 45 seconds." >&2
  return 1
}

expect_status() {
  actual="$1"
  expected="$2"
  label="$3"
  if [ "$actual" != "$expected" ]; then
    echo "$label: expected HTTP $expected, received $actual" >&2
    exit 1
  fi
}

wait_for_server

token_status="$(request "$work_dir/token.json" \
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
  "$oidc_origin/oauth/token")"
expect_status "$token_status" "200" "OIDC fixture login"
admin_token="$(jq -er '.access_token' "$work_dir/token.json")"

conversation_status="$(request "$work_dir/conversation.json" \
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
  "$api_origin/api/v3/conversations")"
expect_status "$conversation_status" "200" "Create disposable conversation"
conversation_id="$(jq -er '.conversation_id' "$work_dir/conversation.json")"

comment_status="$(request "$work_dir/comment.json" \
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
  "$api_origin/api/v3/comments")"
expect_status "$comment_status" "200" "Create synthetic seed statement"

allowed_xid="fncp_$(openssl rand -hex 24)"
replacement_xid="fncp_$(openssl rand -hex 24)"
allowlist_status="$(request "$work_dir/allowlist.json" \
  --header "Authorization: Bearer $admin_token" \
  --header "X-Forwarded-Proto: https" \
  --header "Content-Type: application/json" \
  --data "$(jq -nc \
    --arg conversation_id "$conversation_id" \
    --arg allowed_xid "$allowed_xid" \
    --arg replacement_xid "$replacement_xid" \
    '{
      conversation_id: $conversation_id,
      xid_allow_list: [$allowed_xid, $replacement_xid],
      replace_all: true
    }')" \
  "$api_origin/api/v3/xidAllowList")"
expect_status "$allowlist_status" "200" "Create synthetic XID allowlist"

gate_status="$(request "$work_dir/gate.json" \
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
  "$api_origin/api/v3/conversations")"
expect_status "$gate_status" "200" "Enable synthetic XID gate"

allowed_status="$(request "$work_dir/allowed.json" \
  --get \
  --header "X-Forwarded-Proto: https" \
  --data-urlencode "conversation_id=$conversation_id" \
  --data-urlencode "xid=$allowed_xid" \
  --data-urlencode "pid=-1" \
  --data-urlencode "lang=en" \
  --data-urlencode "agid=1" \
  "$api_origin/api/v3/participationInit")"
expect_status "$allowed_status" "200" "Allowed XID"
seed_tid="$(jq -er '.nextComment.tid' "$work_dir/allowed.json")"

vote_status="$(request "$work_dir/vote.json" \
  --header "X-Forwarded-Proto: https" \
  --header "Content-Type: application/json" \
  --data "$(jq -nc \
    --arg conversation_id "$conversation_id" \
    --arg xid "$allowed_xid" \
    --argjson tid "$seed_tid" \
    '{
      conversation_id: $conversation_id,
      xid: $xid,
      tid: $tid,
      vote: 0
    }')" \
  "$api_origin/api/v3/votes")"
expect_status "$vote_status" "200" "Establish synthetic XID participant"

warm_status="$(request "$work_dir/warm.json" \
  --get \
  --header "X-Forwarded-Proto: https" \
  --data-urlencode "conversation_id=$conversation_id" \
  --data-urlencode "xid=$allowed_xid" \
  --data-urlencode "pid=-1" \
  --data-urlencode "lang=en" \
  --data-urlencode "agid=1" \
  "$api_origin/api/v3/participationInit")"
expect_status "$warm_status" "200" "Reopen synthetic XID participant"
participant_token="$(jq -r '.auth.token // empty' "$work_dir/warm.json")"
if [ -z "$participant_token" ]; then
  participant_token="$(jq -r '.auth.token // empty' "$work_dir/vote.json")"
fi
if [ -z "$participant_token" ]; then
  echo "Synthetic participant JWT was not issued." >&2
  exit 1
fi

missing_status="$(request "$work_dir/missing.json" \
  --get \
  --header "X-Forwarded-Proto: https" \
  --data-urlencode "conversation_id=$conversation_id" \
  --data-urlencode "pid=-1" \
  --data-urlencode "lang=en" \
  "$api_origin/api/v3/participationInit")"
expect_status "$missing_status" "403" "Missing XID"

invalid_status="$(request "$work_dir/invalid.json" \
  --get \
  --header "X-Forwarded-Proto: https" \
  --data-urlencode "conversation_id=$conversation_id" \
  --data-urlencode "xid=fncp_not_allowlisted_0000000000000000" \
  --data-urlencode "pid=-1" \
  --data-urlencode "lang=en" \
  "$api_origin/api/v3/participationInit")"
expect_status "$invalid_status" "403" "Invalid XID"

oidc_bypass_status="$(request "$work_dir/oidc-bypass.json" \
  --get \
  --header "Authorization: Bearer $admin_token" \
  --header "X-Forwarded-Proto: https" \
  --data-urlencode "conversation_id=$conversation_id" \
  --data-urlencode "pid=-1" \
  --data-urlencode "lang=en" \
  "$api_origin/api/v3/participationInit")"
expect_status "$oidc_bypass_status" "403" "OIDC participant bypass"

revoke_status="$(request "$work_dir/revoke.json" \
  --header "Authorization: Bearer $admin_token" \
  --header "X-Forwarded-Proto: https" \
  --header "Content-Type: application/json" \
  --data "$(jq -nc \
    --arg conversation_id "$conversation_id" \
    --arg replacement_xid "$replacement_xid" \
    '{
      conversation_id: $conversation_id,
      xid_allow_list: [$replacement_xid],
      replace_all: true
    }')" \
  "$api_origin/api/v3/xidAllowList")"
expect_status "$revoke_status" "200" "Revoke synthetic XID"

revoked_status="$(request "$work_dir/revoked.json" \
  --get \
  --header "X-Forwarded-Proto: https" \
  --data-urlencode "conversation_id=$conversation_id" \
  --data-urlencode "xid=$allowed_xid" \
  --data-urlencode "pid=-1" \
  --data-urlencode "lang=en" \
  --data-urlencode "agid=1" \
  "$api_origin/api/v3/participationInit")"
expect_status "$revoked_status" "403" "Revoked XID"

warm_revoked_status="$(request "$work_dir/warm-revoked.json" \
  --get \
  --header "Authorization: Bearer $participant_token" \
  --header "X-Forwarded-Proto: https" \
  --data-urlencode "conversation_id=$conversation_id" \
  --data-urlencode "xid=$allowed_xid" \
  --data-urlencode "pid=-1" \
  --data-urlencode "lang=en" \
  --data-urlencode "agid=1" \
  "$api_origin/api/v3/participationInit")"
expect_status "$warm_revoked_status" "403" "Revoked warm XID session"

close_status="$(request "$work_dir/close.json" \
  --request PUT \
  --header "Authorization: Bearer $admin_token" \
  --header "X-Forwarded-Proto: https" \
  --header "Content-Type: application/json" \
  --data "$(jq -nc --arg conversation_id "$conversation_id" \
    '{conversation_id: $conversation_id, is_active: false}')" \
  "$api_origin/api/v3/conversations")"
expect_status "$close_status" "200" "Close disposable conversation"

printf '%s\n' \
  "FNCP Option C disposable smoke test: PASS" \
  "Conversation: synthetic local QA (closed)" \
  "Allowed XID: 200" \
  "Missing XID: 403" \
  "Invalid XID: 403" \
  "OIDC bypass: 403" \
  "Removed XID: 403" \
  "Removed warm XID session: 403"
