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
participant_origin="http://127.0.0.1:8088"
oidc_origin="https://oidc-simulator:3000"

if [ ! -f "$env_file" ] || [ ! -s "$ca_file" ]; then
  echo "Prepare the disposable staging environment first." >&2
  exit 1
fi

# shellcheck disable=SC1090
. "$env_file"

restart_marker="deploy/fncp/.synthetic-bootstrap-restart"
if [ "$FNCP_SYNTHETIC_BOOTSTRAP_COMPLETE" != "true" ] ||
  [ "$FNCP_GATEWAY_ENFORCEMENT" != "true" ] ||
  [ "$FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT" != "true" ] ||
  [ "$FNCP_GATEWAY_CONVERSATION_ID" != \
    "$FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID" ] ||
  [ -e "$restart_marker" ]
then
  echo "Bootstrap and activate the synthetic binding before the trace." >&2
  exit 1
fi

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

conversation_id="$FNCP_GATEWAY_CONVERSATION_ID"
allowed_xid="fncp_$(openssl rand -hex 24)"
replacement_xid="fncp_$(openssl rand -hex 24)"
allow_key="allow-$(openssl rand -hex 32)"
remove_key="remove-$(openssl rand -hex 32)"

allowlist_status="$(request "$work_dir/allowlist.json" \
  --header "Authorization: Bearer $FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL" \
  --header "Content-Type: application/json" \
  --header "Idempotency-Key: $allow_key" \
  --data "$(jq -nc \
    --arg conversation_id "$conversation_id" \
    --arg participant_xid "$allowed_xid" \
    '{
      conversationId: $conversation_id,
      participantXid: $participant_xid,
      operationVersion: 1
    }')" \
  "$api_origin/fncp/private/xid-allowlist/upsert")"
expect_status "$allowlist_status" "204" "Provider XID upsert"

readback_status="$(request "$work_dir/readback.json" \
  --header "Authorization: Bearer $FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL" \
  --header "Content-Type: application/json" \
  --data "$(jq -nc \
    --arg conversation_id "$conversation_id" \
    --arg participant_xid "$allowed_xid" \
    '{
      conversationId: $conversation_id,
      participantXid: $participant_xid
    }')" \
  "$api_origin/fncp/private/xid-allowlist/readback")"
expect_status "$readback_status" "200" "Provider XID readback"
jq -e \
  --arg conversation_id "$conversation_id" \
  --arg participant_xid "$allowed_xid" \
  '.conversationId == $conversation_id and
   .participantXid == $participant_xid and
   .operationVersion == 1 and
   .present == true' \
  "$work_dir/readback.json" >/dev/null

allowed_status="$(request "$work_dir/allowed.json" \
  --get \
  --header "X-Forwarded-Proto: https" \
  --header "X-FNCP-Gateway-Key: $FNCP_GATEWAY_SHARED_SECRET" \
  --header "X-FNCP-Conversation-ID: $conversation_id" \
  --header "X-FNCP-Participant-XID: $allowed_xid" \
  --data-urlencode "conversation_id=$conversation_id" \
  --data-urlencode "xid=$allowed_xid" \
  --data-urlencode "pid=-1" \
  --data-urlencode "lang=en" \
  --data-urlencode "agid=1" \
  "$api_origin/api/v3/participationInit")"
expect_status "$allowed_status" "200" "Allowed XID"
seed_tid="$(jq -er '.nextComment.tid' "$work_dir/allowed.json")"

participant_status="$(request "$work_dir/participant.html" \
  --get \
  --data-urlencode "xid=$allowed_xid" \
  "$participant_origin/alpha/$conversation_id")"
expect_status "$participant_status" "200" "Allowlisted participant SSR"
for expected_text in \
  "FNCP Option C disposable access QA" \
  "Community-controlled decisions should include transparent follow-through." \
  "Agree" \
  "Disagree" \
  "Pass / Unsure"
do
  if ! grep -Fq "$expected_text" "$work_dir/participant.html"; then
    echo "Allowlisted participant SSR omitted: $expected_text" >&2
    exit 1
  fi
done

missing_participant_status="$(request "$work_dir/participant-missing.html" \
  "$participant_origin/alpha/$conversation_id")"
expect_status "$missing_participant_status" "200" "Missing-XID participant SSR"
if ! grep -Fq \
  "This conversation requires an XID (external identifier) to participate." \
  "$work_dir/participant-missing.html"
then
  echo "Missing-XID participant SSR did not fail closed clearly." >&2
  exit 1
fi

vote_status="$(request "$work_dir/vote.json" \
  --header "X-Forwarded-Proto: https" \
  --header "X-FNCP-Gateway-Key: $FNCP_GATEWAY_SHARED_SECRET" \
  --header "X-FNCP-Conversation-ID: $conversation_id" \
  --header "X-FNCP-Participant-XID: $allowed_xid" \
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
  --header "X-FNCP-Gateway-Key: $FNCP_GATEWAY_SHARED_SECRET" \
  --header "X-FNCP-Conversation-ID: $conversation_id" \
  --header "X-FNCP-Participant-XID: $allowed_xid" \
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
  --header "X-FNCP-Gateway-Key: $FNCP_GATEWAY_SHARED_SECRET" \
  --header "X-FNCP-Conversation-ID: $conversation_id" \
  --header "X-FNCP-Participant-XID: $replacement_xid" \
  --data-urlencode "conversation_id=$conversation_id" \
  --data-urlencode "xid=$replacement_xid" \
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
  --header "Authorization: Bearer $FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL" \
  --header "Content-Type: application/json" \
  --header "Idempotency-Key: $remove_key" \
  --data "$(jq -nc \
    --arg conversation_id "$conversation_id" \
    --arg participant_xid "$allowed_xid" \
    '{
      conversationId: $conversation_id,
      participantXid: $participant_xid,
      operationVersion: 2
    }')" \
  "$api_origin/fncp/private/xid-allowlist/remove")"
expect_status "$revoke_status" "204" "Provider XID removal"

removed_readback_status="$(request "$work_dir/removed-readback.json" \
  --header "Authorization: Bearer $FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL" \
  --header "Content-Type: application/json" \
  --data "$(jq -nc \
    --arg conversation_id "$conversation_id" \
    --arg participant_xid "$allowed_xid" \
    '{
      conversationId: $conversation_id,
      participantXid: $participant_xid
    }')" \
  "$api_origin/fncp/private/xid-allowlist/readback")"
expect_status "$removed_readback_status" "200" "Removed XID readback"
jq -e \
  --arg conversation_id "$conversation_id" \
  --arg participant_xid "$allowed_xid" \
  '.conversationId == $conversation_id and
   .participantXid == $participant_xid and
   .operationVersion == 2 and
   .present == false' \
  "$work_dir/removed-readback.json" >/dev/null

revoked_status="$(request "$work_dir/revoked.json" \
  --get \
  --header "X-Forwarded-Proto: https" \
  --header "X-FNCP-Gateway-Key: $FNCP_GATEWAY_SHARED_SECRET" \
  --header "X-FNCP-Conversation-ID: $conversation_id" \
  --header "X-FNCP-Participant-XID: $allowed_xid" \
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
  --header "X-FNCP-Gateway-Key: $FNCP_GATEWAY_SHARED_SECRET" \
  --header "X-FNCP-Conversation-ID: $conversation_id" \
  --header "X-FNCP-Participant-XID: $allowed_xid" \
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
  "Allowlisted participant SSR: 200 with conversation and controls" \
  "Missing-XID participant SSR: 200 with fail-closed notice" \
  "Allowed XID: 200" \
  "Missing XID: 403" \
  "Invalid XID: 403" \
  "OIDC bypass: 403" \
  "Removed XID: 403" \
  "Removed warm XID session: 403"
