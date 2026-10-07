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

# Reject an absent/malformed manifest before any mutating QA request.
statement_ids_json="$(jq -enc --arg ids "${FNCP_FIXED_STATEMENT_IDS:-}" '
  ($ids | split(",")) as $parts |
  if ($parts | length) == 15 and
     ($parts | all(test("^(0|[1-9][0-9]*)$")))
  then ($parts | map(tonumber)) as $numbers |
    if ($numbers | unique | length) == 15 and
       ($numbers | all(. <= 9007199254740991))
    then $numbers else error("invalid manifest") end
  else error("invalid manifest") end' 2>/dev/null)" || {
  echo "Exactly fifteen synthetic statement IDs must be bound before the trace." >&2
  exit 1
}

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/fncp-polis-smoke.XXXXXX")"

cleanup() {
  # Revoke only this invocation's generated synthetic XID on an early failure.
  # Never broaden cleanup to existing provider records or genuine data.
  if [ -n "${allowed_xid:-}" ] && [ "${provider_removed:-false}" != "true" ]; then
    cleanup_status="$(request "$work_dir/cleanup-revoke.json" \
      --header "Authorization: Bearer $FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL" \
      --header "X-Forwarded-Proto: https" \
      --header "Content-Type: application/json" \
      --header "Idempotency-Key: $remove_key" \
      --data "$(jq -nc --arg conversation_id "$conversation_id" --arg participant_xid "$allowed_xid" \
        '{conversationId: $conversation_id, participantXid: $participant_xid, operationVersion: 2}')" \
      "$api_origin/fncp/private/xid-allowlist/remove")" || cleanup_status="000"
    if [ "$cleanup_status" != "204" ]; then
      echo "Synthetic XID cleanup was not verified; keep this disposable stack isolated." >&2
    fi
  fi
  rm -rf "$work_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

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
  --header "X-Forwarded-Proto: https" \
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
  --header "X-Forwarded-Proto: https" \
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
  --data-urlencode "lang=en" \
  "$api_origin/api/v3/participationInit")"
expect_status "$allowed_status" "200" "Allowed XID"
jq -e 'has("auth") | not' "$work_dir/allowed.json" >/dev/null

statements_status="$(request "$work_dir/statements.json" \
  --get \
  --header "X-Forwarded-Proto: https" \
  --header "X-FNCP-Gateway-Key: $FNCP_GATEWAY_SHARED_SECRET" \
  --header "X-FNCP-Conversation-ID: $conversation_id" \
  --header "X-FNCP-Participant-XID: $allowed_xid" \
  --data-urlencode "conversation_id=$conversation_id" \
  "$api_origin/api/v3/comments")"
expect_status "$statements_status" "200" "Fifteen fixed synthetic statements"
jq -e --argjson expected "$statement_ids_json" \
  'type == "array" and length == 15 and
   ([.[].tid] | sort) == ($expected | sort)' \
  "$work_dir/statements.json" >/dev/null
seed_tid="$(printf '%s' "$statement_ids_json" | jq -er '.[0]')"
# Fifteen IDs cannot occupy all sixteen values; no assumption about their IDs.
unknown_tid="$(printf '%s' "$statement_ids_json" | jq -er '([range(0;16)] - .)[0]')"

participant_status="$(request "$work_dir/participant.html" \
  --get \
  --data-urlencode "xid=$allowed_xid" \
  "$participant_origin/alpha/$conversation_id")"
expect_status "$participant_status" "400" "Direct participant SSR with bare XID"
if ! grep -Fq "Conflicting participant identity." "$work_dir/participant.html"; then
  echo "Direct participant SSR did not preserve the gateway boundary." >&2
  exit 1
fi

missing_participant_status="$(request "$work_dir/participant-missing.html" \
  "$participant_origin/alpha/$conversation_id")"
expect_status "$missing_participant_status" "403" "Direct participant SSR without XID"
if ! grep -Fq \
  "Gateway access required." \
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
    --argjson tid "$seed_tid" \
    '{
      conversation_id: $conversation_id,
      tid: $tid,
      vote: 0
    }')" \
  "$api_origin/api/v3/votes")"
expect_status "$vote_status" "200" "Establish synthetic XID participant"
jq -e 'has("auth") | not' "$work_dir/vote.json" >/dev/null

unknown_vote_status="$(request "$work_dir/unknown-vote.json" \
  --header "X-Forwarded-Proto: https" \
  --header "X-FNCP-Gateway-Key: $FNCP_GATEWAY_SHARED_SECRET" \
  --header "X-FNCP-Conversation-ID: $conversation_id" \
  --header "X-FNCP-Participant-XID: $allowed_xid" \
  --header "Content-Type: application/json" \
  --data "$(jq -nc --argjson tid "$unknown_tid" '{tid: $tid, vote: -1}')" \
  "$api_origin/api/v3/votes")"
expect_status "$unknown_vote_status" "400" "Unknown statement ID"
jq -e '.error == "Invalid fixed-statement vote."' "$work_dir/unknown-vote.json" >/dev/null

invalid_vote_status="$(request "$work_dir/invalid-vote.json" \
  --header "X-Forwarded-Proto: https" \
  --header "X-FNCP-Gateway-Key: $FNCP_GATEWAY_SHARED_SECRET" \
  --header "X-FNCP-Conversation-ID: $conversation_id" \
  --header "X-FNCP-Participant-XID: $allowed_xid" \
  --header "Content-Type: application/json" \
  --data "$(jq -nc --argjson tid "$seed_tid" '{tid: $tid, vote: 2}')" \
  "$api_origin/api/v3/votes")"
expect_status "$invalid_vote_status" "400" "Invalid vote value"
jq -e '.error == "Invalid fixed-statement vote."' "$work_dir/invalid-vote.json" >/dev/null

suggestion_status="$(request "$work_dir/suggestion.json" \
  --header "X-Forwarded-Proto: https" \
  --header "X-FNCP-Gateway-Key: $FNCP_GATEWAY_SHARED_SECRET" \
  --header "X-FNCP-Conversation-ID: $conversation_id" \
  --header "X-FNCP-Participant-XID: $allowed_xid" \
  --header "Content-Type: application/json" \
  --data '{"txt":"Synthetic suggestion must never be stored"}' \
  "$api_origin/api/v3/comments")"
expect_status "$suggestion_status" "404" "Participant suggestions at API origin"
jq -e '.error == "Not found."' "$work_dir/suggestion.json" >/dev/null

proxy_suggestion_status="$(request "$work_dir/proxy-suggestion.html" \
  --header "Content-Type: application/json" \
  --data '{"txt":"Synthetic suggestion must never be stored"}' \
  "$participant_origin/api/v3/comments")"
expect_status "$proxy_suggestion_status" "405" "Participant suggestions at proxy"

direct_vote_status="$(request "$work_dir/direct-vote.json" \
  --header "X-Forwarded-Proto: https" \
  --header "Content-Type: application/json" \
  --data "$(jq -nc --arg conversation_id "$conversation_id" --argjson tid "$seed_tid" \
    '{conversation_id: $conversation_id, tid: $tid, vote: -1}')" \
  "$api_origin/api/v3/votes")"
expect_status "$direct_vote_status" "403" "Direct vote without gateway authority"
jq -e '.error == "Gateway access required."' "$work_dir/direct-vote.json" >/dev/null

warm_status="$(request "$work_dir/warm.json" \
  --get \
  --header "X-Forwarded-Proto: https" \
  --header "X-FNCP-Gateway-Key: $FNCP_GATEWAY_SHARED_SECRET" \
  --header "X-FNCP-Conversation-ID: $conversation_id" \
  --header "X-FNCP-Participant-XID: $allowed_xid" \
  --data-urlencode "conversation_id=$conversation_id" \
  --data-urlencode "lang=en" \
  "$api_origin/api/v3/participationInit")"
expect_status "$warm_status" "200" "Reopen synthetic XID participant"
# Reuse the same established identity after revocation. Internal participant
# JWTs must remain stripped; this is not a genuine browser-session test.
jq -e 'has("auth") | not' "$work_dir/warm.json" >/dev/null

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
  --header "X-Forwarded-Proto: https" \
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
provider_removed="true"

removed_readback_status="$(request "$work_dir/removed-readback.json" \
  --header "Authorization: Bearer $FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL" \
  --header "X-Forwarded-Proto: https" \
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
  --data-urlencode "lang=en" \
  "$api_origin/api/v3/participationInit")"
expect_status "$revoked_status" "403" "Revoked XID"
jq -e '.error == "polis_err_xid_not_allowed"' "$work_dir/revoked.json" >/dev/null

warm_revoked_status="$(request "$work_dir/warm-revoked.json" \
  --header "X-Forwarded-Proto: https" \
  --header "X-FNCP-Gateway-Key: $FNCP_GATEWAY_SHARED_SECRET" \
  --header "X-FNCP-Conversation-ID: $conversation_id" \
  --header "X-FNCP-Participant-XID: $allowed_xid" \
  --header "Content-Type: application/json" \
  --data "$(jq -nc --argjson tid "$seed_tid" '{tid: $tid, vote: -1}')" \
  "$api_origin/api/v3/votes")"
expect_status "$warm_revoked_status" "403" "Revoked established identity write"
jq -e '.error == "polis_err_xid_not_allowed"' "$work_dir/warm-revoked.json" >/dev/null

printf '%s\n' \
  "FNCP Option C disposable smoke test: PASS" \
  "Conversation: shared synthetic local QA; lifecycle unchanged" \
  "Exact fixed synthetic statement count: 15" \
  "Direct participant SSR: bare XID 400; missing authority 403" \
  "Allowed XID: 200" \
  "Unknown statement and invalid vote: 400" \
  "Suggestions: API 404; proxy 405" \
  "Direct vote without gateway: 403" \
  "Participant bearer tokens: not exposed" \
  "Missing XID: 403" \
  "Invalid XID: 403" \
  "OIDC bypass: 403" \
  "Removed XID: 403" \
  "Removed established identity write: 403" \
  "Scope: origin access matrix only; real browser-session assurance not established" \
  "This trace does not test whole-round closure; it revokes only its allocated identity"
