#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
deploy_dir="$repo_root/deploy/fncp"
env_file="$deploy_dir/.env.staging"
compose_file="$deploy_dir/docker-compose.staging.yml"
expected_upstream="424dcae02f0147723a19103dd2d971f6ec1b6db5"
expected_source_revision=$(git -C "$repo_root" rev-parse HEAD)

test -s "$env_file" || {
  echo "Missing $env_file; run prepare-staging.sh first." >&2
  exit 1
}

grep -q "^GIT_HASH=$expected_upstream$" "$env_file"
grep -q "^FNCP_SOURCE_REVISION=$expected_source_revision$" "$env_file"
grep -q "^ENABLE_TELEMETRY=false$" "$env_file"
grep -q "^SHOULD_USE_TRANSLATION_API=false$" "$env_file"
grep -q "^GA_TRACKING_ID=$" "$env_file"
grep -q "^ANTHROPIC_API_KEY=$" "$env_file"
grep -q "^GEMINI_API_KEY=$" "$env_file"
grep -q "^OPENAI_API_KEY=$" "$env_file"
! grep -q "4bumwmv4zf" "$env_file"
! grep -Eq '(^|[[:space:]-])"[0-9]+:[0-9]+"' "$compose_file"
grep -q '"127.0.0.1:8088:8080"' "$compose_file"
grep -q '"127.0.0.1:5500:5000"' "$compose_file"
grep -q '"127.0.0.1:3000:3000"' "$compose_file"
node --test "$deploy_dir/deployment-boundary.test.mjs"
node --test "$deploy_dir/migration-image.test.mjs"
grep -q "Modified by Barayamal on 26 July 2026" \
  "$repo_root/server/src/auth/ensure-participant.ts"
grep -q "Modified by Barayamal on 26 July 2026" \
  "$repo_root/server/src/auth/jwt-utils.ts"
grep -q "https://github.com/Barayamal/polis" \
  "$repo_root/FNCP_SOURCE_AND_DEPLOYMENT.md"

docker compose \
  --env-file "$env_file" \
  -f "$compose_file" \
  config --quiet

echo "FNCP disposable staging configuration: PASS"
