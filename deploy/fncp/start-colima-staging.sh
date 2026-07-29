#!/bin/sh
set -eu

root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$root_dir"

base="deploy/fncp/docker-compose.staging.yml"
override="deploy/fncp/docker-compose.colima.yml"
env_file="deploy/fncp/.env.staging"
cert_dir="deploy/fncp/certs"
keys_dir="server/keys"
colima_marker="deploy/fncp/.colima-staging"

if [ ! -f "$env_file" ]; then
  echo "Missing $env_file. Run deploy/fncp/prepare-staging.sh first." >&2
  exit 1
fi

for certificate in localhost.pem localhost-key.pem rootCA.pem; do
  if [ ! -s "$cert_dir/$certificate" ]; then
    echo "Missing disposable certificate: $cert_dir/$certificate" >&2
    exit 1
  fi
done

for signing_key in jwt-private.pem jwt-public.pem; do
  if [ ! -s "$keys_dir/$signing_key" ]; then
    echo "Missing disposable signing key: $keys_dir/$signing_key" >&2
    exit 1
  fi
done

compose() {
  docker compose \
    --env-file "$env_file" \
    -f "$base" \
    -f "$override" \
    "$@"
}

compose down --remove-orphans
compose create

oidc_container="$(compose ps -aq oidc-simulator)"
server_container="$(compose ps -aq server)"

if [ -z "$oidc_container" ] || [ -z "$server_container" ]; then
  echo "Disposable staging containers were not created." >&2
  exit 1
fi

docker cp "$cert_dir/." "$oidc_container:/root/.simulacrum/certs/"
docker cp -a "$cert_dir/rootCA.pem" "$server_container:/tmp/fncp-rootCA.pem"
docker cp -a "$keys_dir" "$server_container:/app/keys"

compose start
marker_temp="$(mktemp "$colima_marker.XXXXXX")"
trap 'rm -f "$marker_temp"' EXIT INT TERM
chmod 600 "$marker_temp"
printf '%s\n' "compose-override=docker-compose.colima.yml" >"$marker_temp"
mv "$marker_temp" "$colima_marker"
trap - EXIT INT TERM
compose ps
