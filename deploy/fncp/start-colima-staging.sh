#!/bin/sh
set -eu

root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$root_dir"

base="deploy/fncp/docker-compose.staging.yml"
override="deploy/fncp/docker-compose.colima.yml"
env_file="deploy/fncp/.env.staging"
cert_dir="deploy/fncp/certs"

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
docker cp "$cert_dir/rootCA.pem" "$server_container:/tmp/fncp-rootCA.pem"

compose start
compose ps
