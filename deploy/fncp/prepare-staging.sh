#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
deploy_dir="$repo_root/deploy/fncp"
env_file="$deploy_dir/.env.staging"
cert_dir="$deploy_dir/certs"
keys_dir="$repo_root/server/keys"

if [ -e "$env_file" ]; then
  echo "Refusing to replace existing $env_file" >&2
  exit 1
fi

mkdir -p "$cert_dir" "$keys_dir"

postgres_password=$(openssl rand -hex 24)
auth_secret=$(openssl rand -hex 32)
login_pepper=$(openssl rand -hex 32)
encryption_password=$(openssl rand -hex 32)
math_password=$(openssl rand -hex 24)
server_runtime_uid=$(id -u)
server_runtime_gid=$(id -g)

sed \
  -e "s/SERVER_RUNTIME_UID=REPLACE_WITH_LOCAL_UID/SERVER_RUNTIME_UID=$server_runtime_uid/" \
  -e "s/SERVER_RUNTIME_GID=REPLACE_WITH_LOCAL_GID/SERVER_RUNTIME_GID=$server_runtime_gid/" \
  -e "s/POSTGRES_PASSWORD=REPLACE_WITH_RANDOM_VALUE/POSTGRES_PASSWORD=$postgres_password/" \
  -e "s#DATABASE_URL=postgres://fncp_polis:REPLACE_WITH_RANDOM_VALUE@postgres:5432/fncp_polis_staging#DATABASE_URL=postgres://fncp_polis:$postgres_password@postgres:5432/fncp_polis_staging#" \
  -e "s/AUTH_CLIENT_SECRET=REPLACE_WITH_RANDOM_VALUE/AUTH_CLIENT_SECRET=$auth_secret/" \
  -e "s/LOGIN_CODE_PEPPER=REPLACE_WITH_RANDOM_VALUE/LOGIN_CODE_PEPPER=$login_pepper/" \
  -e "s/ENCRYPTION_PASSWORD_00001=REPLACE_WITH_RANDOM_VALUE/ENCRYPTION_PASSWORD_00001=$encryption_password/" \
  -e "s/WEBSERVER_PASS=REPLACE_WITH_RANDOM_VALUE/WEBSERVER_PASS=$math_password/" \
  "$deploy_dir/staging.env.example" >"$env_file"
chmod 600 "$env_file"

openssl genrsa -out "$cert_dir/rootCA-key.pem" 3072 >/dev/null 2>&1
openssl req -x509 -new -nodes -key "$cert_dir/rootCA-key.pem" \
  -sha256 -days 7 -subj "/CN=FNCP disposable staging CA" \
  -out "$cert_dir/rootCA.pem" >/dev/null 2>&1
openssl genrsa -out "$cert_dir/localhost-key.pem" 2048 >/dev/null 2>&1
openssl req -new -key "$cert_dir/localhost-key.pem" \
  -subj "/CN=localhost" -out "$cert_dir/localhost.csr" >/dev/null 2>&1
printf '%s\n' \
  "authorityKeyIdentifier=keyid,issuer" \
  "basicConstraints=CA:FALSE" \
  "keyUsage=digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment" \
  "subjectAltName=@alt_names" \
  "[alt_names]" \
  "DNS.1=localhost" \
  "DNS.2=oidc-simulator" \
  >"$cert_dir/localhost.ext"
openssl x509 -req -in "$cert_dir/localhost.csr" \
  -CA "$cert_dir/rootCA.pem" -CAkey "$cert_dir/rootCA-key.pem" \
  -CAcreateserial -out "$cert_dir/localhost.pem" \
  -days 7 -sha256 -extfile "$cert_dir/localhost.ext" >/dev/null 2>&1
chmod 600 "$cert_dir"/*-key.pem

if [ ! -s "$keys_dir/jwt-private.pem" ] || [ ! -s "$keys_dir/jwt-public.pem" ]; then
  openssl genrsa -out "$keys_dir/jwt-private.pem" 3072 >/dev/null 2>&1
  openssl rsa -in "$keys_dir/jwt-private.pem" -pubout \
    -out "$keys_dir/jwt-public.pem" >/dev/null 2>&1
  chmod 600 "$keys_dir/jwt-private.pem"
fi
chmod 644 "$keys_dir/jwt-public.pem" "$cert_dir/rootCA.pem"

echo "Prepared disposable staging configuration."
echo "Secrets and certificates are git-ignored and expire after seven days."
