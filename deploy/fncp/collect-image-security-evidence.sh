#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPOSITORY_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.staging.yml"
EXAMPLE_ENV="$SCRIPT_DIR/staging.env.example"
RUNTIME_ENV="$SCRIPT_DIR/.env.staging"
EVIDENCE_TOOL="$SCRIPT_DIR/image-security-evidence.mjs"
LOCK_FILE="$SCRIPT_DIR/image-security.lock.json"
PLATFORM=linux/arm64
PRODUCTION_SERVICES="server math client-participation-alpha nginx-proxy"
QA_INFRASTRUCTURE_SERVICES="postgres oidc-simulator"
SCAN_SCOPE=${FNCP_SCAN_SCOPE:-arm64-candidate-four}
case "$SCAN_SCOPE" in
  arm64-candidate-four)
    SERVICES="$PRODUCTION_SERVICES"
    ;;
  staging-six)
    SERVICES="postgres oidc-simulator server math client-participation-alpha nginx-proxy"
    ;;
  *)
    echo "Unknown scan scope: $SCAN_SCOPE" >&2
    echo "Expected arm64-candidate-four or staging-six." >&2
    exit 2
    ;;
esac
SOURCE_SHORT=$(git -C "$REPOSITORY_ROOT" rev-parse --short=12 HEAD)
PROJECT_NAME=${FNCP_SCAN_PROJECT_NAME:-"fncp-option-c-scan-$SOURCE_SHORT"}
OUTPUT_DIR=${1:-"$HOME/Documents/Codex/option-c-image-security-$SOURCE_SHORT"}
CREATED_RUNTIME_ENV=0
KEEP_IMAGES=${FNCP_KEEP_SCAN_IMAGES:-0}
SKIP_BUILD=${FNCP_SKIP_SCAN_BUILD:-0}
ALLOW_DIRTY_SOURCE=${FNCP_ALLOW_DIRTY_SOURCE:-0}
export DOCKER_DEFAULT_PLATFORM="$PLATFORM"

for setting in \
  "FNCP_KEEP_SCAN_IMAGES=$KEEP_IMAGES" \
  "FNCP_SKIP_SCAN_BUILD=$SKIP_BUILD" \
  "FNCP_ALLOW_DIRTY_SOURCE=$ALLOW_DIRTY_SOURCE"
do
  value=${setting#*=}
  case "$value" in
    0|1) ;;
    *)
      echo "${setting%%=*} must be 0 or 1." >&2
      exit 2
      ;;
  esac
done

case "$PROJECT_NAME" in
  ""|[!a-z0-9]*|*[!a-z0-9_-]*)
    echo "FNCP_SCAN_PROJECT_NAME must be a lowercase Compose project name." >&2
    exit 2
    ;;
esac

if [ "$SCAN_SCOPE" = arm64-candidate-four ] && [ "$SKIP_BUILD" -eq 1 ]; then
  echo "ARM64 candidate evidence cannot use FNCP_SKIP_SCAN_BUILD=1." >&2
  exit 2
fi

case "$OUTPUT_DIR" in
  /*) ;;
  *)
    echo "Evidence output must be an absolute path." >&2
    exit 2
    ;;
esac

if [ -e "$OUTPUT_DIR" ]; then
  echo "Refusing to overwrite existing evidence: $OUTPUT_DIR" >&2
  exit 2
fi

TREE_STATUS_RAW=$(
  git -C "$REPOSITORY_ROOT" status --porcelain=v1 --untracked-files=all
)
if [ -n "$TREE_STATUS_RAW" ] && [ "$ALLOW_DIRTY_SOURCE" -ne 1 ]; then
  echo "Refusing to label a dirty source tree as an exact image candidate." >&2
  echo "Set FNCP_ALLOW_DIRTY_SOURCE=1 only for an explicitly labelled WIP run." >&2
  exit 2
fi

cleanup() {
  if [ "$CREATED_RUNTIME_ENV" -eq 1 ]; then
    rm -f "$RUNTIME_ENV"
  fi
  if [ "$KEEP_IMAGES" -ne 1 ]; then
    for service in $SERVICES; do
      docker image rm "$PROJECT_NAME-$service:latest" >/dev/null 2>&1 || true
    done
  fi
}
trap cleanup EXIT INT TERM

cd "$REPOSITORY_ROOT"
umask 077
mkdir -p \
  "$OUTPUT_DIR/sbom" \
  "$OUTPUT_DIR/scan" \
  "$OUTPUT_DIR/scanner" \
  "$OUTPUT_DIR/runtime-assertions" \
  "$OUTPUT_DIR/grype-cache"

node "$EVIDENCE_TOOL" validate-lock >"$OUTPUT_DIR/lock-validation.json"
node "$EVIDENCE_TOOL" service-scope "$SCAN_SCOPE" >"$OUTPUT_DIR/scope.json"
node "$EVIDENCE_TOOL" source-manifest >"$OUTPUT_DIR/source-manifest.json"
cp "$LOCK_FILE" "$OUTPUT_DIR/image-security.lock.json"

TREE_STATE=$(
  node -e \
    'const m=require(process.argv[1]); process.stdout.write(m.source.treeState)' \
    "$OUTPUT_DIR/source-manifest.json"
)
if [ "$TREE_STATE" != clean ] && [ "$ALLOW_DIRTY_SOURCE" -ne 1 ]; then
  echo "Refusing to label a dirty source tree as an exact image candidate." >&2
  echo "Set FNCP_ALLOW_DIRTY_SOURCE=1 only for an explicitly labelled WIP run." >&2
  exit 2
fi

if [ ! -e "$RUNTIME_ENV" ]; then
  cp "$EXAMPLE_ENV" "$RUNTIME_ENV"
  CREATED_RUNTIME_ENV=1
fi

if [ "$SKIP_BUILD" -ne 1 ]; then
  if ! docker compose \
    --env-file "$EXAMPLE_ENV" \
    -p "$PROJECT_NAME" \
    -f "$COMPOSE_FILE" \
    build --pull --no-cache $SERVICES \
    >"$OUTPUT_DIR/build.log" 2>&1; then
    echo "Image build failed; inspect $OUTPUT_DIR/build.log." >&2
    exit 1
  fi
fi

node "$EVIDENCE_TOOL" image-index "$PROJECT_NAME" "$SCAN_SCOPE" \
  >"$OUTPUT_DIR/image-index.json"

for service in server client-participation-alpha oidc-simulator; do
  case " $SERVICES " in
    *" $service "*) ;;
    *) continue ;;
  esac
  case "$service" in
    server)
      sentinels=jest,nodemon,prettier,supertest,ts-jest
      check_keys=1
      check_npm=1
      check_alpha_build_tools=0
      ;;
    client-participation-alpha)
      # Astro resolves TypeScript through production dependencies (tsconfck and
      # zod-to-ts), so it is not a reliable direct-development sentinel here.
      sentinels=eslint,jest,prettier,ts-jest,ts-node
      check_keys=1
      check_npm=1
      check_alpha_build_tools=1
      ;;
    oidc-simulator)
      sentinels=nodemon
      check_keys=1
      check_npm=0
      check_alpha_build_tools=0
      ;;
  esac
  image_id=$(
    node "$EVIDENCE_TOOL" image-id \
      "$OUTPUT_DIR/image-index.json" "$service"
  )
  docker run --rm \
    --platform "$PLATFORM" \
    --entrypoint node \
    -e "FNCP_SENTINELS=$sentinels" \
    -e "FNCP_CHECK_KEYS=$check_keys" \
    -e "FNCP_CHECK_NPM=$check_npm" \
    -e "FNCP_CHECK_ALPHA_BUILD_TOOLS=$check_alpha_build_tools" \
    "$image_id" \
    -e '
      const fs = require("node:fs");
      const sentinels = process.env.FNCP_SENTINELS.split(",");
      const present = sentinels.filter((name) =>
        fs.existsSync(`/app/node_modules/${name}/package.json`),
      );
      const keysPresent =
        process.env.FNCP_CHECK_KEYS === "1" && fs.existsSync("/app/keys");
      const globalNpmRuntimePresent =
        process.env.FNCP_CHECK_NPM === "1" &&
        (fs.existsSync("/usr/local/lib/node_modules/npm") ||
          fs.existsSync("/usr/local/bin/npm") ||
          fs.existsSync("/usr/local/bin/npx"));
      const packageManagerRuntimePathsPresent =
        process.env.FNCP_CHECK_NPM === "1"
          ? [
              "/usr/local/lib/node_modules/npm",
              "/usr/local/bin/corepack",
              "/usr/local/bin/npm",
              "/usr/local/bin/npx",
              "/usr/local/bin/pnpm",
              "/usr/local/bin/pnpx",
              "/usr/local/bin/yarn",
              "/usr/local/bin/yarnpkg",
            ].filter((path) => fs.existsSync(path))
          : [];
      const buildOnlyPackagePathsPresent = [];
      const collectBuildOnlyPackages = (directory) => {
        for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
          if (!entry.isDirectory()) continue;
          const absolute = `${directory}/${entry.name}`;
          const forbidden =
            entry.name === "@esbuild" ||
            entry.name === "esbuild" ||
            entry.name === "sharp" ||
            (directory.endsWith("/@img") && entry.name.startsWith("sharp-"));
          if (forbidden) {
            buildOnlyPackagePathsPresent.push(absolute);
          } else {
            collectBuildOnlyPackages(absolute);
          }
        }
      };
      if (
        process.env.FNCP_CHECK_ALPHA_BUILD_TOOLS === "1" &&
        fs.existsSync("/app/node_modules")
      ) {
        collectBuildOnlyPackages("/app/node_modules");
      }
      const result = {
        status:
          present.length === 0 &&
          !keysPresent &&
          packageManagerRuntimePathsPresent.length === 0 &&
          buildOnlyPackagePathsPresent.length === 0
            ? "pass"
            : "fail",
        developmentPackageSentinels: sentinels,
        developmentPackageSentinelsPresent: present,
        generatedKeysDirectoryPresent: keysPresent,
        globalNpmRuntimePresent,
        packageManagerRuntimePathsPresent,
        buildOnlyPackagePathsPresent,
      };
      console.log(JSON.stringify(result, null, 2));
      if (result.status !== "pass") process.exit(1);
    ' >"$OUTPUT_DIR/runtime-assertions/$service.json"
done

SYFT_IMAGE=$(node "$EVIDENCE_TOOL" scanner-ref syft)
GRYPE_IMAGE=$(node "$EVIDENCE_TOOL" scanner-ref grype)

docker run --rm \
  --platform "$PLATFORM" \
  -e GRYPE_CHECK_FOR_APP_UPDATE=false \
  -e GRYPE_DB_CACHE_DIR=/grype-cache \
  -v "$OUTPUT_DIR/grype-cache:/grype-cache" \
  "$GRYPE_IMAGE" \
  db update \
  >"$OUTPUT_DIR/scanner/grype-db-update.log" 2>&1

for service in $SERVICES; do
  image_id=$(
    node "$EVIDENCE_TOOL" image-id \
      "$OUTPUT_DIR/image-index.json" "$service"
  )
  docker run --rm \
    --platform "$PLATFORM" \
    -e SYFT_CHECK_FOR_APP_UPDATE=false \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$OUTPUT_DIR:/out" \
    "$SYFT_IMAGE" \
    scan "docker:$image_id" \
    -o "cyclonedx-json=/out/sbom/$service.cdx.json"

  docker run --rm \
    --platform "$PLATFORM" \
    -e GRYPE_CHECK_FOR_APP_UPDATE=false \
    -e GRYPE_DB_AUTO_UPDATE=false \
    -v "$OUTPUT_DIR:/out" \
    -e GRYPE_DB_CACHE_DIR=/grype-cache \
    -v "$OUTPUT_DIR/grype-cache:/grype-cache" \
    "$GRYPE_IMAGE" \
    "sbom:/out/sbom/$service.cdx.json" \
    -o json \
    --file "/out/scan/$service.grype.json"
done

node "$EVIDENCE_TOOL" scan-summary "$OUTPUT_DIR" \
  >"$OUTPUT_DIR/scan-summary.json"
tar -C "$OUTPUT_DIR/grype-cache" -czf \
  "$OUTPUT_DIR/scanner/grype-db-cache.tar.gz" .
rm -rf "$OUTPUT_DIR/grype-cache"

(
  cd "$OUTPUT_DIR"
  find . -type f ! -name checksums.sha256 -print |
    LC_ALL=C sort |
    xargs shasum -a 256
) >"$OUTPUT_DIR/checksums.sha256"

echo "Image security evidence written to $OUTPUT_DIR"
echo "The ARM64 candidate gate and release-attestation boundary are in scan-summary.json."
