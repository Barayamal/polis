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
PRODUCTION_SERVICES="server math client-participation-alpha nginx-proxy polis-migration"
QA_INFRASTRUCTURE_SERVICES="postgres oidc-simulator"
SCAN_SCOPE=${FNCP_SCAN_SCOPE:-arm64-candidate-five}
case "$SCAN_SCOPE" in
  arm64-candidate-five)
    SERVICES="$PRODUCTION_SERVICES"
    ;;
  staging-seven)
    SERVICES="postgres oidc-simulator server math client-participation-alpha nginx-proxy polis-migration"
    ;;
  *)
    echo "Unknown scan scope: $SCAN_SCOPE" >&2
    echo "Expected arm64-candidate-five or staging-seven." >&2
    exit 2
    ;;
esac
SOURCE_SHORT=$(git -C "$REPOSITORY_ROOT" rev-parse --short=12 HEAD)
SOURCE_REVISION=$(git -C "$REPOSITORY_ROOT" rev-parse HEAD)
case "$SOURCE_REVISION" in
  ""|*[!0-9a-f]*)
    echo "Could not resolve an exact source revision." >&2
    exit 2
    ;;
esac
if [ "${#SOURCE_REVISION}" -ne 40 ]; then
  echo "Could not resolve an exact source revision." >&2
  exit 2
fi
export FNCP_SOURCE_REVISION="$SOURCE_REVISION"
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

if [ "$SCAN_SCOPE" = arm64-candidate-five ] && [ "$SKIP_BUILD" -eq 1 ]; then
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
      expected_alpine_packages="libpq=18.4-r0,openssl=3.5.7-r0,ca-certificates=20260611-r0"
      ;;
    client-participation-alpha)
      # Astro resolves TypeScript through production dependencies (tsconfck and
      # zod-to-ts), so it is not a reliable direct-development sentinel here.
      sentinels=eslint,jest,prettier,ts-jest,ts-node
      check_keys=1
      check_npm=1
      check_alpha_build_tools=1
      expected_alpine_packages=
      ;;
    oidc-simulator)
      sentinels=nodemon
      check_keys=1
      check_npm=0
      check_alpha_build_tools=0
      expected_alpine_packages=
      ;;
  esac
  image_id=$(
    node "$EVIDENCE_TOOL" image-id \
      "$OUTPUT_DIR/image-index.json" "$service"
  )
  docker run --rm \
    --platform "$PLATFORM" \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --entrypoint node \
    -e "FNCP_SERVICE=$service" \
    -e "FNCP_SENTINELS=$sentinels" \
    -e "FNCP_CHECK_KEYS=$check_keys" \
    -e "FNCP_CHECK_NPM=$check_npm" \
    -e "FNCP_CHECK_ALPHA_BUILD_TOOLS=$check_alpha_build_tools" \
    -e "FNCP_EXPECTED_ALPINE_PACKAGES=$expected_alpine_packages" \
    "$image_id" \
    -e '
      const fs = require("node:fs");
      const service = process.env.FNCP_SERVICE;
      const effectiveUser = process.getuid() === 0 ? "root" : "non-root";
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
              "/app/node_modules/.bin/astro",
              "/app/node_modules/.bin/rolldown",
              "/app/node_modules/.bin/vite",
            ].filter((path) => fs.existsSync(path))
          : [];
      const buildOnlyPackagePathsPresent = [];
      const expectedAlpinePackages = (
        process.env.FNCP_EXPECTED_ALPINE_PACKAGES || ""
      ).split(",").filter(Boolean);
      const installedAlpinePackages = new Map();
      if (
        expectedAlpinePackages.length > 0 &&
        fs.existsSync("/lib/apk/db/installed")
      ) {
        for (const record of fs
          .readFileSync("/lib/apk/db/installed", "utf8")
          .split(/\n\n/u)) {
          const lines = record.split(/\n/u);
          const name = lines.find((line) => line.startsWith("P:"))?.slice(2);
          const version = lines.find((line) => line.startsWith("V:"))?.slice(2);
          if (name && version) installedAlpinePackages.set(name, version);
        }
      }
      const alpinePackageMismatches = expectedAlpinePackages
        .map((specification) => {
          const separator = specification.indexOf("=");
          const name = specification.slice(0, separator);
          const expectedVersion = specification.slice(separator + 1);
          const actualVersion = installedAlpinePackages.get(name) || null;
          return actualVersion === expectedVersion
            ? null
            : { name, expectedVersion, actualVersion };
        })
        .filter(Boolean);
      const collectBuildOnlyPackages = (directory) => {
        for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
          if (!entry.isDirectory()) continue;
          const absolute = `${directory}/${entry.name}`;
          const forbidden =
            entry.name === "@astrojs" ||
            entry.name === "@esbuild" ||
            entry.name === "@oxc-project" ||
            entry.name === "@rolldown" ||
            entry.name === "@types" ||
            entry.name === "@vitejs" ||
            entry.name === "astro" ||
            entry.name === "esbuild" ||
            entry.name === "lightningcss" ||
            entry.name.startsWith("lightningcss-") ||
            entry.name === "rolldown" ||
            entry.name === "sharp" ||
            entry.name === "vite" ||
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
          effectiveUser === "non-root" &&
          present.length === 0 &&
          !keysPresent &&
          packageManagerRuntimePathsPresent.length === 0 &&
          buildOnlyPackagePathsPresent.length === 0 &&
          alpinePackageMismatches.length === 0
            ? "pass"
            : "fail",
        artifact: service,
        effectiveUser,
        developmentPackageSentinels: sentinels,
        developmentPackageSentinelsPresent: present,
        generatedKeysDirectoryPresent: keysPresent,
        globalNpmRuntimePresent,
        packageManagerRuntimePathsPresent,
        buildOnlyPackagePathsPresent,
        expectedAlpinePackages,
        alpinePackageMismatches,
      };
      console.log(JSON.stringify(result, null, 2));
      if (result.status !== "pass") process.exit(1);
    ' >"$OUTPUT_DIR/runtime-assertions/$service.json"
done

for service in math nginx-proxy; do
  case " $SERVICES " in
    *" $service "*) ;;
    *) continue ;;
  esac
  image_id=$(
    node "$EVIDENCE_TOOL" image-id \
      "$OUTPUT_DIR/image-index.json" "$service"
  )
  case "$service" in
    math)
      docker run --rm \
        --platform "$PLATFORM" \
        --network none \
        --read-only \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        --entrypoint sh \
        "$image_id" \
        -euc '
          test "$(id -u)" -ne 0
          test -x /app/bin/run
          test -r /app/classpath
          test ! -e /app/deps.edn
          test ! -e /usr/local/lib/clojure
          test ! -e /usr/local/bin/clj
          test ! -e /usr/local/bin/clojure
          printf "%s\n" \
            "{\"status\":\"pass\",\"artifact\":\"math\",\"effectiveUser\":\"non-root\",\"clojureBuildToolPresent\":false}"
        ' >"$OUTPUT_DIR/runtime-assertions/math.json"
      ;;
    nginx-proxy)
      docker run --rm \
        --platform "$PLATFORM" \
        --network none \
        --read-only \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        --entrypoint sh \
        "$image_id" \
        -euc '
          test "$(id -u)" -ne 0
          test -r /etc/nginx/conf.d/default.conf
          grep -q "listen 8080 default_server;" \
            /etc/nginx/conf.d/default.conf
          printf "%s\n" \
            "{\"status\":\"pass\",\"artifact\":\"nginx-proxy\",\"effectiveUser\":\"non-root\",\"reviewedConfigPresent\":true}"
        ' >"$OUTPUT_DIR/runtime-assertions/nginx-proxy.json"
      ;;
  esac
done

case " $SERVICES " in
  *" polis-migration "*)
    migration_image_id=$(
      node "$EVIDENCE_TOOL" image-id \
        "$OUTPUT_DIR/image-index.json" polis-migration
    )
    configured_revision=$(
      docker image inspect \
        --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' \
        "$migration_image_id"
    )
    configured_source=$(
      docker image inspect \
        --format '{{ index .Config.Labels "org.opencontainers.image.source" }}' \
        "$migration_image_id"
    )
    configured_base_digest=$(
      docker image inspect \
        --format '{{ index .Config.Labels "org.opencontainers.image.base.digest" }}' \
        "$migration_image_id"
    )
    configured_base_name=$(
      docker image inspect \
        --format '{{ index .Config.Labels "org.opencontainers.image.base.name" }}' \
        "$migration_image_id"
    )
    configured_user=$(
      docker image inspect --format '{{.Config.User}}' "$migration_image_id"
    )
    configured_entrypoint=$(
      docker image inspect \
        --format '{{json .Config.Entrypoint}}' "$migration_image_id"
    )
    configured_command=$(
      docker image inspect \
        --format '{{json .Config.Cmd}}' "$migration_image_id"
    )
    if [ "$configured_revision" != "$SOURCE_REVISION" ]; then
      echo "Migration image revision label does not match the exact source." >&2
      exit 1
    fi
    if [ "$configured_source" != "https://github.com/Barayamal/polis" ]; then
      echo "Migration image source label does not match the reviewed fork." >&2
      exit 1
    fi
    if [ "$configured_base_digest" != \
      "sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193" ]; then
      echo "Migration image base digest label is not the reviewed digest." >&2
      exit 1
    fi
    if [ "$configured_base_name" != \
      "docker.io/library/postgres:17-alpine" ]; then
      echo "Migration image base-name label is not the reviewed image." >&2
      exit 1
    fi
    case "$configured_user" in
      ""|0|0:*|root|root:*)
        echo "Migration image has an unsafe configured user." >&2
        exit 1
        ;;
    esac
    if [ "$configured_entrypoint" != \
      '["/usr/local/bin/fncp-run-migrations"]' ]; then
      echo "Migration image entrypoint is not the reviewed runner." >&2
      exit 1
    fi
    if [ "$configured_command" != 'null' ]; then
      echo "Migration image inherited an unexpected default command." >&2
      exit 1
    fi
    docker run --rm \
      --platform "$PLATFORM" \
      --network none \
      --read-only \
      --cap-drop ALL \
      --security-opt no-new-privileges \
      --entrypoint sh \
      "$migration_image_id" \
      -euc '
        test "$(id -u)" -ne 0
        test -x /usr/local/bin/fncp-run-migrations
        for required_command in \
          cat find mktemp psql rm sha256sum sh sort tr wc; do
          command -v "$required_command" >/dev/null
        done
        for forbidden_command in \
          clusterdb createdb createuser docker-enforce-initdb.sh \
          docker-ensure-initdb.sh docker-entrypoint.sh \
          dropdb dropuser ecpg gosu initdb \
          oid2name pg_amcheck pg_archivecleanup pg_basebackup pgbench \
          pg_checksums pg_combinebackup pg_config pg_controldata \
          pg_createsubscriber \
          pg_ctl pg_dump pg_dumpall pg_isready pg_receivewal \
          pg_recvlogical pg_resetwal pg_restore pg_rewind \
          pg_test_fsync pg_test_timing pg_upgrade pg_verifybackup \
          pg_waldump pg_walsummary postmaster postgres reindexdb vacuumdb \
          vacuumlo; do
          ! command -v "$forbidden_command" >/dev/null
        done
        test ! -e /docker-entrypoint-initdb.d
        test "$(find /opt/fncp/migrations -mindepth 1 -maxdepth 1 \
          -type f -name "*.sql" | wc -l | tr -d " ")" -gt 0
        test -z "$(find /opt/fncp/migrations -mindepth 2 -print -quit)"
        printf "%s\n" \
          "{\"status\":\"pass\",\"artifact\":\"polis-migration\",\"effectiveUser\":\"non-root\",\"migrationRunner\":\"/usr/local/bin/fncp-run-migrations\",\"migrationRunnerPresent\":true,\"requiredToolsPresent\":true,\"serverAndLifecycleToolsPresent\":false,\"initdbHooksPresent\":false,\"topLevelMigrationsOnly\":true,\"psqlPresent\":true,\"postgresServerPresent\":false}"
      ' >"$OUTPUT_DIR/runtime-assertions/polis-migration.json"
    ;;
esac

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
