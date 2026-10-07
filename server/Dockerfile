# syntax=docker.io/docker/dockerfile:1.4@sha256:9ba7531bd80fb0a858632727cf7a112fbfd19b17e94c4e84ced81e24ef1a0dbc
# Requires BuildKit (default in Docker 23+; on older versions prefix
# the build command with `DOCKER_BUILDKIT=1`). Only the development target uses
# a persistent npm cache mount; production dependency installation is cold.
# To build locally, for example:
# docker build -t polis-server:local .
# To run locally, for example:
# docker run --rm --name polis-server --env-file .env --network polis-dev_polis-net \
#  -p 5000:5000 --target dev polis-server:local
#
# For a dev build, use `--target dev`.
# Should default to prod build, but you can also explicitly use `--target prod`

FROM docker.io/library/node:24.18.1-alpine@sha256:f70403e87646dc51b45295f4b8b70cdad0b63d2297c4c9899119b03f7af7a6b3 AS fncp-busybox-fixed

RUN apk add --no-cache \
  build-base=0.5-r4 \
  curl=8.22.0-r0 \
  file=5.47-r2 \
  linux-headers=7.0.0-r1 \
  patch=2.8-r0 \
  pkgconf=2.5.1-r0 \
  utmps-dev=0.1.3.3-r0 \
  utmps-static=0.1.3.3-r0
COPY busybox-fixed /opt/fncp-busybox-fix
RUN chmod 0555 /opt/fncp-busybox-fix/build-fixed-busybox.sh \
  && /opt/fncp-busybox-fix/build-fixed-busybox.sh
COPY zlib-fixed /opt/fncp-zlib-fix
RUN chmod 0555 /opt/fncp-zlib-fix/build-fixed-zlib.sh \
  && /opt/fncp-zlib-fix/build-fixed-zlib.sh

FROM docker.io/library/node:22.23.2-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS base

ARG NODE_ENV

WORKDIR /app

COPY package*.json ./

EXPOSE 5000


# Define the development build

FROM base as dev

# Set default NODE_ENV to development unless overridden at build time with --build-arg NODE_ENV=production
ENV NODE_ENV ${NODE_ENV:-development}
RUN apk add --no-cache \
    libpq-dev=18.6-r0 \
    g++=15.2.0-r5 \
    make=4.4.1-r4 \
    python3=3.14.8-r0
RUN npm config set fetch-retries 5 && \
    npm config set fetch-retry-mintimeout 20000 && \
    npm config set fetch-retry-maxtimeout 120000
RUN --mount=type=cache,target=/root/.npm npm ci --production=false --no-audit --no-fund

COPY . .

CMD npm run dev



# Build the production closure without copying tests, documentation or
# experimental source into the final participant-facing image.

FROM base as build

ENV NODE_ENV ${NODE_ENV:-production}

RUN apk add --no-cache \
    libpq-dev=18.6-r0 \
    g++=15.2.0-r5 \
    make=4.4.1-r4 \
    python3=3.14.8-r0

RUN npm config set fetch-retries 5 && \
    npm config set fetch-retry-mintimeout 20000 && \
    npm config set fetch-retry-maxtimeout 120000
RUN npm ci --production=false --no-audit --no-fund

COPY tsconfig.json index.ts app.ts unsupportedBrowser.html ./
COPY src ./src
COPY types ./types
RUN npm run build

RUN npm prune --omit=dev --no-audit --no-fund && npm cache clean --force && \
    find dist -type f -name '*.map' -delete


# Define the minimal, non-root production runtime. Starting from the exact
# pinned image again prevents the build-stage package lock, compiler toolchain
# and source tree from crossing the stage boundary.

FROM docker.io/library/node:22.23.2-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS prod

ENV NODE_ENV ${NODE_ENV:-production}
WORKDIR /app

LABEL org.barayamal.fncp.busybox.remediation="CVE-2025-60876-upstream-patch"
COPY --from=fncp-busybox-fixed /out/busybox /bin/busybox
RUN set -eu; \
  test "$(readlink -f /bin/sh)" = /bin/busybox; \
  test "$(readlink -f /usr/bin/wget)" = /bin/busybox; \
  bad_url="$(printf 'http://127.0.0.1/%b' '\rX-FNCP: injected')"; \
  if /usr/bin/wget "$bad_url" >/tmp/wget.stdout 2>/tmp/wget.stderr; then exit 1; fi; \
  grep -Fq 'Unencoded control character found in the URL!' /tmp/wget.stderr; \
  rm -f /tmp/wget.stdout /tmp/wget.stderr

RUN apk add --no-cache \
      libpq=18.6-r0 \
      openssl=3.5.9-r0 \
      libcrypto3=3.5.9-r0 \
      libssl3=3.5.9-r0 \
      ca-certificates=20260909-r0 && \
    rm -rf \
      /usr/local/lib/node_modules/npm \
      /usr/local/bin/corepack \
      /usr/local/bin/npm \
      /usr/local/bin/npx \
      /usr/local/bin/pnpm \
      /usr/local/bin/pnpx \
      /usr/local/bin/yarn \
      /usr/local/bin/yarnpkg
COPY --from=fncp-busybox-fixed /out/zlib/lib/libz.so.1.3.2 /lib/libz.so.1.3.2
COPY --from=fncp-busybox-fixed /out/zlib/evidence/provenance.txt /usr/share/fncp-security/zlib-provenance.txt
RUN test "$(sha256sum /lib/libz.so.1.3.2 | awk '{print $1}')" = "$(sed -n 's/^binary_sha256=//p' /usr/share/fncp-security/zlib-provenance.txt)"

COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
COPY --from=build --chown=node:node \
  /app/src/prompts/moderation/script.xml \
  ./src/prompts/moderation/script.xml
COPY --from=build --chown=node:node \
  /app/src/prompts/report_experimental/system.xml \
  ./src/prompts/report_experimental/system.xml

USER node

EXPOSE 5000
CMD ["node", "--max_old_space_size=2048", "--gc_interval=100", "dist/index.js"]

# Dedicated First Nations Community Pulse release artifact. The immutable image
# default makes omission select the guarded production contract; an explicit
# runtime override to an empty, false or malformed value is rejected by startup
# admission rather than falling back to ordinary Pol.is.
FROM prod AS fncp-production
ARG SOURCE_REVISION
RUN case "$SOURCE_REVISION" in \
      ""|*[!0-9a-f]*) exit 1 ;; \
    esac \
    && test "${#SOURCE_REVISION}" -eq 40
ENV FNCP_OPTION_C_RELEASE_MODE=production
# Leave native/heap overhead inside the dedicated 1536 MiB container limit.
CMD ["node", "--max_old_space_size=1024", "--gc_interval=100", "dist/index.js"]
LABEL org.barayamal.fncp.release-mode="production" \
      org.barayamal.fncp.zlib.remediation="CVE-2026-85091-df84af25dc1942490e1d1c899a07619152a46148" \
      org.opencontainers.image.source="https://github.com/Barayamal/polis" \
      org.opencontainers.image.revision="${SOURCE_REVISION}"

# Keep the Dockerfile's default and ordinary upstream `prod` target
# non-dedicated. Option C release tooling must select `fncp-production`
# explicitly and is checked by deployment-boundary tests.
FROM prod AS upstream-production
