# syntax=docker.io/docker/dockerfile:1.4@sha256:9ba7531bd80fb0a858632727cf7a112fbfd19b17e94c4e84ced81e24ef1a0dbc
FROM docker.io/library/node:24-alpine@sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd AS fncp-busybox-fixed

RUN apk add --no-cache \
  build-base=0.5-r4 \
  curl=8.21.0-r0 \
  file=5.47-r2 \
  linux-headers=7.0.0-r1 \
  patch=2.8-r0 \
  pkgconf=2.5.1-r0 \
  utmps-dev=0.1.3.3-r0 \
  utmps-static=0.1.3.3-r0
COPY busybox-fixed /opt/fncp-busybox-fix
RUN chmod 0555 /opt/fncp-busybox-fix/build-fixed-busybox.sh \
  && /opt/fncp-busybox-fix/build-fixed-busybox.sh

FROM docker.io/library/node:24-alpine@sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd AS build
WORKDIR /app

ARG PUBLIC_SERVICE_URL
ARG INTERNAL_SERVICE_URL
ARG OIDC_CACHE_KEY_PREFIX
ARG OIDC_CACHE_KEY_ID_TOKEN_SUFFIX
ARG PUBLIC_AUTH_NAMESPACE

ENV PUBLIC_SERVICE_URL=$PUBLIC_SERVICE_URL
ENV INTERNAL_SERVICE_URL=$INTERNAL_SERVICE_URL
ENV PUBLIC_OIDC_CACHE_KEY_PREFIX=$OIDC_CACHE_KEY_PREFIX
ENV PUBLIC_OIDC_CACHE_KEY_ID_TOKEN_SUFFIX=$OIDC_CACHE_KEY_ID_TOKEN_SUFFIX
ENV PUBLIC_AUTH_NAMESPACE=$PUBLIC_AUTH_NAMESPACE
ENV ASTRO_TELEMETRY_DISABLED=1

COPY package*.json ./
RUN npm config set fetch-retries 5 && \
    npm config set fetch-retry-mintimeout 20000 && \
    npm config set fetch-retry-maxtimeout 120000
RUN npm ci
COPY . .

RUN npm run build

# Astro, Vite and Sharp are required to produce the standalone bundle, but the
# configured passthrough image service leaves no Sharp import in that bundle.
# Keep npm's production closure for the external imports that remain, then
# remove the reviewed build-only package families before crossing the stage.
RUN npm prune --omit=dev && npm cache clean --force && \
    rm -rf \
      node_modules/@esbuild \
      node_modules/@img \
      node_modules/@astrojs \
      node_modules/@oxc-project \
      node_modules/@rolldown \
      node_modules/@types \
      node_modules/@visx/vendor/node_modules/@types \
      node_modules/@vitejs \
      node_modules/astro \
      node_modules/astro/node_modules/@esbuild \
      node_modules/astro/node_modules/esbuild \
      node_modules/esbuild \
      node_modules/lightningcss \
      node_modules/lightningcss-* \
      node_modules/rolldown \
      node_modules/sharp \
      node_modules/vite \
      node_modules/.bin/astro \
      node_modules/.bin/rolldown \
      node_modules/.bin/vite && \
    test -z "$(find node_modules -type d \( \
      -name '@astrojs' -o \
      -name '@esbuild' -o \
      -name '@oxc-project' -o \
      -name '@rolldown' -o \
      -name '@types' -o \
      -name '@vitejs' -o \
      -name 'astro' -o \
      -name 'esbuild' -o \
      -name 'lightningcss' -o \
      -name 'lightningcss-*' -o \
      -name 'rolldown' -o \
      -name 'sharp' -o \
      -name 'vite' -o \
      -path '*/@img/sharp-*' \
    \) -print -quit)" && \
    for path in \
      node_modules/.bin/astro \
      node_modules/.bin/rolldown \
      node_modules/.bin/vite; do \
        test ! -e "$path"; \
        test ! -L "$path"; \
    done

FROM docker.io/library/node:24-alpine@sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd AS runtime
WORKDIR /app

ARG SOURCE_REVISION
RUN case "$SOURCE_REVISION" in \
      ""|*[!0-9a-f]*) exit 1 ;; \
    esac \
    && test "${#SOURCE_REVISION}" -eq 40
LABEL org.barayamal.fncp.busybox.remediation="CVE-2025-60876-upstream-patch" \
      org.opencontainers.image.source="https://github.com/Barayamal/polis" \
      org.opencontainers.image.revision="${SOURCE_REVISION}"
COPY --from=fncp-busybox-fixed /out/busybox /bin/busybox
RUN set -eu; \
  test "$(readlink -f /bin/sh)" = /bin/busybox; \
  test "$(readlink -f /usr/bin/wget)" = /bin/busybox; \
  bad_url="$(printf 'http://127.0.0.1/%b' '\rX-FNCP: injected')"; \
  if /usr/bin/wget "$bad_url" >/tmp/wget.stdout 2>/tmp/wget.stderr; then exit 1; fi; \
  grep -Fq 'Unencoded control character found in the URL!' /tmp/wget.stderr; \
  rm -f /tmp/wget.stdout /tmp/wget.stderr

ARG PUBLIC_SERVICE_URL
ARG INTERNAL_SERVICE_URL
ARG OIDC_CACHE_KEY_PREFIX
ARG OIDC_CACHE_KEY_ID_TOKEN_SUFFIX
ARG PUBLIC_AUTH_NAMESPACE

ENV PUBLIC_SERVICE_URL=$PUBLIC_SERVICE_URL
ENV INTERNAL_SERVICE_URL=$INTERNAL_SERVICE_URL
ENV PUBLIC_OIDC_CACHE_KEY_PREFIX=$OIDC_CACHE_KEY_PREFIX
ENV PUBLIC_OIDC_CACHE_KEY_ID_TOKEN_SUFFIX=$OIDC_CACHE_KEY_ID_TOKEN_SUFFIX
ENV PUBLIC_AUTH_NAMESPACE=$PUBLIC_AUTH_NAMESPACE
ENV ASTRO_TELEMETRY_DISABLED=1

COPY --from=build /app/dist ./dist
COPY --from=build /app/node_modules ./node_modules

RUN rm -rf \
  /usr/local/lib/node_modules/npm \
  /usr/local/bin/corepack \
  /usr/local/bin/npm \
  /usr/local/bin/npx \
  /usr/local/bin/pnpm \
  /usr/local/bin/pnpx \
  /usr/local/bin/yarn \
  /usr/local/bin/yarnpkg

USER node

EXPOSE 4321
CMD ["node", "dist/server/entry.mjs"]
