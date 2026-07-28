# syntax=docker.io/docker/dockerfile:1.4@sha256:9ba7531bd80fb0a858632727cf7a112fbfd19b17e94c4e84ced81e24ef1a0dbc
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
RUN --mount=type=cache,target=/root/.npm npm ci
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
      node_modules/astro/node_modules/@esbuild \
      node_modules/astro/node_modules/esbuild \
      node_modules/esbuild \
      node_modules/sharp && \
    test -z "$(find node_modules -type d \( \
      -name '@esbuild' -o \
      -name 'esbuild' -o \
      -name 'sharp' -o \
      -path '*/@img/sharp-*' \
    \) -print -quit)"

FROM docker.io/library/node:24-alpine@sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd AS runtime
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
