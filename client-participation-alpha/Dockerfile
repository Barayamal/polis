# syntax=docker/dockerfile:1.4
FROM docker.io/library/node:24-alpine@sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd
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

RUN npm prune --omit=dev && npm cache clean --force && \
    rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx

EXPOSE 4321
CMD ["node", "dist/server/entry.mjs"]
