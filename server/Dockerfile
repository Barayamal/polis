# syntax=docker.io/docker/dockerfile:1.4@sha256:9ba7531bd80fb0a858632727cf7a112fbfd19b17e94c4e84ced81e24ef1a0dbc
# Requires BuildKit (default in Docker 23+; on older versions prefix
# the build command with `DOCKER_BUILDKIT=1`). The `RUN --mount=type=cache`
# directives below are silently ignored without BuildKit.
# To build locally, for example:
# docker build -t polis-server:local .
# To run locally, for example:
# docker run --rm --name polis-server --env-file .env --network polis-dev_polis-net \
#  -p 5000:5000 --target dev polis-server:local
#
# For a dev build, use `--target dev`.
# Should default to prod build, but you can also explicitly use `--target prod`

FROM docker.io/library/node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2 AS base

ARG NODE_ENV

WORKDIR /app

COPY package*.json ./

EXPOSE 5000


# Define the development build

FROM base as dev

# Set default NODE_ENV to development unless overridden at build time with --build-arg NODE_ENV=production
ENV NODE_ENV ${NODE_ENV:-development}
RUN apk add --no-cache libpq-dev g++ make python3
RUN npm config set fetch-retries 5 && \
    npm config set fetch-retry-mintimeout 20000 && \
    npm config set fetch-retry-maxtimeout 120000
RUN --mount=type=cache,target=/root/.npm npm ci --production=false

COPY . .

CMD npm run dev



# Build the production closure without copying tests, documentation or
# experimental source into the final participant-facing image.

FROM base as build

ENV NODE_ENV ${NODE_ENV:-production}

RUN apk add --no-cache libpq-dev g++ make python3

RUN npm config set fetch-retries 5 && \
    npm config set fetch-retry-mintimeout 20000 && \
    npm config set fetch-retry-maxtimeout 120000
RUN --mount=type=cache,target=/root/.npm npm ci --production=false

COPY tsconfig.json index.ts app.ts unsupportedBrowser.html ./
COPY src ./src
COPY types ./types
RUN npm run build

RUN npm prune --omit=dev && npm cache clean --force && \
    find dist -type f -name '*.map' -delete


# Define the minimal, non-root production runtime. Starting from the exact
# pinned image again prevents the build-stage package lock, compiler toolchain
# and source tree from crossing the stage boundary.

FROM docker.io/library/node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2 AS prod

ENV NODE_ENV ${NODE_ENV:-production}
WORKDIR /app

RUN apk add --no-cache libpq openssl ca-certificates && \
    rm -rf \
      /usr/local/lib/node_modules/npm \
      /usr/local/bin/corepack \
      /usr/local/bin/npm \
      /usr/local/bin/npx \
      /usr/local/bin/pnpm \
      /usr/local/bin/pnpx \
      /usr/local/bin/yarn \
      /usr/local/bin/yarnpkg

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
