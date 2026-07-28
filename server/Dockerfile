# syntax=docker/dockerfile:1.4
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

# This package is needed at runtime
RUN apk add libpq-dev

RUN apk add --no-cache --virtual .build \
  g++ make python3

COPY package*.json ./

EXPOSE 5000


# Define the development build

FROM base as dev

# Set default NODE_ENV to development unless overridden at build time with --build-arg NODE_ENV=production
ENV NODE_ENV ${NODE_ENV:-development}
RUN npm config set fetch-retries 5 && \
    npm config set fetch-retry-mintimeout 20000 && \
    npm config set fetch-retry-maxtimeout 120000
RUN --mount=type=cache,target=/root/.npm npm ci --production=false

COPY . .

CMD npm run dev



# Define the production build

FROM base as prod

# Set default NODE_ENV to production unless overridden at build time with --build-arg NODE_ENV=development
ENV NODE_ENV ${NODE_ENV:-production}

# Install OpenSSL and CA Certificates (CRITICAL for production)
RUN apk add --no-cache openssl ca-certificates

RUN npm config set fetch-retries 5 && \
    npm config set fetch-retry-mintimeout 20000 && \
    npm config set fetch-retry-maxtimeout 120000
RUN --mount=type=cache,target=/root/.npm npm ci --production=false

# For prod builds, to minimize the image size, remove the dependencies tagged with `--virtual .build` above.
RUN apk del .build

COPY . .

RUN npm run build

# The TypeScript compiler, npm CLI and test/lint tooling are needed to build
# the image, but must not remain in the participant-facing runtime. The final
# process invokes Node directly, so retaining npm would add an unnecessary
# package-manager attack surface.
RUN npm prune --omit=dev && npm cache clean --force && \
    rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx

CMD ["node", "--max_old_space_size=2048", "--gc_interval=100", "dist/index.js"]
