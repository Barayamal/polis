# syntax=docker.io/docker/dockerfile:1.4@sha256:9ba7531bd80fb0a858632727cf7a112fbfd19b17e94c4e84ced81e24ef1a0dbc
# Use an official Node.js runtime as a parent image
FROM docker.io/library/node:24-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d

# Install curl for health checks, openssl for certificate generation, and create certificate directory
RUN apt-get update && apt-get install -y curl openssl && rm -rf /var/lib/apt/lists/* && \
    mkdir -p /root/.simulacrum/certs

# Set the working directory in the container
WORKDIR /app

# Copy package.json and package-lock.json (or yarn.lock)
COPY package*.json ./

# Install app dependencies
RUN npm config set fetch-retries 5 && \
    npm config set fetch-retry-mintimeout 20000 && \
    npm config set fetch-retry-maxtimeout 120000
RUN --mount=type=cache,target=/root/.npm npm ci

# Bundle app source
COPY . .

# Ensure TypeScript is built
RUN npm run build

RUN npm prune --omit=dev && npm cache clean --force

# Your app binds to port 3000 so you'll use the EXPOSE instruction to have it mapped by the Docker daemon
EXPOSE 3000

# Health check to ensure the service is ready
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -k -f https://localhost:3000/.well-known/jwks.json || exit 1

# Define the command to run your app
CMD [ "node", "dist/index.js" ]
