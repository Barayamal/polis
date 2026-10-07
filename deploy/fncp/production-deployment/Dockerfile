# syntax=docker.io/docker/dockerfile:1.4@sha256:9ba7531bd80fb0a858632727cf7a112fbfd19b17e94c4e84ced81e24ef1a0dbc
FROM docker.io/library/node:24.18.1-alpine@sha256:f70403e87646dc51b45295f4b8b70cdad0b63d2297c4c9899119b03f7af7a6b3 AS busybox-fixed
RUN apk add --no-cache build-base=0.5-r4 curl=8.22.0-r0 file=5.47-r2 linux-headers=7.0.0-r1 patch=2.8-r0 pkgconf=2.5.1-r0 utmps-dev=0.1.3.3-r0 utmps-static=0.1.3.3-r0
COPY server/busybox-fixed /opt/fncp-busybox-fix
RUN chmod 0555 /opt/fncp-busybox-fix/build-fixed-busybox.sh && /opt/fncp-busybox-fix/build-fixed-busybox.sh
COPY deploy/fncp/production-security/zlib-fixed /opt/fncp-zlib-fix
RUN chmod 0555 /opt/fncp-zlib-fix/build-fixed-zlib.sh && /opt/fncp-zlib-fix/build-fixed-zlib.sh
FROM docker.io/library/node:22.23.2-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS dependencies
WORKDIR /build
COPY deploy/fncp/production-identity/package.json deploy/fncp/production-identity/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund
FROM docker.io/library/node:22.23.2-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS participant
COPY --from=busybox-fixed /out/busybox /bin/busybox
RUN apk add --no-cache libcrypto3=3.5.8-r0 libssl3=3.5.8-r0 ca-certificates=20260909-r0 && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/corepack /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/pnpm /usr/local/bin/pnpx /usr/local/bin/yarn /usr/local/bin/yarnpkg
COPY --from=busybox-fixed /out/zlib/lib/libz.so.1.3.2 /lib/libz.so.1.3.2
COPY --from=busybox-fixed /out/zlib/evidence/provenance.txt /usr/share/fncp-security/zlib-provenance.txt
RUN test "$(sha256sum /lib/libz.so.1.3.2 | awk '{print $1}')" = "$(sed -n 's/^binary_sha256=//p' /usr/share/fncp-security/zlib-provenance.txt)"
WORKDIR /app
COPY --from=dependencies --chown=1000:1000 /build/node_modules ./deploy/fncp/production-identity/node_modules
COPY --chown=1000:1000 deploy/fncp/production-identity/identity.mjs deploy/fncp/production-identity/https-transport.mjs deploy/fncp/production-identity/relay-route.mjs ./deploy/fncp/production-identity/
COPY --chown=1000:1000 deploy/fncp/production-provider/provider.mjs ./deploy/fncp/production-provider/
COPY --chown=1000:1000 deploy/fncp/production-activation/authority.mjs deploy/fncp/production-activation/protocol.mjs ./deploy/fncp/production-activation/
COPY --chown=1000:1000 deploy/fncp/production-service/access.mjs deploy/fncp/production-service/browser.mjs deploy/fncp/production-service/contracts.mjs deploy/fncp/production-service/custody.mjs deploy/fncp/production-service/event-receiver.mjs deploy/fncp/production-service/main.mjs deploy/fncp/production-service/operator.mjs deploy/fncp/production-service/operator-cli.mjs deploy/fncp/production-service/principal-boundary.mjs deploy/fncp/production-service/service.mjs deploy/fncp/production-service/store-schema.mjs deploy/fncp/production-service/store-validation.mjs deploy/fncp/production-service/wordpress-bridge.mjs ./deploy/fncp/production-service/
COPY --chown=1000:1000 deploy/fncp/production-service/public ./deploy/fncp/production-service/public
ENV NODE_ENV=production
USER 1000:1000
ARG SOURCE_REVISION
RUN node -e 'if(!/^[a-f0-9]{40}$/.test(process.argv[1])) process.exit(1)' "$SOURCE_REVISION"
LABEL org.barayamal.fncp.profile="FNCP_PRODUCTION_SERVICE_V1" org.opencontainers.image.revision="$SOURCE_REVISION" org.barayamal.fncp.busybox.remediation="CVE-2025-60876-upstream-patch" org.barayamal.fncp.zlib.remediation="CVE-2026-85091-df84af25dc1942490e1d1c899a07619152a46148"
CMD ["node","--max-old-space-size=384","deploy/fncp/production-service/main.mjs","/run/fncp/service.json"]
