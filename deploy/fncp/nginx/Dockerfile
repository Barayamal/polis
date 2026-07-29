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

FROM docker.io/library/nginx:1.30.4-alpine3.24-slim@sha256:ddde39c6e51f02fde7410c2e9c234cf2d0a4c7bdbbe176aeb37d8ad7ab4eb58c

LABEL org.barayamal.fncp.busybox.remediation="CVE-2025-60876-upstream-patch"
COPY --from=fncp-busybox-fixed /out/busybox /bin/busybox
RUN set -eu; \
  test "$(readlink -f /bin/sh)" = /bin/busybox; \
  test "$(readlink -f /usr/bin/wget)" = /bin/busybox; \
  bad_url="$(printf 'http://127.0.0.1/%b' '\rX-FNCP: injected')"; \
  if /usr/bin/wget "$bad_url" >/tmp/wget.stdout 2>/tmp/wget.stderr; then exit 1; fi; \
  grep -Fq 'Unencoded control character found in the URL!' /tmp/wget.stderr; \
  rm -f /tmp/wget.stdout /tmp/wget.stderr

# Disposable loopback QA boundary only. Production TLS/WAF/load balancing is a
# separate, unimplemented control; do not expose this image directly.
RUN mkdir -p \
      /var/cache/nginx/client_temp \
      /var/cache/nginx/fastcgi_temp \
      /var/cache/nginx/proxy_temp \
      /var/cache/nginx/scgi_temp \
      /var/cache/nginx/uwsgi_temp \
    && touch /var/run/nginx.pid \
    && chown -R nginx:nginx /var/cache/nginx /var/run/nginx.pid

COPY --chown=nginx:nginx nginx/fncp-staging.conf /etc/nginx/conf.d/default.conf

USER nginx

EXPOSE 8080

CMD ["nginx", "-g", "daemon off;"]
