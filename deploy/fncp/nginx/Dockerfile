FROM docker.io/library/nginx:1.30.4-alpine3.24-slim@sha256:ddde39c6e51f02fde7410c2e9c234cf2d0a4c7bdbbe176aeb37d8ad7ab4eb58c

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
