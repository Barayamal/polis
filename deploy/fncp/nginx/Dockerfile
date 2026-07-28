FROM docker.io/library/nginx:1.30.4-alpine3.24-slim@sha256:ddde39c6e51f02fde7410c2e9c234cf2d0a4c7bdbbe176aeb37d8ad7ab4eb58c

# Disposable loopback QA boundary only. Production TLS/WAF/load balancing is a
# separate, unimplemented control; do not expose this image directly.
COPY nginx/fncp-staging.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
