FROM docker.io/nginx:1.21.5-alpine

# Disposable loopback QA boundary only. Production TLS/WAF/load balancing is a
# separate, unimplemented control; do not expose this image directly.
COPY nginx/fncp-staging.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
