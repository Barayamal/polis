FROM docker.io/library/nginx:1.30.4-alpine3.24@sha256:97d490c12ba55b4946b01546d1c3ed324e8d41ab1c9fcb2a616aa470620e5b46

# Disposable loopback QA boundary only. Production TLS/WAF/load balancing is a
# separate, unimplemented control; do not expose this image directly.
COPY nginx/fncp-staging.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
