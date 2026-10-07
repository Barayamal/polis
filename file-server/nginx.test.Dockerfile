# Disposable legacy CI proxy only. The inherited nginx/TLS configuration is
# compatibility test infrastructure, not an FNCP production release candidate.
# This is the same base resolved by the failed CI jobs, fixed by index digest.
FROM docker.io/library/nginx:1.21.5-alpine@sha256:eb05700fe7baa6890b74278e39b66b2ed1326831f9ec3ed4bdc6361a4ac2f333

COPY nginx/nginx-ssl.site.default.conf /etc/nginx/conf.d/default.conf.template
COPY nginx/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod 0555 /docker-entrypoint.sh && mkdir -p /etc/nginx/certs

# Leaf certificate and private key arrive through read-only runtime mounts.
# No certificate, key, CA or generated credentials are copied into this image.
EXPOSE 80
EXPOSE 443
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
