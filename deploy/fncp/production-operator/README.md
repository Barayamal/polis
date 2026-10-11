# Operator loopback gateway

`FNCP_OPERATOR_LOOPBACK_GATEWAY_V1` is the V3-only opaque TCP bridge between
Docker's host-publishable bridge and the otherwise internal participant edge and
WordPress networks. Docker documents that an `internal: true` network has no
connection to host interfaces, so publishing directly from the V2 internal
networks does not create a usable host route.

The gateway is a tenth, independently locked ARM64 image. It publishes only
`127.0.0.1:8443` and `127.0.0.1:9443`, forwards opaque bytes only to
`edge:8443` and `wordpress:8443`, and holds no TLS key, cookie, participant data,
database credential, activation authority or durable volume. TLS continues to
terminate at the destination service, so the operator must still verify the
reviewed hostname and trust chain.

The container runs as UID/GID1000, read-only, with all capabilities dropped,
`no-new-privileges`, a64PID limit,128MiB memory, half a CPU and a small private
tmpfs. Each route permits at most32 concurrent connections and a60-second idle
period. The application services remain only on internal networks; only this
credential-free fixed bridge joins `operator_access`.

This is local operator reachability, not public ingress or launch approval. A
remote operator still needs a separately reviewed authenticated tunnel to the
host loopback ports. See
[OPERATOR-LOOPBACK.md](../production-deployment/OPERATOR-LOOPBACK.md).

Relevant upstream references:

- Pol.is self-hosting: <https://github.com/compdemocracy/polis/blob/stable/README.md>
- Pol.is TLS guidance: <https://github.com/compdemocracy/polis/blob/stable/docs/ssl.md>
- Docker internal networks: <https://docs.docker.com/compose/how-tos/networking/#internal-networks>
- Docker loopback publishing: <https://docs.docker.com/engine/network/port-publishing/>
