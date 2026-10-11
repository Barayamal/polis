# V3 operator-only loopback access

`FNCP_PRODUCTION_COMPOSE_V3` is the closed operator-access profile for the
self-hosted candidate. It preserves the V2 edge and internal service isolation.
A separate tenth image, `FNCP_OPERATOR_LOOPBACK_GATEWAY_V1`, publishes only:

```text
https://127.0.0.1:8443  participant edge
https://127.0.0.1:9443  WordPress staff administration
```

Both Docker bindings use host IP `127.0.0.1` and TCP. The gateway targets its own
ports8443 and9443, then forwards opaque TLS bytes only to `edge:8443` and
`wordpress:8443`. The destination services publish nothing and remain on
internal networks. The gateway holds no private material or durable state. The
bindings are not LAN or Internet listeners. Direct PostgreSQL, MariaDB, API, math,
participant-event and native Pol.is proxy ports remain unpublished.

## Safe operator procedure

1. Verify the saved `compose.json`, image lock, source lock and
   `operatorAccessSha256` against the approved closed candidate.
2. Start with admission closed. Confirm Docker reports only the two exact
   loopback bindings on the operator gateway, no binding on edge/WordPress, and
   no `0.0.0.0`, `::`, random or extra binding.
3. On the host, connect to the participant edge on port8443 and the WordPress
   staff interface on port9443 using the separately trusted candidate CA and
   expected hostname. Do not bypass TLS verification.
4. If remote staff access is approved later, use a separately reviewed,
   authenticated tunnel that forwards to these loopback ports. Do not change
   Compose to a wildcard host address.
5. Keep participant admission closed until the exact activation challenge,
   synthetic negative/positive journey, recovery rehearsal and launch decision
   are separately approved.

The profile creates no tunnel, DNS, public certificate, identity-provider app,
firewall rule or participant invitation. A loopback probe is deployment evidence,
not authorization to expose, activate or open the service.
