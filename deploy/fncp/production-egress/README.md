# Fixed OIDC relay foundation

This local foundation restricts each TCP listener to one preconfigured numeric
destination. It does not complete roadmap Step 02 or enable egress in Compose or
the closed installer. The production participant must remain on internal networks
when this is integrated.

`createProductionEgressPolicy({tokenEndpoint,jwksUri,targets:{token,jwks}})` in
`policy.mjs` creates an immutable, hashed descriptor. Endpoints are exact HTTPS
URLs on port 443. Targets are conservative public numeric IPv4/IPv6 addresses;
DNS names, private/special-purpose destinations and alternate ports are rejected.
Token and JWKS listeners are fixed at 8445 and 8446. A changed IP pin or endpoint
changes the policy hash and must close admission and require new qualification.
`validateProductionEgressPolicy` reconstructs and verifies a saved descriptor;
copied objects do not themselves carry constructor authority.

`createFixedOidcRelay({policy,listenHost,timeoutMs?})` in `relay.mjs` accepts only
an object issued by those validators. Its bind address must be an explicit RFC1918
IPv4 address on the private participant-to-relay network. Wildcard and loopback
bindings are unavailable in that constructor. `start()` returns actual listeners;
`snapshot()` returns aggregate connection counters; `close()` permanently drains
both listeners and all connections. Only the relay may join an external network.
The relay must mount no participant, WordPress, database or activation credentials.

The relay forwards opaque bytes. It has no CONNECT/SOCKS protocol, resolver,
caller-selected target, TLS termination or payload logging. There are at most 32
active connections, an absolute deadline of at most five seconds per connection,
and a 128 KiB cap in each direction. HTTP body/header limits and verified provider
hostname/CA/SNI remain the responsibility of the existing OIDC HTTPS transport.
It must preserve the provider hostname while connecting to the relay and must
never fall back to direct egress when the relay is unavailable.

This proves fixed numeric destinations, not a hostname/path firewall: shared
provider/CDN IPs can host other names. A host firewall must independently restrict
the relay's actual outbound IP:443 destinations and block all application egress;
no kernel-level egress enforcement is claimed here. Review the selected provider's
IP-change process before staging. No real provider has been contacted or verified.
Compose/service binding, material custody, effective network/firewall inspection,
the installer, credential renewal, joined recovery and real provider compatibility
remain outstanding. The transport route's policy hash must be matched to these
exact endpoint/target policy bytes by that future staging boundary; a syntactically
valid hash alone proves no deployment or network policy. No exact full candidate
has been qualified by these standalone fixtures.

Run local fixtures with `node --test deploy/fncp/production-egress/*.test.mjs`.
`test-support/synthetic-relay.mjs` has a separate profile and branded constructor
for random loopback ports. A synthetic policy is rejected by the production relay
and production descriptor validator; it cannot authorize external destinations.
