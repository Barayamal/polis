# FNCP logging and disabled-route boundary

When `FNCP_GATEWAY_ENFORCEMENT=true`, the dedicated First Nations Community
Pulse origin exposes only the six participant capabilities declared in
`fncp-gateway.ts`.

`POST /api/v3/joinWithInvite` is not one of those capabilities. The gateway
middleware returns `404` before `hybridAuthOptional`, parameter middleware, or
the join handler can authenticate, map, create, or join a user. This applies
regardless of whether the request carries:

- no XID;
- an allowlisted or removed XID;
- a `suzinvite`; or
- a valid but previously unseen OIDC identity.

The FNCP logging boundary runs before development access logging and body
parsing. It structurally omits FNCP body, query, request-state, error, identity,
session, invitation, and private-header material before log transports.

## Conservative POST diagnostic suppression

While enforcement is enabled, the early boundary cannot inspect an unparsed
JSON body to determine its conversation safely. It therefore suppresses
request diagnostics for **every** `POST` to:

- `/api/v3/comments`;
- `/api/v3/votes`; and
- `/api/v3/joinWithInvite`.

This can reduce diagnostics for an ordinary non-FNCP comments or votes request
on the same dedicated server. It is an intentional P2 observability trade-off:
privacy and fail-closed isolation take priority over retaining request-level
diagnostics. Ordinary upstream behaviour is unchanged when enforcement is off.
