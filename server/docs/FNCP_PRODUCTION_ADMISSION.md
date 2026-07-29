# First Nations Community Pulse production admission

The dedicated Option C server refuses to listen unless its full access
boundary is configured. This contract does not affect an ordinary upstream
Pol.is deployment: when `FNCP_OPTION_C_RELEASE_MODE` is absent, startup and the
optional FNCP middleware retain their existing behaviour.

## Exact startup contract

A dedicated production task must provide:

- `NODE_ENV=production`;
- `FNCP_OPTION_C_RELEASE_MODE=production`;
- `FNCP_GATEWAY_ENFORCEMENT=true`;
- `FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT=true`;
- the same valid conversation ID in
  `FNCP_GATEWAY_CONVERSATION_ID` and
  `FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID`;
- a 32–512 character base64url `FNCP_GATEWAY_SHARED_SECRET`; and
- a different 32–512 character base64url
  `FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL`.

Release builds must select the `fncp-production` target in
`server/Dockerfile`. That target immutably defaults
`FNCP_OPTION_C_RELEASE_MODE=production`; omission therefore selects the guarded
contract. An explicit empty, false or malformed runtime override is rejected.
The generic `prod` target and the Dockerfile's final upstream-production stage
remain non-dedicated for ordinary Pol.is.

Missing values, `false`, case variants, malformed values, mismatched
conversation IDs, invalid credentials and reused credentials all stop the
process before it opens its listening socket. Errors identify only the failed
configuration class and never print a conversation ID or credential.

The gateway and provider loaders also remain fail-closed at request time for a
dedicated production process. If either enforcement value changes from exact
`true`, the gateway responds unavailable and the provider policy refuses to
treat the conversation as unmanaged.

## Emergency shutdown

Never set either enforcement switch to `false` as an emergency action. That is
not a kill switch.

Use the operational containment sequence instead:

1. deny public ingress at the load balancer, WAF or network boundary;
2. revoke active invitations and remove their provider allowlist entries
   through the reviewed operator path;
3. preserve audit and incident evidence without logging credentials or XIDs;
4. repair and verify the exact production configuration; and
5. restore ingress only after the startup admission, provider readback and
   removed-XID tests pass.

If the admission contract fails, keep the service out of rotation. Do not
bypass the check or start the ordinary Pol.is configuration for the managed
conversation.
