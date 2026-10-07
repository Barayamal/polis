# Joined-install synthetic journey actor

This separate privileged **QA-only** process controls no production service and
is never copied into a normal runtime image. It uses invented identities, one
synthetic WordPress operator, native HTTPS requests and the normal private
operator socket. It creates18 participants and270 vote responses following the
included15-statement/three-cohort fixture. Direct database readback and math
analysis remain the runtime controller's separate responsibilities.

The controller stages these five files and exact copies of the current
`production-activation/offline-sign.mjs` and `protocol.mjs` into a private owned
QA volume mounted at `/run/qa`, UID1000, directory0700/files0600. The participant
image supplies the ordinary operator client at `/app`. The QA actor mounts
participant state for private IPC and read-only ledger inspection; it must never
be adopted as an ordinary normal service. The actor needs core + participant
edge network membership so its fixed `qa-issuer:8443` is reachable by the normal
participant and its HTTPS client can reach `edge:8443` and `wordpress:8443`.
The controller owns helper/volume cleanup and full runtime observations.

Run `node /run/qa/owner.mjs` with a persistent stdin. First line is private JSON:

- `profile: "FNCP_JOINED_INSTALL_QA_OWNER_V3"` for V3 deployments;
  `FNCP_JOINED_INSTALL_QA_OWNER_V2` remains supported for V2.
- `issuer`: same explicit standalone invented provider configuration as
  `createStandaloneQaIssuer`; profile `FNCP_NORMAL_MAIN_QA_IDP_V1`, origin
  `https://qa-issuer:8443`, host `0.0.0.0`, port8443, clientId `fncp-main-qa`,
  callbackUri `https://pulse.synthetic.invalid/oidc/callback`, TLS key/cert,
  ES256 signing key, clientSecret and separate ownerKey.
- `issuerCa`, `edgeCa`, `wordpressCa`: exact CA PEM strings.
- `operatorPassword`: synthetic `qa_operator` password (43 base64url chars).
- `activationPrivateKey`: offline QA Ed25519 key, never normal material.
- `expectedBinding`: deploymentId, conversationId, sourceRevision and exact
  distinct image IDs: ten for V3 (including `edge` and `operator`) or nine for
  V2 (including `edge`). V3 also requires `operatorAccessSha256`.

After `READY`, send one JSON command per line: `{"action":"prove"}`, then
`{"action":"close-admission"}`, optional `{"action":"snapshot"}`, and
`{"action":"stop"}`. The controller must explicitly open the native Pol.is
round through reviewed maintenance before `prove`, close it after the actor's
closure, and stop every normal service before joined backup/renewal.

Participant requests connect only to `edge:8443` while preserving public
`Host`, `Origin` and verified TLS SNI `pulse.synthetic.invalid`. Tests reject
private routes, injected authority, unknown cookies and anonymous voting; spoofed
forwarding metadata remains unauthenticated. The main flow covers OIDC login,
declarations, pending native WordPress registration, nonce/anonymous staff
rejections, activation binding, durable event retry, approval, account-bound
invitation, voting, terminal warm-session revocation, and warm-session denial
after closure. No `qa_observer` account is expected or created.

The QA actor saves private vote expectations, held browser state and the recovery
descriptor into its owned QA volume. Output includes only checkpoints, counts,
route/status/timing observations and generic failures; private state must remain
private and be removed after the controller extracts redacted evidence.
Successful V3 proof reports `actualTenImageActivationBinding`; V2 retains
`actualNineImageActivationBinding`. Neither field is reported for the other
version.

These are HTTP/TLS protocol checks, not real-browser, real-mailbox or external
staging proof. The runtime controller must preserve failed attempts and must not
retry uncertain votes. Nothing sends invitations or external messages.
