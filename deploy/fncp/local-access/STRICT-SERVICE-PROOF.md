# Strict local HTTP profile and private operator capability

This is a local synthetic service boundary, not production operator authentication,
an approval to open a round, real identity integration or a deployable release.
No public surface, retained store, Docker stack, email or participant is involved.

## HTTP profile

`createLocalAccess` accepts an optional `httpProfile: 'strict-service'` only with
`identityMode: INTEGRATED_IDENTITY_MODE`, its trusted identity foundation and a
mandatory activation admission guard. Every other supplied profile is rejected.
The profile is fixed when the service is created; HTTP inputs cannot change it.

All HTTP paths beginning with `/test-admin` or `/test-auth` are denied in this
profile, including when the caller knows the old test administrator bearer.
The policy is applied before reading the body. Health, bound invitation redemption,
participation and logout retain their existing loopback and request-level controls.
The absent/default profile deliberately retains legacy proof behavior. This does
not silently convert either standalone legacy launcher into the strict service.

## Private capability

Only the strict profile returns a frozen `app.operator` object with these methods:

| Method | Result and boundary |
| --- | --- |
| `await operator.status()` | Existing aggregate synthetic status; available while the authority is closed, but not after service shutdown begins. |
| `await operator.setRoundOpen(open)` | Exact Boolean required. Opening still requires current signed activation; explicit closure invalidates current authority and invitations. |
| `await operator.issueInvitation(fixture)` | Exact opaque mapped fixture string from the verified-identity path. Requires the same current identity, signed WordPress approval, active authority and open round as before. Fixed existing 600-second default; local response only. |

Each returns the existing domain result, not an HTTP response/status tuple.
Extra arguments are rejected. These operations share the existing 32-operation
admission cap and single-process queue with HTTP, identity and signed-event work.
New operations fail once shutdown begins; previously admitted operations drain.
There is no public raw dispatch, fixture creation, direct approve/revoke, signing,
identity injection, account lookup or arbitrary invitation lifetime capability.

The capability itself is authority: keep it inside trusted server composition and
never return it to a browser, deserialize it from a request or expose a generic
HTTP bridge to it. This patch does not supply operator login, MFA, audit custody,
invitation delivery or permission to call its positive actions on a real system.

The HMAC-verifying WordPress receiver continues to call private
`ingestWordPressEvent`. Its serialized, schema-checked event gate retains the
existing approval/revocation logic. Removing HTTP test routes must not bypass that
gate or make a signed identity an eligibility approval. Self-attestation and round
approval are not Indigenous heritage verification.

## Verification

The 31 focused tests pass on Node 24.21.0 and 26.8.2:

```sh
node --test deploy/fncp/local-access/strict-service-profile.test.mjs
```

Coverage includes invalid configuration, unchanged default profiles, 12 blocked
test-route prefixes with GET and POST plus the correct bearer, the exact three
private methods, strict inputs, closed startup, independently signed activation,
separate open, signed-event approval/revocation, invitation replacement/account
binding, lease expiry, new-generation invalidation, shared queue capacity and
shutdown admission/drain. The shutdown test independently checks its owned port is
refused. A related 193-test access/activation/integrated regression run also passed
on Node 26.8.2. These counts overlap and must not be added as unique tests.

Tests use in-memory SQLite/activation ledgers, explicit fake identity capabilities,
a model Pol.is provider and fresh ephemeral HTTP listeners only. They do not claim
real-provider conformance, browser rendering, network isolation beyond loopback,
production identity/activation, reviewed hosting or production readiness.
