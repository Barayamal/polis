# D14 — Private provider allowlist API evidence

Date: 29 July 2026
Status: source-complete for integration; production remains **HOLD**
Isolated parent source: `40015a249aef3122afcb3ddf7e9eba688ff6b06c`

## Outcome

The Pol.is fork now contains the provider-side half of the Option C invitation
boundary. It matches the Community Pulse authority client's reviewed contract:

- `POST /fncp/private/xid-allowlist/upsert`
- `POST /fncp/private/xid-allowlist/readback`
- `POST /fncp/private/xid-allowlist/remove`

All three operations are fixed-path, bearer-authenticated and bound to one
configured conversation. Upsert and removal are naturally idempotent set
operations. Stable operation keys are validated by operation, while the
authority retains their lifecycle ledger; write retries return an empty `204`.
Readback uses the primary
database pool and returns only the exact conversation ID, opaque participant
XID and presence boolean required by the authority's fail-closed comparison.

## Security boundary

- The adapter is outside the public `/api/v3` namespace.
- The FNCP Nginx participant proxy does not expose any adapter path.
- Disabled, incomplete or unauthenticated access returns a generic `404`.
- Browser origins, cookies, query parameters, extra body fields, malformed
  XIDs, non-JSON media types and wrong operation keys fail before storage.
- Database statements are parameterised and require the exact conversation to
  have `use_xid_whitelist = TRUE`.
- A same-owner XID already scoped to a different conversation is not moved.
- Removal changes only the exact conversation-scoped allowlist row. The
  six-route revalidation layer remains responsible for immediate warm-session
  denial.
- No credential, idempotency key or database error is returned or logged.
  Development request-body logging redacts every `/fncp/private/` body.
- The opaque XID is echoed only in the authenticated private readback because
  the authority must compare both scope fields before invitation issuance.
- The private bearer credential is generated into the ignored local staging
  environment and is not supplied to the browser/SSR participant service.

## Verification

The source batch includes:

- pure request-boundary unit tests;
- an in-memory HTTP contract test covering retry, readback and removal;
- a disposable PostgreSQL store integration test and an Express route
  integration test;
- a deployment/source-boundary test proving non-exposure and log redaction.

Local verification completed against the isolated source:

- server build and lint: passed;
- exact changed-file formatting: passed;
- complete non-database unit suite: 165/165 passed;
- disposable PostgreSQL adapter integration: 4/4 passed;
- deployment and source-boundary suite: 55/55 passed.

The full Express/OIDC integration test is authored for the retained integrated
stack. It was not executed in this isolated adapter batch because that trace
requires the complete disposable identity-provider topology; it remains an
explicit integration gate rather than being represented as local evidence.

No image was published, no registry login occurred, no cloud resource was
created and no service was deployed.

## Remaining integration gates

1. Merge this branch with the Community Pulse lifecycle and current dependency
   remediation heads.
2. Wire the authority's private origin and bearer credential through managed
   secret delivery; never expose either to participant code.
3. Run the disposable end-to-end
   `prepared → provider-allowlisted → issued → redeemed → revoked →
   provider-removed` trace against a retained exact-hash stack.
4. Prove response-loss recovery by retrying the same operation key and requiring
   exact primary readback before issuance.
5. Repeat removal plus all-six-route denial after a participant has a warm
   session.
6. Complete backup/restore, deletion, load, monitoring, incident and independent
   privacy/security testing before genuine onboarding.
