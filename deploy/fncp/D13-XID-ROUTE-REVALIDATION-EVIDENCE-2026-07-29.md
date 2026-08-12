# FNCP Option C D13 six-route XID revalidation — 29 July 2026

## Decision

This change is a **qualified GO for further synthetic Option C staging only**.
It is not a production approval, registry artifact, cloud deployment or live
participant service. Production remains **HOLD / NO-GO**.

No genuine registration, eligibility record, invitation, identity, vote or
statement was used. No package registry, image registry or cloud service was
contacted.

## Problem corrected

The retained FNCP participant surface contains six method-and-route
capabilities. Four already reached the XID allowlist check indirectly through
participant middleware. Two read routes—comments and math/PCA—did not have an
equivalent explicit guard in their route chains.

Relying on different implicit paths made revocation coverage difficult to
prove and could allow a removed XID to retain read access on those two routes.

## Implemented boundary

One reusable route guard now runs after hybrid authentication, conversation
resolution and XID parsing, and before each handler:

| Capability | Explicit revalidation |
|---|---:|
| `GET /api/v3/comments` | Yes |
| `GET /api/v3/math/pca2` | Yes |
| `GET /api/v3/nextComment` | Yes |
| `GET /api/v3/participationInit` | Yes |
| `POST /api/v3/comments` | Yes |
| `POST /api/v3/votes` | Yes |

For an XID-allowlisted conversation, the guard:

- uses the authenticated XID JWT claim for an already-warm participant when
  present, rather than trusting a conflicting request parameter;
- validates that XID against the resolved internal conversation and owner;
- rejects missing and non-allowlisted XIDs with `403`;
- sets `Cache-Control: no-store` on those access-denied responses;
- passes unexpected lookup failures to the global error handler without
  continuing to the route handler; and
- records a request-local, internal-zid marker only after the check succeeds.

The existing check inside `ensureParticipant` remains as defence in depth for
any caller that does not install the explicit guard. On a guarded route, the
success marker prevents a duplicate allowlist lookup for the same request and
internal conversation.

Non-XID participant JWTs cannot satisfy the guard on an allowlisted
conversation. A conversation without XID allowlisting retains its existing
public behaviour after the conversation configuration read.

No new public or administrator API was added.

## Verification completed

- `node --test deploy/fncp/deployment-boundary.test.mjs`
  - **7/7 passed**
  - locks the exact six server route chains to hybrid auth, XID parsing and the
    explicit revalidation guard;
  - retains the five exact proxy locations and six method capabilities.
- Focused Jest unit suites:
  - **32/32 passed** across the XID guard and private-origin gateway suites;
  - the 16 XID-guard cases cover fresh allowlisted access, missing XID, removed
    warm JWT XID, authenticated-claim precedence, non-XID bypass denial,
    unexpected lookup failure and no duplicate database lookup after the route
    guard;
  - the 16 gateway cases retain exact-route, secret, conversation, alias,
    identity-conflict, cookie and unused-route denial coverage.
- TypeScript production build: **passed**.
- ESLint: **passed**.
- `git diff --check`: **passed**.

The test dependency tree was reused from an already-installed sibling local
worktree. No dependency installation or network access occurred.

## Integration coverage authored

The disposable PostgreSQL/OIDC integration suite now defines all-six-route
matrices for:

1. a fresh, never-allowlisted synthetic XID; and
2. an established synthetic participant immediately after its XID is removed.

Every route must return a non-cacheable `403
polis_err_xid_not_allowed`; staff OIDC access must remain available.

That database-backed suite was **not executed in this isolated batch** because
no disposable PostgreSQL/OIDC test stack was running and this task did not
authorize pulling or creating replacement infrastructure. It must pass on an
exact retained stack before merge or image rebuilding.

## Remaining gates

1. Run the expanded integration suite on a disposable retained stack and
   record all twelve denied route results plus the staff-control result.
2. Run the integrated gateway → authority → private Pol.is browser trace,
   including voting, statement submission, lost-response recovery, revocation
   and zero-data cleanup.
3. Rebuild the exact release images and repeat checksums, SBOMs and unsuppressed
   scans for the final source hash and target architectures.
4. Complete backup/restore, scoped deletion, monitoring, load, incident and
   independent security/privacy exercises.
5. Keep genuine participants, registry publication and Australian cloud
   deployment out of scope until separately approved and all production gates
   pass.
