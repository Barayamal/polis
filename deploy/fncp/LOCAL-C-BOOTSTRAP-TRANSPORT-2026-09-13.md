# Option C — bootstrap HTTPS and database contract

> Portability note — 7 October 2026: workstation paths were removed, and artifacts outside this source snapshot are labelled retained local evidence. Dated results below remain historical; this edit adds no runtime or release claim.

Checkpoint: **2026-09-13T22:50:43+10:00. LOCAL_ONLY / KEEP_CLOSED.**

This increment connects the existing bootstrap protocol to a real bounded HTTPS
client and adds a source-derived, read-only database query contract. These are
implementation steps toward self-hosting, **not a complete runnable stack**.
Actual TLS requests in the tests reach newly created synthetic API fixtures;
they do not reach Pol.is, WordPress, Docker or a database.

## What changed

- [HTTPS transport](./fresh-runtime/bootstrap-http.mjs): only canonical literal
  loopback HTTPS, explicit certificate trust, normal IP-SAN verification plus an
  exact leaf-certificate pin checked before bearer release. No redirects, proxy,
  cookies, arbitrary per-request routes, credential refresh or automatic retries.
- [Issuer handoff](./fresh-runtime/bootstrap-issuer.mjs): the transport accepts a
  live factory-branded issuer and consumes its single invented-subject token.
  Fabricated/copied issuer objects or caller-supplied tokens are not accepted.
- [Protocol lineage and cancellation](./fresh-runtime/bootstrap-protocol.mjs):
  active private requests carry an opaque per-run scope and cancellation signal.
  One client cannot mix two bootstrap runs. Cancellation or client close rejects
  pending work; a two-second whole-send deadline covers ownership callbacks,
  TLS, headers, body and final checks. Late completion cannot dispatch or grant
  success. These bounds are event-loop timers, not hard real-time guarantees.
- [Database contract](./fresh-runtime/bootstrap-database-contract.mjs): fixed
  parameterized SELECT descriptors for required catalog objects and one
  conversation-scoped closed-state/seed-vote baseline. Validators reject forged
  descriptors, incomplete output and unexpected aggregate values. No connection
  or SQL execution is implemented by this module.

The client has a 19-request ceiling for the existing sequence: create, fifteen
seed inserts, seed readback, close/XID-gate update and conversation readback. Its
response limit is 65,536 bytes with strict UTF-8 decoding. JSON/domain validation
remains in the protocol. Failures during an admitted send are sanitized and latch
failure; uncertain requests cannot be retried through this client. Concurrent or
duplicate attempts are rejected without changing an already admitted request.

The runtime manager must supply the exact owned endpoint/certificate and a
trusted `assertOwned` callback. That callback is checked before and after I/O but
**is not independent Docker ownership evidence or a sandbox**. There is no
default helper launcher. Tests explicitly supply model ownership; a successful
TLS handshake does not prove an approved image, correct database, no egress or
safe process lifecycle. A timed-out trusted callback may still be running; it
must not be described as successful cleanup.

Client close denies transport and aborts its pending request; it does not stop
the helper or close the issuer. Their separate owner must do both. Issuer closure
still does not revoke a token verified with cached keys before its short expiry.

## Database evidence stays separate

The catalog contract checks required public tables, column types/nullability,
keys, ID-trigger signatures and vote-rule presence in PostgreSQL17 inside a
read-only transaction. Presence is **not** full migration validation, proof of
function/rule bodies, permissions, schema ownership or application readiness.

The baseline contract expects one closed conversation, its owner/participant,
fifteen fixed-seed IDs, **15 raw vote rows and 15 latest-unique rows**, all seed-owner
Pass votes, and no applicable allowlist/XID/provider-operation rows. Legacy
owner-level entries are included in the applicable-entry checks. Statement texts
and the exact invented OIDC subject require separate existing API/identity checks.
The SQL uses a single snapshot and returns aggregate fields only; parameters and
descriptors remain private. No current or historical database was queried.
SQL parsing/PostgreSQL acceptance has not been verified; only source-contract
and result-validator tests ran. The existing application pool's `isReadOnly`
label does not start a READ ONLY transaction, and its database-SSL branch uses
`rejectUnauthorized:false`. Neither is suitable evidence for the future isolated
executor's read-only or certificate-verification guarantees; do not copy those
settings as a shortcut.

## Verification

- Node26.8.2: **1,735/1,735 PASS**, 24,014.212542ms.
- Node24.21.0: **1,735/1,735 PASS**, 23,741.216209ms.
- Both: zero failures, cancellations or skips. **65 new tests are included**, not
  additional:37 HTTPS,23 database-contract,3 issuer-handoff and2 protocol tests.
  The fresh-runtime subset is217 overlapping tests.
- PHP: **59 PASS** across23 identity,23 journal and13 plugin stub/model checks.
- The complete positive model journey made19 real HTTPS requests, verified19
  JWTs from one synthetic credential, and performed57 trusted ownership callback
  checks. These are not independent Docker ownership checks. Both TLS1.2/1.3 are
  allowed; the suite does not establish both were independently exercised.
- Negative tests cover wrong CA, an otherwise valid CA-signed alternate leaf
  before any HTTP request, redirects, oversized/invalid/truncated bodies,
  cross-run/replay denial, cancellation and cumulative whole-send timeout.
  Review fixed a BOM/Unicode-whitespace normalization edge case; the final
  regression rejects those responses before seed creation.
- Eight current source/test files total158,916 bytes with SHA-256 inventory.
  The separate limited27-file/230,564-byte proof graph still matches its pins.
  Neither inventory is a complete release closure or runtime/deployment approval.
- Independent review confirms all eight current hashes and27 limited-graph pins,
  with both limited-graph digests unchanged. All152 local links checked across
  the current repo/owner documents resolve; `git diff --check` passes.

Aggregate test evidence (retained local evidence, `evidence/bootstrap-transport-continuation-2026-09-13.json`; not included in this source snapshot)
and current source inventory (retained local evidence, `evidence/bootstrap-transport-source-closure-2026-09-13.json`; not included in this source snapshot)
record the result. Earlier22:21 source inventories are historical; the protocol
and issuer files changed in this increment. Fresh test listeners/fixtures were
cleaned up by their owners. Known fixed staging ports and Colima were not rechecked.

## Next steps — practical order

1. **Finish the fresh runtime manager.** Bind these components to a separately
   reviewed ordinary bootstrap image and exact new container/database IDs.
   Implement the actual ownership callback and bounded SQL executor with a fixed
   search path/read-only transaction. Do not use this client against retained
   services or treat a caller's `true` assertion as image/network approval.
2. **Complete image and startup inputs.** The ordinary image remains unpinned;
   the dedicated gated image is not a substitute. Resolve fresh schema/startup,
   the Auth0 ManagementClient constructor inputs, container-reachable issuer/JWKS
   and scoped certificate trust. Keep mail, translation and other external
   integrations disabled. Do not turn off dedicated access gates to bootstrap.
3. **Prove local topology before application mutation.** Verify exact images and
   fresh ports, host/container reachability and negative egress. The earlier
   Colima/internal-bridge publishing conflict remains unresolved; no unrestricted
   bridge fallback, retained VM restart, image pull/build or resource adoption is
   implied by this report.
4. **Run the actual synthetic journey.** New databases/keys/invented identities
   only: actual bootstrap IDs and raw/latest seed baselines, closed readback,
   exact helper stop, then a separately guarded active transition for synthetic
   QA. Join real fresh WordPress decisions/outbox, strict access and Pol.is;
   verify rightful redemption, forwarded-link denial, selective and terminal
   warm revocation, recovery and cleanup in the browser.
5. **Keep production decisions separate.** C remains the selected direction;
   C1/C2/C3 are unselected, totals NOT COSTED and approved spending A$0. No choice
   is needed to continue shared local source work. Hosting, real identity,
   delivery, public changes and launch need their own evidence and approvals.

No external correspondence, publication, submission, deployment, participant
test, retention operation, repository commit/push/PR, remote CI or spending took
place. Public Pulse/results/WordPress/fallback surfaces were not changed or
freshly inspected. No Docker/Colima, native browser or WordPress-download checks
were rerun. Retained configuration, keys, archives and stores were not opened.
Only new synthetic test certificates/fixtures/listeners are used and cleaned up.

The owner guide (retained local evidence, `C-SELF-HOSTING-GUIDE.md`; outside this repository)
and [fresh integration plan](./LOCAL-C-FRESH-RUNTIME-PLAN-2026-09-13.md) remain the
working path. Historical start/stop commands are not fresh-run instructions.

Official references: [Pol.is self-hosting/source instructions](https://github.com/compdemocracy/polis/blob/stable/README.md),
[configuration](https://github.com/compdemocracy/polis/blob/stable/docs/configuration.md),
and [JWT middleware source](https://github.com/compdemocracy/polis/blob/stable/server/src/auth/jwt-middleware.ts).
The latter two were re-read for this increment. Upstream guidance is the technical
basis, not certification of Barayamal's custom voter-access controls.
