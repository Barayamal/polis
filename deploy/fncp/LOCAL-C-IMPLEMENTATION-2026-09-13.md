# Option C — local implementation evidence

**13 September 2026 · SYNTHETIC ONLY · Production and launch HOLD**

This is a newly executed local implementation, not a deployed voter service.
No external message, PR submission, commit, push, purchase, public edit, real
invitation or participant test was performed. Historical registration retention
and genuine participant records were not accessed.

## Source and environment

- Repository: a separate clone of `https://github.com/Barayamal/polis.git`.
- Baseline: `2898471efe889976670b09977ca6c08946dc04d9`.
- Local branch: `local/c-selfhost-20260913`; changes remain uncommitted/unpushed.
- Official source/guidance: [upstream Quick Start](https://github.com/compdemocracy/polis#quick-start), [configuration](https://github.com/compdemocracy/polis/blob/edge/docs/configuration.md), [branch workflow](https://github.com/compdemocracy/polis/blob/edge/docs/branch-workflow.md), [TLS](https://github.com/compdemocracy/polis/blob/edge/docs/ssl.md), [XIDs](https://compdemocracy.org/xid/), [single-use URLs](https://compdemocracy.org/creating-single-use-urls/).
- Checked upstream stable `6f1c395379af311a0f4c2c9c9ec8501c5e4d9a1c` and edge `ec966374909f4214605657963888413028fe9a0b`; fetched, not merged.
- Dedicated Colima profile `fncp-c-20260913`, Docker context `colima-fncp-c-20260913`: ARM64, 4 CPUs, 6 GB RAM, 40 GB data disk. Existing default context/profile was not repurposed.
- Built and ran six local services: PostgreSQL, OIDC simulator, Pol.is API, math worker, alpha client, nginx. Database has no published port; published service ports bind only to `127.0.0.1`.
- Server dependency tests/build: pinned Node22; alpha: pinned Node24; new SQLite harness: local Node26.

The dedicated server image uses `fncp-production` admission, but its name is not
production approval. Development OIDC, certificates, local networking and
synthetic credentials are not a production identity/infrastructure design.

## Implemented and repaired

1. Repaired unavailable exact Alpine package pins while retaining digest-pinned
   base images and existing BusyBox hardening.
2. Added the exact owner-approved fifteen seed statements; compared all text
   against the owner pack. Bootstrap binds the conversation and fifteen unique
   numeric statement IDs through one guarded environment-file replacement.
3. Gateway accepts votes only for that fixed manifest with the narrow numeric
   vote envelope. Missing/invalid manifest fails closed for voting. Suggestions
   and unapproved/native/direct participant routes remain blocked.
4. Added persisted synthetic round approvals, account-bound expiring/single-use
   invitations, hashed secrets/sessions and a narrow server-derived XID bridge.
   Mailbox authentication is explicitly simulated; no email/SMS implementation.
5. Added live local approval checks and ordered revocation: local denial first,
   then provider removal/readback. Local round closure invalidates local access;
   cross-store atomicity/provider-wide closure is not claimed.
6. Updated stale smoke assertions to the actual direct-route denials, exact
   fifteen seeds and stripped participant tokens. The trace no longer closes
   the shared synthetic conversation; it revokes only its own identity.
7. Added guarded synthetic backup/isolated restore and scoped allowlist cleanup.
8. Applied bounded server/alpha security updates, including Astro/adapters and
   compatible development-tooling patches; see the [dependency review](DEPENDENCY-REVIEW-2026-09-13.md).
9. Preserved safe upstream 400/403 errors through the local bridge without
   reflecting provider error text; other failures remain generic 503.

## Verification actually completed

Counts below identify separate commands/scopes. Do not add overlapping suites
to claim unique test coverage.

| Check | Result | What this establishes |
| --- | --- | --- |
| Six-service Docker build and startup | PASS | Executable local stack; not production readiness |
| Final patched server/alpha image rebuild and recreation | PASS | Runtime checks repeated on patched images |
| `node --test deploy/fncp/*.test.mjs deploy/fncp/local-access/*.test.mjs deploy/fncp/local-recovery/*.test.mjs` | **142/142 PASS** | Source/static, bootstrap, dependency, model invitation and recovery/cleanup boundary tests |
| Fresh Node22 server parsing/gateway/query-builder suites | **95/95 PASS** | Includes three new qs parsing regressions; not broad DB integration |
| Initial gateway/admission/fixed-statement HTTP middleware unit group | 94/94 PASS | Separate earlier targeted group; overlaps other gateway tests |
| Fresh Node24 alpha source/build-output boundaries | **6/6 + 3/3 PASS**, build PASS | Source and compiled-output checks, including no Sharp/private values in browser assets |
| `local-access/real-origin-smoke.mjs` | PASS on final images | Actual Pol.is approval/readback, synthetic account-bound invitation, expiry/forward/replay rejection, one synthetic vote, unknown-ID rejection, warm-session revocation |
| `smoke-test.sh` | PASS on final images | Exact fifteen-ID set; invalid TID/vote 400; suggestion API404/proxy405; native/direct vote403; revoked established identity403; no participant bearer export |
| Scoped synthetic allowlist cleanup | PASS | One orphan test entry revoked from an earlier failed trace; final independent scoped whitelist count zero; votes/statements unchanged |
| Synthetic PostgreSQL backup/isolated restore | PASS on final checkpoint | 62 tables, 427 columns, 116 indexes, 11 routines, 331 constraints, one known synthetic conversation, 15 known seeds and 21 vote rows matched after restore |
| Whitespace/syntax checks | PASS | `git diff --check` and relevant Node/shell syntax checks |

The 21 stored vote rows are **synthetic database rows, not a participant count**.
The checkpoint includes seed-related and test activity. No genuine participants
or responses are represented. Aggregate equality is not byte-for-byte recovery
verification. Only PostgreSQL was backed up/restored; the separate invitation
SQLite state and whole-service/production recovery remain outside that proof.

## Security audit outcome

Final npm package audits:

- Server production: **one moderate** (`csv-parse`), zero high/critical.
- Server full tree: one moderate plus **three high package findings** in the
  development-only nodemon → notifier → semver chain (one propagated advisory).
- Alpha production and full tree: **zero findings** at the fresh audit.

No automatic major upgrades or out-of-range notifier override were forced.
The CSV migration and notifier upgrade need separate compatibility review.
No complete image SBOM/OS/JVM vulnerability scan, signed release attestation,
production migration lifecycle test or required remote CI run was completed.
A package gate pass must not be described as whole-stack security clearance.

## Failures and corrective work

- First image build failed on packages no longer present at the old exact
  Alpine versions. Updated exact pins; rebuilt successfully.
- An early smoke assertion expected HTTP403 for a bare-XID alpha request; the
  real correct rejection was HTTP400. Corrected the test, not the access
  control. Its one leftover synthetic allowance was subsequently revoked and
  independently checked; no test vote/statement deletion was required.
- First recovery attempt failed before restoration. Retry succeeded before
  functional hardening, so the original cause remains unproven. Added precise
  failure stages, fixed redacted diagnostic codes and final-server TCP
  readiness instead of a temporary initialization Unix socket. Repeated
  isolated restores passed. The source database was never overwritten.
- Optional Rolldown WASM peer warnings remain; native ARM64 alpha builds and
  boundary checks passed. WASM fallback compatibility was not tested.

## Boundaries and remaining work

This is API-only synthetic proof. Still required: real authentication/account
recovery, scoped WordPress approval synchronisation, browser voter journey,
deployment-bound activation, durable provider retry/reconciliation and
distributed whole-round closure; restricted reporting/scoped deletion,
current-upstream review, full release security/CI and production operations.

The legacy broad DB suites were not run against this synthetic round: one
store suite resets tables and the API suite needs separate trusted-CA/user
fixture setup. The actual-origin tests above are the observed DB-backed path.

Self-attestation/round approval is not verified Indigenous heritage. No ancestry
documents are part of this implementation. The maximum-20/15-statement owner
scope and provisional October dates do not activate participation. PR #27 and
the existing Pol.is fork PR are not GO authority. Spending remains unapproved.

Source/image metadata is captured separately by `capture-local-proof.mjs` in
the ignored `evidence/local-wip-<timestamp>/` folder. It records dirty-tree
provenance and exact local image IDs, not release attestation. Source hashes
include uncommitted local work; baseline OCI revision labels alone are
insufficient to identify the patched images.

The runtime is stopped after the final evidence capture to release laptop
resources. Images, source, synthetic database and private synthetic backup
archives are retained locally. Only execution-owned temporary restore
containers/networks were removed. No public surface was changed or reopened.
