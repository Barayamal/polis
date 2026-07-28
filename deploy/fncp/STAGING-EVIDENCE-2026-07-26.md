# Option C disposable staging evidence — observed through 28 July 2026

Status: **local synthetic-data staging only — not production approved**

## Evidence summary

| Check                                   | Result                                                                                                                                                                          |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Upstream Pol.is baseline                | Pinned to `424dcae02f0147723a19103dd2d971f6ec1b6db5`                                                                                                                            |
| Original focused automated tests        | **PASS** — 22 unit tests and 4 integration tests                                                                                                                                |
| Current server source                   | **PASS — bounded checks** — build, lint and 19 focused tests passed; error middleware now follows every asynchronously installed route; actual Express-stack timeout returns `408` JSON |
| Key-free server unit invocation         | **PARTIAL** — 97 passed; 12 known database-configuration/JWT-key fixture failures; not a whole-suite pass                                                                        |
| Pre-correction minimum-route integration | **PASS** — all 9 disposable PostgreSQL/OIDC cases, including standard staff OIDC/JWT compatibility; corrected source requires an exact rerun                                    |
| Participant alpha checks                | **PASS** — 124 Jest tests, lint, production build, 3 source-boundary tests and 2 built-output boundary tests                                                                    |
| Dependency-audit parser                 | **PASS** — 6 tests                                                                                                                                                              |
| Local staging configuration             | **PASS**                                                                                                                                                                        |
| Post-correction cold-start access matrix | **PASS** — rebuilt server image; synthetic conversation closed; allowlisted XID `200`; missing XID `403`; invalid XID `403`; OIDC bypass attempt `403`; removed XID `403`; warm session after removal `403` |
| Cold-start handoff                      | **PASS** — helper validates and copies the two disposable participant JWT keys into the created server container; smoke waits up to 45 seconds for bounded API readiness       |
| API transport simulation                | **PASS** — every Pol.is API request in the local smoke supplies `X-Forwarded-Proto: https`; a non-GET write without that signal returns `400` without continuing middleware      |
| Pre-correction participant surface      | **PASS IN THE EXACT DISPOSABLE STACK** — only six alpha-used routes remain; nine unused/optional routes, HEAD aliases and notifications are denied; corrected-source browser trace remains |
| Minimal component path                  | **PASS — local source/build contract** — administration, legacy-participant, report and full file-server bundles are excluded from the FNCP Compose path                         |
| Math image build                        | **PASS** after prefetching its required dependency in `math/Dockerfile`                                                                                                         |
| No-load local runtime snapshot          | Approximately **1.21% CPU** and **1.09 GiB memory**; this is not a load test or capacity result                                                                                 |
| Six Node production-tree audits         | **BLOCKED** — the current six-tree component snapshots contain 73 vulnerable package groups before cross-lockfile deduplication: 11 low, 22 moderate, 32 high and 8 critical    |
| Minimal API-server audit after D7        | **IMPROVED, STILL BLOCKED** — 27 vulnerable groups: 1 critical, 4 high, 16 moderate and 6 low; Express/Connect is removed and no direct critical/high finding remains            |
| Exact-image/SBOM production gate        | **BLOCKED** — mixed D7/D6 WIP composite contains 24 Critical and 125 High observations; the corrected server was rebuilt and smoke-tested but its earlier SBOM/scan is stale     |
| Disposable data and secrets             | **SYNTHETIC AND LOCAL ONLY** — generated environment, certificates, JWT keys, conversation and identities are disposable; no genuine participant data or cloud deployment was used |

The clean cold-start test used one disposable local conversation and synthetic
identities only. The helper failed closed unless both generated signing keys
were present, copied those keys into the newly created server container
without adding them to an image, and then started the loopback-only stack. The
API smoke waited for at most 45 seconds and supplied the secure reverse-proxy
signal expected by the server. It closed the synthetic conversation before
reporting success. Release review then moved `globalErrorHandler` after every
asynchronously installed route and corrected the trust-proxy description to
the actual one-hop setting. The corrected server image was rebuilt from that
source and the complete cold-start matrix passed again before the disposable
stack, volume, certificates, signing keys and environment were purged.

No hosted or production conversation was changed, no service was made publicly
accessible, no cloud resource was created, and no genuine registration,
eligibility evidence, invitation, vote or statement was used.

## Decision

This evidence shows that the bounded local stack builds and that the tested
XID revocation path failed closed in the recorded cold-start API matrix. The
participant alpha keeps gateway credentials server-side and uses same-origin
browser paths. The positive provider surface is now limited to the six routes
called by the pinned alpha; the unused `participants_extended` bridge was
removed, and the end-of-statements state no longer displays or calls an email
subscription form. All 9 exact disposable PostgreSQL/OIDC cases passed,
including standard staff authentication, on the preceding candidate. The
corrected source has repeated the cold-start access matrix, but the broader
nine-case integration has not been rerun; neither result authorises a live
deployment.

Production gateway hardening remains a separate workstream. Do not expose the
gateway or treat the staging access matrix as production assurance until the
remaining direct dependency blockers are resolved, the authoritative
authorization service and private gateway adapter are integrated, and the
exact corrected release passes the remaining integration, a disposable
real-browser trace, fresh image/SBOM scan,
backup/restore, deletion, monitoring, load and operational review.
