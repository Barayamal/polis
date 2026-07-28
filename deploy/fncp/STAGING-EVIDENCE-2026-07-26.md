# Option C disposable staging evidence — observed through 28 July 2026

Status: **local synthetic-data staging only — not production approved**

## Evidence summary

| Check                                   | Result                                                                                                                                                                          |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Upstream Pol.is baseline                | Pinned to `424dcae02f0147723a19103dd2d971f6ec1b6db5`                                                                                                                            |
| Original focused automated tests        | **PASS** — 22 unit tests and 4 integration tests                                                                                                                                |
| Current server source                   | **PASS** — 39 focused dependency/access tests, TypeScript build and lint                                                                                                        |
| Exact current minimum-route integration | **PASS** — all 9 disposable PostgreSQL/OIDC cases, including standard staff OIDC/JWT compatibility                                                                              |
| Participant alpha checks                | **PASS** — 124 Jest tests, lint, production build, 3 source-boundary tests and 2 built-output boundary tests                                                                    |
| Dependency-audit parser                 | **PASS** — 6 tests                                                                                                                                                              |
| Local staging configuration             | **PASS**                                                                                                                                                                        |
| Disposable access smoke matrix          | **PASS** — allowlisted XID `200`; missing XID `403`; invalid XID `403`; OIDC bypass attempt `403`; removed XID `403`; warm-session request after XID removal `403`              |
| Participant provider surface            | **PASS IN THE EXACT DISPOSABLE STACK** — only six alpha-used routes remain; nine unused/optional routes, HEAD aliases and notifications are denied; browser traces remain         |
| Minimal component path                  | **PASS — local source/build contract** — administration, legacy-participant, report and full file-server bundles are excluded from the FNCP Compose path                         |
| Math image build                        | **PASS** after prefetching its required dependency in `math/Dockerfile`                                                                                                         |
| No-load local runtime snapshot          | Approximately **1.21% CPU** and **1.09 GiB memory**; this is not a load test or capacity result                                                                                 |
| Six Node production-tree audits         | **BLOCKED** — the 26 July six-tree snapshot has 154 component package-findings before cross-lockfile deduplication: 14 low, 59 moderate, 63 high and 18 critical                 |
| Minimal API-server audit after D1        | **IMPROVED, STILL BLOCKED** — 94 findings: 9 critical, 27 high, 48 moderate and 10 low; direct critical/high packages remain                                                     |
| Remaining dependency surfaces           | **NOT YET AUDITED** — base/OS images, nginx, PostgreSQL, JVM/Clojure, generated-bundle reachability and an image/SBOM scan                                                      |
| Disposable data and secrets             | **PURGED** — containers, database volume, generated certificates, staging environment and JWT keys removed after the test                                                       |

The tests used one disposable local conversation and synthetic identities only.
No hosted or production conversation was changed, no service was made publicly
accessible, and no genuine registration, eligibility evidence, invitation,
vote or statement was used.

## Decision

This evidence shows that the bounded local stack builds and that its current
XID revocation path fails closed in the previously tested API routes. The
participant alpha keeps gateway credentials server-side and uses same-origin
browser paths. The positive provider surface is now limited to the six routes
called by the pinned alpha; the unused `participants_extended` bridge was
removed, and the end-of-statements state no longer displays or calls an email
subscription form. All 9 exact disposable PostgreSQL/OIDC cases passed,
including standard staff authentication. This closes the exact-stack code
gate locally, but it does **not** authorise a live deployment.

Production gateway hardening remains a separate workstream. Do not expose the
gateway or treat the staging access matrix as production assurance until the
remaining direct dependency blockers are resolved, the authoritative
authorization service and private gateway adapter are integrated, and the
exact release passes a disposable real-browser trace, image/SBOM scan,
backup/restore, deletion, monitoring, load and operational review.
