# Option C disposable staging evidence — 26 July 2026

Status: **local synthetic-data staging only — not production approved**

## Evidence summary

| Check                                   | Result                                                                                                                                                                          |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Upstream Pol.is baseline                | Pinned to `424dcae02f0147723a19103dd2d971f6ec1b6db5`                                                                                                                            |
| Original focused automated tests        | **PASS** — 22 unit tests and 4 integration tests                                                                                                                                |
| Current server source                   | **PASS** — 16 focused minimum-route gateway unit tests, TypeScript build and lint                                                                                               |
| Exact current minimum-route integration | **NOT RUN** — 8 cases are authored for the disposable PostgreSQL/OIDC rerun                                                                                                     |
| Last-passed integration baseline        | **PASS** — 5 cases before the current route reduction; not evidence for the exact current source                                                                                |
| Participant alpha checks                | **PASS** — 124 Jest tests, lint, production build, 3 source-boundary tests and 2 built-output boundary tests                                                                    |
| Dependency-audit parser                 | **PASS** — 6 tests                                                                                                                                                              |
| Local staging configuration             | **PASS**                                                                                                                                                                        |
| Disposable access smoke matrix          | **PASS** — allowlisted XID `200`; missing XID `403`; invalid XID `403`; OIDC bypass attempt `403`; removed XID `403`; warm-session request after XID removal `403`              |
| Participant provider surface            | **CLOSED IN SOURCE; VERIFICATION PENDING** — only six alpha-used routes remain; nine unused/optional routes and notifications are denied; exact-stack and browser traces remain |
| Math image build                        | **PASS** after prefetching its required dependency in `math/Dockerfile`                                                                                                         |
| No-load local runtime snapshot          | Approximately **1.21% CPU** and **1.09 GiB memory**; this is not a load test or capacity result                                                                                 |
| Six Node production-tree audits         | **BLOCKED** — 154 component package-findings before cross-lockfile deduplication: 14 low, 59 moderate, 63 high and 18 critical                                                  |
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
subscription form. The 8 current DB-backed integration cases remain
unexecuted, so the release gate stays P0. This evidence does **not** authorise a
live deployment.

Production gateway hardening remains a separate workstream. Do not expose the
gateway or treat the staging access matrix as production assurance until the
component dependency blockers are resolved, the authoritative authorization
service implements bounded lost-response recovery, and the exact release
passes a disposable real-browser trace, image/SBOM scan, backup/restore,
deletion, monitoring, load and operational review.
