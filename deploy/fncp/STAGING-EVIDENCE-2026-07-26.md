# Option C disposable staging evidence — 26 July 2026

Status: **local synthetic-data staging only — not production approved**

## Evidence summary

| Check | Result |
|---|---|
| Upstream Pol.is baseline | Pinned to `424dcae02f0147723a19103dd2d971f6ec1b6db5` |
| Original focused automated tests | **PASS** — 22 unit tests and 4 integration tests |
| Post-hardening server checks | **PASS** — 14 gateway unit tests, TypeScript build and 5 integration tests |
| Participant alpha checks | **PASS** — 124 Jest tests, lint, production build, 2 source-boundary tests and 2 built-output boundary tests |
| Dependency-audit parser | **PASS** — 6 tests |
| Local staging configuration | **PASS** |
| Disposable access smoke matrix | **PASS** — allowlisted XID `200`; missing XID `403`; invalid XID `403`; OIDC bypass attempt `403`; removed XID `403`; warm-session request after XID removal `403` |
| Protected participant route parity | **PARTIAL** — unsupported `GET /participants_extended` returns `404`; trusted `PUT` reaches upstream authentication and returns `401`, not a gateway `403` |
| Math image build | **PASS** after prefetching its required dependency in `math/Dockerfile` |
| No-load local runtime snapshot | Approximately **1.21% CPU** and **1.09 GiB memory**; this is not a load test or capacity result |
| Six Node production-tree audits | **BLOCKED** — 154 component package-findings before cross-lockfile deduplication: 14 low, 59 moderate, 63 high and 18 critical |
| Remaining dependency surfaces | **NOT YET AUDITED** — base/OS images, nginx, PostgreSQL, JVM/Clojure, generated-bundle reachability and an image/SBOM scan |
| Disposable data and secrets | **PURGED** — containers, database volume, generated certificates, staging environment and JWT keys removed after the test |

The tests used one disposable local conversation and synthetic identities only.
No hosted or production conversation was changed, no service was made publicly
accessible, and no genuine registration, eligibility evidence, invitation,
vote or statement was used.

## Decision

This evidence shows that the bounded local stack builds and that its current
XID revocation path fails closed in the tested API routes. The participant
alpha now keeps gateway credentials server-side and uses same-origin browser
paths. The corrected participant route reaches the upstream authentication
boundary, but a trusted `PUT /participants_extended` still returns `401`;
the server-side participant-auth bridge is therefore an unresolved P0. This
evidence does **not** authorise a live deployment.

Production gateway hardening remains a separate workstream. Do not expose the
gateway or treat the staging access matrix as production assurance until the
component dependency blockers are resolved, the authoritative authorization
service implements bounded lost-response recovery, and the exact release
passes a disposable real-browser trace, image/SBOM scan, backup/restore,
deletion, monitoring, load and operational review.
