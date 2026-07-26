# Option C disposable staging evidence — 26 July 2026

Status: **local synthetic-data staging only — not production approved**

## Evidence summary

| Check | Result |
|---|---|
| Upstream Pol.is baseline | Pinned to `424dcae02f0147723a19103dd2d971f6ec1b6db5` |
| Focused automated tests | **PASS** — 22 unit tests and 4 integration tests |
| Local staging configuration | **PASS** |
| Disposable access smoke matrix | **PASS** — allowlisted XID `200`; missing XID `403`; invalid XID `403`; OIDC bypass attempt `403`; removed XID `403`; warm-session request after XID removal `403` |
| Math image build | **PASS** after prefetching its required dependency in `math/Dockerfile` |
| Settled local runtime | Approximately **0.71% CPU** and **632.2 MiB memory** |
| Production dependency audit | **BLOCKED** — 103 production vulnerabilities: 10 low, 50 moderate, 32 high and 11 critical |

The tests used one disposable local conversation and synthetic identities only.
No hosted or production conversation was changed, no service was made publicly
accessible, and no genuine registration, eligibility evidence, invitation,
vote or statement was used.

## Decision

This evidence shows that the bounded local stack builds and that its current
XID revocation path fails closed in the tested API routes. It does **not**
authorise a live deployment.

Production gateway hardening remains a separate workstream. Do not expose the
gateway or treat the staging access matrix as production assurance until the
production dependency audit blocker is resolved and the exact release passes
gateway-route coverage, backup/restore, deletion, monitoring and operational
review.
