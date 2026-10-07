# Exact local image security verification — 13 September 2026

Status: **image release gate FAIL; local WIP evidence only; no publication or release attestation.**

This snapshot covers the seven existing ARM64 staging image subjects recorded in
`evidence/exact-images-wip-20260913-arm64-02/image-index.json`. It does not refer to
mutable tags after later rebuilds. Source evidence was collected at
`2026-09-13T02:44:37.256Z` from a dirty working tree based on commit
`2898471efe889976670b09977ca6c08946dc04d9`; the complete non-ignored source manifest
is retained. The scan is separate from the clean npm dependency audit results.

## Results

Counts are unsuppressed scanner matches, **not unique vulnerabilities or proven
exploits**. One advisory can match multiple installed packages and images.

| Scope / artifact | Critical | High | Medium | Low | Negligible | Unknown |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Production: server | 0 | 3 | 9 | 2 | 0 | 0 |
| Production: math | 4 | 14 | 5 | 0 | 0 | 0 |
| Production: participant alpha | 4 | 17 | 11 | 2 | 0 | 0 |
| Production: nginx proxy | 4 | 14 | 5 | 0 | 0 | 0 |
| Production: migration task | 4 | 18 | 6 | 0 | 0 | 3 |
| **Five production artifacts** | **16** | **66** | **36** | **4** | **0** | **3** |
| QA infrastructure: PostgreSQL | 5 | 57 | 33 | 4 | 0 | 3 |
| QA infrastructure: OIDC simulator | 22 | 100 | 108 | 19 | 104 | 24 |

The five production artifacts contain 2,911 catalogued components and 125 matches.
The seven-image total is 7,588 components and 604 matches. No direct development
package sentinel was present in the production SBOMs. All five production runtime
assertions passed: non-root execution, reviewed runtime-only boundaries and the
artifact-specific checks in the existing collector.

The math SBOM includes **127 Maven-identified components**. This Grype scan reports
**no Java/JAR vulnerability match** in that image; its Critical/High findings are
Alpine OpenSSL packages. This is a statement about the selected scanner/database,
not a guarantee that the JVM or every dependency is vulnerability-free.

## Production Critical/High findings and bounded repair candidates

The versions below are fixes reported by the captured Grype database. Package/base
availability, exact replacement digests, compatibility and fresh-image results
must be verified before treating any repair as complete. No affected artifact was
changed to silence a finding during this verification.

| Image(s) | Runtime package / detected path | Installed | Scanner-indicated bounded target | Critical/High matches |
| --- | --- | --- | --- | --- |
| server | Node binary, `/usr/local/bin/node` | 22.23.1 | 22.23.2, same major | 0 / 3 |
| participant alpha | Node binary, `/usr/local/bin/node` | 24.18.0 | 24.18.1, same major | 0 / 3 |
| math, participant alpha, nginx, migration | `libcrypto3` and `libssl3`; Alpine installed-package records at `/lib/apk/db/installed` | 3.5.7-r0 | 3.5.8-r0, same package branch | 4 / 14 per image |
| migration | `libuuid`; Alpine installed-package record at `/lib/apk/db/installed` | 2.42.1-r0 | 2.42.3-r1; r0 fixes only a subset | 0 / 4 |

Node advisories: CVE-2026-56846, CVE-2026-56848 and CVE-2026-58043 (High).
OpenSSL advisories: CVE-2026-63073 and CVE-2026-75803 (Critical);
CVE-2026-18798, CVE-2026-63076, CVE-2026-14457, CVE-2026-14456,
CVE-2026-63072, CVE-2026-54874 and CVE-2026-63075 (High).
`libuuid` advisories: CVE-2026-76642, CVE-2026-78409, CVE-2026-78408 and
CVE-2026-78410 (High). Exact match metadata, fix versions and advisory source URLs
are retained in each `scan/*.grype.json` file.

These findings indicate patch-level remediation candidates, not a demonstrated
need to redesign the application or perform a major JVM migration. Medium, Low
and Unknown findings remain in the unmodified evidence; there is no suppression,
VEX exemption or claim that an earlier custom BusyBox repair makes every current
match disappear.

## Execution and provenance

- Explicit Docker context: `colima-fncp-c-20260913`; platform `linux/arm64`.
- Existing server, participant, math, proxy, PostgreSQL and OIDC images were not
  rebuilt, replaced, restarted or deleted by this scan.
- Only the previously missing `polis-migration` artifact was built using Compose.
  Its migration entrypoint was never executed, no database was connected, and its
  checks ran with an overridden shell entrypoint, no network and read-only root.
- Scanner tooling was pinned by the existing lock: Syft **1.49.0** and Grype
  **0.116.0**, including immutable image digests.
- One scanner database download was allowed. Database schema **v6.1.9**, built
  **2026-09-12T06:27:25Z**, was valid and identical for every scan. The downloaded
  database is archived and checksummed in `scanner/grype-db-cache.tar.gz`.
- App-update checks were disabled. Every per-image assertion, SBOM generation and
  vulnerability scan container was network-isolated (`--network none`). Image and
  database downloads were inbound only; no report upload, registry push or
  publication occurred. No participant data or runtime volumes entered a scan.
- The unchanged collector stopped at the **QA-only OIDC image's root-user runtime
  assertion**. That failed JSON is preserved. A local ignored continuation script
  ran the remaining unchanged production assertions and all seven image scans.
  Thus complete scan evidence exists, but the original seven-image collector
  invocation is **not** claimed to have passed.
- The existing summary validator accepted exact image subjects, scanner versions,
  the common fresh database and all five production runtime assertions, and
  correctly emitted `arm64CandidateGate.status = fail`.
- Image-evidence unit tests: **27 passed, 0 failed**. Both local wrapper scripts
  passed `bash -n`. All **28** files in `checksums.sha256` independently verified.

The wrappers are local ignored files in `evidence/`:
`run-offline-image-scan-20260913.sh` and
`continue-offline-image-scan-20260913.sh`. They retain current image tags and skip
rebuilding existing subjects. Do not call this a clean candidate build.

## Evidence identity and next steps

Evidence directory: `deploy/fncp/evidence/exact-images-wip-20260913-arm64-02/`
(approximately 392 MiB, including the archived vulnerability database).

- `scan-summary.json` SHA-256:
  `5e8f130c10a45ac2d17128f622fc49bf5ce41bd65334405ab927ef6df3af06c3`
- `image-index.json` SHA-256:
  `8af69624ca32ad8e19d66d12c1774e095a10ba62ad25ea942c6fc1cd79929086`

1. Verify and pin the bounded patched Node/OpenSSL/libuuid artifacts; keep the
   present evidence immutable as the before snapshot.
2. Rebuild affected local images and rerun exact-image assertions, synthetic
   regressions and unsuppressed SBOM/scanning against a current common database.
3. Fix or explicitly separate the disposable OIDC root-user assertion failure;
   never deploy the simulator as the production participant-identity provider.
4. Address the separate QA-infrastructure findings if those disposable images
   remain in use. Do not combine them with the five-artifact production gate or
   portray their exclusion as remediation.
5. Keep release status HOLD until the exact intended deployment architecture,
   immutable release subjects and remaining operational/identity assurances are
   verified. This report authorizes no publication, deployment, participant test,
   destructive action or external communication.
