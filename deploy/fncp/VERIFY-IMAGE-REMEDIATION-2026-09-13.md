# Local image remediation verification — 13 September 2026

**Latest result: the five rebuilt ARM64 production artifacts pass the existing
zero-Critical/zero-High image policy. This is not deployment GO or a clean release
attestation. Fifteen unsuppressed Medium matches remain.**

The [earlier verification](VERIFY-EXACT-IMAGE-SCAN-2026-09-13.md) and its complete
seven-image evidence remain unchanged as the before snapshot. This report covers
only the five patched production artifacts. QA infrastructure was not repaired or
rescanned: its earlier findings and the OIDC root-user assertion failure remain
outstanding.

## Bounded changes completed

- Server Node **22.23.1 → 22.23.2**, retaining Node 22. Participant alpha Node
  **24.18.0 → 24.18.1**, retaining Node 24. Every associated BusyBox build stage
  uses the same reviewed Node 24 patch image. Official release notes identify
  these as security updates: [Node 22.23.2](https://nodejs.org/en/blog/release/v22.23.2)
  and [Node 24.18.1](https://nodejs.org/en/blog/release/v24.18.1).
- Exact registry index and ARM64/AMD64 child digests were verified and recorded in
  `image-security.lock.json`. Pinning AMD64 metadata is **not** an AMD64 build or
  test result; this local verification ran on ARM64 only.
- All five release Dockerfiles explicitly pin **libcrypto3/libssl3 3.5.8-r0**.
  Migration additionally pins **libuuid 2.42.3-r1**, avoiding the earlier r0
  revision that fixed only part of the identified advisory set. Availability was
  verified through Alpine's package-index simulation and successful image builds.
- Custom BusyBox replacement, its control-character rejection build probe,
  non-root runtime users, runtime-only closures, migration client-only removal
  and the production gateway contract were retained.
- Added regression checks for exact Node/OpenSSL/libuuid pins. The migration
  package-install boundary now permits **only** the three reviewed exact security
  packages. Tests reject extra build tools, unpinned packages, an incomplete
  libuuid revision and additional package-install commands.
- Historical July alpha evidence was not rewritten. Its test now binds the
  original historical base identity; current lock/Dockerfile correspondence is
  independently checked.

## Fresh unsuppressed scan result

Scans completed at **2026-09-13T03:03:02.079Z**. Counts are scanner matches, not
unique CVEs or demonstrated exploits.

| Production artifact | Before Critical / High | After Critical / High | Remaining Medium |
| --- | ---: | ---: | ---: |
| server | 0 / 3 | 0 / 0 | 3 |
| math | 4 / 14 | 0 / 0 | 3 |
| participant alpha | 4 / 17 | 0 / 0 | 3 |
| nginx proxy | 4 / 14 | 0 / 0 | 3 |
| migration task | 4 / 18 | 0 / 0 | 3 |
| **Five-artifact total** | **16 / 66** | **0 / 0** | **15** |

The final five SBOMs catalogue **2,911 components**. There are no Low, Negligible or
Unknown matches in this five-image scan, and no development-package sentinel.
Math still catalogues 127 Maven components; this database reports no Java/JAR
match. This does not establish that every component is vulnerability-free.

The remaining 15 Medium matches are **CVE-2025-60876**, recorded against the
`busybox`, `busybox-binsh` and `ssl_client` APK aliases (1.37.0-r31) in each image.
The images retain the custom patched BusyBox binary and their build-time
control-character rejection probes pass, while the package metadata continues to
produce these matches. **No suppression, VEX exclusion or severity-policy change
was used.** The finding record remains available for release review.

## Exact final subjects

| Artifact | Local immutable image ID |
| --- | --- |
| server | `sha256:07f8a21105ed90963ccdf0981d884323116187583a464bb581db14c621d33a98` |
| math | `sha256:5f4ed27c4a951b0cb81b7db54565e0027bcbbfd2e2bbc880cefdcbc67a111d48` |
| participant alpha | `sha256:f47eca0c3f94c7dc24a38c0a650ecdb164fcbe62eed269a5b6e266e7b4c788c5` |
| nginx proxy | `sha256:d333d4f8ce4ac228b112dc8958fd28156d003c87e09d81e64b0a69ac4ab5375a` |
| migration task | `sha256:e9bc9d5078fd79b2cd9d05dba0facc4cb9617e195465ae0a9a2cc9496352c6a5` |

The four changed running services were recreated from these images using
`compose up -d --no-build --no-deps server math client-participation-alpha nginx-proxy`
in context `colima-fncp-c-20260913`. PostgreSQL, OIDC and the synthetic WordPress
MySQL containers were not recreated. **The migration artifact was built and
inspected only; its migration entrypoint was never run.** No bootstrap, reset,
volume deletion or participant-data operation occurred. Final application smokes
are tracked separately by the main task.

## Verification and provenance

- All **five** release images rebuilt successfully. Server TypeScript and alpha
  Astro builds passed. The math build's exact runtime/JAR boot probe passed.
- All **five existing runtime assertions** passed. Additional read-only,
  network-isolated assertions verified the actual Node versions and exact
  installed OpenSSL/libuuid package revisions in the final image subjects.
- Image, BusyBox and migration boundary suites: **40/40 tests passed**.
- Fresh clean **Node 22.23.2 / npm 10.9.8** ARM64 container: TypeScript build,
  **107/107 focused server tests across four suites**, and **2/2 installed
  Nodemon compatibility tests** passed. Test source was mounted read-only and
  `node_modules`/`dist` used disposable anonymous volumes. This focused run used
  `npm ci --ignore-scripts`; the separate production image build performed its
  normal dependency installation and native build.
- Syft **1.49.0** and Grype **0.116.0** remained digest-pinned. All image assertions,
  SBOM generation and vulnerability scans ran with `--network none`. The rescan
  used the **same archived, valid database** as the before scan: schema v6.1.9,
  built **2026-09-12T06:27:25Z**, restored locally and mounted read-only. No scanner
  DB update, upload or remote reporting occurred during the rescan.
- No thresholds were weakened. The existing summary validator bound all five
  exact images, scanners, common database and runtime assertions and returned
  `arm64CandidateGate.status = pass`.
- `git diff --check` passed for all changed Dockerfiles, lock and boundary tests.

Evidence directory:
`deploy/fncp/evidence/exact-images-wip-20260913-arm64-patched/`.
Its source manifest is a **post-code-freeze WIP workspace snapshot**, not proof
that every subsequently edited owner document was an image build input. The
source tree remains dirty; the baseline commit is
`2898471efe889976670b09977ca6c08946dc04d9`. No clean-candidate attestation or
immutable published registry release was created. Source-manifest and checksum
finalization are separate from the offline scan runner to avoid claiming that
concurrent harness/document edits were an exact build-source attestation.

- `scan-summary.json` SHA-256:
  `cf89d995be6b3ccb8f7105d6851a15c0b2ae2070ad752bf064945eb6c4526af2`
- `image-index.json` SHA-256:
  `475f1e948ec89bdf8a714f0b92fa1d3785bf9c7dbfe46ed1897c6a4d3789be16`

## Still required before any release

Keep all public surfaces closed. The result clears only the selected **local
ARM64 image-severity policy**, not identity-provider integration, live WordPress
configuration, participant assurance, operational security, deployment-bound
activation, owner approval or release attestation. QA-only PostgreSQL/OIDC
findings and the OIDC root-user boundary remain unresolved. No participant
invitations, external correspondence, publication, deployment, migration or
destructive action is authorized by this report.
