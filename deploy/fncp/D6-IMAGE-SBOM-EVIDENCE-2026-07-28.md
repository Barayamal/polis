# FNCP Option C D6 exact-image and SBOM evidence — 28 July 2026

> Historical six-image baseline. nginx, participant alpha and server were
> subsequently rebuilt and rescanned in the
> [D7 bounded remediation record](./D7-BOUNDED-IMAGE-REMEDIATION-EVIDENCE-2026-07-28.md).
> PostgreSQL, OIDC simulator and math remain at the D6 result.

## Decision

The local `linux/arm64` Option C candidate builds, produces a complete
CycloneDX SBOM and Grype result for each of its six images, and passes the
runtime pruning/key-exclusion assertions. It **fails the production image
gate**.

The scan recorded 1,410 vulnerability-match observations: 57 Critical, 296
High, 741 Medium, 190 Low, 110 Negligible and 16 Unknown. These are scanner
match observations across images, not 1,410 unique vulnerabilities and not a
claim that every match is exploitable. Production remains closed until the
Critical and High result is zero under the current policy or a separately
reviewed policy explicitly documents and approves each exception.

This was a local, synthetic-data, zero-cloud-spend exercise. No image was
pushed, signed or deployed; no registry login occurred; and no registration,
eligibility evidence, vote or statement was used.

## Exact evidence boundary

| Field | Recorded value |
|---|---|
| Source commit | `22f9f342e6e8dd616ae2c3b2d106d6f6a23c960e` |
| Source state | dirty working-tree candidate |
| Manifested files | 1,412 non-ignored files |
| Source aggregate SHA-256 | `f568e1918e14f7a284ddc3fe4cc89be74f3178773ea30b5dea8993447d4c7788` |
| Build platform | `linux/arm64` |
| Evidence generated | `2026-07-28T05:29:10.231Z` |
| Evidence directory | `/Users/deansosupremo/Documents/Codex/2026-07-10/rev/outputs/option-c-image-security-wip-20260728-0550` |
| Evidence checksum-file SHA-256 | `d024e966798dc208130d90adf4a7f2897d23fec28232f72c5d854ba34a08e81b` |

The evidence is deliberately labelled `wip`: the source tree contained the
reviewed Express, image-hardening and evidence-tool changes but was not a clean
commit. The local image IDs below identify those exact local image
configurations. Their Compose-generated local name digests are not registry
manifests and must not be used as deployable registry references. A clean
commit must be rebuilt, rescanned, pushed by digest and signed before a
production candidate exists.

## Locked inputs and tools

All six Dockerfiles now use OCI index digests, recorded with their resolved
`linux/arm64` child digests in
[`image-security.lock.json`](./image-security.lock.json). The evidence tools
also run from immutable scanner image digests:

| Tool | Version | OCI index digest | `linux/arm64` child digest |
|---|---:|---|---|
| Syft | 1.49.0 | `sha256:13b53ebabe3d215268c90cf8fb9b875f0183908245f376fd4b3a2cb69d21d484` | `sha256:99ba1223ceabba63c6ebcaf339b83f2a2f8a307df11740c3d996d262f13b81a5` |
| Grype | 0.116.0 | `sha256:fd4ab4d1042b522c896e73bdf09ab8bf384fa417df99d6dd0d6e1008c7e7c821` | `sha256:1219f4e3da38bd258d3e18b8444ecbb913c13808743bd327fccc4aa48fcf8ff7` |

Grype used valid database schema `v6.1.9`, built
`2026-07-27T07:24:06Z`. Its source URL declared SHA-256
`9d32360e16bb29e7895e7ae2bcc73bd0e7b3a9fcfe63941af8a7122e097b4ee6`.
The raw scan for every image preserves the scanner version and database
descriptor.

## Image results

| Service | Exact local image ID | Docker-reported bytes | SBOM components | Critical | High | Other matches | Fix available / unavailable |
|---|---|---:|---:|---:|---:|---:|---:|
| PostgreSQL | `sha256:06bdc4ad33120f2cd4c2871d2ae85d68c5586d5eee7e9389cd125639b8034be2` | 114,986,630 | 612 | 1 | 18 | 23 | 39 / 3 |
| OIDC simulator | `sha256:fb240cbf49352f9f822163f3a23a9445126f0b21da103ce9a2ecf1a5aca9f673` | 99,760,439 | 4,057 | 17 | 46 | 211 | 33 / 241 |
| Pol.is server | `sha256:83b50b0b7c63fd2dd01c294ea7f25006db42e827479bfebf862d81f3e97d62f9` | 284,946,248 | 2,864 | 12 | 58 | 75 | 140 / 5 |
| Math worker | `sha256:3dedb7bf2b102dfedfc65f3caa0ebe87aa790faa704024bc19940719e6caa07d` | 334,352,952 | 7,787 | 4 | 23 | 572 | 152 / 447 |
| Participant alpha | `sha256:24fdff9c915d6bb9496e3bdda41c9b5b3826467639076e2539e18adc41efa251` | 127,711,259 | 1,265 | 2 | 38 | 60 | 97 / 3 |
| nginx proxy | `sha256:b9c1d5ea64b7d14db5600c1a503ddd85f525fff691cdd0cfe02761fa8d6d5054` | 9,983,199 | 1,131 | 21 | 113 | 116 | 120 / 130 |
| **Total observations** | — | — | **17,716** | **57** | **296** | **1,057** | — |

“Other” is Medium, Low, Negligible and Unknown combined. Component counts and
matches may repeat the same component or advisory between images.

## Hardening completed and verified

- Every base image and scanner image is pinned to an immutable OCI index
  digest, with the resolved arm64 child recorded separately.
- Node final images run `npm prune --omit=dev`.
- The server final image no longer carries the build-only Python/pip toolchain.
- The math image resolves only its runtime alias, not the development alias.
- Astro telemetry is disabled during the participant build.
- Broad Docker build contexts exclude `.env.*`, generated certificates,
  generated JWT keys, local `node_modules` and local build output as
  applicable.
- Server, participant-alpha and OIDC runtime assertions all passed:
  generated `/app/keys` was absent and the reviewed direct-development package
  sentinels were absent.
- TypeScript remains in the alpha image through Astro production dependencies
  `tsconfck` and `zod-to-ts`; it is not evidence that the direct development
  dependency survived pruning.
- ESLint remains in the server production tree through
  `@tevko/sensemaking-tools` and its TypeScript ESLint dependencies. That is a
  production dependency-classification and image-bloat blocker, not a failed
  `npm prune` assertion.

## Remediation order

1. **Replace the EOL proxy base.** `nginx:1.21.5-alpine` contains Alpine
   3.15.0. Grype warned that vulnerability data for this EOL distribution may
   be incomplete or outdated; it nevertheless produced 21 Critical and 113
   High matches. Move to a supported nginx/OS line, review configuration
   compatibility, pin the new digest and rebuild.
2. **Reduce the server production graph.** The exact server image has 12
   Critical and 58 High matches. High-priority package paths include
   `fast-xml-parser`, `form-data`, old `lodash`, `protobufjs`, `tar` and their
   owning optional capabilities. Remove disabled AI, translation, telemetry
   and report/sensemaking packages from the FNCP runtime image where
   technically possible; upgrade the remaining reachable paths.
3. **Upgrade the participant build/runtime graph.** The alpha image has 2
   Critical and 38 High matches, including Astro/Vite ecosystem packages,
   `tar` and module-level Go standard-library observations. Upgrade the exact
   lockfile and re-evaluate each embedded-Go result with a symbol-capable SBOM
   or binary/reachability evidence.
4. **Modernise the math dependencies.** The math image has 4 Critical and 23
   High matches, including old Jetty, PostgreSQL JDBC, c3p0 and protobuf
   artifacts. Upgrade those direct/transitive artifacts and reassess whether a
   smaller runtime image can exclude build/cache material.
5. **Refresh database and QA bases.** PostgreSQL’s Critical/High observations
   are Go-module/standard-library matches with fixes reported; refresh the
   supported base and triage exact binaries. The OIDC simulator is synthetic
   local QA only and must not be deployed as production identity. Keep it out
   of the production manifest; update it separately for safe ongoing QA.
6. **Repeat against a clean, immutable candidate.** Rebuild all images from a
   clean commit, run the full functional and browser matrix, produce SBOMs,
   require the image policy to pass, then push by registry digest and add
   signatures/attestations. Do not promote mutable `latest` tags.

## Reproduction

From the repository root, with Docker available:

```sh
node --test deploy/fncp/image-security-evidence.test.mjs

./deploy/fncp/collect-image-security-evidence.sh \
  /absolute/new/no-overwrite/evidence-directory
```

The collector:

- refuses relative or existing output paths;
- refuses a dirty tree unless `FNCP_ALLOW_DIRTY_SOURCE=1` explicitly labels a
  WIP run;
- builds all six images with pulled digest-pinned bases unless
  `FNCP_SKIP_SCAN_BUILD=1` is explicitly used for already-built exact images;
- records a whole non-ignored source manifest and local image index;
- performs runtime key/development-package assertions;
- creates CycloneDX JSON with pinned Syft and raw JSON scans with pinned Grype;
- records a concise gate summary plus checksums; and
- contains no cloud command, registry login or image push.

The successful WIP evidence reused the already-built exact images:

```sh
FNCP_SCAN_PROJECT_NAME=fncp-option-c-scan-wip-20260728 \
FNCP_SKIP_SCAN_BUILD=1 \
FNCP_KEEP_SCAN_IMAGES=1 \
FNCP_ALLOW_DIRTY_SOURCE=1 \
./deploy/fncp/collect-image-security-evidence.sh \
  /Users/deansosupremo/Documents/Codex/2026-07-10/rev/outputs/option-c-image-security-wip-20260728-0550
```

## Limitations

- This is dirty-tree WIP evidence, not a release attestation.
- The images are local arm64 artifacts and have not been tested as
  multi-architecture registry manifests.
- Digest-pinned base images and package lockfiles improve repeatability, but
  `apk`/`apt` repository resolution and Maven/Clojure artifact retrieval are
  not yet a fully offline, checksum-verified build. The exact resulting local
  image IDs are recorded; byte-for-byte rebuild reproducibility is not proven.
- Grype warned that Go packages without function symbols fall back to
  module-level matching and may produce false positives. Those matches remain
  in the fail-closed totals until specifically resolved.
- Grype’s EOL Alpine warning means the proxy result may be incomplete as well
  as severe; it is not a reason to waive the proxy blocker.
- A vulnerability match is not, by itself, exploitability evidence. Equally,
  disabled configuration is not proof that an installed vulnerable package is
  unreachable. Exceptions require package ownership, reachability and
  compensating-control evidence.
- This evidence does not satisfy the remaining browser, backup/restore,
  deletion, load, monitoring, Australian infrastructure ownership, incident
  response or operational readiness gates.

## Gate result

**FAIL — do not expose Option C to the internet and do not onboard genuine
participants.** The evidence workflow is ready to rerun after each bounded
remediation, but the present images are not production candidates.
