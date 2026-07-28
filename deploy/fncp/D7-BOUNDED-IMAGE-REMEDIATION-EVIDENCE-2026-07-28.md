# FNCP Option C D7 bounded image remediation evidence — 28 July 2026

## Decision

The bounded nginx, participant-alpha and server remediation pass produced
large, reproducible Critical/High reductions, but the **production image gate
still fails**. Do not expose Option C to the internet and do not onboard
genuine participants.

This was a local `linux/arm64`, synthetic-only exercise. No cloud resource,
registry login, image push, deployment, participant record, vote or statement
was used or changed. The source tree remains an uncommitted WIP candidate.

## Scope and comparable scanner boundary

Only these three D6 images were changed, rebuilt and rescanned:

1. nginx proxy;
2. participant alpha; and
3. Pol.is server.

PostgreSQL, OIDC simulator and math were not rebuilt. Their D6 results remain
unchanged and must not be represented as remediated.

The D7 SBOMs were generated with digest-pinned Syft 1.49.0 and scanned with
digest-pinned Grype 0.116.0 using the same valid Grype database as D6:
schema `v6.1.9`, built `2026-07-27T07:24:06Z`, declared database SHA-256
`9d32360e16bb29e7895e7ae2bcc73bd0e7b3a9fcfe63941af8a7122e097b4ee6`.
This makes the before/after vulnerability-match comparison like-for-like.

Raw D7 evidence is preserved at:

`/Users/deansosupremo/Documents/Codex/2026-07-10/rev/outputs/option-c-image-security-remediation-wip-20260728`

## Exact image results

| Service | D6 Critical | D6 High | D7 Critical | D7 High | D7 Medium | D7 Low | D7 total |
|---|---:|---:|---:|---:|---:|---:|---:|
| nginx proxy | 21 | 113 | 0 | 2 | 6 | 0 | 8 |
| Participant alpha | 2 | 38 | 1 | 24 | 30 | 7 | 62 |
| Pol.is server | 12 | 58 | 1 | 12 | 24 | 7 | 44 |
| **Affected-image total** | **35** | **209** | **2** | **38** | **60** | **14** | **114** |

Combining these three D7 scans with the unchanged D6 PostgreSQL, OIDC and math
scans gives a current six-image composite of **24 Critical, 125 High, 591
Medium, 163 Low, 110 Negligible and 16 Unknown observations; 1,029 total**.
That composite is for prioritisation only: it is not a clean-candidate
attestation because three images were intentionally reused from D6.

| Service | Exact D7 local image ID | Docker bytes |
|---|---|---:|
| nginx proxy | `sha256:2d211fa2683dfa780f0497f2e0a9de0a3665324afa2c1ae83b9e3a251939991d` | 25,947,938 |
| Participant alpha | `sha256:9cc930337a539f242770075837765a94e29787c678b892a648f8acb822fd93c9` | 121,026,185 |
| Pol.is server | `sha256:c08293e8c02c0066fbb3d4e6dc8d3f1c369a865e24f49a131caa1d6916536f5d` | 281,532,379 |

These are local image IDs, not deployable registry references.

## Remediations completed

### nginx proxy

- Replaced EOL `nginx:1.21.5-alpine` / Alpine 3.15 with the current official
  stable semantic tag
  `nginx:1.30.4-alpine3.24@sha256:97d490c12ba55b4946b01546d1c3ed324e8d41ab1c9fcb2a616aa470620e5b46`.
- Recorded the resolved `linux/arm64` child digest
  `sha256:d64d001f60e9a65d45980907e9070fc46d418980f311052e73c0df2eccc3cc30`.
- Added a regression contract that rejects moving `latest`, `stable` and
  `mainline` tags and requires the Dockerfile to match the exact lock.
- Preserved the six-route proxy boundary and `/alpha/` rewrite behavior.

The two residual High observations are Alpine `tiff@4.7.1-r0` matches with no
fix reported by this database snapshot.

### Participant alpha

- Updated within the existing framework lines:
  Astro `5.16.4` to `5.18.2` and `@astrojs/node` `9.5.1` to `9.5.5`.
- Pinned compatible transitive fixes for Vite `6.4.3`, Rollup `4.62.3`,
  PostCSS `8.5.23`, js-yaml `4.3.0` and the affected picomatch lines.
- Retained lodash `4.17.23`; npm explicitly marks `4.18.0` as a bad release.
- Removed the unused global npm CLI from the final runtime.

The final production-only npm registry audit reports **409 production
dependencies and 11 vulnerable package groups: 0 Critical, 8 High, 1
Moderate and 2 Low**.

The remaining exact-image Critical/High observations are:

- one Critical and 18 High Go standard-library module observations against
  the esbuild arm64 binary compiled with Go 1.23.12;
- two High Astro observations;
- three High lodash observations through Visx;
- one High sharp observation.

The compatible esbuild `0.25.12` patch built and passed every test but did not
change the embedded Go compiler version or scanner result. A symbol-aware Go
SBOM/reachability assessment or a reviewed framework/toolchain major upgrade
is required; this pass does not waive those findings.

### Pol.is server

- Moved four build/test-only roots (`@babel/preset-env`, `babel-jest`,
  `@types/uuid` and `ts-node`) to development dependencies.
- Aligned all eight direct AWS SDK v3 packages to exact same-major
  `3.1096.0`, removing the vulnerable fast-xml-parser chains.
- Added compatible fixes for protobufjs `7.6.5`, `@grpc/grpc-js` `1.13.5`,
  ws `8.21.1`, form-data `2.5.6`, affected minimatch lines and picomatch
  `2.3.2`.
- Changed the production process from `npm run serve` to the equivalent direct
  Node command and removed the unused global npm CLI.

The final production-only npm registry audit reports **753 production
dependencies and 27 vulnerable package groups: 1 Critical, 4 High, 16
Moderate and 6 Low**. The D5 baseline was 986 production packages and 61
groups: 4 Critical, 8 High, 43 Moderate and 6 Low.

The exact-image Critical/High residual is concentrated in:

- `sql@0.78.0` → `lodash@4.1.0`: one Critical and four High observations,
  with no non-breaking npm fix;
- build/test-shaped dependencies retained transitively by the runtime
  `@tevko/sensemaking-tools` package: Babel, brace-expansion, flatted and
  js-yaml observations.

Replacing the query builder or splitting the experimental report/sensemaking
capability into a separately built runtime is architectural work and was
deliberately not attempted in this bounded pass.

## Verification

- Image security and lock contracts: **13/13 PASS**.
- nginx `1.30.4` configuration syntax: **PASS**.
- Disposable nginx route matrix: participant rewrite and asset/API proxy
  routes **PASS**; disallowed method returned **405**; unknown/admin route
  returned **404**.
- Participant alpha: lint **PASS**; Jest **124/124 PASS**; production build
  **PASS**; source boundaries **3/3 PASS**; built boundaries **2/2 PASS**.
- Server: TypeScript build **PASS**; lint **PASS**; bounded middleware,
  timeout, gateway, participant-policy, comment-egress and dependency
  contracts **38/38 PASS**.
- Final participant/server runtime assertions: compiled entry present; global
  npm absent; direct-development sentinels absent; server `/app/keys` absent.
- Subsequent clean cold-start staging QA of the same working-tree candidate:
  **PASS**. The helper validated and copied both disposable participant JWT
  keys into the created server container; the smoke used a bounded 45-second
  readiness wait and supplied `X-Forwarded-Proto: https` to the local Pol.is
  API.
- Disposable full-stack smoke result: synthetic conversation closed;
  allowlisted XID `200`; missing XID, invalid XID, staff-OIDC participant
  bypass, removed XID and warm-session request after removal each `403`.
- HTTPS rejection regression: **PASS** — the insecure write response returns
  after `400` and cannot continue to the next handler.

The generated signing keys were runtime-only and remain excluded from the
server image. No genuine data or cloud deployment was used.

After these images were scanned, release review corrected the Express error
middleware ordering so `globalErrorHandler` follows every asynchronously
installed route. Build, lint and 19 focused tests passed, including an actual
Express-stack `408` JSON regression and a production-source ordering contract;
the key-free full unit invocation passed 97 tests with 12 known
database/JWT-fixture failures and is not a whole-suite pass. The corrected
server image was subsequently rebuilt and passed the complete synthetic
cold-start access matrix. It still does **not** inherit the server image ID or
SBOM/scan attestation recorded above; regenerate and review that evidence
before any merge or release decision.

No real-browser, backup/restore, deletion, monitoring, load or
multi-architecture test is claimed by this D7 pass.

## Checksums

| Artifact | SHA-256 |
|---|---|
| Participant lockfile | `e3786facc1a0532d382a6d74e4c77af935cd998e72a20480d4a4e0ddacaaef2c` |
| Server lockfile | `5f8d1b6cd0820852237d03ce59084d58a00553ea91d99bf7170ceb9346aa1996` |
| Image lock | `9f8b46f375099328470752e5e7b1302f578b4697ecac9ced261ef7b0968f40e9` |
| Final alpha SBOM | `dfdb1041f2eb57301a6a2136ddaaf0effafe0809030ebdc8f52fb246b35c2f23` |
| Final alpha Grype JSON | `f3b61d916d6893ed1b634b5a16ef7ad91bdef92831d8a557920ea53d28699b87` |
| Server SBOM | `5e9b850d2b8e976be31349110dad55f0e65b3962a227941419b6b362e399287c` |
| Server Grype JSON | `4ee58636ce45347b73a9b7149780a563005c8fad5d959faf29df29e4069b2def` |
| nginx SBOM | `488c4e3af615528e17adf78b190a7fd071018d0c6d278d62ec42c732a2a14fb6` |
| nginx Grype JSON | `16258e399d26a34931951f250e747a94c095693b6664dbdd526f7aecb7e8f2c8` |

## Next bounded order

1. Split the FNCP server runtime from experimental report/sensemaking
   dependencies, then replace the unmaintained `sql` query builder under
   dedicated query-contract tests.
2. Decide whether to migrate participant alpha to a fixed Astro/sharp/esbuild
   toolchain; do not force a major override without route and rendered-output
   regression evidence.
3. Modernise the math worker's old Jetty, PostgreSQL JDBC, c3p0 and protobuf
   graph in its own change set.
4. Refresh PostgreSQL's gosu/Go basis and keep the synthetic OIDC simulator
   explicitly outside every production manifest.
5. Rebuild and scan all six images from a clean commit, then run the complete
   disposable-stack, browser and operational readiness matrix.

Production remains closed until the current zero-Critical/High policy passes
or every exception is separately reviewed, owned, documented and approved.
