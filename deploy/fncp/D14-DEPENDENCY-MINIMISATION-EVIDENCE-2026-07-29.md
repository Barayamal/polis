# D14 — Option C dependency and math-runtime minimisation evidence

Date: 29 July 2026
Decision: **HOLD / NO-GO**
Scope: local ARM64 source and image assurance only

## Outcome

This batch removes or upgrades the reviewed known-fix production dependencies,
replaces the legacy AWS SDK v2 data-export signer with the already-used AWS SDK
v3, and replaces the full Ubuntu/JDK math runtime with a pinned Alpine runtime
and a 16-module `jlink` image.

It does **not** attest the final eight-image release set. The server image must
be rebuilt again after the six-route XID and provider-allowlist branches are
integrated. No registry login, image publication, signing, cloud resource or
deployment occurred.

## Production dependency result

- Exact Node 22 production image build: passed.
- TypeScript production build: passed.
- Production `npm audit --omit=dev`: 407 production dependencies, 0 findings.
- Grype runtime scan: 0 Critical, 0 High, 3 Medium metadata aliases for the
  same patched BusyBox CVE.
- Server runtime user: `node`.
- Local ARM64 image index: `sha256:9173aec92a0a91f5494dedc87cdd446975aff40baf2118949924b6544f801de2`.

Removed unused production clients:

- `aws-sdk`
- `@google-cloud/aiplatform`
- `@google-cloud/vertexai`
- `googleapis`

The data-export S3 presigner now uses `S3Client`, `GetObjectCommand` and
`getSignedUrl` from AWS SDK v3. The source compiles, lints and passes its
dependency/source contract.

The complete development and test closure still reports 11 advisories
(8 High, 1 Moderate and 2 Low). Those packages are pruned before the production
stage and are not present in the scanned runtime. They remain separate
maintenance debt rather than being represented as a zero-finding development
toolchain.

## Math runtime result

| Measure | Previous local baseline | Remediated local image |
|---|---:|---:|
| Docker inspect size | 383,043,603 bytes | 82,986,859 bytes |
| Reduction | — | 78.3% |
| JDK modules | full JDK | 16 |
| Alpine runtime packages | not applicable | 16 |
| Runtime user | root/default | `65532:65532` |
| Critical / High scan findings | planning baseline only | 0 / 0 |
| Remaining scan rows | 191 Ubuntu rows plus Java findings in prior evidence | 3 patched BusyBox aliases |

The three remaining scan rows are `busybox`, `busybox-binsh` and `ssl_client`
package aliases for `CVE-2025-60876`. The final `/bin/busybox` is rebuilt from
the pinned Alpine source with the upstream fix and passes the control-character
rejection test.

Exact local ARM64 proof values:

- OCI image index:
  `sha256:5ee75a02f686fd7106c9b582528144d081ee045c7865474b32451aae84692383`
- Linux/ARM64 image manifest:
  `sha256:467d911a85bdea4086eab64bb992278f04c99d522537fc09a4629405571dbfc1`
- `/bin/busybox`:
  `sha256:1e12790ba34a89c92f9372fed351fc092cf189a434d2440e3754298a84ddd7a5`
- upstream CVE patch:
  `sha256:976d637bb57e65c8b4ba6964ca1a172919abf00750187ae7206050be0a0693a0`
- math Dockerfile:
  `sha256:495808aff561025e07884fd50a25f6bcf63f55170f7473ce808e5dbb33759947`
- math dependencies:
  `sha256:6d0a1a50655c06f60941b523658b5496862d045df1d6bacf7505f1802990facd`

The Dockerfile and dependency hashes above predate only this evidence document;
they remain the exact inputs of the recorded math build.

Removed or upgraded math closure:

- Excluded unused `poi-ooxml`, removing its OOXML/parser dependency graph.
- Jackson core/data formats upgraded to `2.21.5`.
- Guava pinned to `32.0.0-android`.
- Logback classic/core upgraded to `1.5.34`.
- Runtime changed to pinned Alpine 3.24 plus a pinned Corretto Alpine builder.
- The build-only `binutils` package is not copied into the final image.

## Verification

- Focused deployment/security tests: 40/40 passed before adding the dedicated
  dependency contract.
- Dedicated dependency/source contract: 4/4 passed.
- Math tests: 56 tests / 158 assertions passed.
- JWT tests with disposable local RSA keys: 17/17 passed.
- Server TypeScript build: passed.
- Server lint: passed.
- Modified TypeScript Prettier check: passed.
- Full unit attempt: 143/155 passed; the 12 remaining tests require the
  repository's disposable PostgreSQL/OIDC integration harness. They were not
  treated as source failures or silently marked passed.

## Remaining gate

1. Integrate the XID, provider-allowlist and dependency branches.
2. Run the disposable PostgreSQL/OIDC stack and the complete server suite.
3. Rebuild all eight exact-source ARM64 images.
4. Generate SBOMs and unsuppressed scans for that integrated source pair.
5. Generate VEX from per-architecture manifests and exact BusyBox bytes.
6. Repeat the same exercise natively on Linux AMD64.

Production remains **HOLD / NO-GO** until the invitation lifecycle, integrated
browser trace, recovery, deletion, monitoring, load and independent review
gates are complete.
