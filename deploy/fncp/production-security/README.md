# MariaDB security candidate — unreleased

22 September 2026. This separate recipe leaves `production-deployment/Dockerfile.mariadb`, the old eight-image lock and the frozen delivery unchanged. It is **not** an approved replacement image or an all-clear security assessment.

`Dockerfile.mariadb-candidate` retains the reviewed vendor MariaDB 11.8.9 base by digest and pins only `libc6` and `libc-bin` to Ubuntu Noble `2.39-0ubuntu8.9`, the version identified in [USN-8737-2](https://ubuntu.com/security/notices/USN-8737-2). It fails rather than silently choosing another package version. Runtime UID/GID remains `999:999`, `gosu` is removed, normal entrypoint remains `mariadbd`, and separately provisioned data is still required.

The revision label identifies the **base source**; the explicit `UNRELEASED_LOCAL_CANDIDATE` label and Dockerfile SHA identify the uncommitted recipe. A commit ID alone does not certify these additions.

## Actual local result

- ARM64 image reference: `sha256:11b29120318b0da6623be5ebcc7d0df64b6e2e9b7c8c7afe96f82a9f89e4f7d7` (Docker's image/manifest-index ID).
- Platform manifest: `sha256:cc0872e0bbd3eb8a858862e4cc159a80544c15e1a4a6f2ae61fc4c4584b847f3`.
- Image config: `sha256:4e51915eb6e36ca2f6c327563057caa503649b17b98fe934c0e917470f08e884`.
- Candidate Dockerfile SHA-256: `54662a31d4cbec3dcaa4dfbe167473e2174932212a1625e27c7944eea61e6bd8`.
- Fresh disposable datadir initialization, socket-only SQL and stop/restart succeeded as non-root with no network, capabilities or published ports. Two invented rows survived, including a synthetic `revoked` value. **This is database smoke testing, not WordPress or participant-revocation integration proof.**
- Fresh Syft 1.49.0 / Grype 0.116.0 pinned ARM64 scan: **478 raw matches — 0 Critical, 0 High, 465 Medium, 10 Low, 3 Negligible; 122 unique vulnerability IDs; zero ignored matches**. Advisory database built `2026-09-21T06:39:24Z`.

The two patched packages are verified at `.9`; twelve earlier package/CVE matches covering the six advisory IDs do not appear in this new scan. Seventeen new package/CVE matches appear with the newer feed, so the MariaDB-only total is **478 now versus 473 in its old scan**, not a claimed net reduction or blanket clearance. Feeds differ; this is not a controlled same-feed comparison. Remaining glibc, vendor MariaDB, rsync and other package findings require explicit review. The old **496** total covered **eight images** and must not be directly compared with this one-image result. The WordPress High has not been rescanned here.

The first collector attempt failed on unsupported `sbom:-` syntax. Its partial evidence remains in `mariadb-security-01`; the corrected collector uses Grype's documented stdin mode and succeeded separately in `mariadb-security-02`.

## Reproduce after local resource review

Use a dedicated task-owned engine with no user runtime/volumes. Do not start the normal Compose stack or reuse retained private state. The build has network access for public registry and signed package downloads; the SQL smoke container does not. Export/scan commands do not publish an image.

```sh
# From this repository, with DOCKER_HOST deliberately set to the task-owned engine:
docker build --platform linux/arm64 --pull --progress plain \
  --build-arg BASE_SOURCE_REVISION=9fccfec82797573dd5c873f1dee761378dff3706 \
  --build-arg CANDIDATE_DOCKERFILE_SHA256=54662a31d4cbec3dcaa4dfbe167473e2174932212a1625e27c7944eea61e6bd8 \
  -t fncp-mariadb-local-candidate:20260922 \
  -f deploy/fncp/production-security/Dockerfile.mariadb-candidate .
```

Resolve the actual resulting ID; never assume a rebuilt image has the ID above. The collector needs an explicit local socket, that exact ID and a **new**, absolute output directory:

```text
node deploy/fncp/production-security/collect-candidate.mjs \
  unix:///absolute/task-engine/docker.sock \
  sha256:EXACT_REBUILT_IMAGE_ID \
  /new/absolute/evidence-directory
```

The collector's current socket syntax is macOS `/Users/.../docker.sock`; Linux packaging is not implemented. It validates candidate labels/architecture/user, records package inventory, runs ephemeral fresh/restart SQL, produces a CycloneDX SBOM, downloads a fresh advisory database, retains raw results and hashes its completed evidence. It refuses existing evidence directories. Its pinned Syft container has access to the **dedicated** Docker socket to read image contents; never point this at a shared/production daemon.

## Before promotion

1. Review relevant residual findings and package origins without suppressing the raw reports.
2. Rebuild all changed roles with an exact reviewed source/image lock and consistent source metadata; do not mix this ad hoc image into old activation/recovery proofs.
3. Prove normal WordPress/MariaDB approval and revocation, all native voting/math/export behavior, complete joined recovery and rollback on that lock.
4. Re-scan every actual release image, record current feed time and applicability decisions. Obtain separate staging and opening approvals as applicable.

The collector is an engineering helper, not a secure deletion tool, production provisioner, vulnerability disposition engine or launch gate by itself.
