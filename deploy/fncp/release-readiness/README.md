# Closed-release snapshot verifier

This **read-only, offline** helper verifies the September 14 normal Compose delivery profile. It does not run Docker, Git, an application, a scanner or a provider request. It does not extract archives, install dependencies, modify files or grant deployment authority.

## Run it

Use the separately reviewed helper checkout, not scripts taken from an untrusted package. Node 22+ syntax is used; this addition was executed and tested on **Node 26.8.2 only**. No extra npm packages are required.

```sh
node deploy/fncp/release-readiness/verify-package.mjs \
  /absolute/canonical/path/to/polis-normal-compose-build \
  --manifest-sha256 3463c4439055ed24043e0b5d8d6cd9a3915392c7473487f7cba199f768a17449
```

The hash above is the independently read/reviewed September 14 delivery's `SHA256SUMS.txt` digest, recorded on September 15. It is **not** the Git bundle digest or an image digest. Retain this anchor separately from the package. Do not calculate an anchor from an unknown package and treat the resulting self-consistency check as authentication. A local recorded hash is not a digital signature or protection against replacement of both helper and anchor.

Exit 0 means this local snapshot passed integrity and the specified cross-receipt checks. Exit 1 means rejection. Output contains fixed error codes and aggregate evidence, never file contents, paths or raw errors. Both outcomes set `deploymentAuthorized:false`.

## Checks

- Exact manifest grammar, unique normalized paths, case-alias rejection and no traversal/control/backslash paths or self-referential manifest.
- Complete file membership and directory-prefix membership; no unlisted files or empty directories.
- Canonical root; regular single-link files; no symlink directories, symlink files, hardlinks or special files.
- Bounded enumeration and streaming reads: 5,000 entries, depth 32, 1 MiB manifest, 256 MiB per member, 1 GiB total, 16 MiB per parsed receipt. Inputs above these limits are rejected, not partially approved.
- Every member's SHA-256; file and directory identity/mtime/ctime checks across the read; a final inventory comparison detects ordinary changes.
- Normal-delivery profile, counts and explicit local-only/non-production flags.
- Runtime source, separate offline-tool revision and bundle bytes/receipt identity. The required reviewed bundle receipt must report PASS.
- Final 47-test Node 22 offline recovery receipt, including exact source/runtime revision linkage and zero failures/skips/cancellations.
- Exactly eight image roles. Each recorded OCI image-index digest links to one ARM64/Linux manifest and its config digest, with raw bytes hashed independently. Selected sizes, platform and copied-source receipts must match. An OCI **index** digest is deliberately different from its config digest and can differ from Syft's exported-manifest digest.

## What it does not prove

Use a **quiescent, trusted local snapshot without concurrent writers**. Portable Node path-based traversal is not an atomic directory-descriptor sandbox against a malicious actor swapping ancestor directories. The before/after checks catch ordinary drift, including the deterministic drift regression, but cannot make that stronger adversarial guarantee. The helper does not accept arbitrary filesystem trees as safe data sources.

It verifies bundle bytes against the anchored record but does **not** inspect Git pack objects, run `git fsck`, rehash full container image layers, reconstruct images, rescan vulnerabilities or rerun source/image extraction. Those are separate release steps. It does not independently reproduce every historical test count or every narrative assertion. Required receipt consistency is not fresh runtime proof.

The package intentionally retains the unresolved security findings, invented-provider limitations and closed state. PASS is not a finding waiver, live host approval, OIDC/HTTPS proof, participant-test permission or launch GO. New images, changed helper/source, modified material or a new package require their own reviewed evidence and anchor. Do not rewrite the frozen delivery to make verification pass.

## Tests and recorded check

```sh
node --test deploy/fncp/release-readiness/verify-package.test.mjs
```

The 55 synthetic tests include unsafe manifests, missing/extra/changed members, links, ordinary concurrent drift, malformed receipts, conflicting source/test/bundle metadata, OCI-index versus config confusion, platform/role mismatches, redacted CLI errors and successful read-only execution. Temporary test fixtures are not participant data.

The actual immutable delivery passed: **452 checksum entries, 453 files, 33,209,251 bytes, eight descriptor chains**. Its runtime revision remains `6f44b6df88fa68dc02f278d71358695b1662e32f`; offline tools remain `9fccfec82797573dd5c873f1dee761378dff3706`. This new helper is a source-only addition outside those images.

## Related work

- [Offline provider contract preflight](../production-identity/PROVIDER-PREFLIGHT.md)
- [Official Pol.is installation guidance](https://github.com/compdemocracy/polis/blob/stable/README.md)
- [Official Pol.is configuration](https://github.com/compdemocracy/polis/blob/stable/docs/configuration.md)
- [Official Pol.is HTTPS guidance](https://github.com/compdemocracy/polis/blob/stable/docs/ssl.md)

The official guidance supplies the Docker/configuration basis. This exact-delivery verifier and Barayamal's approval/access controls are project additions, not upstream Pol.is features.
