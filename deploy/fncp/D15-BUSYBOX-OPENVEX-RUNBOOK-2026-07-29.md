# D15 — architecture-bound BusyBox OpenVEX runbook

Status: source tooling complete; no production attestation issued.

## Purpose

`generate-busybox-openvex.mjs` produces one deterministic OpenVEX 0.2.0
document for one exact OCI image manifest and one exact CPU architecture. It
does not accept a tag, a multi-architecture index as the subject, or unverified
hash claims.

The generator binds the statement to all of the following:

- the registry-qualified OCI repository;
- the exact raw per-architecture manifest bytes, digest and media type;
- the exact raw OCI config bytes and their descriptor digest;
- `linux/amd64` or `linux/arm64`;
- the exact extracted `/bin/busybox` SHA-256 and ELF machine;
- the exact `CVE-2025-60876.patch` SHA-256.

The input also requires the multi-architecture index digest so the generator
can prove that it is distinct from the statement subject. The index digest is
not emitted as a product identifier and cannot broaden the statement.

The output follows the
[OpenVEX 0.2.0 product and subcomponent model](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md).
The product uses an OCI package URL with the required `repository_url`
qualifier. The binary is a hash-addressed subcomponent, and its identifiers
record the exact source-patch hash without incorrectly claiming that the patch
file ships inside the runtime image.

## Safety boundary

A scan row, tag, index digest, build log, or previously observed hash is not
enough to issue this VEX document. Generate it only after the final candidate
image exists and its architecture-specific manifest digest has been resolved.

The historical ARM64 values in the unit test are fixtures. They deliberately
cannot generate a document with the synthetic test binary and are not a
production attestation.

## Required evidence

1. Resolve the exact index descriptor and the selected platform descriptor.
2. Confirm the selected descriptor media type is an image manifest, not an
   image index or Docker manifest list.
3. Save the raw image manifest and raw config JSON without reformatting either
   file. The generator hashes the original bytes and follows the manifest's
   config descriptor.
4. Pull by the per-architecture manifest digest.
5. Create a container from that digest and copy `/bin/busybox` out unchanged.
6. Retain the exact patch file from the reviewed source commit.
7. Calculate SHA-256 for the binary and patch.
8. Populate an input JSON file conforming to
   `busybox-vex-input.schema.json`.

Never reuse an evidence input after the image, patch, architecture, timestamp,
or document version changes.

## Input example

The values below are placeholders, not release evidence:

```json
{
  "schemaVersion": 1,
  "document": {
    "author": "https://barayamal.com.au/",
    "role": "Document Creator",
    "timestamp": "2026-07-29T08:00:00Z",
    "version": 1
  },
  "subject": {
    "repository": "docker.io/barayamal/fncp-polis-math",
    "reference": "docker.io/barayamal/fncp-polis-math@sha256:<PER_ARCH_MANIFEST>",
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "manifestDigest": "sha256:<PER_ARCH_MANIFEST>",
    "indexDigest": "sha256:<MULTI_ARCH_INDEX>",
    "platform": {
      "os": "linux",
      "architecture": "arm64"
    }
  },
  "busybox": {
    "path": "/bin/busybox",
    "version": "1.37.0",
    "sha256": "<EXTRACTED_BINARY_SHA256>"
  },
  "patch": {
    "name": "CVE-2025-60876.patch",
    "sha256": "<PATCH_SHA256>"
  },
  "vulnerability": {
    "id": "CVE-2025-60876",
    "status": "not_affected",
    "justification": "vulnerable_code_not_present"
  }
}
```

## Generate

From the repository root:

```sh
node deploy/fncp/generate-busybox-openvex.mjs \
  --input /absolute/path/evidence-input.json \
  --busybox /absolute/path/busybox \
  --patch /absolute/path/CVE-2025-60876.patch \
  --manifest /absolute/path/manifest.json \
  --config /absolute/path/config.json \
  --output /absolute/path/fncp-busybox.openvex.json
```

The output path must not already exist. Omitting `--output` writes the
canonical JSON to standard output. The same input and evidence bytes produce
the same document ID and byte-for-byte JSON.

The generator fails closed if:

- any input object has an unknown or missing field;
- the timestamp is not a real second-precision UTC timestamp;
- the repository is not registry-qualified;
- the reference is a tag, generic name, index digest, or a different digest;
- the subject media type is an index or manifest list;
- the raw manifest bytes do not hash to the declared per-architecture digest;
- the raw manifest's config descriptor does not hash to the config bytes;
- the config OS, architecture or variant differs from the declared platform;
- the architecture is absent or unsupported;
- either file hash differs from the declaration;
- the binary is not a 64-bit ELF for the declared architecture; or
- the patch is not a UTF-8 unified diff naming `CVE-2025-60876`.

## Review before release

1. Run `node --test deploy/fncp/generate-busybox-openvex.test.mjs`.
2. Recalculate the manifest, config, binary and patch hashes independently.
3. Confirm the product PURL contains the per-architecture manifest digest,
   `arch`, `os`, and `repository_url`.
4. Confirm the multi-architecture index digest does not occur anywhere in the
   output.
5. Confirm the BusyBox subcomponent hash matches the bytes copied from the
   exact manifest.
6. Confirm the `oci-config` identifier matches the config descriptor and the
   config declares the same OS and architecture as the product PURL.
7. Confirm the source-patch hash matches the reviewed source commit.
8. Validate the resulting document with an independent OpenVEX consumer.
9. Sign and publish only under a separately approved immutable-image release.

Until those release checks and approvals are complete, retain the generated
document as candidate evidence and keep Option C on HOLD.
