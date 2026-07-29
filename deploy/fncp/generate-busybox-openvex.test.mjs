import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  generateOpenVex,
  sha256,
  stableJson,
  validateInput,
  verifyEvidenceBytes,
} from "./generate-busybox-openvex.mjs";

const digest = (character) => `sha256:${character.repeat(64)}`;
const manifestMediaType =
  "application/vnd.oci.image.manifest.v1+json";

function elf(machine) {
  const bytes = Buffer.alloc(64);
  bytes[0] = 0x7f;
  bytes.write("ELF", 1, "ascii");
  bytes[4] = 2;
  bytes[5] = 1;
  bytes.writeUInt16LE(machine, 18);
  bytes.write("fncp-busybox-test", 24, "ascii");
  return bytes;
}

const patchBytes = Buffer.from(
  [
    "--- a/networking/wget.c",
    "+++ b/networking/wget.c",
    "@@ -1 +1 @@",
    "-/* vulnerable */",
    "+/* Fix for CVE-2025-60876 */",
    "",
  ].join("\n"),
  "utf8",
);

function validFixture({
  architecture = "arm64",
  machine = architecture === "arm64" ? 183 : 62,
} = {}) {
  const busyboxBytes = elf(machine);
  const configBytes = Buffer.from(
    JSON.stringify({
      architecture,
      os: "linux",
      rootfs: {
        type: "layers",
        diff_ids: [digest("d")],
      },
    }),
    "utf8",
  );
  const configDigest = `sha256:${sha256(configBytes)}`;
  const manifestBytes = Buffer.from(
    JSON.stringify({
      schemaVersion: 2,
      mediaType: manifestMediaType,
      config: {
        mediaType: "application/vnd.oci.image.config.v1+json",
        digest: configDigest,
        size: configBytes.length,
      },
      layers: [
        {
          mediaType:
            "application/vnd.oci.image.layer.v1.tar+gzip",
          digest: digest("c"),
          size: 1,
        },
      ],
    }),
    "utf8",
  );
  const manifestDigest = `sha256:${sha256(manifestBytes)}`;
  const input = {
    schemaVersion: 1,
    document: {
      author: "https://barayamal.com.au/",
      role: "Document Creator",
      timestamp: "2026-07-29T08:00:00Z",
      version: 1,
    },
    subject: {
      repository: "docker.io/barayamal/fncp-polis-math",
      reference:
        `docker.io/barayamal/fncp-polis-math@${manifestDigest}`,
      mediaType: manifestMediaType,
      manifestDigest,
      indexDigest: digest("b"),
      platform: {
        os: "linux",
        architecture,
      },
    },
    busybox: {
      path: "/bin/busybox",
      version: "1.37.0",
      sha256: sha256(busyboxBytes),
    },
    patch: {
      name: "CVE-2025-60876.patch",
      sha256: sha256(patchBytes),
    },
    vulnerability: {
      id: "CVE-2025-60876",
      status: "not_affected",
      justification: "vulnerable_code_not_present",
    },
  };
  return {
    input,
    evidence: {
      busyboxBytes,
      patchBytes,
      manifestBytes,
      configBytes,
    },
    configDigest,
  };
}

const validInput = (options) => validFixture(options).input;

// These are historical ARM64 proof values used to lock validation behaviour.
// They are deliberately never emitted as a production attestation.
const knownArm64ProofFixture = {
  ...validInput(),
  subject: {
    ...validInput().subject,
    reference:
      "docker.io/barayamal/fncp-polis-math@sha256:467d911a85bdea4086eab64bb992278f04c99d522537fc09a4629405571dbfc1",
    manifestDigest:
      "sha256:467d911a85bdea4086eab64bb992278f04c99d522537fc09a4629405571dbfc1",
    indexDigest:
      "sha256:5ee75a02f686fd7106c9b582528144d081ee045c7865474b32451aae84692383",
  },
  busybox: {
    path: "/bin/busybox",
    version: "1.37.0",
    sha256:
      "1e12790ba34a89c92f9372fed351fc092cf189a434d2440e3754298a84ddd7a5",
  },
  patch: {
    name: "CVE-2025-60876.patch",
    sha256:
      "976d637bb57e65c8b4ba6964ca1a172919abf00750187ae7206050be0a0693a0",
  },
};

test("the known ARM64 proof fixture is schema-valid but not silently attested", () => {
  assert.equal(validateInput(knownArm64ProofFixture), knownArm64ProofFixture);
  assert.throws(
    () =>
      generateOpenVex(
        knownArm64ProofFixture,
        validFixture().evidence,
      ),
    /subject\.manifestDigest does not match/u,
  );
});

test("the reviewed patch fixture has the expected exact SHA-256", async () => {
  const reviewedPatch = await readFile(
    new URL("./busybox-fixed/CVE-2025-60876.patch", import.meta.url),
  );
  assert.equal(
    sha256(reviewedPatch),
    knownArm64ProofFixture.patch.sha256,
  );
});

test("generation is deterministic and binds manifest, architecture, binary and patch", () => {
  const { input, evidence, configDigest } = validFixture();
  const first = generateOpenVex(input, evidence);
  const second = generateOpenVex(input, evidence);

  assert.equal(stableJson(first), stableJson(second));
  assert.match(
    first["@id"],
    /^https:\/\/barayamal\.com\.au\/\.well-known\/openvex\/fncp-busybox-[0-9a-f]{64}$/u,
  );
  assert.equal(first["@context"], "https://openvex.dev/ns/v0.2.0");
  assert.equal(first.statements[0].status, "not_affected");
  assert.equal(
    first.statements[0].justification,
    "vulnerable_code_not_present",
  );

  const product = first.statements[0].products[0];
  assert.match(
    product["@id"],
    /pkg:oci\/fncp-polis-math@sha256:[0-9a-f]{64}\?arch=arm64&os=linux&repository_url=docker\.io%2Fbarayamal%2Ffncp-polis-math/u,
  );
  assert.equal(
    product.identifiers["oci-manifest"],
    input.subject.reference,
  );
  assert.equal(product.identifiers["oci-platform"], "linux/arm64");
  assert.equal(product.identifiers["oci-config"], configDigest);
  assert.equal(
    product.hashes["sha-256"],
    input.subject.manifestDigest.slice(7),
  );
  assert.equal(product.subcomponents.length, 1);
  assert.equal(
    product.subcomponents[0].hashes["sha-256"],
    input.busybox.sha256,
  );
  assert.equal(
    product.subcomponents[0].identifiers["source-patch-sha256"],
    input.patch.sha256,
  );
  assert.equal(
    product.subcomponents[0].identifiers["elf-machine"],
    "EM_AARCH64",
  );
  assert.doesNotMatch(stableJson(first), new RegExp(input.subject.indexDigest));
  assert.notEqual(
    product.hashes["sha-256"],
    input.subject.indexDigest.slice(7),
  );
});

test("AMD64 evidence requires an AMD64 ELF and records EM_X86_64", () => {
  const { input, evidence } = validFixture({
    architecture: "amd64",
  });
  const document = generateOpenVex(input, evidence);
  assert.equal(
    document.statements[0].products[0].subcomponents[0].identifiers[
      "elf-machine"
    ],
    "EM_X86_64",
  );
  assert.equal(
    document.statements[0].products[0].identifiers["oci-platform"],
    "linux/amd64",
  );
});

test("generic, tagged, index-only and inconsistent subjects fail closed", () => {
  const input = validInput();

  assert.throws(
    () =>
      validateInput({
        ...input,
        subject: {
          ...input.subject,
          repository: "fncp-polis-math",
          reference:
            `fncp-polis-math@${input.subject.manifestDigest}`,
        },
      }),
    /registry host/u,
  );
  assert.throws(
    () =>
      validateInput({
        ...input,
        subject: {
          ...input.subject,
          reference: `${input.subject.repository}:latest`,
        },
      }),
    /subject\.reference must be/u,
  );
  assert.throws(
    () =>
      validateInput({
        ...input,
        subject: {
          ...input.subject,
          reference:
            `${input.subject.repository}@${input.subject.indexDigest}`,
        },
      }),
    /subject\.reference must be/u,
  );
  assert.throws(
    () =>
      validateInput({
        ...input,
        subject: {
          ...input.subject,
          manifestDigest: input.subject.indexDigest,
          reference:
            `${input.subject.repository}@${input.subject.indexDigest}`,
        },
      }),
    /per-architecture manifest digest/u,
  );
  assert.throws(
    () =>
      validateInput({
        ...input,
        subject: {
          ...input.subject,
          mediaType: "application/vnd.oci.image.index.v1+json",
        },
      }),
    /index or Docker manifest list/u,
  );
});

test("unexpected fields, malformed timestamps and mixed architectures fail closed", () => {
  const { input } = validFixture();
  assert.throws(
    () => validateInput({ ...input, fixtureOnly: true }),
    /unexpected field\(s\): fixtureOnly/u,
  );
  assert.throws(
    () =>
      validateInput({
        ...input,
        document: {
          ...input.document,
          timestamp: "2026-02-31T08:00:00Z",
        },
      }),
    /real calendar timestamp/u,
  );
  assert.throws(
    () =>
      verifyEvidenceBytes(
        validFixture({
          architecture: "amd64",
          machine: 183,
        }).input,
        validFixture({
          architecture: "amd64",
          machine: 183,
        }).evidence,
      ),
    /does not match amd64/u,
  );
});

test("raw OCI manifest and config bytes must match the subject and platform", () => {
  const { input, evidence } = validFixture();
  assert.throws(
    () =>
      verifyEvidenceBytes(input, {
        ...evidence,
        manifestBytes: Buffer.concat([
          evidence.manifestBytes,
          Buffer.from("\n", "utf8"),
        ]),
      }),
    /subject\.manifestDigest does not match/u,
  );
  assert.throws(
    () =>
      verifyEvidenceBytes(input, {
        ...evidence,
        configBytes: Buffer.concat([
          evidence.configBytes,
          Buffer.from("\n", "utf8"),
        ]),
      }),
    /config descriptor size does not match/u,
  );

  const amd64 = validFixture({ architecture: "amd64" });
  assert.throws(
    () =>
      verifyEvidenceBytes(
        {
          ...amd64.input,
          subject: {
            ...amd64.input.subject,
            platform: {
              os: "linux",
              architecture: "arm64",
            },
          },
        },
        amd64.evidence,
      ),
    /OCI config platform does not exactly match/u,
  );

  const indexBytes = Buffer.from(
    JSON.stringify({
      schemaVersion: 2,
      mediaType: "application/vnd.oci.image.index.v1+json",
      manifests: [],
    }),
    "utf8",
  );
  const indexAsManifestDigest = `sha256:${sha256(indexBytes)}`;
  assert.throws(
    () =>
      verifyEvidenceBytes(
        {
          ...input,
          subject: {
            ...input.subject,
            reference:
              `${input.subject.repository}@${indexAsManifestDigest}`,
            manifestDigest: indexAsManifestDigest,
          },
        },
        {
          ...evidence,
          manifestBytes: indexBytes,
        },
      ),
    /not the declared single-platform image manifest/u,
  );
});

test("declared hashes must match the exact supplied binary and patch bytes", () => {
  const { input, evidence } = validFixture();

  assert.throws(
    () =>
      verifyEvidenceBytes(
        {
          ...input,
          busybox: {
            ...input.busybox,
            sha256: "0".repeat(64),
          },
        },
        evidence,
      ),
    /busybox\.sha256 does not match/u,
  );
  assert.throws(
    () =>
      verifyEvidenceBytes(
        {
          ...input,
          patch: {
            ...input.patch,
            sha256: "0".repeat(64),
          },
        },
        evidence,
      ),
    /patch\.sha256 does not match/u,
  );
  assert.throws(
    () =>
      verifyEvidenceBytes(
        input,
        {
          ...evidence,
          patchBytes: Buffer.from("--- a/a\n+++ b/b\n", "utf8"),
        },
      ),
    /patch\.sha256 does not match/u,
  );
});

test("the checked-in JSON Schema is strict at every object boundary", async () => {
  const schema = JSON.parse(
    await readFile(
      new URL("./busybox-vex-input.schema.json", import.meta.url),
      "utf8",
    ),
  );
  assert.equal(schema.additionalProperties, false);
  assert.equal(schema.properties.document.additionalProperties, false);
  assert.equal(schema.properties.subject.additionalProperties, false);
  assert.equal(
    schema.properties.subject.properties.platform.additionalProperties,
    false,
  );
  assert.equal(schema.properties.busybox.additionalProperties, false);
  assert.equal(schema.properties.patch.additionalProperties, false);
  assert.equal(schema.properties.vulnerability.additionalProperties, false);
  assert.deepEqual(schema.properties.subject.properties.mediaType.enum, [
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
  ]);
});
