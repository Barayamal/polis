#!/usr/bin/env node

import { createHash } from "node:crypto";
import { basename, resolve } from "node:path";
import {
  readFile,
  stat,
  writeFile,
} from "node:fs/promises";
import { fileURLToPath } from "node:url";

const OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0";
const DOCUMENT_NAMESPACE =
  "https://barayamal.com.au/.well-known/openvex/fncp-busybox-";
const OCI_MANIFEST_MEDIA_TYPES = new Set([
  "application/vnd.oci.image.manifest.v1+json",
  "application/vnd.docker.distribution.manifest.v2+json",
]);
const INDEX_MEDIA_TYPES = new Set([
  "application/vnd.oci.image.index.v1+json",
  "application/vnd.docker.distribution.manifest.list.v2+json",
]);
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const SHA256_HEX = /^[0-9a-f]{64}$/u;
const TIMESTAMP =
  /^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:[0-2][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$/u;
const REPOSITORY_SEGMENT =
  /^[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*$/u;
const EXPECTED_ELF_MACHINES = Object.freeze({
  amd64: Object.freeze({ code: 62, label: "EM_X86_64" }),
  arm64: Object.freeze({ code: 183, label: "EM_AARCH64" }),
});
const TOP_LEVEL_KEYS = Object.freeze([
  "schemaVersion",
  "document",
  "subject",
  "busybox",
  "patch",
  "vulnerability",
]);
const OBJECT_KEYS = Object.freeze({
  document: ["author", "role", "timestamp", "version"],
  subject: [
    "repository",
    "reference",
    "mediaType",
    "manifestDigest",
    "indexDigest",
    "platform",
  ],
  platform: ["os", "architecture", "variant"],
  busybox: ["path", "version", "sha256"],
  patch: ["name", "sha256"],
  vulnerability: ["id", "status", "justification"],
});

function fail(message) {
  throw new Error(`BusyBox VEX input rejected: ${message}`);
}

function assertPlainObject(value, label) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail(`${label} must be a JSON object`);
  }
}

function assertExactKeys(value, allowed, required, label) {
  assertPlainObject(value, label);
  const keys = Object.keys(value);
  const unexpected = keys.filter((key) => !allowed.includes(key));
  if (unexpected.length > 0) {
    fail(`${label} has unexpected field(s): ${unexpected.sort().join(", ")}`);
  }
  const missing = required.filter(
    (key) => !Object.prototype.hasOwnProperty.call(value, key),
  );
  if (missing.length > 0) {
    fail(`${label} is missing field(s): ${missing.join(", ")}`);
  }
}

function assertString(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    fail(`${label} must be a non-empty string`);
  }
}

function assertExact(value, expected, label) {
  if (value !== expected) {
    fail(`${label} must be ${JSON.stringify(expected)}`);
  }
}

function assertSha256Digest(value, label) {
  if (!SHA256_DIGEST.test(value)) {
    fail(`${label} must be a lowercase sha256:<64-hex> digest`);
  }
}

function assertSha256Hex(value, label) {
  if (!SHA256_HEX.test(value)) {
    fail(`${label} must be 64 lowercase hexadecimal characters`);
  }
}

function assertTimestamp(value) {
  if (!TIMESTAMP.test(value)) {
    fail("document.timestamp must be a second-precision UTC RFC3339 value");
  }
  const parsed = new Date(value);
  if (
    Number.isNaN(parsed.getTime()) ||
    parsed.toISOString() !== value.replace("Z", ".000Z")
  ) {
    fail("document.timestamp is not a real calendar timestamp");
  }
}

function assertRepository(repository) {
  assertString(repository, "subject.repository");
  if (
    repository.includes("://") ||
    repository.includes("@") ||
    repository.includes("//") ||
    repository !== repository.toLowerCase()
  ) {
    fail(
      "subject.repository must be a lowercase registry-qualified OCI repository without a scheme, tag, digest, or empty segment",
    );
  }

  const [registry, ...segments] = repository.split("/");
  if (
    segments.length === 0 ||
    (!registry.includes(".") && !registry.includes(":")) ||
    !/^[a-z0-9.-]+(?::[0-9]+)?$/u.test(registry) ||
    segments.some((segment) => !REPOSITORY_SEGMENT.test(segment))
  ) {
    fail(
      "subject.repository must include a registry host and valid OCI path segments",
    );
  }
}

function validatePlatform(platform) {
  assertExactKeys(
    platform,
    OBJECT_KEYS.platform,
    ["os", "architecture"],
    "subject.platform",
  );
  assertExact(platform.os, "linux", "subject.platform.os");
  if (!Object.hasOwn(EXPECTED_ELF_MACHINES, platform.architecture)) {
    fail("subject.platform.architecture must be amd64 or arm64");
  }
  if (platform.variant !== undefined) {
    if (
      platform.architecture !== "arm64" ||
      typeof platform.variant !== "string" ||
      !/^v[0-9]+$/u.test(platform.variant)
    ) {
      fail(
        "subject.platform.variant is allowed only for arm64 and must look like v8",
      );
    }
  }
}

export function validateInput(input) {
  assertExactKeys(input, TOP_LEVEL_KEYS, TOP_LEVEL_KEYS, "input");
  assertExact(input.schemaVersion, 1, "schemaVersion");

  assertExactKeys(
    input.document,
    OBJECT_KEYS.document,
    OBJECT_KEYS.document,
    "document",
  );
  assertExact(
    input.document.author,
    "https://barayamal.com.au/",
    "document.author",
  );
  assertExact(input.document.role, "Document Creator", "document.role");
  assertTimestamp(input.document.timestamp);
  if (
    !Number.isSafeInteger(input.document.version) ||
    input.document.version < 1
  ) {
    fail("document.version must be a positive integer");
  }

  assertExactKeys(
    input.subject,
    OBJECT_KEYS.subject,
    OBJECT_KEYS.subject,
    "subject",
  );
  assertRepository(input.subject.repository);
  assertSha256Digest(
    input.subject.manifestDigest,
    "subject.manifestDigest",
  );
  assertSha256Digest(input.subject.indexDigest, "subject.indexDigest");
  if (input.subject.manifestDigest === input.subject.indexDigest) {
    fail(
      "subject.manifestDigest must be a per-architecture manifest digest, not the multi-architecture index digest",
    );
  }
  if (INDEX_MEDIA_TYPES.has(input.subject.mediaType)) {
    fail("subject.mediaType identifies an OCI index or Docker manifest list");
  }
  if (!OCI_MANIFEST_MEDIA_TYPES.has(input.subject.mediaType)) {
    fail("subject.mediaType must identify a single-platform image manifest");
  }
  const expectedReference =
    `${input.subject.repository}@${input.subject.manifestDigest}`;
  assertExact(
    input.subject.reference,
    expectedReference,
    "subject.reference",
  );
  validatePlatform(input.subject.platform);

  assertExactKeys(
    input.busybox,
    OBJECT_KEYS.busybox,
    OBJECT_KEYS.busybox,
    "busybox",
  );
  assertExact(input.busybox.path, "/bin/busybox", "busybox.path");
  assertExact(input.busybox.version, "1.37.0", "busybox.version");
  assertSha256Hex(input.busybox.sha256, "busybox.sha256");

  assertExactKeys(
    input.patch,
    OBJECT_KEYS.patch,
    OBJECT_KEYS.patch,
    "patch",
  );
  assertExact(
    input.patch.name,
    "CVE-2025-60876.patch",
    "patch.name",
  );
  assertSha256Hex(input.patch.sha256, "patch.sha256");
  if (input.patch.sha256 === input.busybox.sha256) {
    fail("patch.sha256 and busybox.sha256 cannot be identical");
  }

  assertExactKeys(
    input.vulnerability,
    OBJECT_KEYS.vulnerability,
    OBJECT_KEYS.vulnerability,
    "vulnerability",
  );
  assertExact(
    input.vulnerability.id,
    "CVE-2025-60876",
    "vulnerability.id",
  );
  assertExact(
    input.vulnerability.status,
    "not_affected",
    "vulnerability.status",
  );
  assertExact(
    input.vulnerability.justification,
    "vulnerable_code_not_present",
    "vulnerability.justification",
  );

  return input;
}

export function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function detectElfMachine(bytes) {
  if (
    bytes.length < 20 ||
    bytes[0] !== 0x7f ||
    bytes[1] !== 0x45 ||
    bytes[2] !== 0x4c ||
    bytes[3] !== 0x46
  ) {
    fail("the supplied BusyBox file is not an ELF binary");
  }
  if (bytes[4] !== 2) {
    fail("the supplied BusyBox file is not a 64-bit ELF binary");
  }
  const endian = bytes[5];
  if (endian !== 1 && endian !== 2) {
    fail("the supplied BusyBox ELF binary has an invalid byte order");
  }
  return endian === 1 ? bytes.readUInt16LE(18) : bytes.readUInt16BE(18);
}

function verifyPatchBytes(bytes) {
  const source = bytes.toString("utf8");
  if (
    source.includes("\uFFFD") ||
    !source.includes("CVE-2025-60876") ||
    !/^--- a\//mu.test(source) ||
    !/^\+\+\+ b\//mu.test(source)
  ) {
    fail(
      "the supplied patch is not a UTF-8 unified diff for CVE-2025-60876",
    );
  }
}

function parseJsonBytes(bytes, label) {
  let source;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail(`${label} is not valid UTF-8`);
  }
  try {
    return JSON.parse(source);
  } catch {
    fail(`${label} is not valid JSON`);
  }
}

function verifyOciEvidence(input, manifestBytes, configBytes) {
  const actualManifestHash = `sha256:${sha256(manifestBytes)}`;
  if (actualManifestHash !== input.subject.manifestDigest) {
    fail(
      `subject.manifestDigest does not match the supplied raw OCI manifest bytes (actual ${actualManifestHash})`,
    );
  }
  const manifest = parseJsonBytes(manifestBytes, "OCI manifest evidence");
  assertPlainObject(manifest, "OCI manifest evidence");
  if (
    manifest.schemaVersion !== 2 ||
    manifest.mediaType !== input.subject.mediaType ||
    Array.isArray(manifest.manifests)
  ) {
    fail(
      "the supplied OCI subject is not the declared single-platform image manifest",
    );
  }
  assertPlainObject(manifest.config, "OCI manifest config descriptor");
  assertSha256Digest(
    manifest.config.digest,
    "OCI manifest config descriptor digest",
  );
  if (
    !Number.isSafeInteger(manifest.config.size) ||
    manifest.config.size !== configBytes.length
  ) {
    fail(
      "OCI manifest config descriptor size does not match the supplied config bytes",
    );
  }
  if (!Array.isArray(manifest.layers) || manifest.layers.length === 0) {
    fail("the supplied OCI image manifest has no layers");
  }

  const actualConfigHash = `sha256:${sha256(configBytes)}`;
  if (manifest.config.digest !== actualConfigHash) {
    fail(
      `OCI config digest does not match the supplied raw config bytes (actual ${actualConfigHash})`,
    );
  }
  const config = parseJsonBytes(configBytes, "OCI config evidence");
  assertPlainObject(config, "OCI config evidence");
  if (
    config.os !== input.subject.platform.os ||
    config.architecture !== input.subject.platform.architecture ||
    (input.subject.platform.variant !== undefined &&
      config.variant !== input.subject.platform.variant) ||
    (input.subject.platform.variant === undefined &&
      config.variant !== undefined)
  ) {
    fail(
      "OCI config platform does not exactly match subject.platform",
    );
  }
  return actualConfigHash;
}

export function verifyEvidenceBytes(
  input,
  {
    busyboxBytes,
    patchBytes,
    manifestBytes,
    configBytes,
  },
) {
  validateInput(input);
  const byteBuffers = {
    busyboxBytes,
    patchBytes,
    manifestBytes,
    configBytes,
  };
  const invalid = Object.entries(byteBuffers)
    .filter(([, value]) => !Buffer.isBuffer(value))
    .map(([name]) => name);
  if (invalid.length > 0) {
    fail(
      `evidence must be supplied as byte buffers: ${invalid.join(", ")}`,
    );
  }

  const configDigest = verifyOciEvidence(
    input,
    manifestBytes,
    configBytes,
  );
  const actualBusyboxHash = sha256(busyboxBytes);
  if (actualBusyboxHash !== input.busybox.sha256) {
    fail(
      `busybox.sha256 does not match the supplied /bin/busybox bytes (actual ${actualBusyboxHash})`,
    );
  }
  const actualPatchHash = sha256(patchBytes);
  if (actualPatchHash !== input.patch.sha256) {
    fail(
      `patch.sha256 does not match the supplied patch bytes (actual ${actualPatchHash})`,
    );
  }

  const elfMachine = detectElfMachine(busyboxBytes);
  const expectedMachine =
    EXPECTED_ELF_MACHINES[input.subject.platform.architecture];
  if (elfMachine !== expectedMachine.code) {
    fail(
      `/bin/busybox ELF machine ${elfMachine} does not match ${input.subject.platform.architecture} (${expectedMachine.label})`,
    );
  }
  verifyPatchBytes(patchBytes);

  return Object.freeze({
    busyboxSha256: actualBusyboxHash,
    patchSha256: actualPatchHash,
    elfMachine: expectedMachine.label,
    configDigest,
  });
}

function canonicalValue(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalValue);
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalValue(value[key])]),
    );
  }
  return value;
}

export function stableJson(value) {
  return `${JSON.stringify(canonicalValue(value), null, 2)}\n`;
}

function encodePurl(value) {
  return encodeURIComponent(value)
    .replace(/!/gu, "%21")
    .replace(/'/gu, "%27")
    .replace(/\(/gu, "%28")
    .replace(/\)/gu, "%29")
    .replace(/\*/gu, "%2A");
}

function productPurl(input) {
  const imageName = input.subject.repository.split("/").at(-1);
  const qualifiers = [
    ["arch", input.subject.platform.architecture],
    ["os", input.subject.platform.os],
    ["repository_url", input.subject.repository],
  ];
  if (input.subject.platform.variant !== undefined) {
    qualifiers.push(["variant", input.subject.platform.variant]);
  }
  const query = qualifiers
    .sort(([left], [right]) => {
      if (left < right) return -1;
      if (left > right) return 1;
      return 0;
    })
    .map(([key, value]) => `${key}=${encodePurl(value)}`)
    .join("&");
  return `pkg:oci/${encodePurl(imageName)}@${input.subject.manifestDigest}?${query}`;
}

function platformName(platform) {
  return [platform.os, platform.architecture, platform.variant]
    .filter(Boolean)
    .join("/");
}

export function generateOpenVex(input, evidence) {
  const verified = verifyEvidenceBytes(input, evidence);
  const inputDigest = sha256(Buffer.from(stableJson(input), "utf8"));
  const manifestHex = input.subject.manifestDigest.slice("sha256:".length);
  const platform = platformName(input.subject.platform);

  return {
    "@context": OPENVEX_CONTEXT,
    "@id": `${DOCUMENT_NAMESPACE}${inputDigest}`,
    author: input.document.author,
    role: input.document.role,
    timestamp: input.document.timestamp,
    last_updated: input.document.timestamp,
    version: input.document.version,
    tooling: "fncp-busybox-openvex/1",
    statements: [
      {
        vulnerability: {
          "@id":
            `https://nvd.nist.gov/vuln/detail/${input.vulnerability.id}`,
          name: input.vulnerability.id,
        },
        products: [
          {
            "@id": productPurl(input),
            identifiers: {
              "oci-manifest": input.subject.reference,
              "oci-config": verified.configDigest,
              "oci-platform": platform,
              "oci-media-type": input.subject.mediaType,
            },
            hashes: {
              "sha-256": manifestHex,
            },
            subcomponents: [
              {
                "@id":
                  `urn:fncp:busybox:${input.busybox.sha256}`,
                identifiers: {
                  path: input.busybox.path,
                  version: input.busybox.version,
                  "elf-machine": verified.elfMachine,
                  "source-patch-name": input.patch.name,
                  "source-patch-sha256": verified.patchSha256,
                },
                hashes: {
                  "sha-256": verified.busyboxSha256,
                },
              },
            ],
          },
        ],
        status: input.vulnerability.status,
        justification: input.vulnerability.justification,
        status_notes:
          `Exact ${platform} image manifest ${input.subject.manifestDigest}; ` +
          `${input.busybox.path} sha256:${input.busybox.sha256}; ` +
          `${input.patch.name} sha256:${input.patch.sha256}.`,
        impact_statement:
          `The exact ${input.busybox.path} ELF binary in this architecture-specific image was built with the named CVE patch; the generator verified both supplied artifacts byte-for-byte before issuing this statement.`,
      },
    ],
  };
}

async function readRegularFile(path, label) {
  const metadata = await stat(path);
  if (!metadata.isFile()) {
    fail(`${label} must be a regular file`);
  }
  return readFile(path);
}

export async function generateOpenVexFromFiles(
  input,
  busyboxFile,
  patchFile,
  manifestFile,
  configFile,
) {
  if (basename(busyboxFile) !== "busybox") {
    fail("the supplied BusyBox evidence file must be named busybox");
  }
  if (basename(patchFile) !== input.patch.name) {
    fail(`the supplied patch evidence file must be named ${input.patch.name}`);
  }
  const [
    busyboxBytes,
    patchBytes,
    manifestBytes,
    configBytes,
  ] = await Promise.all([
    readRegularFile(busyboxFile, "BusyBox evidence"),
    readRegularFile(patchFile, "patch evidence"),
    readRegularFile(manifestFile, "OCI manifest evidence"),
    readRegularFile(configFile, "OCI config evidence"),
  ]);
  return generateOpenVex(input, {
    busyboxBytes,
    patchBytes,
    manifestBytes,
    configBytes,
  });
}

function parseArguments(args) {
  const options = {};
  const allowed = new Set([
    "--input",
    "--busybox",
    "--patch",
    "--manifest",
    "--config",
    "--output",
  ]);
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (!allowed.has(name) || value === undefined || value.startsWith("--")) {
      throw new Error(
        "Usage: generate-busybox-openvex.mjs --input INPUT.json --busybox busybox --patch CVE-2025-60876.patch --manifest manifest.json --config config.json [--output OUTPUT.json]",
      );
    }
    if (Object.hasOwn(options, name)) {
      throw new Error(`Duplicate argument: ${name}`);
    }
    options[name] = value;
  }
  for (const required of [
    "--input",
    "--busybox",
    "--patch",
    "--manifest",
    "--config",
  ]) {
    if (!Object.hasOwn(options, required)) {
      throw new Error(`Missing required argument: ${required}`);
    }
  }
  return options;
}

async function main(args) {
  const options = parseArguments(args);
  const inputPath = resolve(options["--input"]);
  let input;
  try {
    input = JSON.parse(await readFile(inputPath, "utf8"));
  } catch (error) {
    throw new Error(`Unable to read input JSON: ${error.message}`);
  }

  const document = await generateOpenVexFromFiles(
    input,
    resolve(options["--busybox"]),
    resolve(options["--patch"]),
    resolve(options["--manifest"]),
    resolve(options["--config"]),
  );
  const output = stableJson(document);
  if (options["--output"] === undefined) {
    process.stdout.write(output);
    return;
  }
  await writeFile(resolve(options["--output"]), output, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o644,
  });
}

const isCli =
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isCli) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
