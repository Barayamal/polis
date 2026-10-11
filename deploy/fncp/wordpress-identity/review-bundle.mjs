#!/usr/bin/env node
/** Deterministic source-review ZIP only. No installer, PHP execution, network,
 * runtime/configuration lookup, extraction, activation, or production authority.
 * Only the currently reviewed five-file closure may enter the archive. */
import { createHash } from 'node:crypto';
import { constants, closeSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync,
  readFileSync, readdirSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, parse, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assembleWordPressBundle, validateWordPressBundle, WORDPRESS_FILES } from './package-check.mjs';

export const REVIEW_ROOT = 'fncp-wordpress-local-review';
export const REVIEW_ARCHIVE_NAME = REVIEW_ROOT + '.zip';
export const REVIEW_MANIFEST_NAME = 'manifest.json';
export const REVIEWED_SOURCE_CLOSURE_SHA256 = 'e6aea2cff34ec55e365e9189e0ea3cd523302ee474dd7bf8169af8b5db628363';
const EMBEDDED_MANIFEST = REVIEW_ROOT + '/REVIEW-MANIFEST.json';
const ARCHIVE_NAMES = Object.freeze([...WORDPRESS_FILES.map(path => REVIEW_ROOT + '/' + path), EMBEDDED_MANIFEST]);
const MAX_ARCHIVE_BYTES = 327_680;
const MAX_MANIFEST_BYTES = 16_384;
const failure = () => new Error('WordPress review bundle rejected; KEEP_CLOSED.');
const need = condition => { if (!condition) throw failure(); };
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const json = value => JSON.stringify(value, null, 2) + '\n';
const typedByteLength = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), 'byteLength').get;

// Reject getters, custom prototypes, toJSON hooks, sparse arrays and opaque
// objects before serialising a caller's claimed source manifest.
function dataOnly(value, depth = 0, budget = { left: 2000 }) {
  need(depth < 12 && --budget.left >= 0);
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    need(typeof value !== 'string' || value.length <= 8192); return value;
  }
  if (typeof value === 'number') { need(Number.isSafeInteger(value)); return value; }
  need(typeof value === 'object');
  const array = Array.isArray(value);
  need(Object.getPrototypeOf(value) === (array ? Array.prototype : Object.prototype));
  const keys = Reflect.ownKeys(value); need(keys.length <= 256);
  const result = array ? [] : {};
  if (array) {
    const length = Object.getOwnPropertyDescriptor(value, 'length');
    need(length && 'value' in length && Number.isSafeInteger(length.value) && length.value <= 255 &&
      keys.length === length.value + 1);
    for (let index = 0; index < length.value; index++) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      need(descriptor && 'value' in descriptor && descriptor.enumerable);
      result.push(dataOnly(descriptor.value, depth + 1, budget));
    }
  } else for (const key of keys) {
    need(typeof key === 'string' && /^[A-Za-z][A-Za-z0-9]*$/u.test(key) &&
      !['constructor', 'prototype', 'toJSON'].includes(key));
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    need(descriptor && 'value' in descriptor && descriptor.enumerable);
    result[key] = dataOnly(descriptor.value, depth + 1, budget);
  }
  return result;
}

function sourceInput(input) {
  need(input && Object.getPrototypeOf(input) === Object.prototype &&
    Reflect.ownKeys(input).length === 2);
  const fd = Object.getOwnPropertyDescriptor(input, 'files');
  const md = Object.getOwnPropertyDescriptor(input, 'manifest');
  need(fd && md && 'value' in fd && 'value' in md && fd.enumerable && md.enumerable);
  const original = fd.value;
  need(original instanceof Map && Object.getPrototypeOf(original) === Map.prototype && Reflect.ownKeys(original).length === 0);
  const files = new Map();
  for (const [name, content] of Map.prototype.entries.call(original)) {
    need(files.size < 5 && typeof name === 'string' && typeof content === 'string');
    files.set(name, content);
  }
  const manifest = validateWordPressBundle(files);
  need(manifest.sourceClosureSha256 === REVIEWED_SOURCE_CLOSURE_SHA256 &&
    json(dataOnly(md.value)) === json(manifest));
  return { files, manifest };
}

function reviewManifest(closure) {
  return {
    schemaVersion: 1, artifactKind: 'WORDPRESS_SOURCE_REVIEW_ARCHIVE',
    classification: 'LOCAL_REVIEW_ONLY_KEEP_CLOSED', mode: 'SYNTHETIC_ONLY',
    productionReady: false, deployablePackage: false, launchAuthority: false,
    archiveRoot: REVIEW_ROOT, sourceClosureSha256: closure.sourceClosureSha256,
    sourceFiles: closure.fileCount, dependencyCount: closure.dependencyCount,
    entrypoint: closure.entrypoint, files: closure.files,
    sourceBytePreservation: 'EXACT_REVIEWED_FIVE_FILE_DIGEST_PIN',
    zipFormat: { method: 'STORED', timestamp: '1980-01-01T00:00:00',
      fileMode: '0644', directoryEntries: false, extraFields: false, comments: false },
    limitations: ['not-an-installable-production-release', 'no-install-or-activation',
      'no-extraction-performed', 'no-wordpress-core-or-host-runtime', 'no-runtime-state-or-configuration',
      'no-real-identity-or-heritage-verification', 'synthetic-guards-unchanged',
      'digest-pinning-is-not-php-security-certification', 'sha256-is-not-a-publisher-signature'],
  };
}

function publicManifest(review, archive) {
  return { ...review, archive: { filename: REVIEW_ARCHIVE_NAME, entries: ARCHIVE_NAMES.length,
    bytes: archive.length, sha256: sha(archive) } };
}

const CRC_TABLE = Array.from({ length: 256 }, (_, byte) => {
  let crc = byte;
  for (let bit = 0; bit < 8; bit++) crc = crc & 1 ? 0xedb88320 ^ (crc >>> 1) : crc >>> 1;
  return crc >>> 0;
});
function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) crc = CRC_TABLE[(crc ^ byte) & 255] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function encodeZip(entries) {
  const local = []; const central = []; let offset = 0;
  for (const [path, bytes] of entries) {
    const name = Buffer.from(path, 'ascii'); const crc = crc32(bytes);
    const head = Buffer.alloc(30);
    head.writeUInt32LE(0x04034b50, 0); head.writeUInt16LE(20, 4);
    head.writeUInt16LE(33, 12); // DOS date 1980-01-01; fixed time 00:00:00.
    head.writeUInt32LE(crc, 14); head.writeUInt32LE(bytes.length, 18); head.writeUInt32LE(bytes.length, 22);
    head.writeUInt16LE(name.length, 26);
    local.push(head, name, bytes);
    const directory = Buffer.alloc(46);
    directory.writeUInt32LE(0x02014b50, 0); directory.writeUInt16LE(0x0314, 4); // Unix, ZIP 2.0.
    directory.writeUInt16LE(20, 6); directory.writeUInt16LE(33, 14);
    directory.writeUInt32LE(crc, 16); directory.writeUInt32LE(bytes.length, 20); directory.writeUInt32LE(bytes.length, 24);
    directory.writeUInt16LE(name.length, 28); directory.writeUInt32LE((0o100644 << 16) >>> 0, 38);
    directory.writeUInt32LE(offset, 42); central.push(directory, name);
    offset += head.length + name.length + bytes.length;
  }
  const centralBytes = Buffer.concat(central); const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralBytes.length, 12); end.writeUInt32LE(offset, 16);
  const archive = Buffer.concat([...local, centralBytes, end]); need(archive.length <= MAX_ARCHIVE_BYTES);
  return archive;
}

/** Pure: accepts the existing source-checker's {files, manifest}; no disk I/O.
 * A changed source digest requires an explicit source review and pin update. */
export function buildWordPressReviewBundle(sourceBundle) {
  try {
    const source = sourceInput(sourceBundle); const review = reviewManifest(source.manifest);
    const embedded = Buffer.from(json(review)); need(embedded.length <= MAX_MANIFEST_BYTES);
    const entries = WORDPRESS_FILES.map(path => [REVIEW_ROOT + '/' + path, Buffer.from(source.files.get(path))]);
    entries.push([EMBEDDED_MANIFEST, embedded]);
    const archive = encodeZip(entries);
    const verified = validateWordPressReviewArchive(archive);
    return { archive, manifest: verified.manifest };
  } catch { throw failure(); }
}

/** Independent strict ZIP reader; does not call the ZIP encoder or extract.
 * Exactly six stored entries, ordinary file modes, canonical layout, matching
 * local/central metadata and checksums, and the reviewed source pin are required.
 * This is intentionally NOT a general-purpose ZIP parser. */
export function validateWordPressReviewArchive(input) {
  try {
    need(Buffer.isBuffer(input) && Object.getPrototypeOf(input) === Buffer.prototype);
    const length = typedByteLength.call(input); need(length >= 22 && length <= MAX_ARCHIVE_BYTES);
    // Copy raw typed-array storage, not Buffer.from(input), which can execute a
    // caller-provided valueOf hook. Input methods and length accessors are ignored.
    const bytes = Buffer.alloc(length); Uint8Array.prototype.set.call(bytes, input);
    const end = bytes.length - 22;
    need(bytes.readUInt32LE(end) === 0x06054b50 && bytes.readUInt16LE(end + 4) === 0 &&
      bytes.readUInt16LE(end + 6) === 0 && bytes.readUInt16LE(end + 8) === 6 &&
      bytes.readUInt16LE(end + 10) === 6 && bytes.readUInt16LE(end + 20) === 0);
    const centralSize = bytes.readUInt32LE(end + 12); const centralStart = bytes.readUInt32LE(end + 16);
    need(centralStart > 0 && centralSize > 0 && centralStart + centralSize === end);
    let centralOffset = centralStart; let localOffset = 0; const files = new Map(); let embedded;
    for (const expectedName of ARCHIVE_NAMES) {
      need(centralOffset + 46 <= end && bytes.readUInt32LE(centralOffset) === 0x02014b50);
      const c = bytes.subarray(centralOffset, centralOffset + 46);
      need(c.readUInt16LE(4) === 0x0314 && c.readUInt16LE(6) === 20 && c.readUInt16LE(8) === 0 &&
        c.readUInt16LE(10) === 0 && c.readUInt16LE(12) === 0 && c.readUInt16LE(14) === 33 &&
        c.readUInt16LE(30) === 0 && c.readUInt16LE(32) === 0 && c.readUInt16LE(34) === 0 &&
        c.readUInt16LE(36) === 0 && c.readUInt32LE(38) === ((0o100644 << 16) >>> 0) &&
        c.readUInt32LE(42) === localOffset);
      const length = c.readUInt32LE(24); const nameLength = c.readUInt16LE(28);
      need(length > 0 && length <= (expectedName === EMBEDDED_MANIFEST ? MAX_MANIFEST_BYTES : 65_536) &&
        c.readUInt32LE(20) === length && nameLength === Buffer.byteLength(expectedName) &&
        centralOffset + 46 + nameLength <= end);
      const name = bytes.subarray(centralOffset + 46, centralOffset + 46 + nameLength);
      need(name.equals(Buffer.from(expectedName, 'ascii')));
      need(localOffset + 30 + nameLength + length <= centralStart && bytes.readUInt32LE(localOffset) === 0x04034b50);
      const l = bytes.subarray(localOffset, localOffset + 30);
      need(l.readUInt16LE(4) === 20 && l.readUInt16LE(6) === 0 && l.readUInt16LE(8) === 0 &&
        l.readUInt16LE(10) === 0 && l.readUInt16LE(12) === 33 && l.readUInt32LE(14) === c.readUInt32LE(16) &&
        l.readUInt32LE(18) === length && l.readUInt32LE(22) === length && l.readUInt16LE(26) === nameLength &&
        l.readUInt16LE(28) === 0 && bytes.subarray(localOffset + 30, localOffset + 30 + nameLength).equals(name));
      const payload = bytes.subarray(localOffset + 30 + nameLength, localOffset + 30 + nameLength + length);
      need(crc32(payload) === c.readUInt32LE(16));
      if (expectedName === EMBEDDED_MANIFEST) embedded = payload;
      else {
        const source = new TextDecoder('utf-8', { fatal: true }).decode(payload);
        need(Buffer.from(source).equals(payload)); files.set(expectedName.slice(REVIEW_ROOT.length + 1), source);
      }
      localOffset += 30 + nameLength + length; centralOffset += 46 + nameLength;
    }
    need(localOffset === centralStart && centralOffset === end);
    const closure = validateWordPressBundle(files); need(closure.sourceClosureSha256 === REVIEWED_SOURCE_CLOSURE_SHA256);
    const review = reviewManifest(closure); need(embedded && embedded.equals(Buffer.from(json(review))));
    return { files, manifest: publicManifest(review, bytes) };
  } catch { throw failure(); }
}

function plainDirectory(path) {
  need(isAbsolute(path) && resolve(path) === path && realpathSync(path) === path);
  const root = parse(path).root; let current = root;
  for (const part of path.slice(root.length).split('/').filter(Boolean)) {
    current = join(current, part); const stat = lstatSync(current);
    need(stat.isDirectory() && !stat.isSymbolicLink());
  }
}

function outputPath(path) {
  need(typeof path === 'string' && path.length > 1 && path.length <= 4096 &&
    !/[\0-\x1f\x7f]/u.test(path) && isAbsolute(path) && resolve(path) === path);
  // Review files must not be written to a WordPress installation or hidden state
  // tree. Existing parents are inspected only for directory identity, never content.
  need(!path.split('/').some(part => part.startsWith('.') || ['wp-content', 'mu-plugins', 'plugins'].includes(part)));
  plainDirectory(dirname(path));
  let absent = false;
  try { lstatSync(path); } catch (error) { absent = error.code === 'ENOENT'; }
  need(absent);
}

function assertOutputDirectory(path, expected) {
  plainDirectory(path); const actual = lstatSync(path);
  need(actual.dev === expected.dev && actual.ino === expected.ino && (actual.mode & 0o777) === 0o700);
}

function writeNewFile(directory, directoryStat, name, bytes) {
  assertOutputDirectory(directory, directoryStat); const path = join(directory, name); let fd;
  try {
    fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    writeFileSync(fd, bytes); fsyncSync(fd);
    const actual = fstatSync(fd);
    need(actual.isFile() && actual.nlink === 1 && actual.size === bytes.length && (actual.mode & 0o777) === 0o600);
  } finally { if (fd !== undefined) closeSync(fd); }
  assertOutputDirectory(directory, directoryStat);
}

function readNewFile(directory, directoryStat, name, expectedBytes) {
  assertOutputDirectory(directory, directoryStat); const path = join(directory, name); let fd;
  const before = lstatSync(path);
  need(before.isFile() && !before.isSymbolicLink() && before.nlink === 1 && before.size === expectedBytes &&
    (before.mode & 0o777) === 0o600 && realpathSync(path) === path);
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW); const opened = fstatSync(fd);
    need(opened.dev === before.dev && opened.ino === before.ino && opened.nlink === 1);
    const bytes = readFileSync(fd); const after = fstatSync(fd); const current = lstatSync(path);
    need(bytes.length === expectedBytes && after.dev === before.dev && after.ino === before.ino &&
      after.nlink === 1 && after.size === before.size && after.mtimeMs === before.mtimeMs && after.ctimeMs === before.ctimeMs &&
      current.dev === before.dev && current.ino === before.ino && current.nlink === 1 &&
      current.isFile() && !current.isSymbolicLink() && current.size === before.size &&
      current.mtimeMs === before.mtimeMs && current.ctimeMs === before.ctimeMs);
    assertOutputDirectory(directory, directoryStat); return bytes;
  } finally { if (fd !== undefined) closeSync(fd); }
}

/** Local file creation only. The explicit absolute directory must not exist;
 * its parent must already exist and be canonical. Never overwrites or cleans up
 * a partial result. Ordinary races are checked, not a hostile-writer sandbox. */
export function writeWordPressReviewBundle(outputDirectory) {
  try {
    outputPath(outputDirectory);
    const bundle = buildWordPressReviewBundle(assembleWordPressBundle());
    const manifestBytes = Buffer.from(json(bundle.manifest));
    mkdirSync(outputDirectory, { mode: 0o700 }); const directoryStat = lstatSync(outputDirectory);
    assertOutputDirectory(outputDirectory, directoryStat);
    writeNewFile(outputDirectory, directoryStat, REVIEW_ARCHIVE_NAME, bundle.archive);
    writeNewFile(outputDirectory, directoryStat, REVIEW_MANIFEST_NAME, manifestBytes);
    const archive = readNewFile(outputDirectory, directoryStat, REVIEW_ARCHIVE_NAME, bundle.archive.length);
    const manifest = readNewFile(outputDirectory, directoryStat, REVIEW_MANIFEST_NAME, manifestBytes.length);
    const verified = validateWordPressReviewArchive(archive);
    need(manifest.equals(Buffer.from(json(verified.manifest))) && archive.equals(bundle.archive) &&
      JSON.stringify(readdirSync(outputDirectory).sort()) === JSON.stringify([REVIEW_ARCHIVE_NAME, REVIEW_MANIFEST_NAME].sort()));
    return verified.manifest;
  } catch { throw failure(); }
}

const invoked = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invoked) {
  try {
    need(process.argv.length === 4 && process.argv[2] === '--output-dir');
    console.log(json(writeWordPressReviewBundle(process.argv[3])).trimEnd());
  } catch {
    console.error('WordPress review bundle rejected; KEEP_CLOSED. No install or activation performed. Any fresh partial output is retained for inspection.');
    process.exitCode = 1;
  }
}
