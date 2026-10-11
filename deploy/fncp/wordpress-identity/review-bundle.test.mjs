import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync,
  symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assembleWordPressBundle, validateWordPressBundle, WORDPRESS_FILES, WORDPRESS_ENTRY } from './package-check.mjs';
import { buildWordPressReviewBundle, validateWordPressReviewArchive, writeWordPressReviewBundle,
  REVIEW_ROOT, REVIEW_ARCHIVE_NAME, REVIEW_MANIFEST_NAME, REVIEWED_SOURCE_CLOSURE_SHA256 } from './review-bundle.mjs';

const source = assembleWordPressBundle();
const bundle = () => buildWordPressReviewBundle(source);
const rejected = operation => assert.throws(operation, /^Error: WordPress review bundle rejected; KEEP_CLOSED\.$/u);
const checker = fileURLToPath(new URL('./review-bundle.mjs', import.meta.url));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
function directory(t) {
  const path = realpathSync(mkdtempSync(join(tmpdir(), 'fncp-wordpress-review-test-')));
  t.after(() => rmSync(path, { recursive: true, force: true })); return path;
}
function changeArchive(change) { const bytes = bundle().archive; change(bytes); return bytes; }
function offsets(bytes) {
  const end = bytes.length - 22; const central = bytes.readUInt32LE(end + 16); const result = [];
  let position = central;
  for (let index = 0; index < 6; index++) {
    const nameLength = bytes.readUInt16LE(position + 28);
    const local = bytes.readUInt32LE(position + 42);
    const length = bytes.readUInt32LE(position + 24);
    result.push({ central: position, local, payload: local + 30 + nameLength, length, nameLength });
    position += 46 + nameLength;
  }
  return { end, central, entries: result };
}
// Test-only second CRC implementation: no implementation helper is imported.
function crc(bytes) {
  let value = 0xffffffff;
  for (const byte of bytes) {
    value ^= byte;
    for (let bit = 0; bit < 8; bit++) value = value & 1 ? (value >>> 1) ^ 0xedb88320 : value >>> 1;
  }
  return (value ^ 0xffffffff) >>> 0;
}
function mutatePayloadAndRepairCrc(bytes, index, mutate) {
  const entry = offsets(bytes).entries[index]; const payload = bytes.subarray(entry.payload, entry.payload + entry.length);
  mutate(payload); const checksum = crc(payload);
  bytes.writeUInt32LE(checksum, entry.local + 14); bytes.writeUInt32LE(checksum, entry.central + 16);
}

test('deterministic review ZIP round-trips the exact five original PHP source bytes', () => {
  const first = bundle(); const second = bundle(); const reversed = buildWordPressReviewBundle({ files: new Map([...source.files].reverse()), manifest: source.manifest });
  assert.ok(first.archive.equals(second.archive)); assert.ok(first.archive.equals(reversed.archive));
  assert.deepEqual(first.manifest, second.manifest);
  const verified = validateWordPressReviewArchive(first.archive);
  assert.deepEqual([...verified.files], [...source.files]); assert.deepEqual(verified.manifest, first.manifest);
  assert.equal(verified.manifest.sourceClosureSha256, REVIEWED_SOURCE_CLOSURE_SHA256);
  assert.equal(verified.manifest.archive.sha256, sha(first.archive));
  assert.equal(verified.manifest.archive.bytes, first.archive.length); assert.equal(verified.manifest.archive.entries, 6);
  assert.equal(first.archive.length, 50986); assert.equal(first.manifest.archive.sha256, '368a1f3569d459a08cbbf14dac8149e2523c8a07e8289cbeee6ba14ce86ef40a');
});

test('archive preserves original sibling require paths and disabled-by-default guards', () => {
  const { files, manifest } = validateWordPressReviewArchive(bundle().archive);
  assert.deepEqual([...files.keys()], WORDPRESS_FILES);
  assert.match(files.get(WORDPRESS_ENTRY), /require_once __DIR__ \. '\/\.\.\/wordpress-local\/journal\.php';/u);
  assert.match(files.get(WORDPRESS_ENTRY), /FNCP_WP_SYNTHETIC_ONLY !== true/u);
  assert.match(files.get(WORDPRESS_ENTRY), /FNCP_WP_IDENTITY_FRESH_INSTANCE !== true/u);
  assert.match(files.get(WORDPRESS_ENTRY), /wp_get_environment_type\(\) !== 'local'/u);
  assert.equal(manifest.classification, 'LOCAL_REVIEW_ONLY_KEEP_CLOSED'); assert.equal(manifest.mode, 'SYNTHETIC_ONLY');
  for (const key of ['productionReady', 'deployablePackage', 'launchAuthority']) assert.equal(manifest[key], false);
  assert.equal(manifest.sourceFiles, 5); assert.equal(manifest.dependencyCount, 5);
  assert.ok(!JSON.stringify(manifest).includes('<?php')); assert.ok(!JSON.stringify(manifest).includes('.runtime'));
});

test('caller maps, source manifests and previous archive results are not mutated or shared', () => {
  const beforeFiles = [...source.files]; const beforeManifest = JSON.stringify(source.manifest);
  const first = bundle(); const snapshot = Buffer.from(first.archive);
  const result = validateWordPressReviewArchive(first.archive); result.files.clear(); result.manifest.archive.sha256 = 'invented';
  assert.equal(validateWordPressReviewArchive(first.archive).files.size, 5);
  assert.ok(first.archive.equals(snapshot)); assert.deepEqual([...source.files], beforeFiles);
  assert.equal(JSON.stringify(source.manifest), beforeManifest);
});
test('archive validation consumes raw bytes without executing Buffer hooks or accessors', () => {
  let touched = 0; const archive = bundle().archive;
  archive.valueOf = () => { touched++; return archive; };
  archive.subarray = () => { touched++; throw new Error('must not run'); };
  archive.readUInt32LE = () => { touched++; throw new Error('must not run'); };
  Object.defineProperty(archive, 'length', { get() { touched++; throw new Error('must not run'); } });
  assert.equal(validateWordPressReviewArchive(archive).files.size, 5); assert.equal(touched, 0);
});

for (const [name, value] of [['missing', undefined], ['null', null], ['array', []], ['string', 'private-invented'], ['empty', {}]]) {
  test('unsafe source input rejected: ' + name, () => rejected(() => buildWordPressReviewBundle(value)));
}
for (const missing of WORDPRESS_FILES) test('missing dependency cannot be archived: ' + missing, () => {
  const files = new Map(source.files); files.delete(missing);
  rejected(() => buildWordPressReviewBundle({ files, manifest: source.manifest }));
});
for (const path of ['../private.php', '/absolute.php', 'wordpress-identity/../wordpress-local/contract.php',
  'wordpress-identity/.runtime/state.php', 'wordpress-identity\\registry.php', 'WORDPRESS-IDENTITY/registry.php']) {
  test('extra traversal or alias cannot enter archive: ' + path, () => {
    const files = new Map(source.files); files.set(path, '<?php\n');
    rejected(() => buildWordPressReviewBundle({ files, manifest: source.manifest }));
  });
}

test('source drift is denied even with a valid re-derived dependency manifest', () => {
  const files = new Map(source.files); files.set(WORDPRESS_ENTRY, files.get(WORDPRESS_ENTRY) + '\n// changed source\n');
  const manifest = validateWordPressBundle(files); assert.notEqual(manifest.sourceClosureSha256, REVIEWED_SOURCE_CLOSURE_SHA256);
  rejected(() => buildWordPressReviewBundle({ files, manifest }));
});
test('removing a synthetic guard cannot be hidden behind unchanged dependency paths', () => {
  const files = new Map(source.files); files.set(WORDPRESS_ENTRY, files.get(WORDPRESS_ENTRY).replace('FNCP_WP_SYNTHETIC_ONLY !== true', 'false'));
  const manifest = validateWordPressBundle(files); assert.equal(manifest.closureComplete, true);
  rejected(() => buildWordPressReviewBundle({ files, manifest }));
});
test('source manifest claims must exactly match source-checker output', () => {
  for (const changed of [{ ...source.manifest, productionReady: true }, { ...source.manifest, sourceClosureSha256: '0'.repeat(64) },
    { ...source.manifest, files: [] }, { ...source.manifest, extra: 'private-invented' }]) {
    rejected(() => buildWordPressReviewBundle({ files: source.files, manifest: changed }));
  }
});
test('source accessors and JSON hooks are not executed', () => {
  let touched = 0;
  const getterInput = { manifest: source.manifest }; Object.defineProperty(getterInput, 'files', { enumerable: true, get() { touched++; return source.files; } });
  rejected(() => buildWordPressReviewBundle(getterInput));
  const manifest = { ...source.manifest }; Object.defineProperty(manifest, 'files', { enumerable: true, get() { touched++; return []; } });
  rejected(() => buildWordPressReviewBundle({ files: source.files, manifest }));
  rejected(() => buildWordPressReviewBundle({ files: source.files, manifest: { ...source.manifest, toJSON() { touched++; return source.manifest; } } }));
  assert.equal(touched, 0);
});
test('map subclasses, own overrides, symbols, cycles and non-data manifests are rejected', () => {
  class CustomMap extends Map {}
  rejected(() => buildWordPressReviewBundle({ files: new CustomMap(source.files), manifest: source.manifest }));
  const overridden = new Map(source.files); overridden.get = () => { throw new Error('must not run'); };
  rejected(() => buildWordPressReviewBundle({ files: overridden, manifest: source.manifest }));
  const cycle = { ...source.manifest }; cycle.files = cycle;
  for (const manifest of [cycle, new Date(), Object.assign({ ...source.manifest }, { [Symbol('x')]: true }),
    { ...source.manifest, files: new Array(5) }, Object.create(source.manifest)]) {
    rejected(() => buildWordPressReviewBundle({ files: source.files, manifest }));
  }
});

for (const [name, value] of [['null', null], ['string', 'private-invented'], ['array', []],
  ['typed-array', new Uint8Array(32)], ['empty', Buffer.alloc(0)], ['oversized', Buffer.alloc(327681)]]) {
  test('unsafe archive input rejected: ' + name, () => rejected(() => validateWordPressReviewArchive(value)));
}
for (const [name, mutation] of [
  ['leading bytes', bytes => Buffer.concat([Buffer.from('bad'), bytes])],
  ['trailing bytes', bytes => Buffer.concat([bytes, Buffer.from('bad')])],
  ['truncated EOCD', bytes => bytes.subarray(0, -1)],
  ['truncated local body', bytes => bytes.subarray(0, 100)],
  ['extra full archive', bytes => Buffer.concat([bytes, bytes])],
]) test('non-canonical ZIP framing rejected: ' + name, () => rejected(() => validateWordPressReviewArchive(mutation(bundle().archive))));

for (const [name, field, value, width] of [
  ['local signature', 0, 0, 4], ['required version', 4, 10, 2], ['encrypted flag', 6, 1, 2],
  ['data descriptor flag', 6, 8, 2], ['deflate method', 8, 8, 2], ['time', 10, 1, 2], ['date', 12, 34, 2],
  ['crc', 14, 0, 4], ['compressed size', 18, 0, 4], ['uncompressed size', 22, 0, 4],
  ['name length', 26, 1, 2], ['extra fields', 28, 1, 2],
]) test('ambiguous local ZIP metadata rejected: ' + name, () => {
  const bytes = changeArchive(bytes => bytes[width === 4 ? 'writeUInt32LE' : 'writeUInt16LE'](value, field));
  rejected(() => validateWordPressReviewArchive(bytes));
});

for (const [name, field, value, width] of [
  ['central signature', 0, 0, 4], ['creator version', 4, 20, 2], ['needed version', 6, 10, 2],
  ['encrypted flag', 8, 1, 2], ['method', 10, 8, 2], ['time', 12, 1, 2], ['date', 14, 34, 2],
  ['CRC', 16, 0, 4], ['compressed size', 20, 0, 4], ['uncompressed size', 24, 0xffffffff, 4],
  ['name length', 28, 1, 2], ['extra', 30, 1, 2], ['comment', 32, 1, 2], ['disk number', 34, 1, 2],
  ['internal attributes', 36, 1, 2], ['symlink attributes', 38, (0o120777 << 16) >>> 0, 4],
  ['executable attributes', 38, (0o100755 << 16) >>> 0, 4], ['overlapping local offset', 42, 1, 4],
]) test('ambiguous central ZIP metadata rejected: ' + name, () => {
  const bytes = changeArchive(bytes => { const { central } = offsets(bytes); bytes[width === 4 ? 'writeUInt32LE' : 'writeUInt16LE'](value, central + field); });
  rejected(() => validateWordPressReviewArchive(bytes));
});

for (const [name, field, value, width] of [
  ['EOCD signature', 0, 0, 4], ['disk number', 4, 1, 2], ['central disk', 6, 1, 2],
  ['this disk entries', 8, 5, 2], ['all entries', 10, 7, 2], ['central size', 12, 1, 4],
  ['central offset', 16, 1, 4], ['ZIP64 offset', 16, 0xffffffff, 4], ['comment length', 20, 1, 2],
]) test('multi-disk, ZIP64 or malformed trailer rejected: ' + name, () => {
  const bytes = changeArchive(bytes => { const { end } = offsets(bytes); bytes[width === 4 ? 'writeUInt32LE' : 'writeUInt16LE'](value, end + field); });
  rejected(() => validateWordPressReviewArchive(bytes));
});

test('local and central traversal names are rejected even when they agree', () => {
  const bytes = changeArchive(bytes => { const e = offsets(bytes).entries[0];
    bytes.write('../', e.local + 30, 'ascii'); bytes.write('../', e.central + 46, 'ascii'); });
  rejected(() => validateWordPressReviewArchive(bytes));
});
test('backslash, case and null-byte name aliases are rejected', () => {
  for (const value of [0x5c, 0x46, 0]) {
    const bytes = changeArchive(bytes => { const e = offsets(bytes).entries[0]; bytes[e.local + 30] = value; bytes[e.central + 46] = value; });
    rejected(() => validateWordPressReviewArchive(bytes));
  }
});
test('duplicate entry names cannot replace a required dependency', () => {
  const bytes = changeArchive(bytes => { const { entries } = offsets(bytes); const first = entries[0]; const second = entries[1];
    const name = bytes.subarray(first.central + 46, first.central + 46 + first.nameLength);
    name.copy(bytes, second.local + 30); name.copy(bytes, second.central + 46); });
  rejected(() => validateWordPressReviewArchive(bytes));
});
test('payload damage is rejected by checksums', () => {
  const bytes = changeArchive(bytes => { bytes[offsets(bytes).entries[0].payload + 7] ^= 1; });
  rejected(() => validateWordPressReviewArchive(bytes));
});
test('CRC-repaired source tampering still fails the reviewed SHA256 pin', () => {
  const bytes = changeArchive(bytes => mutatePayloadAndRepairCrc(bytes, 0, payload => {
    const text = payload.toString(); const position = text.indexOf('FNCP'); assert.ok(position > 0); payload[position] = 'Z'.charCodeAt(0);
  }));
  rejected(() => validateWordPressReviewArchive(bytes));
});
test('CRC-repaired embedded GO claim fails canonical manifest validation', () => {
  const bytes = changeArchive(bytes => mutatePayloadAndRepairCrc(bytes, 5, payload => {
    const position = payload.indexOf('"productionReady": false'); assert.ok(position >= 0);
    payload.write('"productionReady": true ', position, 'utf8');
  }));
  rejected(() => validateWordPressReviewArchive(bytes));
});

test('writer creates only two verified files in a fresh restrictive local directory', t => {
  const parent = directory(t); const output = join(parent, 'review');
  const manifest = writeWordPressReviewBundle(output);
  assert.deepEqual(readdirSync(output).sort(), [REVIEW_ARCHIVE_NAME, REVIEW_MANIFEST_NAME].sort());
  assert.equal(lstatSync(output).mode & 0o777, 0o700);
  for (const name of [REVIEW_ARCHIVE_NAME, REVIEW_MANIFEST_NAME]) assert.equal(lstatSync(join(output, name)).mode & 0o777, 0o600);
  assert.deepEqual(JSON.parse(readFileSync(join(output, REVIEW_MANIFEST_NAME), 'utf8')), manifest);
  assert.deepEqual(validateWordPressReviewArchive(readFileSync(join(output, REVIEW_ARCHIVE_NAME))).manifest, manifest);
});
test('fresh-directory writer never overwrites an existing result or unrelated file', t => {
  const parent = directory(t); const output = join(parent, 'review');
  writeWordPressReviewBundle(output); const archive = readFileSync(join(output, REVIEW_ARCHIVE_NAME));
  rejected(() => writeWordPressReviewBundle(output)); assert.ok(readFileSync(join(output, REVIEW_ARCHIVE_NAME)).equals(archive));
  const existing = join(parent, 'existing'); writeFileSync(existing, 'preserved-invented');
  rejected(() => writeWordPressReviewBundle(existing)); assert.equal(readFileSync(existing, 'utf8'), 'preserved-invented');
});
test('even an empty pre-existing or partial output directory is rejected without cleanup', t => {
  const parent = directory(t); const output = join(parent, 'review'); mkdirSync(output);
  rejected(() => writeWordPressReviewBundle(output)); assert.deepEqual(readdirSync(output), []);
  writeFileSync(join(output, 'partial'), 'preserve'); rejected(() => writeWordPressReviewBundle(output));
  assert.equal(readFileSync(join(output, 'partial'), 'utf8'), 'preserve');
});
test('a hardlinked existing output name cannot be overwritten or unlinked', t => {
  const parent = directory(t); const original = join(parent, 'original'); const output = join(parent, 'review');
  writeFileSync(original, 'preserved-invented'); linkSync(original, output);
  rejected(() => writeWordPressReviewBundle(output));
  assert.equal(readFileSync(original, 'utf8'), 'preserved-invented'); assert.equal(readFileSync(output, 'utf8'), 'preserved-invented');
  assert.equal(lstatSync(output).nlink, 2);
});
test('symlink output and symlink parents are rejected without following their contents', t => {
  const parent = directory(t); const real = join(parent, 'real'); mkdirSync(real);
  const alias = join(parent, 'alias'); symlinkSync(real, alias);
  rejected(() => writeWordPressReviewBundle(alias)); rejected(() => writeWordPressReviewBundle(join(alias, 'review')));
  assert.deepEqual(readdirSync(real), []);
});
test('relative, aliased, missing-parent, hidden-state and plugin-installation paths are rejected', t => {
  const parent = directory(t);
  for (const path of ['relative-review', parent + '/.', parent + '/fresh/../review', parent + '/review/',
    join(parent, 'missing', 'review'), join(parent, '.runtime', 'review'), join(parent, 'wp-content', 'review'),
    join(parent, 'plugins', 'review'), join(parent, 'mu-plugins', 'review'), parent + '/review\0private-invented']) {
    rejected(() => writeWordPressReviewBundle(path));
  }
  assert.deepEqual(readdirSync(parent), []);
});
test('module import is inert and produces no output files', t => {
  const parent = directory(t);
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', 'await import(' + JSON.stringify(new URL('./review-bundle.mjs', import.meta.url).href) + ')'],
    { cwd: parent, encoding: 'utf8' });
  assert.equal(result.status, 0); assert.equal(result.stdout, ''); assert.equal(result.stderr, ''); assert.deepEqual(readdirSync(parent), []);
});
test('CLI requires an explicit fresh output directory and never silently accepts extra actions', t => {
  const parent = directory(t);
  for (const args of [[], ['--output-dir'], ['--install'], ['--output-dir', join(parent, 'new'), '--activate'],
    ['--output-dir', join(parent, 'new'), '--source', 'private-invented'], ['--output-dir=' + join(parent, 'new')]]) {
    const result = spawnSync(process.execPath, [checker, ...args], { cwd: parent, encoding: 'utf8' });
    assert.equal(result.status, 1); assert.equal(result.stdout, ''); assert.ok(!result.stderr.includes('private-invented'));
  }
  assert.deepEqual(readdirSync(parent), []);
});
test('CLI writes deterministic archive and manifest bytes across separate fresh directories', t => {
  const parent = directory(t); const first = join(parent, 'first'); const second = join(parent, 'second');
  const a = JSON.parse(execFileSync(process.execPath, [checker, '--output-dir', first], { encoding: 'utf8' }));
  const b = JSON.parse(execFileSync(process.execPath, [checker, '--output-dir', second], { encoding: 'utf8' }));
  assert.deepEqual(a, b);
  for (const name of [REVIEW_ARCHIVE_NAME, REVIEW_MANIFEST_NAME]) assert.ok(readFileSync(join(first, name)).equals(readFileSync(join(second, name))));
  const result = spawnSync(process.execPath, [checker, '--output-dir', first], { encoding: 'utf8' }); assert.equal(result.status, 1);
  assert.equal(a.archive.filename, REVIEW_ROOT + '.zip');
});
