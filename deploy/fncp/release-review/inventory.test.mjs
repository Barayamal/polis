import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, realpathSync, mkdirSync, writeFileSync, unlinkSync, symlinkSync, linkSync, rmSync, rmdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { FIXED_MANIFEST } from './manifest.mjs';
import { inventoryRepository, validateManifest, validateArtifactClaims, safeSourcePath, safeFailure } from './inventory.mjs';

const clone = () => structuredClone(FIXED_MANIFEST);
function fixture(t) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'fncp-offline-inventory-')));
  t.after(() => rmSync(root, { recursive: true }));
  for (const path of FIXED_MANIFEST.sourcePaths) { mkdirSync(dirname(join(root, path)), { recursive: true }); writeFileSync(join(root, path), 'INVENTED SOURCE FIXTURE: ' + path); }
  return root;
}
const claims = () => FIXED_MANIFEST.components.filter(entry => entry.kind === 'POLIS_IMAGE').map(entry => ({ id: entry.id, reference: 'example.test/polis@sha256:' + 'a'.repeat(64) }));

test('fixed manifest includes exactly five application artifacts, including migration', () => {
  assert.deepEqual(FIXED_MANIFEST.components.filter(entry => entry.kind === 'POLIS_IMAGE').map(entry => entry.id), ['polis-server', 'polis-math', 'polis-alpha', 'polis-proxy', 'polis-migration']);
  assert.equal(FIXED_MANIFEST.components.length, 20);
  assert.ok(FIXED_MANIFEST.components.find(entry => entry.id === 'identity-adapter')
    .sources.includes('deploy/fncp/identity-foundation/bounded-response.mjs'));
  assert.equal(new Set(FIXED_MANIFEST.sourcePaths).size, FIXED_MANIFEST.sourcePaths.length);
});
test('fixed manifest is deeply immutable', () => { assert.throws(() => FIXED_MANIFEST.components[0].sources.push('secret')); assert.throws(() => { FIXED_MANIFEST.components[0].gap = ''; }); });
test('inventory hashes exact source entries, returns no contents or absolute root', t => {
  const root = fixture(t), report = inventoryRepository(root);
  assert.equal(report.inventoryComplete, true); assert.equal(report.classification, 'KEEP_CLOSED'); assert.equal(report.deployable, false); assert.equal(report.activationAuthority, false);
  assert.equal(report.coverage.polisImageArtifacts, 5); assert.equal(report.coverage.measuredImages, 0); assert.equal(report.coverage.npmLockfiles, 3);
  assert.equal(report.coverage.excludedFromFiveImageCoverage.length, 15);
  assert.equal(JSON.stringify(report).includes(root), false); assert.equal(JSON.stringify(report).includes('INVENTED SOURCE FIXTURE:'), false);
  const entry = report.sources[0]; assert.equal(entry.sha256, createHash('sha256').update(readFileSync(join(root, entry.path))).digest('hex'));
});
test('file changes alter source entry digest without granting authority', t => {
  const root = fixture(t), before = inventoryRepository(root);
  writeFileSync(join(root, FIXED_MANIFEST.sourcePaths[0]), 'CHANGED INVENTED SOURCE');
  const after = inventoryRepository(root); assert.notEqual(before.sourceEntryDigest, after.sourceEntryDigest); assert.equal(after.classification, 'KEEP_CLOSED');
});
test('repeated unchanged inventory is deterministic', t => { const root = fixture(t); assert.deepEqual(inventoryRepository(root), inventoryRepository(root)); });
test('unlisted private state is neither scanned nor hashed', t => {
  const root = fixture(t); const before = inventoryRepository(root);
  mkdirSync(join(root, 'deploy/fncp/local-access/.runtime'), { recursive: true });
  writeFileSync(join(root, 'deploy/fncp/local-access/.runtime/private.sqlite'), 'NEVER READ THIS PRIVATE FIXTURE');
  writeFileSync(join(root, '.env'), 'DO_NOT_OUTPUT_PRIVATE_FIXTURE');
  assert.deepEqual(inventoryRepository(root), before);
});
for (const [name, change] of [
  ['missing critical component', m => m.components.splice(0, 1)],
  ['duplicate critical component', m => m.components.push(m.components[0])],
  ['missing critical source', m => m.sourcePaths.splice(0, 1)],
  ['duplicate source', m => m.sourcePaths.push(m.sourcePaths[0])],
  ['missing dependency lock', m => m.dependencyFiles.pop()],
  ['changed kind', m => { m.components[0].kind = 'EXTERNAL_DEPENDENCY'; }],
  ['cleared gap', m => { m.components[0].gap = ''; }],
  ['GO metadata injection', m => { m.classification = 'GO'; }],
  ['private source substitution', m => { m.sourcePaths[0] = '.env'; }],
]) test('manifest rejects ' + name, () => { const m = clone(); change(m); assert.throws(() => validateManifest(m), { message: 'MANIFEST_REJECTED' }); });
test('manifest rejects toJSON laundering of a truncated source list', () => {
  const m = clone(); m.sourcePaths.pop(); m.toJSON = () => FIXED_MANIFEST;
  assert.throws(() => validateManifest(m), { message: 'MANIFEST_REJECTED' });
});
test('manifest rejects accessors before invoking them', () => {
  const m = clone(); let called = false; Object.defineProperty(m, 'sourcePaths', { enumerable: true, get() { called = true; return FIXED_MANIFEST.sourcePaths; } });
  assert.throws(() => validateManifest(m), { message: 'MANIFEST_REJECTED' }); assert.equal(called, false);
});
test('manifest rejects hidden symbol metadata', () => { const m = clone(); m[Symbol('GO')] = true; assert.throws(() => validateManifest(m), { message: 'MANIFEST_REJECTED' }); });
test('manifest rejects cycles rather than serializing raw errors', () => { const m = clone(); m.cycle = m; assert.throws(() => validateManifest(m), { message: 'MANIFEST_REJECTED' }); });

for (const path of ['/tmp/file', '../file', 'server/../file', './file', 'server//file', 'server\\file', '.env', 'prod.env', 'server/keys/key.pem', 'deploy/fncp/.runtime/data', 'deploy/fncp/evidence/status.json', 'server/node_modules/pkg/index.js', 'server/private.sqlite-wal', 'server/wp-config.php', 'server/%2e%2e/file', 'server/file\0']) {
  test('path boundary rejects ' + JSON.stringify(path), () => assert.throws(() => safeSourcePath(path), { message: 'SOURCE_PATH_REJECTED' }));
}
test('missing source fails without exposing path', t => { const root = fixture(t); unlinkSync(join(root, FIXED_MANIFEST.sourcePaths[0])); assert.throws(() => inventoryRepository(root), { message: 'SOURCE_UNAVAILABLE' }); });
test('symlink source rejects without following private target', t => {
  const root = fixture(t), target = join(root, FIXED_MANIFEST.sourcePaths[0]); unlinkSync(target); writeFileSync(join(root, '.env'), 'PRIVATE'); symlinkSync(join(root, '.env'), target);
  assert.throws(() => inventoryRepository(root), { message: 'SOURCE_BOUNDARY_REJECTED' });
});
test('hardlinked source is rejected', t => { const root = fixture(t); linkSync(join(root, FIXED_MANIFEST.sourcePaths[0]), join(root, 'hardlink')); assert.throws(() => inventoryRepository(root), { message: 'SOURCE_BOUNDARY_REJECTED' }); });
test('directory replacing source is rejected', t => { const root = fixture(t), target = join(root, FIXED_MANIFEST.sourcePaths[0]); unlinkSync(target); mkdirSync(target); assert.throws(() => inventoryRepository(root), { message: 'SOURCE_BOUNDARY_REJECTED' }); });
test('oversize source is rejected before hashing', t => { const root = fixture(t); writeFileSync(join(root, FIXED_MANIFEST.sourcePaths[0]), Buffer.alloc(8 * 1024 * 1024 + 1)); assert.throws(() => inventoryRepository(root), { message: 'SOURCE_BOUNDARY_REJECTED' }); });
test('root symlink alias is rejected', t => {
  const root = fixture(t), alias = root + '-alias'; symlinkSync(root, alias); t.after(() => unlinkSync(alias));
  assert.throws(() => inventoryRepository(alias), { message: 'ROOT_REJECTED' });
});
test('noncanonical root alias is rejected', t => { const root = fixture(t); assert.throws(() => inventoryRepository(root + '/.'), { message: 'ROOT_REJECTED' }); });
test('ancestor symlink is rejected', t => {
  const root = fixture(t), directory = join(root, 'server/src/auth'), target = join(root, 'moved-auth');
  mkdirSync(target); for (const name of ['fncp-production-admission.ts', 'fncp-participant-policy.ts', 'fncp-gateway.ts']) { writeFileSync(join(target, name), 'INVENTED'); unlinkSync(join(directory, name)); }
  rmdirSync(directory); symlinkSync(target, directory); assert.throws(() => inventoryRepository(root), { message: 'SOURCE_BOUNDARY_REJECTED' });
});
test('five digest-form claims remain unverified and cannot change KEEP_CLOSED', t => { const root = fixture(t); assert.deepEqual(validateArtifactClaims(claims()), { submitted: 5, independentlyVerified: false }); assert.deepEqual(inventoryRepository(root, { artifactClaims: claims() }), inventoryRepository(root)); });
for (const [name, change] of [
  ['mutable tag', c => { c[0].reference = 'example.test/polis:latest'; }],
  ['bare local image ID', c => { c[0].reference = 'sha256:' + 'a'.repeat(64); }],
  ['missing artifact', c => { c.pop(); }],
  ['duplicate artifact', c => { c[4] = c[0]; }],
  ['unknown artifact', c => { c[0].id = 'wordpress'; }],
  ['malformed digest', c => { c[0].reference = 'example.test/polis@sha256:abc'; }],
  ['upper-case digest', c => { c[0].reference = 'example.test/polis@sha256:' + 'A'.repeat(64); }],
  ['URL credentials', c => { c[0].reference = 'https://secret@example.test/polis@sha256:' + 'a'.repeat(64); }],
  ['trailing newline', c => { c[0].reference += '\n'; }],
  ['claimed verification', c => { c[0].verified = true; }],
]) test('image assertions reject ' + name, () => { const c = claims(); change(c); assert.throws(() => validateArtifactClaims(c), { message: 'IMAGE_CLAIMS_REJECTED' }); });
test('raw diagnostic is replaced by fixed fail-closed response', () => { const output = JSON.stringify(safeFailure(new Error('SECRET /private/path'))); assert.equal(output.includes('SECRET'), false); assert.equal(output.includes('/private/path'), false); assert.equal(JSON.parse(output).classification, 'KEEP_CLOSED'); });
test('command rejects arbitrary path arguments with structured safe output', () => {
  const run = spawnSync(process.execPath, [fileURLToPath(new URL('./inventory.mjs', import.meta.url)), '--root=/private/secret'], { encoding: 'utf8' });
  assert.equal(run.status, 1); const report = JSON.parse(run.stdout); assert.equal(report.error, 'ARGUMENTS_REJECTED'); assert.equal(report.classification, 'KEEP_CLOSED'); assert.equal(run.stderr, ''); assert.equal(run.stdout.includes('/private/secret'), false);
});
test('command performs actual bounded repository inventory without runtime startup', () => {
  const report = JSON.parse(execFileSync(process.execPath, [fileURLToPath(new URL('./inventory.mjs', import.meta.url))], { encoding: 'utf8' }));
  assert.equal(report.inventoryComplete, true); assert.equal(report.classification, 'KEEP_CLOSED'); assert.equal(report.coverage.networkUsed, false); assert.equal(report.coverage.runtimeServicesImportedOrStarted, false);
  assert.ok(report.components.every(entry => entry.gap.length > 60));
});
