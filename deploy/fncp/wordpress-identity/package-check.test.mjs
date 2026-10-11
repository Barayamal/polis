import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, linkSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assembleWordPressBundle, validateWordPressBundle, WORDPRESS_ENTRY, WORDPRESS_FILES } from './package-check.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const checker = fileURLToPath(new URL('./package-check.mjs', import.meta.url));
const actual = () => new Map(WORDPRESS_FILES.map(path => [path, readFileSync(join(root, path), 'utf8')]));
const rejects = files => assert.throws(() => validateWordPressBundle(files), /^Error: WordPress source closure rejected\.$/u);
const edited = (path, mutation) => { const files = actual(); files.set(path, mutation(files.get(path))); return files; };
function directory(t) {
  const path = realpathSync(mkdtempSync(join(tmpdir(), 'fncp-wordpress-package-check-')));
  t.after(() => rmSync(path, { recursive: true, force: true }));
  for (const [name, text] of actual()) { mkdirSync(dirname(join(path, name)), { recursive: true }); writeFileSync(join(path, name), text); }
  return path;
}

test('actual source assembles all five files and five edges in the original sibling layout', () => {
  const { files, manifest } = assembleWordPressBundle();
  assert.deepEqual([...files.keys()], WORDPRESS_FILES);
  assert.equal(manifest.fileCount, 5); assert.equal(manifest.dependencyCount, 5);
  assert.equal(manifest.outcome, 'KEEP_CLOSED'); assert.equal(manifest.mode, 'SYNTHETIC_ONLY');
  for (const flag of ['productionReady', 'deployablePackage', 'archiveWritten', 'sourceExecuted', 'networkUsed', 'sourceModified']) assert.equal(manifest[flag], false);
  assert.equal(manifest.entrypoint, WORDPRESS_ENTRY);
  for (const file of manifest.files) {
    assert.equal(file.sourcePath, 'deploy/fncp/' + file.bundlePath);
    assert.equal(file.sha256, createHash('sha256').update(files.get(file.bundlePath)).digest('hex'));
    assert.equal(file.bytes, Buffer.byteLength(files.get(file.bundlePath)));
  }
  assert.match(files.get(WORDPRESS_ENTRY), /FNCP_WP_SYNTHETIC_ONLY/u);
  assert.equal(files.get(WORDPRESS_ENTRY), readFileSync(join(root, WORDPRESS_ENTRY), 'utf8'));
});

test('pure map validator is deterministic, order-independent and does not mutate inputs', () => {
  const files = actual(); const before = [...files];
  const reversed = new Map([...files].reverse());
  assert.deepEqual(validateWordPressBundle(files), validateWordPressBundle(reversed));
  assert.deepEqual([...files], before);
  const altered = edited('wordpress-local/contract.php', text => text + '\n// source change\n');
  assert.notEqual(validateWordPressBundle(files).sourceClosureSha256, validateWordPressBundle(altered).sourceClosureSha256);
});

for (const missing of WORDPRESS_FILES) test('missing dependency is rejected: ' + missing, () => {
  const files = actual(); files.delete(missing); rejects(files);
});

for (const extra of ['wordpress-identity/.runtime/wp-config.php', 'wordpress-identity/tests.php',
  'wordpress-identity/operator-proof.php', 'wordpress-identity/runtime.mjs', 'wordpress-identity/credentials.json',
  'wordpress-identity/../wordpress-local/contract.php', '/wordpress-local/contract.php']) {
  test('non-source/alias entry is rejected before bundling: ' + extra, () => {
    const files = actual(); files.set(extra, '<?php\n'); rejects(files);
  });
}

const dependency = "require_once __DIR__ . '/registry.php';";
for (const [name, replacement] of Object.entries({
  dynamic: "require_once $path;",
  interpolated: 'require_once __DIR__ . "/$path.php";',
  escape: "require_once __DIR__ . '/../../secrets.php';",
  missingSibling: "require_once __DIR__ . '/../wordpress-local/missing.php';",
  wrapper: "require_once 'php://filter/resource=registry.php';",
  absolute: "require_once '/registry.php';",
  parenthesised: "require_once (__DIR__ . '/registry.php');",
  include: "include __DIR__ . '/registry.php';",
  require: "require __DIR__ . '/registry.php';",
  includeOnce: "include_once __DIR__ . '/registry.php';",
  suffix: "require_once __DIR__ . '/registry.php' . $suffix;",
  evaluation: 'eval($code);',
  backtick: 'echo `cat other.php`;',
  heredoc: "echo <<<TEXT\nrequire_once $dynamic;\nTEXT;",
  complexInterpolation: 'echo "${include($path)}";',
  braceInterpolation: 'echo "{$object->{include($path)}}";',
})) test('unsupported or escaping source dependency denied: ' + name, () => rejects(edited(WORDPRESS_ENTRY, text => text.replace(dependency, replacement))));

test('comments and quoted dependency-looking text do not alter the closure', () => {
  const files = edited(WORDPRESS_ENTRY, text => text + '\n/* require_once $bad; */\n// include $bad;\n# require $bad;\n' +
    "echo 'require_once $bad;';\necho \"include $bad;\";\n");
  assert.equal(validateWordPressBundle(files).dependencyCount, 5);
});

test('comments between reviewed dependency tokens are harmless', () => {
  const files = edited(WORDPRESS_ENTRY, text => text.replace(dependency, "require_once /* local */ __DIR__ . '/registry.php';"));
  assert.equal(validateWordPressBundle(files).closureComplete, true);
});

for (const [name, suffix] of Object.entries({ duplicate: '\n' + dependency,
  hiddenDynamic: '\nif (false) { require_once $never; }',
  unclosedString: "\necho 'unfinished;", unclosedComment: '\n/* unfinished',
  closeTag: '\n?>', secondOpen: '\n<?php', privateKey: '\n// -----BEGIN PRIVATE KEY-----',
  nullByte: '\0', nonASCIIIdentifier: '\n$café = 1;' })) {
  test('malformed or unreviewed source denied: ' + name, () => rejects(edited(WORDPRESS_ENTRY, text => text + suffix)));
}

test('removed dependency edge is rejected even when the file remains in the map', () => {
  rejects(edited(WORDPRESS_ENTRY, text => text.replace(dependency, '')));
});

test('wrong map/source types and oversized files are rejected with no reflected content', () => {
  for (const value of [null, {}, [], new Map()]) rejects(value);
  for (const value of [Buffer.from('private-invented'), null, {}, '<?php\n' + 'x'.repeat(65_536)]) {
    const files = actual(); files.set(WORDPRESS_ENTRY, value); rejects(files);
  }
});

test('filesystem assembly does not inspect unrelated runtime or secret files', t => {
  const path = directory(t); const runtime = join(path, 'wordpress-identity', '.runtime'); mkdirSync(runtime);
  const privatePath = join(runtime, 'credentials.json'); writeFileSync(privatePath, 'private-invented-do-not-read'); chmodSync(privatePath, 0);
  const result = assembleWordPressBundle(path);
  assert.equal(result.manifest.fileCount, 5); assert.ok(!JSON.stringify(result.manifest).includes('private-invented'));
});

test('symlink file cannot substitute a source dependency', t => {
  const path = directory(t); const target = join(path, 'wordpress-local/contract.php');
  const saved = join(path, 'preserved.php'); writeFileSync(saved, readFileSync(target)); rmSync(target); symlinkSync(saved, target);
  assert.throws(() => assembleWordPressBundle(path), /source closure rejected/u);
});

test('symlink directory cannot redirect a sibling closure', t => {
  const path = directory(t); const real = join(path, 'separate'); mkdirSync(real);
  for (const name of ['contract.php', 'journal.php']) writeFileSync(join(real, name), readFileSync(join(path, 'wordpress-local', name)));
  rmSync(join(path, 'wordpress-local'), { recursive: true }); symlinkSync(real, join(path, 'wordpress-local'));
  assert.throws(() => assembleWordPressBundle(path), /source closure rejected/u);
});

test('hardlinked source and non-canonical source roots are rejected', t => {
  const path = directory(t); linkSync(join(path, WORDPRESS_ENTRY), join(path, 'unreviewed-link.php'));
  assert.throws(() => assembleWordPressBundle(path), /source closure rejected/u);
  assert.throws(() => assembleWordPressBundle(path + '/.'), /source closure rejected/u);
  assert.throws(() => assembleWordPressBundle('relative'), /source closure rejected/u);
});

test('invalid UTF-8 is not silently rewritten into a bundle', t => {
  const path = directory(t); writeFileSync(join(path, WORDPRESS_ENTRY), Buffer.from([0x3c, 0x3f, 0x70, 0x68, 0x70, 0x0a, 0xff]));
  assert.throws(() => assembleWordPressBundle(path), /source closure rejected/u);
});

test('CLI prints source hashes only and has no install/output/path override', () => {
  const manifest = JSON.parse(execFileSync(process.execPath, [checker, '--check'], { encoding: 'utf8' }));
  assert.equal(manifest.outcome, 'KEEP_CLOSED'); assert.equal(manifest.fileCount, 5);
  assert.ok(!JSON.stringify(manifest).includes('<?php'));
  for (const args of [[], ['--install'], ['--check', '--output=private-invented'], ['--check', '--source=/tmp/private-invented']]) {
    const result = spawnSync(process.execPath, [checker, ...args], { encoding: 'utf8' });
    assert.equal(result.status, 1); assert.equal(result.stdout, '');
    assert.equal(result.stderr, 'WordPress source closure rejected; KEEP_CLOSED. No archive, install or activation performed.\n');
  }
});
