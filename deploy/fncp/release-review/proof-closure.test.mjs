import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, realpathSync, readFileSync, writeFileSync, mkdirSync, rmSync,
  symlinkSync, linkSync, lstatSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { PROOF_SOURCE_PATHS, REVIEWED_PROOF_CLOSURE, inspectProofSourceClosure,
  validateProofSourceClosure, proofClosureFailure } from './proof-closure.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CLI = fileURLToPath(new URL('./proof-closure.mjs', import.meta.url));
const denied = /Proof source closure rejected; KEEP_CLOSED\./u;
const original = () => new Map(PROOF_SOURCE_PATHS.map(path => [path, readFileSync(join(ROOT, path), 'utf8')]));
function fixture(t) {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'fncp-proof-closure-test-')));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const root = join(directory, 'sources'); mkdirSync(root, { mode: 0o700 });
  for (const [path, source] of original()) {
    mkdirSync(dirname(join(root, path)), { recursive: true, mode: 0o700 });
    writeFileSync(join(root, path), source, { flag: 'wx', mode: 0o600 });
  }
  return { directory, root };
}
const subprocess = args => spawnSync(process.execPath, [CLI, ...args], {
  encoding: 'utf8', timeout: 10_000, maxBuffer: 131_072,
  env: { PATH: process.env.PATH ?? '/usr/bin:/bin' },
});

test('exact source-only reviewed closure includes strict graph, legacy roots, assets and dependency inputs', () => {
  const result = inspectProofSourceClosure();
  assert.equal(result.reviewedSourceClosureMatches, true);
  assert.equal(result.classification, 'KEEP_CLOSED');
  for (const key of ['fullReleaseClosure', 'deployable', 'activationAuthority']) assert.equal(result[key], false);
  assert.equal(result.coverage.sourceFiles, 27); assert.equal(result.coverage.jsModules, 21);
  assert.equal(result.coverage.browserAssets, 4); assert.equal(result.coverage.dependencyInputs, 2);
  assert.equal(result.coverage.firstPartyImportEdges, 30); assert.equal(result.coverage.staticAssetEdges, 4);
  for (const key of ['sourceExecuted', 'runtimeServicesImportedOrStarted', 'environmentOrPrivateStateRead',
    'networkUsed', 'dependenciesInstalled', 'archiveWritten', 'imagesBuilt']) assert.equal(result.coverage[key], false);
  assert.equal(result.entrypoints.length, 5);
  assert.equal(result.files.find(file => file.path === 'local-browser/browser-server.mjs').assets.length, 4);
  assert.match(result.sourceClosureSha256, /^[a-f0-9]{64}$/u);
  assert.match(result.manifestSha256, /^[a-f0-9]{64}$/u);
  assert.deepEqual(result.declaredLockedPackages.map(item => item.name), ['openid-client', 'jose', 'oauth4webapi']);
  assert.equal(JSON.stringify(result).includes(ROOT), false);
  assert.equal(result.files.some(file => Object.hasOwn(file, 'source')), false);
});

test('programmatic strict local root excludes proof drivers and grants no production entrypoint', () => {
  const entry = REVIEWED_PROOF_CLOSURE.entrypoints.find(item => item.path === 'strict-service/service.mjs');
  assert.equal(entry.kind, 'PROGRAMMATIC_STRICT_LOCAL_COMPOSITION_NOT_PRODUCTION_CLI');
  const files = new Map(REVIEWED_PROOF_CLOSURE.files.map(item => [item.path, item]));
  const seen = new Set();
  const visit = path => {
    if (seen.has(path)) return;
    seen.add(path); const file = files.get(path); assert.ok(file);
    for (const child of [...file.imports, ...file.assets]) visit(child);
  };
  visit(entry.path);
  assert.equal(seen.size, 14);
  assert.ok(seen.has('strict-service/supervisor.mjs'));
  assert.ok(seen.has('activation-foundation/controlled-access.mjs'));
  assert.ok(seen.has('wordpress-identity/server-registration.mjs'));
  assert.ok(![...seen].some(path => /synthetic-fixtures|synthetic-harness|synthetic-browser-driver|proof-harness|integration-client/u.test(path)));
  // Identity and provider implementations are trusted in-process dependencies,
  // not discovered or attested merely because this composition accepts them.
  assert.equal(seen.has('identity-foundation/identity.mjs'), false);
});

test('pure redirect coordinator is an explicit component root without test issuer or signer dependencies', () => {
  const path = 'identity-foundation/https-redirect-driver.mjs';
  const entry = REVIEWED_PROOF_CLOSURE.entrypoints.find(item => item.path === path);
  assert.equal(entry.kind, 'PURE_INJECTED_HTTPS_REDIRECT_COORDINATOR_NOT_PROVIDER_OR_DEPLOYMENT');
  const file = REVIEWED_PROOF_CLOSURE.files.find(item => item.path === path);
  assert.equal(file.kind, 'JS_SOURCE'); assert.deepEqual(file.imports, []);
  assert.deepEqual(file.assets, []); assert.deepEqual(file.packages, []);
  assert.ok(!REVIEWED_PROOF_CLOSURE.entrypoints.some(item => /redirect-tls-lab|synthetic-tls-lab/u.test(item.path)));
  assert.ok(!REVIEWED_PROOF_CLOSURE.files.some(item => /redirect-tls-lab|synthetic-tls-lab/u.test(item.path)));
  // Injection is an explicit caller boundary, not a falsely discovered import.
  const service = REVIEWED_PROOF_CLOSURE.files.find(item => item.path === 'strict-service/service.mjs');
  assert.equal(service.imports.includes(path), false);
});

test('same explicit bytes produce deterministic result irrespective of Map insertion order', () => {
  const sources = original();
  assert.deepEqual(validateProofSourceClosure(sources), validateProofSourceClosure(new Map([...sources].reverse())));
});

for (const path of PROOF_SOURCE_PATHS) test(`review pin rejects one-byte drift: ${path}`, () => {
  const sources = original(); sources.set(path, sources.get(path) + '\n');
  assert.throws(() => validateProofSourceClosure(sources), denied);
});

for (const path of ['../escape.mjs', '/absolute.mjs', 'local-browser/../escape.mjs', 'local-browser\\escape.mjs',
  'local-browser/%2e%2e/escape.mjs', '.env.staging', 'local-access/.runtime/admin.json',
  'keys/signing.pem', 'local-access/runtime/private.sqlite', 'node_modules/openid-client/index.js']) {
  test(`unknown/private path rejected without reading it: ${path}`, () => {
    const sources = original(); sources.delete(PROOF_SOURCE_PATHS[0]); sources.set(path, 'not-read');
    assert.throws(() => validateProofSourceClosure(sources), denied);
  });
}

test('missing and extra source entries are denied', () => {
  const missing = original(); missing.delete(PROOF_SOURCE_PATHS[0]);
  assert.throws(() => validateProofSourceClosure(missing), denied);
  const extra = original(); extra.set('local-browser/extra.mjs', 'not-reviewed');
  assert.throws(() => validateProofSourceClosure(extra), denied);
});

test('nontext, empty and over-budget inputs are denied without serialization hooks', () => {
  for (const value of [Buffer.from('bytes'), '', 'x'.repeat(131_073), null, { toString() { throw new Error('must not call'); } }]) {
    const sources = original(); sources.set(PROOF_SOURCE_PATHS[0], value);
    assert.throws(() => validateProofSourceClosure(sources), denied);
  }
});

test('Map subclasses, own iterator/get hooks, plain objects and proxies cannot change source interpretation', () => {
  class EvilMap extends Map { entries() { throw new Error('must not call'); } }
  const ownHook = original(); ownHook.get = () => 'forged';
  const ownIterator = original(); ownIterator[Symbol.iterator] = () => { throw new Error('must not call'); };
  for (const input of [new EvilMap(original()), ownHook, ownIterator, Object.fromEntries(original()), new Proxy(original(), {}), null]) {
    assert.throws(() => validateProofSourceClosure(input), denied);
  }
});

test('caller-created manifests cannot launder source changes, even with matching replacement hashes', () => {
  const sources = original(); const path = PROOF_SOURCE_PATHS[0]; sources.set(path, 'changed');
  const manifest = structuredClone(REVIEWED_PROOF_CLOSURE);
  manifest.files[0].sha256 = createHash('sha256').update('changed').digest('hex');
  assert.throws(() => validateProofSourceClosure(sources, manifest), denied);
  assert.throws(() => validateProofSourceClosure(original(), structuredClone(REVIEWED_PROOF_CLOSURE)), denied);
  assert.throws(() => inspectProofSourceClosure(ROOT, manifest), denied);
  const getter = Object.create(null, { files: { get() { throw new Error('must not call'); } } });
  assert.throws(() => validateProofSourceClosure(original(), getter), denied);
});

test('exported manifest is deeply immutable', () => {
  assert.throws(() => { REVIEWED_PROOF_CLOSURE.files[0].sha256 = '0'.repeat(64); }, TypeError);
  assert.throws(() => { REVIEWED_PROOF_CLOSURE.files[1].imports.push('elsewhere.mjs'); }, TypeError);
  assert.throws(() => { PROOF_SOURCE_PATHS.push('elsewhere.mjs'); }, TypeError);
});

test('fixed source fixture passes and unrelated private sentinel is not opened or reported', t => {
  const { root } = fixture(t);
  const privateDir = join(root, '.runtime'); mkdirSync(privateDir, { mode: 0o700 });
  const sentinel = join(privateDir, 'private-key.pem'); writeFileSync(sentinel, 'PRIVATE_SENTINEL_NEVER_OUTPUT', { mode: 0o000 });
  const before = lstatSync(sentinel);
  const result = inspectProofSourceClosure(root); const after = lstatSync(sentinel);
  assert.equal(result.coverage.sourceFiles, 27); assert.equal(JSON.stringify(result).includes('PRIVATE_SENTINEL'), false);
  assert.equal(after.atimeMs, before.atimeMs); assert.equal(after.mtimeMs, before.mtimeMs);
});

test('missing, directory, malformed UTF-8 and over-budget files are rejected at the disk boundary', t => {
  for (const kind of ['missing', 'directory', 'invalid-utf8', 'oversized']) {
    const { root } = fixture(t); const target = join(root, PROOF_SOURCE_PATHS[0]); rmSync(target);
    if (kind === 'directory') mkdirSync(target);
    if (kind === 'invalid-utf8') writeFileSync(target, Buffer.from([0xff]));
    if (kind === 'oversized') writeFileSync(target, 'x'.repeat(131_073));
    assert.throws(() => inspectProofSourceClosure(root), denied);
  }
});

test('source symlink and hardlink aliases are rejected', t => {
  for (const kind of ['symlink', 'hardlink']) {
    const { directory, root } = fixture(t); const target = join(root, PROOF_SOURCE_PATHS[0]);
    const peer = join(directory, 'owned-peer.mjs'); writeFileSync(peer, readFileSync(target)); rmSync(target);
    if (kind === 'symlink') symlinkSync(peer, target); else linkSync(peer, target);
    assert.throws(() => inspectProofSourceClosure(root), denied);
  }
});

test('source parent directory symlink is rejected', t => {
  const { directory, root } = fixture(t); const target = join(root, 'activation-foundation');
  const peer = join(directory, 'owned-activation'); mkdirSync(peer);
  for (const path of PROOF_SOURCE_PATHS.filter(path => path.startsWith('activation-foundation/'))) {
    writeFileSync(join(peer, path.slice('activation-foundation/'.length)), readFileSync(join(root, path)));
  }
  rmSync(target, { recursive: true }); symlinkSync(peer, target);
  assert.throws(() => inspectProofSourceClosure(root), denied);
});

test('relative, lexical alias, missing and symbolic source roots are rejected', t => {
  const { directory, root } = fixture(t); const alias = join(directory, 'source-alias'); symlinkSync(root, alias);
  for (const input of ['.', root + '/.', root + '/../sources', join(directory, 'absent'), alias]) {
    assert.throws(() => inspectProofSourceClosure(input), denied);
  }
});

test('disk source drift remains rejected after an otherwise valid fixture was read', t => {
  const { root } = fixture(t); assert.equal(inspectProofSourceClosure(root).reviewedSourceClosureMatches, true);
  writeFileSync(join(root, 'seed-statements.json'), '[]\n');
  assert.throws(() => inspectProofSourceClosure(root), denied);
});

test('CLI is read-only with no arguments and produces only the bounded successful manifest', () => {
  const result = subprocess([]); assert.equal(result.status, 0); assert.equal(result.signal, null);
  assert.equal(result.stderr, ''); const manifest = JSON.parse(result.stdout);
  assert.equal(manifest.coverage.sourceFiles, 27); assert.equal(manifest.deployable, false);
  assert.equal(manifest.classification, 'KEEP_CLOSED'); assert.equal(result.stdout.includes(ROOT), false);
});

test('CLI refuses caller paths and options with fixed content-free failure', () => {
  for (const args of [['--root', '/private-not-read'], ['--output', '/private-not-written'], ['--manifest', '/private-not-read']]) {
    const result = subprocess(args); assert.equal(result.status, 1); assert.equal(result.stderr, '');
    assert.deepEqual(JSON.parse(result.stdout), proofClosureFailure());
    assert.equal(result.stdout.includes('/private'), false);
  }
});
