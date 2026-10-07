import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {parseManifest, verifyPackage, cli} from './verify-package.mjs';

const sha = value => createHash('sha256').update(value).digest('hex');
const roles = ['api', 'math', 'migration', 'postgres', 'participant', 'wordpress', 'mariadb', 'proxy'];
const revision = 'a'.repeat(40), offline = 'b'.repeat(40), fingerprint = 'c'.repeat(64);

function fixture(t) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'fncp-package-test-')));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const files = new Map();
  const put = (name, data) => files.set(name, Buffer.isBuffer(data) ? data : Buffer.from(typeof data === 'string' ? data : JSON.stringify(data)));
  const images = {};
  for (const role of roles) {
    const at = `evidence/image-assurance/scans/${role}`;
    const config = Buffer.from(JSON.stringify({architecture: 'arm64', os: 'linux', role}));
    const configDigest = `sha256:${sha(config)}`;
    const manifest = Buffer.from(JSON.stringify({schemaVersion: 2, config: {digest: configDigest, size: config.length}}));
    const manifestDigest = `sha256:${sha(manifest)}`;
    const index = Buffer.from(JSON.stringify({schemaVersion: 2, mediaType: 'application/vnd.oci.image.index.v1+json', manifests: [{digest: manifestDigest, size: manifest.length, platform: {os: 'linux', architecture: 'arm64'}}]}));
    images[role] = `sha256:${sha(index)}`;
    put(`${at}/image.root-descriptor.json`, index);
    put(`${at}/image.platform-manifest.json`, manifest);
    put(`${at}/image.image-config.json`, config);
    put(`${at}/image.binding.json`, {requestedDockerImageId: images[role], selectedPlatform: 'linux/arm64', selectedConfigDigest: configDigest, selectedPlatformManifestDigest: manifestDigest});
    put(`${at}/source-file-binding.json`, {role, allComparedBytesEqual: true, imageId: images[role], sourceRevision: revision, sourceFingerprint: fingerprint});
  }
  put('evidence/image-assurance/approved-runtime-lock.json', {version: 1, sourceRevision: revision, sourceFingerprint: fingerprint, images});
  // Deliberately not a Git pack: this tool promises byte binding, not Git object verification.
  const bundle = Buffer.from('synthetic public bundle stand-in');
  put('source/polis-production-reviewed.bundle', bundle);
  put('source/bundle-verification.json', {profile: 'REVIEWED_SOURCE_BUNDLE_VERIFICATION_V1', result: 'PASS', bundle: 'polis-production-reviewed.bundle', runtimeRevision: revision, refs: {'refs/heads/main': offline}, sha256: sha(bundle), bytes: bundle.length});
  put('evidence/node22-recovery-9fcc/summary.json', {profile: 'NODE22_TARGETED_OFFLINE_RECOVERY_9FCC_V1', result: 'PASS', sourceRevision: offline, runtimeRevisionUnchanged: revision, testCount: 47, passed: 47, failed: 0, skipped: 0, cancelled: 0, containerExitCode: 0});
  put('VERIFICATION.json', {profile: 'FNCP_NORMAL_COMPOSE_LOCAL_DELIVERY_V1', result: 'LOCAL_BUILD_AND_REHEARSAL_COMPLETE', runtimeSourceRevision: revision, finalOfflineToolRevision: offline, runtimeSourceFingerprint: fingerprint, sourceBundleSha256: sha(bundle), imageRoles: 8, publishedHostPorts: 0, publicDeployment: false, realOidcProviderVerified: false, publicBrowserTlsVerified: false, paidResourcesCreated: false, privateTaskRuntimeMaterialIncluded: false, sha256Manifest: 'SHA256SUMS.txt', includedFileCount: files.size + 2, checksumEntries: files.size + 1});
  const save = () => {
    for (const [name, bytes] of files) {
      fs.mkdirSync(path.dirname(path.join(root, name)), {recursive: true});
      fs.writeFileSync(path.join(root, name), bytes);
    }
    const manifest = Buffer.from([...files].sort(([a], [b]) => a.localeCompare(b)).map(([name, bytes]) => `${sha(bytes)}  ${name}\n`).join(''));
    fs.writeFileSync(path.join(root, 'SHA256SUMS.txt'), manifest);
    return sha(manifest);
  };
  const change = (name, fn) => { const object = JSON.parse(files.get(name)); fn(object); put(name, object); };
  return {root, files, save, put, change, anchor: save()};
}

test('valid snapshot passes with explicit evidence limitations and leaves every member unchanged', t => {
  const f = fixture(t);
  const before = [...f.files.keys(), 'SHA256SUMS.txt'].map(p => fs.statSync(path.join(f.root, p)).mtimeMs);
  const result = verifyPackage(f.root, f.anchor);
  assert.equal(result.result, 'PASS'); assert.equal(result.verifiedImageDescriptorChains, 8);
  for (const key of ['fullImageLayersRehashed', 'gitPackObjectsVerified', 'freshRuntimeTest', 'freshVulnerabilityScan', 'realOidcVerified', 'deploymentAuthorized']) assert.equal(result[key], false);
  assert.deepEqual([...f.files.keys(), 'SHA256SUMS.txt'].map(p => fs.statSync(path.join(f.root, p)).mtimeMs), before);
});

for (const name of ['/absolute', '../escape', 'a/../b', './a', 'a//b', 'a\\b', 'a\tb', 'a\u0000b', 'a:b', 'a.', 'a /b', 'e\u0301', 'a/'.repeat(33) + 'b']) {
  test(`unsafe manifest path rejected: ${JSON.stringify(name)}`, () => {
    assert.throws(() => parseManifest(Buffer.from(`${'a'.repeat(64)}  ${name}\n`)), /UNSAFE_MEMBER_PATH/);
  });
}
test('duplicate and case-alias manifest members rejected', () => {
  for (const name of ['A', 'a']) assert.throws(() => parseManifest(Buffer.from(`${'a'.repeat(64)}  A\n${'b'.repeat(64)}  ${name}\n`)), /DUPLICATE_MEMBER/);
});
test('manifest cannot checksum itself', () => assert.throws(() => parseManifest(Buffer.from(`${'a'.repeat(64)}  SHA256SUMS.txt\n`)), /SELF_REFERENTIAL/));
test('malformed and unbounded manifests rejected', () => {
  for (const value of ['', 'a', 'A'.repeat(64) + '  file\n', 'a'.repeat(64) + ' *file\n', 'a'.repeat(64) + '  file\r\n']) assert.throws(() => parseManifest(Buffer.from(value)));
  assert.throws(() => parseManifest(Buffer.alloc(2 ** 20 + 1)), /MANIFEST_SIZE/);
  assert.throws(() => parseManifest(Buffer.from(Array.from({length: 5001}, (_, i) => `${'a'.repeat(64)}  f${i}\n`).join(''))), /ENTRY_LIMIT/);
});
test('trusted manifest anchor is mandatory and cannot come from mutable package self-consistency', t => {
  const f = fixture(t);
  for (const anchor of [undefined, '', 'bad', 1]) assert.throws(() => verifyPackage(f.root, anchor), /TRUSTED_MANIFEST_HASH_REQUIRED/);
  f.change('VERIFICATION.json', v => { v.extra = 'self-consistent modification'; }); f.save();
  assert.throws(() => verifyPackage(f.root, f.anchor), /TRUST_ANCHOR_MISMATCH/);
});
test('changed, missing and unlisted files fail', t => {
  const f = fixture(t), file = path.join(f.root, 'VERIFICATION.json');
  fs.appendFileSync(file, ' '); assert.throws(() => verifyPackage(f.root, f.anchor), /MEMBER_HASH_MISMATCH/);
  f.save(); fs.unlinkSync(file); assert.throws(() => verifyPackage(f.root, f.anchor), /MEMBERSHIP_MISMATCH/);
  f.save(); fs.writeFileSync(path.join(f.root, 'unexpected'), 'x'); assert.throws(() => verifyPackage(f.root, f.anchor), /MEMBERSHIP_MISMATCH/);
});
test('member symlinks, nested directory symlinks and hardlinks fail without following them', t => {
  const f = fixture(t), file = path.join(f.root, 'VERIFICATION.json');
  fs.symlinkSync(file, path.join(f.root, 'link')); assert.throws(() => verifyPackage(f.root, f.anchor), /SYMLINK_MEMBER/); fs.unlinkSync(path.join(f.root, 'link'));
  fs.symlinkSync(path.join(f.root, 'source'), path.join(f.root, 'linked-directory')); assert.throws(() => verifyPackage(f.root, f.anchor), /SYMLINK_MEMBER/); fs.unlinkSync(path.join(f.root, 'linked-directory'));
  fs.linkSync(file, path.join(f.root, 'hardlink')); assert.throws(() => verifyPackage(f.root, f.anchor), /UNSAFE_MEMBER_TYPE/);
});
test('root must be absolute and canonical', t => {
  const f = fixture(t);
  assert.throws(() => verifyPackage('.', f.anchor), /ABSOLUTE_ROOT_REQUIRED/);
  fs.symlinkSync(f.root, path.join(f.root, 'alias'));
  assert.throws(() => verifyPackage(path.join(f.root, 'alias'), f.anchor), /CANONICAL_ROOT_REQUIRED/);
});
test('unlisted empty directories are rejected', t => {
  const f = fixture(t); fs.mkdirSync(path.join(f.root, 'unlisted-empty'));
  assert.throws(() => verifyPackage(f.root, f.anchor), /DIRECTORY_MEMBERSHIP_MISMATCH/);
});
test('ordinary tree drift during read is rejected', t => {
  const f = fixture(t), original = fs.readSync;
  let changed = false;
  fs.readSync = (...args) => {
    const count = original(...args);
    if (!changed) { changed = true; fs.writeFileSync(path.join(f.root, 'new-member'), 'synthetic'); }
    return count;
  };
  try { assert.throws(() => verifyPackage(f.root, f.anchor), /PACKAGE_CHANGED/); }
  finally { fs.readSync = original; }
});

for (const [name, edit, code] of [
  ['VERIFICATION.json', v => { v.publicDeployment = true; }, 'LOCAL_ONLY_BOUNDARY_MISMATCH'],
  ['VERIFICATION.json', v => { delete v.realOidcProviderVerified; }, 'LOCAL_ONLY_BOUNDARY_MISMATCH'],
  ['VERIFICATION.json', v => { v.publishedHostPorts = 1; }, 'LOCAL_ONLY_BOUNDARY_MISMATCH'],
  ['VERIFICATION.json', v => { v.includedFileCount++; }, 'DELIVERY_COUNT_MISMATCH'],
  ['VERIFICATION.json', v => { v.runtimeSourceRevision = 'bad'; }, 'SOURCE_IDENTITY_INVALID'],
  ['VERIFICATION.json', v => { v.profile = 'UNKNOWN'; }, 'UNSUPPORTED_DELIVERY_PROFILE'],
  ['source/bundle-verification.json', v => { v.refs['refs/heads/main'] = revision; }, 'BUNDLE_BINDING_MISMATCH'],
  ['source/bundle-verification.json', v => { v.bytes++; }, 'BUNDLE_BINDING_MISMATCH'],
  ['source/bundle-verification.json', v => { v.result = 'FAIL'; }, 'BUNDLE_BINDING_MISMATCH'],
  ['source/bundle-verification.json', v => { v.profile = 'OTHER'; }, 'BUNDLE_BINDING_MISMATCH'],
  ['evidence/node22-recovery-9fcc/summary.json', v => { v.result = 'FAIL'; }, 'OFFLINE_TEST_RECEIPT_MISMATCH'],
  ['evidence/node22-recovery-9fcc/summary.json', v => { v.sourceRevision = revision; }, 'OFFLINE_TEST_RECEIPT_MISMATCH'],
  ['evidence/node22-recovery-9fcc/summary.json', v => { v.skipped = 1; }, 'OFFLINE_TEST_RECEIPT_MISMATCH'],
  ['evidence/image-assurance/approved-runtime-lock.json', v => { v.sourceFingerprint = '0'.repeat(64); }, 'IMAGE_LOCK_MISMATCH'],
  ['evidence/image-assurance/approved-runtime-lock.json', v => { delete v.images.proxy; }, 'IMAGE_LOCK_MISMATCH'],
  ['evidence/image-assurance/approved-runtime-lock.json', v => { v.images.extra = v.images.api; }, 'IMAGE_LOCK_MISMATCH'],
  ['evidence/image-assurance/scans/api/image.binding.json', v => { v.requestedDockerImageId = v.selectedConfigDigest; }, 'IMAGE_ROOT_BINDING_MISMATCH'],
  ['evidence/image-assurance/scans/api/image.binding.json', v => { v.selectedPlatform = 'linux/amd64'; }, 'IMAGE_PLATFORM_MISMATCH'],
  ['evidence/image-assurance/scans/api/image.binding.json', v => { v.selectedPlatformManifestDigest = 'sha256:' + '0'.repeat(64); }, 'IMAGE_MANIFEST_BINDING_MISMATCH'],
  ['evidence/image-assurance/scans/api/image.binding.json', v => { v.selectedConfigDigest = 'sha256:' + '0'.repeat(64); }, 'IMAGE_CONFIG_BINDING_MISMATCH'],
  ['evidence/image-assurance/scans/api/source-file-binding.json', v => { v.sourceRevision = offline; }, 'IMAGE_SOURCE_RECEIPT_MISMATCH'],
]) {
  test(`cross-receipt conflict: ${code} (${name})`, t => {
    const f = fixture(t); f.change(name, edit);
    assert.throws(() => verifyPackage(f.root, f.save()), new RegExp(code));
  });
}
for (const value of [null, [], 1, false, 'text']) {
  test(`nonobject receipt rejected: ${JSON.stringify(value)}`, t => {
    const f = fixture(t); f.put('VERIFICATION.json', JSON.stringify(value));
    assert.throws(() => verifyPackage(f.root, f.save()), /RECEIPT_OBJECT_REQUIRED/);
  });
}
for (const manifests of [null, {}, [null], [1]]) {
  test(`malformed image index rejected: ${JSON.stringify(manifests)}`, t => {
    const f = fixture(t), at = 'evidence/image-assurance/scans/api';
    f.change(`${at}/image.root-descriptor.json`, v => { v.manifests = manifests; });
    const newDigest = `sha256:${sha(f.files.get(`${at}/image.root-descriptor.json`))}`;
    f.change(`${at}/image.binding.json`, v => { v.requestedDockerImageId = newDigest; });
    f.change('evidence/image-assurance/approved-runtime-lock.json', v => { v.images.api = newDigest; });
    assert.throws(() => verifyPackage(f.root, f.save()), /IMAGE_INDEX_SHAPE_INVALID/);
  });
}
test('JSON parse failure is redacted', t => {
  const f = fixture(t); f.put('VERIFICATION.json', 'PRIVATE-LOOKING-INVALID-VALUE');
  const result = cli([f.root, '--manifest-sha256', f.save()]);
  assert.equal(result.output.code, 'INVALID_RECEIPT_JSON'); assert.ok(!JSON.stringify(result).includes('PRIVATE-LOOKING'));
});
test('CLI reports only redacted status and fails on missing files or extra arguments', t => {
  const f = fixture(t);
  for (const args of [[], [f.root, '--manifest-sha256', f.anchor, 'extra'], ['/nonexistent-sensitive-path', '--manifest-sha256', f.anchor]]) {
    const r = cli(args); assert.equal(r.status, 1); assert.equal(r.output.deploymentAuthorized, false);
    assert.ok(!JSON.stringify(r).includes('sensitive-path')); assert.ok(!JSON.stringify(r).includes(f.root));
  }
  const script = fileURLToPath(new URL('./verify-package.mjs', import.meta.url));
  const child = spawnSync(process.execPath, [script, f.root, '--manifest-sha256', f.anchor], {encoding: 'utf8', timeout: 10000});
  assert.equal(child.status, 0, child.stderr); assert.equal(JSON.parse(child.stdout).result, 'PASS'); assert.equal(child.stderr, '');
});
