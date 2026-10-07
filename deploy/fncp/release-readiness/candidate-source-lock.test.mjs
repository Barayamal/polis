import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm, chmod, symlink, link, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createCandidateSourceLock, validateCandidateSourceLock, validateCandidateSourceLockShape, validateCandidateReleaseLock } from './candidate-source-lock.mjs';
import { imageRoles } from '../production-deployment/compose.mjs';

const error = /FNCP_CANDIDATE_SOURCE_REJECTED/u;
async function fixture(t) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'fncp-source-lock-'))); t.after(() => rm(root, { recursive: true, force: true }));
  const git = args => {
    const result = spawnSync('git', ['-C', root, ...args], { encoding: 'utf8', env: {
      PATH: process.env.PATH, HOME: root, LANG: 'C', GIT_CONFIG_NOSYSTEM: '1',
      GIT_AUTHOR_NAME: 'Synthetic', GIT_AUTHOR_EMAIL: 'synthetic@example.invalid',
      GIT_COMMITTER_NAME: 'Synthetic', GIT_COMMITTER_EMAIL: 'synthetic@example.invalid',
    }});
    assert.equal(result.status, 0, result.stderr); return result.stdout.trim();
  };
  git(['init', '--quiet']); await writeFile(join(root, 'tracked.mjs'), 'export const value = 1;\n');
  await writeFile(join(root, '.gitignore'), 'ignored-output/\n');
  git(['add', '.']); const tree = git(['write-tree']); const commit = git(['commit-tree', tree, '-m', 'Synthetic test fixture']);
  git(['update-ref', 'HEAD', commit]);
  return { root, git };
}
function imageLock(source, version = 1) {
  return { version, sourceRevision: source.sourceRevision, sourceFingerprint: source.sourceFingerprint,
    images: Object.fromEntries(imageRoles(version).map((role, index) => [role, 'sha256:' + (index + 1).toString(16).padStart(64, '0')])) };
}

test('locks modified tracked and untracked source, excludes ignored output, is read-only and frozen', async t => {
  const { root, git } = await fixture(t);
  await writeFile(join(root, 'tracked.mjs'), 'export const value = 2;\n');
  await writeFile(join(root, 'added.mjs'), 'export const added = true;\n');
  await mkdir(join(root, 'ignored-output')); await writeFile(join(root, 'ignored-output', 'private.key'), 'not source');
  const status = git(['status', '--porcelain=v1']), source = await createCandidateSourceLock(root);
  assert.deepEqual(source.files.map(file => file.path), ['.gitignore','added.mjs','tracked.mjs']);
  assert.ok(Object.isFrozen(source.files[0])); assert.equal(git(['status', '--porcelain=v1']), status);
  assert.deepEqual(await validateCandidateSourceLock(root, source), source);
});

test('source content drift and membership drift reject a prior lock', async t => {
  const { root } = await fixture(t), source = await createCandidateSourceLock(root);
  await writeFile(join(root, 'tracked.mjs'), 'changed');
  await assert.rejects(validateCandidateSourceLock(root, source), error);
  await writeFile(join(root, 'tracked.mjs'), 'export const value = 1;\n');
  await writeFile(join(root, 'new-source.mjs'), 'new source');
  await assert.rejects(validateCandidateSourceLock(root, source), error);
});

test('executable-bit drift changes source lock', async t => {
  const { root } = await fixture(t), source = await createCandidateSourceLock(root);
  await chmod(join(root, 'tracked.mjs'), 0o755);
  await assert.rejects(validateCandidateSourceLock(root, source), error);
});

test('only the two explicit generated lock paths are excluded', async t => {
  const { root } = await fixture(t), source = await createCandidateSourceLock(root);
  await mkdir(join(root, 'deploy/fncp/selfhost'), { recursive: true });
  await mkdir(join(root, 'deploy/fncp/release-readiness'), { recursive: true });
  for (const at of ['deploy/fncp/selfhost/source-lock.json','deploy/fncp/release-readiness/source-lock.json']) await writeFile(join(root, at), 'generated');
  assert.deepEqual(await createCandidateSourceLock(root), source);
  await writeFile(join(root, 'other-source-lock.json'), '{}');
  await assert.rejects(validateCandidateSourceLock(root, source), error);
});

test('file symlinks reject', async t => {
  const { root } = await fixture(t); await symlink(join(root, 'tracked.mjs'), join(root, 'alias.mjs'));
  await assert.rejects(createCandidateSourceLock(root), error);
});
test('hard links reject', async t => {
  const { root } = await fixture(t); await link(join(root, 'tracked.mjs'), join(root, 'alias.mjs'));
  await assert.rejects(createCandidateSourceLock(root), error);
});
test('noncanonical root rejects', async t => {
  const { root } = await fixture(t);
  await assert.rejects(createCandidateSourceLock(root + '/.'), error);
});
test('tracked missing file rejects', async t => {
  const { root } = await fixture(t); await rm(join(root, 'tracked.mjs'));
  await assert.rejects(createCandidateSourceLock(root), error);
});
test('suspicious private paths reject without exposing contents', async t => {
  const { root } = await fixture(t); await writeFile(join(root, '.env'), 'SYNTHETIC_SECRET=never-echo');
  await assert.rejects(createCandidateSourceLock(root), { message: 'FNCP_CANDIDATE_SOURCE_REJECTED' });
});
test('case aliases reject', async t => {
  const { root } = await fixture(t); await writeFile(join(root, 'Case.mjs'), 'a');
  // The default macOS filesystem aliases these names. A malformed manifest still
  // exercises the cross-platform alias rejection without relying on host case.
  const source = await createCandidateSourceLock(root), bad = structuredClone(source);
  bad.files.push({ ...bad.files.find(file => file.path === 'Case.mjs'), path: 'case.mjs' });
  assert.throws(() => validateCandidateSourceLockShape(bad), error);
});
test('manifest substitutions, getter properties, unknown fields and false hash reject', async t => {
  const { root } = await fixture(t), source = await createCandidateSourceLock(root);
  for (const mutate of [
    lock => { lock.sourceFingerprint = '0'.repeat(64); },
    lock => { lock.files[0].path = '../outside'; },
    lock => { lock.files.reverse(); },
    lock => { lock.authorization = true; },
    lock => { Object.defineProperty(lock, 'sourceRevision', { get() { throw Error('getter'); }, enumerable: true }); },
  ]) { const bad = structuredClone(source); mutate(bad); assert.throws(() => validateCandidateSourceLockShape(bad), error); }
});
test('V1, V2 and V3 exact image sets bind the same candidate source explicitly', async t => {
  const { root } = await fixture(t), source = await createCandidateSourceLock(root);
  for (const version of [1, 2, 3]) {
    const images = imageLock(source, version);
    assert.deepEqual(validateCandidateReleaseLock(source, images, version), images);
    assert.equal(Object.keys(images.images).length, version === 1 ? 8 : version === 2 ? 9 : 10);
    assert.throws(() => validateCandidateReleaseLock(source, images, version === 1 ? 2 : 1), error);
  }
});
test('missing/substitute edge, image duplicates and wrong source cannot bind V2', async t => {
  const { root } = await fixture(t), source = await createCandidateSourceLock(root);
  for (const mutate of [
    lock => { delete lock.images.edge; },
    lock => { lock.images.extra = lock.images.edge; },
    lock => { lock.images.edge = lock.images.participant; },
    lock => { lock.sourceRevision = 'a'.repeat(40); },
    lock => { lock.sourceFingerprint = 'b'.repeat(64); },
  ]) { const images = imageLock(source, 2); mutate(images); assert.throws(() => validateCandidateReleaseLock(source, images, 2), error); }
});
