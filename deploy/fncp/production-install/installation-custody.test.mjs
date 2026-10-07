import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { acquireInstallationLock, createInstallationScratch } from './installation-custody.mjs';
function fixture(t) { const path = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'fncp-install-custody-'))); fs.chmodSync(path, 0o700); t.after(() => fs.rmSync(path, { recursive: true, force: true })); return path; }
test('target installation lock refuses another evidence directory and remains after failure', t => {
  const path = join(fixture(t), 'target'), first = acquireInstallationLock(path);
  assert.throws(() => acquireInstallationLock(path)); first.finish(false);
  assert.equal(fs.statSync(path + '.install.lock').mode & 0o777, 0o600); assert.throws(() => acquireInstallationLock(path));
});
test('only successful installation releases its own target mutex', t => {
  const path = join(fixture(t), 'target'), lock = acquireInstallationLock(path); lock.verify(); lock.finish(true); assert.equal(fs.existsSync(path + '.install.lock'), false);
});
test('replaced lock is not removed', t => {
  const path = join(fixture(t), 'target'), lock = acquireInstallationLock(path); fs.renameSync(path + '.install.lock', path + '.original'); fs.writeFileSync(path + '.install.lock', 'foreign', { mode: 0o600 });
  assert.throws(() => lock.finish(true)); assert.equal(fs.readFileSync(path + '.install.lock', 'utf8'), 'foreign');
});
test('maintenance credentials are removed with their exact private scratch namespace', t => {
  const root = fixture(t), path = join(root, 'scratch'), scratch = createInstallationScratch(); scratch.directory(path); scratch.directory(join(path, 'wordpress-initialize')); scratch.file(join(path, 'wordpress-initialize', 'owner.json'), Buffer.from('SYNTHETIC_ONLY'));
  scratch.cleanup(); assert.equal(fs.existsSync(path), false);
});
test('unknown or replaced scratch material is preserved and cleanup fails closed', t => {
  const root = fixture(t), path = join(root, 'scratch'), scratch = createInstallationScratch(); scratch.directory(path); scratch.file(join(path, 'owner.json'), Buffer.from('SYNTHETIC_ONLY'));
  fs.renameSync(join(path, 'owner.json'), join(path, 'old')); fs.writeFileSync(join(path, 'owner.json'), 'foreign', { mode: 0o600 });
  assert.throws(() => scratch.cleanup()); assert.equal(fs.readFileSync(join(path, 'owner.json'), 'utf8'), 'foreign');
});
