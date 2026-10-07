import assert from 'node:assert/strict';
import { chmod, mkdtemp, writeFile, realpath, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { inspectArchive } from './archive.mjs';

const denied = { message: 'FNCP_OFFLINE_CORE_RECOVERY_REJECTED' };
function entry(name, { kind = 'file', content = '', uid = 70, gid = 70, mode = kind === 'directory' ? 0o700 : 0o600,
  type = kind === 'directory' ? '5' : '0', link = '', declaredSize } = {}) {
  const bytes = Buffer.from(content); const block = Buffer.alloc(512);
  block.write(name, 0, 100, 'utf8');
  const octal = (value, start, size) => block.write(value.toString(8).padStart(size - 1, '0') + '\0', start, size, 'ascii');
  octal(mode, 100, 8); octal(uid, 108, 8); octal(gid, 116, 8); octal(declaredSize ?? bytes.length, 124, 12); octal(0, 136, 12);
  block.fill(32, 148, 156); block.write(type, 156, 1); block.write(link, 157, 100); block.write('ustar\0', 257, 6);
  block.write(block.reduce((sum, value) => sum + value, 0).toString(8).padStart(6, '0') + '\0 ', 148, 8);
  return Buffer.concat([block, bytes, Buffer.alloc(Math.ceil(bytes.length / 512) * 512 - bytes.length)]);
}
const base = () => [entry('pgdata/', { kind: 'directory' }), entry('pgdata/global/', { kind: 'directory' }),
  entry('pgdata/PG_VERSION', { content: '17\n' }), entry('pgdata/global/pg_control', { content: 'invented-control' }),
  ...['fncp.conf', 'fncp-initialized', 'server.key', 'server.crt'].map(name => entry('pgdata/' + name, { content: 'invented-fixture' }))];
async function fixture(t, parts) {
  const dir = await mkdtemp(join(await realpath(tmpdir()), 'fncp-offline-archive-test-')); await chmod(dir, 0o700);
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, 'private.tar'); await writeFile(path, Buffer.concat([...parts, Buffer.alloc(1024)]), { mode: 0o600 });
  return { path, dir };
}
test('private USTAR yields bounded file-content records without extracting or starting anything', async t => {
  const h = await fixture(t, base()); const result = await inspectArchive(h.path);
  assert.equal(result.version, 1); assert.equal(result.records.length, 8);
  assert.match(result.archiveSha256, /^[0-9a-f]{64}$/);
  assert.match(result.fileContentSha256, /^[0-9a-f]{64}$/);
  assert.doesNotMatch(JSON.stringify(result), /invented-control|invented-fixture/);
});
for (const [name, extra] of [
  ['absolute path', entry('/outside', { content: 'x' })], ['traversal', entry('pgdata/../outside', { content: 'x' })],
  ['duplicate entry', entry('pgdata/PG_VERSION', { content: 'x' })],
  ['symbolic link', entry('pgdata/link', { type: '2', link: '/outside' })],
  ['hard link', entry('pgdata/link', { type: '1', link: 'pgdata/PG_VERSION' })],
  ['device', entry('pgdata/device', { type: '3' })], ['PAX header', entry('pgdata/pax', { type: 'x' })],
  ['wrong UID', entry('pgdata/uid', { uid: 0 })], ['wrong GID', entry('pgdata/gid', { gid: 0 })],
  ['public mode', entry('pgdata/readable', { mode: 0o644 })],
  ['missing parent', entry('pgdata/absent/file')], ['live postmaster marker', entry('pgdata/postmaster.pid')],
  ['unsafe declared size', entry('pgdata/large', { declaredSize: 600 * 1024 * 1024 })],
]) test(`archive rejects ${name}`, async t => { const h = await fixture(t, [...base(), extra]); await assert.rejects(inspectArchive(h.path), denied); });
test('damaged checksums, truncated payload and data after end markers reject', async t => {
  const damaged = base(); damaged[2][20] ^= 1;
  const h = await fixture(t, damaged); await assert.rejects(inspectArchive(h.path), denied);
  await writeFile(h.path, Buffer.concat([...base(), entry('pgdata/truncated', { declaredSize: 1024 })]));
  await assert.rejects(inspectArchive(h.path), denied);
  await writeFile(h.path, Buffer.concat([...base(), Buffer.alloc(1024), entry('pgdata/after-end')]));
  await assert.rejects(inspectArchive(h.path), denied);
});
test('archive reader rejects symlinks and public file permissions', async t => {
  const h = await fixture(t, base()); await chmod(h.path, 0o644);
  await assert.rejects(inspectArchive(h.path), denied); await chmod(h.path, 0o600);
  const link = join(h.dir, 'link.tar'); await symlink(h.path, link);
  await assert.rejects(inspectArchive(link), denied);
});
