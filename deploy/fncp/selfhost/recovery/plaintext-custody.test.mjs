import assert from 'node:assert/strict';
import { chmod, lstat, mkdtemp, open, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createPlaintextCustody } from './plaintext-custody.mjs';
import { encryptArchive, decryptArchive } from './encryption.mjs';
import { runPrivateCommand } from './command-runner.mjs';

const denied = { message: 'FNCP_OFFLINE_CORE_RECOVERY_REJECTED' };
async function fixture(t) {
  const dir = await mkdtemp(join(await realpath(tmpdir()), 'fncp-core-custody-test-')); await chmod(dir, 0o700);
  t.after(() => rm(dir, { recursive: true, force: true }));
  return { dir, custody: createPlaintextCustody() };
}
async function create(path, custody, value = 'private plaintext') {
  const file = await open(path, 'wx', 0o600);
  try { custody.record(path, await file.stat({ bigint: true })); await file.writeFile(value); }
  finally { await file.close(); }
}

test('post-encryption failure removes source and authenticated plaintext but retains ciphertext and separate key', async t => {
  const { dir, custody } = await fixture(t);
  const plaintextPath = join(dir, 'source.tar'); const restored = join(dir, 'authenticated.tar');
  const encryptedPath = join(dir, 'snapshot.enc'); const keyPath = join(dir, 'separate.key');
  const context = { version: 1, test: true };
  await assert.rejects(async () => {
    try {
      await create(plaintextPath, custody, Buffer.concat([Buffer.from('sentinel'), randomBytes(80_000)]));
      await writeFile(keyPath, randomBytes(32), { mode: 0o600, flag: 'wx' });
      await encryptArchive({ plaintextPath, encryptedPath, keyPath, context });
      await decryptArchive({ encryptedPath, plaintextPath: restored, keyPath, expectedContext: context, onPlaintextCreated: custody.record });
      throw new Error('SIMULATED_POST_ENCRYPTION_VALIDATION_FAILURE');
    } finally { await custody.cleanup(); }
  }, { message: 'SIMULATED_POST_ENCRYPTION_VALIDATION_FAILURE' });
  await assert.rejects(lstat(plaintextPath), { code: 'ENOENT' });
  await assert.rejects(lstat(restored), { code: 'ENOENT' });
  assert.equal((await lstat(encryptedPath)).mode & 0o777, 0o600);
  assert.equal((await readFile(keyPath)).length, 32);
  assert.deepEqual(await custody.cleanup(), { ephemeralPlaintextRemoved: true });
});

test('partial command output is registered before failure and removed by finally', async t => {
  const { dir, custody } = await fixture(t); const path = join(dir, 'partial.tar');
  await assert.rejects(async () => {
    try {
      await runPrivateCommand(process.execPath, ['-e', 'process.stdout.write("partial"); process.exitCode = 1'],
        { outputPath: path, onOutputCreated: custody.record });
    } finally { await custody.cleanup(); }
  }, denied);
  await assert.rejects(lstat(path), { code: 'ENOENT' });
});

test('replaced inode is preserved while other invocation files are still removed', async t => {
  const { dir, custody } = await fixture(t); const path = join(dir, 'changed.tar'); const other = join(dir, 'other.tar');
  await create(path, custody); await create(other, custody);
  await rename(path, join(dir, 'moved-original.tar')); await writeFile(path, 'unrelated replacement', { mode: 0o600, flag: 'wx' });
  await assert.rejects(custody.cleanup(), denied);
  assert.equal(await readFile(path, 'utf8'), 'unrelated replacement');
  await assert.rejects(lstat(other), { code: 'ENOENT' });
});

test('existing output collision is never registered or removed', async t => {
  const { dir, custody } = await fixture(t); const path = join(dir, 'pre-existing.tar');
  await writeFile(path, 'preserve', { mode: 0o600, flag: 'wx' });
  await assert.rejects(runPrivateCommand(process.execPath, ['-e', 'process.exit(0)'],
    { outputPath: path, onOutputCreated: custody.record }), denied);
  await custody.cleanup(); assert.equal(await readFile(path, 'utf8'), 'preserve');
});

test('stderr warning plus exit zero is rejected without exposing control-file fields', async () => {
  await assert.rejects(runPrivateCommand(process.execPath, ['-e',
    'process.stdout.write("postgres (PostgreSQL) 17.11\\nDatabase cluster state: shut down\\n"); process.stderr.write("pg_controldata: warning: calculated CRC checksum does not match value stored in file\\nprivate-control-field");'],
  { rejectStderr: true }), denied);
});

test('clean zero-exit control command remains usable with strict diagnostics policy', async () => {
  assert.equal(await runPrivateCommand(process.execPath, ['-e', 'process.stdout.write("clean output\\n")'],
    { rejectStderr: true }), 'clean output');
});
