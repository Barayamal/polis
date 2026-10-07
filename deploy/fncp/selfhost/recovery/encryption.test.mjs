import assert from 'node:assert/strict';
import { chmod, mkdtemp, writeFile, readFile, realpath, rm, lstat } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { encryptArchive, decryptArchive } from './encryption.mjs';

const denied = { message: 'FNCP_OFFLINE_CORE_RECOVERY_REJECTED' };
async function fixture(t) {
  const dir = await mkdtemp(join(await realpath(tmpdir()), 'fncp-core-encryption-test-')); await chmod(dir, 0o700);
  t.after(() => rm(dir, { recursive: true, force: true }));
  const plaintextPath = join(dir, 'source.tar'); const encryptedPath = join(dir, 'snapshot.enc');
  const keyPath = join(dir, 'separate.key'); const restored = join(dir, 'verified.tar');
  const value = Buffer.concat([Buffer.from('private sentinel archive content'), randomBytes(128 * 1024)]);
  await writeFile(plaintextPath, value, { mode: 0o600 }); await writeFile(keyPath, randomBytes(32), { mode: 0o600 });
  const context = { sourceImage: 'sha256:' + 'a'.repeat(64), sourceContentSha256: 'b'.repeat(64) };
  await encryptArchive({ plaintextPath, encryptedPath, keyPath, context });
  return { plaintextPath, encryptedPath, keyPath, restored, value, context };
}
test('streamed AES-GCM round trip authenticates before restoring private plaintext', async t => {
  const h = await fixture(t); const encrypted = await readFile(h.encryptedPath);
  assert.equal(encrypted.includes(Buffer.from('private sentinel archive content')), false);
  const result = await decryptArchive({ encryptedPath: h.encryptedPath, plaintextPath: h.restored, keyPath: h.keyPath, expectedContext: h.context });
  assert.equal(result.authenticated, true); assert.deepEqual(await readFile(h.restored), h.value);
  assert.equal((await lstat(h.restored)).mode & 0o777, 0o600);
});
for (const portion of ['header', 'ciphertext', 'tag', 'key', 'context']) test(`changed ${portion} fails and leaves no unauthenticated plaintext`, async t => {
  const h = await fixture(t);
  if (portion === 'key') await writeFile(h.keyPath, randomBytes(32));
  else if (portion !== 'context') {
    const bytes = await readFile(h.encryptedPath);
    const position = portion === 'header' ? 12 + 25 : portion === 'tag' ? bytes.length - 1 : bytes.length - 100;
    bytes[position] ^= 1; await writeFile(h.encryptedPath, bytes);
  }
  await assert.rejects(decryptArchive({ encryptedPath: h.encryptedPath, plaintextPath: h.restored, keyPath: h.keyPath,
    expectedContext: portion === 'context' ? { different: true } : h.context }), denied);
  await assert.rejects(lstat(h.restored), { code: 'ENOENT' });
});
test('truncated archives and nonprivate keys reject', async t => {
  const h = await fixture(t); await chmod(h.keyPath, 0o644);
  await assert.rejects(decryptArchive({ encryptedPath: h.encryptedPath, plaintextPath: h.restored, keyPath: h.keyPath, expectedContext: h.context }), denied);
  await chmod(h.keyPath, 0o600); await writeFile(h.encryptedPath, Buffer.alloc(10));
  await assert.rejects(decryptArchive({ encryptedPath: h.encryptedPath, plaintextPath: h.restored, keyPath: h.keyPath, expectedContext: h.context }), denied);
});
