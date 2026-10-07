import { constants } from 'node:fs';
import { open, realpath, lstat, unlink } from 'node:fs/promises';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { MAX_ARCHIVE_BYTES, recoveryFailure, digest } from './archive.mjs';

const MAGIC = Buffer.from('FNCPPG01');
const MAX_HEADER = 4096;
async function privateFile(path, max) {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await file.stat({ bigint: true });
    if (!stat.isFile() || stat.nlink !== 1n || stat.uid !== BigInt(process.getuid())
      || (stat.mode & 0o7777n) !== 0o600n || stat.size < 1n || stat.size > BigInt(max)
      || await realpath(path) !== resolve(path)) throw recoveryFailure();
    return { file, stat };
  } catch { await file.close(); throw recoveryFailure(); }
}
async function write(file, bytes) {
  let offset = 0;
  while (offset < bytes.length) {
    const { bytesWritten } = await file.write(bytes, offset, bytes.length - offset);
    if (!bytesWritten) throw recoveryFailure(); offset += bytesWritten;
  }
}
async function read(file, bytes, position) {
  let offset = 0;
  while (offset < bytes.length) {
    const { bytesRead } = await file.read(bytes, offset, bytes.length - offset, position + offset);
    if (!bytesRead) throw recoveryFailure(); offset += bytesRead;
  }
}
async function unchanged(path, original, file) {
  const current = await file.stat({ bigint: true }); const named = await lstat(path, { bigint: true });
  for (const key of ['ino', 'dev', 'size', 'mtimeNs', 'ctimeNs', 'uid', 'mode', 'nlink']) {
    if (original[key] !== current[key] || original[key] !== named[key]) throw recoveryFailure();
  }
}
async function readKey(path) {
  const { file, stat } = await privateFile(path, 32);
  try { if (stat.size !== 32n) throw recoveryFailure(); const key = Buffer.alloc(32); await read(file, key, 0); return key; }
  finally { await file.close(); }
}

/** Retained archive contains only AES-256-GCM ciphertext plus an authenticated
 * bounded header. The independently owned 0600 key file is supplied explicitly.
 */
export async function encryptArchive({ plaintextPath, encryptedPath, keyPath, context }) {
  let input; let output; let key;
  try {
    ({ file: input } = await privateFile(plaintextPath, MAX_ARCHIVE_BYTES));
    const stat = await input.stat({ bigint: true }); key = await readKey(keyPath);
    const iv = randomBytes(12);
    const header = { version: 1, algorithm: 'AES-256-GCM', iv: iv.toString('base64url'),
      plaintextBytes: Number(stat.size), context };
    const encoded = Buffer.from(JSON.stringify(header));
    if (encoded.length > MAX_HEADER) throw recoveryFailure();
    const length = Buffer.alloc(4); length.writeUInt32BE(encoded.length);
    const aad = Buffer.concat([MAGIC, length, encoded]);
    const cipher = createCipheriv('aes-256-gcm', key, iv); cipher.setAAD(aad);
    output = await open(encryptedPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    await write(output, aad);
    const buffer = Buffer.alloc(64 * 1024); let position = 0;
    while (position < Number(stat.size)) {
      const chunk = buffer.subarray(0, Math.min(buffer.length, Number(stat.size) - position));
      await read(input, chunk, position); await write(output, cipher.update(chunk)); position += chunk.length;
    }
    await write(output, cipher.final()); await write(output, cipher.getAuthTag()); await output.sync();
    await unchanged(plaintextPath, stat, input);
    return { version: 1, algorithm: 'AES-256-GCM', headerSha256: digest(aad), plaintextBytes: position };
  } catch { throw recoveryFailure(); }
  finally { key?.fill(0); await input?.close(); await output?.close(); }
}

/** Authentication must succeed before the returned plaintext may be inspected
 * or restored. A failed authentication removes only this invocation's newly
 * created private plaintext file; the encrypted evidence and key are retained.
 */
export async function decryptArchive({ encryptedPath, plaintextPath, keyPath, expectedContext, onPlaintextCreated }) {
  let input; let output; let key; let created; let complete = false;
  try {
    const opened = await privateFile(encryptedPath, MAX_ARCHIVE_BYTES + MAX_HEADER + 28);
    input = opened.file; const stat = opened.stat;
    const prefix = Buffer.alloc(12); await read(input, prefix, 0);
    if (!prefix.subarray(0, 8).equals(MAGIC)) throw recoveryFailure();
    const length = prefix.readUInt32BE(8);
    if (length < 1 || length > MAX_HEADER || Number(stat.size) < 12 + length + 17) throw recoveryFailure();
    const encoded = Buffer.alloc(length); await read(input, encoded, 12);
    const header = JSON.parse(encoded.toString('utf8'));
    if (Object.keys(header).sort().join(',') !== 'algorithm,context,iv,plaintextBytes,version'
      || header.version !== 1 || header.algorithm !== 'AES-256-GCM'
      || typeof header.iv !== 'string' || !/^[A-Za-z0-9_-]{16}$/u.test(header.iv)
      || Buffer.from(header.iv, 'base64url').length !== 12
      || !Number.isSafeInteger(header.plaintextBytes) || header.plaintextBytes < 1
      || header.plaintextBytes > MAX_ARCHIVE_BYTES || JSON.stringify(header.context) !== JSON.stringify(expectedContext)
      || header.plaintextBytes !== Number(stat.size) - 12 - length - 16) throw recoveryFailure();
    const tag = Buffer.alloc(16); await read(input, tag, Number(stat.size) - 16); key = await readKey(keyPath);
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(header.iv, 'base64url'));
    decipher.setAAD(Buffer.concat([prefix, encoded])); decipher.setAuthTag(tag);
    output = await open(plaintextPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    created = await output.stat({ bigint: true });
    onPlaintextCreated?.(plaintextPath, created);
    const buffer = Buffer.alloc(64 * 1024); let remaining = header.plaintextBytes; let position = 12 + length;
    while (remaining) {
      const chunk = buffer.subarray(0, Math.min(buffer.length, remaining));
      await read(input, chunk, position); await write(output, decipher.update(chunk));
      position += chunk.length; remaining -= chunk.length;
    }
    await write(output, decipher.final()); await output.sync();
    await unchanged(encryptedPath, stat, input); complete = true;
    return { authenticated: true, plaintextBytes: header.plaintextBytes };
  } catch { throw recoveryFailure(); }
  finally {
    key?.fill(0); await input?.close(); await output?.close();
    if (created && !complete) {
      const current = await lstat(plaintextPath, { bigint: true });
      if (created.ino === current.ino && created.dev === current.dev && current.isFile()
        && current.uid === BigInt(process.getuid()) && current.nlink === 1n) await unlink(plaintextPath);
    }
  }
}
