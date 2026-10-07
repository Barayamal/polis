import { constants } from 'node:fs';
import { open, lstat, realpath } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';

export const MAX_ARCHIVE_BYTES = 512 * 1024 * 1024;
export const recoveryFailure = () => new Error('FNCP_OFFLINE_CORE_RECOVERY_REJECTED');
export const digest = bytes => createHash('sha256').update(bytes).digest('hex');

function number(bytes) {
  const value = bytes.toString('ascii').replace(/\0.*$/u, '').trim();
  if (!/^[0-7]+$/u.test(value)) throw recoveryFailure();
  const result = Number.parseInt(value, 8);
  if (!Number.isSafeInteger(result) || result < 0) throw recoveryFailure();
  return result;
}

function text(bytes) {
  const zero = bytes.indexOf(0);
  const raw = zero < 0 ? bytes : bytes.subarray(0, zero);
  if (zero >= 0 && bytes.subarray(zero).some(value => value !== 0)) throw recoveryFailure();
  const value = raw.toString('utf8');
  if (!Buffer.from(value).equals(raw) || /[\u0000-\u001f\u007f\\]/u.test(value)) throw recoveryFailure();
  return value;
}

function header(bytes) {
  const checksum = number(bytes.subarray(148, 156));
  const normalized = Buffer.from(bytes); normalized.fill(32, 148, 156);
  if (normalized.reduce((sum, value) => sum + value, 0) !== checksum) throw recoveryFailure();
  const magic = bytes.subarray(257, 263).toString('ascii');
  if (magic !== 'ustar\0' && magic !== 'ustar ') throw recoveryFailure();
  const prefix = text(bytes.subarray(345, 500));
  let path = (prefix ? prefix + '/' : '') + text(bytes.subarray(0, 100));
  const kind = bytes[156] === 53 ? 'directory' : (bytes[156] === 0 || bytes[156] === 48) ? 'file' : null;
  if (!kind || text(bytes.subarray(157, 257))) throw recoveryFailure();
  if (kind === 'directory') path = path.replace(/\/$/u, '');
  if (!path || path.length > 255 || path.startsWith('/') || path.split('/').some(part => !part || part === '.' || part === '..')
    || !(path === 'pgdata' || path.startsWith('pgdata/')) || path === 'pgdata/postmaster.pid') throw recoveryFailure();
  const mode = number(bytes.subarray(100, 108));
  const uid = number(bytes.subarray(108, 116)); const gid = number(bytes.subarray(116, 124));
  const size = number(bytes.subarray(124, 136));
  if (uid !== 70 || gid !== 70 || mode > 0o777 || (mode & 0o077) !== 0
    || (kind === 'directory' && (mode !== 0o700 || size !== 0))
    || (kind === 'file' && mode !== 0o600) || size > MAX_ARCHIVE_BYTES) throw recoveryFailure();
  return { path, kind, mode, uid, gid, size };
}

async function exactly(file, buffer, position) {
  let offset = 0;
  while (offset < buffer.length) {
    const { bytesRead } = await file.read(buffer, offset, buffer.length - offset, position + offset);
    if (!bytesRead) throw recoveryFailure(); offset += bytesRead;
  }
}

/** Validate the private uncompressed USTAR before extraction. Only the fixed
 * pgdata tree, UID/GID70, private regular files and directories are accepted.
 * No PAX/GNU extensions, links, devices, traversal, duplicate path or sparse
 * entries can influence extraction. Contents and names stay in private records.
 */
export async function inspectArchive(path) {
  let file;
  try {
    file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await file.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.uid !== BigInt(process.getuid())
      || (before.mode & 0o7777n) !== 0o600n || before.size < 1024n || before.size > BigInt(MAX_ARCHIVE_BYTES)
      || before.size % 512n !== 0n || await realpath(path) !== resolve(path)) throw recoveryFailure();
    const records = []; const paths = new Map(); const whole = createHash('sha256');
    const block = Buffer.alloc(512); const chunk = Buffer.alloc(64 * 1024);
    let position = 0; let ended = false; let zeroBlocks = 0;
    while (position < Number(before.size)) {
      await exactly(file, block, position); whole.update(block); position += 512;
      if (block.every(value => value === 0)) { ended = true; zeroBlocks++; continue; }
      if (ended || records.length >= 20_000) throw recoveryFailure();
      const record = header(block);
      if (paths.has(record.path)) throw recoveryFailure();
      if (record.path !== 'pgdata') {
        const parent = record.path.slice(0, record.path.lastIndexOf('/'));
        if (paths.get(parent)?.kind !== 'directory') throw recoveryFailure();
      } else if (record.kind !== 'directory') throw recoveryFailure();
      const payload = createHash('sha256'); let remaining = record.size;
      const paddedSize = Math.ceil(record.size / 512) * 512;
      if (position + paddedSize > Number(before.size)) throw recoveryFailure();
      while (remaining) {
        const size = Math.min(remaining, chunk.length);
        const bytes = chunk.subarray(0, size); await exactly(file, bytes, position);
        payload.update(bytes); whole.update(bytes); position += size; remaining -= size;
      }
      const padding = paddedSize - record.size;
      if (padding) {
        const bytes = chunk.subarray(0, padding); await exactly(file, bytes, position);
        if (bytes.some(value => value !== 0)) throw recoveryFailure();
        whole.update(bytes); position += padding;
      }
      paths.set(record.path, record); records.push({ ...record, sha256: payload.digest('hex') });
    }
    if (zeroBlocks < 2 || !paths.has('pgdata/PG_VERSION') || !paths.has('pgdata/global/pg_control')
      || !paths.has('pgdata/fncp.conf') || !paths.has('pgdata/fncp-initialized')
      || !paths.has('pgdata/server.key') || !paths.has('pgdata/server.crt')) throw recoveryFailure();
    const after = await file.stat({ bigint: true }); const named = await lstat(path, { bigint: true });
    for (const key of ['ino', 'dev', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs']) {
      if (before[key] !== after[key] || before[key] !== named[key]) throw recoveryFailure();
    }
    records.sort((a, b) => a.path.localeCompare(b.path, 'en'));
    return { version: 1, archiveSha256: whole.digest('hex'), bytes: Number(before.size),
      fileContentSha256: digest(JSON.stringify(records)), records };
  } catch { throw recoveryFailure(); }
  finally { await file?.close(); }
}
