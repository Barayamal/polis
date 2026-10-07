import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';

export const MAX_BYTES = 512 * 1024 * 1024;
export const failure = () => new Error('Joined production recovery denied.');
export const sha = b => createHash('sha256').update(b).digest('hex');
export const VOLUMES = Object.freeze(['postgres', 'mariadb', 'participant_state', 'participant_material', 'wordpress_material', 'proxy_material']);
export const VOLUMES_V2 = Object.freeze([...VOLUMES, 'edge_material']);
export function volumeRoles(version = 1) { if (version === 1) return VOLUMES; if ([2,3].includes(version)) return VOLUMES_V2; throw failure(); }
const OWNERS = { postgres: 70, mariadb: 999, participant_state: 1000, participant_material: 1000, wordpress_material: 33, proxy_material: 101, edge_material: 1000 };
const REQUIRED = { postgres: ['pgdata/PG_VERSION', 'pgdata/global/pg_control', 'pgdata/fncp.conf', 'pgdata/fncp-initialized', 'pgdata/server.key', 'pgdata/server.crt'],
  mariadb: ['ibdata1', 'mysql'], participant_state: ['access.sqlite', 'activation.sqlite'], participant_material: ['service.json'],
  wordpress_material: ['config.json', 'plugin-config.json', 'server.pem', 'server-key.pem', 'receiver-ca.pem'], proxy_material: ['proxy-cert.pem', 'proxy-key.pem'], edge_material: ['config.json', 'server.pem', 'server-key.pem', 'upstream-ca.pem'] };
const stable = (a, b) => ['ino', 'dev', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs'].every(k => a[k] === b[k]);
export async function privateInput(path, maximum = MAX_BYTES) {
  let file;
  try {
    if (typeof path !== 'string' || resolve(path) !== path || await fs.realpath(path) !== path) throw failure();
    file = await fs.open(path, constants.O_RDONLY | constants.O_NOFOLLOW); const stat = await file.stat({ bigint: true });
    if (!stat.isFile() || stat.nlink !== 1n || stat.uid !== BigInt(process.getuid()) || (stat.mode & 0o7777n) !== 0o600n
      || stat.size < 1n || stat.size > BigInt(maximum)) throw failure();
    return { file, stat };
  } catch { await file?.close(); throw failure(); }
}
export async function unchanged(path, opened) {
  if (!stable(opened.stat, await opened.file.stat({ bigint: true })) || !stable(opened.stat, await fs.lstat(path, { bigint: true }))) throw failure();
}
export async function exactly(file, buffer, position) {
  let offset = 0; while (offset < buffer.length) { const r = await file.read(buffer, offset, buffer.length - offset, position + offset); if (!r.bytesRead) throw failure(); offset += r.bytesRead; }
}
export async function write(file, buffer) {
  let offset = 0; while (offset < buffer.length) { const r = await file.write(buffer, offset, buffer.length - offset); if (!r.bytesWritten) throw failure(); offset += r.bytesWritten; }
}
function number(b) { const v = b.toString('ascii').replace(/\0.*$/u, '').trim(); if (!/^[0-7]+$/u.test(v)) throw failure(); const n = Number.parseInt(v, 8); if (!Number.isSafeInteger(n) || n < 0) throw failure(); return n; }
function text(b) {
  const i = b.indexOf(0), raw = i < 0 ? b : b.subarray(0, i);
  if (i >= 0 && b.subarray(i).some(x => x !== 0)) throw failure();
  const s = raw.toString('utf8'); if (!Buffer.from(s).equals(raw) || /[\u0000-\u001f\u007f\\]/u.test(s)) throw failure(); return s;
}
function normalize(path, directory) {
  if (directory) path = path.replace(/\/$/u, '');
  if (path === '.') return '';
  if (path.startsWith('./')) path = path.slice(2);
  if (!path || path.length > 255 || path.startsWith('/') || path.split('/').some(s => !s || s === '.' || s === '..')) throw failure();
  return path;
}
function allowed(role, r) {
  const owner = OWNERS[role]; if (owner === undefined || r.mode > 0o1777 || r.size > MAX_BYTES) throw failure();
  if (r.path === '') {
    const pgRoot = role === 'postgres' && r.uid === 0 && r.gid === 0 && r.mode === 0o1777;
    const modes = role === 'mariadb' ? [0o700, 0o750, 0o755] : [0o700];
    if (r.kind !== 'directory' || !(pgRoot || r.uid === owner && r.gid === owner && modes.includes(r.mode))) throw failure();
  } else {
    if (r.uid !== owner || r.gid !== owner) throw failure();
    if (role === 'postgres') {
      if (!(r.path === 'pgdata' || r.path.startsWith('pgdata/')) || r.path === 'pgdata/postmaster.pid'
        || r.mode !== (r.kind === 'directory' ? 0o700 : 0o600)) throw failure();
    } else if (role === 'mariadb') {
      if (/(^|\/)(?:mysqld\.pid|mysqld\.sock)$/u.test(r.path)
        || !(r.kind === 'directory' ? [0o700, 0o750, 0o755] : [0o600, 0o640, 0o644, 0o660]).includes(r.mode)) throw failure();
    } else if (r.path.includes('/') || r.kind !== 'file' || ![0o400, 0o600].includes(r.mode)
      || r.size < 1 || r.size > (role === 'participant_state' ? 16 * 1024 * 1024 : 262144)
      || role !== 'participant_material' && !REQUIRED[role].includes(r.path)) throw failure();
  }
  if (r.kind === 'directory' && r.size !== 0) throw failure();
}
function header(block, role) {
  const copy = Buffer.from(block); copy.fill(32, 148, 156);
  if (number(block.subarray(148, 156)) !== copy.reduce((a, b) => a + b, 0)
    || !['ustar\0', 'ustar '].includes(block.subarray(257, 263).toString('ascii'))) throw failure();
  const kind = block[156] === 53 ? 'directory' : [0, 48].includes(block[156]) ? 'file' : null;
  if (!kind || text(block.subarray(157, 257))) throw failure();
  const prefix = text(block.subarray(345, 500));
  const r = { path: normalize((prefix ? prefix + '/' : '') + text(block.subarray(0, 100)), kind === 'directory'), kind,
    mode: number(block.subarray(100, 108)), uid: number(block.subarray(108, 116)), gid: number(block.subarray(116, 124)),
    size: number(block.subarray(124, 136)), mtime: number(block.subarray(136, 148)) };
  allowed(role, r); return r;
}

/** Fixed-role USTAR inspection precedes every restore. Rejects links, devices,
 * PAX/GNU extensions, duplicate/traversing names and role-incompatible owners.
 * File names/content hashes are private intermediate data, never public output.
 */
export async function inspectVolumeArchive(path, role) {
  let opened;
  try {
    opened = await privateInput(path); const { file, stat } = opened;
    if (stat.size < 1024n || stat.size % 512n) throw failure();
    const records = [], paths = new Map(), whole = createHash('sha256'), block = Buffer.alloc(512), chunk = Buffer.alloc(65536);
    let position = 0, ended = false, zeroBlocks = 0;
    while (position < Number(stat.size)) {
      await exactly(file, block, position); whole.update(block); position += 512;
      if (block.every(b => b === 0)) { ended = true; zeroBlocks++; continue; }
      if (ended || records.length >= 20000) throw failure();
      const r = header(block, role);
      if (paths.has(r.path) || r.path !== '' && paths.get(r.path.includes('/') ? r.path.slice(0, r.path.lastIndexOf('/')) : '')?.kind !== 'directory') throw failure();
      const offset = position, padded = Math.ceil(r.size / 512) * 512, hash = createHash('sha256');
      if (position + padded > Number(stat.size)) throw failure();
      let remaining = r.size;
      while (remaining) { const bytes = chunk.subarray(0, Math.min(remaining, chunk.length)); await exactly(file, bytes, position); hash.update(bytes); whole.update(bytes); position += bytes.length; remaining -= bytes.length; }
      if (padded > r.size) { const bytes = chunk.subarray(0, padded - r.size); await exactly(file, bytes, position); if (bytes.some(b => b)) throw failure(); whole.update(bytes); position += bytes.length; }
      const record = { ...r, sha256: hash.digest('hex'), offset }; records.push(record); paths.set(r.path, record);
    }
    if (zeroBlocks < 2 || !paths.has('') || REQUIRED[role].some(name => !paths.has(name))) throw failure();
    if (role === 'participant_state' && records.length !== 3 || role === 'wordpress_material' && records.length !== 6 || role === 'proxy_material' && records.length !== 3 || role === 'edge_material' && records.length !== 5) throw failure();
    await unchanged(path, opened);
    const logical = records.map(({ offset, mtime, ...r }) => r).sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
    return { role, bytes: Number(stat.size), archiveSha256: whole.digest('hex'), contentSha256: sha(JSON.stringify(logical)), records };
  } catch { throw failure(); }
  finally { await opened?.file.close(); }
}

export async function readArchiveMember(path, inventory, name, maximum = 262144) {
  const r = inventory.records.find(r => r.path === name);
  if (!r || r.kind !== 'file' || r.size > maximum) throw failure();
  const opened = await privateInput(path), bytes = Buffer.alloc(r.size);
  try { await exactly(opened.file, bytes, r.offset); if (sha(bytes) !== r.sha256) throw failure(); await unchanged(path, opened); return bytes; }
  catch { bytes.fill(0); throw failure(); } finally { await opened.file.close(); }
}
function octal(block, offset, length, n) { const s = n.toString(8); if (s.length > length - 1) throw failure(); block.write(s.padStart(length - 1, '0') + '\0', offset, length, 'ascii'); }
function encodedHeader(r) {
  const block = Buffer.alloc(512), name = r.path || './';
  if (Buffer.byteLength(name) > 99) throw failure(); block.write(name, 0, 100, 'utf8');
  octal(block, 100, 8, r.mode); octal(block, 108, 8, r.uid); octal(block, 116, 8, r.gid);
  octal(block, 124, 12, r.size); octal(block, 136, 12, r.mtime); block.fill(32, 148, 156);
  block[156] = r.kind === 'directory' ? 53 : 48; block.write('ustar\0', 257, 6, 'ascii'); block.write('00', 263, 2, 'ascii');
  const sum = block.reduce((a, b) => a + b, 0); block.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'ascii'); return block;
}

/** Rebuild only flat private material/state archives with explicit replacements.
 * Database volume archives are never rewritten by this function.
 */
export async function rewritePrivateVolumeArchive({ sourcePath, targetPath, inventory, replacements, onCreated }) {
  let output;
  try {
    if (!['participant_state', 'participant_material', 'wordpress_material', 'proxy_material', 'edge_material'].includes(inventory.role)
      || !(replacements instanceof Map) || [...replacements.keys()].some(k => !inventory.records.some(r => r.path === k && r.kind === 'file'))) throw failure();
    output = await fs.open(targetPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    onCreated?.(targetPath, await output.stat({ bigint: true }));
    for (const r of inventory.records) {
      const bytes = r.kind === 'file' ? replacements.has(r.path) ? replacements.get(r.path) : await readArchiveMember(sourcePath, inventory, r.path, 16 * 1024 * 1024) : Buffer.alloc(0);
      try { if (!Buffer.isBuffer(bytes)) throw failure(); const next = { ...r, size: bytes.length }; allowed(inventory.role, next);
        await write(output, encodedHeader(next)); await write(output, bytes); if (bytes.length % 512) await write(output, Buffer.alloc(512 - bytes.length % 512));
      } finally { if (!replacements.has(r.path)) bytes.fill(0); }
    }
    await write(output, Buffer.alloc(1024)); await output.sync();
  } catch { throw failure(); } finally { await output?.close(); }
  return inspectVolumeArchive(targetPath, inventory.role);
}
