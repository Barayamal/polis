// Read-only source provenance for uncommitted local candidates. This is not a
// signature, a complete dependency lock, an image proof, or release authority.
import { spawnSync } from 'node:child_process';
import { lstat, realpath, open } from 'node:fs/promises';
import { resolve, isAbsolute, join } from 'node:path';
import { createHash, X509Certificate } from 'node:crypto';
import { validateProductionImageLock } from '../production-deployment/compose.mjs';

const OMIT = new Set(['deploy/fncp/selfhost/source-lock.json', 'deploy/fncp/release-readiness/source-lock.json']);
const CERTIFICATES = new Set(['math/test/fixtures/dedicated-test-ca.pem', 'math/test/fixtures/dedicated-test-leaf.pem']);
const LIMIT = Object.freeze({ files: 10000, file: 32 * 1024 * 1024, total: 256 * 1024 * 1024 });
const reject = () => { throw new Error('FNCP_CANDIDATE_SOURCE_REJECTED'); };
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const hex = (value, length) => typeof value === 'string' && new RegExp(`^[a-f0-9]{${length}}$`, 'u').test(value);
const stamp = stat => ['dev','ino','mode','nlink','size','mtimeNs','ctimeNs'].map(key => String(stat[key])).join(':');
function exact(value, names) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype || Reflect.ownKeys(value).length !== names.length
    || names.some(name => !Object.hasOwn(value, name)) || Object.values(Object.getOwnPropertyDescriptors(value)).some(d => !Object.hasOwn(d, 'value'))) reject();
}
function array(value) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || Object.keys(value).length !== value.length
    || Reflect.ownKeys(value).length !== value.length + 1 || Object.values(Object.getOwnPropertyDescriptors(value)).some(d => !Object.hasOwn(d, 'value'))) reject();
}
function safeName(name) {
  if (typeof name !== 'string' || name.length > 1024 || isAbsolute(name) || /[\u0000-\u001f\u007f\\:]/u.test(name)
    || name !== name.normalize('NFC') || name.split('/').some(part => !part || part === '.' || part === '..' || /[. ]$/u.test(part))) reject();
  if (/(^|\/)(node_modules|\.git|keys|certs|private|\.runtime)(\/|$)/u.test(name)
    || /(^|\/)\.env(?:\.|$)/u.test(name) || /\.(key|pem|sqlite|sqlite3|db|dump|p12|pfx)$/iu.test(name) && !CERTIFICATES.has(name)) reject();
}
function git(root, args) {
  const result = spawnSync('git', ['-C', root, ...args], { encoding: 'utf8', timeout: 15000, maxBuffer: 4 * 1024 * 1024,
    env: { PATH: process.env.PATH, HOME: process.env.HOME, LANG: 'C', LC_ALL: 'C', GIT_OPTIONAL_LOCKS: '0' }, shell: false });
  if (result.status !== 0 || result.error || result.signal) reject();
  return result.stdout;
}
function membership(root) {
  const raw = git(root, ['ls-files', '--cached', '--others', '--exclude-standard', '-z']);
  if (!raw.endsWith('\0')) reject();
  const names = raw.slice(0, -1).split('\0').filter(name => !OMIT.has(name)).sort();
  if (!names.length || names.length > LIMIT.files || new Set(names.map(name => name.toLowerCase())).size !== names.length) reject();
  names.forEach(safeName);
  return names;
}
async function oneFile(root, name) {
  const path = join(root, name);
  const components = name.split('/'); components.pop();
  let ancestor = root;
  const directories = [];
  for (const part of ['', ...components]) {
    if (part) ancestor = join(ancestor, part);
    const stat = await lstat(ancestor, { bigint: true });
    if (!stat.isDirectory() || stat.isSymbolicLink()) reject();
    directories.push([ancestor, stamp(stat)]);
  }
  const before = await lstat(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n || before.size > BigInt(LIMIT.file)) reject();
  const file = await open(path, 'r');
  let bytes;
  try {
    if (stamp(await file.stat({ bigint: true })) !== stamp(before)) reject();
    bytes = await file.readFile();
    if (bytes.length !== Number(before.size) || stamp(await file.stat({ bigint: true })) !== stamp(before)
      || stamp(await lstat(path, { bigint: true })) !== stamp(before)) reject();
  } finally { await file.close(); }
  for (const [path, expected] of directories) if (stamp(await lstat(path, { bigint: true })) !== expected) reject();
  if (await realpath(root) !== root) reject();
  if (CERTIFICATES.has(name)) {
    const pem = bytes.toString('utf8');
    if (!/^-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+\n-----END CERTIFICATE-----\n?$/u.test(pem)) reject();
    new X509Certificate(pem);
  }
  return { entry: { path: name, sha256: sha(bytes), executable: Boolean(before.mode & 0o111n) }, size: bytes.length, stamp: stamp(before) };
}
function freeze(value) { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; }

export function validateCandidateSourceLockShape(lock) {
  try {
    exact(lock, ['version','sourceRevision','sourceFingerprint','files']); array(lock.files);
    if (lock.version !== 1 || !hex(lock.sourceRevision, 40) || !hex(lock.sourceFingerprint, 64)
      || !lock.files.length || lock.files.length > LIMIT.files) reject();
    let previous = ''; const aliases = new Set();
    for (const file of lock.files) {
      exact(file, ['path','sha256','executable']); safeName(file.path);
      if (OMIT.has(file.path) || file.path <= previous || aliases.has(file.path.toLowerCase())
        || !hex(file.sha256, 64) || typeof file.executable !== 'boolean') reject();
      previous = file.path; aliases.add(file.path.toLowerCase());
    }
    const files = lock.files.map(file => ({ path: file.path, sha256: file.sha256, executable: file.executable }));
    if (sha(JSON.stringify(files)) !== lock.sourceFingerprint) reject();
    return freeze({ version: 1, sourceRevision: lock.sourceRevision, sourceFingerprint: lock.sourceFingerprint, files });
  } catch { reject(); }
}

/** Includes tracked files and nonignored additions; writes nothing. Run on a
 * quiescent trusted checkout. Two passes detect ordinary concurrent drift,
 * not an adversarial filesystem writer or ignored build inputs. */
export async function createCandidateSourceLock(root) {
  try {
    if (typeof root !== 'string' || !isAbsolute(root) || resolve(root) !== root || await realpath(root) !== root) reject();
    if (git(root, ['rev-parse', '--show-toplevel']).trim() !== root) reject();
    const revision = git(root, ['rev-parse', 'HEAD']).trim(); if (!hex(revision, 40)) reject();
    const names = membership(root), files = [], stamps = []; let total = 0;
    for (const name of names) {
      const row = await oneFile(root, name); total += row.size; if (total > LIMIT.total) reject();
      files.push(row.entry); stamps.push(row.stamp);
    }
    if (JSON.stringify(membership(root)) !== JSON.stringify(names) || git(root, ['rev-parse', 'HEAD']).trim() !== revision) reject();
    for (let index = 0; index < names.length; index++) {
      const row = await oneFile(root, names[index]);
      if (row.stamp !== stamps[index] || JSON.stringify(row.entry) !== JSON.stringify(files[index])) reject();
    }
    if (JSON.stringify(membership(root)) !== JSON.stringify(names) || git(root, ['rev-parse', 'HEAD']).trim() !== revision) reject();
    return validateCandidateSourceLockShape({ version: 1, sourceRevision: revision, sourceFingerprint: sha(JSON.stringify(files)), files });
  } catch { reject(); }
}

export async function validateCandidateSourceLock(root, supplied) {
  try {
    const lock = validateCandidateSourceLockShape(supplied), observed = await createCandidateSourceLock(root);
    if (JSON.stringify(lock) !== JSON.stringify(observed)) reject();
    return observed;
  } catch { reject(); }
}

/** Schema/source binding only. Actual image bytes and copy receipts must be
 * verified separately; no image existence or deployment claim is inferred. */
export function validateCandidateReleaseLock(sourceLock, imageLock, composeVersion) {
  try {
    const source = validateCandidateSourceLockShape(sourceLock), images = validateProductionImageLock(imageLock);
    if (![1, 2, 3].includes(composeVersion) || images.version !== composeVersion
      || images.sourceRevision !== source.sourceRevision || images.sourceFingerprint !== source.sourceFingerprint) reject();
    return images;
  } catch { reject(); }
}
