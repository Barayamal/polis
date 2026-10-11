import fs from 'node:fs';
import { dirname, resolve } from 'node:path';
const denied = () => new Error('FNCP_CLOSED_INSTALL_REJECTED:CUSTODY');
const same = (a, b) => a.ino === b.ino && a.dev === b.dev;
function directory(path) {
  if (typeof path !== 'string' || resolve(path) !== path || fs.realpathSync(path) !== path) throw denied();
  const stat = fs.lstatSync(path); if (!stat.isDirectory() || stat.uid !== process.getuid() || (stat.mode & 0o7777) !== 0o700) throw denied(); return stat;
}
function privateFile(stat) { return stat.isFile() && stat.uid === process.getuid() && stat.nlink === 1 && (stat.mode & 0o7777) === 0o600; }
/** One exclusive target mutex. Success releases only its original inode; any
 * incomplete installation retains the lock, with no stale-PID/age takeover. */
export function acquireInstallationLock(targetDirectory) {
  if (typeof targetDirectory !== 'string' || resolve(targetDirectory) !== targetDirectory || targetDirectory === '/') throw denied();
  const parent = dirname(targetDirectory), parentStat = directory(parent), path = targetDirectory + '.install.lock';
  const fd = fs.openSync(path, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600), stat = fs.fstatSync(fd);
  const verify = () => { if (!same(directory(parent), parentStat) || ![fs.fstatSync(fd), fs.lstatSync(path)].every(s => same(s, stat) && privateFile(s))) throw denied(); };
  let finished = false;
  return Object.freeze({ verify, finish(success) {
    if (finished || typeof success !== 'boolean') throw denied();
    try { verify(); if (success) fs.unlinkSync(path); } finally { finished = true; fs.closeSync(fd); }
  } });
}
/** Remove only explicitly created scratch files/directories whose inode and
 * private ownership remain intact. Unknown or replaced material is preserved. */
export function createInstallationScratch() {
  const files = [], directories = [];
  return Object.freeze({
    directory(path) { fs.mkdirSync(path, { mode: 0o700 }); directories.push([path, directory(path)]); },
    file(path, bytes) {
      const parent = directory(dirname(path)), fd = fs.openSync(path, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
      try { const stat = fs.fstatSync(fd); files.push([path, stat, parent]); if (!privateFile(stat)) throw denied(); fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    },
    cleanup() {
      for (const [path, stat, parent] of files) {
        if (!same(directory(dirname(path)), parent)) throw denied();
        const current = fs.lstatSync(path); if (!same(current, stat) || !privateFile(current)) throw denied(); fs.unlinkSync(path);
      }
      for (const [path, stat] of directories.reverse()) { if (!same(directory(path), stat)) throw denied(); fs.rmdirSync(path); }
    },
  });
}
