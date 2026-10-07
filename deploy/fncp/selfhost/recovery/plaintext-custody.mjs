import { lstat, unlink } from 'node:fs/promises';
import { isAbsolute, resolve } from 'node:path';
import { recoveryFailure } from './archive.mjs';

/** Register the fstat of each exclusively created plaintext file before writing
 * bytes. Cleanup deletes only that same owned, single-link private file; changed
 * custody is retained and rejected, never interpreted as deletion authority.
 */
export function createPlaintextCustody() {
  const created = new Map();
  function record(path, stat) {
    if (!isAbsolute(path) || resolve(path) !== path || created.has(path)
      || !stat.isFile() || stat.uid !== BigInt(process.getuid()) || stat.nlink !== 1n
      || (stat.mode & 0o7777n) !== 0o600n) throw recoveryFailure();
    created.set(path, { ino: stat.ino, dev: stat.dev });
  }
  async function cleanup() {
    let rejected = false;
    for (const [path, original] of created) {
      try {
        const current = await lstat(path, { bigint: true });
        if (current.ino !== original.ino || current.dev !== original.dev || !current.isFile()
          || current.uid !== BigInt(process.getuid()) || current.nlink !== 1n
          || (current.mode & 0o7777n) !== 0o600n) throw recoveryFailure();
        await unlink(path); created.delete(path);
      } catch (error) {
        if (error.code === 'ENOENT') created.delete(path);
        else rejected = true;
      }
    }
    if (rejected) throw recoveryFailure();
    return { ephemeralPlaintextRemoved: true };
  }
  return Object.freeze({ record, cleanup });
}
