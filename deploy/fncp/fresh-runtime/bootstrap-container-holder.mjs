/** Keeps only the fresh --network none namespace alive for the sibling PG.
 * No app imports, listener, filesystem read, child process or network work.
 * The separate fixed bootstrap command runs via an explicitly owned exec.
 */
import { pathToFileURL } from 'node:url';
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv.length !== 2 || process.platform !== 'linux' || process.getuid() !== 1000) process.exit(1);
  const limit = setTimeout(() => process.exit(1), 900000);
  process.once('SIGTERM', () => { clearTimeout(limit); process.exit(0); });
  process.once('SIGINT', () => { clearTimeout(limit); process.exit(0); });
}
