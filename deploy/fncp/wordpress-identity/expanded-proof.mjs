/** Explicit local-only actual seamless registration + closed four-store restore. */
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { runWordPressIdentityProof } from './actual-proof.mjs';
import { runExpandedRecovery } from '../expanded-recovery/run.mjs';
export const runSeamlessExpandedProof = () => runWordPressIdentityProof({ seamless: true, recovery: runExpandedRecovery });
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3 || process.argv[2] !== '--synthetic-seamless-expanded') throw new Error('Explicit synthetic expanded mode required.');
  runSeamlessExpandedProof().then(report => { process.exitCode = report.outcome === 'PASS' ? 0 : 1; })
    .catch(() => { console.error('SEAMLESS_EXPANDED_PROOF=FAIL; diagnostics redacted.'); process.exitCode = 1; });
}
