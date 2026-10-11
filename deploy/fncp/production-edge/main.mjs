import { createContainerParticipantEdge } from './material.mjs';
process.umask(0o077);
let edge, monitor, stopping = false;
async function shutdown(code = 0) {
  if (stopping) return; stopping = true; clearInterval(monitor);
  try { await edge?.close(); process.exitCode = code; } catch { process.exitCode = 1; }
}
process.once('SIGTERM', () => void shutdown());
process.once('SIGINT', () => void shutdown());
process.once('uncaughtException', () => void shutdown(1));
process.once('unhandledRejection', () => void shutdown(1));
try {
  if (process.argv.length !== 3 || process.argv[2] !== '/run/fncp/edge/config.json') throw Error();
  edge = createContainerParticipantEdge({ configurationPath: process.argv[2] });
  const state = await edge.start();
  if (stopping) { await edge.close(); throw Error(); }
  process.stdout.write(JSON.stringify({ profile: state.profile, ready: true }) + '\n');
  monitor = setInterval(() => { try { edge.verify(); } catch { void shutdown(1); } }, 1000);
  monitor.unref();
} catch { process.stderr.write('Participant edge startup rejected.\n'); await shutdown(1); }
