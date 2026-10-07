import { CONTAINER_LISTENERS, createOperatorLoopbackGateway } from './gateway.mjs';

process.umask(0o077);
let gateway, stopping = false;
async function shutdown(code = 0) {
  if (stopping) return; stopping = true;
  try { await gateway?.close(); process.exitCode = code; } catch { process.exitCode = 1; }
}
process.once('SIGTERM', () => void shutdown());
process.once('SIGINT', () => void shutdown());
process.once('uncaughtException', () => void shutdown(1));
process.once('unhandledRejection', () => void shutdown(1));
try {
  if (process.argv.length !== 2) throw Error();
  gateway = createOperatorLoopbackGateway({ listeners: CONTAINER_LISTENERS });
  const state = await gateway.start();
  if (stopping) { await gateway.close(); throw Error(); }
  process.stdout.write(JSON.stringify(state) + '\n');
} catch { process.stderr.write('Operator loopback gateway startup rejected.\n'); await shutdown(1); }
