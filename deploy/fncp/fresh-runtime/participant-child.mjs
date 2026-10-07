/** Fixed ordinary Pol.is participant child. Dedicated private stdio and IPC;
 * no index.js, public listener, browser admin route or executable selection.
 * HTTP exists only on this container's loopback; outer owner attests isolation.
 */
import { createRequire } from 'node:module';
import { statSync, fstatSync, existsSync } from 'node:fs';
import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

const methods = new Map([
  ['/api/v3/participationInit', 'GET'], ['/api/v3/nextComment', 'GET'], ['/api/v3/votes', 'POST'],
  ['/fncp/private/xid-allowlist/upsert', 'POST'], ['/fncp/private/xid-allowlist/readback', 'POST'],
  ['/fncp/private/xid-allowlist/remove', 'POST'],
]);
export function participantRouteAllowed(method, url) {
  if (typeof method !== 'string' || typeof url !== 'string' || url.length > 4096 ||
      /[%\\\u0000-\u0020\u007f]/u.test(url)) return false;
  const path = url.split('?')[0];
  return methods.get(path) === method;
}

async function run() {
  if (process.platform !== 'linux' || process.getuid?.() !== 1000 || process.argv.length !== 2 ||
      process.execArgv.length !== 0 || !process.connected || typeof process.send !== 'function' ||
      process.env.FNCP_OPTION_C_RELEASE_MODE !== 'production' || process.env.NODE_ENV !== 'production' ||
      process.env.API_SERVER_PORT !== '5500' || process.env.DATABASE_SSL !== 'true' ||
      process.env.DATABASE_SSL_CA_FILE !== '/run/fncp/bootstrap/postgres-cert.pem' ||
      process.env.FNCP_FRESH_BOOTSTRAP_LOCAL_ONLY !== undefined ||
      process.cwd() !== '/app' || existsSync('/app/.env')) throw new Error('private child rejected');
  const target = statSync('/dev/null');
  for (const fd of [0, 1, 2]) {
    const current = fstatSync(fd);
    if (!current.isCharacterDevice() || current.dev !== target.dev || current.ino !== target.ino) throw new Error('private stdio rejected');
  }
  let server; let closing = false;
  const sockets = new Set();
  const finish = code => {
    if (closing) return; closing = true;
    const deadline = setTimeout(() => process.exit(code || 1), 2500);
    for (const socket of sockets) socket.destroy();
    const exited = () => { clearTimeout(deadline); process.exit(code); };
    if (server) server.close(exited); else exited();
  };
  process.once('disconnect', () => finish(1));
  process.once('SIGTERM', () => finish(0));
  process.once('SIGINT', () => finish(1));
  process.once('uncaughtException', () => finish(1));
  process.once('unhandledRejection', () => finish(1));
  process.on('message', message => {
    if (message && Object.keys(message).length === 1 && message.type === 'stop') finish(0);
    else finish(1);
  });
  setTimeout(() => finish(1), 600000).unref();
  const require = createRequire('/opt/fncp/server/dist/app.js');
  require('/opt/fncp/server/dist/src/auth/fncp-production-admission.js').assertFncpProductionAdmission(process.env);
  // Read readiness alone is insufficient: the application intentionally denies
  // votes until all fifteen actual bootstrap TIDs have been bound explicitly.
  const gateway = require('/opt/fncp/server/dist/src/auth/fncp-gateway.js').loadFncpGatewayConfig(process.env);
  if (!gateway.fixedStatementIds || gateway.fixedStatementIds.size !== 15) throw new Error('private voting configuration rejected');
  // The public-only image has the ordinary prompt assets under /app. Its .env
  // absence was checked above; no existing host configuration is mounted.
  const application = require('/opt/fncp/server/dist/app.js');
  await application.appReady;
  if (closing) return;
  server = createServer((req, res) => {
    if (closing || req.socket.remoteAddress !== '127.0.0.1' || req.headers.host !== '127.0.0.1:5500' ||
        !participantRouteAllowed(req.method, req.url)) {
      res.writeHead(404, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      res.end('{"error":"unavailable"}'); return;
    }
    application.default(req, res);
  });
  server.maxConnections = 32;
  server.requestTimeout = 12000; server.headersTimeout = 5000; server.keepAliveTimeout = 1000;
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  server.once('error', () => finish(1));
  await new Promise(resolveReady => server.listen({ host: '127.0.0.1', port: 5500, exclusive: true }, resolveReady));
  if (closing) return;
  process.send({ type: 'PARTICIPANT_CHILD_READY', loopbackPort: 5500, actualPolis: true });
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  run().catch(() => process.exit(1));
}
