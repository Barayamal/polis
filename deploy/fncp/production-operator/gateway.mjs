import { createConnection, createServer } from 'node:net';

export const PROFILE = 'FNCP_OPERATOR_LOOPBACK_GATEWAY_V1';
const fail = () => new Error('Operator loopback gateway rejected.');
const integer = value => Number.isSafeInteger(value) && value > 0 && value <= 65535;

function validate(listeners) {
  if (!Array.isArray(listeners) || listeners.length !== 2) throw fail();
  const allowed = new Set(['8443:edge:8443', '9443:wordpress:8443']);
  for (const item of listeners) {
    if (item === null || typeof item !== 'object' || Array.isArray(item)
      || Reflect.ownKeys(item).some(key => !['listenHost', 'listenPort', 'upstreamHost', 'upstreamPort'].includes(key))
      || item.listenHost !== '0.0.0.0' || !integer(item.listenPort) || !integer(item.upstreamPort)
      || !/^[a-z][a-z0-9-]{0,62}$/u.test(item.upstreamHost)
      || !allowed.delete(`${item.listenPort}:${item.upstreamHost}:${item.upstreamPort}`)) throw fail();
  }
  if (allowed.size) throw fail();
  return listeners.map(item => Object.freeze({ ...item }));
}

/** Fixed, TLS-transparent operator bridge. It receives only the two Compose
 * loopback-published ports and forwards opaque bytes to the isolated HTTPS
 * services. It holds no certificates, cookies, participant data or authority.
 */
export function createOperatorLoopbackGateway({ listeners, connect = createConnection,
  listen = (server, item) => new Promise((resolve, reject) => {
    const error = () => reject(fail()); server.once('error', error);
    server.listen(item.listenPort, item.listenHost, () => { server.off('error', error); resolve(); });
  }) } = {}) {
  const plan = validate(listeners);
  if (typeof connect !== 'function' || typeof listen !== 'function') throw fail();
  const servers = [], sockets = new Set(); let phase = 'CREATED';
  const closeSocket = socket => { sockets.delete(socket); socket.destroy(); };
  for (const item of plan) {
    let active = 0;
    const server = createServer(incoming => {
      if (phase !== 'RUNNING' || active >= 32) { incoming.destroy(); return; }
      active += 1; sockets.add(incoming); incoming.setTimeout(60_000);
      const upstream = connect({ host: item.upstreamHost, port: item.upstreamPort });
      sockets.add(upstream); upstream.setTimeout(60_000);
      let settled = false, closed = 0;
      const cleanup = () => {
        if (!settled) { settled = true; active -= 1; }
        sockets.delete(incoming); sockets.delete(upstream);
      };
      const finish = () => { if (++closed === 2) cleanup(); };
      const abort = () => { cleanup(); closeSocket(incoming); closeSocket(upstream); };
      incoming.once('close', finish); incoming.once('error', abort); incoming.once('timeout', abort);
      upstream.once('close', finish); upstream.once('error', abort); upstream.once('timeout', abort);
      incoming.pipe(upstream); upstream.pipe(incoming);
    });
    server.on('error', () => { if (phase === 'RUNNING') void close(); });
    servers.push({ server, item });
  }
  const close = async () => {
    if (phase === 'CLOSED') return { profile: PROFILE, listenerClosed: true };
    phase = 'CLOSED'; for (const socket of sockets) socket.destroy(); sockets.clear();
    await Promise.all(servers.map(({ server }) => new Promise(resolve => server.close(() => resolve()))));
    return { profile: PROFILE, listenerClosed: true };
  };
  return Object.freeze({
    async start() {
      if (phase !== 'CREATED') throw fail(); phase = 'RUNNING';
      try {
        await Promise.all(servers.map(({ server, item }) => listen(server, item)));
      } catch { await close(); throw fail(); }
      return Object.freeze({ profile: PROFILE, ready: true, listeners: plan.length });
    },
    close,
    snapshot: () => Object.freeze({ profile: PROFILE, phase, listeners: plan.length, openSockets: sockets.size }),
  });
}

export const CONTAINER_LISTENERS = Object.freeze([
  Object.freeze({ listenHost: '0.0.0.0', listenPort: 8443, upstreamHost: 'edge', upstreamPort: 8443 }),
  Object.freeze({ listenHost: '0.0.0.0', listenPort: 9443, upstreamHost: 'wordpress', upstreamPort: 8443 }),
]);
