// Internal socket mechanism. Public production and test constructors validate
// and brand their own disjoint policies before reaching this implementation.
import { createServer, connect } from 'node:net';
import { Transform } from 'node:stream';

const deny = () => new Error('OIDC relay unavailable.');
const MAX_CONCURRENT = 32;
const MAX_BYTES = 131_072;
export function createRelayRuntime({ policy, listenHost, timeoutMs = 5000 }) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 5000) throw deny();
  const active = new Set(), servers = new Map(), pendingStarts = new Set();
  const counts = { accepted: 0, completed: 0, rejected: 0, expired: 0, byteLimit: 0 };
  let phase = 'NEW', closePromise;
  function serve(route, incoming) {
    if (phase !== 'RUNNING' || active.size >= MAX_CONCURRENT) { counts.rejected++; incoming.destroy(); return; }
    incoming.setNoDelay(true);
    const outgoing = connect({ host: route.targetAddress, port: route.targetPort,
      family: route.targetAddress.includes(':') ? 6 : 4 });
    outgoing.setNoDelay(true);
    const record = { incoming, outgoing, timer: null, done: false, filters: [] };
    active.add(record); counts.accepted++;
    const finish = reason => {
      if (record.done) return; record.done = true; clearTimeout(record.timer); active.delete(record);
      if (reason === 'expired') counts.expired++; else if (reason === 'bytes') counts.byteLimit++;
      else if (reason === 'complete') counts.completed++;
      incoming.destroy(); outgoing.destroy(); for (const filter of record.filters) filter.destroy();
    };
    record.stop = () => finish('closed');
    record.timer = setTimeout(() => finish('expired'), timeoutMs);
    const bounded = () => {
      let bytes = 0;
      const filter = new Transform({ highWaterMark: 16_384, transform(chunk, encoding, callback) {
        bytes += chunk.length;
        if (bytes > MAX_BYTES || record.done) { finish('bytes'); callback(deny()); return; }
        callback(null, chunk);
      } });
      filter.on('error', () => finish('error')); record.filters.push(filter); return filter;
    };
    incoming.on('error', () => finish('error')); outgoing.on('error', () => finish('error'));
    incoming.on('close', () => finish('complete')); outgoing.on('close', () => finish('complete'));
    incoming.pipe(bounded()).pipe(outgoing); outgoing.pipe(bounded()).pipe(incoming);
  }
  async function start() {
    if (phase !== 'NEW') throw deny(); phase = 'STARTING';
    try {
      const listeners = {};
      for (const [name, route] of Object.entries(policy.routes)) {
        if (phase !== 'STARTING') throw deny();
        const server = createServer(socket => serve(route, socket)); servers.set(name, server);
        server.on('error', () => { if (phase === 'RUNNING') void close(); });
        const opening = new Promise((resolve, reject) => {
          const failed = () => { server.off('listening', ready); reject(deny()); };
          const ready = () => { server.off('error', failed); resolve(); };
          server.once('error', failed); server.once('listening', ready);
          server.listen({ host: listenHost, port: route.listenPort, exclusive: true });
        });
        pendingStarts.add(opening);
        try { await opening; } finally { pendingStarts.delete(opening); }
        const address = server.address();
        if (!address || typeof address === 'string') throw deny();
        listeners[name] = Object.freeze({ host: address.address, port: address.port });
      }
      if (phase !== 'STARTING') throw deny(); phase = 'RUNNING';
      return Object.freeze({ profile: policy.profile, policySha256: policy.policySha256,
        listeners: Object.freeze(listeners) });
    } catch { await close(); throw deny(); }
  }
  async function close() {
    if (closePromise) return closePromise; phase = 'CLOSING';
    closePromise = (async () => {
      for (const record of [...active]) record.stop();
      // A close during asynchronous bind must also close the listener after
      // that bind settles, rather than returning with a late open socket.
      await Promise.allSettled([...pendingStarts]);
      await Promise.all([...servers.values()].map(server => new Promise(resolve => {
        if (!server.listening) { resolve(); return; }
        server.close(() => resolve());
      })));
      phase = 'CLOSED'; return Object.freeze({ closed: true, activeConnections: active.size });
    })(); return closePromise;
  }
  return Object.freeze({ start, close, snapshot() { return Object.freeze({ phase,
    activeConnections: active.size, openListeners: [...servers.values()].filter(server => server.listening).length,
    ...counts }); } });
}
