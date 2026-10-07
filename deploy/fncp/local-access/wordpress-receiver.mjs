import { createServer } from 'node:http';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { validEvent } from './wordpress-events.mjs';

export const MAX_RECEIVER_REQUESTS = 32;

export function createWordPressReceiver({ mode, secret, ingest, now = Date.now }) {
  if (mode !== 'fixture-only' || !/^[A-Za-z0-9_-]{32,512}$/u.test(secret) || typeof ingest !== 'function' || typeof now !== 'function') throw new Error('Invalid synthetic receiver configuration.');
  let pendingRequests = 0; let closing = false; let closePromise; let releaseDrain; let cancelListen;
  const fresh = (stamp) => {
    try {
      const time = now();
      return Number.isSafeInteger(time) && time >= 0 && Math.abs(Math.floor(time / 1000) - Number(stamp)) <= 300;
    } catch { return false; }
  };
  const server = createServer(async (req, res) => {
    res.setHeader('Cache-Control', 'no-store'); res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    let admitted = false; let ingestStarted = false;
    const reply = (status, value) => {
      if (res.destroyed || res.writableEnded) return;
      if (res.headersSent) { res.destroy(); return; }
      const body = JSON.stringify(value); // Serialize before committing headers.
      if (closing || !req.complete) res.setHeader('Connection', 'close');
      res.writeHead(status); res.end(body);
    };
    try {
      if (closing) return reply(503, { error: 'Local receiver closing.' });
      if (pendingRequests >= MAX_RECEIVER_REQUESTS) return reply(503, { error: 'Local request capacity reached.' });
      pendingRequests += 1; admitted = true; // Readers and unsettled ingests share this bound.
      if (req.socket.remoteAddress !== '127.0.0.1' || req.headers.host !== `127.0.0.1:${server.address().port}` ||
        req.method !== 'POST' || req.url !== '/internal/wordpress/events' || req.headers.origin || req.headers.cookie ||
        req.headers['sec-fetch-site'] || req.headers.authorization) return reply(403, { error: 'Signed local events only.' });
      if (req.headers['content-type'] !== 'application/json') return reply(415, { error: 'JSON required.' });
      const stamp = req.headers['x-fncp-wp-timestamp']; const signature = req.headers['x-fncp-wp-signature'];
      if (typeof stamp !== 'string' || !/^[0-9]{10}$/u.test(stamp) || !fresh(stamp) ||
        typeof signature !== 'string' || !/^sha256=[0-9a-f]{64}$/u.test(signature)) return reply(401, { error: 'Signature required.' });
      let size = 0; const chunks = [];
      for await (const chunk of req) { size += chunk.length; if (size > 4096) return reply(413, { error: 'Event too large.' }); chunks.push(chunk); }
      const raw = Buffer.concat(chunks);
      const expected = 'sha256=' + createHmac('sha256', secret).update(stamp + '.').update(raw).digest('hex');
      if (!timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return reply(401, { error: 'Invalid signature.' });
      let event; try { event = JSON.parse(raw.toString('utf8')); } catch { return reply(400, { error: 'Invalid JSON.' }); }
      if (!validEvent(event) || req.headers['x-fncp-wp-event-id'] !== event.event_id) return reply(400, { error: 'Invalid synthetic event.' });
      if (!req.complete || req.aborted || res.destroyed) return reply(400, { error: 'Complete event body required.' });
      // Headers may have been fresh before a slow body arrived. Never start an
      // ingest with an expired signature or an invalid/failed clock.
      if (!fresh(stamp)) return reply(401, { error: 'Signature required.' });
      ingestStarted = true;
      return reply(200, await ingest(event));
    } catch (error) {
      reply([400, 403, 409].includes(error?.status) ? error.status : 503, { error: ingestStarted
        ? 'Synthetic event outcome unconfirmed; retain and retry the same event.'
        : 'Synthetic event not applied; retain and retry the same event.' });
    } finally {
      if (admitted) pendingRequests -= 1;
      if (closing && pendingRequests === 0) releaseDrain?.();
    }
  });
  server.requestTimeout = 12000; server.headersTimeout = 5000;
  return {
    async listen(port = 8101) {
      if (closing) throw new Error('Local receiver closing.');
      if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('Invalid local port.');
      if (cancelListen || server.listening) throw new Error('Local service is already starting or listening.');
      return new Promise((resolve, reject) => {
        let settled = false;
        const settle = (error) => {
          if (settled) return;
          settled = true; cancelListen = undefined;
          server.off('error', onError); server.off('listening', onListening);
          if (error) reject(error);
          else resolve(`http://127.0.0.1:${server.address().port}`);
        };
        const onError = (error) => settle(error);
        const onListening = () => settle();
        // Native close can suppress the listening callback. Settle our caller
        // explicitly, and detach both listeners on every completion path.
        cancelListen = () => settle(new Error('Local receiver closing.'));
        server.once('error', onError); server.once('listening', onListening);
        try { server.listen(port, '127.0.0.1'); } catch (error) { settle(error); }
      });
    },
    close() {
      if (!closePromise) {
        closing = true;
        cancelListen?.();
        // Disconnect is not cancellation of an ingest. Drain admitted work even
        // after its HTTP peer has gone; never reopen this receiver instance.
        const drained = pendingRequests === 0 ? Promise.resolve() : new Promise(resolve => { releaseDrain = resolve; });
        const socketClosed = new Promise((resolve, reject) => server.close(error => {
          if (error && error.code !== 'ERR_SERVER_NOT_RUNNING') reject(error);
          else resolve();
        }));
        closePromise = Promise.all([drained, socketClosed]);
      }
      return closePromise;
    },
  };
}
