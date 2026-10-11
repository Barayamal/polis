/** Fresh in-memory models and owned ephemeral loopback listeners only. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, connect } from 'node:net';
import { createLocalAccess } from './access-server.mjs';
import { createLocalBrowser } from '../local-browser/browser-server.mjs';
import { createWordPressReceiver } from './wordpress-receiver.mjs';

const secret = 'invented_start_close_secret_'.repeat(3);
const forbidden = () => { throw new Error('No backend or ingestion operation permitted.'); };
const makers = [
  ['access', () => createLocalAccess({ mode: 'fixture-only', dbPath: ':memory:', adminSecret: secret,
    conversationId: '9syntheticStartupRound', provider: { allowlist: forbidden, participate: forbidden } }), 'Local service is closing.'],
  ['browser', () => createLocalBrowser({ mode: 'fixture-only', backend: { request: forbidden } }), 'Local service is closing.'],
  ['receiver', () => createWordPressReceiver({ mode: 'fixture-only', secret, ingest: forbidden }), 'Local receiver closing.'],
];
const turn = () => new Promise(resolve => setImmediate(resolve));
async function probe(t, port = 0) {
  const server = createServer(socket => socket.end());
  t.after(() => new Promise(resolve => server.close(resolve)));
  await new Promise((resolve, reject) => {
    server.once('error', reject); server.listen(port, '127.0.0.1', resolve);
  });
  return { port: server.address().port, close: () => new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())) };
}
async function refused(port) {
  await new Promise((resolve, reject) => {
    const socket = connect({ host: '127.0.0.1', port });
    socket.setTimeout(1000);
    socket.once('connect', () => { socket.destroy(); reject(new Error('Closed listener reappeared.')); });
    socket.once('timeout', () => { socket.destroy(); reject(new Error('Listener check timed out.')); });
    socket.once('error', error => { socket.destroy(); error.code === 'ECONNREFUSED' ? resolve() : reject(error); });
  });
}

for (const [name, make, closingMessage] of makers) {
  test(`${name} immediate close rejects pending listen and releases the exact port`, { timeout: 5000 }, async t => {
    const reservation = await probe(t); const { port } = reservation; await reservation.close();
    const app = make(); t.after(() => app.close());
    // Do not await listen: native close may suppress its listening callback.
    const started = app.listen(port);
    const rejection = assert.rejects(started, { message: closingMessage });
    const closing = app.close(); assert.equal(app.close(), closing);
    await Promise.all([rejection, closing]);
    assert.equal(app.close(), closing);
    await turn(); await turn(); await refused(port);
    // Independent reclamation proves that neither startup nor shutdown left a
    // hidden listener. A new instance is required; this one cannot resurrect.
    const rebound = await probe(t, port); assert.equal(rebound.port, port);
    await assert.rejects(app.listen(port), { message: closingMessage });
  });

  test(`${name} concurrent listen rejects without stranding or replacing the first startup`, { timeout: 5000 }, async t => {
    const app = make(); t.after(() => app.close());
    const first = app.listen(0);
    await assert.rejects(app.listen(0), { message: 'Local service is already starting or listening.' });
    const origin = await first; const port = Number(new URL(origin).port);
    assert.ok(port > 0);
    await assert.rejects(app.listen(0), { message: 'Local service is already starting or listening.' });
    await app.close(); await refused(port);
  });

  test(`${name} repeated bind failure removes startup handlers and allows a later valid listen`, { timeout: 5000 }, async t => {
    const occupied = await probe(t); const app = make(); t.after(() => app.close());
    const warnings = [];
    const warned = warning => {
      if (warning.name === 'MaxListenersExceededWarning' && ['error', 'listening'].includes(warning.type)) warnings.push(warning);
    };
    process.on('warning', warned); t.after(() => process.off('warning', warned));
    for (let attempt = 0; attempt < 12; attempt++) await assert.rejects(app.listen(occupied.port), { code: 'EADDRINUSE' });
    await turn(); assert.deepEqual(warnings, []);
    const origin = await app.listen(0); const port = Number(new URL(origin).port);
    assert.ok(port > 0); assert.notEqual(port, occupied.port);
    await app.close(); await refused(port);
  });

  test(`${name} invalid ports reject before startup without poisoning the instance`, { timeout: 5000 }, async t => {
    const app = make(); t.after(() => app.close());
    for (const port of [-1, 65536, NaN, Infinity, 1.5, '0', null, '/synthetic-never-create.sock']) {
      await assert.rejects(app.listen(port), { message: 'Invalid local port.' });
    }
    const origin = await app.listen(0); const port = Number(new URL(origin).port);
    await app.close(); await refused(port);
  });
}
