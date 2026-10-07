import test from 'node:test';
import assert from 'node:assert/strict';
import { createConnection, createServer } from 'node:net';
import { CONTAINER_LISTENERS, PROFILE, createOperatorLoopbackGateway } from './gateway.mjs';

const denied = { message: 'Operator loopback gateway rejected.' };
test('container plan is exactly the two TLS-transparent routes', () => {
  assert.deepEqual(CONTAINER_LISTENERS, [
    { listenHost: '0.0.0.0', listenPort: 8443, upstreamHost: 'edge', upstreamPort: 8443 },
    { listenHost: '0.0.0.0', listenPort: 9443, upstreamHost: 'wordpress', upstreamPort: 8443 },
  ]);
  for (const edit of [
    x => x.pop(), x => x.push(structuredClone(x[0])), x => { x[0].listenHost = '127.0.0.1'; },
    x => { x[0].listenPort = 443; }, x => { x[0].upstreamHost = 'api'; }, x => { x[1].upstreamPort = 443; },
    x => { x[0].extra = true; },
  ]) { const plan = structuredClone(CONTAINER_LISTENERS); edit(plan); assert.throws(() => createOperatorLoopbackGateway({ listeners: plan }), denied); }
});

test('gateway forwards opaque bytes on both fixed routes and closes all custody', async t => {
  const upstreams = new Map(), upstreamSockets = new Set();
  for (const name of ['edge', 'wordpress']) {
    const server = createServer(socket => { upstreamSockets.add(socket); socket.once('close', () => upstreamSockets.delete(socket)); socket.pipe(socket); });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    upstreams.set(name, { server, port: server.address().port });
  }
  t.after(() => { for (const socket of upstreamSockets) socket.destroy(); for (const { server } of upstreams.values()) server.close(); });
  const ports = new Map();
  const gateway = createOperatorLoopbackGateway({ listeners: CONTAINER_LISTENERS,
    connect: ({ host }) => createConnection(upstreams.get(host).port, '127.0.0.1'),
    listen: (server, item) => new Promise((resolve, reject) => {
      server.once('error', reject); server.listen(0, '127.0.0.1', () => { ports.set(item.listenPort, server.address().port); resolve(); });
    }) });
  await gateway.start();
  for (const [fixed, actual] of ports) {
    const socket = createConnection(actual, '127.0.0.1');
    await new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject); });
    const received = new Promise((resolve, reject) => { socket.once('data', resolve); socket.once('error', reject); });
    socket.write(Buffer.from(`opaque-${fixed}`));
    assert.equal((await received).toString(), `opaque-${fixed}`);
    socket.destroy();
  }
  assert.equal(gateway.snapshot().phase, 'RUNNING');
  await gateway.close();
  assert.deepEqual(gateway.snapshot(), { profile: PROFILE, phase: 'CLOSED', listeners: 2, openSockets: 0 });
});

test('production gateway can start and close when fixed ports are available', async t => {
  // This test deliberately avoids calling start: CI hosts may legitimately use
  // the operator ports. Lifecycle and byte forwarding are proven in the image
  // rehearsal where the fixed Compose listeners are isolated and owned.
  const gateway = createOperatorLoopbackGateway({ listeners: CONTAINER_LISTENERS });
  t.after(() => gateway.close());
  assert.deepEqual(gateway.snapshot(), { profile: PROFILE, phase: 'CREATED', listeners: 2, openSockets: 0 });
  assert.deepEqual(await gateway.close(), { profile: PROFILE, listenerClosed: true });
});
