import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer, connect } from 'node:net';
import { once } from 'node:events';
import { createSyntheticEgressPolicy, createSyntheticFixedOidcRelay } from './test-support/synthetic-relay.mjs';

async function until(predicate, timeout = 1500) {
  const end = Date.now() + timeout;
  while (!predicate()) { if (Date.now() >= end) throw new Error('Fixture deadline exceeded');
    await new Promise(resolve => setTimeout(resolve, 5)); }
}
async function upstream(t, echo = true, unsolicitedBytes = 0) {
  const sockets = new Set(), counts = { connections: 0, bytes: 0 };
  const server = createServer(socket => { sockets.add(socket); counts.connections++;
    socket.on('close', () => sockets.delete(socket)); socket.on('error', () => {});
    socket.on('data', data => { counts.bytes += data.length; if (echo) socket.write(data); });
    if (unsolicitedBytes) socket.write(Buffer.alloc(unsolicitedBytes, 23));
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); });
  return { port: server.address().port, counts, server };
}
async function fixture(t, { echo = true, timeoutMs = 1000, replyBytes = 0 } = {}) {
  const token = await upstream(t, echo, replyBytes), jwks = await upstream(t, echo);
  const policy = createSyntheticEgressPolicy({ tokenEndpoint: 'https://localhost:' + token.port + '/token',
    jwksUri: 'https://localhost:' + jwks.port + '/jwks', targets: {
      token: { address: '127.0.0.1', port: token.port }, jwks: { address: '127.0.0.1', port: jwks.port } } });
  const relay = createSyntheticFixedOidcRelay({ policy, listenHost: '127.0.0.1', timeoutMs });
  t.after(() => relay.close()); const result = await relay.start(); return { relay, policy, ...result, token, jwks };
}
async function client(t, listener) {
  const socket = connect(listener.port, listener.host); socket.on('error', () => {});
  t.after(() => socket.destroy()); await once(socket, 'connect'); return socket;
}
const socketClosed = socket => socket.destroyed ? Promise.resolve()
  : new Promise(resolve => socket.once('close', resolve));
test('opaque relay forwards binary bytes unchanged only to each preconfigured target', async t => {
  const f = await fixture(t), token = await client(t, f.listeners.token), jwks = await client(t, f.listeners.jwks);
  const payload = Buffer.from([0, 255, 22, 3, 3, 1, 2, 3, 0]);
  const received = once(token, 'data'); token.write(payload); assert.deepEqual((await received)[0], payload);
  const data = once(jwks, 'data'); jwks.write('JWKS fixed route'); assert.equal((await data)[0].toString(), 'JWKS fixed route');
  assert.equal(f.token.counts.connections, 1); assert.equal(f.jwks.counts.connections, 1);
  assert.equal(f.relay.snapshot().activeConnections, 2);
  assert.deepEqual(Object.keys(f.relay.snapshot()).sort(), ['accepted','activeConnections','byteLimit','completed','expired','openListeners','phase','rejected']);
});
test('CONNECT-looking bytes do not select any destination or change the fixed route', async t => {
  const f = await fixture(t), socket = await client(t, f.listeners.token);
  const payload = 'CONNECT unapproved.example:443 HTTP/1.1\r\nHost: unapproved.example\r\n\r\n';
  const response = once(socket, 'data'); socket.write(payload);
  assert.equal((await response)[0].toString(), payload);
  assert.equal(f.token.counts.connections, 1); assert.equal(f.jwks.counts.connections, 0);
});
test('absolute deadline terminates idle and continuously active connections', async t => {
  const f = await fixture(t, { echo: false, timeoutMs: 100 }), socket = await client(t, f.listeners.token);
  const writing = setInterval(() => socket.write('x'), 10); t.after(() => clearInterval(writing));
  await socketClosed(socket); clearInterval(writing);
  assert.equal(f.relay.snapshot().expired, 1); assert.equal(f.relay.snapshot().activeConnections, 0);
});
test('byte ceiling drops an oversized request before forwarding the excess chunk', async t => {
  const f = await fixture(t, { echo: false }), socket = await client(t, f.listeners.token);
  socket.write(Buffer.alloc(131_073, 42)); await socketClosed(socket);
  assert.equal(f.relay.snapshot().byteLimit, 1); assert.ok(f.token.counts.bytes <= 131_072);
  assert.equal(f.relay.snapshot().activeConnections, 0);
});
test('independent response byte ceiling drops an oversized upstream response', async t => {
  const f = await fixture(t, { echo: false, replyBytes: 262_144 }), socket = await client(t, f.listeners.token);
  let bytes = 0; socket.on('data', chunk => { bytes += chunk.length; }); await socketClosed(socket);
  assert.equal(f.relay.snapshot().byteLimit, 1); assert.ok(bytes <= 131_072);
  assert.equal(f.relay.snapshot().activeConnections, 0);
});
test('upstream refusal closes the admitted route without retry or alternate target', async t => {
  const f = await fixture(t); await new Promise(resolve => f.token.server.close(resolve));
  const socket = await client(t, f.listeners.token); await socketClosed(socket);
  assert.equal(f.token.counts.connections, 0); assert.equal(f.jwks.counts.connections, 0);
  assert.equal(f.relay.snapshot().accepted, 1); assert.equal(f.relay.snapshot().activeConnections, 0);
  assert.equal(f.relay.snapshot().phase, 'RUNNING');
});
test('client abort drains its target connection without leaking an active record', async t => {
  const f = await fixture(t), socket = await client(t, f.listeners.token);
  await until(() => f.token.counts.connections === 1); socket.destroy();
  await until(() => f.relay.snapshot().activeConnections === 0);
  assert.equal(f.token.counts.connections, 1);
});
test('concurrency capacity denies the 33rd connection before opening its target socket', async t => {
  const f = await fixture(t, { echo: false, timeoutMs: 5000 });
  const clients = await Promise.all(Array.from({ length: 32 }, () => client(t, f.listeners.token)));
  await until(() => f.token.counts.connections === 32);
  const extra = await client(t, f.listeners.token); await until(() => extra.destroyed);
  assert.equal(f.relay.snapshot().rejected, 1); assert.equal(f.token.counts.connections, 32);
  assert.equal(f.relay.snapshot().activeConnections, 32);
  await f.relay.close(); assert.ok(clients.every(socket => socket.destroyed || socket.readyState !== 'open')
    || f.relay.snapshot().activeConnections === 0);
});
test('close drains listeners and sockets permanently; stopped listeners refuse connections', async t => {
  const f = await fixture(t, { echo: false }), socket = await client(t, f.listeners.token);
  const closed = socketClosed(socket); assert.deepEqual(await f.relay.close(), { closed: true, activeConnections: 0 });
  await closed; assert.equal(f.relay.snapshot().openListeners, 0); assert.equal(f.relay.snapshot().phase, 'CLOSED');
  await assert.rejects(f.relay.start(), { message: 'OIDC relay unavailable.' });
  const attempted = connect(f.listeners.token.port, f.listeners.token.host);
  t.after(() => attempted.destroy()); const [error] = await once(attempted, 'error'); assert.equal(error.code, 'ECONNREFUSED');
});
test('close during initial bind cannot leave a late listener open', async t => {
  const token = await upstream(t), policy = createSyntheticEgressPolicy({ tokenEndpoint: 'https://localhost:' + token.port + '/token',
    jwksUri: 'https://localhost:' + token.port + '/jwks', targets: {
      token: { address: '127.0.0.1', port: token.port }, jwks: { address: '127.0.0.1', port: token.port } } });
  const relay = createSyntheticFixedOidcRelay({ policy, listenHost: '127.0.0.1' }); t.after(() => relay.close());
  const starting = assert.rejects(relay.start(), { message: 'OIDC relay unavailable.' });
  await relay.close(); await starting;
  assert.equal(relay.snapshot().openListeners, 0); assert.equal(relay.snapshot().phase, 'CLOSED');
});
