/** Fixed-port loopback tests, run serially. These do NOT create a container or
 * change a hosts file/DNS/global trust. Every listener is newly test-owned;
 * failure to acquire 8444 is a test failure, never permission to stop its user.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, X509Certificate } from 'node:crypto';
import { request } from 'node:https';
import { createServer, connect } from 'node:net';
import { checkServerIdentity } from 'node:tls';
import { createBootstrapIssuer, claimBootstrapIssuerPublicJwks } from './bootstrap-issuer.mjs';
import { createBootstrapApiTrust, claimBootstrapApiTrust } from './bootstrap-api-trust.mjs';
import { createBootstrapJwksService, createBootstrapContainerJwksService } from './bootstrap-jwks-service.mjs';

const ERROR = 'Fresh public JWKS service rejected; private details withheld.';
const namespaceId = 'a'.repeat(24);
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const rejected = promise => assert.rejects(promise, error => error.message === ERROR && error.cause === undefined);
async function issuerFixture(t) {
  const issuer = await createBootstrapIssuer(); t.after(() => issuer.close()); return issuer;
}
async function fixture(t) {
  const issuer = await issuerFixture(t);
  const service = await createBootstrapContainerJwksService({ issuer, namespaceId });
  t.after(() => service.close()); return { issuer, service, config: service.configuration() };
}
async function independentlyRefused() {
  await new Promise((resolve, reject) => {
    const socket = connect({ host: '127.0.0.1', port: 8444 }); socket.setTimeout(500);
    socket.once('connect', () => { socket.destroy(); reject(new Error('Owned fixed listener remained reachable.')); });
    socket.once('timeout', () => { socket.destroy(); reject(new Error('Owned fixed listener refusal timed out.')); });
    socket.once('error', error => { socket.destroy(); error.code === 'ECONNREFUSED' ? resolve() : reject(error); });
  });
}
async function ownedOccupant(t) {
  let connections = 0; let bytesReceived = 0;
  const server = createServer(socket => {
    connections++; socket.on('data', bytes => { bytesReceived += bytes.length; }); socket.destroy();
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject); server.listen(8444, '127.0.0.1', resolve);
  });
  t.after(() => new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())));
  return { server, summary: () => ({ connections, bytesReceived }) };
}
async function localRequest(config, options = {}) {
  assert.equal(config.localAddress, '127.0.0.1'); assert.equal(config.localPort, 8444);
  return new Promise((resolve, reject) => {
    let req, response, settled = false;
    const finish = (error, value) => {
      if (settled) return; settled = true; clearTimeout(timer);
      if (error) { response?.destroy(); req?.destroy(); reject(error); } else resolve(value);
    };
    const timer = setTimeout(() => finish(new Error('Owned fixed TLS request timed out.')), 2000);
    req = request({ hostname: '127.0.0.1', port: 8444, servername: options.servername ?? config.hostname,
      ca: Object.hasOwn(options, 'ca') ? options.ca : config.certificatePem, rejectUnauthorized: true,
      minVersion: 'TLSv1.2', agent: false,
      checkServerIdentity(host, peer) {
        const error = checkServerIdentity(options.servername ?? config.hostname, peer);
        return error || (sha(peer.raw) !== config.certificateSha256 ? new Error('Owned fixed TLS leaf mismatch.') : undefined);
      },
      method: options.method ?? 'GET', path: options.path ?? '/.well-known/jwks.json',
      headers: { host: new URL(config.jwksUri).host, connection: 'close', ...options.headers },
    }, res => {
      response = res; const chunks = []; let size = 0;
      res.on('data', bytes => { size += bytes.length; if (size > 8192) finish(new Error('Owned public response bound exceeded.')); else chunks.push(bytes); });
      res.once('error', finish); res.once('aborted', () => finish(new Error('Owned public response aborted.')));
      res.once('end', () => finish(null, { status: res.statusCode, headers: res.headers, complete: res.complete,
        body: Buffer.concat(chunks).toString('utf8'), authorized: req.socket.authorized,
        peerSha256: sha(req.socket.getPeerCertificate().raw), protocol: req.socket.getProtocol() }));
    });
    req.once('error', finish); req.end(options.body);
  });
}

test('fixed role binds exactly loopback8444 while keeping DNS identity separate from reachability claims', async t => {
  const f = await fixture(t);
  assert.equal(f.config.localAddress, '127.0.0.1'); assert.equal(f.config.localPort, 8444);
  assert.equal(f.config.hostname, `fncp-fresh-jwks-${namespaceId}`);
  assert.equal(f.config.jwksUri, `https://${f.config.hostname}:8444/.well-known/jwks.json`);
  assert.equal(f.service.summary().mode, 'FIXED_LOOPBACK_JWKS_8444_ROLE_ONLY');
  for (const key of ['containerRoleImplemented', 'containerReachabilityVerified', 'runtimeOwnershipVerified',
    'productionReady', 'globalTrustChanged', 'tokenIssuanceImplemented']) assert.equal(f.service.summary()[key], false);
  const cert = new X509Certificate(f.config.certificatePem);
  assert.equal(cert.checkHost(f.config.hostname, { subject: 'never', wildcards: false }), f.config.hostname);
  assert.equal(cert.checkIP('127.0.0.1'), undefined); assert.equal(sha(cert.raw), f.config.certificateSha256);
});
test('actual pinned DNS-SAN TLS on fixed loopback serves the exact original verified public JWK bytes', async t => {
  const issuer = await issuerFixture(t); const apiTrust = await createBootstrapApiTrust({ issuer });
  const expectedKey = claimBootstrapApiTrust(apiTrust).publicJwk;
  const service = await createBootstrapContainerJwksService({ issuer, namespaceId }); t.after(() => service.close());
  const config = service.configuration(); const response = await localRequest(config);
  assert.equal(response.status, 200); assert.equal(response.complete, true); assert.equal(response.authorized, true);
  assert.equal(response.peerSha256, config.certificateSha256); assert.ok(['TLSv1.2', 'TLSv1.3'].includes(response.protocol));
  assert.equal(response.body, JSON.stringify({ keys: [expectedKey] }));
  assert.equal(issuer.summary().tokensIssued, 0); assert.equal(issuer.summary().clientFetches, 1);
  assert.equal(service.summary().publicHandoffs, 1); assert.equal(service.summary().servedRequests, 1);
});
test('bind collision neither probes nor stops the pre-existing test-owned occupant', async t => {
  const occupant = await ownedOccupant(t); const issuer = await issuerFixture(t);
  await rejected(createBootstrapContainerJwksService({ issuer, namespaceId }));
  assert.equal(occupant.server.listening, true); assert.deepEqual(occupant.summary(), { connections: 0, bytesReceived: 0 });
  assert.equal(issuer.summary().tokensIssued, 0); assert.equal(issuer.summary().closed, false);
  // An uncertain fixed-role attempt cannot consume another public claim or
  // retry after the collision, even though no foreign listener was touched.
  await rejected(createBootstrapContainerJwksService({ issuer, namespaceId }));
  assert.equal(issuer.summary().clientFetches, 1); assert.deepEqual(occupant.summary(), { connections: 0, bytesReceived: 0 });
});
test('invalid fields/selectors/proxies reject before any fixed bind or issuer claim', async t => {
  const occupant = await ownedOccupant(t); const issuer = await issuerFixture(t); let touched = 0;
  const getter = { issuer, get namespaceId() { touched++; throw new Error('private'); } };
  const proxy = new Proxy({}, { get() { touched++; }, ownKeys() { touched++; } });
  for (const options of [undefined, null, {}, getter, proxy,
    { issuer, namespaceId, port: 8444 }, { issuer, namespaceId, address: '127.0.0.1' },
    { issuer, namespaceId, certificatePem: 'private' }, { issuer, namespaceId, keyPath: '/not-read' },
    { issuer, namespaceId, factory: () => {} }, { issuer, namespaceId, [Symbol('hidden')]: true },
    { issuer, namespaceId: 'localhost' }, { issuer, namespaceId: 'A'.repeat(24) }])
    await rejected(createBootstrapContainerJwksService(options));
  await rejected(createBootstrapContainerJwksService({ issuer, namespaceId }, undefined));
  assert.equal(touched, 0); assert.equal(issuer.summary().clientFetches, 0);
  assert.deepEqual(occupant.summary(), { connections: 0, bytesReceived: 0 });
});
test('copied/fabricated issuer capabilities cannot supply a public key or trigger a fixed-port probe', async t => {
  const occupant = await ownedOccupant(t); const issuer = await issuerFixture(t); let touched = 0;
  for (const value of [{}, { ...issuer }, new Proxy(issuer, { get() { touched++; } }),
    { get fetchJwks() { touched++; }, issueToken() { touched++; } }])
    await rejected(createBootstrapContainerJwksService({ issuer: value, namespaceId }));
  assert.equal(touched, 0); assert.equal(issuer.summary().clientFetches, 0);
  assert.deepEqual(occupant.summary(), { connections: 0, bytesReceived: 0 });
});
test('wrong CA or wrong DNS identity is denied before any HTTP request is served', async t => {
  const f = await fixture(t); const unrelated = await issuerFixture(t);
  await assert.rejects(localRequest(f.config, { ca: unrelated.configuration().certificatePem }));
  await assert.rejects(localRequest(f.config, { servername: 'wrong.synthetic.invalid' }));
  assert.equal(f.service.summary().servedRequests, 0);
  const good = await localRequest(f.config); assert.equal(good.status, 200);
});
test('fixed role still enforces exact private host/path and denies browser credentials and body-bearing reads', async t => {
  const f = await fixture(t);
  for (const options of [
    { headers: { host: '127.0.0.1:8444' } }, { path: '/.well-known/jwks.json?x=1' },
    { path: '/.well-known/openid-configuration' }, { headers: { origin: 'https://foreign.invalid' } },
    { headers: { authorization: 'Bearer invented' } }, { headers: { cookie: 'invented=1' } },
    { headers: { 'content-length': '1' }, body: 'x' },
  ]) { const response = await localRequest(f.config, options); assert.equal(response.status, 403); assert.equal(response.body, '{}'); }
  assert.equal(f.service.summary().servedRequests, 0); assert.equal(f.service.summary().rejectedRequests, 7);
});
test('public reply has no cookies, redirect, CORS, signing material or bearer', async t => {
  const f = await fixture(t); const response = await localRequest(f.config);
  assert.equal(response.headers['content-type'], 'application/json'); assert.equal(response.headers['cache-control'], 'no-store');
  assert.equal(response.headers['x-content-type-options'], 'nosniff'); assert.equal(response.headers.location, undefined);
  assert.equal(response.headers['set-cookie'], undefined); assert.equal(response.headers['access-control-allow-origin'], undefined);
  assert.doesNotMatch(response.body, /PRIVATE KEY|"d"\s*:|"p"\s*:|access_token|refresh_token/u);
});
test('original issuer closure invalidates fixed role and independently refuses8444 without minting', async t => {
  const f = await fixture(t); await f.issuer.close();
  assert.throws(() => f.service.configuration(), { message: ERROR });
  await f.service.close(); await independentlyRefused();
  assert.equal(f.service.summary().closed, true); assert.equal(f.service.summary().listenersClosed, true);
  assert.equal(f.issuer.summary().tokensIssued, 0);
});
test('closing fixed role is idempotent and leaves the original issuer independently active', async t => {
  const f = await fixture(t); const first = f.service.close(); assert.equal(first, f.service.close());
  await first; await independentlyRefused(); assert.equal(f.issuer.summary().closed, false);
  assert.equal(f.service.summary().listenersClosed, true); assert.equal(f.service.summary().temporaryCertificateFilesRemoved, true);
  assert.throws(() => f.service.configuration(), { message: ERROR });
});
test('ephemeral and fixed factories share a single irreversible public role per original issuer', async t => {
  const issuer = await issuerFixture(t);
  const ephemeral = await createBootstrapJwksService({ issuer, namespaceId }); t.after(() => ephemeral.close());
  assert.equal(ephemeral.summary().mode, 'PUBLIC_JWKS_LOOPBACK_PRIMITIVE_ONLY');
  assert.notEqual(ephemeral.configuration().localPort, 8444);
  await rejected(createBootstrapContainerJwksService({ issuer, namespaceId }));
  await ephemeral.close(); await rejected(createBootstrapContainerJwksService({ issuer, namespaceId }));
  assert.equal(issuer.summary().clientFetches, 1);
});
test('a used fixed role cannot be converted into another ephemeral public service', async t => {
  const f = await fixture(t); await rejected(createBootstrapJwksService({ issuer: f.issuer, namespaceId }));
  await f.service.close(); await rejected(createBootstrapJwksService({ issuer: f.issuer, namespaceId }));
  await assert.rejects(claimBootstrapIssuerPublicJwks(f.issuer)); assert.equal(f.issuer.summary().clientFetches, 1);
});
test('fixed role summary remains aggregate-only and exact methods reject extra configuration arguments', async t => {
  const f = await fixture(t); const summary = f.service.summary();
  assert.ok(Object.isFrozen(summary)); assert.ok(Object.isFrozen(f.config));
  for (const value of [namespaceId, f.config.jwksUri, f.config.certificatePem, f.config.certificateSha256])
    assert.equal(JSON.stringify(summary).includes(value), false);
  assert.throws(() => f.service.configuration(undefined), { message: ERROR });
  assert.throws(() => f.service.summary(undefined), { message: ERROR });
  await rejected(f.service.close(undefined)); assert.equal((await localRequest(f.config)).status, 200);
});
