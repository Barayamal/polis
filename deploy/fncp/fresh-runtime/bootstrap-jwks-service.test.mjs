import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, X509Certificate } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { request } from 'node:https';
import { createRequire } from 'node:module';
import { connect } from 'node:net';
import { checkServerIdentity } from 'node:tls';
import { pathToFileURL } from 'node:url';
import { createBootstrapIssuer, claimBootstrapIssuerPublicJwks, claimBootstrapIssuerForTransport } from './bootstrap-issuer.mjs';
import { createBootstrapJwksService } from './bootstrap-jwks-service.mjs';

const identityRequire = createRequire(new URL('../identity-foundation/package.json', import.meta.url));
const { createLocalJWKSet, decodeJwt, jwtVerify } = await import(pathToFileURL(identityRequire.resolve('jose')).href);
const SERVICE = 'Fresh public JWKS service rejected; private details withheld.';
const ISSUER = 'Local synthetic bootstrap issuer rejected; private details withheld.';
const namespaceId = 'a'.repeat(24);
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const rejected = promise => assert.rejects(promise, error => error.message === SERVICE && error.cause === undefined);
const issuerRejected = promise => assert.rejects(promise, error => error.message === ISSUER && error.cause === undefined);
async function issuerFixture(t) {
  const issuer = await createBootstrapIssuer(); t.after(() => issuer.close()); return issuer;
}
async function fixture(t, id = namespaceId) {
  const issuer = await issuerFixture(t);
  const service = await createBootstrapJwksService({ issuer, namespaceId: id });
  t.after(() => service.close()); return { issuer, service, config: service.configuration() };
}
async function refused(port) {
  await new Promise((resolve, reject) => {
    const socket = connect({ host: '127.0.0.1', port }); socket.setTimeout(500);
    socket.once('connect', () => { socket.destroy(); reject(new Error('Test-owned listener remained open.')); });
    socket.once('timeout', () => { socket.destroy(); reject(new Error('Test-owned refusal check timed out.')); });
    socket.once('error', error => { socket.destroy(); error.code === 'ECONNREFUSED' ? resolve() : reject(error); });
  });
}
// Only the capability's newly owned literal-loopback port can be contacted.
// Fixed DNS identity is still checked with SNI + standard SAN + exact leaf pin;
// this is not evidence that Docker DNS, the fixed container port or routing work.
async function localRequest(config, options = {}) {
  assert.equal(config.localAddress, '127.0.0.1'); assert.ok(config.localPort > 1023 && config.localPort <= 65535);
  return new Promise((resolve, reject) => {
    let req; let response; let done = false;
    const finish = (error, value) => {
      if (done) return; done = true; clearTimeout(timer);
      if (error) { response?.destroy(); req?.destroy(); reject(error); } else resolve(value);
    };
    const timer = setTimeout(() => finish(new Error('Bounded local TLS test timed out.')), 2000);
    req = request({ hostname: '127.0.0.1', port: config.localPort,
      servername: options.servername ?? config.hostname,
      ca: Object.hasOwn(options, 'ca') ? options.ca : config.certificatePem,
      rejectUnauthorized: true, minVersion: 'TLSv1.2', agent: false,
      checkServerIdentity(host, peer) {
        const error = checkServerIdentity(options.servername ?? config.hostname, peer);
        return error || (digest(peer.raw) !== config.certificateSha256 ? new Error('Test leaf mismatch.') : undefined);
      },
      method: options.method ?? 'GET', path: options.path ?? '/.well-known/jwks.json',
      headers: { host: new URL(config.jwksUri).host, connection: 'close', ...options.headers },
    }, res => {
      response = res; const chunks = []; let size = 0;
      res.on('data', bytes => { size += bytes.length; if (size > 8192) finish(new Error('Test response exceeded bound.')); else chunks.push(Buffer.from(bytes)); });
      res.once('error', error => finish(error)); res.once('aborted', () => finish(new Error('Test response aborted.')));
      res.once('end', () => finish(null, { status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8'),
        authorized: req.socket.authorized, protocol: req.socket.getProtocol() }));
    });
    req.once('error', error => finish(error)); req.end(options.body);
  });
}

test('public handoff rejects fabricated/copied/proxy issuers without touching methods or minting', async t => {
  const issuer = await issuerFixture(t); let reads = 0;
  const lookalike = { get fetchJwks() { reads++; throw new Error('private'); } };
  for (const value of [undefined, null, {}, lookalike, { ...issuer }, new Proxy(issuer, { get() { reads++; } })]) {
    await issuerRejected(claimBootstrapIssuerPublicJwks(value));
  }
  await issuerRejected(claimBootstrapIssuerPublicJwks(issuer, undefined));
  assert.equal(reads, 0); assert.equal(issuer.summary().tokensIssued, 0); assert.equal(issuer.summary().clientFetches, 0);
});
test('one-shot public handoff contains only public text/activity and uses the original verified fetch', async t => {
  const issuer = await issuerFixture(t); const handoff = await claimBootstrapIssuerPublicJwks(issuer);
  assert.deepEqual(Object.keys(handoff), ['publicJwksText', 'signal', 'assertActive']);
  assert.equal(Object.isFrozen(handoff), true); assert.equal(handoff.signal.aborted, false);
  assert.equal(handoff.assertActive(), undefined); assert.throws(() => handoff.assertActive(undefined));
  assert.equal(issuer.summary().tokensIssued, 0); assert.equal(issuer.summary().verifiedTlsFetches, 1);
  assert.ok(Buffer.byteLength(handoff.publicJwksText) <= 8192);
  assert.deepEqual(Object.keys(JSON.parse(handoff.publicJwksText).keys[0]), ['kty', 'n', 'e', 'kid', 'use', 'alg']);
  assert.doesNotMatch(handoff.publicJwksText, /PRIVATE KEY|"d"\s*:|token|bearer/iu);
  await issuerRejected(claimBootstrapIssuerPublicJwks(issuer));
  await issuer.close(); assert.equal(handoff.signal.aborted, true); assert.throws(() => handoff.assertActive());
});
test('public handoff does not consume or reset the independent single-token authority', async t => {
  const issuer = await issuerFixture(t); const handoff = await claimBootstrapIssuerPublicJwks(issuer);
  const privateHandoff = claimBootstrapIssuerForTransport(issuer);
  assert.equal(typeof privateHandoff.token, 'string'); assert.equal(issuer.summary().tokensIssued, 1);
  assert.throws(() => issuer.issueToken()); await issuerRejected(claimBootstrapIssuerPublicJwks(issuer));
  assert.equal(JSON.parse(handoff.publicJwksText).keys.length, 1);
});
test('uncertain public fetch/closure consumes its cap and never recreates the issuer', async t => {
  const issuer = await issuerFixture(t);
  const pending = issuerRejected(claimBootstrapIssuerPublicJwks(issuer));
  await issuer.close(); await pending;
  await issuerRejected(claimBootstrapIssuerPublicJwks(issuer));
  assert.equal(issuer.summary().tokensIssued, 0); assert.equal(issuer.summary().clientFetches, 1);
});
test('factory rejects arbitrary inputs, getters, proxies, paths, TLS material and namespace overrides before claiming', async t => {
  const issuer = await issuerFixture(t); let reads = 0;
  const getter = { issuer, get namespaceId() { reads++; return namespaceId; } };
  for (const value of [undefined, null, {}, getter, new Proxy({}, { get() { reads++; } }),
    { issuer, namespaceId, port: 8444 }, { issuer, namespaceId, certificatePem: 'invented' },
    { issuer, namespaceId, privateKeyPath: '/retained/private' }, { issuer, namespaceId, [Symbol('hidden')]: true },
    { issuer, namespaceId: 'localhost' }, { issuer, namespaceId: 'A'.repeat(24) }]) await rejected(createBootstrapJwksService(value));
  await rejected(createBootstrapJwksService({ issuer, namespaceId }, undefined));
  assert.equal(reads, 0); assert.equal(issuer.summary().clientFetches, 0); assert.equal(issuer.summary().tokensIssued, 0);
});
test('service cannot accept structural issuer methods or create a second public service for the same issuer', async t => {
  const f = await fixture(t); let calls = 0;
  await rejected(createBootstrapJwksService({ issuer: { fetchJwks() { calls++; } }, namespaceId }));
  await rejected(createBootstrapJwksService({ issuer: f.issuer, namespaceId: 'b'.repeat(24) }));
  assert.equal(calls, 0); assert.equal(f.issuer.summary().verifiedTlsFetches, 1);
});
test('fresh DNS-SAN TLS serves exactly the original canonical one-key public bytes', async t => {
  const f = await fixture(t); const response = await localRequest(f.config);
  assert.equal(response.status, 200); assert.equal(response.authorized, true); assert.ok(['TLSv1.2', 'TLSv1.3'].includes(response.protocol));
  assert.equal(f.config.hostname, `fncp-fresh-jwks-${namespaceId}`);
  assert.equal(f.config.jwksUri, `https://${f.config.hostname}:8444/.well-known/jwks.json`);
  const cert = new X509Certificate(f.config.certificatePem);
  assert.equal(cert.checkHost(f.config.hostname, { subject: 'never', wildcards: false }), f.config.hostname);
  assert.equal(cert.checkIP('127.0.0.1'), undefined);
  assert.equal(digest(cert.raw), f.config.certificateSha256);
  assert.equal(response.body, JSON.stringify(await f.issuer.fetchJwks()));
  assert.equal(Number(response.headers['content-length']), Buffer.byteLength(response.body));
  assert.equal(f.issuer.summary().tokensIssued, 0);
});
test('response has no redirect, cookie, CORS or credential disclosure', async t => {
  const f = await fixture(t); const response = await localRequest(f.config);
  assert.equal(response.headers['content-type'], 'application/json'); assert.equal(response.headers['cache-control'], 'no-store');
  assert.equal(response.headers['x-content-type-options'], 'nosniff'); assert.equal(response.headers.location, undefined);
  assert.equal(response.headers['access-control-allow-origin'], undefined); assert.equal(response.headers['set-cookie'], undefined);
  assert.doesNotMatch(response.body, /PRIVATE KEY|"d"\s*:|"p"\s*:|"q"\s*:|access_token|refresh_token/iu);
});
test('each service owns fresh TLS material even for the same requested namespace', async t => {
  const a = await fixture(t); const b = await fixture(t);
  assert.notEqual(a.config.certificatePem, b.config.certificatePem);
  assert.notEqual(a.config.certificateSha256, b.config.certificateSha256);
  assert.notEqual(a.config.localPort, b.config.localPort);
  await assert.rejects(localRequest(a.config, { ca: b.config.certificatePem }));
  assert.equal(a.service.summary().servedRequests, 0);
});
test('default trust and a wrong DNS SAN do not authorize the service', async t => {
  const f = await fixture(t);
  await assert.rejects(localRequest(f.config, { ca: undefined }));
  await assert.rejects(localRequest(f.config, { servername: 'wrong.example.invalid' }), error => error.code === 'ERR_TLS_CERT_ALTNAME_INVALID');
  assert.equal(f.service.summary().servedRequests, 0);
});
test('only literal GET /.well-known/jwks.json exists; no discovery/login/token/redirect surface', async t => {
  const f = await fixture(t);
  for (const path of ['/', '/login', '/token', '/authorize', '/.well-known/openid-configuration', '/.well-known/jwks.json?x=1',
    '/.well-known/%6awks.json', '/.well-known/JWKS.json']) {
    const result = await localRequest(f.config, { path }); assert.equal(result.status, 403); assert.equal(result.body, '{}');
  }
  for (const method of ['POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']) {
    const result = await localRequest(f.config, { method }); assert.equal(result.status, 403); assert.equal(result.body, method === 'HEAD' ? '' : '{}');
  }
  assert.equal(f.service.summary().servedRequests, 0);
});
test('foreign Host, Origin, cookie, bearer and body-bearing GET are denied', async t => {
  const f = await fixture(t);
  for (const options of [{ headers: { host: 'outside.example.invalid' } }, { headers: { origin: 'https://outside.example.invalid' } },
    { headers: { authorization: 'Bearer synthetic-never-used' } }, { headers: { cookie: 'synthetic=only' } },
    { headers: { 'content-length': '1' }, body: 'x' }, { headers: { 'transfer-encoding': 'chunked' }, body: 'x' }]) {
    const result = await localRequest(f.config, options); assert.equal(result.status, 403); assert.equal(result.body, '{}');
  }
  assert.equal(f.service.summary().servedRequests, 0); assert.equal(f.service.summary().rejectedRequests, 6);
});
test('fixed request budget cannot be reset by a new HTTP connection', async t => {
  const f = await fixture(t);
  for (let i = 0; i < 32; i++) assert.equal((await localRequest(f.config)).status, 200);
  assert.equal((await localRequest(f.config)).status, 403);
  assert.equal(f.service.summary().servedRequests, 32); assert.equal(f.service.summary().rejectedRequests, 1);
});
test('configuration/summary/close reject extra arguments without adopting caller data', async t => {
  const f = await fixture(t); let reads = 0;
  const hostile = new Proxy({}, { get() { reads++; throw new Error('private'); } });
  for (const input of [undefined, hostile, '/retained/private', 'https://outside.example.invalid']) {
    assert.throws(() => f.service.configuration(input), { message: SERVICE });
    assert.throws(() => f.service.summary(input), { message: SERVICE }); await rejected(f.service.close(input));
  }
  assert.equal(reads, 0); assert.equal(f.service.summary().closed, false);
});
test('closing service synchronously latches requests, removes its exact listener and leaves issuer independently live', async t => {
  const f = await fixture(t); const pending = f.service.close(); assert.equal(f.service.close(), pending);
  assert.throws(() => f.service.configuration(), { message: SERVICE });
  await pending; await refused(f.config.localPort);
  assert.equal(f.service.summary().closed, true); assert.equal(f.service.summary().listenersClosed, true);
  assert.equal(f.issuer.summary().closed, false); assert.equal(f.issuer.summary().tokensIssued, 0);
});
test('original issuer closure immediately denies service work and closes its static listener', async t => {
  const f = await fixture(t); await f.issuer.close();
  assert.throws(() => f.service.configuration(), { message: SERVICE });
  await f.service.close(); await refused(f.config.localPort);
  assert.equal(f.service.summary().listenersClosed, true);
});
test('original issuer expiry denies static service; no second token lifetime is introduced', async t => {
  const f = await fixture(t);
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() }); t.mock.timers.tick(120_000);
  assert.throws(() => f.service.configuration(), { message: SERVICE });
  await f.service.close(); await refused(f.config.localPort);
  assert.equal(f.issuer.summary().expired, true); assert.equal(f.issuer.summary().tokensIssued, 0);
});
test('closed issuer cannot create a new static service', async t => {
  const issuer = await issuerFixture(t); await issuer.close();
  await rejected(createBootstrapJwksService({ issuer, namespaceId }));
  assert.equal(issuer.summary().clientFetches, 0);
});
test('cached public keys still validate the original token after service/issuer closure until normal token expiry', async t => {
  const f = await fixture(t); const config = f.issuer.configuration(); const token = f.issuer.issueToken();
  const publicKeys = JSON.parse((await localRequest(f.config)).body);
  await f.service.close(); await f.issuer.close();
  const result = await jwtVerify(token, createLocalJWKSet(publicKeys), { issuer: config.issuer, audience: config.audience, algorithms: ['RS256'] });
  assert.equal(result.payload.sub, decodeJwt(token).sub);
  assert.equal(f.service.summary().cachedTokenRevocationImplemented, false);
  assert.ok(result.payload.exp - result.payload.iat <= 120);
});
test('an incomplete owned TLS connection is destroyed by close with independently refused port', async t => {
  const f = await fixture(t); const socket = connect({ host: '127.0.0.1', port: f.config.localPort });
  socket.on('error', () => {}); await new Promise(resolve => socket.once('connect', resolve));
  const ended = new Promise(resolve => socket.once('close', resolve));
  await f.service.close(); await ended; await refused(f.config.localPort);
});
test('hard connection deadline closes a silent socket without waiting for application data', async t => {
  const f = await fixture(t); const started = Date.now();
  const socket = connect({ host: '127.0.0.1', port: f.config.localPort }); socket.on('error', () => {});
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('Connection exceeded test bound.')); }, 2500);
    socket.once('close', () => { clearTimeout(timer); resolve(); });
  });
  assert.ok(Date.now() - started < 2400); assert.equal(f.service.summary().servedRequests, 0);
});
test('aggregate summary has no namespace, endpoints, public/private keys or tokens and states unverified topology', async t => {
  const f = await fixture(t); const response = await localRequest(f.config); const text = JSON.stringify(f.service.summary());
  const key = JSON.parse(response.body).keys[0];
  for (const privateValue of [namespaceId, f.config.hostname, f.config.jwksUri, f.config.certificatePem, f.config.certificateSha256, key.n, key.kid]) {
    assert.equal(text.includes(privateValue), false);
  }
  for (const key of ['containerRoleImplemented', 'containerReachabilityVerified', 'runtimeOwnershipVerified', 'productionReady',
    'globalTrustChanged', 'tokenIssuanceImplemented', 'rsaPrivateKeyExported', 'tlsPrivateKeyExported']) assert.equal(f.service.summary()[key], false);
  assert.equal(f.service.summary().publicHandoffs, 1); assert.equal(f.service.summary().temporaryCertificateFilesRemoved, true);
  assert.equal(Object.isFrozen(f.service), true); assert.equal(Object.isFrozen(f.config), true);
});
test('source has no file/key/URL adoption, signer, bearer, Docker launcher or token lifetime copy', async () => {
  const source = await readFile(new URL('./bootstrap-jwks-service.mjs', import.meta.url), 'utf8');
  assert.equal((source.match(/^export /gmu) ?? []).length, 2);
  assert.deepEqual([...source.matchAll(/^export async function (\w+)\(/gmu)].map(match => match[1]),
    ['createBootstrapJwksService', 'createBootstrapContainerJwksService']);
  assert.match(source, /claimBootstrapIssuerPublicJwks\(issuer\)/u); assert.match(source, /server\.listen\(0, '127\.0\.0\.1'/u);
  assert.match(source, /subjectAltName=DNS:\$\{hostname\}/u); assert.match(source, /O_NOFOLLOW \| constants\.O_NONBLOCK/u);
  assert.doesNotMatch(source, /issueToken\(|privateKey\.export|runDocker\(|process\.env|120_000|setInterval|fetch\(|rejectUnauthorized:\s*false/u);
  assert.match(source, /for \(const path of \[keyPath, certPath\]\)/u); assert.match(source, /rmdirSync\(directory\)/u);
});
