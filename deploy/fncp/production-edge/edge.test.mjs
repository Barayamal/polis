import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:https';
import { connect, checkServerIdentity } from 'node:tls';
import { createParticipantEdge } from './edge.mjs';
import { freshLeaf } from './tls-fixture.mjs';
import { freshCertificate } from '../production-identity/test-support/https-issuer.mjs';
import { serviceFixture, refused } from '../production-service/test-support/service-fixture.mjs';

async function fixture(t, { tls = freshCertificate(), discardCookies = ['__cf_bm'], respond } = {}) {
  const calls = [];
  const backend = createServer({ ...tls, minVersion: 'TLSv1.2' }, async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    calls.push({ path: req.url, method: req.method, headers: req.headers, body: Buffer.concat(chunks).toString() });
    if (respond) respond(req, res);
    else { res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end('{"ok":true}'); }
  });
  backend.on('tlsClientError', () => {});
  await new Promise(resolve => backend.listen(0, '127.0.0.1', resolve));
  t.after(async () => { backend.closeAllConnections(); await new Promise(resolve => backend.close(resolve)); });
  const leaf = freshLeaf(), edgeTls = leaf.tls, edgeCa = leaf.ca;
  const options = { publicOrigin: 'https://127.0.0.1', listen: { host: '127.0.0.1', port: 0 },
    upstream: { address: '127.0.0.1', port: backend.address().port, ca: tls.cert }, tls: edgeTls, discardCookies };
  const edge = createParticipantEdge(options); const listener = await edge.start();
  t.after(() => edge.close());
  return { edge, options, edgeTls, edgeCa, calls, port: listener.port, call: callClient(listener.port, edgeCa, options.publicOrigin) };
}
function callClient(port, ca, origin) {
  return (path, { method = 'GET', headers = {}, body } = {}) => new Promise((resolve, reject) => {
    const outgoing = request({ hostname: '127.0.0.1', port, ca, rejectUnauthorized: true, agent: false, path, method,
      servername: '', checkServerIdentity: (_hostname, certificate) => checkServerIdentity('127.0.0.1', certificate),
      headers: { host: new URL(origin).host, connection: 'close', 'sec-fetch-site': 'same-origin',
        'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty', ...(body === undefined ? {} : {
          origin, 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) }), ...headers } }, res => {
      const chunks = []; res.on('data', chunk => chunks.push(chunk)); res.once('error', reject);
      res.once('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    outgoing.setTimeout(7000, () => outgoing.destroy(Error('test deadline'))); outgoing.once('error', reject); outgoing.end(body);
  });
}
async function raw(port, ca, requestText) {
  return new Promise((resolve, reject) => {
    let response = '';
    const socket = connect({ host: '127.0.0.1', port, ca, rejectUnauthorized: true }, () => socket.write(requestText));
    socket.setTimeout(7000, () => socket.destroy(Error('raw test deadline')));
    socket.on('data', chunk => response += chunk); socket.once('error', reject); socket.once('end', () => resolve(response));
  });
}

test('only explicitly approved edge cookie is removed; application values and browser controls are unchanged', async t => {
  const f = await fixture(t); const session = 'A'.repeat(43), transaction = 'B'.repeat(43);
  const result = await f.call('/session', { headers: { cookie: `__cf_bm=opaque.example==; __Host-fncp-session=${session}; __Host-fncp-transaction=${transaction}`,
    origin: f.options.publicOrigin, 'x-csrf-token': 'C'.repeat(43), 'sec-fetch-site': 'same-origin' } });
  assert.equal(result.status, 200);
  assert.equal(f.calls[0].headers.cookie, `__Host-fncp-session=${session}; __Host-fncp-transaction=${transaction}`);
  assert.equal(f.calls[0].headers.origin, f.options.publicOrigin);
  assert.equal(f.calls[0].headers['x-csrf-token'], 'C'.repeat(43));
  assert.equal(f.calls[0].headers['sec-fetch-site'], 'same-origin');
  assert.equal(f.calls[0].headers.host, new URL(f.options.publicOrigin).host);
});

test('edge-cookie deletion is opt-in and never generalized to unknown cookies', async t => {
  const f = await fixture(t, { discardCookies: [] });
  assert.equal((await f.call('/session', { headers: { cookie: '__cf_bm=opaque' } })).status, 403);
  assert.equal((await f.call('/session', { headers: { cookie: 'cf_clearance=opaque' } })).status, 403);
  assert.equal(f.calls.length, 0);
});

test('spoofed proxy metadata is discarded, never used as authority; protected headers are rejected', async t => {
  const f = await fixture(t);
  const dropped = { forwarded: 'host=attacker.invalid;proto=http', 'x-forwarded-for': '203.0.113.2',
    'x-forwarded-host': 'attacker.invalid', 'x-forwarded-proto': 'http', 'x-forwarded-port': '80',
    'x-real-ip': '203.0.113.2', 'cf-connecting-ip': '203.0.113.2', 'cf-ray': 'not-authentication',
    'cf-ipcountry': 'XX', 'cf-visitor': '{"scheme":"http"}', 'cdn-loop': 'cloudflare' };
  assert.equal((await f.call('/session', { headers: dropped })).status, 200);
  for (const key of Object.keys(dropped)) assert.equal(f.calls[0].headers[key], undefined, key);
  for (const headers of [{ host: 'attacker.invalid', 'x-forwarded-host': new URL(f.options.publicOrigin).host },
    { authorization: 'Bearer invented' }, { 'x-fncp-principal': 'invented' }, { 'x-forwarded-secret': 'invented' }]) {
    assert.equal((await f.call('/session', { headers })).status, 403);
  }
  assert.equal(f.calls.length, 1);
});

test('malformed, duplicate and unknown cookies fail closed before upstream', async t => {
  const f = await fixture(t);
  for (const cookie of ['__cf_bm=a; __cf_bm=b', '__Host-fncp-session=a; __Host-fncp-session=b',
    '__cf_bm="quoted"', '__cf_bm=white space', '__cf_bm=a; unrelated=b', '__cf_bm=a;', '=value']) {
    assert.ok([400, 403].includes((await f.call('/session', { headers: { cookie } })).status));
  }
  assert.equal(f.calls.length, 0);
});

test('routing excludes private receiver, operator, WordPress, native Pol.is and noncanonical paths', async t => {
  const f = await fixture(t);
  for (const path of ['/health', '/events', '/operator', '/wp-admin/', '/wp-json/', '/api/v3/votes',
    '/polis/conversations', '/results', '//attacker.invalid/session', '/%73ession', '/x/../session',
    '/session?extra=1', '/session/']) assert.ok([400, 404].includes((await f.call(path)).status), path);
  assert.equal((await f.call('/session', { method: 'POST', body: '{}' })).status, 404);
  assert.equal(f.calls.length, 0);
});

test('duplicate authority headers and connection-nominated authority never become a sanitized valid request', async t => {
  const f = await fixture(t); const host = new URL(f.options.publicOrigin).host;
  for (const extra of [`Host: ${host}\r\n`, 'Cookie: __cf_bm=a\r\nCookie: __cf_bm=b\r\n',
    'Connection: Origin\r\nOrigin: https://attacker.invalid\r\n']) {
    const reply = await raw(f.port, f.edgeCa, `GET /session HTTP/1.1\r\nHost: ${host}\r\n${extra}\r\n`);
    assert.match(reply, /^HTTP\/1\.1 400 /u);
  }
  assert.equal(f.calls.length, 0);
});

test('native TLS rejects untrusted CA and wrong upstream hostname, without fallback or retry', async t => {
  const f = await fixture(t, { tls: freshCertificate(true) });
  assert.equal((await f.call('/session')).status, 502); assert.equal(f.calls.length, 0);
  const normal = await fixture(t);
  const bad = createParticipantEdge({ ...normal.options, upstream: { ...normal.options.upstream, ca: freshCertificate().cert } });
  t.after(() => bad.close()); const listener = await bad.start();
  const call = callClient(listener.port, normal.edgeCa, normal.options.publicOrigin);
  assert.equal((await call('/session')).status, 502); assert.equal(normal.calls.length, 0);
});

test('redirects, security headers and separate secure Set-Cookie values are forwarded without following or rewriting', async t => {
  const cookies = ['__Host-fncp-session=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0',
    `__Host-fncp-transaction=${'B'.repeat(43)}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=300`];
  const f = await fixture(t, { respond: (_req, res) => { res.writeHead(303, { location: '/', 'set-cookie': cookies,
    'cache-control': 'no-store', 'content-security-policy': "default-src 'none'", 'strict-transport-security': 'max-age=31536000' }); res.end(''); } });
  const result = await f.call('/oidc/callback?code=invented&state=invented&iss=https%3A%2F%2Fissuer.example.invalid');
  assert.equal(result.status, 303); assert.equal(result.headers.location, '/');
  assert.deepEqual(result.headers['set-cookie'], cookies); assert.equal(result.headers['cache-control'], 'no-store');
  assert.equal(result.headers['content-security-policy'], "default-src 'none'");
  assert.equal(f.calls.length, 1);
});

test('oversize bodies, compression and unsafe connection headers are refused', async t => {
  const f = await fixture(t);
  for (const request of [{ body: 'a'.repeat(4097) }, { body: '{}', headers: { 'content-encoding': 'gzip' } },
    { body: '{}', headers: { connection: 'cookie' } }]) {
    assert.ok([400, 403, 413].includes((await f.call('/registration', { method: 'POST', ...request })).status));
  }
  assert.equal(f.calls.length, 0);
});

test('configuration cannot select external addresses, plain TLS, arbitrary discard names or incomplete trust', async t => {
  const f = await fixture(t);
  for (const patch of [{ listen: { host: '0.0.0.0', port: 443 } }, { upstream: { ...f.options.upstream, address: '203.0.113.1' } },
    { upstream: { ...f.options.upstream, address: 'localhost' } }, { upstream: { ...f.options.upstream, port: 0 } },
    { upstream: { ...f.options.upstream, rejectUnauthorized: false } }, { discardCookies: ['anything'] },
    { discardCookies: ['__cf_bm', '__cf_bm'] }, { publicOrigin: 'http://127.0.0.1' },
    { publicOrigin: 'https://127.0.0.1/' }, { tls: freshCertificate(true) }, { tls: freshCertificate() }, { arbitraryTransport: () => {} }]) {
    assert.throws(() => createParticipantEdge({ ...f.options, ...patch }), /configuration rejected/u);
  }
});

test('closure is idempotent and cannot leave or restart an owned listener', async t => {
  const f = await fixture(t);
  assert.deepEqual(await f.edge.close(), { closed: true, listenerClosed: true });
  assert.deepEqual(await f.edge.close(), { closed: true, listenerClosed: true });
  await refused(f.port); await assert.rejects(() => f.edge.start());
});

test('client-authentication-only TLS leaf is rejected before starting a listener', async t => {
  const f = await fixture(t);
  const clientOnly = freshLeaf({ purpose: 'clientAuth' });
  assert.throws(() => createParticipantEdge({ ...f.options, tls: clientOnly.tls }), /configuration rejected/u);
});

test('real production BFF behind edge keeps OIDC, CSRF and closed admission controls intact', async t => {
  const x = await serviceFixture(t); const service = await x.create(); await service.start();
  const leaf = freshLeaf();
  const edge = createParticipantEdge({ publicOrigin: x.manifest.participant.origin, listen: { host: '127.0.0.1', port: 0 },
    upstream: { address: '127.0.0.1', port: x.participantPort, ca: x.participantTls.cert },
    tls: leaf.tls, discardCookies: ['__cf_bm'] });
  t.after(() => edge.close()); const listener = await edge.start();
  const send = callClient(listener.port, leaf.ca, x.manifest.participant.origin);
  const jar = new Map([['__cf_bm', 'invented-edge-cookie']]); let csrf;
  async function call(path, values, extra = {}) {
    const result = await send(path, { method: values === undefined ? 'GET' : 'POST',
      ...(values === undefined ? {} : { body: JSON.stringify(values) }), headers: {
        cookie: [...jar].map(([key, value]) => `${key}=${value}`).join('; '), ...(csrf ? { 'x-csrf-token': csrf } : {}), ...extra } });
    for (const cookie of result.headers['set-cookie'] ?? []) {
      const [key, value] = cookie.split(';')[0].split('='); if (value) jar.set(key, value); else jar.delete(key);
    }
    const body = /application\/json/u.test(result.headers['content-type'] ?? '') ? JSON.parse(result.body) : result.body;
    if (body?.csrf) csrf = body.csrf;
    return { ...result, body };
  }
  assert.equal((await call('/session')).status, 200);
  assert.equal((await call('/oidc/login', {}, { 'x-csrf-token': 'wrong' })).status, 403);
  assert.equal((await call('/oidc/login', {}, { origin: 'https://attacker.invalid' })).status, 403);
  assert.equal((await call('/oidc/login', {}, { 'sec-fetch-site': 'cross-site' })).status, 403);
  const begun = await call('/oidc/login', {}); assert.equal(begun.status, 200);
  const callback = new URL(x.h.issuer.authorizationResponse(begun.body.authorizationUrl));
  const finished = await call(callback.pathname + callback.search, undefined,
    { 'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document', 'sec-fetch-user': '?1' });
  assert.equal(finished.status, 303); assert.equal(finished.headers.location, '/');
  const authenticated = await call('/session'); assert.equal(authenticated.body.authenticated, true);
  const registration = await call('/registration', { consentVersion: x.manifest.content.consentVersion,
    adultSelfAttested: true, eligibilitySelfAttested: true, registrationConsent: true });
  assert.equal(registration.status, 200); assert.equal(registration.body.registrationState, 'pending');
  assert.equal(registration.body.participantAccessGranted, false);
  assert.equal((await call('/polis/participation-init')).status, 403);
  assert.equal(service.operator.status().roundOpen, false); assert.equal(x.h.votes.length, 0);
  assert.equal((await call('/session', undefined, { cookie: '__Host-fncp-session=malformed' })).status, 403);
  assert.equal((await call('/session/logout', {})).status, 200);
  assert.equal((await call('/session')).body.authenticated, false);
});
