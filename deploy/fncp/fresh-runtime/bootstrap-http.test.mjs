import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { connect } from 'node:net';
import { connect as connectTls, checkServerIdentity } from 'node:tls';
import { createHash, X509Certificate } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { createBootstrapIssuer } from './bootstrap-issuer.mjs';
import { createBootstrapProtocol, verifyBootstrapProtocolRequest, httpRequestForBootstrap } from './bootstrap-protocol.mjs';
import { createBootstrapHttpTransport } from './bootstrap-http.mjs';

const dependency = createRequire(new URL('../identity-foundation/package.json', import.meta.url));
const { createLocalJWKSet, jwtVerify } = await import(pathToFileURL(dependency.resolve('jose')).href);
const MESSAGE = 'Fresh bootstrap HTTPS transport rejected; private details withheld.';
const PROTOCOL = /Fresh bootstrap protocol failed; private evidence preserved and replay denied\./u;
const HELPER = 'a'.repeat(64); const CONVERSATION = '3SyntheticBootstrap'; const PID = 37;
const TIDS = [103, 7, 219, 48, 301, 76, 519, 1024, 614, 913, 1217, 1901, 2013, 111, 3077];
const seeds = JSON.parse(await readFile(new URL('../seed-statements.json', import.meta.url), 'utf8'));
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { resolve, promise }; };
const rejected = promise => assert.rejects(promise, error => error.message === MESSAGE && error.cause === undefined);
const throws = fn => assert.throws(fn, { message: MESSAGE });

// Every certificate, signing issuer, listener, protocol directory and model
// below belongs to this invocation. No Docker or existing service is contacted.
async function certificate(t, alternateLeaf = false) {
  const directory = await mkdtemp(join(tmpdir(), 'fncp-bootstrap-http-tls-test-'));
  t.after(() => rm(directory, { recursive: true, force: true })); await chmod(directory, 0o700);
  const keyPath = join(directory, 'test-key.pem'); const certPath = join(directory, 'test-cert.pem');
  const openssl = args => spawnSync('/opt/homebrew/bin/openssl', args, {
    cwd: directory, shell: false, stdio: ['ignore', 'pipe', 'pipe'], timeout: 10000, maxBuffer: 8192,
    env: { PATH: '/opt/homebrew/bin:/usr/bin:/bin', LANG: 'C', LC_ALL: 'C', OPENSSL_CONF: '/dev/null' },
  });
  const result = openssl(['req', '-x509', '-newkey', 'ec', '-pkeyopt',
    'ec_paramgen_curve:prime256v1', '-noenc', '-days', '1', '-subj', '/CN=127.0.0.1',
    '-addext', 'subjectAltName=IP:127.0.0.1', '-addext', 'basicConstraints=critical,CA:TRUE',
    '-keyout', keyPath, '-out', certPath]);
  assert.equal(result.status, 0, 'Fresh synthetic certificate creation succeeds without exposing command output.');
  await chmod(keyPath, 0o600); await chmod(certPath, 0o600);
  if (!alternateLeaf) return { key: await readFile(keyPath), cert: await readFile(certPath, 'utf8') };
  const leafKey = join(directory, 'leaf-key.pem'); const leafCsr = join(directory, 'leaf.csr'); const leafCert = join(directory, 'leaf-cert.pem');
  assert.equal(openssl(['req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-noenc',
    '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1', '-addext', 'basicConstraints=critical,CA:FALSE',
    '-keyout', leafKey, '-out', leafCsr]).status, 0, 'Fresh alternate leaf request succeeds.');
  assert.equal(openssl(['x509', '-req', '-in', leafCsr, '-CA', certPath, '-CAkey', keyPath, '-set_serial', '1',
    '-days', '1', '-copy_extensions', 'copy', '-out', leafCert]).status, 0, 'Fresh alternate leaf signing succeeds.');
  await chmod(leafKey, 0o600); await chmod(leafCsr, 0o600); await chmod(leafCert, 0o600);
  return { key: await readFile(leafKey), cert: await readFile(leafCert, 'utf8'), ca: await readFile(certPath, 'utf8') };
}
async function refused(port) {
  await new Promise((resolve, reject) => {
    const socket = connect({ host: '127.0.0.1', port }); socket.setTimeout(500);
    socket.once('connect', () => { socket.destroy(); reject(new Error('Owned test listener is still open.')); });
    socket.once('timeout', () => { socket.destroy(); reject(new Error('Owned listener closure was not verified.')); });
    socket.once('error', error => { socket.destroy(); error.code === 'ECONNREFUSED' ? resolve() : reject(new Error('Unexpected closure result.')); });
  });
}
function modelReply(method, path, body, state) {
  if (method === 'POST' && path === '/api/v3/conversations') {
    assert.equal(body.is_active, true); assert.equal(body.is_data_open, false); assert.equal(body.spam_filter, false);
    return { conversation_id: CONVERSATION };
  }
  if (method === 'POST' && path === '/api/v3/comments') {
    const index = state.seedPayloads.length;
    assert.deepEqual(body, { conversation_id: CONVERSATION, txt: seeds[index], is_seed: true });
    state.seedPayloads.push(body); return { tid: TIDS[index], currentPid: PID };
  }
  if (method === 'GET' && path === `/api/v3/comments?conversation_id=${CONVERSATION}&moderation=true&include_voting_patterns=true`) {
    assert.equal(state.seedPayloads.length, 15);
    return state.seedPayloads.map((item, i) => ({ conversation_id: CONVERSATION, tid: TIDS[i], txt: item.txt,
      is_seed: true, pid: PID, mod: 1, active: true, agree_count: 0, disagree_count: 0, pass_count: 1, count: 1 })).reverse();
  }
  if (method === 'PUT' && path === '/api/v3/conversations') {
    assert.deepEqual(body, { conversation_id: CONVERSATION, is_active: false, use_xid_whitelist: true,
      xid_required: true, send_created_email: false }); state.closedRound = true; return { conversation_id: CONVERSATION };
  }
  if (method === 'GET' && path === `/api/v3/conversations?conversation_id=${CONVERSATION}`) {
    assert.equal(state.closedRound, true);
    return { conversation_id: CONVERSATION, is_owner: true, is_active: false, use_xid_whitelist: true,
      xid_required: true, is_data_open: false, strict_moderation: true, is_anon: true, is_draft: false,
      topics_enabled: false, treevite_enabled: false, profanity_filter: false, spam_filter: false };
  }
  throw new Error('Unexpected synthetic endpoint.');
}
const json = (res, value) => { const body = JSON.stringify(value); res.writeHead(200, {
  'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(body),
}); res.end(body); };

async function fixture(t, options = {}) {
  const tls = await certificate(t, options.alternateLeaf); const ca = options.ca ?? tls.ca ?? tls.cert; const sockets = new Set();
  const state = { requests: 0, seedPayloads: [], closedRound: false, verifiedTokens: 0, tokenHashes: new Set(),
    paths: [], operations: [], ownershipChecks: 0, helperClosed: false, errors: 0 };
  let keys; let config;
  const server = createServer({ key: tls.key, cert: tls.cert, minVersion: 'TLSv1.2' }, async (req, res) => {
    state.requests++; state.paths.push({ method: req.method, path: req.url });
    req.on('error', () => {}); res.on('error', () => {});
    try {
      assert.equal(req.socket.remoteAddress, '127.0.0.1');
      assert.equal(req.headers.cookie, undefined); assert.equal(req.headers['x-forwarded-proto'], 'https');
      assert.match(req.headers.authorization, /^Bearer [A-Za-z0-9_.-]+$/u);
      if (keys) {
        const token = req.headers.authorization.slice(7);
        const { payload } = await jwtVerify(token, keys, { issuer: config.issuer, audience: config.audience, algorithms: ['RS256'] });
        assert.equal(payload.email_verified, false); assert.equal(payload.email, 'bootstrap-admin@bootstrap.example.invalid');
        state.verifiedTokens++; state.tokenHashes.add(createHash('sha256').update(token).digest('hex'));
      }
      const chunks = []; let length = 0;
      for await (const chunk of req) { length += chunk.length; assert.ok(length < 8192); chunks.push(chunk); }
      const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : null;
      if (options.respond) return await options.respond(req, res, state, body);
      json(res, modelReply(req.method, req.url, body, state));
    } catch { state.errors++; res.destroy(); }
  });
  server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  server.on('tlsClientError', () => {});
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const port = server.address().port; const origin = `https://127.0.0.1:${port}`;
  let issuer; let transport; const instances = [];
  // Register listener cleanup before any later factory/JWKS setup can fail.
  t.after(async () => {
    try {
      transport?.close();
      for (const instance of instances) {
        try { await instance.close(); } catch { /* Failure evidence is inspected before this test-only removal. */ }
        await rm(instance.privateDirectory, { recursive: true, force: true });
      }
    } finally {
      try { await issuer?.close(); }
      finally {
        for (const socket of sockets) socket.destroy();
        await new Promise(resolve => server.close(resolve)); await refused(port); tls.key.fill(0);
      }
    }
  });
  issuer = await createBootstrapIssuer(); config = issuer.configuration();
  if (options.verifyTokens) keys = createLocalJWKSet(await issuer.fetchJwks());
  const assertOwned = async lease => {
    state.ownershipChecks++;
    assert.equal(Object.isFrozen(lease), true);
    assert.deepEqual(lease, { origin, certificateSha256: createHash('sha256').update(new X509Certificate(ca).raw).digest('hex') });
    if (options.owner) return options.owner(lease, state);
  };
  const settings = { origin, certificatePem: ca, issuer, assertOwned };
  if (!options.noTransport) transport = createBootstrapHttpTransport(settings);
  async function protocol(hook) {
    const instance = await createBootstrapProtocol({ async driver(request) {
      await verifyBootstrapProtocolRequest(request); state.operations.push(request.operation);
      if (hook) { const result = await hook(request); if (result !== undefined) return result; }
      if (request.operation === 'inspect-helper') return { id: HELPER, imageId: 'sha256:' + 'd'.repeat(64),
        os: 'linux', architecture: 'arm64', ordinary: true, owned: true, loopbackOnly: true,
        egressVerified: true, schemaReady: true, running: true };
      if (request.operation === 'close-helper') { assert.deepEqual(request.payload, { id: HELPER }); state.helperClosed = true; return { id: HELPER, running: false }; }
      if (request.operation === 'inspect-closed') { assert.equal(state.helperClosed, true); return { id: HELPER, running: false }; }
      return transport.send(request);
    } });
    instances.push(instance); return instance;
  }
  async function verifyAlternateLeafChainOnly() {
    assert.equal(options.alternateLeaf, true);
    await new Promise((resolve, reject) => {
      const socket = connectTls({ host: '127.0.0.1', port, ca, rejectUnauthorized: true, minVersion: 'TLSv1.2' });
      const timer = setTimeout(() => { socket.destroy(); reject(new Error('Fresh chain-only TLS check timed out.')); }, 1500);
      socket.once('error', () => { clearTimeout(timer); socket.destroy(); reject(new Error('Fresh alternate leaf chain was not trusted.')); });
      socket.once('secureConnect', () => {
        try {
          assert.equal(socket.authorized, true); const peer = socket.getPeerCertificate();
          assert.equal(checkServerIdentity('127.0.0.1', peer), undefined);
          assert.notEqual(createHash('sha256').update(peer.raw).digest('hex'), createHash('sha256').update(new X509Certificate(ca).raw).digest('hex'));
          clearTimeout(timer); socket.destroy(); resolve();
        } catch { clearTimeout(timer); socket.destroy(); reject(new Error('Fresh alternate leaf verification failed.')); }
      });
    });
  }
  return { state, issuer, config, transport, protocol, settings, server, verifyAlternateLeafChainOnly };
}
async function failedRun(f) {
  const p = await f.protocol(); await assert.rejects(p.run(), PROTOCOL);
  assert.equal(f.state.helperClosed, true); assert.equal(f.transport.summary().retries, 0);
  await assert.rejects(p.run(), PROTOCOL); return p;
}

test('nineteen actual verified HTTPS requests carry one factory token through the entire modeled bootstrap protocol', async t => {
  const f = await fixture(t, { verifyTokens: true }); const p = await f.protocol(); const result = await p.run();
  assert.deepEqual(result.binding, { conversationId: CONVERSATION, statementIds: TIDS });
  assert.equal(result.evidence, 'INJECTED_PROTOCOL_ONLY'); assert.equal(result.roundOpen, false); assert.equal(result.activationGranted, false);
  assert.equal(result.latestUniqueSeedOwnerVotes, 15); assert.equal(result.rawVoteHistory, 'NOT_CHECKED');
  assert.equal(f.state.requests, 19); assert.equal(f.state.errors, 0); assert.equal(f.state.verifiedTokens, 19);
  assert.equal(f.state.tokenHashes.size, 1); assert.equal(f.state.ownershipChecks, 57); assert.equal(f.state.helperClosed, true);
  const summary = f.transport.summary();
  assert.deepEqual([summary.dispatched, summary.tlsResponses, summary.acceptedResponses], [19, 19, 19]);
  assert.equal(summary.actualPolisVerified, false); assert.equal(summary.containerRuntimeVerified, false); assert.equal(summary.productionReady, false);
  assert.equal(summary.ownership, 'TRUSTED_CALLBACK_NOT_INDEPENDENTLY_PROVED');
  assert.equal(summary.wholeSendDeadlineMs, 2000); assert.equal(summary.responseByteLimit, 65536);
  const output = JSON.stringify(summary); assert.equal(output.includes(f.settings.origin), false); assert.equal(output.includes('Bearer'), false);
  assert.deepEqual(f.state.paths.slice(16).map(item => item.method), ['GET', 'PUT', 'GET']);
  f.transport.close(); f.transport.close(); assert.equal(f.transport.summary().closed, true);
});

test('constructor rejects ambient hosts, paths, accessors, proxies and override options before issuing a token', async t => {
  const f = await fixture(t, { noTransport: true }); let reads = 0;
  for (const origin of ['https://localhost:49199', 'https://127.0.0.1:443', 'https://127.0.0.1:65536',
    f.settings.origin + '/', f.settings.origin + '/api', f.settings.origin + '?x=1', 'http://127.0.0.1:49199']) {
    throws(() => createBootstrapHttpTransport({ ...f.settings, origin }));
  }
  for (const options of [undefined, null, {}, { ...f.settings, timeout: 20 },
    { ...f.settings, get origin() { reads++; } }, new Proxy(f.settings, { get() { reads++; } }),
    { ...f.settings, assertOwned: new Proxy(() => {}, {}) }, { ...f.settings, certificatePem: 'private-invalid-certificate' }]) {
    throws(() => createBootstrapHttpTransport(options));
  }
  throws(() => createBootstrapHttpTransport()); throws(() => createBootstrapHttpTransport(f.settings, undefined));
  assert.equal(reads, 0); assert.equal(f.state.requests, 0); assert.equal(f.issuer.summary().tokensIssued, 0);
});

test('issuer handoff is branded and one-shot, and does not expose underlying issuer failures', async t => {
  const f = await fixture(t); throws(() => createBootstrapHttpTransport(f.settings));
  throws(() => createBootstrapHttpTransport({ ...f.settings, issuer: { ...f.issuer } }));
  throws(() => createBootstrapHttpTransport({ ...f.settings, issuer: { issueToken() { throw new Error('private-token'); } } }));
  assert.equal(f.state.requests, 0); assert.equal(f.issuer.summary().tokensIssued, 1);
});

test('wrong fresh CA rejects the real TLS handshake before any HTTP request or token reaches the endpoint', async t => {
  const ca = await certificate(t); const f = await fixture(t, { ca: ca.cert }); await failedRun(f);
  assert.equal(f.state.requests, 0); assert.deepEqual([f.transport.summary().dispatched, f.transport.summary().tlsResponses], [1, 0]);
});

test('a different valid IP leaf signed by the supplied CA cannot receive the bearer because the owned leaf is pinned exactly', async t => {
  const f = await fixture(t, { alternateLeaf: true }); await f.verifyAlternateLeafChainOnly(); await failedRun(f);
  assert.equal(f.state.requests, 0); assert.deepEqual([f.transport.summary().dispatched, f.transport.summary().tlsResponses], [1, 0]);
});

for (const [name, respond] of [
  ['redirect', (req, res) => { res.writeHead(302, { location: '/not-followed', 'content-type': 'application/json' }); res.end('{}'); }],
  ['non-200 status', (req, res) => { res.writeHead(401, { 'content-type': 'application/json' }); res.end('{"private":"do-not-leak"}'); }],
  ['Location even with status 200', (req, res) => { res.writeHead(200, { location: '/not-followed', 'content-type': 'application/json' }); res.end('{}'); }],
  ['missing content type', (req, res) => { res.writeHead(200); res.end('{}'); }],
  ['HTML content type', (req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end('private-html'); }],
  ['duplicate content type', (req, res) => { res.writeHead(200, ['Content-Type', 'application/json', 'Content-Type', 'application/json']); res.end('{}'); }],
  ['content encoding', (req, res) => { res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'gzip' }); res.end('{}'); }],
  ['oversize declared content length', (req, res) => { res.writeHead(200, { 'content-type': 'application/json', 'content-length': 65537 }); res.end('{}'); }],
  ['oversize chunked body', (req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.write('a'.repeat(32768)); res.end('b'.repeat(32769)); }],
  ['malformed UTF-8', (req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(Buffer.from([0xc3, 0x28])); }],
  ['truncated response', (req, res) => { res.writeHead(200, { 'content-type': 'application/json', 'content-length': 90 }); res.end('{}'); }],
]) {
  test(`actual HTTPS ${name} fails closed, is not retried and does not expose response content`, async t => {
    const f = await fixture(t, { respond }); await failedRun(f);
    assert.equal(f.state.requests, 1); assert.equal(f.transport.summary().acceptedResponses, 0);
    assert.equal(f.transport.summary().failed, true); assert.equal(f.transport.summary().redirectsFollowed, 0);
  });
}

test('valid UTF-8 but malformed JSON is not silently rewritten into a valid bootstrap response', async t => {
  const f = await fixture(t, { respond(req, res) { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"private":'); } });
  await failedRun(f); assert.equal(f.state.requests, 1); assert.equal(f.transport.summary().acceptedResponses, 1);
});

test('BOM and non-JSON whitespace prefixes remain visible to the protocol and cannot authorize seed creation', async t => {
  for (const prefix of ['\uFEFF', '\u00A0']) {
    const f = await fixture(t, { respond(req, res) {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(prefix + JSON.stringify({ conversation_id: CONVERSATION }));
    } });
    await failedRun(f); assert.equal(f.state.requests, 1);
    assert.equal(f.transport.summary().acceptedResponses, 1);
    assert.equal(f.state.operations.includes('create-seed'), false);
    assert.equal(f.state.seedPayloads.length, 0);
  }
});

for (const kind of ['fabricated', 'copied', 'stale', 'metadata']) {
  test(`${kind} protocol authority cannot dispatch an HTTP request`, async t => {
    const f = await fixture(t);
    if (kind === 'fabricated') await rejected(f.transport.send(Object.freeze({ operation: 'create-conversation', payload: {} })));
    else if (kind === 'stale') {
      let saved; const p = await f.protocol(request => {
        if (request.operation === 'create-conversation') { saved = request; throw new Error('Test model stops without sending.'); }
      }); await assert.rejects(p.run(), PROTOCOL); await rejected(f.transport.send(saved));
    } else {
      const operation = kind === 'metadata' ? 'inspect-helper' : 'create-conversation';
      const p = await f.protocol(async request => {
        if (request.operation !== operation) return;
        await rejected(f.transport.send(kind === 'copied' ? { ...request } : request));
        throw new Error('Invalid authority stopped.');
      }); await assert.rejects(p.run(), PROTOCOL);
    }
    assert.equal(f.state.requests, 0); assert.equal(f.transport.summary().dispatched, 0);
  });
}

test('one still-active request cannot be replayed after an acknowledged mutation', async t => {
  const f = await fixture(t); const p = await f.protocol(async request => {
    if (request.operation === 'create-conversation') {
      const response = await f.transport.send(request); await rejected(f.transport.send(request)); return response;
    }
    if (request.operation === 'create-seed') throw new Error('Bounded single-mutation test stops.');
  });
  await assert.rejects(p.run(), PROTOCOL); assert.equal(f.state.requests, 1); assert.equal(f.transport.summary().acceptedResponses, 1);
});

test('a transport already bound to one protocol rejects a second genuinely branded protocol without dispatch', async t => {
  const f = await fixture(t);
  const a = await f.protocol(request => { if (request.operation === 'create-seed') throw new Error('Stop first protocol.'); });
  await assert.rejects(a.run(), PROTOCOL); assert.equal(f.state.requests, 1);
  const b = await f.protocol(); await assert.rejects(b.run(), PROTOCOL);
  assert.equal(f.state.requests, 1); assert.equal(f.transport.summary().dispatched, 1);
});

test('closed and expired factory issuers cannot authorize new HTTPS requests', async t => {
  const a = await fixture(t); await a.issuer.close(); await failedRun(a); assert.equal(a.state.requests, 0);
  const b = await fixture(t); const now = Date.now(); const mock = t.mock.method(Date, 'now', () => now + 120001);
  try { await failedRun(b); assert.equal(b.state.requests, 0); } finally { mock.mock.restore(); }
});

test('ownership rejection before dispatch is sanitized and cannot turn into a retry', async t => {
  const f = await fixture(t, { owner() { throw new Error('private-container-identity-and-token'); } });
  await failedRun(f); assert.equal(f.state.requests, 0); assert.equal(f.transport.summary().dispatched, 0);
});

test('an ownership boolean is not accepted as a trusted callback acknowledgement', async t => {
  const f = await fixture(t, { owner() { return true; } }); await failedRun(f); assert.equal(f.state.requests, 0);
});

test('post-response ownership loss prevents accepting an already acknowledged remote mutation', async t => {
  const f = await fixture(t, { owner(lease, state) { if (state.ownershipChecks === 3) throw new Error('private-post-response-replacement'); } });
  await failedRun(f); assert.equal(f.state.requests, 1);
  assert.deepEqual([f.transport.summary().dispatched, f.transport.summary().tlsResponses, f.transport.summary().acceptedResponses], [1, 1, 0]);
});

test('never-settling ownership check is bounded and its late resolution cannot dispatch after the whole-send deadline', async t => {
  const gate = deferred(); const f = await fixture(t, { owner() { return gate.promise; } }); const start = performance.now();
  await failedRun(f); const elapsed = performance.now() - start; assert.ok(elapsed >= 1700 && elapsed < 4000);
  gate.resolve(); await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.state.requests, 0); assert.equal(f.transport.summary().dispatched, 0); assert.equal(f.transport.summary().busy, false);
});

test('nonresponding real HTTPS endpoint is bounded by the whole-send deadline and never retried', async t => {
  const f = await fixture(t, { respond() {} }); const start = performance.now(); await failedRun(f);
  const elapsed = performance.now() - start; assert.ok(elapsed >= 1700 && elapsed < 4000);
  assert.equal(f.state.requests, 1); assert.equal(f.transport.summary().acceptedResponses, 0);
});

test('the cumulative ownership and HTTPS response time cannot exceed the whole-send deadline even when each stage is shorter', async t => {
  const timers = new Set(); const late = deferred();
  const delay = () => new Promise(resolve => {
    const timer = setTimeout(() => { timers.delete(timer); resolve(); }, 1100); timers.add(timer);
  });
  t.after(() => { for (const timer of timers) clearTimeout(timer); });
  const f = await fixture(t, {
    async owner(lease, state) { if (state.ownershipChecks === 1) await delay(); },
    async respond(req, res) { await delay(); try { json(res, { conversation_id: CONVERSATION }); } finally { late.resolve(); } },
  });
  const start = performance.now(); await failedRun(f); const elapsed = performance.now() - start;
  assert.ok(elapsed >= 1700 && elapsed < 3000); assert.equal(f.state.requests, 1);
  await late.promise; assert.equal(f.transport.summary().acceptedResponses, 0);
  assert.equal(f.transport.summary().failed, true); assert.equal(f.transport.summary().busy, false);
});

for (const operation of ['transport-close', 'protocol-cancel', 'protocol-close']) {
  test(`${operation} interrupts a real partial HTTPS response without accepting or replaying it`, async t => {
    const entered = deferred(); const f = await fixture(t, { respond(req, res) {
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': 300 }); res.write('{'); entered.resolve();
    } });
    const p = await f.protocol(); const running = p.run(); const outcome = assert.rejects(running, PROTOCOL); await entered.promise;
    const start = performance.now(); let closing;
    if (operation === 'transport-close') f.transport.close();
    else if (operation === 'protocol-cancel') p.cancel();
    else closing = p.close().catch(() => {});
    await outcome; await closing;
    assert.ok(performance.now() - start < 1000); assert.equal(f.state.requests, 1);
    assert.equal(f.transport.summary().acceptedResponses, 0); assert.equal(f.state.helperClosed, true);
  });
}

for (const operation of ['transport-close', 'protocol-cancel']) {
  test(`${operation} interrupts ownership wait and prevents late callback dispatch`, async t => {
    const entered = deferred(); const gate = deferred();
    const f = await fixture(t, { owner() { entered.resolve(); return gate.promise; } });
    const p = await f.protocol(); const outcome = assert.rejects(p.run(), PROTOCOL); await entered.promise;
    const start = performance.now(); operation === 'transport-close' ? f.transport.close() : p.cancel(); await outcome;
    assert.ok(performance.now() - start < 1000); gate.resolve(); await new Promise(resolve => setImmediate(resolve));
    assert.equal(f.state.requests, 0); assert.equal(f.transport.summary().dispatched, 0); assert.equal(f.state.helperClosed, true);
  });
}

test('concurrent transport send rejects the second operation while preserving the first acknowledged response', async t => {
  const entered = deferred(); const release = deferred();
  const f = await fixture(t, { async respond(req, res) { entered.resolve(); await release.promise; json(res, { conversation_id: CONVERSATION }); } });
  const p = await f.protocol(async request => {
    if (request.operation === 'create-conversation') {
      const first = f.transport.send(request); await entered.promise; await rejected(f.transport.send(request)); release.resolve(); return first;
    }
    if (request.operation === 'create-seed') throw new Error('Single-response concurrency check ends.');
  });
  await assert.rejects(p.run(), PROTOCOL); assert.equal(f.state.requests, 1); assert.equal(f.transport.summary().acceptedResponses, 1);
});
