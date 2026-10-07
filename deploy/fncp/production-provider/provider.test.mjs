import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { connect } from 'node:net';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, realpathSync, chmodSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { createProductionPolisProvider, isProductionPolisProvider } from './provider.mjs';
const unavailable = { message: 'Provider unavailable.' };
const invalid = { message: 'Invalid provider operation.' };
const xid = 'fncp_' + 'x'.repeat(43);
function certificate(wrongHost = false) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), 'fncp-private-provider-test-'))); chmodSync(dir, 0o700);
  try {
    const r = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-noenc', '-days', '1',
      '-subj', '/CN=FNCP invented private provider', '-addext', 'basicConstraints=critical,CA:TRUE',
      '-addext', wrongHost ? 'subjectAltName=DNS:wrong.example.invalid' : 'subjectAltName=IP:127.0.0.1',
      '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'ca.pem')], { timeout: 10000, maxBuffer: 8192, stdio: ['ignore', 'pipe', 'pipe'] });
    if (r.status !== 0) throw Error('Synthetic certificate generation failed.');
    return { key: readFileSync(join(dir, 'key.pem')), cert: readFileSync(join(dir, 'ca.pem')) };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}
async function fixture(t, wrongHost = false) {
  const tls = certificate(wrongHost), calls = [], sockets = new Set(), providers = [];
  let behavior = 'normal', version = null, override;
  const comment = { tid: 0, txt: 'Invented fixed statement.', remaining: 15, total: 15, currentPid: 9, email: 'private@example.invalid', arbitrary: { secret: 'hidden' } };
  const server = createServer(tls, async (req, res) => {
    req.on('error', () => {}); res.on('error', () => {});
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString('utf8');
    calls.push({ path: req.url, method: req.method, headers: req.headers, body: raw ? JSON.parse(raw) : undefined });
    if (behavior === 'stall') return;
    if (behavior === 'stalled-body') { res.writeHead(200, { 'content-type': 'application/json' }); res.write('{'); return; }
    if (behavior === 'redirect') { res.writeHead(302, { 'content-type': 'application/json', location: '/forbidden' }); res.end('{}'); return; }
    if (behavior === 'oversized') { res.writeHead(200, { 'content-type': 'application/json' }); res.end('x'.repeat(262145)); return; }
    if (behavior === 'compressed') { res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'gzip' }); res.end('{}'); return; }
    if (behavior === 'html') { res.writeHead(200, { 'content-type': 'text/html' }); res.end('sensitive upstream error'); return; }
    if (behavior === 'truncated') { res.writeHead(200, { 'content-type': 'application/json', 'content-length': 100 }); res.write('{'); res.flushHeaders(); setImmediate(() => res.destroy()); return; }
    if (behavior === 'deny') { res.writeHead(403, { 'content-type': 'application/json' }); res.end(JSON.stringify({ error: 'sensitive upstream description' })); return; }
    let body = override;
    if (req.url.endsWith('/upsert') || req.url.endsWith('/remove')) {
      if (req.url.endsWith('/upsert') && version !== 2) version = 1;
      if (req.url.endsWith('/remove')) version = 2;
      res.writeHead(204); res.end(); return;
    }
    if (body === undefined) body = req.url.endsWith('/readback') ? { conversationId: '9fixedConversation', participantXid: xid, operationVersion: version, present: version === 1 }
      : req.url.startsWith('/api/v3/nextComment') ? comment
        : { nextComment: comment, votes: [{ tid: 1, vote: -1, pid: 99 }], conversation: { conversation_id: '9fixedConversation', owner: 'private' },
          auth: { token: 'private' }, ptpt: { pid: 1 }, user: { email: 'private' }, pca: { private: true }, famous: { private: true } };
    res.writeHead(200, { 'content-type': 'application/json', 'set-cookie': 'never=forward' }); res.end(JSON.stringify(body));
  });
  server.on('connection', s => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const options = { origin: `https://127.0.0.1:${port}`, conversationId: '9fixedConversation', statementIds: Array.from({ length: 15 }, (_, i) => i),
    gatewaySecret: 'g'.repeat(43), providerSecret: 'p'.repeat(43), ca: tls.cert };
  t.after(async () => {
    for (const p of providers) p.close(); for (const s of sockets) s.destroy();
    await new Promise(resolve => server.close(resolve));
    await new Promise((resolve, reject) => { const s = connect({ host: '127.0.0.1', port });
      s.once('connect', () => { s.destroy(); reject(Error('Owned listener remained open')); });
      s.once('error', e => e.code === 'ECONNREFUSED' ? resolve() : reject(e)); });
  });
  return { options, calls, setBehavior: b => { behavior = b; }, setBody: b => { override = b; },
    create(overrides = {}) { const p = createProductionPolisProvider({ ...options, ...overrides }); providers.push(p); return p; } };
}

test('actual HTTPS fixed routes separate credentials and version2 tombstone readback, with no generic transport', async t => {
  const h = await fixture(t), p = h.create(); assert.ok(isProductionPolisProvider(p)); assert.ok(Object.isFrozen(p));
  assert.equal(isProductionPolisProvider({ ...p }), false); assert.equal(p.request, undefined); assert.equal(p.gatewaySecret, undefined);
  await p.allowlist('upsert', xid); assert.equal((await p.allowlist('readback', xid)).operationVersion, 1);
  await p.allowlist('remove', xid); const read = await p.allowlist('readback', xid); assert.equal(read.present, false); assert.equal(read.operationVersion, 2);
  const expected = { tid: 0, txt: 'Invented fixed statement.', remaining: 15, total: 15 };
  assert.deepEqual(await p.participate('init', xid), { nextComment: expected, votes: [{ tid: 1, vote: -1 }] });
  assert.deepEqual(await p.participate('next', xid), expected);
  assert.deepEqual(await p.participate('vote', xid, { tid: 0, vote: 1 }), { nextComment: expected });
  for (const c of h.calls) {
    assert.equal(c.headers.cookie, undefined); assert.equal(c.headers.origin, undefined); assert.equal(c.headers['x-forwarded-proto'], undefined);
    if (c.path.startsWith('/fncp/private/')) { assert.equal(c.headers.authorization, 'Bearer ' + 'p'.repeat(43)); assert.equal(c.headers['x-fncp-gateway-key'], undefined); }
    else { assert.equal(c.headers.authorization, undefined); assert.equal(c.headers['x-fncp-gateway-key'], 'g'.repeat(43)); assert.equal(c.headers['x-fncp-participant-xid'], xid); }
  }
  assert.equal(h.calls[0].body.operationVersion, 1); assert.equal(h.calls[2].body.operationVersion, 2);
  assert.match(h.calls[0].headers['idempotency-key'], /^allow-[a-f0-9]{64}$/); assert.match(h.calls[2].headers['idempotency-key'], /^remove-[a-f0-9]{64}$/);
});

for (const mode of ['wrong-ca', 'no-ca', 'wrong-hostname', 'environment-bypass']) test(`native HTTPS rejects ${mode} before any HTTP request`, async t => {
  const h = await fixture(t, mode === 'wrong-hostname'); const other = certificate();
  const p = h.create(mode === 'no-ca' ? { ca: undefined } : mode === 'wrong-ca' || mode === 'environment-bypass' ? { ca: other.cert } : {});
  const before = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  try {
    if (mode === 'environment-bypass') process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    await assert.rejects(p.allowlist('readback', xid), unavailable); assert.equal(h.calls.length, 0);
  } finally { if (before === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED; else process.env.NODE_TLS_REJECT_UNAUTHORIZED = before; }
});

test('configuration and operation inputs cannot select routes, headers, IDs, credentials or TLS overrides', async t => {
  const h = await fixture(t), p = h.create();
  for (const o of [{ origin: 'http://127.0.0.1:99' }, { origin: h.options.origin + '/' }, { origin: h.options.origin + '/path' },
    { origin: 'https://user:secret@127.0.0.1' }, { origin: h.options.origin + '?x' }, { fetch() {} }, { rejectUnauthorized: false },
    { gatewaySecret: h.options.providerSecret }, { statementIds: [0] }, { ca: Buffer.from('bad') }]) assert.throws(() => h.create(o), invalid);
  const getter = { ...h.options }; Object.defineProperty(getter, 'origin', { get() { throw Error('must not evaluate'); } });
  assert.throws(() => createProductionPolisProvider(getter), invalid);
  for (const [kind, values] of [['unknown', {}], ['next', { url: '/elsewhere' }], ['vote', { tid: 99, vote: 1 }],
    ['vote', { tid: 0, vote: 2 }], ['vote', { tid: 0, vote: 1, xid }]]) await assert.rejects(p.participate(kind, xid, values), invalid);
  await assert.rejects(p.allowlist('remove-all', xid), invalid); assert.equal(h.calls.length, 0);
  const binding = p.binding(); binding.statementIds[0] = 99; h.options.statementIds[0] = 99; h.options.ca.fill(0);
  assert.equal(p.binding().statementIds[0], 0); await p.participate('next', xid);
});

for (const behavior of ['redirect', 'oversized', 'compressed', 'html', 'truncated']) test(`rejects ${behavior}, without redirect following or leaked error bodies`, async t => {
  const h = await fixture(t), p = h.create(); h.setBehavior(behavior);
  await assert.rejects(p.participate('init', xid), unavailable); assert.equal(h.calls.length, 1);
});

test('generic denial and narrow projection reject inconsistent readback, non-fixed statements and malformed successful bodies', async t => {
  const h = await fixture(t), p = h.create(); h.setBehavior('deny'); await assert.rejects(p.participate('next', xid), { message: 'Participation denied.' });
  h.setBehavior('normal');
  for (const body of [{ conversationId: '9wrongConversation', participantXid: xid, operationVersion: 1, present: true },
    { conversationId: '9fixedConversation', participantXid: xid, operationVersion: 2, present: true }]) {
    h.setBody(body); await assert.rejects(p.allowlist('readback', xid), unavailable);
  }
  for (const body of [{ tid: 99, txt: 'unapproved' }, { error: 'unexpected success error' }, { tid: 0, txt: 'x', total: 21 }, { tid: 0, txt: 'x', total: 14 }]) {
    h.setBody(body); await assert.rejects(p.participate('next', xid), unavailable);
  }
  h.setBody({ error: 'unexpected success error' }); await assert.rejects(p.participate('vote', xid, { tid: 0, vote: 1 }), unavailable);
  h.setBody({}); assert.deepEqual(await p.participate('next', xid), {});
  h.setBody({ nextComment: null, votes: [] }); assert.deepEqual(await p.participate('init', xid), { nextComment: null, votes: [] });
});

test('complete-body deadline bounds a stalled response and never retries a vote', async t => {
  const h = await fixture(t), p = h.create(); h.setBehavior('stalled-body'); const start = performance.now();
  await assert.rejects(p.participate('vote', xid, { tid: 0, vote: 1 }), unavailable);
  assert.ok(performance.now() - start < 6500); assert.equal(h.calls.length, 1);
});

test('32-operation bound, irreversible close and pending cancellation cannot produce a late result', async t => {
  const h = await fixture(t), p = h.create(); h.setBehavior('stall');
  const pending = Array.from({ length: 32 }, () => assert.rejects(p.allowlist('readback', xid), unavailable));
  await assert.rejects(p.allowlist('readback', xid), unavailable); p.close(); p.close(); await Promise.all(pending);
  await assert.rejects(p.participate('next', xid), unavailable); assert.ok(h.calls.length <= 32);
});
