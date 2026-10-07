/** Local private-helper/source fixtures only. No Docker, actual Pol.is/PG,
 * fixed /run file, container entrypoint or production configuration is used.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, writeFile, rm, symlink, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash, X509Certificate } from 'node:crypto';
import { createServer } from 'node:https';
import { createRequire } from 'node:module';

const SOURCE = new URL('./bootstrap-container-run.mjs', import.meta.url);
const require = createRequire(new URL('../../../server/package.json', import.meta.url));
const ts = require('typescript');
const ns = 'a'.repeat(24);
const sha = b => createHash('sha256').update(b).digest('hex');
const seeds = JSON.parse(await readFile(new URL('../seed-statements.json', import.meta.url), 'utf8'));
async function exposed(t) {
  const directory = await mkdtemp(join(tmpdir(), 'fncp-container-run-source-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  let source = await readFile(SOURCE, 'utf8');
  source = source.replace(/from '(\.{1,2}\/[^']+)'/gu, (_whole, relative) => `from ${JSON.stringify(new URL(relative, SOURCE).href)}`);
  // Expose private pure/parser/transport helpers in this NEW test copy only.
  // Neither main dispatch nor the Linux/UID/fixed-path guard is replaced.
  source += '\nexport {launchValue, canonical, environment, requestAt, acceptAt, readFixed, send, jwksDiagnostics};\n';
  await writeFile(join(directory, 'test-module.mjs'), source, { mode: 0o600, flag: 'wx' });
  return { directory, ...(await import(pathToFileURL(join(directory, 'test-module.mjs')).href)) };
}
async function certificate(t, names = `IP:127.0.0.1,DNS:fncp-fresh-pg-${ns}`) {
  const directory = await mkdtemp(join(tmpdir(), 'fncp-container-run-cert-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const executable = process.platform === 'darwin' ? '/opt/homebrew/bin/openssl' : '/usr/bin/openssl';
  const child = spawnSync(executable, ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
    '-noenc', '-days', '1', '-subj', '/CN=synthetic.invalid', '-addext', 'subjectAltName=' + names,
    '-keyout', join(directory, 'key.pem'), '-out', join(directory, 'cert.pem')], {
    env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C', OPENSSL_CONF: '/dev/null' },
    stdio: ['ignore', 'pipe', 'pipe'], shell: false, timeout: 5000, maxBuffer: 8192,
  });
  assert.equal(child.status, 0); assert.equal(child.error, undefined);
  const cert = await readFile(join(directory, 'cert.pem'), 'utf8');
  return { cert, key: await readFile(join(directory, 'key.pem')), pin: sha(new X509Certificate(cert).raw) };
}
const launch = cert => ({ namespaceId: ns, database: 'fncp_fresh_' + 'b'.repeat(24), user: 'fncp_fresh_' + 'c'.repeat(24),
  password: 'd'.repeat(64), databaseCertificatePem: cert.cert, databaseCertificateSha256: cert.pin });
const bytes = value => Buffer.from(JSON.stringify(value));
function journey(api) {
  const binding = { statementIds: [] };
  api.acceptAt(0, { conversation_id: '3FreshCliFixture' }, binding, seeds);
  for (let i = 1; i < 16; i++) api.acceptAt(i, { tid: i * 3, currentPid: 7 }, binding, seeds);
  return binding;
}
const rows = binding => seeds.map((txt, i) => ({ conversation_id: binding.conversationId, tid: binding.statementIds[i], pid: 7,
  txt, is_seed: true, mod: 1, active: true, agree_count: 0, disagree_count: 0, pass_count: 1, count: 1 }));
const closed = binding => ({ conversation_id: binding.conversationId, is_owner: true, is_active: false,
  use_xid_whitelist: true, xid_required: true, is_data_open: false, strict_moderation: true, is_anon: true,
  is_draft: false, topics_enabled: false, treevite_enabled: false, profanity_filter: false, spam_filter: false });
async function endpoint(t, cert, handler) {
  const sockets = new Set(); let received = 0;
  const server = createServer({ key: cert.key, cert: cert.cert }, (req, res) => { received++; handler(req, res); });
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  server.on('tlsClientError', () => {});
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  t.after(() => new Promise((resolve, reject) => {
    server.close(error => error ? reject(error) : resolve()); for (const socket of sockets) socket.destroy();
  }));
  return { config: { origin: `https://127.0.0.1:${server.address().port}`, certificatePem: cert.cert, certificateSha256: cert.pin },
    received: () => received };
}

test('canonical launch requires the exact six fields and matching dual-IP/DNS pinned leaf', async t => {
  const api = await exposed(t); const cert = await certificate(t); const value = launch(cert);
  assert.deepEqual(api.launchValue(bytes(value)), value); assert.ok(Object.isFrozen(api.launchValue(bytes(value))));
  assert.deepEqual(api.launchValue(Buffer.from(JSON.stringify(value) + '\n')), value);
  for (const name of Object.keys(value)) { const bad = { ...value }; delete bad[name]; assert.throws(() => api.launchValue(bytes(bad))); }
  for (const extra of ['port', 'host', 'apiOrigin', 'keyPath', 'dockerId']) assert.throws(() => api.launchValue(bytes({ ...value, [extra]: 'private' })));
  for (const [name, replacement] of [['namespaceId', 'f'.repeat(24)], ['database', 'retained'], ['user', 'postgres'],
    ['password', 'short'], ['databaseCertificateSha256', '0'.repeat(64)]]) assert.throws(() => api.launchValue(bytes({ ...value, [name]: replacement })));
});
test('single-IP-only or single-DNS-only database certificates cannot satisfy the real shared role', async t => {
  const api = await exposed(t);
  for (const names of ['IP:127.0.0.1', `DNS:fncp-fresh-pg-${ns}`]) {
    const cert = await certificate(t, names); assert.throws(() => api.launchValue(bytes(launch(cert))));
  }
});
test('JSON normalization cannot hide duplicates, BOM, NBSP, malformed UTF8 or pretty-printed launch', async t => {
  const api = await exposed(t); const cert = await certificate(t); const value = launch(cert); const text = JSON.stringify(value);
  for (const raw of ['\uFEFF' + text, '\u00A0' + text, JSON.stringify(value, null, 2),
    text.replace('{', '{"namespaceId":"wrong",')]) assert.throws(() => api.launchValue(Buffer.from(raw)));
  assert.throws(() => api.launchValue(Buffer.concat([Buffer.from([0xff]), Buffer.from(text)])));
  assert.deepEqual(api.canonical(' \t\r\n{"safe":true}\r\n'), { safe: true });
});
test('generated child profile is exact33 fields and passes the existing pure profile validator', async t => {
  const api = await exposed(t); const cert = await certificate(t);
  const value = api.environment(launch(cert), 'https://127.0.0.1:23456/', { certificateSha256: 'e'.repeat(64) }, '1'.repeat(64), '2'.repeat(64));
  const source = await readFile(new URL('../../../server/src/auth/fncp-bootstrap-startup.ts', import.meta.url), 'utf8');
  const transpiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS } }).outputText;
  const filename = join(api.directory, 'profile.cjs'); await writeFile(filename, transpiled, { mode: 0o600, flag: 'wx' });
  const validator = require(filename).freshBootstrapStartup;
  assert.equal(Object.keys(value).length, 33); assert.equal(validator(value).namespaceId, ns); assert.ok(Object.isFrozen(value));
  assert.equal(value.JWT_PRIVATE_KEY_PATH, '/run/fncp/bootstrap/participant-private.pem');
  assert.equal(value.JWKS_URI, `https://fncp-fresh-jwks-${ns}:8444/.well-known/jwks.json`);
  assert.equal(value.PATH, '/usr/bin:/bin'); assert.equal(value.NODE_OPTIONS, undefined);
});
test('exact19 request plan has one create,15 seeds,read-before-closePUT,and final closed read', async t => {
  const api = await exposed(t); const binding = journey(api);
  const requests = Array.from({ length: 19 }, (_, step) => api.requestAt(step, binding, seeds));
  assert.deepEqual(requests.map(value => value.method), ['POST', ...Array(15).fill('POST'), 'GET', 'PUT', 'GET']);
  assert.equal(requests[0].path, '/api/v3/conversations');
  assert.equal(requests[0].body.spam_filter, false); assert.equal(requests[0].body.is_data_open, false);
  for (let i = 1; i < 16; i++) assert.deepEqual(requests[i], { method: 'POST', path: '/api/v3/comments',
    body: { conversation_id: binding.conversationId, txt: seeds[i - 1], is_seed: true } });
  assert.equal(requests[16].path, `/api/v3/comments?conversation_id=${binding.conversationId}&moderation=true&include_voting_patterns=true`);
  assert.deepEqual(requests[17].body, { conversation_id: binding.conversationId, is_active: false,
    use_xid_whitelist: true, xid_required: true, send_created_email: false });
  assert.equal(requests[18].path, `/api/v3/conversations?conversation_id=${binding.conversationId}`);
  for (const invalid of [-1, 19, 1.1, '1']) assert.throws(() => api.requestAt(invalid, binding, seeds));
});
test('response binding captures nonsequentialactualIDs and stable owner PID without positional assumptions', async t => {
  const api = await exposed(t); const binding = journey(api);
  assert.deepEqual(binding.statementIds, Array.from({ length: 15 }, (_, i) => (i + 1) * 3)); assert.equal(binding.seedOwnerPid, 7);
  api.acceptAt(16, rows(binding).reverse(), binding, seeds);
  api.acceptAt(17, { conversation_id: binding.conversationId }, binding, seeds);
  api.acceptAt(18, closed(binding), binding, seeds);
});
test('invalid conversation IDs,duplicate statement IDs and owner changes are rejected', async t => {
  const api = await exposed(t);
  for (const id of ['retained', '9fncpBootstrap' + 'a'.repeat(48), '3bad?query', '3tiny'])
    assert.throws(() => api.acceptAt(0, { conversation_id: id }, { statementIds: [] }, seeds));
  const binding = { statementIds: [] }; api.acceptAt(0, { conversation_id: '3FreshCliFixture' }, binding, seeds);
  api.acceptAt(1, { tid: 99, currentPid: 7 }, binding, seeds);
  for (const body of [{ tid: 99, currentPid: 7 }, { tid: 101, currentPid: 8 }, { tid: -0, currentPid: 7 },
    { tid: 101, currentPid: '7' }, { tid: 2147483648, currentPid: 7 }]) assert.throws(() => api.acceptAt(2, body, binding, seeds));
});
test('seed readback requires every exact text/ID/PID/count and rejects foreign or duplicate rows', async t => {
  const api = await exposed(t); const binding = journey(api);
  for (const [key, value] of [['conversation_id', '3Different'], ['pid', 9], ['txt', 'not the pinned seed'], ['is_seed', false],
    ['mod', 0], ['active', false], ['agree_count', 1], ['disagree_count', 1], ['pass_count', 0], ['count', 2]]) {
    const body = rows(binding); body[0][key] = value; assert.throws(() => api.acceptAt(16, body, binding, seeds));
  }
  const duplicate = rows(binding); duplicate[1] = duplicate[0]; assert.throws(() => api.acceptAt(16, duplicate, binding, seeds));
  assert.throws(() => api.acceptAt(16, rows(binding).slice(1), binding, seeds));
});
test('final state does not accept missing,open,unguarded or wrong-conversation flags', async t => {
  const api = await exposed(t); const binding = journey(api);
  for (const key of Object.keys(closed(binding))) {
    const absent = closed(binding); delete absent[key]; assert.throws(() => api.acceptAt(18, absent, binding, seeds));
    const wrong = closed(binding); wrong[key] = typeof wrong[key] === 'boolean' ? !wrong[key] : '3Different';
    assert.throws(() => api.acceptAt(18, wrong, binding, seeds));
  }
});
test('bounded fixed-file reader rejects fresh symlinks,directories and oversizedpublicsource', async t => {
  const api = await exposed(t); const file = join(api.directory, 'fresh.txt');
  await writeFile(file, 'public', { mode: 0o600, flag: 'wx' }); assert.equal((await api.readFixed(file, 32, false)).bytes.toString(), 'public');
  const link = join(api.directory, 'link'); await symlink(file, link); await assert.rejects(api.readFixed(link, 32, false));
  const directory = join(api.directory, 'folder'); await mkdir(directory); await assert.rejects(api.readFixed(directory, 32, false));
  await assert.rejects(api.readFixed(file, 5, false));
});
test('real fresh TLS transport sends fixed canonical bytes after exact peer-pin verification', async t => {
  const api = await exposed(t); const cert = await certificate(t); let receivedBody = '', receivedHeaders;
  const server = await endpoint(t, cert, (req, res) => { receivedHeaders = req.headers; req.on('data', chunk => { receivedBody += chunk; });
    req.on('end', () => { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"conversation_id":"3FreshCliFixture"}'); }); });
  const descriptor = api.requestAt(0, {}, seeds); const aborter = new AbortController();
  const body = await api.send(server.config, descriptor, 'invented-local-test-bearer', aborter.signal, () => {});
  assert.deepEqual(body, { conversation_id: '3FreshCliFixture' }); assert.equal(receivedBody, JSON.stringify(descriptor.body));
  assert.equal(receivedHeaders.authorization, 'Bearer invented-local-test-bearer'); assert.equal(server.received(), 1);
});
test('wrong exactleaf pin rejects before the synthetic server receives any bearer HTTP request', async t => {
  const api = await exposed(t); const cert = await certificate(t);
  const server = await endpoint(t, cert, (_req, res) => { res.end('{}'); });
  await assert.rejects(api.send({ ...server.config, certificateSha256: '0'.repeat(64) }, api.requestAt(0, {}, seeds),
    'invented-local-test-bearer', new AbortController().signal, () => {}));
  assert.equal(server.received(), 0);
});
test('all19 canonical HTTPS requests complete against a fresh synthetic response model only', async t => {
  const api = await exposed(t); const cert = await certificate(t); const expected = journey(api);
  let step = 0; const requests = [];
  const server = await endpoint(t, cert, (req, res) => {
    const chunks = []; req.on('data', chunk => chunks.push(chunk)); req.on('end', () => {
      const raw = Buffer.concat(chunks).toString(); const n = step++;
      requests.push({ method: req.method, path: req.url, body: raw ? JSON.parse(raw) : null });
      const body = n === 0 || n === 17 ? { conversation_id: expected.conversationId } : n < 16 ?
        { tid: expected.statementIds[n - 1], currentPid: expected.seedOwnerPid } : n === 16 ? rows(expected).reverse() : closed(expected);
      res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(body));
    });
  });
  const actual = { statementIds: [] }; const signal = new AbortController().signal;
  for (let n = 0; n < 19; n++) {
    const descriptor = api.requestAt(n, actual, seeds);
    const body = await api.send(server.config, descriptor, 'invented-local-test-bearer', signal, () => {});
    api.acceptAt(n, body, actual, seeds);
    assert.deepEqual(requests[n], descriptor);
  }
  assert.equal(server.received(), 19); assert.deepEqual(actual, expected);
  // This fixture never invokes the actual CLI, Pol.is application or SQL worker.
});
test('redirect,nonJSON,encoded and noncanonical responses fail without following any extra route', async t => {
  const api = await exposed(t); const cert = await certificate(t);
  for (const [status, headers, body] of [[302, { location: 'https://external.invalid' }, '{}'],
    [200, { 'content-type': 'text/plain' }, '{}'], [200, { 'content-type': 'application/json', 'content-encoding': 'gzip' }, '{}'],
    [200, { 'content-type': 'application/json' }, '\uFEFF{}'], [200, { 'content-type': 'application/json' }, '{"x":1,"x":2}']]) {
    const server = await endpoint(t, cert, (_req, res) => { res.writeHead(status, headers); res.end(body); });
    await assert.rejects(api.send(server.config, api.requestAt(0, {}, seeds), 'invented-local-test-bearer', new AbortController().signal, () => {}));
    assert.equal(server.received(), 1);
  }
});
test('cancelled pending TLS response and failed post-response activity check cannot be accepted', async t => {
  const api = await exposed(t); const cert = await certificate(t); const aborter = new AbortController();
  const server = await endpoint(t, cert, (_req, _res) => aborter.abort());
  await assert.rejects(api.send(server.config, api.requestAt(0, {}, seeds), 'invented-local-test-bearer', aborter.signal, () => {
    if (aborter.signal.aborted) throw new Error('private cancelled');
  }));
  let checks = 0;
  const good = await endpoint(t, cert, (_req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{}'); });
  await assert.rejects(api.send(good.config, api.requestAt(0, {}, seeds), 'invented-local-test-bearer', new AbortController().signal,
    () => { if (++checks === 4) throw new Error('private post-response'); }));
});
test('direct CLI rejects execution flags before touching fixedlaunch,DB,issuer or actual app', () => {
  const child = spawnSync(process.execPath, ['--no-warnings', fileURLToPath(SOURCE)], {
    env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' }, stdio: ['ignore', 'pipe', 'pipe'], timeout: 10000, maxBuffer: 4096,
  });
  assert.equal(child.status, 1); assert.equal(child.stderr.toString(), '');
  const summary = JSON.parse(child.stdout); assert.equal(summary.phase, 'PLATFORM'); assert.equal(summary.outcome, 'FAIL');
  assert.equal(summary.httpRequestsAttempted, 0); assert.equal(summary.actualPolisAppExecuted, false);
  assert.equal(summary.containerOwnershipVerified, false); assert.equal(summary.roundOpen, 'UNVERIFIED');
  assert.equal(summary.jwksServedRequests, null); assert.equal(summary.jwksRejectedRequests, null); assert.equal(summary.jwksTlsErrors, null);
});
test('cancellation during any admitted key write prevents later writes and issuer creation', async () => {
  const source = await readFile(SOURCE, 'utf8');
  // Execute the actual source stage verbatim with invented key bytes and held
  // write callbacks, not the Linux CLI or any fixed filesystem location.
  const start = source.indexOf('    const key = Buffer.from(pair.privateKey.export');
  const end = source.indexOf("    phase = 'API_START';", start);
  assert.ok(start > 0 && end > start);
  const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
  const stage = new AsyncFunction('pair', 'check', 'exclusive', 'createBootstrapIssuer',
    'createBootstrapContainerJwksService', 'launch', 'randomBytes',
    'let phase, keysGenerated, issuerAttempted, issuer, jwksAttempted, jwks;\n' + source.slice(start, end));
  for (const heldWrite of [1, 2, 3]) {
    let cancelled = false, writes = 0, issuers = 0, release, admitted;
    const entered = new Promise(resolve => { admitted = resolve; });
    const held = new Promise(resolve => { release = resolve; });
    const pending = stage({ privateKey: { export: () => 'invented private fixture' }, publicKey: { export: () => 'invented public fixture' } },
      () => { if (cancelled) throw new Error('synthetic cancellation'); },
      async () => { if (++writes === heldWrite) { admitted(); await held; } },
      async () => { issuers++; throw new Error('issuer must not be created'); },
      async () => { throw new Error('JWKS must not be created'); },
      { databaseCertificatePem: 'invented cert' }, () => { throw new Error('randomness must not be requested'); });
    await entered; cancelled = true; release(); await assert.rejects(pending);
    assert.equal(writes, heldWrite); assert.equal(issuers, 0);
  }
});
test('source binds real execution to directLinuxUID1000,no inheritedenv/no retries and exclusive private attempts', async t => {
  const api = await exposed(t);
  assert.deepEqual(api.jwksDiagnostics(undefined), { jwksServedRequests: null, jwksRejectedRequests: null, jwksTlsErrors: null });
  assert.deepEqual(api.jwksDiagnostics({ servedRequests: 0, rejectedRequests: 0, tlsErrors: 0 }),
    { jwksServedRequests: 0, jwksRejectedRequests: 0, jwksTlsErrors: 0 });
  const counts = api.jwksDiagnostics({ servedRequests: 1, rejectedRequests: 2, tlsErrors: 3, privateToken: 'must-not-escape' });
  assert.deepEqual(counts, { jwksServedRequests: 1, jwksRejectedRequests: 2, jwksTlsErrors: 3 }); assert.ok(Object.isFrozen(counts));
  for (const bad of [null, '0', -1, -0, 0.5, Number.MAX_SAFE_INTEGER + 1])
    assert.throws(() => api.jwksDiagnostics({ servedRequests: bad, rejectedRequests: 0, tlsErrors: 0 }));
  const source = await readFile(SOURCE, 'utf8');
  assert.match(source, /process\.platform !== 'linux' \|\| process\.getuid\?\.\(\) !== 1000/u);
  assert.match(source, /pathToFileURL\(resolve\(process\.argv\[1\]\)\)\.href === import\.meta\.url/u);
  assert.match(source, /ROOT \+ '\/attempt\.jsonl', constants\.O_WRONLY \| constants\.O_CREAT \| constants\.O_EXCL \| constants\.O_NOFOLLOW/u);
  assert.match(source, /holderContainerStopped: false, databaseProcessStopped: false, containerOwnershipVerified: false/u);
  assert.match(source, /roundOpen: closedReadback \? false : 'UNVERIFIED'/u);
  assert.ok(source.indexOf("phase = 'SCHEMA'") < source.indexOf('issuer = await createBootstrapIssuer()'));
  assert.ok(source.indexOf("await record('HTTP_ATTEMPTED_NO_REPLAY'") < source.indexOf('const body = await send('));
  assert.doesNotMatch(source, /process\.env|claimBootstrapIssuerForTransport|createBootstrapProtocol|runDocker|execSync|console\./u);
});
