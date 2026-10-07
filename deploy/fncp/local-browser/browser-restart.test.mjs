/** Fresh-process BFF crash proof. Actual local HTTP cookies and CSRF, MODEL
 * fixture authentication/backend only. Never reads or writes saved state.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { fork, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { createConnection } from 'node:net';
import { fileURLToPath } from 'node:url';

const childPath = fileURLToPath(new URL('./restart-proof-child.mjs', import.meta.url));
const random = () => randomBytes(32).toString('base64url');
const check = (condition, label) => assert.equal(condition === true, true, label);

function worker() {
  // Empty environment and execArgv prevent inherited credentials, NODE_OPTIONS,
  // preload hooks and test-runner flags from changing the child fixture.
  const child = fork(childPath, ['--synthetic-bff-restart-proof'], {
    env: {}, execArgv: [], stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
  });
  const pending = new Map(); let sequence = 0; let outputSeen = false;
  for (const stream of [child.stdout, child.stderr]) stream.on('data', () => { outputSeen = true; });
  const exited = new Promise(resolve => child.once('exit', (code, signal) => {
    for (const { reject, timer } of pending.values()) { clearTimeout(timer); reject(new Error('Synthetic child ended before its reply.')); }
    pending.clear(); resolve({ code, signal });
  }));
  child.on('error', () => {
    for (const { reject, timer } of pending.values()) { clearTimeout(timer); reject(new Error('Synthetic child could not start.')); }
    pending.clear();
  });
  child.on('message', message => {
    const request = pending.get(message?.id); if (!request) return;
    pending.delete(message.id); clearTimeout(request.timer);
    if (message.ok !== true) request.reject(new Error('Synthetic child operation failed.'));
    else request.resolve(message);
  });
  async function command(op, values = {}) {
    if (!child.connected || child.exitCode !== null || child.signalCode !== null) throw new Error('Synthetic child is not available.');
    const id = ++sequence;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { pending.delete(id); reject(new Error('Synthetic child reply deadline.')); }, 5000);
      pending.set(id, { resolve, reject, timer });
      child.send({ id, op, ...values }, error => {
        if (error && pending.has(id)) { pending.delete(id); clearTimeout(timer); reject(new Error('Synthetic child IPC failed.')); }
      });
    });
  }
  async function terminate(signal = 'SIGKILL') {
    if (child.exitCode === null && child.signalCode === null) child.kill(signal);
    let timer;
    try { return await Promise.race([exited, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Synthetic child shutdown deadline.')), 5000); })]); }
    finally { clearTimeout(timer); }
  }
  return { command, terminate, exited, pid: child.pid, outputSeen: () => outputSeen };
}

async function request(origin, path, { body, cookie, csrf } = {}) {
  const payload = body === undefined ? undefined : JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = httpRequest(origin + path, { method: payload === undefined ? 'GET' : 'POST', timeout: 3000,
      headers: { 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'same-origin', 'Sec-Fetch-Dest': 'empty',
        ...(cookie ? { Cookie: cookie } : {}), ...(payload === undefined ? {} : { Origin: origin,
          'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload), 'X-CSRF-Token': csrf ?? '' }) } }, res => {
      const chunks = []; let size = 0;
      res.on('data', chunk => { size += chunk.length; if (size > 65536) res.destroy(new Error('Synthetic HTTP reply limit.')); else chunks.push(chunk); });
      res.on('error', () => reject(new Error('Synthetic HTTP reply failed.')));
      res.on('end', () => {
        try { const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          resolve({ status: res.statusCode, body, cookie: res.headers['set-cookie']?.[0]?.split(';')[0], text: JSON.stringify(body) });
        } catch { reject(new Error('Synthetic HTTP reply was invalid.')); }
      });
    });
    req.on('error', () => reject(new Error('Synthetic HTTP request failed.')));
    req.on('timeout', () => req.destroy());
    if (payload !== undefined) req.write(payload); req.end();
  });
}

async function closed(port) {
  return new Promise(resolve => {
    const socket = createConnection({ host: '127.0.0.1', port });
    const finish = result => { socket.removeAllListeners(); socket.destroy(); resolve(result); };
    socket.once('connect', () => finish(false));
    socket.once('error', error => finish(error.code === 'ECONNREFUSED'));
    socket.setTimeout(1000, () => finish(false));
  });
}

test('restart child refuses direct execution without the private test IPC channel', () => {
  const result = spawnSync(process.execPath, [childPath, '--synthetic-bff-restart-proof'], { env: {}, timeout: 3000, encoding: 'utf8' });
  assert.equal(result.status, 1); assert.equal(result.stdout, ''); assert.equal(result.stderr, '');
});

for (const phase of ['visitor', 'authenticated', 'participant']) test(`actual BFF crash/restart rejects a previously live ${phase} cookie on the same origin`, { timeout: 25_000 }, async () => {
  const credentials = { fixtureSecret: random(), invitation: random(), auth: random(), participant: random() };
  const children = []; let port; let origin;
  try {
    const first = worker(); children.push(first);
    const ready = await first.command('start', { port: 0, credentials }); origin = ready.origin;
    check(/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/u.test(origin), 'only an ephemeral loopback listener was started');
    port = Number(new URL(origin).port);
    let result = await request(origin, '/api/session'); assert.equal(result.status, 200);
    let cookie = result.cookie; let csrf = result.body.csrf;
    if (phase !== 'visitor') {
      result = await request(origin, '/api/login', { cookie, csrf, body: { fixture: 'synthetic_restart_fixture', fixtureSecret: credentials.fixtureSecret } });
      assert.equal(result.status, 200); cookie = result.cookie; csrf = result.body.csrf;
    }
    if (phase === 'participant') {
      result = await request(origin, '/api/redeem', { cookie, csrf, body: { invitationToken: credentials.invitation } });
      assert.equal(result.status, 200); cookie = result.cookie; csrf = result.body.csrf;
      assert.equal((await request(origin, '/api/participation-init', { cookie })).status, 200);
      assert.equal((await request(origin, '/api/next-comment', { cookie })).status, 200);
    }
    result = await request(origin, '/api/session', { cookie });
    assert.equal(result.status, 200); assert.equal(result.body.phase, phase);
    check(typeof cookie === 'string' && typeof csrf === 'string' && result.body.csrf === csrf && result.cookie === undefined,
      'the exact retained cookie and CSRF were accepted, not silently replaced');
    // An intentionally incomplete login reaches body validation (400) with the
    // real CSRF, but stops at request verification (403) with an invented one.
    // This proves the retained CSRF passed the actual guard before the crash,
    // without authenticating again, rotating the cookie or dispatching a model.
    assert.equal((await request(origin, '/api/login', { cookie, csrf, body: {} })).status, 400);
    assert.equal((await request(origin, '/api/login', { cookie, csrf: random(), body: {} })).status, 403);
    for (const secret of Object.values(credentials)) check(!result.text.includes(secret), 'backend model authority stayed out of the browser response');
    const prior = (await first.command('counts')).counts;
    assert.deepEqual(prior, phase === 'visitor' ? { calls: 0, loginCalls: 0, protectedCalls: 0, voteCalls: 0 } :
      phase === 'authenticated' ? { calls: 1, loginCalls: 1, protectedCalls: 0, voteCalls: 0 } :
        { calls: 4, loginCalls: 1, protectedCalls: 3, voteCalls: 0 });
    const crash = await first.terminate(); assert.equal(crash.signal, 'SIGKILL');
    check(await closed(port), 'the crashed child listener is closed before replacement');
    const second = worker(); children.push(second);
    const replacement = await second.command('start', { port, credentials });
    check(replacement.pid !== ready.pid && replacement.pid === second.pid, 'replacement is a genuinely different OS process');
    check(replacement.origin === origin, 'the replacement binds the identical origin, not a new port');
    // Seven requests use exact, previously accepted cookie+CSRF, not canaries.
    for (const [path, body] of [
      ['/api/participation-init'], ['/api/next-comment'],
      ['/api/redeem', { invitationToken: credentials.invitation }], ['/api/votes', { tid: 1, vote: 0 }],
      ['/api/login', { fixture: 'synthetic_restart_fixture', fixtureSecret: credentials.fixtureSecret }],
      ['/api/registration', {}], ['/api/logout', {}],
    ]) assert.equal((await request(origin, path, { cookie, csrf, body })).status, 401);
    const visitor = await request(origin, '/api/session', { cookie });
    assert.equal(visitor.status, 200); assert.equal(visitor.body.phase, 'visitor');
    check(typeof visitor.cookie === 'string' && visitor.cookie !== cookie && visitor.body.csrf !== csrf,
      'old cookie is not adopted and fresh visitor authority is independently generated');
    check(visitor.body.registrationEnabled !== true, 'the model does not auto-enable registration');
    assert.equal((await request(origin, '/api/login', { cookie: visitor.cookie, csrf,
      body: { fixture: 'synthetic_restart_fixture', fixtureSecret: credentials.fixtureSecret } })).status, 403);
    const fresh = { cookie: visitor.cookie, csrf: visitor.body.csrf };
    assert.equal((await request(origin, '/api/participation-init', fresh)).status, 403);
    assert.equal((await request(origin, '/api/redeem', { ...fresh, body: { invitationToken: credentials.invitation } })).status, 403);
    assert.equal((await request(origin, '/api/votes', { ...fresh, body: { tid: 1, vote: 0 } })).status, 403);
    assert.equal((await request(origin, '/api/registration', { ...fresh, body: {} })).status, 404);
    assert.deepEqual((await second.command('counts')).counts, { calls: 0, loginCalls: 0, protectedCalls: 0, voteCalls: 0 });
    check((await second.command('stop')).listenerClosed, 'replacement closed through the actual BFF shutdown');
    const ended = await second.exited; assert.equal(ended.code, 0); assert.equal(ended.signal, null);
  } finally {
    for (const child of children) await child.terminate();
    if (port) check(await closed(port), 'every owned listener is closed after the test');
    for (const child of children) check(!child.outputSeen(), 'no child output or invented credentials were printed');
  }
});
