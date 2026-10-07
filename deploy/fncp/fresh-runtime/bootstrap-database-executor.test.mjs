import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, connect } from 'node:net';
import { TLSSocket, createSecureContext, connect as connectTls, checkServerIdentity } from 'node:tls';
import { createHash, randomBytes, X509Certificate } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createBootstrapDatabaseExecutor } from './bootstrap-database-executor.mjs';
import { bootstrapSchemaQuery, bootstrapBaselineQuery, bootstrapDatabaseQueryContract,
  validateBootstrapSchemaResult, validateBootstrapBaselineResult } from './bootstrap-database-contract.mjs';

const ids = [8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987, 1597, 2584, 4181, 2147483647];
const input = () => ({ conversationId: '7freshDatabaseQA', statementIds: [...ids], seedOwnerPid: 23 });
const schema = () => ({ server_major_17: true, transaction_read_only: true, origin_replication_role: true,
  tables_match: true, columns_match: true, unique_keys_match: true, foreign_keys_match: true,
  id_triggers_match: true, vote_rule_present: true, function_signatures_match: true });
const baseline = () => ({ transaction_read_only: true, target_rows: 1, conversation_alias_rows: 1,
  owner_rows: 1, owner_mapping_rows: 1, participant_rows: 1, owner_participant_rows: 1,
  statement_rows: 15, valid_seed_rows: 15, distinct_expected_statement_ids: 15,
  raw_vote_rows: 15, raw_seed_owner_pass_rows: 15, raw_distinct_seed_ids: 15,
  latest_unique_vote_rows: 15, latest_seed_owner_pass_rows: 15, latest_distinct_seed_ids: 15,
  applicable_whitelist_rows: 0, applicable_xid_rows: 0, provider_operation_rows: 0, closed_flags_match: true });
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { resolve, promise }; };
const MESSAGE = 'Fresh bootstrap database execution rejected; private details withheld.';
const rejected = promise => assert.rejects(promise, error => error.message === MESSAGE && error.cause === undefined);
const throws = fn => assert.throws(fn, { message: MESSAGE });
const signal = () => new AbortController().signal;
const SETUP = ['BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY', 'SET LOCAL search_path = pg_catalog',
  'SET LOCAL statement_timeout = 1000', 'SET LOCAL lock_timeout = 250', 'SET LOCAL idle_in_transaction_session_timeout = 2000',
  'SET LOCAL row_security = off'];
const i16 = n => { const b = Buffer.alloc(2); b.writeInt16BE(n); return b; };
const i32 = n => { const b = Buffer.alloc(4); b.writeInt32BE(n); return b; };
const cstr = text => Buffer.from(text + '\0');
const message = (type, ...parts) => { const body = Buffer.concat(parts); return Buffer.concat([Buffer.from(type), i32(body.length + 4), body]); };
function stringAt(bytes, cursor) { const end = bytes.indexOf(0, cursor.offset); assert.ok(end >= cursor.offset); const value = bytes.toString('utf8', cursor.offset, end); cursor.offset = end + 1; return value; }
function rowDescription(columns) {
  return message('T', i16(columns.length), ...columns.map(({ name, dataTypeID }) =>
    Buffer.concat([cstr(name), i32(0), i16(0), i32(dataTypeID), i16(dataTypeID === 16 ? 1 : 4), i32(-1), i16(0)])));
}
function dataRow(columns, row) {
  return message('D', i16(columns.length), ...columns.map(({ name }) => {
    const value = row[name]; if (value === null) return i32(-1);
    const text = typeof value === 'boolean' ? value ? 't' : 'f' : String(value); const bytes = Buffer.from(text);
    return Buffer.concat([i32(bytes.length), bytes]);
  }));
}
async function certificate(t, alternateLeaf = false) {
  const directory = await mkdtemp(join(tmpdir(), 'fncp-database-wire-tls-test-'));
  await chmod(directory, 0o700); t.after(() => rm(directory, { recursive: true, force: true }));
  const keyPath = join(directory, 'owned-key.pem'); const certPath = join(directory, 'owned-cert.pem');
  const openssl = args => spawnSync('/opt/homebrew/bin/openssl', args, { cwd: directory, shell: false,
    stdio: ['ignore', 'pipe', 'pipe'], timeout: 10000, maxBuffer: 8192,
    env: { PATH: '/opt/homebrew/bin:/usr/bin:/bin', LANG: 'C', LC_ALL: 'C', OPENSSL_CONF: '/dev/null' } });
  assert.equal(openssl(['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-noenc',
    '-days', '1', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1',
    '-addext', 'basicConstraints=critical,CA:TRUE', '-keyout', keyPath, '-out', certPath]).status, 0, 'Fresh fixture certificate generated.');
  await chmod(keyPath, 0o600); await chmod(certPath, 0o600);
  if (!alternateLeaf) return { key: await readFile(keyPath), cert: await readFile(certPath, 'utf8') };
  const leafKey = join(directory, 'leaf-key.pem'); const leafCsr = join(directory, 'leaf.csr'); const leafCert = join(directory, 'leaf-cert.pem');
  assert.equal(openssl(['req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-noenc',
    '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1', '-addext', 'basicConstraints=critical,CA:FALSE',
    '-keyout', leafKey, '-out', leafCsr]).status, 0, 'Alternate fresh leaf requested.');
  assert.equal(openssl(['x509', '-req', '-in', leafCsr, '-CA', certPath, '-CAkey', keyPath, '-set_serial', '1',
    '-days', '1', '-copy_extensions', 'copy', '-out', leafCert]).status, 0, 'Alternate fresh leaf signed.');
  for (const file of [leafKey, leafCsr, leafCert]) await chmod(file, 0o600);
  return { key: await readFile(leafKey), cert: await readFile(leafCert, 'utf8'), ca: await readFile(certPath, 'utf8') };
}
async function refused(port) {
  await new Promise((resolve, reject) => {
    const socket = connect({ host: '127.0.0.1', port }); socket.setTimeout(500);
    socket.once('connect', () => { socket.destroy(); reject(new Error('Owned synthetic listener remained open.')); });
    socket.once('timeout', () => { socket.destroy(); reject(new Error('Owned listener closure not verified.')); });
    socket.once('error', error => { socket.destroy(); error.code === 'ECONNREFUSED' ? resolve() : reject(new Error('Unexpected owned listener state.')); });
  });
}

/** This deliberately minimal PostgreSQL wire model never parses or executes SQL.
 * It records actual extended-protocol requests and emits synthetic aggregate rows.
 * Socket/certificate/worker evidence is real; catalog/database evidence is not. */
async function fixture(t, options = {}) {
  const tls = await certificate(t, options.alternateLeaf); const ca = options.ca ?? tls.ca ?? tls.cert;
  const sockets = new Set(); const state = { connections: 0, sslRequests: 0, startups: [], queries: [], binds: [],
    terminations: 0, peerClosures: 0, parserErrors: 0, ownershipChecks: 0 };
  const schemaQuery = bootstrapSchemaQuery(); const baselineQuery = bootstrapBaselineQuery(input());
  const contracts = new Map([[schemaQuery.text, bootstrapDatabaseQueryContract(schemaQuery)], [baselineQuery.text, bootstrapDatabaseQueryContract(baselineQuery)]]);
  const context = createSecureContext({ key: tls.key, cert: tls.cert, minVersion: 'TLSv1.2' });
  const server = createServer(raw => {
    state.connections++; sockets.add(raw); raw.on('error', () => {});
    raw.on('close', () => { sockets.delete(raw); state.peerClosures++; });
    let initial = Buffer.alloc(0);
    const sslRequest = chunk => {
      initial = Buffer.concat([initial, chunk]); if (initial.length < 8) return;
      raw.off('data', sslRequest);
      try { assert.equal(initial.length, 8); assert.equal(initial.readInt32BE(0), 8); assert.equal(initial.readInt32BE(4), 80877103); }
      catch { state.parserErrors++; raw.destroy(); return; }
      state.sslRequests++;
      if (options.noSslAnswer) return;
      if (options.denyTls) { raw.end('N'); return; }
      raw.write('S');
      const socket = new TLSSocket(raw, { isServer: true, secureContext: context }); sockets.add(socket);
      socket.on('error', () => {}); socket.on('close', () => sockets.delete(socket));
      let pending = Buffer.alloc(0); let started = false; let statement; let columns; let currentRows; let transaction = false;
      const ready = () => socket.write(message('Z', Buffer.from(transaction ? 'T' : 'I')));
      const startup = packet => {
        assert.equal(packet.readInt32BE(4), 196608); const cursor = { offset: 8 }; const parameters = {};
        while (cursor.offset < packet.length - 1) { const key = stringAt(packet, cursor); parameters[key] = stringAt(packet, cursor); }
        state.startups.push(parameters); started = true;
        if (options.onStartup) options.onStartup(socket, state);
        if (options.holdStartup) return;
        socket.write(Buffer.concat([message('R', i32(0)), message('S', cstr('server_version'), cstr('17.0')),
          message('S', cstr('client_encoding'), cstr('UTF8')), message('K', i32(123), i32(456)), message('Z', Buffer.from('I'))]));
      };
      const handle = (type, body) => {
        const cursor = { offset: 0 };
        if (type === 'P') {
          stringAt(body, cursor); statement = stringAt(body, cursor);
          state.queries.push(statement); const contract = contracts.get(statement);
          columns = contract?.columns.map(item => ({ ...item }));
          currentRows = columns ? [contract.kind === 'schema' ? schema() : baseline()] : [];
          if (options.columns && columns) columns = options.columns(columns);
          if (options.rows && columns) currentRows = options.rows(currentRows, contract);
          socket.write(message('1')); return;
        }
        if (type === 'B') {
          stringAt(body, cursor); stringAt(body, cursor); const formats = body.readInt16BE(cursor.offset); cursor.offset += 2 + formats * 2;
          const count = body.readInt16BE(cursor.offset); cursor.offset += 2; const values = [];
          for (let i = 0; i < count; i++) { const n = body.readInt32BE(cursor.offset); cursor.offset += 4;
            values.push(n === -1 ? null : body.toString('utf8', cursor.offset, cursor.offset + n)); if (n >= 0) cursor.offset += n; }
          state.binds.push({ sql: statement, values }); socket.write(message('2')); return;
        }
        if (type === 'D') { socket.write(columns ? rowDescription(columns) : message('n')); return; }
        if (type === 'E') {
          if (columns && options.onSelect) options.onSelect(socket, state);
          if (columns && options.holdSelect) return;
          if (columns && options.selectBytes) { socket.write(options.selectBytes(columns, currentRows)); return; }
          if (columns) for (const row of currentRows) socket.write(dataRow(columns, row));
          const tag = /^BEGIN/iu.test(statement) ? 'BEGIN' : /^ROLLBACK/iu.test(statement) ? 'ROLLBACK' : columns ? `SELECT ${currentRows.length}` : 'SET';
          if (tag === 'BEGIN') transaction = true; if (tag === 'ROLLBACK') transaction = false;
          socket.write(message('C', cstr(tag))); return;
        }
        if (type === 'S') { if (!(columns && (options.holdSelect || options.selectBytes))) ready(); return; }
        if (type === 'H') return;
        if (type === 'X') { state.terminations++; socket.end(); return; }
        throw new Error('Unexpected model protocol message.');
      };
      socket.on('data', chunk => {
        try {
          pending = Buffer.concat([pending, chunk]); assert.ok(pending.length < 65536);
          while (pending.length >= (started ? 5 : 4)) {
            const length = pending.readInt32BE(started ? 1 : 0); const total = length + (started ? 1 : 0);
            assert.ok(length >= 4 && total <= 65536); if (pending.length < total) break;
            const packet = pending.subarray(0, total); pending = pending.subarray(total);
            if (!started) startup(packet); else handle(String.fromCharCode(packet[0]), packet.subarray(5));
          }
        } catch { state.parserErrors++; socket.destroy(); }
      });
    };
    raw.on('data', sslRequest);
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const port = server.address().port; let executor;
  t.after(async () => {
    try { await executor?.close(); }
    finally { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); await refused(port); tls.key.fill(0); }
  });
  const database = 'fncp_fresh_' + randomBytes(12).toString('hex'); const user = 'fncp_fresh_' + randomBytes(12).toString('hex');
  const password = randomBytes(32).toString('hex');
  const settings = { port, database, user, password, certificatePem: ca, async assertOwned(lease) {
    state.ownershipChecks++; assert.equal(Object.isFrozen(lease), true);
    assert.deepEqual(lease, { port, database, user, certificateSha256: createHash('sha256').update(new X509Certificate(ca).raw).digest('hex') });
    if (options.owner) return options.owner(lease, state);
  } };
  if (!options.noExecutor) executor = createBootstrapDatabaseExecutor(settings);
  async function verifyAlternateLeafChainOnly() {
    assert.equal(options.alternateLeaf, true);
    await new Promise((resolve, reject) => {
      const raw = connect({ host: '127.0.0.1', port }); let secure;
      const timer = setTimeout(() => { secure?.destroy(); raw.destroy(); reject(new Error('Fresh chain-only check timed out.')); }, 1500);
      const fail = () => { clearTimeout(timer); secure?.destroy(); raw.destroy(); reject(new Error('Fresh alternate leaf chain not verified.')); };
      raw.once('error', fail); raw.once('connect', () => raw.write(Buffer.concat([i32(8), i32(80877103)])));
      raw.once('data', data => {
        try { assert.equal(data.toString(), 'S'); } catch { fail(); return; }
        secure = connectTls({ socket: raw, host: '127.0.0.1', ca, rejectUnauthorized: true, minVersion: 'TLSv1.2' });
        secure.once('error', fail); secure.once('secureConnect', () => {
          try {
            assert.equal(secure.authorized, true); const peer = secure.getPeerCertificate();
            assert.equal(checkServerIdentity('127.0.0.1', peer), undefined);
            assert.notEqual(createHash('sha256').update(peer.raw).digest('hex'), createHash('sha256').update(new X509Certificate(ca).raw).digest('hex'));
            clearTimeout(timer); secure.destroy(); raw.destroy(); resolve();
          } catch { fail(); }
        });
      });
    });
  }
  return { state, settings, executor, schemaQuery, baselineQuery, verifyAlternateLeafChainOnly };
}

function workersClosed(f, accepted) {
  const summary = f.executor.summary(); assert.equal(summary.busy, false);
  assert.equal(summary.workersClosed, summary.workersStarted); assert.equal(summary.acceptedQueries, accepted);
  assert.equal(summary.retries, 0); assert.equal(summary.auxiliaryCancelConnections, 0);
}

test('real TLS PostgreSQL wire model accepts schema then baseline on two separately closed workers without executing an engine', async t => {
  const f = await fixture(t);
  const a = await f.executor.execute(f.schemaQuery, { signal: signal() });
  assert.deepEqual(a, validateBootstrapSchemaResult(f.schemaQuery, [schema()])); workersClosed(f, 1);
  const b = await f.executor.execute(f.baselineQuery, { signal: signal() });
  assert.deepEqual(b, validateBootstrapBaselineResult(f.baselineQuery, [baseline()])); workersClosed(f, 2);
  assert.equal(f.state.connections, 2); assert.equal(f.state.sslRequests, 2); assert.equal(f.state.startups.length, 2);
  assert.equal(f.state.parserErrors, 0); assert.equal(f.state.terminations, 2); assert.equal(f.state.ownershipChecks, 4);
  assert.deepEqual(f.state.queries, [...SETUP, f.schemaQuery.text, 'ROLLBACK', ...SETUP, f.baselineQuery.text, 'ROLLBACK']);
  assert.deepEqual(f.state.binds.find(item => item.sql === f.baselineQuery.text).values,
    [input().conversationId, '{' + ids.map(value => JSON.stringify(String(value))).join(',') + '}', '23']);
  for (const item of f.state.binds.filter(item => item.sql !== f.baselineQuery.text)) assert.deepEqual(item.values, []);
  for (const startup of f.state.startups) {
    assert.equal(startup.database, f.settings.database); assert.equal(startup.user, f.settings.user);
    assert.equal(startup.application_name, 'fncp_fresh_bootstrap_read');
    assert.equal(startup.options, '-c default_transaction_read_only=on -c search_path=pg_catalog -c statement_timeout=1000 -c lock_timeout=250 -c idle_in_transaction_session_timeout=2000');
  }
  const summary = f.executor.summary(); assert.equal(summary.phase, 'complete'); assert.equal(Object.isFrozen(summary), true);
  for (const field of ['actualPostgreSQLVerified', 'actualBootstrapExecuted', 'databaseReady', 'activationGranted', 'roundOpen']) assert.equal(summary[field], false);
  assert.equal(summary.ownership, 'TRUSTED_CALLBACK_NOT_INDEPENDENTLY_PROVED');
  for (const privateValue of [f.settings.database, f.settings.user, f.settings.password, f.settings.certificatePem, input().conversationId]) assert.equal(JSON.stringify(summary).includes(privateValue), false);
  await f.executor.close(); await f.executor.close(); assert.equal(f.executor.summary().closed, true);
});

test('factory rejects caller hosts, retained names, credentials, overrides, accessors and proxies without connecting', async t => {
  const f = await fixture(t, { noExecutor: true }); let reads = 0;
  for (const options of [undefined, null, {}, { ...f.settings, host: '127.0.0.1' }, { ...f.settings, execute() {} },
    { ...f.settings, database: 'retained' }, { ...f.settings, user: 'postgres' }, { ...f.settings, password: 'private-invalid' },
    { ...f.settings, certificatePem: 'private-certificate' }, { ...f.settings, get port() { reads++; } },
    new Proxy(f.settings, { get() { reads++; } }), { ...f.settings, assertOwned: new Proxy(() => {}, {}) }]) throws(() => createBootstrapDatabaseExecutor(options));
  for (const port of [0, 443, 65536, '5432', 5432.5, NaN, Infinity]) throws(() => createBootstrapDatabaseExecutor({ ...f.settings, port }));
  throws(() => createBootstrapDatabaseExecutor()); throws(() => createBootstrapDatabaseExecutor(f.settings, undefined));
  assert.equal(reads, 0); assert.equal(f.state.connections, 0);
});

test('query admission rejects forged/copied/proxy descriptors and invalid signal objects before ownership or connection', async t => {
  const f = await fixture(t); let reads = 0;
  for (const query of [undefined, null, {}, { ...f.schemaQuery }, JSON.parse(JSON.stringify(f.schemaQuery)),
    new Proxy(f.schemaQuery, { get() { reads++; } })]) await rejected(f.executor.execute(query, { signal: signal() }));
  for (const options of [undefined, null, {}, { signal: {} }, { signal: { aborted: false } }, { signal: new Proxy(signal(), {}) },
    { get signal() { reads++; } }, { signal: signal(), other: true }]) await rejected(f.executor.execute(f.schemaQuery, options));
  await rejected(f.executor.execute(f.schemaQuery)); await rejected(f.executor.execute(f.schemaQuery, { signal: signal() }, undefined));
  assert.equal(reads, 0); assert.equal(f.state.connections, 0); assert.equal(f.state.ownershipChecks, 0);
  assert.equal(f.executor.summary().failed, false);
});

test('baseline before schema and duplicate stages are denied without consuming the rightful schema-baseline sequence', async t => {
  const f = await fixture(t); await rejected(f.executor.execute(f.baselineQuery, { signal: signal() }));
  assert.equal(f.state.connections, 0);
  await f.executor.execute(f.schemaQuery, { signal: signal() });
  await rejected(f.executor.execute(bootstrapSchemaQuery(), { signal: signal() })); assert.equal(f.state.connections, 1);
  await f.executor.execute(f.baselineQuery, { signal: signal() });
  await rejected(f.executor.execute(f.baselineQuery, { signal: signal() })); assert.equal(f.state.connections, 2); workersClosed(f, 2);
});

test('wrong fresh CA denies the TLS handshake before database/user startup or query data is released', async t => {
  const ca = await certificate(t); const f = await fixture(t, { ca: ca.cert });
  await rejected(f.executor.execute(f.schemaQuery, { signal: signal() })); workersClosed(f, 0);
  assert.equal(f.state.sslRequests, 1); assert.equal(f.state.startups.length, 0); assert.equal(f.state.queries.length, 0);
});

test('an otherwise valid CA-signed alternate leaf is denied before PostgreSQL startup identifiers', async t => {
  const f = await fixture(t, { alternateLeaf: true }); await f.verifyAlternateLeafChainOnly();
  await rejected(f.executor.execute(f.schemaQuery, { signal: signal() })); workersClosed(f, 0);
  assert.equal(f.state.startups.length, 0); assert.equal(f.state.queries.length, 0);
});

test('server refusal of SSL cannot trigger a plaintext PostgreSQL fallback', async t => {
  const f = await fixture(t, { denyTls: true }); await rejected(f.executor.execute(f.schemaQuery, { signal: signal() }));
  workersClosed(f, 0); assert.equal(f.state.connections, 1); assert.equal(f.state.startups.length, 0);
});

for (const [name, options] of [
  ['no aggregate rows', { rows: () => [] }],
  ['duplicate aggregate rows', { rows: rows => [...rows, { ...rows[0] }] }],
  ['wrong boolean text', { rows: rows => [{ ...rows[0], tables_match: 'true' }] }],
  ['false catalog result', { rows: rows => [{ ...rows[0], tables_match: false }] }],
  ['null catalog result', { rows: rows => [{ ...rows[0], tables_match: null }] }],
  ['wrong result field OID', { columns: columns => columns.map((item, i) => i === 0 ? { ...item, dataTypeID: 25 } : item) }],
  ['wrong result column name', { columns: columns => columns.map((item, i) => i === 0 ? { ...item, name: 'private_other_field' } : item) }],
  ['duplicate result column name', { columns: columns => columns.map((item, i) => i === 1 ? { ...item, name: columns[0].name } : item) }],
]) {
  test(`wire ${name} is rejected, the worker closes, and the failed query is never retried`, async t => {
    const f = await fixture(t, options); await rejected(f.executor.execute(f.schemaQuery, { signal: signal() }));
    workersClosed(f, 0); assert.equal(f.state.connections, 1); assert.equal(f.executor.summary().failed, true);
    await rejected(f.executor.execute(f.schemaQuery, { signal: signal() })); assert.equal(f.state.connections, 1);
  });
}

test('baseline integer parsing rejects noncanonical numeric text instead of coercing it into an accepted count', async t => {
  const f = await fixture(t, { rows(rows, contract) { return contract.kind === 'baseline' ? [{ ...rows[0], raw_vote_rows: '015' }] : rows; } });
  await f.executor.execute(f.schemaQuery, { signal: signal() });
  await rejected(f.executor.execute(f.baselineQuery, { signal: signal() })); workersClosed(f, 1);
  assert.equal(f.state.connections, 2); assert.equal(f.executor.summary().failed, true);
});

test('a wire response beyond the fixed byte limit cannot produce a validated result', async t => {
  const f = await fixture(t, { selectBytes() { return message('S', cstr('application_name'), cstr('x'.repeat(131072))); } });
  await rejected(f.executor.execute(f.schemaQuery, { signal: signal() })); workersClosed(f, 0);
  assert.equal(f.state.connections, 1); assert.equal(f.executor.summary().wireByteLimit, 131072);
});

test('backend errors expose only the sanitized executor error and cannot leave a live worker', async t => {
  const f = await fixture(t, { selectBytes() { return message('E', Buffer.from('SERROR\0CXX000\0Mprivate-row-password-and-database\0\0')); } });
  await rejected(f.executor.execute(f.schemaQuery, { signal: signal() })); workersClosed(f, 0);
  assert.equal(f.state.connections, 1);
});

test('a stalled pg wire parser is bounded by the parent deadline and cannot strand the worker or authorize a retry', async t => {
  // A CommandComplete without its required cstring terminator stalls the
  // installed parser. Only the independent parent, not that worker loop, times out.
  const f = await fixture(t, { selectBytes() { return message('C', Buffer.from('UNTERMINATED')); } });
  const start = performance.now(); await rejected(f.executor.execute(f.schemaQuery, { signal: signal() }));
  const elapsed = performance.now() - start; assert.ok(elapsed >= 5500 && elapsed < 8500);
  workersClosed(f, 0); assert.equal(f.state.connections, 1); assert.equal(f.executor.summary().failed, true);
});

test('ownership rejection and non-undefined acknowledgement deny the operation before any worker starts', async t => {
  for (const owner of [() => { throw new Error('private-owner-resource'); }, () => true]) {
    const f = await fixture(t, { owner }); await rejected(f.executor.execute(f.schemaQuery, { signal: signal() }));
    assert.equal(f.state.connections, 0); assert.equal(f.executor.summary().workersStarted, 0); workersClosed(f, 0);
  }
});

test('ownership lost after worker completion prevents accepting its otherwise valid aggregate', async t => {
  const f = await fixture(t, { owner(lease, state) { if (state.ownershipChecks === 2) throw new Error('private-replaced-resource'); } });
  await rejected(f.executor.execute(f.schemaQuery, { signal: signal() })); workersClosed(f, 0);
  assert.equal(f.state.connections, 1); assert.equal(f.state.queries.length, 8); assert.equal(f.state.terminations, 1);
});

test('pre-aborted signal denies execution without launching a worker', async t => {
  const f = await fixture(t); const controller = new AbortController(); controller.abort();
  await rejected(f.executor.execute(f.schemaQuery, { signal: controller.signal }));
  assert.equal(f.state.connections, 0); assert.equal(f.executor.summary().workersStarted, 0);
});

test('genuine AbortSignal own listener overrides cannot intercept cancellation or leak getter errors', async t => {
  const entered = deferred(); const f = await fixture(t, { holdSelect: true, onSelect() { entered.resolve(); } });
  const controller = new AbortController(); let reads = 0;
  for (const name of ['addEventListener', 'removeEventListener']) Object.defineProperty(controller.signal, name, {
    get() { reads++; throw new Error('private-signal-listener-override'); },
  });
  const result = rejected(f.executor.execute(f.schemaQuery, { signal: controller.signal }));
  await entered.promise; const start = performance.now(); controller.abort(); await result;
  assert.ok(performance.now() - start < 2000); assert.equal(reads, 0); workersClosed(f, 0);
  assert.equal(f.state.connections, 1);
});

for (const operation of ['abort', 'close']) {
  test(`${operation} interrupts pending network work and confirms worker closure without a second cancel connection`, async t => {
    const entered = deferred(); const f = await fixture(t, { holdSelect: true, onSelect() { entered.resolve(); } });
    const controller = new AbortController(); const result = rejected(f.executor.execute(f.schemaQuery, { signal: controller.signal }));
    await entered.promise; const start = performance.now();
    if (operation === 'abort') controller.abort(); else await f.executor.close();
    await result; assert.ok(performance.now() - start < 2000); workersClosed(f, 0); assert.equal(f.state.connections, 1);
  });
}

for (const operation of ['abort', 'close']) {
  test(`${operation} interrupts pending ownership and a late acknowledgement cannot create a connection`, async t => {
    const entered = deferred(); const release = deferred();
    const f = await fixture(t, { owner() { entered.resolve(); return release.promise; } });
    const controller = new AbortController(); const result = rejected(f.executor.execute(f.schemaQuery, { signal: controller.signal }));
    await entered.promise; const start = performance.now();
    if (operation === 'abort') controller.abort(); else await f.executor.close();
    await result; assert.ok(performance.now() - start < 1500); release.resolve(); await new Promise(resolve => setImmediate(resolve));
    assert.equal(f.state.connections, 0); assert.equal(f.executor.summary().workersStarted, 0); workersClosed(f, 0);
  });
}

test('never-settling ownership is parent-deadline bounded and its late resolution cannot launch a worker', async t => {
  const release = deferred(); const f = await fixture(t, { owner() { return release.promise; } });
  const start = performance.now(); await rejected(f.executor.execute(f.schemaQuery, { signal: signal() }));
  assert.ok(performance.now() - start >= 5500 && performance.now() - start < 8500);
  release.resolve(); await new Promise(resolve => setImmediate(resolve)); workersClosed(f, 0);
  assert.equal(f.state.connections, 0); assert.equal(f.executor.summary().workersStarted, 0);
});

test('duplicate concurrent execution cannot start another worker or invalidate the admitted successful operation', async t => {
  const entered = deferred(); const release = deferred();
  const f = await fixture(t, { owner(lease, state) { if (state.ownershipChecks === 1) { entered.resolve(); return release.promise; } } });
  const first = f.executor.execute(f.schemaQuery, { signal: signal() }); await entered.promise;
  await rejected(f.executor.execute(f.schemaQuery, { signal: signal() })); release.resolve();
  assert.deepEqual(await first, validateBootstrapSchemaResult(f.schemaQuery, [schema()])); workersClosed(f, 1);
  assert.equal(f.state.connections, 1); assert.equal(f.executor.summary().failed, false);
});

test('the fixed worker ignores ambient PG and Node configuration instead of selecting another endpoint or executable hook', async t => {
  const f = await fixture(t); const poison = { PGHOST: '203.0.113.1', PGPORT: '1', PGUSER: 'private_ambient_user',
    PGDATABASE: 'private_ambient_database', PGPASSWORD: 'private_ambient_password', PGSSLMODE: 'disable',
    PGOPTIONS: '-c default_transaction_read_only=off', NODE_OPTIONS: '--require=/nonexistent-private-hook',
    NODE_EXTRA_CA_CERTS: '/nonexistent-private-ca', NODE_TLS_REJECT_UNAUTHORIZED: '0' };
  const old = new Map(Object.keys(poison).map(key => [key, process.env[key]]));
  try {
    Object.assign(process.env, poison);
    await f.executor.execute(f.schemaQuery, { signal: signal() }); workersClosed(f, 1);
    assert.equal(f.state.connections, 1); assert.equal(f.state.startups[0].user, f.settings.user);
    assert.equal(f.state.startups[0].database, f.settings.database);
  } finally { for (const [key, value] of old) { if (value === undefined) delete process.env[key]; else process.env[key] = value; } }
});
