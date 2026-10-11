/** Fixed one-query child of bootstrap-database-executor. Private inputs only via
 * IPC. No command-line credentials, environment fallbacks, pool or SQL input.
 * Parent deadline is essential: an untrusted pg wire parser can stall this loop.
 */
import Client from '../../../server/node_modules/pg/lib/client.js';
import Query from '../../../server/node_modules/pg/lib/query.js';
import { createHash, X509Certificate } from 'node:crypto';
import { checkServerIdentity } from 'node:tls';
import { bootstrapSchemaQuery, bootstrapBaselineQuery, bootstrapDatabaseQueryContract,
  validateBootstrapSchemaResult, validateBootstrapBaselineResult } from './bootstrap-database-contract.mjs';

const die = () => process.exit(1); // OS closes this child's one owned socket.
process.on('uncaughtException', die); process.on('unhandledRejection', die);
process.on('disconnect', die);
let claimed = false;
process.on('message', async input => {
  if (claimed) die(); claimed = true;
  try {
    if (!input || Object.keys(input).sort().join() !== 'config,kind,values') die();
    const { config, kind, values } = input;
    if (!config || Object.keys(config).sort().join() !== 'certificatePem,database,password,port,user' ||
        !Number.isSafeInteger(config.port) || config.port < 1024 || config.port > 65535 ||
        ![config.database, config.user].every(v => typeof v === 'string' && /^fncp_fresh_[a-f0-9]{24}$/u.test(v)) ||
        typeof config.password !== 'string' || !/^[a-f0-9]{64}$/u.test(config.password) ||
        typeof config.certificatePem !== 'string' || Buffer.byteLength(config.certificatePem) > 8192) die();
    let query;
    if (kind === 'schema' && Array.isArray(values) && values.length === 0) query = bootstrapSchemaQuery();
    else if (kind === 'baseline' && Array.isArray(values) && values.length === 3) query = bootstrapBaselineQuery({ conversationId: values[0], statementIds: values[1], seedOwnerPid: values[2] });
    else die();
    const contract = bootstrapDatabaseQueryContract(query);
    const fingerprint = createHash('sha256').update(new X509Certificate(config.certificatePem).raw).digest('hex');
    const peerCheck = peer => checkServerIdentity('127.0.0.1', peer) || !Buffer.isBuffer(peer.raw) ||
      createHash('sha256').update(peer.raw).digest('hex') !== fingerprint;
    const client = new Client({ host: '127.0.0.1', port: config.port, user: config.user, database: config.database, password: config.password,
      connectionTimeoutMillis: 1000, keepAlive: false, application_name: 'fncp_fresh_bootstrap_read',
      options: '-c default_transaction_read_only=on -c search_path=pg_catalog -c statement_timeout=1000 -c lock_timeout=250 -c idle_in_transaction_session_timeout=2000',
      ssl: { ca: config.certificatePem, rejectUnauthorized: true, minVersion: 'TLSv1.2',
        checkServerIdentity(host, peer) { if (peerCheck(peer)) return new Error('Owned TLS peer rejected.'); } },
      types: { getTypeParser() { return value => value; } },
    });
    client.on('error', die);
    const con = client.connection;
    const startup = con.startup.bind(con);
    con.startup = parameters => {
      // pg emits sslconnect before TLS secureConnect. Do not even send the
      // startup user/database until IP validation, CA and exact leaf succeed.
      con.stream.once('secureConnect', () => {
        if (con.stream.authorized !== true || con.stream.remoteAddress !== '127.0.0.1' ||
            !['TLSv1.2', 'TLSv1.3'].includes(con.stream.getProtocol()) || peerCheck(con.stream.getPeerCertificate())) die();
        startup(parameters);
      });
    };
    con.on('sslconnect', () => {
      let bytes = 0;
      con.stream.prependListener('data', chunk => {
        bytes += chunk.length;
        // Destroy alone does not prevent other listeners parsing this chunk.
        if (bytes > 131072) die();
      });
    });
    for (const event of ['copyInResponse', 'copyOutResponse', 'copyBothResponse', 'copyData', 'notification', 'portalSuspended']) con.prependListener(event, die);
    let current;
    con.prependListener('rowDescription', message => {
      if (!current || current.description || message.fields.length !== current.columns.length) die();
      current.description = true;
      for (let i = 0; i < message.fields.length; i++) {
        const field = message.fields[i]; const expected = current.columns[i];
        if (field.name !== expected.name || field.dataTypeID !== expected.dataTypeID || field.format !== 'text') die();
      }
    });
    con.prependListener('commandComplete', message => {
      if (!current || current.commandSeen || message.text !== current.command) die(); current.commandSeen = true;
    });
    con.prependListener('readyForQuery', message => {
      if (message.status !== (current?.status ?? 'I')) die();
    });
    const execute = (text, values, columns, command, status) => new Promise((resolve, reject) => {
      const state = { columns, command, status, commandSeen: false, description: false, rows: [] }; current = state;
      // An event listener with NO callback disables pg's unbounded accumulator.
      const request = new Query({ text, values, queryMode: 'extended', rowMode: 'array' });
      request.on('row', row => {
        if (!state.description || state.rows.length || row.length !== columns.length || !columns.length) die();
        const result = {};
        columns.forEach(({ name, dataTypeID }, index) => {
          const value = row[index];
          if (dataTypeID === 16 && ['t', 'f'].includes(value)) result[name] = value === 't';
          else if (dataTypeID === 23 && typeof value === 'string' && /^(0|[1-9][0-9]{0,9}|-[1-9][0-9]{0,9})$/u.test(value) && Number(value) >= -2147483648 && Number(value) <= 2147483647) result[name] = Number(value);
          else die();
        });
        state.rows.push(result);
      });
      request.once('error', reject);
      request.once('end', result => {
        if (Array.isArray(result) || !state.commandSeen || result.rows.length !== 0 || state.rows.length !== (columns.length ? 1 : 0) ||
            result.fields.length !== columns.length || (columns.length && result.rowCount !== 1)) die();
        current = undefined; resolve(state.rows);
      });
      client.query(request);
    });
    await client.connect();
    await execute('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY', [], [], 'BEGIN', 'T');
    for (const setting of ["search_path = pg_catalog", "statement_timeout = 1000", "lock_timeout = 250", "idle_in_transaction_session_timeout = 2000", "row_security = off"]) {
      await execute('SET LOCAL ' + setting, [], [], 'SET', 'T');
    }
    const rows = await execute(query.text, query.values, contract.columns, 'SELECT 1', 'T');
    (kind === 'schema' ? validateBootstrapSchemaResult : validateBootstrapBaselineResult)(query, rows);
    await execute('ROLLBACK', [], [], 'ROLLBACK', 'I');
    await client.end();
    // Success is accepted only after parent observes this process fully closed.
    process.send({ rows }, error => { process.exit(error ? 1 : 0); });
  } catch { die(); }
});
if (typeof process.send !== 'function') die();
