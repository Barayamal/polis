/** Bounded concrete pg driver for ONLY an exact newly owned bootstrap database.
 * Import/factory do not connect. Ownership is a mandatory trusted callback,
 * not independent resource provenance. No retained endpoint discovery, shell,
 * Docker, pool, retry, credential file or caller SQL/executable is supported.
 * A separate process bounds even a stalled wire parser. This is not a sandbox
 * against malicious database functions, and does not attest schema provenance.
 */
import { fork } from 'node:child_process';
import { X509Certificate, createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { isProxy } from 'node:util/types';
import { bootstrapDatabaseQueryContract, validateBootstrapSchemaResult, validateBootstrapBaselineResult } from './bootstrap-database-contract.mjs';

const failure = () => new Error('Fresh bootstrap database execution rejected; private details withheld.');
const DEADLINE_MS = 6000;
const WORKER = fileURLToPath(new URL('./bootstrap-database-worker.mjs', import.meta.url));
const DIRECTORY = fileURLToPath(new URL('./', import.meta.url));
const aborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted').get;
const addListener = EventTarget.prototype.addEventListener;
const removeListener = EventTarget.prototype.removeEventListener;
function exact(value, names) {
  if (!value || typeof value !== 'object' || isProxy(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value)) || Reflect.ownKeys(value).length !== names.length) throw failure();
  const fields = Object.getOwnPropertyDescriptors(value);
  if (names.some(name => !fields[name] || !Object.hasOwn(fields[name], 'value'))) throw failure();
  return Object.fromEntries(names.map(name => [name, fields[name].value]));
}

export function createBootstrapDatabaseExecutor(options) {
  if (arguments.length !== 1) throw failure();
  const { port, database, user, password, certificatePem, assertOwned } = exact(options, ['port', 'database', 'user', 'password', 'certificatePem', 'assertOwned']);
  let certificateSha256;
  try {
    if (!Number.isSafeInteger(port) || port < 1024 || port > 65535 ||
        ![database, user].every(v => typeof v === 'string' && /^fncp_fresh_[a-f0-9]{24}$/u.test(v)) ||
        typeof password !== 'string' || !/^[a-f0-9]{64}$/u.test(password) || typeof assertOwned !== 'function' || isProxy(assertOwned) ||
        typeof certificatePem !== 'string' || Buffer.byteLength(certificatePem) > 8192 ||
        !/^-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+\n-----END CERTIFICATE-----\n?$/u.test(certificatePem)) throw failure();
    const cert = new X509Certificate(certificatePem);
    if (cert.checkIP('127.0.0.1') !== '127.0.0.1' || Date.parse(cert.validFrom) > Date.now() || Date.parse(cert.validTo) <= Date.now()) throw failure();
    certificateSha256 = createHash('sha256').update(cert.raw).digest('hex');
  } catch { throw failure(); }
  const lease = Object.freeze({ port, database, user, certificateSha256 });
  const config = { port, database, user, password, certificatePem };
  let closed = false; let failed = false; let busy = false; let phase = 'schema'; let interrupt; let active; let worker;
  const counts = { workersStarted: 0, workersClosed: 0, acceptedQueries: 0, ownershipChecks: 0 };
  async function stopWorker() {
    const target = worker;
    if (!target || target.closed) return;
    target.child.kill('SIGTERM');
    const timer = setTimeout(() => { if (!target.closed) target.child.kill('SIGKILL'); }, 300);
    let limit;
    try {
      await Promise.race([target.close, new Promise((resolve, reject) => { limit = setTimeout(() => reject(failure()), 1300); })]);
    } finally { clearTimeout(timer); clearTimeout(limit); }
  }
  const api = {
    async execute(query, options) {
      let contract; let signal;
      try {
        if (arguments.length !== 2 || closed || failed || busy || phase === 'complete') throw failure();
        ({ signal } = exact(options, ['signal']));
        if (!signal || isProxy(signal) || aborted.call(signal)) throw failure();
        contract = bootstrapDatabaseQueryContract(query);
        if (contract.kind !== phase) throw failure();
      } catch { throw failure(); }
      busy = true;
      let timer; let deny; let ended = false;
      const denied = new Promise((resolve, reject) => { deny = () => { failed = true; reject(failure()); }; });
      // Do not invoke potentially overridden methods on a genuine AbortSignal.
      // Admission checks also use the intrinsic aborted getter after every wait.
      interrupt = deny; addListener.call(signal, 'abort', deny, { once: true });
      timer = setTimeout(deny, DEADLINE_MS);
      const check = () => { if (ended || closed || failed || aborted.call(signal)) throw failure(); };
      const owner = async () => {
        check(); counts.ownershipChecks++;
        if (await Promise.race([Promise.resolve().then(() => { check(); return assertOwned(lease); }), denied]) !== undefined) throw failure();
        check();
      };
      const run = async () => {
        await owner(); check();
        const rows = await new Promise((resolve, reject) => {
          check();
          const child = fork(WORKER, [], { execPath: process.execPath, execArgv: [], cwd: DIRECTORY,
            env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' }, serialization: 'json',
            stdio: ['ignore', 'pipe', 'pipe', 'ipc'] });
          let closeResolve; let message; let invalid = false; let bytes = 0;
          const target = { child, closed: false, close: new Promise(resolve => { closeResolve = resolve; }) };
          worker = target; counts.workersStarted++;
          const rejectWorker = () => { invalid = true; deny(); reject(failure()); };
          child.once('error', rejectWorker);
          for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => {
            bytes += chunk.length; if (bytes > 4096) rejectWorker(); // raw diagnostics never leave this boundary
          });
          child.on('message', value => {
            try {
              if (message !== undefined || JSON.stringify(value).length > 8192) throw failure();
              const body = exact(value, ['rows']);
              // Revalidate original branded query; the worker cannot grant GO.
              (contract.kind === 'schema' ? validateBootstrapSchemaResult : validateBootstrapBaselineResult)(query, body.rows);
              message = body.rows;
            } catch { rejectWorker(); }
          });
          child.once('close', (code, killedBy) => {
            target.closed = true; counts.workersClosed++; closeResolve();
            if (invalid || code !== 0 || killedBy || message === undefined) reject(failure()); else resolve(message);
          });
          child.send({ config, kind: contract.kind, values: contract.values }, error => { if (error) rejectWorker(); });
        });
        check(); await owner(); check();
        const result = (contract.kind === 'schema' ? validateBootstrapSchemaResult : validateBootstrapBaselineResult)(query, rows);
        counts.acceptedQueries++; phase = contract.kind === 'schema' ? 'baseline' : 'complete'; return result;
      };
      active = (async () => {
        try { return await Promise.race([run(), denied]); }
        catch { failed = true; await stopWorker(); throw failure(); }
        finally {
          ended = true; clearTimeout(timer); removeListener.call(signal, 'abort', deny);
          interrupt = undefined; busy = false;
        }
      })();
      return active;
    },
    async close() {
      if (arguments.length) throw failure();
      closed = true; interrupt?.();
      if (active) await active.catch(() => {});
      await stopWorker();
    },
    summary() {
      if (arguments.length) throw failure();
      return Object.freeze({ mode: 'BOUNDED_LOOPBACK_POSTGRESQL_WORKER', ownership: 'TRUSTED_CALLBACK_NOT_INDEPENDENTLY_PROVED',
        actualPostgreSQLVerified: false, actualBootstrapExecuted: false, databaseReady: false, activationGranted: false,
        roundOpen: false, closed, failed, busy, phase, ...counts, wholeQueryDeadlineMs: DEADLINE_MS,
        cleanupDeadlineMs: 1300, wireByteLimit: 131072, maximumRows: 1, retries: 0, auxiliaryCancelConnections: 0 });
    },
  };
  return Object.freeze(api);
}
