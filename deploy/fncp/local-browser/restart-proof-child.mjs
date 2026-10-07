/** Test-only subprocess: actual BFF HTTP handler, invented in-memory backend.
 * No access/identity service, WordPress, Docker, provider, database or file writes.
 * Random invented credentials enter via private IPC only; never print them.
 */
import { createLocalBrowser, MODE } from './browser-server.mjs';
import { readFileSync } from 'node:fs';

const token = /^[A-Za-z0-9_-]{43}$/u;
const statement = { tid: 1, txt: JSON.parse(readFileSync(new URL('../seed-statements.json', import.meta.url), 'utf8'))[0] };
let app; let started = false; let closing = false; let counts;

const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const reply = (id, body) => new Promise(resolve => {
  if (!process.connected) { resolve(false); return; }
  // Await the IPC flush before exiting; never rely on process.exit flushing it.
  process.send({ id, ...body }, error => resolve(!error));
});

async function stop(exitCode = 0) {
  if (closing) return;
  closing = true;
  try { if (app) await app.close(); } catch { exitCode = 1; }
  process.exit(exitCode);
}

function modelBackend(credentials) {
  let invitationUsed = false;
  counts = { calls: 0, loginCalls: 0, protectedCalls: 0, voteCalls: 0 };
  // The same invented backend capabilities are deliberately valid in both
  // children. A replay denial must therefore come from the fresh BFF, not a
  // changed model credential or an unavailable provider.
  return {
    async request(path, body, credential) {
      counts.calls++;
      if (path === '/test-auth/mailbox-simulator') {
        counts.loginCalls++;
        return body?.fixture === 'synthetic_restart_fixture' && body.fixtureSecret === credentials.fixtureSecret ?
          { status: 200, body: { fixtureAuthToken: credentials.auth, mailboxOwnership: 'SIMULATED_NOT_VERIFIED' } } :
          { status: 401, body: {} };
      }
      counts.protectedCalls++;
      if (path === '/invitations/redeem') {
        if (credential !== credentials.auth || body?.invitationToken !== credentials.invitation || invitationUsed) return { status: 403, body: {} };
        invitationUsed = true;
        return { status: 201, body: { mode: 'SYNTHETIC_ONLY', participationToken: credentials.participant } };
      }
      if (path === '/session/logout') return { status: 200, body: {} };
      if (!['/polis/participation-init', '/polis/next-comment', '/polis/votes'].includes(path) || credential !== credentials.participant) {
        return { status: 401, body: {} };
      }
      if (path === '/polis/votes') counts.voteCalls++;
      return { status: 200, body: path === '/polis/next-comment' ? { ...statement } : { nextComment: { ...statement } } };
    },
  };
}

if (process.argv.length !== 3 || process.argv[2] !== '--synthetic-bff-restart-proof' || typeof process.send !== 'function') {
  process.exitCode = 1;
} else {
  // Deliberately do not inherit a network adapter or read any saved runtime.
  globalThis.fetch = () => { throw new Error('External fetch is unavailable in the restart proof.'); };
  process.on('disconnect', () => { void stop(); });
  for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => { void stop(); });
  let operations = Promise.resolve();
  process.on('message', message => {
    operations = operations.then(async () => {
      if (!Number.isSafeInteger(message?.id) || message.id < 1) throw new Error();
      if (message.op === 'start' && !started && exact(message, ['id', 'op', 'port', 'credentials']) &&
          Number.isInteger(message.port) && message.port >= 0 && message.port <= 65535 &&
          exact(message.credentials, ['fixtureSecret', 'invitation', 'auth', 'participant']) &&
          Object.values(message.credentials).every(value => typeof value === 'string' && token.test(value)) &&
          new Set(Object.values(message.credentials)).size === 4) {
        started = true;
        app = createLocalBrowser({ mode: MODE, backend: modelBackend(message.credentials) });
        const origin = await app.listen(message.port);
        await reply(message.id, { ok: true, mode: 'SYNTHETIC_MODEL_BACKEND', pid: process.pid, origin });
      } else if (message.op === 'counts' && started && exact(message, ['id', 'op'])) {
        await reply(message.id, { ok: true, counts: { ...counts } });
      } else if (message.op === 'stop' && started && exact(message, ['id', 'op'])) {
        await app.close(); app = undefined;
        await reply(message.id, { ok: true, listenerClosed: true });
        await stop();
      } else throw new Error();
    }).catch(async () => {
      // A malformed message or child error must not echo its payload.
      await reply(Number.isSafeInteger(message?.id) ? message.id : 0, { ok: false, error: 'Synthetic restart child failed.' });
      await stop(1);
    });
  });
}
