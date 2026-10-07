/** Disposable UI smoke fixture only. The real local browser UI wraps an
 * in-memory model, NOT Pol.is, WordPress, HTTPS/OIDC or a real identity service.
 * No CLI, autostart, remote transport, retained store or credential logging.
 */
import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { connect } from 'node:net';
import { createLocalBrowser } from './browser-server.mjs';

const FIXTURE = 'synthetic_ui_smoke';
const LIFETIME_MS = 5 * 60_000;
const MAX_BACKEND_REQUESTS = 512;
const seeds = JSON.parse(readFileSync(new URL('../seed-statements.json', import.meta.url), 'utf8'));
if (!Array.isArray(seeds) || seeds.length !== 15 || new Set(seeds).size !== 15
  || seeds.some(text => typeof text !== 'string' || !text || text.length > 3000)) {
  throw new Error('Synthetic UI smoke seed configuration rejected.');
}
const routes = new Map([
  ['/health', undefined], ['/test-auth/mailbox-simulator', ['fixture', 'fixtureSecret']],
  ['/invitations/redeem', ['invitationToken']], ['/polis/participation-init', undefined],
  ['/polis/next-comment', undefined], ['/polis/votes', ['tid', 'vote']], ['/session/logout', []],
]);
const random = () => randomBytes(32).toString('base64url');
const digest = value => createHash('sha256').update(value).digest();
const same = (left, right) => typeof left === 'string' && timingSafeEqual(digest(left), digest(right));
const response = (status, body) => ({ status, body });
function exact(value, keys) {
  return keys === undefined ? value === undefined : value && typeof value === 'object'
    && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype
    && Reflect.ownKeys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key))
    && Object.values(Object.getOwnPropertyDescriptors(value)).every(field => Object.hasOwn(field, 'value'));
}

function verifyPortClosed(port) {
  return new Promise((resolve, reject) => {
    const socket = connect({ host: '127.0.0.1', port });
    let settled = false;
    const finish = ok => {
      if (settled) return; settled = true; socket.destroy();
      if (ok) resolve(); else reject(new Error('Synthetic UI smoke listener closure unconfirmed.'));
    };
    socket.setTimeout(500);
    socket.once('connect', () => finish(false));
    socket.once('timeout', () => finish(false));
    socket.once('error', error => finish(error.code === 'ECONNREFUSED'));
  });
}

/** No arguments, caller hosts/ports, injected identity, transport or persistence.
 * Returned credentials are private invented UI inputs; never print or publish.
 */
export async function createUiSmokeLab(...args) {
  if (args.length) throw new Error('Synthetic UI smoke lab accepts no configuration.');
  const fixtureSecret = random(); const invitation = random();
  const authToken = random(); const participationToken = random();
  const expiresAt = Date.now() + LIFETIME_MS;
  const counters = { backendRequests: 0, loginSuccesses: 0, invitationRedemptions: 0,
    votes: 0, agree: 0, disagree: 0, pass: 0, logouts: 0, rejections: 0 };
  let authActive = false; let participantActive = false; let invitationUsed = false;
  let closing = false; let listenerClosed = false; let closeFailed = false;
  let lifetimeExpired = false; let closePromise; let timer; let browser; let origin; let port;
  let nextIndex = 0;
  const next = () => nextIndex < seeds.length ? { tid: nextIndex, txt: seeds[nextIndex] } : null;
  function deny(status = 403) {
    counters.rejections = Math.min(counters.rejections + 1, MAX_BACKEND_REQUESTS + 1);
    return response(status, { mode: 'SYNTHETIC_ONLY', error: 'Synthetic UI model rejected.' });
  }
  const backend = Object.freeze({
    async request(path, body, credential) {
      counters.backendRequests = Math.min(counters.backendRequests + 1, MAX_BACKEND_REQUESTS + 1);
      if (closing || Date.now() >= expiresAt || counters.backendRequests > MAX_BACKEND_REQUESTS) return deny(503);
      if (!routes.has(path) || !exact(body, routes.get(path))) return deny(400);
      if (path === '/health') {
        if (credential !== undefined) return deny();
        return response(200, { mode: 'SYNTHETIC_ONLY', productionReady: false,
          heritageVerification: false, realEmailEnabled: false });
      }
      if (path === '/test-auth/mailbox-simulator') {
        if (credential !== undefined || body.fixture !== FIXTURE || !same(body.fixtureSecret, fixtureSecret)) return deny(401);
        authActive = true; counters.loginSuccesses++;
        return response(200, { mode: 'SYNTHETIC_ONLY', fixtureAuthToken: authToken,
          mailboxOwnership: 'SIMULATED_NOT_VERIFIED' });
      }
      if (path === '/invitations/redeem') {
        if (!authActive || !same(credential, authToken) || invitationUsed || !same(body.invitationToken, invitation)) return deny();
        invitationUsed = true; participantActive = true; counters.invitationRedemptions++;
        return response(200, { mode: 'SYNTHETIC_ONLY', participationToken });
      }
      if (path === '/session/logout') {
        if (!(participantActive && same(credential, participationToken)) && !(authActive && same(credential, authToken))) return deny(401);
        authActive = false; participantActive = false; counters.logouts++;
        return response(200, { mode: 'SYNTHETIC_ONLY', loggedOut: true });
      }
      if (!participantActive || !same(credential, participationToken)) return deny(401);
      if (path === '/polis/participation-init') return response(200, { nextComment: next() });
      if (path === '/polis/next-comment') return response(200, next());
      if (path !== '/polis/votes' || !Number.isSafeInteger(body.tid) || body.tid !== nextIndex
        || nextIndex >= seeds.length || !Number.isInteger(body.vote) || ![-1, 0, 1].includes(body.vote)) return deny(409);
      counters.votes++;
      counters[body.vote === -1 ? 'agree' : body.vote === 1 ? 'disagree' : 'pass']++;
      nextIndex++;
      return response(200, { nextComment: next() });
    },
  });

  function close() {
    if (closePromise) return closePromise;
    closing = true; authActive = false; participantActive = false;
    clearTimeout(timer);
    closePromise = (async () => {
      let complete = true;
      try { if (browser) await browser.close(); } catch { complete = false; }
      try { if (port !== undefined) await verifyPortClosed(port); listenerClosed = true; } catch { complete = false; }
      if (!complete) { closeFailed = true; throw new Error('Synthetic UI smoke listener closure unconfirmed.'); }
    })();
    return closePromise;
  }

  try {
    browser = createLocalBrowser({ mode: 'fixture-only', backend, sessionLifetimeMs: LIFETIME_MS, maxSessions: 8 });
    origin = await browser.listen(0); port = Number(new URL(origin).port);
    if (!/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/u.test(origin) || port > 65535) throw new Error();
    timer = setTimeout(() => {
      lifetimeExpired = true;
      void close().catch(() => { closeFailed = true; });
    }, Math.max(0, expiresAt - Date.now()));
    timer.unref();
    return Object.freeze({
      origin,
      fixtureCredentials: Object.freeze({ fixture: FIXTURE, fixtureSecret }),
      invitation,
      summary: () => Object.freeze({ classification: 'MODEL_ONLY_HTTP', modelOnly: true,
        realPolis: false, realWordPress: false, httpsOidc: false, realIdentityProvider: false,
        externalTransportEnabled: false, productionReady: false, retainedDataUsed: false,
        browserEngineEvidence: 'NOT_RECORDED_BY_LAB', seedCount: seeds.length,
        lifetimeMs: LIFETIME_MS, ...counters, invitationUsed, closing, listenerClosed, closeFailed, lifetimeExpired }),
      close,
    });
  } catch {
    let complete = true;
    try { await close(); } catch { complete = false; }
    throw new Error(complete ? 'Synthetic UI smoke setup failed; local resources closed.'
      : 'Synthetic UI smoke setup failed; listener closure unconfirmed.');
  }
}
