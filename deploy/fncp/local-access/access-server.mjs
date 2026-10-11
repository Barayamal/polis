/** Barayamal local synthetic integration proof. NOT production authentication. */
import { createServer } from 'node:http';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { createWordPressEventGate, ROUND } from './wordpress-events.mjs';

export const MODE = 'fixture-only';
export const INTEGRATED_IDENTITY_MODE = 'verified-synthetic-oidc';
export const STRICT_SERVICE_HTTP_PROFILE = 'strict-service';
export const POLIS_ORIGIN = 'http://127.0.0.1:5500';
// Shared by HTTP body readers, queued/running HTTP work and direct entry points.
export const MAX_PENDING_OPERATIONS = 32;
const token = () => randomBytes(32).toString('base64url');
const hash = (value) => createHash('sha256').update(value).digest('hex');
const equal = (a, b) => typeof a === 'string' && typeof b === 'string' &&
  timingSafeEqual(Buffer.from(hash(a)), Buffer.from(hash(b)));
const secretPattern = /^[A-Za-z0-9_-]{32,512}$/u;
const fixturePattern = /^synthetic_[a-z][a-z0-9_]{0,39}$/u;
const blockedResponseKeys = /^(auth|authorization|access_token|refresh_token|id_token|token|jwt|xid|pid|uid|email|password|secret|session)$/iu;

export class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function exact(body, required, optional = []) {
  if (!body || Array.isArray(body) || typeof body !== 'object' ||
      required.some((key) => !(key in body)) ||
      Object.keys(body).some((key) => ![...required, ...optional].includes(key))) {
    throw new HttpError(400, 'Invalid request.');
  }
}

function sanitized(value) {
  if (Array.isArray(value)) return value.map(sanitized);
  if (value && typeof value === 'object') return Object.fromEntries(
    Object.entries(value).filter(([key]) => !blockedResponseKeys.test(key))
      .map(([key, item]) => [key, sanitized(item)]));
  return value;
}

/** Fixed-origin transport: no external URL, caller headers, cookies or redirects. */
export class LocalPolisProvider {
  constructor({ conversationId, gatewaySecret, providerSecret }) {
    if (!/^[0-9][A-Za-z0-9_-]{5,99}$/u.test(conversationId) ||
        !secretPattern.test(gatewaySecret) || !secretPattern.test(providerSecret) ||
        gatewaySecret === providerSecret) throw new Error('Invalid local provider configuration.');
    Object.assign(this, { conversationId, gatewaySecret, providerSecret });
  }

  async request(path, options) {
    const response = await fetch(POLIS_ORIGIN + path, {
      ...options, redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    // Restrict response size without logging or persisting bodies/credentials.
    const chunks = []; let size = 0;
    for await (const chunk of response.body ?? []) {
      size += chunk.length;
      if (size > 2 * 1024 * 1024) throw new Error('Provider response limit.');
      chunks.push(chunk);
    }
    const raw = Buffer.concat(chunks).toString('utf8');
    return { status: response.status, body: raw ? JSON.parse(raw) : null };
  }

  async allowlist(operation, xid) {
    if (!['upsert', 'readback', 'remove'].includes(operation) ||
        !/^fncp_[A-Za-z0-9_-]{16,251}$/u.test(xid)) throw new Error('Invalid provider operation.');
    const headers = { 'Content-Type': 'application/json',
      Authorization: `Bearer ${this.providerSecret}`, 'X-Forwarded-Proto': 'https' };
    const body = { conversationId: this.conversationId, participantXid: xid };
    if (operation !== 'readback') {
      body.operationVersion = operation === 'upsert' ? 1 : 2;
      headers['Idempotency-Key'] = `${operation === 'upsert' ? 'allow' : 'remove'}-${hash(this.conversationId + ':' + xid)}`;
    }
    const result = await this.request(`/fncp/private/xid-allowlist/${operation}`, {
      method: 'POST', headers, body: JSON.stringify(body),
    });
    if (result.status !== (operation === 'readback' ? 200 : 204)) throw new Error('Provider unavailable.');
    if (operation === 'readback' && (result.body?.conversationId !== this.conversationId ||
      result.body?.participantXid !== xid || typeof result.body?.present !== 'boolean')) {
      throw new Error('Provider readback mismatch.');
    }
    return result.body;
  }

  async participate(kind, xid, values = {}) {
    const route = { init: '/api/v3/participationInit', next: '/api/v3/nextComment', vote: '/api/v3/votes' }[kind];
    if (!route || !/^fncp_[A-Za-z0-9_-]{16,251}$/u.test(xid)) throw new Error('Invalid participant route.');
    const headers = { 'X-Forwarded-Proto': 'https', 'X-FNCP-Gateway-Key': this.gatewaySecret,
      'X-FNCP-Conversation-ID': this.conversationId, 'X-FNCP-Participant-XID': xid };
    // No xid/pid/user token is accepted in query/body or returned to the caller.
    const body = { conversation_id: this.conversationId };
    let suffix = '';
    if (kind === 'vote') {
      body.tid = values.tid; body.vote = values.vote;
      headers['Content-Type'] = 'application/json';
    } else {
      body.lang = 'en'; body.agid = '1';
      suffix = '?' + new URLSearchParams(body).toString();
    }
    const result = await this.request(route + suffix, {
      method: kind === 'vote' ? 'POST' : 'GET', headers,
      ...(kind === 'vote' ? { body: JSON.stringify(body) } : {}),
    });
    if (result.status !== 200) {
      const status = [400, 403].includes(result.status) ? result.status : 503;
      throw new HttpError(status, status === 400 ? 'Invalid participation request.' :
        status === 403 ? 'Participation denied.' : 'Provider unavailable.');
    }
    return sanitized(result.body);
  }
}

/** All mutating/access operations are serialized in this single local process.
 * Local revocation is committed BEFORE provider removal; failed removal can be
 * retried. This is not an atomic transaction spanning SQLite and PostgreSQL.
 */
export function createLocalAccess({ mode, dbPath, adminSecret, conversationId, provider,
  now = Date.now, authLifetimeMs = 15 * 60_000, sessionLifetimeMs = 30 * 60_000, admissionGuard,
  identityMode, identityFoundation, httpProfile }) {
  if (mode !== MODE || !secretPattern.test(adminSecret) ||
      !/^[0-9][A-Za-z0-9_-]{5,99}$/u.test(conversationId) || !provider) {
    throw new Error('Explicit fixture-only synthetic mode and valid configuration are required.');
  }
  if (adminSecret === provider.gatewaySecret || adminSecret === provider.providerSecret) {
    throw new Error('Administrator credential must be separate.');
  }
  if (admissionGuard && (typeof admissionGuard.assertActive !== 'function' || typeof admissionGuard.close !== 'function')) {
    throw new Error('Invalid synthetic admission guard.');
  }
  const integrated = identityMode === INTEGRATED_IDENTITY_MODE;
  const strictService = httpProfile === STRICT_SERVICE_HTTP_PROFILE;
  if (httpProfile !== undefined && (!strictService || !integrated || !admissionGuard)) {
    throw new Error('Strict service HTTP profile requires verified identity and activation.');
  }
  if ((identityMode !== undefined && !integrated) || (identityFoundation !== undefined && !integrated) ||
      (integrated && (!admissionGuard || typeof identityFoundation?.isVerifiedPrincipal !== 'function' ||
        typeof identityFoundation?.participantXid !== 'function'))) {
    throw new Error('Strict synthetic identity integration configuration required.');
  }
  // Pin the trusted instance's methods; no HTTP request can replace this verifier.
  const verifyPrincipal = integrated ? identityFoundation.isVerifiedPrincipal.bind(identityFoundation) : undefined;
  const deriveXid = integrated ? identityFoundation.participantXid.bind(identityFoundation) : undefined;
  const identityCapabilities = new Map();
  const identityPrincipals = new Map();
  const db = new DatabaseSync(dbPath);
  const originalTables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").all().map(row => row.name);
  if ((!integrated && originalTables.includes('identity_mappings')) ||
      (integrated && originalTables.length && !originalTables.includes('identity_mappings'))) {
    db.close(); throw new Error('Use a separate strict synthetic identity database; mode conversion is not allowed.');
  }
  db.exec(`PRAGMA foreign_keys=ON; PRAGMA journal_mode=DELETE;
    CREATE TABLE IF NOT EXISTS round (id TEXT PRIMARY KEY, open INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS fixtures (id TEXT PRIMARY KEY, credential_hash TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS approvals (fixture TEXT NOT NULL REFERENCES fixtures(id),
      round TEXT NOT NULL REFERENCES round(id), xid TEXT NOT NULL UNIQUE,
      state TEXT NOT NULL CHECK(state IN ('pending','approved','revoked')),
      PRIMARY KEY(fixture,round));
    CREATE TABLE IF NOT EXISTS invitations (token_hash TEXT PRIMARY KEY,
      fixture TEXT NOT NULL, round TEXT NOT NULL, expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY,
      fixture TEXT NOT NULL, round TEXT NOT NULL, kind TEXT NOT NULL, expires INTEGER NOT NULL);`);
  if (integrated) db.exec(`CREATE TABLE IF NOT EXISTS identity_mappings (
    account_id TEXT PRIMARY KEY, fixture TEXT NOT NULL UNIQUE REFERENCES fixtures(id),
    round TEXT NOT NULL REFERENCES round(id), xid TEXT NOT NULL UNIQUE);`);
  const existing = db.prepare('SELECT id FROM round').all();
  if (existing.some((row) => row.id !== conversationId)) { db.close(); throw new Error('Database is bound to a different round.'); }
  db.prepare('INSERT OR IGNORE INTO round(id) VALUES(?)').run(conversationId);
  const closeLocal = () => {
    identityCapabilities.clear(); identityPrincipals.clear();
    db.exec('BEGIN IMMEDIATE');
    try {
      db.prepare('UPDATE round SET open=0 WHERE id=?').run(conversationId);
      db.prepare('DELETE FROM sessions').run();
      db.prepare('UPDATE invitations SET used=1').run();
      db.exec('COMMIT');
    } catch (error) { db.exec('ROLLBACK'); throw error; }
  };
  let admissionGeneration;
  // The dedicated wrapper starts closed and invalidates pre-restart authority.
  // The older standalone fixture harness deliberately retains its original API.
  if (admissionGuard) {
    if (db.prepare('SELECT count(*) AS n FROM fixtures').get().n > 20) {
      db.close(); throw new Error('Controlled synthetic fixture capacity exceeded.');
    }
    closeLocal();
  }
  const checkAdmission = (expectedGeneration) => {
    if (!admissionGuard) return undefined;
    try {
      const generation = admissionGuard.assertActive();
      if (typeof generation !== 'string' || !generation) throw new Error('Missing generation.');
      if (generation !== admissionGeneration) { closeLocal(); admissionGeneration = generation; }
      if (expectedGeneration !== undefined && generation !== expectedGeneration) throw new Error('Authority changed.');
      return generation;
    } catch {
      closeLocal(); admissionGeneration = undefined;
      throw new HttpError(403, 'Current deployment activation required.');
    }
  };
  const approval = (fixture) => db.prepare('SELECT * FROM approvals WHERE fixture=? AND round=?').get(fixture, conversationId);
  const roundOpen = () => db.prepare('SELECT open FROM round WHERE id=?').get(conversationId).open === 1;
  const invalidateIdentity = (fixture) => {
    for (const [key, capability] of identityCapabilities) if (capability.fixture === fixture) identityCapabilities.delete(key);
    identityPrincipals.delete(fixture);
    db.prepare('DELETE FROM sessions WHERE fixture=? AND round=?').run(fixture, conversationId);
    db.prepare('UPDATE invitations SET used=1 WHERE fixture=? AND round=?').run(fixture, conversationId);
  };
  const assertPrincipal = (principal, expectedFixture) => {
    try {
      if (!integrated || verifyPrincipal(principal) !== true || !Object.isFrozen(principal) ||
          principal.emailVerifiedByIssuer !== true || principal.mode !== 'SYNTHETIC_ONLY' ||
          principal.assurance !== 'OIDC_ID_TOKEN_VERIFIED' ||
          typeof principal.accountId !== 'string' || !/^acct_[A-Za-z0-9_-]{43}$/u.test(principal.accountId)) throw new Error();
      const fixture = 'synthetic_i' + hash(principal.accountId).slice(0, 39);
      const derived = deriveXid(principal, conversationId);
      if (derived?.ok !== true || typeof derived.xid !== 'string' || !/^fncp_[A-Za-z0-9_-]{43}$/u.test(derived.xid) ||
          (expectedFixture !== undefined && fixture !== expectedFixture)) throw new Error();
      const mapping = db.prepare('SELECT * FROM identity_mappings WHERE account_id=?').get(principal.accountId);
      if ((!mapping && expectedFixture !== undefined) ||
          mapping && (mapping.fixture !== fixture || mapping.round !== conversationId || mapping.xid !== derived.xid)) throw new Error();
      return { accountId: principal.accountId, fixture, xid: derived.xid };
    } catch {
      if (expectedFixture) invalidateIdentity(expectedFixture);
      throw new HttpError(401, 'Current verified synthetic identity required.');
    }
  };
  const assertFixturePrincipal = (fixture) => {
    if (!integrated) return undefined;
    const principal = identityPrincipals.get(fixture);
    assertPrincipal(principal, fixture);
    return principal;
  };
  const issueSession = (fixture, kind, duration, principal) => {
    const value = token();
    db.prepare('INSERT INTO sessions VALUES(?,?,?,?,?)').run(hash(value), fixture, conversationId, kind, now() + duration);
    if (integrated) identityCapabilities.set(hash(value), { fixture, kind, principal });
    return value;
  };
  const currentSession = (authorization, kind) => {
    const supplied = /^Bearer ([A-Za-z0-9_-]{32,512})$/u.exec(authorization ?? '')?.[1];
    const session = supplied ? db.prepare('SELECT * FROM sessions WHERE token_hash=?').get(hash(supplied)) : undefined;
    if (!session || session.kind !== kind || session.round !== conversationId || session.expires <= now()) {
      throw new HttpError(401, 'Session required.');
    }
    if (integrated) {
      const capability = identityCapabilities.get(hash(supplied));
      if (!capability || capability.fixture !== session.fixture || capability.kind !== kind) {
        invalidateIdentity(session.fixture); throw new HttpError(401, 'Current verified synthetic identity required.');
      }
      assertPrincipal(capability.principal, session.fixture);
    }
    return session;
  };
  const assertApproved = (fixture) => {
    wordpressGate.assertCurrent(fixture);
    const row = approval(fixture);
    if (!row || row.state !== 'approved') throw new HttpError(403, 'Round approval required.');
    if (integrated) {
      const mapping = db.prepare('SELECT * FROM identity_mappings WHERE fixture=? AND round=?').get(fixture, conversationId);
      if (!mapping || mapping.xid !== row.xid) {
        invalidateIdentity(fixture); throw new HttpError(403, 'Mapped round approval required.');
      }
    }
    return row;
  };

  async function dispatch(method, path, body, authorization) {
    const key = `${method} ${path}`;
    if (key === 'GET /health') return [200, { mode: 'SYNTHETIC_ONLY', productionReady: false,
      mailboxOwnership: integrated ? 'SYNTHETIC_OIDC_ISSUER_ASSERTION' : 'SIMULATED',
      identityMode: integrated ? INTEGRATED_IDENTITY_MODE : 'fixture-simulator',
      heritageVerification: false, realEmailEnabled: false }];
    if (path.startsWith('/test-admin/')) {
      if (!equal(authorization, `Bearer ${adminSecret}`)) throw new HttpError(404, 'Not found.');
      if (key === 'GET /test-admin/status') {
        try { checkAdmission(); } catch { /* status remains readable while closed */ }
        return [200, {
        mode: 'SYNTHETIC_ONLY', open: roundOpen(),
        fixtures: db.prepare('SELECT count(*) AS n FROM fixtures').get().n,
        approvals: db.prepare("SELECT state,count(*) AS count FROM approvals GROUP BY state").all(),
      }]; }
      if (key === 'POST /test-admin/fixtures') {
        if (integrated) throw new HttpError(404, 'Not found.');
        exact(body, ['fixture']);
        if (typeof body.fixture !== 'string' || !fixturePattern.test(body.fixture)) throw new HttpError(400, 'Use a synthetic fixture name.');
        if (db.prepare('SELECT id FROM fixtures WHERE id=?').get(body.fixture)) throw new HttpError(409, 'Fixture already exists.');
        if (admissionGuard && db.prepare('SELECT count(*) AS n FROM fixtures').get().n >= 20) {
          throw new HttpError(409, 'Controlled synthetic fixture capacity reached.');
        }
        const fixtureSecret = token();
        db.prepare('INSERT INTO fixtures VALUES(?,?)').run(body.fixture, hash(fixtureSecret));
        return [201, { fixture: body.fixture, fixtureSecret, warning: 'SIMULATED mailbox ownership; no email sent.' }];
      }
      if (key === 'POST /test-admin/round') {
        exact(body, ['open']);
        if (typeof body.open !== 'boolean') throw new HttpError(400, 'Invalid request.');
        if (body.open) checkAdmission();
        db.prepare('UPDATE round SET open=? WHERE id=?').run(Number(body.open), conversationId);
        if (!body.open) {
          if (integrated) { identityCapabilities.clear(); identityPrincipals.clear(); }
          db.prepare("DELETE FROM sessions WHERE kind='participation'").run();
          db.prepare('UPDATE invitations SET used=1').run();
          admissionGuard?.close(); admissionGeneration = undefined;
        }
        return [200, { open: body.open, boundary: 'LOCAL_GATEWAY_ONLY' }];
      }
      if (['POST /test-admin/approve', 'POST /test-admin/revoke', 'POST /test-admin/invitations'].includes(key)) {
        exact(body, ['fixture'], key.endsWith('invitations') ? ['ttlSeconds'] : []);
        if (typeof body.fixture !== 'string' || !fixturePattern.test(body.fixture) || !db.prepare('SELECT id FROM fixtures WHERE id=?').get(body.fixture)) {
          throw new HttpError(400, 'Unknown synthetic fixture.');
        }
        if (key.endsWith('/approve')) {
          const approvalGeneration = integrated ? checkAdmission() : undefined;
          if (integrated) assertFixturePrincipal(body.fixture);
          let row = approval(body.fixture);
          if (row?.state === 'revoked') throw new HttpError(409, 'Revocation is terminal in this proof.');
          wordpressGate.assertNotRevoked(body.fixture);
          const mapping = integrated ? db.prepare('SELECT * FROM identity_mappings WHERE fixture=? AND round=?').get(body.fixture, conversationId) : undefined;
          if (integrated && (!mapping || row && row.xid !== mapping.xid)) throw new HttpError(403, 'Mapped synthetic identity required.');
          if (!row) {
            db.prepare('INSERT INTO approvals VALUES(?,?,?,?)').run(body.fixture, conversationId, integrated ? mapping.xid : 'fncp_' + token(), 'pending');
            row = approval(body.fixture);
          }
          await provider.allowlist('upsert', row.xid);
          if (integrated) { checkAdmission(approvalGeneration); assertFixturePrincipal(body.fixture); }
          const confirmed = await provider.allowlist('readback', row.xid);
          if (integrated) { checkAdmission(approvalGeneration); assertFixturePrincipal(body.fixture); }
          if (!confirmed.present || confirmed.operationVersion !== 1) throw new Error('Provider readback mismatch.');
          db.prepare("UPDATE approvals SET state='approved' WHERE fixture=? AND round=?").run(body.fixture, conversationId);
          return [200, { state: 'approved', description: 'Approved for this synthetic round; not heritage verified.' }];
        }
        if (key.endsWith('/revoke')) {
          const row = approval(body.fixture);
          if (!row) throw new HttpError(409, 'No approval to revoke.');
          if (integrated) {
            for (const [key, capability] of identityCapabilities) if (capability.fixture === body.fixture) identityCapabilities.delete(key);
            identityPrincipals.delete(body.fixture);
          }
          db.exec('BEGIN IMMEDIATE');
          try {
            db.prepare("UPDATE approvals SET state='revoked' WHERE fixture=? AND round=?").run(body.fixture, conversationId);
            db.prepare('DELETE FROM sessions WHERE fixture=? AND round=?').run(body.fixture, conversationId);
            db.prepare('UPDATE invitations SET used=1 WHERE fixture=? AND round=?').run(body.fixture, conversationId);
            db.exec('COMMIT');
          } catch (error) { db.exec('ROLLBACK'); throw error; }
          await provider.allowlist('remove', row.xid);
          const confirmed = await provider.allowlist('readback', row.xid);
          if (confirmed.present || confirmed.operationVersion !== 2) throw new Error('Provider removal mismatch.');
          return [200, { state: 'revoked', providerRemovalVerified: true }];
        }
        checkAdmission();
        assertFixturePrincipal(body.fixture);
        assertApproved(body.fixture);
        if (!roundOpen()) throw new HttpError(403, 'Round closed.');
        const ttl = body.ttlSeconds ?? 600;
        if (!Number.isInteger(ttl) || ttl < 1 || ttl > 900) throw new HttpError(400, 'Invitation lifetime must be 1–900 seconds.');
        const invitationToken = token();
        // Reissuing invalidates unused earlier invitations for the same account.
        db.prepare('UPDATE invitations SET used=1 WHERE fixture=? AND round=?').run(body.fixture, conversationId);
        db.prepare('INSERT INTO invitations VALUES(?,?,?,?,0)').run(hash(invitationToken), body.fixture, conversationId, now() + ttl * 1000);
        return [201, { invitationToken, expiresAt: now() + ttl * 1000,
          delivery: 'LOCAL_RESPONSE_ONLY_NO_EMAIL_OR_MESSAGE' }];
      }
      throw new HttpError(404, 'Not found.');
    }
    if (key === 'POST /test-auth/mailbox-simulator') {
      if (integrated) throw new HttpError(404, 'Not found.');
      exact(body, ['fixture', 'fixtureSecret']);
      const row = typeof body.fixture === 'string' ? db.prepare('SELECT * FROM fixtures WHERE id=?').get(body.fixture) : undefined;
      if (!row || typeof body.fixtureSecret !== 'string' || !secretPattern.test(body.fixtureSecret) || !equal(hash(body.fixtureSecret), row.credential_hash)) {
        throw new HttpError(401, 'Fixture authentication failed.');
      }
      return [200, { fixtureAuthToken: issueSession(row.id, 'fixture-auth', authLifetimeMs),
        mailboxOwnership: 'SIMULATED_NOT_VERIFIED' }];
    }
    if (key === 'POST /invitations/redeem') {
      exact(body, ['invitationToken']);
      checkAdmission();
      const session = currentSession(authorization, 'fixture-auth');
      assertApproved(session.fixture);
      if (!roundOpen()) throw new HttpError(403, 'Round closed.');
      if (typeof body.invitationToken !== 'string' || !secretPattern.test(body.invitationToken)) throw new HttpError(403, 'Invitation not valid for this account.');
      const invitation = db.prepare('SELECT * FROM invitations WHERE token_hash=?').get(hash(body.invitationToken));
      if (!invitation || invitation.fixture !== session.fixture || invitation.round !== conversationId ||
          invitation.used || invitation.expires <= now()) throw new HttpError(403, 'Invitation not valid for this account.');
      db.exec('BEGIN IMMEDIATE');
      try {
        const used = db.prepare('UPDATE invitations SET used=1 WHERE token_hash=? AND used=0').run(hash(body.invitationToken));
        if (used.changes !== 1) throw new HttpError(403, 'Invitation already used.');
        // A new redemption replaces earlier participation sessions.
        db.prepare("DELETE FROM sessions WHERE fixture=? AND round=? AND kind='participation'").run(session.fixture, conversationId);
        const principal = integrated ? identityCapabilities.get(hash(authorization.slice(7)))?.principal : undefined;
        if (integrated) for (const [key, capability] of identityCapabilities) {
          if (capability.fixture === session.fixture && capability.kind === 'participation') identityCapabilities.delete(key);
        }
        const participationToken = issueSession(session.fixture, 'participation', sessionLifetimeMs, principal);
        db.exec('COMMIT');
        return [201, { participationToken, identity: 'OPAQUE_SERVER_SIDE', mode: 'SYNTHETIC_ONLY' }];
      } catch (error) { db.exec('ROLLBACK'); throw error; }
    }
    if (key === 'POST /session/logout') {
      exact(body, []);
      if (integrated) {
        // Logout is a negative operation: even an expired principal/token may
        // remove its server-held capabilities. It never grants new authority.
        const supplied = /^Bearer ([A-Za-z0-9_-]{32,512})$/u.exec(authorization ?? '')?.[1];
        const session = supplied ? db.prepare('SELECT * FROM sessions WHERE token_hash=?').get(hash(supplied)) : undefined;
        if (!session || session.round !== conversationId || !['fixture-auth', 'participation'].includes(session.kind)) {
          throw new HttpError(401, 'Session required.');
        }
        invalidateIdentity(session.fixture);
      } else {
        currentSession(authorization, 'participation');
        db.prepare('DELETE FROM sessions WHERE token_hash=?').run(hash(authorization.slice(7)));
      }
      return [200, { loggedOut: true }];
    }
    const capability = { 'GET /polis/participation-init': 'init', 'GET /polis/next-comment': 'next', 'POST /polis/votes': 'vote' }[key];
    if (capability) {
      const operationGeneration = checkAdmission();
      if (capability === 'vote') {
        exact(body, ['tid', 'vote']);
        if (!Number.isSafeInteger(body.tid) || body.tid < 0 || ![-1, 0, 1].includes(body.vote)) {
          throw new HttpError(400, 'Invalid fixed-statement vote.');
        }
      }
      const session = currentSession(authorization, 'participation');
      const row = assertApproved(session.fixture);
      if (!roundOpen()) throw new HttpError(403, 'Round closed.');
      const result = await provider.participate(capability, row.xid, capability === 'vote' ? body : {});
      // Withhold an expired/closed in-flight response; this cannot undo a vote
      // already accepted by the provider. Never automatically retry that vote.
      checkAdmission(operationGeneration);
      currentSession(authorization, 'participation');
      assertApproved(session.fixture);
      return [200, sanitized(result)];
    }
    throw new HttpError(404, 'Not found.');
  }

  const wordpressGate = createWordPressEventGate({ db, HttpError, requireApproval: integrated, apply: async (event) => {
    const fixture = event.subject;
    if (event.state === 'revoked' && !approval(fixture)) {
      if (integrated) invalidateIdentity(fixture);
      return;
    }
    await dispatch('POST', '/test-admin/' + (event.state === 'approved' ? 'approve' : 'revoke'),
      { fixture }, `Bearer ${adminSecret}`);
  } });
  let chain = Promise.resolve(); let pendingOperations = 0;
  let closing = false; let closePromise; let cancelListen;
  const reserve = () => {
    if (closing) throw new HttpError(503, 'Local service is closing.');
    if (pendingOperations >= MAX_PENDING_OPERATIONS) throw new HttpError(503, 'Local request capacity reached.');
    pendingOperations += 1;
    let released = false;
    return () => { if (!released) { released = true; pendingOperations -= 1; } };
  };
  const enqueue = (operation) => {
    const current = chain.then(operation);
    chain = current.catch(() => {});
    return current;
  };
  const enqueueDirect = (operation) => {
    let release;
    try { release = reserve(); } catch (error) { return Promise.reject(error); }
    return enqueue(operation).finally(release);
  };
  const server = createServer(async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
    const reply = (status, body) => {
      if (res.destroyed || res.writableEnded) return;
      // Early rejection must not retain a socket awaiting an unread slow body.
      if (closing || !req.complete) res.setHeader('Connection', 'close');
      res.writeHead(status); res.end(JSON.stringify(body));
    };
    let release;
    try {
      release = reserve(); // Includes incomplete bodies, before collecting bytes.
      const address = server.address();
      if (req.socket.remoteAddress !== '127.0.0.1' || req.headers.host !== `127.0.0.1:${address.port}` ||
          req.headers.origin || req.headers.cookie || req.headers['sec-fetch-site'] ||
          Object.keys(req.headers).some((key) => key.startsWith('x-fncp-'))) {
        throw new HttpError(403, 'Local API access only.');
      }
      if (!req.url?.startsWith('/') || req.url.includes('?') || req.url.includes('%') || req.url.includes('\\')) {
        throw new HttpError(400, 'Invalid path.');
      }
      // This policy belongs to the HTTP boundary, not dispatch: authenticated
      // signed-event ingest still needs its private, serialized approval path.
      // Possession of the old test bearer never re-enables operator HTTP routes.
      if (strictService && (req.url.startsWith('/test-admin') || req.url.startsWith('/test-auth'))) {
        throw new HttpError(404, 'Not found.');
      }
      let size = 0; const chunks = [];
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 4096) throw new HttpError(413, 'Request too large.');
        chunks.push(chunk);
      }
      let body = {};
      if (req.method === 'POST') {
        if (req.headers['content-type'] !== 'application/json') throw new HttpError(415, 'JSON required.');
        try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
        catch { throw new HttpError(400, 'Invalid JSON.'); }
      } else if (size) throw new HttpError(400, 'Unexpected body.');
      const current = enqueue(() => dispatch(req.method, req.url, body, req.headers.authorization));
      const [status, result] = await current;
      reply(status, result);
    } catch (error) {
      reply(error instanceof HttpError ? error.status : 503,
        { error: error instanceof HttpError ? error.message : 'Local proof operation unavailable.', mode: 'SYNTHETIC_ONLY' });
    } finally { release?.(); }
  });
  server.requestTimeout = 12000; server.headersTimeout = 5000;
  return {
    ...(strictService ? { operator: Object.freeze({
      status(...args) {
        return enqueueDirect(async () => {
          if (args.length !== 0) throw new HttpError(400, 'Invalid private operator request.');
          const [, result] = await dispatch('GET', '/test-admin/status', {}, `Bearer ${adminSecret}`);
          return result;
        });
      },
      setRoundOpen(...args) {
        return enqueueDirect(async () => {
          if (args.length !== 1 || typeof args[0] !== 'boolean') throw new HttpError(400, 'Invalid private operator request.');
          const [, result] = await dispatch('POST', '/test-admin/round', { open: args[0] }, `Bearer ${adminSecret}`);
          return result;
        });
      },
      issueInvitation(...args) {
        return enqueueDirect(async () => {
          if (args.length !== 1 || typeof args[0] !== 'string' || !/^synthetic_i[a-f0-9]{39}$/u.test(args[0])) {
            throw new HttpError(400, 'Invalid private operator request.');
          }
          // The existing current-identity, signed-approval, activation and open
          // round checks remain authoritative. No direct approval or custom TTL.
          const [, result] = await dispatch('POST', '/test-admin/invitations', { fixture: args[0] }, `Bearer ${adminSecret}`);
          return result;
        });
      },
    }) } : {}),
    ...(integrated ? { authenticateIdentity(principal) {
      return enqueueDirect(() => {
        // Login alone grants no participation. Synchronize any active generation
        // before minting; a future activation still invalidates these capabilities.
        try { checkAdmission(); } catch { /* authentication is allowed while closed */ }
        const identity = assertPrincipal(principal);
        wordpressGate.assertNotRevoked(identity.fixture);
        if (approval(identity.fixture)?.state === 'revoked') throw new HttpError(403, 'Round approval revoked.');
        const existing = db.prepare('SELECT * FROM identity_mappings WHERE account_id=?').get(identity.accountId);
        if (!existing) {
          if (db.prepare('SELECT count(*) AS n FROM identity_mappings').get().n >= 20) throw new HttpError(409, 'Controlled synthetic identity capacity reached.');
          db.exec('BEGIN IMMEDIATE');
          try {
            // Unusable random hash supports the legacy table shape; no fixture
            // credential is minted or exposed and the simulator is disabled.
            db.prepare('INSERT INTO fixtures VALUES(?,?)').run(identity.fixture, hash(token()));
            db.prepare('INSERT INTO identity_mappings VALUES(?,?,?,?)').run(identity.accountId, identity.fixture, conversationId, identity.xid);
            db.exec('COMMIT');
          } catch (error) { db.exec('ROLLBACK'); throw error; }
        }
        invalidateIdentity(identity.fixture);
        identityPrincipals.set(identity.fixture, principal);
        const fixtureAuthToken = issueSession(identity.fixture, 'fixture-auth', authLifetimeMs, principal);
        return { fixtureAuthToken, fixture: identity.fixture, mode: 'SYNTHETIC_ONLY', assurance: 'OIDC_ID_TOKEN_VERIFIED' };
      });
    }, registrationIdentity(principal) {
      return enqueueDirect(() => {
        // Private BFF read only: an identity assertion alone is insufficient.
        // Synchronize activation before inspecting capabilities so a new lease
        // cannot revive authentication from an earlier generation or process.
        checkAdmission();
        const identity = assertPrincipal(principal);
        if (identityPrincipals.get(identity.fixture) !== principal) {
          throw new HttpError(401, 'Current verified synthetic identity required.');
        }
        assertPrincipal(principal, identity.fixture);
        const authenticated = [...identityCapabilities].some(([key, capability]) => {
          if (capability.principal !== principal || capability.fixture !== identity.fixture ||
              capability.kind !== 'fixture-auth') return false;
          const session = db.prepare('SELECT * FROM sessions WHERE token_hash=?').get(key);
          return session?.fixture === identity.fixture && session.round === conversationId &&
            session.kind === 'fixture-auth' && session.expires > now();
        });
        if (!authenticated) throw new HttpError(401, 'Current verified synthetic identity required.');
        wordpressGate.assertNotRevoked(identity.fixture);
        if (approval(identity.fixture)?.state === 'revoked') throw new HttpError(403, 'Round approval revoked.');
        // Registration may precede approval and an open round. No session,
        // invitation, provider operation or eligibility decision is created.
        return Object.freeze({ mode: 'SYNTHETIC_ONLY', fixture: identity.fixture, roundId: ROUND });
      });
    } } : {}),
    // In-process, authenticated receiver only; no new general-purpose HTTP admin route.
    ingestWordPressEvent(event) {
      return enqueueDirect(() => wordpressGate.ingest(event));
    },
    async listen(port = 8099) {
      if (closing) throw new Error('Local service is closing.');
      if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('Invalid local port.');
      if (cancelListen || server.listening) throw new Error('Local service is already starting or listening.');
      return new Promise((resolve, reject) => {
        let settled = false;
        const settle = (error) => {
          if (settled) return;
          settled = true; cancelListen = undefined;
          server.off('error', onError); server.off('listening', onListening);
          if (error) reject(error);
          else resolve(`http://127.0.0.1:${server.address().port}`);
        };
        const onError = (error) => settle(error);
        const onListening = () => settle();
        // Native close can suppress the listening callback. Settle our caller
        // explicitly, and detach both listeners on every completion path.
        cancelListen = () => settle(new Error('Local service is closing.'));
        server.once('error', onError); server.once('listening', onListening);
        try { server.listen(port, '127.0.0.1'); } catch (error) { settle(error); }
      });
    },
    close() {
      if (closePromise) return closePromise;
      closing = true; // Synchronous latch: no direct/HTTP operation may join the drain.
      cancelListen?.();
      closePromise = (async () => {
        await new Promise((resolve, reject) => server.close((error) => {
          if (error && error.code !== 'ERR_SERVER_NOT_RUNNING') reject(error); else resolve();
        }));
        // Already admitted work retains its real outcome. Do not timeout or
        // replay a provider side effect merely to make shutdown look complete.
        await chain; identityCapabilities.clear(); identityPrincipals.clear(); db.close();
      })();
      return closePromise;
    },
  };
}
