/** Invented principals plus in-memory WordPress HTTP model; no runtime/services. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID, createHash } from 'node:crypto';
import { createServerRegistrationBridge, ServerRegistrationError } from './server-registration.mjs';
import { createRegistrationIssuer, signEnvelope, CHALLENGE_DOMAIN, CONSENT_VERSION } from './registration-issuer.mjs';

const ORIGIN = 'http://127.0.0.1:8103';
const opaque = () => randomBytes(32).toString('base64url');
const digest = value => createHash('sha256').update(value).digest('hex');
const consent = () => ({ adultSelfAttested: true, eligibilitySelfAttested: true, registrationConsent: true, consentVersion: CONSENT_VERSION });
const denied = code => error => error instanceof ServerRegistrationError && error.code === code && !error.message.includes('synthetic_private_sentinel');
const response = (body, cookie, extra = {}) => new Response(JSON.stringify(body), { status: 200,
  headers: { 'Content-Type': 'application/json; charset=UTF-8', 'Cache-Control': 'no-store, private',
    ...(cookie ? { 'Set-Cookie': `fncp_wp_identity=${cookie}; Path=/; HttpOnly; SameSite=Strict` } : {}), ...extra } });

function model(options = {}) {
  let stamp = 1_900_000_000_000; const records = new WeakMap(); const guests = new Map();
  const secret = opaque(); const calls = []; const issued = []; let hook = options.hook;
  const issuer = createRegistrationIssuer({ mode: 'SYNTHETIC_ONLY', challengeSecret: secret, registrationSecret: opaque(), now: () => stamp,
    registrationIdentity: async principal => {
      if (!records.has(principal) || records.get(principal).expires <= stamp) throw new Error('synthetic_private_sentinel');
      return { mode: 'SYNTHETIC_ONLY', fixture: records.get(principal).fixture, roundId: 'synthetic_round_local' };
    }, principalDeadline: principal => records.get(principal)?.expires });
  const registrationIssuer = Object.freeze({ mode: 'SYNTHETIC_ONLY', async issue(request) {
    const result = await issuer.issue(request); issued.push({ request, result }); return result;
  } });
  const fetchImpl = async (url, init) => {
    const fields = init.body ? new URLSearchParams(init.body) : undefined;
    const action = fields?.get('action') ?? new URL(url).searchParams.get('action');
    const call = { url, init, action, fields }; calls.push(call);
    const overridden = await hook?.(call, calls.length);
    if (overridden !== undefined) return overridden;
    assert.ok(url === ORIGIN + '/wp-admin/admin-post.php' + (fields ? '' : '?action=fncp_identity_session'));
    assert.equal(init.redirect, 'error'); assert.equal(init.headers.Authorization, undefined);
    assert.equal(init.headers['X-FNCP-Gateway-Key'], undefined);
    if (action === 'fncp_identity_session') {
      assert.equal(init.headers.Cookie, undefined);
      const cookie = opaque(); const csrf = opaque(); guests.set(cookie, { csrf });
      return response({ mode: 'SYNTHETIC_ONLY', csrfToken: csrf }, cookie);
    }
    assert.equal(init.headers.Origin, ORIGIN);
    assert.equal(init.headers['Content-Type'], 'application/x-www-form-urlencoded');
    const cookie = init.headers.Cookie?.slice('fncp_wp_identity='.length); const guest = guests.get(cookie);
    assert.ok(!!guest && fields.get('csrfToken') === guest.csrf);
    if (action === 'fncp_identity_challenge') {
      assert.deepEqual([...fields.keys()].sort(), ['action', 'csrfToken']);
      guest.challenge = signEnvelope({ schemaVersion: 1, purpose: 'wordpress-registration-challenge', audience: 'fncp-synthetic-bff',
        challengeId: randomUUID(), browserBinding: digest(cookie), roundId: 'synthetic_round_local',
        issuedAt: Math.floor(stamp / 1000), expiresAt: Math.floor(stamp / 1000) + 120 }, secret, CHALLENGE_DOMAIN);
      return response({ mode: 'SYNTHETIC_ONLY', challenge: guest.challenge });
    }
    if (action === 'fncp_identity_register') {
      assert.deepEqual([...fields.keys()].sort(), ['action', 'csrfToken', 'receipt']);
      const receipt = JSON.parse(fields.get('receipt'));
      assert.ok(issued.some(item => item.result.receipt.payload === receipt.payload && item.result.receipt.signature === receipt.signature));
      const claims = JSON.parse(Buffer.from(receipt.payload, 'base64url'));
      assert.ok(claims.browserBinding === digest(cookie));
      assert.equal(claims.registrationConsent, true);
      assert.equal(claims.adultSelfAttested, true); assert.equal(claims.eligibilitySelfAttested, true);
      return response({ mode: 'SYNTHETIC_ONLY', registered: true, registrationId: randomUUID(), csrfToken: opaque() }, opaque());
    }
    throw new Error('Unexpected local model action.');
  };
  const bridge = createServerRegistrationBridge({ registrationIssuer, now: () => stamp, fetchImpl, requestTimeoutMs: options.requestTimeoutMs ?? 3000 });
  const mint = () => { const principal = Object.freeze({ mode: 'SYNTHETIC_ONLY', assurance: 'OIDC_ID_TOKEN_VERIFIED' });
    records.set(principal, { expires: stamp + 60_000, fixture: 'synthetic_i' + digest(opaque()).slice(0, 39) }); return principal; };
  const input = principal => ({ principal, browserDeadline: stamp + 60_000, input: consent() });
  return { bridge, calls, issued, registrationIssuer, fetchImpl, mint, input, setHook(value) { hook = value; }, advance(ms) { stamp += ms; } };
}

test('bridge construction requires a synthetic issuer and bounded trusted transport settings', () => {
  for (const settings of [undefined, {}, { registrationIssuer: { mode: 'production', issue() {} } },
    { registrationIssuer: { mode: 'SYNTHETIC_ONLY' } },
    { registrationIssuer: { mode: 'SYNTHETIC_ONLY', issue() {} }, requestTimeoutMs: 3001 }]) {
    assert.throws(() => createServerRegistrationBridge(settings), /configuration rejected/u);
  }
});

test('seamless handoff uses three exact private WP requests and exposes only a pending registration reference', async () => {
  const m = model(); const result = await m.bridge.register(m.input(m.mint()));
  assert.deepEqual(Object.keys(result).sort(), ['registrationId', 'status']); assert.equal(Object.isFrozen(result), true);
  assert.equal(result.status, 'SUBMITTED_NOT_APPROVED'); assert.match(result.registrationId, /^[0-9a-f-]{36}$/u);
  assert.deepEqual(m.calls.map(call => call.action), ['fncp_identity_session', 'fncp_identity_challenge', 'fncp_identity_register']);
  assert.equal(m.issued.length, 1);
  for (const key of ['cookie', 'csrfToken', 'challenge', 'receipt', 'fixture', 'accountId', 'approved', 'invitationToken']) assert.equal(Object.hasOwn(result, key), false);
});

test('input rejects caller-selected identities/challenges/routes and every non-boolean or incomplete attestation before HTTP', async () => {
  const m = model(); const principal = m.mint();
  for (const input of [{ ...consent(), fixture: 'synthetic_caller' }, { ...consent(), challenge: {} },
    { ...consent(), url: 'https://invalid.example.test' }, { ...consent(), consentVersion: 'different' },
    { ...consent(), adultSelfAttested: false }, { ...consent(), registrationConsent: 'true' },
    { ...consent(), eligibilitySelfAttested: [] }, { registrationConsent: true }, null]) {
    await assert.rejects(m.bridge.register({ ...m.input(principal), input }), denied('INVALID_INPUT'));
  }
  assert.equal(m.calls.length, 0);
  assert.equal((await m.bridge.register(m.input(principal))).status, 'SUBMITTED_NOT_APPROVED');
});

test('absent or expired browser identity is denied before HTTP; copied branded-looking principal cannot produce a receipt', async () => {
  const m = model(); const principal = m.mint();
  for (const candidate of [null, {}, 'synthetic_string', Object.freeze({ mode: 'SYNTHETIC_ONLY' })]) {
    await assert.rejects(m.bridge.register(m.input(candidate)), denied('IDENTITY_REQUIRED'));
  }
  const expired = m.input(principal); m.advance(60_001);
  await assert.rejects(m.bridge.register(expired), denied('IDENTITY_REQUIRED')); assert.equal(m.calls.length, 0);
  await assert.rejects(m.bridge.register(m.input(Object.freeze({ ...principal }))), denied('UNCONFIRMED'));
  assert.equal(m.calls.filter(call => call.action === 'fncp_identity_register').length, 0);
});

test('same principal is one attempt after success or uncertain transport and never silently retried/adopted', async () => {
  const m = model(); const principal = m.mint(); const request = m.input(principal);
  await m.bridge.register(request); await assert.rejects(m.bridge.register(request), denied('ATTEMPT_USED'));
  assert.equal(m.calls.length, 3);
  const failed = model({ hook: call => { if (call.action === 'fncp_identity_register') throw new Error('synthetic_private_sentinel'); } });
  const uncertain = failed.input(failed.mint());
  await assert.rejects(failed.bridge.register(uncertain), denied('UNCONFIRMED'));
  await assert.rejects(failed.bridge.register(uncertain), denied('ATTEMPT_USED'));
  assert.equal(failed.calls.length, 3);
});

test('per-principal single flight and four-request global cap do not consume a rejected busy caller', async () => {
  let release; const blocked = new Promise(resolve => { release = resolve; });
  const m = model({ hook: call => call.action === 'fncp_identity_session' ? blocked : undefined });
  const requests = Array.from({ length: 5 }, () => m.input(m.mint()));
  const pending = requests.slice(0, 4).map(request => m.bridge.register(request));
  await assert.rejects(m.bridge.register(requests[0]), denied('ATTEMPT_USED'));
  await assert.rejects(m.bridge.register(requests[4]), denied('BUSY'));
  assert.equal(m.calls.length, 4); release(undefined);
  assert.equal((await Promise.all(pending)).length, 4);
  assert.equal((await m.bridge.register(requests[4])).status, 'SUBMITTED_NOT_APPROVED');
  assert.equal(m.calls.length, 15);
});

test('overlapping identities use independent guest cookies and never share challenge/receipt state', async () => {
  const m = model(); const outcomes = await Promise.all([m.bridge.register(m.input(m.mint())), m.bridge.register(m.input(m.mint()))]);
  assert.ok(outcomes[0].registrationId !== outcomes[1].registrationId);
  const posts = m.calls.filter(call => call.action === 'fncp_identity_register');
  assert.equal(posts.length, 2); assert.ok(posts[0].init.headers.Cookie !== posts[1].init.headers.Cookie);
  assert.ok(m.issued[0].request.input.challenge.payload !== m.issued[1].request.input.challenge.payload);
});

test('redirects, non-JSON, missing no-store, oversized and malformed responses stop with fixed redacted errors', async () => {
  const scenarios = [
    () => new Response('', { status: 302, headers: { Location: 'https://invalid.example.test/private' } }),
    () => new Response('synthetic_private_sentinel', { headers: { 'Content-Type': 'text/html' } }),
    () => new Response('{}', { headers: { 'Content-Type': 'application/json' } }),
    () => new Response('synthetic_private_sentinel'.repeat(1000), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } }),
    () => new Response('{"synthetic_private_sentinel":', { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } }),
    () => response({ mode: 'SYNTHETIC_ONLY', csrfToken: opaque() }, opaque(), { 'Content-Length': '9000' }),
  ];
  for (const scenario of scenarios) {
    const m = model({ hook: () => scenario() });
    await assert.rejects(m.bridge.register(m.input(m.mint())), denied('UNCONFIRMED')); assert.equal(m.calls.length, 1);
  }
});

test('guest cookie must be unique, local-path HttpOnly Strict and cannot be an administrator or broad-domain cookie', async () => {
  const cookieValues = [undefined, 'wordpress_logged_in_admin=synthetic_private_sentinel; Path=/; HttpOnly; SameSite=Strict',
    `fncp_wp_identity=${opaque()}; Path=/; SameSite=Strict`, `fncp_wp_identity=${opaque()}; Path=/; HttpOnly; SameSite=Lax`,
    `fncp_wp_identity=${opaque()}; Path=/; HttpOnly; SameSite=Strict; Domain=invalid.example.test`,
    `fncp_wp_identity=${opaque()}; Path=/; Path=/other; HttpOnly; SameSite=Strict`];
  for (const value of cookieValues) {
    const m = model({ hook: () => response({ mode: 'SYNTHETIC_ONLY', csrfToken: opaque() }, undefined, value ? { 'Set-Cookie': value } : {}) });
    await assert.rejects(m.bridge.register(m.input(m.mint())), denied('UNCONFIRMED')); assert.equal(m.calls.length, 1);
  }
  const m = model({ hook: () => { const result = response({ mode: 'SYNTHETIC_ONLY', csrfToken: opaque() }, opaque());
    result.headers.append('Set-Cookie', `fncp_wp_identity=${opaque()}; Path=/; HttpOnly; SameSite=Strict`); return result; } });
  await assert.rejects(m.bridge.register(m.input(m.mint())), denied('UNCONFIRMED'));
});

test('tampered challenge and unknown registration ACK fields cannot reach browser or become adopted registrations', async () => {
  const forged = model({ hook: call => call.action === 'fncp_identity_challenge'
    ? response({ mode: 'SYNTHETIC_ONLY', challenge: { payload: 'forged', signature: '0'.repeat(64) } }) : undefined });
  await assert.rejects(forged.bridge.register(forged.input(forged.mint())), denied('UNCONFIRMED'));
  assert.equal(forged.calls.length, 2);
  const malformed = model({ hook: call => call.action === 'fncp_identity_register'
    ? response({ mode: 'SYNTHETIC_ONLY', registered: true, registrationId: randomUUID(), csrfToken: opaque(),
      fixture: 'synthetic_private_sentinel' }, opaque()) : undefined });
  const request = malformed.input(malformed.mint());
  await assert.rejects(malformed.bridge.register(request), denied('UNCONFIRMED'));
  await assert.rejects(malformed.bridge.register(request), denied('ATTEMPT_USED')); assert.equal(malformed.calls.length, 3);
});

test('deadline changes during issuer or final WP response withhold success without repeating an uncertain register', async () => {
  const early = model({ hook: call => { if (call.action === 'fncp_identity_challenge') early.advance(60_001); } });
  await assert.rejects(early.bridge.register(early.input(early.mint())), denied('UNCONFIRMED'));
  assert.equal(early.calls.length, 2); assert.equal(early.issued.length, 0);
  const late = model({ hook: call => { if (call.action === 'fncp_identity_register') late.advance(60_001); } });
  const request = late.input(late.mint()); await assert.rejects(late.bridge.register(request), denied('UNCONFIRMED'));
  assert.equal(late.calls.length, 3); assert.equal(late.issued.length, 1);
});

test('bounded fetch timeout fails even when a model transport ignores abort; no automatic retry', async () => {
  const m = model({ requestTimeoutMs: 20, hook: () => new Promise(() => {}) });
  const request = m.input(m.mint()); const before = Date.now();
  await assert.rejects(m.bridge.register(request), denied('UNCONFIRMED'));
  assert.ok(Date.now() - before < 1000); assert.equal(m.calls.length, 1);
  await assert.rejects(m.bridge.register(request), denied('ATTEMPT_USED'));
});

test('bounded streamed body timeout fails even when response headers arrive and the body stalls', async () => {
  const m = model({ requestTimeoutMs: 20, hook: () => new Response(new ReadableStream({ start() {} }), {
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } }) });
  await assert.rejects(m.bridge.register(m.input(m.mint())), denied('UNCONFIRMED'));
  assert.equal(m.calls.length, 1);
});
