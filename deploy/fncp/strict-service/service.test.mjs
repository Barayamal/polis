import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:net';
import { readFileSync } from 'node:fs';
import { createStrictLocalService, STRICT_SERVICE_MODE } from './service.mjs';
import { createSyntheticIdentityHarness } from '../identity-foundation/synthetic-harness.mjs';
import { createSyntheticBrowserDriver } from '../identity-foundation/synthetic-browser-driver.mjs';
import { syntheticBinding, syntheticClaims, syntheticSigningFixture } from '../activation-foundation/synthetic-fixtures.mjs';
import { createBrowserClient } from '../local-browser/integration-client.mjs';
import { signEnvelope, CHALLENGE_DOMAIN, RECEIPT_DOMAIN } from '../wordpress-identity/registration-issuer.mjs';
import { createRedirectTlsLab } from '../identity-foundation/redirect-tls-lab.mjs';
import { createHttpsRedirectDriver } from '../identity-foundation/https-redirect-driver.mjs';

const seeds = JSON.parse(readFileSync(new URL('../seed-statements.json', import.meta.url), 'utf8'));
class Provider {
  conversationId = '9syntheticRoundTest'; states = new Map(); calls = 0; votes = 0;
  async allowlist(operation, xid) {
    this.calls++;
    if (operation === 'upsert' && this.states.get(xid)?.operationVersion !== 2) this.states.set(xid, { present: true, operationVersion: 1 });
    if (operation === 'remove') this.states.set(xid, { present: false, operationVersion: 2 });
    return this.states.get(xid) ?? { present: false, operationVersion: null };
  }
  async participate(kind, xid) {
    this.calls++;
    if (!this.states.get(xid)?.present) throw new Error('Model denied.');
    if (kind === 'vote') this.votes++;
    const statement = { tid: this.votes, txt: seeds[this.votes] };
    return kind === 'next' ? statement : { nextComment: statement };
  }
}
async function setup(t, edit = () => {}) {
  const harness = await createSyntheticIdentityHarness();
  const driver = createSyntheticBrowserDriver({ mode: 'SYNTHETIC_ONLY', identity: harness.identity,
    syntheticAuthorizationResponse: harness.authorizationResponse });
  const signer = syntheticSigningFixture(); const provider = new Provider();
  let binding; let principal;
  const input = { mode: STRICT_SERVICE_MODE, identity: harness.identity,
    oidcDriver: { mode: 'SYNTHETIC_ONLY',
      begin(value) { binding = value.browserSessionId; return driver.begin(value); },
      async complete(value) { const result = await driver.complete(value); principal = result.principal; return result; },
      discard: value => driver.discard(value) },
    provider, activation: { binding: syntheticBinding(), publicKey: signer.publicKey, keyId: signer.keyId },
    storage: { access: ':memory:', activation: ':memory:' }, eventSecret: randomBytes(32).toString('base64url') };
  edit(input);
  const service = await createStrictLocalService(input); t.after(() => service.close());
  let origins;
  return { service, input, provider, harness,
    async start() { ({ origins } = await service.start()); return origins; },
    activate() { return service.operator.activate(signer.signClaims(syntheticClaims(service.operator.activationBinding(),
      Math.floor(Date.now() / 1000), { sequence: service.operator.nextActivationSequence() }))); },
    async login(client, subject = 'synthetic_service_alice') {
      await client.session(); assert.equal((await client.oidcStart()).status, 200);
      const response = await driver.injectTestResponse({ browserSessionId: binding, syntheticSubject: subject, emailVerifiedByIssuer: true });
      const result = await client.oidcCallback(response.callback.callbackUrl);
      return { result, fixture: principal && 'synthetic_i' + createHash('sha256').update(principal.accountId).digest('hex').slice(0, 39) };
    },
    event(fixture, state, version) { return { schema_version: 1, event_id: randomUUID(), subject: fixture,
      round_id: 'synthetic_round_local', version, state, occurred_at: new Date().toISOString().replace(/\.\d{3}Z$/u, 'Z') }; },
    async send(event, secret = input.eventSecret) {
      const stamp = String(Math.floor(Date.now() / 1000)); const raw = JSON.stringify(event);
      const signature = createHmac('sha256', secret).update(stamp + '.' + raw).digest('hex');
      const response = await fetch(origins.receiver + '/internal/wordpress/events', { method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-FNCP-WP-Timestamp': stamp,
          'X-FNCP-WP-Signature': 'sha256=' + signature, 'X-FNCP-WP-Event-ID': event.event_id }, body: raw });
      return { status: response.status, body: await response.json() };
    } };
}

test('strict service constructs without listeners and starts all three closed', async t => {
  const h = await setup(t);
  assert.equal(h.service.snapshot().state, 'CREATED');
  assert.equal(h.provider.calls, 0);
  assert.throws(() => h.service.operator.status(), /not running/u);
  const origins = await h.start();
  assert.deepEqual(Object.keys(origins), ['access', 'receiver', 'browser']);
  assert.equal(h.service.snapshot().state, 'RUNNING');
  assert.equal(h.service.snapshot().httpTestAdministration, false);
  assert.equal((await h.service.operator.status()).open, false);
  await assert.rejects(h.service.operator.setRoundOpen(true), { status: 403 });
  assert.equal(h.provider.calls, 0);
  assert.ok(!/127\.0\.0\.1|Secret|sqlite|privateKey/u.test(JSON.stringify(h.service.snapshot())));
});

test('strict composed HTTP has no admin, fixture or activation endpoint', async t => {
  const h = await setup(t); const origins = await h.start();
  for (const path of ['/test-admin/status', '/test-admin/fixtures', '/test-admin/round', '/test-admin/approve',
    '/test-admin/revoke', '/test-admin/invitations', '/test-auth/mailbox-simulator', '/activation']) {
    const response = await fetch(origins.access + path);
    assert.equal(response.status, 404, path);
  }
  assert.equal(h.service.sendEvent, undefined); assert.equal(h.service.inject, undefined);
  assert.equal(h.service.authenticateIdentity, undefined); assert.equal(h.service.request, undefined);
  assert.equal(h.service.operator.approve, undefined); assert.equal(h.service.operator.revoke, undefined);
  assert.equal(h.service.operator.privateKey, undefined);
  assert.equal(h.provider.calls, 0);
});

test('strict composition carries signed login approval invitation vote and warm revocation without HTTP admin', async t => {
  const h = await setup(t); const origins = await h.start(); h.activate(); await h.service.operator.setRoundOpen(true);
  const alice = createBrowserClient(origins.browser); const bob = createBrowserClient(origins.browser);
  const a = await h.login(alice); const b = await h.login(bob, 'synthetic_service_bob');
  assert.equal(a.result.status, 200); assert.equal(b.result.status, 200);
  assert.equal((await alice.login('synthetic_fallback', 'a'.repeat(43))).status, 404);
  await assert.rejects(h.service.operator.issueInvitation(a.fixture), { status: 403 });
  assert.equal((await alice.initialize()).status, 403);
  const approval = h.event(a.fixture, 'approved', 1);
  assert.equal((await h.send(approval, randomBytes(32).toString('base64url'))).status, 401);
  assert.equal((await h.send(approval)).body.outcome, 'APPLIED');
  assert.equal((await h.send(approval)).body.outcome, 'IDEMPOTENT_NO_OP');
  assert.equal((await h.send(h.event(b.fixture, 'approved', 1))).status, 200);
  const invite = await h.service.operator.issueInvitation(a.fixture);
  assert.equal(invite.delivery, 'LOCAL_RESPONSE_ONLY_NO_EMAIL_OR_MESSAGE');
  assert.equal((await bob.redeem(invite.invitationToken)).status, 403);
  assert.equal((await alice.redeem(invite.invitationToken)).status, 200);
  const statement = (await alice.initialize()).body.statement;
  assert.equal((await alice.vote(statement.tid, 0)).status, 200); assert.equal(h.provider.votes, 1);
  const warm = (await alice.next()).body.statement;
  assert.equal((await h.send(h.event(a.fixture, 'revoked', 2))).status, 200);
  assert.ok([401, 403].includes((await alice.vote(warm.tid, 0)).status));
  assert.equal((await h.send(approval)).body.outcome, 'STALE_NO_OP');
  assert.equal((await h.send(h.event(b.fixture, 'revoked', 2))).status, 200);
  assert.equal((await h.service.operator.setRoundOpen(false)).open, false);
  assert.ok([...h.provider.states.values()].every(value => !value.present));
});

test('foreign foundation principal is denied even when injected driver claims success', async t => {
  const foreign = await createSyntheticIdentityHarness(); const result = await foreign.authenticate();
  const h = await setup(t, input => { input.oidcDriver = { mode: 'SYNTHETIC_ONLY',
    begin: async () => ({ ok: true }), complete: async () => result, discard: () => ({ ok: true }),
    isVerifiedPrincipal: () => true }; });
  const origins = await h.start(); const client = createBrowserClient(origins.browser);
  await client.session(); await client.oidcStart();
  assert.equal((await client.oidcCallback('https://participant.example.invalid/oidc/callback')).status, 401);
  assert.equal((await h.service.operator.status()).fixtures, 0);
  assert.equal(h.provider.calls, 0);
});

test('serialized look-alike principal is not in-process identity authority', async t => {
  const h = await setup(t, input => { input.oidcDriver.complete = async () => ({ ok: true,
    principal: Object.freeze({ accountId: 'acct_' + 'a'.repeat(43), emailVerifiedByIssuer: true,
      assurance: 'OIDC_ID_TOKEN_VERIFIED', eligibilityVerified: false, mode: 'SYNTHETIC_ONLY' }) }); });
  const origins = await h.start(); const client = createBrowserClient(origins.browser);
  await client.session(); await client.oidcStart();
  assert.equal((await client.oidcCallback('https://participant.example.invalid/oidc/callback')).status, 401);
  assert.equal(h.provider.calls, 0);
});

test('construction captures driver methods rather than rereading mutable caller methods', async t => {
  const h = await setup(t); let redirected = false;
  h.input.oidcDriver.begin = () => { redirected = true; throw new Error(); };
  const origins = await h.start(); const client = createBrowserClient(origins.browser);
  assert.equal((await h.login(client)).result.status, 200); assert.equal(redirected, false);
});

test('strict service close latches operator admission and never resurrects the instance', async t => {
  const h = await setup(t); const origins = await h.start();
  const close = h.service.close(); assert.equal(close, h.service.close());
  assert.throws(() => h.service.operator.setRoundOpen(false), /not running/u);
  await close; assert.equal(h.service.snapshot().state, 'CLOSED');
  await assert.rejects(h.service.start());
  for (const origin of Object.values(origins)) await assert.rejects(fetch(origin));
  assert.equal(h.provider.calls, 0);
});

test('strict optional registration uses the same identity and returns a pending reference only', async t => {
  const secret = randomBytes(32).toString('base64url');
  const registrationSecret = randomBytes(32).toString('base64url');
  const guest = randomBytes(32).toString('base64url'); const csrf = randomBytes(32).toString('base64url');
  const registrationId = randomUUID(); const actions = []; let fixture;
  const response = (body, cookie) => new Response(JSON.stringify(body), { headers: {
    'Content-Type': 'application/json', 'Cache-Control': 'no-store',
    ...(cookie ? { 'Set-Cookie': 'fncp_wp_identity=' + cookie + '; Path=/; HttpOnly; SameSite=Strict' } : {}) } });
  const h = await setup(t, input => { input.registration = { challengeSecret: secret, registrationSecret,
    async fetch(url, init) {
      const form = init.body ? new URLSearchParams(init.body) : undefined;
      const action = form?.get('action') ?? new URL(url).searchParams.get('action'); actions.push(action);
      assert.ok(url.startsWith('http://127.0.0.1:8103/wp-admin/admin-post.php'));
      if (action === 'fncp_identity_session') return response({ mode: 'SYNTHETIC_ONLY', csrfToken: csrf }, guest);
      assert.equal(init.headers.Cookie, 'fncp_wp_identity=' + guest); assert.equal(form.get('csrfToken'), csrf);
      if (action === 'fncp_identity_challenge') {
        const seconds = Math.floor(Date.now() / 1000);
        return response({ mode: 'SYNTHETIC_ONLY', challenge: signEnvelope({ schemaVersion: 1,
          purpose: 'wordpress-registration-challenge', audience: 'fncp-synthetic-bff', challengeId: randomUUID(),
          browserBinding: createHash('sha256').update(guest).digest('hex'), roundId: 'synthetic_round_local',
          issuedAt: seconds, expiresAt: seconds + 120 }, secret, CHALLENGE_DOMAIN) });
      }
      assert.equal(action, 'fncp_identity_register');
      const receipt = JSON.parse(form.get('receipt')); const claims = JSON.parse(Buffer.from(receipt.payload, 'base64url'));
      assert.deepEqual(receipt, signEnvelope(claims, registrationSecret, RECEIPT_DOMAIN));
      fixture = claims.fixture;
      return response({ mode: 'SYNTHETIC_ONLY', registered: true, registrationId, csrfToken: randomBytes(32).toString('base64url') },
        randomBytes(32).toString('base64url'));
    } }; });
  const origins = await h.start(); const client = createBrowserClient(origins.browser);
  assert.equal(actions.length, 0); h.activate(); // Synthetic lease only; the voting round stays closed.
  const login = await h.login(client);
  assert.equal(login.result.status, 200);
  const result = await client.register({ adultSelfAttested: true, eligibilitySelfAttested: true,
    registrationConsent: true, consentVersion: 'synthetic-registration-v1' });
  assert.equal(result.status, 200, 'model stages: ' + actions.join(', ')); assert.equal(result.body.registrationStatus, 'SUBMITTED_NOT_APPROVED');
  assert.equal(result.body.registrationId, registrationId); assert.equal(fixture, login.fixture);
  assert.deepEqual(actions, ['fncp_identity_session', 'fncp_identity_challenge', 'fncp_identity_register']);
  assert.ok(!/receipt|challenge|fixture|accountId|xid|Secret/u.test(JSON.stringify(result.body)));
  assert.equal((await h.service.operator.status()).open, false); assert.equal(h.provider.calls, 0);
});

test('strict registration uncertain transport never triggers an automatic second attempt', async t => {
  let calls = 0;
  const h = await setup(t, input => { input.registration = {
    challengeSecret: randomBytes(32).toString('base64url'), registrationSecret: randomBytes(32).toString('base64url'),
    fetch() { calls++; throw new Error('private sentinel'); } }; });
  const origins = await h.start(); const client = createBrowserClient(origins.browser); await h.login(client);
  const consent = { adultSelfAttested: true, eligibilitySelfAttested: true, registrationConsent: true, consentVersion: 'synthetic-registration-v1' };
  const first = await client.register(consent); assert.equal(first.status, 503);
  assert.ok(!JSON.stringify(first).includes('private sentinel'));
  assert.equal((await client.register(consent)).status, 409); assert.equal(calls, 1); assert.equal(h.provider.calls, 0);
});

test('strict service close before start disposes all constructed resources', async t => {
  const h = await setup(t); await h.service.close();
  assert.equal(h.service.snapshot().state, 'CLOSED');
  await assert.rejects(h.service.start()); assert.equal(h.provider.calls, 0);
});

test('strict service immediate start-close settles both without leaving a listener', async t => {
  const h = await setup(t); const starting = h.service.start();
  const rejected = assert.rejects(starting); const closing = h.service.close();
  await rejected; await closing; assert.equal(h.service.snapshot().state, 'CLOSED');
  assert.equal(h.provider.calls, 0);
});

test('occupied second listener rolls back the already started access service', async t => {
  const occupied = createServer(); await new Promise(resolve => occupied.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => occupied.close(resolve)));
  const port = occupied.address().port;
  const h = await setup(t, input => { input.ports = { access: 0, receiver: port, browser: 0 }; });
  await assert.rejects(h.service.start(), error => !/EADDRINUSE|127\.0\.0\.1/u.test(error.message));
  assert.equal(h.service.snapshot().state, 'FAILED');
  assert.ok(h.service.snapshot().services.every(service => service.state === 'CLOSED'));
  assert.equal(h.provider.calls, 0);
});

const validBoundary = () => ({ mode: STRICT_SERVICE_MODE,
  identity: { isVerifiedPrincipal() { return false; }, participantXid() {}, principalDeadline() {} },
  oidcDriver: { mode: 'SYNTHETIC_ONLY', begin() {}, complete() {}, discard() {} },
  provider: new Provider(), activation: { binding: syntheticBinding(), publicKey: syntheticSigningFixture().publicKey, keyId: 'synthetic_test_key' },
  storage: { access: ':memory:', activation: ':memory:' }, eventSecret: 'e'.repeat(43) });
const badConfigs = [
  ['production mode', value => { value.mode = 'PRODUCTION'; }],
  ['unknown option', value => { value.adminSecret = 'do-not-accept'; }],
  ['missing foundation', value => { delete value.identity; }],
  ['missing activation', value => { delete value.activation; }],
  ['provider wrong round', value => { value.provider.conversationId = '9differentRound'; }],
  ['weak event secret', value => { value.eventSecret = 'short'; }],
  ['shared provider/event secret', value => { value.provider.gatewaySecret = value.eventSecret; }],
  ['relative access path', value => { value.storage.access = 'untrusted.sqlite'; }],
  ['non-SQLite path', value => { value.storage.activation = '/tmp/never-open.txt'; }],
  ['duplicate fixed ports', value => { value.ports = { access: 8220, receiver: 8220, browser: 0 }; }],
  ['out of range port', value => { value.ports = { access: 65536, receiver: 0, browser: 0 }; }],
  ['missing port', value => { value.ports = { access: 0, receiver: 0 }; }],
  ['invalid clock', value => { value.now = () => NaN; }],
  ['private signing key', value => { value.activation.publicKey = syntheticSigningFixture().privateKey; }],
  ['incomplete registration', value => { value.registration = {}; }],
  ['shared registration secret', value => { value.registration = { challengeSecret: value.eventSecret, registrationSecret: 'f'.repeat(43), fetch() {} }; }],
  ['noncanonical mode', value => { value.oidcDriver.mode = 'PRODUCTION'; }],
];
for (const [name, edit] of badConfigs) test('strict configuration rejects ' + name, async () => {
  const input = validBoundary(); edit(input);
  await assert.rejects(createStrictLocalService(input), error => /KEEP_CLOSED/u.test(error.message) && !/never-open|do-not-accept/u.test(error.message));
});
test('strict configuration rejects getter-bearing input without executing it', async () => {
  const input = validBoundary(); let called = 0;
  Object.defineProperty(input, 'now', { get() { called++; return Date.now; } });
  await assert.rejects(createStrictLocalService(input)); assert.equal(called, 0);
});

test('strict operator wrapper preserves the exact private arity contract', async t => {
  const h = await setup(t); await h.start();
  await assert.rejects(h.service.operator.status({}), { status: 400 });
  await assert.rejects(h.service.operator.setRoundOpen(false, {}), { status: 400 });
  await assert.rejects(h.service.operator.issueInvitation('synthetic_i' + 'a'.repeat(39), {}), { status: 400 });
  assert.equal(h.provider.calls, 0);
});

test('provider conversation drift before dispatch denies without a provider operation', async t => {
  const h = await setup(t); const origins = await h.start(); h.activate(); await h.service.operator.setRoundOpen(true);
  const client = createBrowserClient(origins.browser); const identity = await h.login(client);
  h.provider.conversationId = '9differentRound';
  const result = await h.send(h.event(identity.fixture, 'approved', 1));
  assert.equal(result.status, 503); assert.equal(h.provider.calls, 0);
  await assert.rejects(h.service.operator.issueInvitation(identity.fixture), { status: 403 });
  h.provider.conversationId = '9syntheticRoundTest';
  assert.equal((await h.service.operator.status()).open, false);
  await assert.rejects(h.service.operator.setRoundOpen(true), { status: 403 });
  assert.equal(h.provider.calls, 0);
});

test('provider drift during an operation withholds success without retry or false rollback', async t => {
  let actualCalls = 0;
  const h = await setup(t, input => {
    const original = input.provider.allowlist.bind(input.provider);
    input.provider.allowlist = async (...args) => {
      actualCalls++; const result = await original(...args);
      input.provider.conversationId = '9differentRound'; return result;
    };
  });
  const origins = await h.start(); h.activate(); await h.service.operator.setRoundOpen(true);
  const client = createBrowserClient(origins.browser); const identity = await h.login(client);
  const result = await h.send(h.event(identity.fixture, 'approved', 1));
  assert.equal(result.status, 503); assert.match(result.body.error, /outcome unconfirmed/u);
  assert.equal(actualCalls, 1); assert.equal(h.provider.calls, 1);
  assert.ok([...h.provider.states.values()].some(row => row.present)); // A side effect is not silently rolled back.
  assert.ok([401, 403].includes((await client.initialize()).status));
});
test('service source contains no runtime test factory signer or automatic invitation delivery', () => {
  const source = readFileSync(new URL('./service.mjs', import.meta.url), 'utf8');
  const imports = source.split('\n').filter(line => line.startsWith('import'));
  assert.ok(!imports.some(line => /synthetic-harness|synthetic-fixtures|proof-harness|integration-client|synthetic-browser-driver/u.test(line)));
  assert.ok(!/console\.|process\.env|writeFile|readFile|injectTestResponse|signClaims/u.test(source));
});

test('provider drift still latches when the operation itself rejects', async t => {
  let calls = 0;
  const h = await setup(t, input => { input.provider.allowlist = async () => {
    calls++; input.provider.conversationId = '9differentRound'; throw new Error('private provider failure');
  }; });
  const origins = await h.start(); h.activate(); await h.service.operator.setRoundOpen(true);
  const identity = await h.login(createBrowserClient(origins.browser));
  const result = await h.send(h.event(identity.fixture, 'approved', 1));
  assert.equal(result.status, 503); assert.equal(calls, 1);
  assert.ok(!JSON.stringify(result).includes('private provider failure'));
  h.provider.conversationId = '9syntheticRoundTest';
  assert.equal((await h.service.operator.status()).open, false);
  await assert.rejects(h.service.operator.setRoundOpen(true), { status: 403 });
});

test('unreadable provider metadata fails closed without invoking the operation', async t => {
  const h = await setup(t); const origins = await h.start(); h.activate(); await h.service.operator.setRoundOpen(true);
  const identity = await h.login(createBrowserClient(origins.browser));
  Object.defineProperty(h.provider, 'conversationId', { configurable: true, get() { throw new Error('private getter'); } });
  const result = await h.send(h.event(identity.fixture, 'approved', 1));
  assert.equal(result.status, 503); assert.equal(h.provider.calls, 0);
  Object.defineProperty(h.provider, 'conversationId', { configurable: true, value: '9syntheticRoundTest' });
  assert.equal((await h.service.operator.status()).open, false);
  await assert.rejects(h.service.operator.setRoundOpen(true), { status: 403 });
});

function validHttpsBoundary() {
  const input = validBoundary();
  input.ports = { access: 0, receiver: 0, browser: 24443 };
  input.httpsRedirect = { mode: 'SYNTHETIC_HTTPS_REDIRECT', origin: 'https://browser.example.invalid:24443',
    key: Buffer.from('test-only-not-parsed-at-configuration-boundary'), cert: Buffer.from('test-only-not-parsed-at-configuration-boundary') };
  input.oidcDriver = { mode: 'SYNTHETIC_ONLY', transport: 'HTTPS_REDIRECT_LAB',
    authorizationEndpoint: 'https://identity.example.invalid:24444/authorize',
    callbackUri: input.httpsRedirect.origin + '/oidc/callback', begin() {}, complete() {}, discard() {} };
  return input;
}

const badHttpsConfigs = [
  ['wrong mode', input => { input.httpsRedirect.mode = 'PRODUCTION'; }],
  ['unknown TLS field', input => { input.httpsRedirect.rejectUnauthorized = false; }],
  ['HTTP origin', input => { input.httpsRedirect.origin = 'http://127.0.0.1:24443'; }],
  ['wrong host', input => { input.httpsRedirect.origin = 'https://participant.example.invalid:24443'; }],
  ['implicit port', input => { input.httpsRedirect.origin = 'https://browser.example.invalid'; }],
  ['default port', input => { input.ports.browser = 443; input.httpsRedirect.origin = 'https://browser.example.invalid:443'; }],
  ['zero port', input => { input.ports.browser = 0; }],
  ['port mismatch', input => { input.ports.browser = 24445; }],
  ['trailing slash', input => { input.httpsRedirect.origin += '/'; }],
  ['query', input => { input.httpsRedirect.origin += '?PRIVATE'; }],
  ['fragment', input => { input.httpsRedirect.origin += '#PRIVATE'; }],
  ['userinfo', input => { input.httpsRedirect.origin = 'https://PRIVATE@browser.example.invalid:24443'; }],
  ['string key', input => { input.httpsRedirect.key = 'PRIVATE KEY'; }],
  ['string certificate', input => { input.httpsRedirect.cert = 'PRIVATE CERT'; }],
  ['empty key', input => { input.httpsRedirect.key = Buffer.alloc(0); }],
  ['oversized key', input => { input.httpsRedirect.key = Buffer.alloc(65537); }],
  ['empty certificate', input => { input.httpsRedirect.cert = Buffer.alloc(0); }],
  ['oversized certificate', input => { input.httpsRedirect.cert = Buffer.alloc(65537); }],
  ['legacy transport', input => { delete input.oidcDriver.transport; }],
  ['wrong transport', input => { input.oidcDriver.transport = 'REMOTE'; }],
  ['callback mismatch', input => { input.oidcDriver.callbackUri = 'https://browser.example.invalid:24443/other'; }],
  ['HTTP authorization', input => { input.oidcDriver.authorizationEndpoint = 'http://identity.example.invalid/authorize'; }],
  ['real authorization hostname', input => { input.oidcDriver.authorizationEndpoint = 'https://identity.example.org/authorize'; }],
  ['bare invalid authorization hostname', input => { input.oidcDriver.authorizationEndpoint = 'https://.invalid/authorize'; }],
  ['same browser authorization hostname', input => { input.oidcDriver.authorizationEndpoint = input.httpsRedirect.origin + '/authorize'; }],
  ['authorization query', input => { input.oidcDriver.authorizationEndpoint += '?PRIVATE'; }],
  ['empty authorization query', input => { input.oidcDriver.authorizationEndpoint += '?'; }],
  ['authorization fragment', input => { input.oidcDriver.authorizationEndpoint += '#PRIVATE'; }],
  ['empty authorization fragment', input => { input.oidcDriver.authorizationEndpoint += '#'; }],
  ['authorization userinfo', input => { input.oidcDriver.authorizationEndpoint = 'https://PRIVATE@identity.example.invalid:24444/authorize'; }],
  ['noncanonical authorization', input => { input.oidcDriver.authorizationEndpoint = 'https://IDENTITY.example.invalid:24444/authorize'; }],
  ['unbounded authorization', input => { input.oidcDriver.authorizationEndpoint = 'https://identity.example.invalid/' + 'a'.repeat(2048); }],
  ['unknown driver capability', input => { input.oidcDriver.extraCapability = () => {}; }],
  ['redirect driver without TLS', input => { delete input.httpsRedirect; }],
];
for (const [name, edit] of badHttpsConfigs) test('strict HTTPS configuration rejects ' + name + ' before construction', async () => {
  const input = validHttpsBoundary(); edit(input);
  await assert.rejects(createStrictLocalService(input), error =>
    error.message === 'Strict local service configuration rejected; KEEP_CLOSED.');
  assert.equal(input.provider.calls, 0);
});

for (const target of ['origin', 'key', 'cert', 'transport', 'authorizationEndpoint', 'callbackUri', 'begin', 'complete', 'discard']) {
  test('strict HTTPS configuration rejects ' + target + ' accessor without invocation', async () => {
    const input = validHttpsBoundary(); let called = 0;
    const object = ['origin', 'key', 'cert'].includes(target) ? input.httpsRedirect : input.oidcDriver;
    Object.defineProperty(object, target, { enumerable: true, configurable: true, get() { called++; throw new Error('PRIVATE'); } });
    await assert.rejects(createStrictLocalService(input), error =>
      error.message === 'Strict local service configuration rejected; KEEP_CLOSED.');
    assert.equal(called, 0); assert.equal(input.provider.calls, 0);
  });
}

test('legacy driver method accessor is refused without invocation', async () => {
  const input = validBoundary(); let called = 0;
  Object.defineProperty(input.oidcDriver, 'begin', { get() { called++; throw new Error('PRIVATE'); } });
  await assert.rejects(createStrictLocalService(input)); assert.equal(called, 0);
});

test('legacy driver transport accessor cannot silently select HTTP', async () => {
  const input = validBoundary(); let called = 0;
  Object.defineProperty(input.oidcDriver, 'transport', { get() { called++; throw new Error('PRIVATE'); } });
  await assert.rejects(createStrictLocalService(input)); assert.equal(called, 0);
});

test('strict service explicitly composes HTTPS BFF and captures TLS bytes and pure driver metadata', async t => {
  const lab = await createRedirectTlsLab(); t.after(() => lab.close());
  const input = validBoundary();
  const actualDriver = createHttpsRedirectDriver({ mode: 'SYNTHETIC_ONLY', identity: lab.identity,
    authorizationEndpoint: lab.authorizationEndpoint, callbackUri: lab.callbackUri });
  let beginCalls = 0;
  input.identity = lab.identity;
  input.oidcDriver = { ...actualDriver, begin(value) { beginCalls++; return actualDriver.begin(value); } };
  input.ports = { access: 0, receiver: 0, browser: lab.browserPort };
  input.httpsRedirect = { ...lab.browserTls, key: Buffer.from(lab.browserTls.key), cert: Buffer.from(lab.browserTls.cert) };
  const service = await createStrictLocalService(input); t.after(() => service.close());
  assert.equal(service.snapshot().state, 'CREATED');
  input.httpsRedirect.key.fill(0); input.httpsRedirect.cert.fill(0);
  input.httpsRedirect.origin = 'https://PRIVATE.example.invalid:24443';
  input.oidcDriver.authorizationEndpoint = 'https://PRIVATE.example.invalid/authorize';
  input.oidcDriver.callbackUri = 'https://PRIVATE.example.invalid/callback';
  input.oidcDriver.transport = 'REMOTE';
  input.oidcDriver.begin = () => { throw new Error('PRIVATE changed driver'); };
  const { origins } = await service.start();
  assert.equal(origins.browser, lab.browserTls.origin);
  assert.ok(origins.access.startsWith('http://127.0.0.1:'));
  assert.ok(origins.receiver.startsWith('http://127.0.0.1:'));
  const headers = { 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty' };
  const initial = await lab.request(origins.browser + '/api/session', { headers });
  assert.equal(initial.status, 200);
  const cookies = initial.headers['set-cookie']; assert.ok(Array.isArray(cookies));
  assert.ok(cookies.every(value => /; Secure/u.test(value)));
  assert.ok(cookies.some(value => /; SameSite=Strict/u.test(value)));
  const started = await lab.request(origins.browser + '/api/oidc/start', { method: 'POST',
    headers: { ...headers, Origin: origins.browser, Cookie: cookies.map(value => value.split(';', 1)[0]).join('; '),
      'Content-Type': 'application/json', 'X-CSRF-Token': JSON.parse(initial.body).csrf }, body: '{}' });
  assert.equal(started.status, 200);
  const authorization = new URL(JSON.parse(started.body).authorizationUrl);
  assert.equal(authorization.origin + authorization.pathname, lab.authorizationEndpoint);
  assert.equal(authorization.searchParams.get('redirect_uri'), lab.callbackUri);
  assert.equal(beginCalls, 1); assert.equal(input.provider.calls, 0);
  assert.equal((await service.operator.status()).open, false);
  assert.ok(!/example\.invalid|PRIVATE|127\.0\.0\.1|CERTIFICATE/u.test(JSON.stringify(service.snapshot())));
  assert.ok(lab.summary().tlsAuthorized >= 2); assert.equal(lab.summary().globalTrustChanged, false);
  await service.close(); assert.equal(service.snapshot().state, 'CLOSED');
  await assert.rejects(lab.request(origins.browser + '/api/session', { headers }));
  await lab.close(); assert.equal(lab.summary().listenersClosed, true);
});
