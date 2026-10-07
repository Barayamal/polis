/** Fresh model-protocol tests only. These do not launch a browser, WordPress or
 * Pol.is. Header/cookie simulation here is not native browser evidence.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer, connect } from 'node:net';
import { channel } from 'node:diagnostics_channel';
import { createRedirectTlsLab } from '../identity-foundation/redirect-tls-lab.mjs';
import { createStrictNativeFixture, createTwoAccountStrictNativeFixture } from './strict-native-fixture.mjs';

const seeds = JSON.parse(readFileSync(new URL('../seed-statements.json', import.meta.url), 'utf8'));
const opaque = () => randomBytes(32).toString('base64url');
const consent = { adultSelfAttested: true, eligibilitySelfAttested: true,
  registrationConsent: true, consentVersion: 'synthetic-registration-v1' };
const apiMetadata = { 'sec-fetch-site': 'same-origin', 'sec-fetch-mode': 'same-origin', 'sec-fetch-dest': 'empty' };
const nav = { 'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document' };
const refused = port => new Promise((resolve, reject) => {
  const socket = connect({ host: '127.0.0.1', port });
  socket.setTimeout(1000);
  socket.once('connect', () => { socket.destroy(); reject(new Error('Fresh owned listener remains open.')); });
  socket.once('timeout', () => { socket.destroy(); reject(new Error('Fresh listener closure unconfirmed.')); });
  socket.once('error', error => { socket.destroy(); error.code === 'ECONNREFUSED' ? resolve() : reject(new Error('Fresh listener closure unconfirmed.')); });
});
async function setup(t, twoAccounts = false) {
  const lab = twoAccounts
    ? await (await import('../identity-foundation/redirect-tls-lab.mjs')).createTwoAccountDocumentRedirectTlsLab()
    : await createRedirectTlsLab();
  let fixture;
  t.after(async () => { try { await fixture?.close(); } finally { await lab.close(); } });
  fixture = await (twoAccounts ? createTwoAccountStrictNativeFixture : createStrictNativeFixture)({ lab, seeds });
  return { lab, fixture, ...createClient(lab) };
}
function createClient(lab) {
  const cookies = new Map(); let csrf;
  const remember = response => {
    for (const line of response.headers['set-cookie'] ?? []) {
      const [pair, ...attrs] = line.split(';').map(value => value.trim()); const i = pair.indexOf('=');
      const name = pair.slice(0, i); const value = pair.slice(i + 1);
      if (attrs.includes('Max-Age=0')) cookies.delete(name); else cookies.set(name, { value, attrs });
    }
    return response;
  };
  const cookie = cross => [...cookies].filter(([, item]) => !cross || item.attrs.includes('SameSite=Lax'))
    .map(([name, item]) => `${name}=${item.value}`).join('; ');
  const api = async (path, body) => {
    const response = remember(await lab.request(lab.browserTls.origin + path, {
      method: body === undefined ? 'GET' : 'POST',
      headers: { ...apiMetadata, cookie: cookie(false), ...(body === undefined ? {} : {
        origin: lab.browserTls.origin, 'content-type': 'application/json', 'x-csrf-token': csrf }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    }));
    const data = JSON.parse(response.body); if (data.csrf) csrf = data.csrf;
    return { status: response.status, data };
  };
  const login = async () => {
    await api('/api/session'); const started = await api('/api/oidc/start', {});
    assert.equal(started.status, 200);
    const authorize = await lab.request(started.data.authorizationUrl, { headers: nav });
    let callbackUri;
    if (authorize.status === 200) {
      assert.match(authorize.body, /<title>Invented sign-in/u);
      callbackUri = /<a id="continue-invented" href="([^"]+)">/u.exec(authorize.body)?.[1]?.replaceAll('&amp;', '&');
      assert.equal(typeof callbackUri, 'string');
    } else { assert.equal(authorize.status, 303); callbackUri = authorize.headers.location; }
    const callback = remember(await lab.request(callbackUri, { headers: { ...nav, cookie: cookie(true) } }));
    assert.equal(callback.status, 303); assert.equal(callback.headers.location, '/');
    const session = await api('/api/session'); assert.equal(session.data.phase, 'authenticated');
    return session;
  };
  return { api, login };
}

test('strict native fixture refuses extra capabilities and seed accessors before reading them', async () => {
  let reads = 0;
  const options = { lab: {}, seeds };
  Object.defineProperty(options, 'path', { get() { reads++; throw new Error('PRIVATE'); }, enumerable: true });
  await assert.rejects(createStrictNativeFixture(options), /KEEP_CLOSED/u);
  const altered = [...seeds]; Object.defineProperty(altered, '0', { get() { reads++; return seeds[0]; } });
  await assert.rejects(createStrictNativeFixture({ lab: {}, seeds: altered }), /KEEP_CLOSED/u);
  await assert.rejects(createStrictNativeFixture({ lab: {}, seeds: [...seeds].reverse() }), /KEEP_CLOSED/u);
  await assert.rejects(createStrictNativeFixture({ lab: {}, seeds: seeds.slice(1) }), /KEEP_CLOSED/u);
  assert.equal(reads, 0);
});

test('strict native fixture rejects a changed lab origin and closed lab without starting service', async t => {
  const lab = await createRedirectTlsLab(); t.after(() => lab.close());
  await assert.rejects(createStrictNativeFixture({ lab: Object.freeze({ ...lab,
    authorizationEndpoint: 'https://outside.invalid:24443/authorize' }), seeds }), /KEEP_CLOSED/u);
  await assert.rejects(createStrictNativeFixture({ lab: Object.freeze({ ...lab,
    callbackUri: lab.callbackUri + '?external=yes' }), seeds }), /KEEP_CLOSED/u);
  await lab.close();
  await assert.rejects(createStrictNativeFixture({ lab, seeds }), /KEEP_CLOSED/u);
});

test('strict native fixture constructs closed, exposes no operator capability and closes idempotently', async t => {
  const h = await setup(t);
  assert.equal(h.fixture.snapshot().state, 'CREATED'); assert.equal(h.fixture.counts().providerCalls, 0);
  for (const name of ['operator', 'provider', 'lab', 'privateKey', 'fixture', 'eventSecret', 'sendEvent', 'request', 'inject']) assert.equal(h.fixture[name], undefined);
  const a = h.fixture.close(); const b = h.fixture.close(); assert.equal(a, b); await a;
  assert.equal(h.fixture.snapshot().state, 'CLOSED');
  await assert.rejects(h.fixture.start(), /KEEP_CLOSED/u);
  await assert.rejects(h.fixture.approve(), /KEEP_CLOSED/u);
  await assert.rejects(h.fixture.openAndIssue(), /KEEP_CLOSED/u);
});

test('strict signed registration approval invitation and warm vote revocation traverse actual access service', async t => {
  const h = await setup(t); const origins = await h.fixture.start();
  assert.equal(origins.browser, h.lab.browserTls.origin);
  await assert.rejects(h.fixture.start(), /KEEP_CLOSED/u);
  await assert.rejects(h.fixture.openAndIssue(), /KEEP_CLOSED/u);
  assert.equal((await h.api('/api/next-comment')).status, 401);
  await h.login(); assert.equal(h.fixture.counts().authentications, 1);
  assert.equal(h.fixture.counts().approvedAccounts, 0);
  assert.equal((await h.api('/api/registration', { ...consent, eligibilitySelfAttested: false })).status, 400);
  assert.equal(h.fixture.counts().registrations, 0);
  const registration = await h.api('/api/registration', consent);
  assert.equal(registration.status, 200); assert.equal(registration.data.registrationStatus, 'SUBMITTED_NOT_APPROVED');
  assert.equal(h.fixture.counts().registrations, 1); assert.equal(h.fixture.counts().providerCalls, 0);
  assert.equal((await h.api('/api/registration', consent)).status, 409);
  await h.fixture.approve();
  assert.equal(h.fixture.counts().approvedAccounts, 1); assert.equal(h.fixture.counts().activeAllowlistEntries, 1);
  assert.equal(h.fixture.counts().providerCalls, 2); assert.equal(h.fixture.counts().participationCalls, 0);
  assert.equal((await h.api('/api/redeem', { invitationToken: opaque() })).status, 403);
  assert.equal((await h.api('/api/next-comment')).status, 403);
  await assert.rejects(h.fixture.approve(), /KEEP_CLOSED/u);
  const invite = await h.fixture.openAndIssue();
  assert.equal(invite.delivery, 'LOCAL_RESPONSE_ONLY_NO_EMAIL_OR_MESSAGE');
  assert.equal((await h.api('/api/redeem', { invitationToken: opaque() })).status, 403);
  assert.equal((await h.api('/api/redeem', { invitationToken: invite.invitationToken })).status, 200);
  assert.equal((await h.api('/api/redeem', { invitationToken: invite.invitationToken })).status, 403);
  const initialized = await h.api('/api/participation-init'); assert.equal(initialized.data.statement.tid, 0);
  const vote = await h.api('/api/votes', { tid: 0, vote: -1 }); assert.equal(vote.status, 200);
  assert.equal(vote.data.statement.tid, 1); assert.equal(h.fixture.counts().votes, 1);
  const before = h.fixture.counts(); const accessPort = Number(new URL(origins.access).port);
  let accessVoteRequests = 0; const requests = channel('http.server.request.start');
  const observe = ({ request }) => { if (request.socket.localPort === accessPort && request.method === 'POST' && request.url === '/polis/votes') accessVoteRequests++; };
  requests.subscribe(observe); t.after(() => requests.unsubscribe(observe));
  await h.fixture.revoke();
  assert.equal(h.fixture.counts().activeAllowlistEntries, 0); assert.equal(h.fixture.counts().approvedAccounts, 0);
  const rejected = await h.api('/api/votes', { tid: 1, vote: 1 });
  assert.ok([401, 403].includes(rejected.status)); assert.equal(accessVoteRequests, 1);
  assert.equal(h.fixture.counts().votes, before.votes);
  assert.equal(h.fixture.counts().participationCalls, before.participationCalls);
  assert.equal(h.fixture.counts().participationAfterRevocation, 0);
  assert.equal((await h.api('/api/session')).data.phase, 'visitor');
  await assert.rejects(h.fixture.openAndIssue(), /KEEP_CLOSED/u);
  const projection = JSON.stringify(h.fixture.evidence());
  for (const value of [invite.invitationToken, h.lab.browserTls.origin, origins.receiver, 'synthetic_i', 'fncp_', 'payload', 'signature'])
    assert.equal(projection.includes(value), false);
  assert.equal(Object.isFrozen(h.fixture.evidence().checks), true); assert.equal(Object.isFrozen(h.fixture.counts()), true);
  const names = new Set(h.fixture.evidence().checks.map(check => check.name));
  for (const name of ['opening without signed activation is denied',
    'signed approval alone cannot issue an invitation while the round is closed',
    'signed revocation removes the provider allowlist with verified readback',
    'original old approval is a stale no-op after terminal revocation']) assert.equal(names.has(name), true, name);
  await h.fixture.close(); assert.equal(h.fixture.snapshot().state, 'CLOSED');
  await Promise.all(Object.values(origins).map(origin => refused(Number(new URL(origin).port))));
});

test('strict native provider validates fixed statement sequence and preserves exact fifteen-vote aggregates', async t => {
  const h = await setup(t); await h.fixture.start(); await h.login();
  await h.api('/api/registration', consent); await h.fixture.approve();
  const invitation = await h.fixture.openAndIssue(); await h.api('/api/redeem', { invitationToken: invitation.invitationToken });
  await h.api('/api/participation-init'); const before = h.fixture.counts().participationCalls;
  assert.equal((await h.api('/api/votes', { tid: 1, vote: -1 })).status, 400);
  assert.equal((await h.api('/api/votes', { tid: 0, vote: 2 })).status, 400);
  assert.equal(h.fixture.counts().participationCalls, before);
  for (let tid = 0; tid < 15; tid++) {
    const result = await h.api('/api/votes', { tid, vote: [-1, 1, 0][tid % 3] });
    assert.equal(result.status, 200); assert.equal(result.data.saved, true);
    assert.equal(result.data.statement?.text ?? null, tid === 14 ? null : seeds[tid + 1]);
  }
  const counts = h.fixture.counts();
  assert.equal(counts.votes, 15); assert.equal(counts.agree, 5); assert.equal(counts.disagree, 5); assert.equal(counts.pass, 5);
  assert.equal(counts.participationCalls, 16); assert.equal(counts.providerCalls, 18);
  assert.equal((await h.api('/api/votes', { tid: 14, vote: 0 })).status, 400);
  assert.equal(h.fixture.counts().providerCalls, counts.providerCalls);
  await h.fixture.revoke(); assert.equal(h.fixture.counts().activeAllowlistEntries, 0);
});

test('occupied strict browser port rolls back both earlier service listeners without provider work', async t => {
  const h = await setup(t); const occupied = createServer();
  await new Promise((resolve, reject) => { occupied.once('error', reject); occupied.listen(h.lab.browserPort, '127.0.0.1', resolve); });
  t.after(() => new Promise(resolve => occupied.close(resolve)));
  await assert.rejects(h.fixture.start(), /KEEP_CLOSED/u);
  assert.equal(h.fixture.snapshot().state, 'FAILED');
  assert.equal(h.fixture.snapshot().services.every(service => service.state === 'CLOSED'), true);
  assert.equal(h.fixture.counts().providerCalls, 0);
});

test('two-account fixture refuses caller-selected capacity and requires the fixed two-account lab', async t => {
  const lab = await createRedirectTlsLab(); t.after(() => lab.close());
  await assert.rejects(createTwoAccountStrictNativeFixture({ lab, seeds }), /KEEP_CLOSED/u);
  await assert.rejects(createTwoAccountStrictNativeFixture({ lab, seeds, accountCount: 2 }), /KEEP_CLOSED/u);
  await assert.rejects(createTwoAccountStrictNativeFixture({ lab, seeds, accountId: 'invented' }), /KEEP_CLOSED/u);
  let reads = 0; const changed = [...seeds];
  Object.defineProperty(changed, '0', { get() { reads++; return seeds[0]; } });
  await assert.rejects(createTwoAccountStrictNativeFixture({ lab, seeds: changed }), /KEEP_CLOSED/u);
  assert.equal(reads, 0);
});

test('two-account fixture waits for two distinct seamless registrations and exposes no account capability', async t => {
  const h = await setup(t, true);
  await assert.rejects(createStrictNativeFixture({ lab: h.lab, seeds }), /KEEP_CLOSED/u);
  await h.fixture.start();
  for (const name of ['operator', 'provider', 'fixture', 'fixtures', 'accounts', 'principal', 'signer', 'selectAccount', 'request', 'inject'])
    assert.equal(h.fixture[name], undefined);
  await assert.rejects(h.fixture.approve(), /KEEP_CLOSED/u);
  await h.login(); await h.api('/api/registration', consent);
  assert.equal(h.fixture.counts().distinctVerifiedAccounts, 1);
  assert.equal(h.fixture.counts().registrations, 1);
  await assert.rejects(h.fixture.approve(), /KEEP_CLOSED/u);
  await assert.rejects(h.fixture.openAndIssue(), /KEEP_CLOSED/u);
  assert.equal(h.fixture.counts().providerCalls, 0);
  const other = createClient(h.lab); await other.login(); await other.api('/api/registration', consent);
  assert.equal(h.fixture.counts().distinctVerifiedAccounts, 2);
  assert.equal(h.fixture.counts().registrations, 2);
  assert.equal(h.fixture.counts().approvedAccounts, 0);
  await h.fixture.approve();
  assert.equal(h.fixture.counts().approvedAccounts, 2);
  assert.equal(h.fixture.counts().activeAllowlistEntries, 2);
  assert.equal(h.fixture.counts().providerCalls, 4);
  assert.equal(h.fixture.counts().providerParticipationCalls, 0);
  await h.fixture.revoke();
  assert.equal(h.fixture.counts().approvedAccounts, 0);
  assert.equal(h.fixture.counts().activeAllowlistEntries, 0);
});

test('two-account cross-redemption cannot burn either bound token and both warm votes reach revoked access', async t => {
  const h = await setup(t, true); const origins = await h.fixture.start();
  const clients = [h, createClient(h.lab)];
  for (const client of clients) {
    await client.login();
    const registration = await client.api('/api/registration', consent);
    assert.equal(registration.status, 200);
    assert.equal(registration.data.registrationStatus, 'SUBMITTED_NOT_APPROVED');
  }
  await h.fixture.approve(); const issued = await h.fixture.openAndIssue();
  assert.equal(Object.isFrozen(issued), true); assert.equal(Object.isFrozen(issued.invitations), true);
  assert.equal(issued.invitations.length, 2);
  assert.notEqual(issued.invitations[0].invitationToken, issued.invitations[1].invitationToken);
  for (const invitation of issued.invitations) assert.equal(invitation.delivery, 'LOCAL_RESPONSE_ONLY_NO_EMAIL_OR_MESSAGE');
  const accessPort = Number(new URL(origins.access).port);
  let redeemRequests = 0; let voteRequests = 0; const requests = channel('http.server.request.start');
  const observe = ({ request }) => {
    if (request.socket.localPort !== accessPort || request.method !== 'POST') return;
    if (request.url === '/invitations/redeem') redeemRequests++;
    if (request.url === '/polis/votes') voteRequests++;
  };
  requests.subscribe(observe); t.after(() => requests.unsubscribe(observe));
  const before = h.fixture.counts();
  for (const [index, client] of clients.entries()) {
    const denied = await client.api('/api/redeem', { invitationToken: issued.invitations[1 - index].invitationToken });
    assert.equal(denied.status, 403);
  }
  assert.equal(redeemRequests, 2); assert.equal(h.fixture.counts().providerCalls, before.providerCalls);
  for (const [index, client] of clients.entries()) {
    const accepted = await client.api('/api/redeem', { invitationToken: issued.invitations[index].invitationToken });
    assert.equal(accepted.status, 200);
    const initialized = await client.api('/api/participation-init'); assert.equal(initialized.data.statement.tid, 0);
    const firstVote = await client.api('/api/votes', { tid: 0, vote: index === 0 ? -1 : 1 });
    assert.equal(firstVote.status, 200); assert.equal(firstVote.data.statement.tid, 1);
  }
  assert.equal(redeemRequests, 4); assert.equal(voteRequests, 2);
  assert.equal(h.fixture.counts().votes, 2); assert.equal(h.fixture.counts().agree, 1); assert.equal(h.fixture.counts().disagree, 1);
  await h.fixture.revoke(); const revoked = h.fixture.counts();
  assert.equal(revoked.approvedAccounts, 0); assert.equal(revoked.activeAllowlistEntries, 0);
  for (const client of clients) {
    const denied = await client.api('/api/votes', { tid: 1, vote: 0 });
    assert.ok([401, 403].includes(denied.status));
    assert.equal((await client.api('/api/session')).data.phase, 'visitor');
  }
  assert.equal(voteRequests, 4); assert.equal(h.fixture.counts().providerCalls, revoked.providerCalls);
  assert.equal(h.fixture.counts().participationAfterRevocation, 0); assert.equal(h.fixture.counts().votes, 2);
  assert.equal(h.fixture.evidence().fixedInventedAccountCount, 2);
  const projection = JSON.stringify(h.fixture.evidence());
  for (const secret of [...issued.invitations.map(value => value.invitationToken), h.lab.browserTls.origin, origins.receiver,
    'synthetic_i', 'fncp_', 'payload', 'signature']) assert.equal(projection.includes(secret), false);
  await h.fixture.close(); assert.equal(h.fixture.snapshot().state, 'CLOSED');
  await Promise.all(Object.values(origins).map(origin => refused(Number(new URL(origin).port))));
});
