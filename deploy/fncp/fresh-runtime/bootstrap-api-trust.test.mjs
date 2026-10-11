import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey } from 'node:crypto';
import { mkdtemp, readFile, rm, mkdir, writeFile, symlink } from 'node:fs/promises';
import { request } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createBootstrapIssuer, claimBootstrapIssuerPublicJwks, claimBootstrapIssuerApiTrust,
  claimBootstrapIssuerForTransport } from './bootstrap-issuer.mjs';
import { createBootstrapJwksService } from './bootstrap-jwks-service.mjs';
import { createBootstrapApiTrust, claimBootstrapApiTrust } from './bootstrap-api-trust.mjs';

const ERROR = 'Fresh bootstrap API trust rejected; private details withheld.';
const ISSUER_ERROR = 'Local synthetic bootstrap issuer rejected; private details withheld.';
const SEED_SHA = 'b8c49ddaab72740df997b4975e84b0a51501fa97e1c622420826f4840bc6e06b';
const sha = value => createHash('sha256').update(value).digest('hex');
const denied = work => assert.rejects(work, error => error.message === ERROR && error.cause === undefined);
const refused = work => assert.throws(work, error => error.message === ERROR && error.cause === undefined);
const issuerDenied = work => assert.rejects(work, error => error.message === ISSUER_ERROR && error.cause === undefined);
async function issuerFixture(t) {
  const issuer = await createBootstrapIssuer(); t.after(() => issuer.close()); return issuer;
}
async function fixture(t) {
  const issuer = await issuerFixture(t); const capability = await createBootstrapApiTrust({ issuer });
  return { issuer, capability };
}
// Every fixture copy below is NEW task-owned source and synthetic seed bytes.
// The real issuer module remains shared by absolute import, so its WeakMap
// origin check is not replaced or mocked. No retained path is read or changed.
async function sourceFixture(t, mode) {
  const directory = await mkdtemp(join(tmpdir(), 'fncp-api-trust-source-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await mkdir(join(directory, 'fresh-runtime'));
  const source = (await readFile(new URL('./bootstrap-api-trust.mjs', import.meta.url), 'utf8'))
    .replace("from './bootstrap-issuer.mjs'", `from ${JSON.stringify(new URL('./bootstrap-issuer.mjs', import.meta.url).href)}`);
  await writeFile(join(directory, 'fresh-runtime/bootstrap-api-trust.mjs'), source, { mode: 0o600, flag: 'wx' });
  const good = await readFile(new URL('../seed-statements.json', import.meta.url));
  const seedPath = join(directory, 'seed-statements.json');
  if (mode === 'directory') await mkdir(seedPath);
  else if (mode === 'symlink') {
    await writeFile(join(directory, 'fresh-pinned-source.json'), good, { mode: 0o600, flag: 'wx' });
    await symlink(join(directory, 'fresh-pinned-source.json'), seedPath);
  } else if (mode !== 'missing') {
    const bytes = mode === 'changed' ? Buffer.concat([good, Buffer.from(' ')]) :
      mode === 'oversize' ? Buffer.alloc(16385, 32) : good;
    await writeFile(seedPath, bytes, { mode: 0o600, flag: 'wx' });
  }
  return { module: await import(pathToFileURL(join(directory, 'fresh-runtime/bootstrap-api-trust.mjs')).href),
    seedPath, good };
}
async function directPublicFetch(config) {
  await new Promise((resolve, reject) => {
    const url = new URL(config.issuer);
    const req = request({ hostname: '127.0.0.1', port: Number(url.port), method: 'GET', path: '/.well-known/jwks.json',
      ca: config.certificatePem, rejectUnauthorized: true, agent: false,
      headers: { host: url.host, connection: 'close' } }, res => {
      res.resume(); res.once('end', () => res.statusCode === 200 ? resolve() : reject(new Error('Synthetic public budget setup failed.')));
      res.once('error', reject);
    });
    req.setTimeout(1000, () => req.destroy(new Error('Synthetic public setup timed out.')));
    req.once('error', reject); req.end();
  });
}

test('factory refuses input expansion, getters and proxies before claiming issuer authority', async t => {
  const issuer = await issuerFixture(t); let reads = 0;
  const getter = { get issuer() { reads++; throw new Error('private sentinel'); } };
  const proxy = new Proxy({ issuer }, { get() { reads++; throw new Error('private sentinel'); }, ownKeys() { reads++; throw new Error('private sentinel'); } });
  const revoked = Proxy.revocable({ issuer }, {}); revoked.revoke();
  for (const options of [undefined, null, {}, [], getter, proxy, revoked.proxy, Object.assign(Object.create(null), { issuer }),
    { issuer, key: {} }, { issuer, url: 'https://external.invalid' }, { issuer, seedPath: '/retained/not-accessed' },
    { issuer, clock: Date.now }, { issuer, [Symbol('hidden')]: true }]) await denied(createBootstrapApiTrust(options));
  await denied(createBootstrapApiTrust({ issuer }, undefined));
  assert.equal(reads, 0); assert.equal(issuer.summary().clientFetches, 0); assert.equal(issuer.summary().tokensIssued, 0);
});
test('only original issuer branding is accepted, not copied capabilities or caller implementations', async t => {
  const issuer = await issuerFixture(t); let reads = 0;
  for (const value of [null, {}, { ...issuer }, new Proxy(issuer, { get() { reads++; } }),
    { get fetchJwks() { reads++; throw new Error('private'); }, configuration() { reads++; } }]) {
    await denied(createBootstrapApiTrust({ issuer: value }));
    await issuerDenied(claimBootstrapIssuerApiTrust(value));
  }
  await issuerDenied(claimBootstrapIssuerApiTrust(issuer, undefined));
  assert.equal(reads, 0); assert.equal(issuer.summary().clientFetches, 0);
});
test('capability has only an immutable aggregate summary and does not mint a token or start a listener', async t => {
  const f = await fixture(t);
  assert.deepEqual(Object.keys(f.capability), ['summary']); assert.ok(Object.isFrozen(f.capability));
  const summary = f.capability.summary();
  assert.ok(Object.isFrozen(summary)); assert.equal(summary.mode, 'PUBLIC_API_TRUST_HANDOFF_ONLY');
  assert.equal(summary.originalIssuerLifetime, true); assert.equal(summary.listenerHandoffClaimed, false);
  assert.equal(summary.pinnedSyntheticStatements, 15); assert.equal(summary.tokensMintedByThisCapability, 0);
  assert.equal(summary.listenersStarted, 0); assert.equal(summary.processesStarted, 0);
  assert.equal(summary.actualPolisVerified, false); assert.equal(summary.runtimeOwnershipVerified, false);
  assert.equal(summary.productionReady, false); refused(() => f.capability.summary(undefined));
  assert.doesNotMatch(JSON.stringify(summary), /https:|PRIVATE KEY|publicJwk|seedStatementsJson|assertActive|certificatePem/u);
  assert.equal(f.issuer.summary().tokensIssued, 0); assert.equal(f.issuer.summary().verifiedTlsFetches, 1);
});
test('claimed public identity is exactly the original issuer key and exact pinned seed bytes', async t => {
  const f = await fixture(t); const identity = claimBootstrapApiTrust(f.capability);
  assert.deepEqual(Object.keys(identity), ['issuer', 'publicJwk', 'seedStatementsJson', 'signal', 'assertActive']);
  assert.ok(Object.isFrozen(identity)); assert.ok(Object.isFrozen(identity.publicJwk));
  assert.equal(identity.issuer, f.issuer.configuration().issuer);
  assert.deepEqual(Object.keys(identity.publicJwk), ['kty', 'n', 'e', 'kid', 'use', 'alg']);
  const publicRole = await claimBootstrapIssuerPublicJwks(f.issuer);
  assert.deepEqual(identity.publicJwk, JSON.parse(publicRole.publicJwksText).keys[0]);
  assert.equal(sha(createPublicKey({ key: identity.publicJwk, format: 'jwk' }).export({ format: 'der', type: 'spki' })), identity.publicJwk.kid);
  assert.equal(identity.seedStatementsJson, await readFile(new URL('../seed-statements.json', import.meta.url), 'utf8'));
  assert.equal(sha(identity.seedStatementsJson), SEED_SHA); assert.equal(JSON.parse(identity.seedStatementsJson).length, 15);
  assert.equal(identity.signal, publicRole.signal); assert.equal(identity.assertActive, publicRole.assertActive);
  assert.equal(identity.assertActive(), undefined); assert.equal(f.issuer.summary().tokensIssued, 0);
  assert.doesNotMatch(JSON.stringify(identity), /PRIVATE KEY|"d"\s*:|"p"\s*:|"q"\s*:|certificatePem|access_token|refresh_token/u);
});
test('public API identity and its key cannot be edited after claim', async t => {
  const f = await fixture(t); const identity = claimBootstrapApiTrust(f.capability);
  assert.throws(() => { identity.issuer = 'https://other.invalid/'; });
  assert.throws(() => { identity.publicJwk.n = 'replacement'; });
  assert.throws(() => { identity.seedStatementsJson = '[]'; });
  assert.throws(() => { identity.assertActive = () => {}; });
  assert.equal(identity.assertActive(), undefined);
});
test('listener claim rejects malformed, copied, proxied and repeated capabilities without reading methods', async t => {
  const f = await fixture(t); let reads = 0;
  const proxy = new Proxy(f.capability, { get() { reads++; } });
  for (const cap of [undefined, null, {}, { ...f.capability }, proxy, { get summary() { reads++; } }]) refused(() => claimBootstrapApiTrust(cap));
  refused(() => claimBootstrapApiTrust(f.capability, undefined));
  assert.equal(reads, 0); assert.equal(f.capability.summary().listenerHandoffClaimed, false);
  claimBootstrapApiTrust(f.capability); assert.equal(f.capability.summary().listenerHandoffClaimed, true);
  refused(() => claimBootstrapApiTrust(f.capability));
});
test('API-role reservation cannot be repeated even before listener claim', async t => {
  const f = await fixture(t);
  await denied(createBootstrapApiTrust({ issuer: f.issuer }));
  await issuerDenied(claimBootstrapIssuerApiTrust(f.issuer));
  assert.equal(f.issuer.summary().clientFetches, 1); assert.equal(f.issuer.summary().tokensIssued, 0);
  assert.equal(f.capability.summary().listenerHandoffClaimed, false);
  claimBootstrapApiTrust(f.capability);
});
test('API-first and JWKS-first public role orders reuse exactly one verified HTTPS fetch', async t => {
  for (const first of ['api', 'jwks']) {
    const issuer = await issuerFixture(t);
    let capability; let jwks;
    if (first === 'api') { capability = await createBootstrapApiTrust({ issuer }); jwks = await claimBootstrapIssuerPublicJwks(issuer); }
    else { jwks = await claimBootstrapIssuerPublicJwks(issuer); capability = await createBootstrapApiTrust({ issuer }); }
    const identity = claimBootstrapApiTrust(capability);
    assert.deepEqual(identity.publicJwk, JSON.parse(jwks.publicJwksText).keys[0]);
    assert.equal(identity.signal, jwks.signal); assert.equal(identity.assertActive, jwks.assertActive);
    assert.equal(issuer.summary().clientFetches, 1); assert.equal(issuer.summary().verifiedTlsFetches, 1);
    assert.equal(issuer.summary().tokensIssued, 0);
  }
});
test('concurrent public roles share the same in-flight verified fetch and original lifetime', async t => {
  const issuer = await issuerFixture(t);
  const [capability, publicRole] = await Promise.all([createBootstrapApiTrust({ issuer }), claimBootstrapIssuerPublicJwks(issuer)]);
  const identity = claimBootstrapApiTrust(capability);
  assert.equal(identity.signal, publicRole.signal); assert.equal(identity.assertActive, publicRole.assertActive);
  assert.equal(issuer.summary().clientFetches, 1); assert.equal(issuer.summary().jwksRequests, 1);
  await issuer.close(); assert.equal(identity.signal.aborted, true); assert.equal(publicRole.signal.aborted, true);
  assert.throws(() => identity.assertActive(), { message: ISSUER_ERROR });
});
test('the real public JWKS service can consume its role after API trust, with no second verified fetch', async t => {
  const f = await fixture(t);
  const service = await createBootstrapJwksService({ issuer: f.issuer, namespaceId: 'e'.repeat(24) });
  t.after(() => service.close()); const identity = claimBootstrapApiTrust(f.capability);
  assert.equal(f.issuer.summary().clientFetches, 1); assert.equal(f.issuer.summary().verifiedTlsFetches, 1);
  assert.equal(f.issuer.summary().tokensIssued, 0); assert.equal(identity.assertActive(), undefined);
  await service.close(); assert.equal(identity.signal.aborted, false); assert.equal(identity.assertActive(), undefined);
});
test('the real public JWKS service can precede API trust without consuming its role', async t => {
  const issuer = await issuerFixture(t);
  const service = await createBootstrapJwksService({ issuer, namespaceId: 'f'.repeat(24) }); t.after(() => service.close());
  const capability = await createBootstrapApiTrust({ issuer }); claimBootstrapApiTrust(capability);
  assert.equal(issuer.summary().clientFetches, 1); assert.equal(issuer.summary().verifiedTlsFetches, 1);
});
test('public role sharing does not consume or restore the independent one-token transport authority', async t => {
  const f = await fixture(t); claimBootstrapApiTrust(f.capability);
  await claimBootstrapIssuerPublicJwks(f.issuer);
  const transport = claimBootstrapIssuerForTransport(f.issuer);
  assert.equal(typeof transport.token, 'string'); assert.equal(f.issuer.summary().tokensIssued, 1);
  assert.throws(() => claimBootstrapIssuerForTransport(f.issuer));
  await denied(createBootstrapApiTrust({ issuer: f.issuer }));
  assert.equal(f.issuer.summary().tokensIssued, 1); assert.equal(f.issuer.summary().clientFetches, 1);
});
test('a failed verified public fetch is cached across independent public roles while issuer remains active', async t => {
  const issuer = await issuerFixture(t); const config = issuer.configuration();
  // Exhaust only this newly owned listener's fixed public request budget. The
  // issuer remains active; a second role would produce another clientFetches
  // increment if it incorrectly retried the first role's rejected fetch.
  for (let i = 0; i < 32; i++) await directPublicFetch(config);
  await denied(createBootstrapApiTrust({ issuer }));
  assert.equal(issuer.summary().closed, false); assert.equal(issuer.summary().clientFetches, 1);
  await issuerDenied(claimBootstrapIssuerPublicJwks(issuer));
  assert.equal(issuer.summary().clientFetches, 1); assert.equal(issuer.summary().tokensIssued, 0);
});
test('close during the shared verified fetch rejects both roles and does not restore either cap', async t => {
  const issuer = await issuerFixture(t);
  const apiPending = denied(createBootstrapApiTrust({ issuer }));
  const jwksPending = issuerDenied(claimBootstrapIssuerPublicJwks(issuer));
  await issuer.close(); await Promise.all([apiPending, jwksPending]);
  await denied(createBootstrapApiTrust({ issuer }));
  assert.equal(issuer.summary().clientFetches, 1); assert.equal(issuer.summary().tokensIssued, 0);
  assert.equal(issuer.summary().listenersClosed, true);
});
test('closed original issuer invalidates an unclaimed API cap without minting or restarting', async t => {
  const f = await fixture(t); await f.issuer.close();
  refused(() => claimBootstrapApiTrust(f.capability));
  assert.equal(f.capability.summary().listenerHandoffClaimed, true);
  await denied(createBootstrapApiTrust({ issuer: f.issuer }));
  assert.equal(f.issuer.summary().tokensIssued, 0); assert.equal(f.issuer.summary().listenersClosed, true);
});
test('the handed-off activity check enforces original expiry without allocating a new lifetime', async t => {
  const f = await fixture(t); const identity = claimBootstrapApiTrust(f.capability);
  const now = Date.now; const future = now() + 120_001;
  try {
    Date.now = () => future;
    assert.throws(() => identity.assertActive(), { message: ISSUER_ERROR });
    assert.equal(identity.signal.aborted, true);
  } finally { Date.now = now; }
  await f.issuer.close(); assert.equal(f.issuer.summary().listenersClosed, true);
});
test('source-copy fixture preserves exact original branding and permits only the pinned fixed seed bytes', async t => {
  const source = await sourceFixture(t, 'good'); const issuer = await issuerFixture(t);
  const cap = await source.module.createBootstrapApiTrust({ issuer }); const value = source.module.claimBootstrapApiTrust(cap);
  assert.equal(sha(value.seedStatementsJson), SEED_SHA); assert.equal(issuer.summary().clientFetches, 1);
  refused(() => claimBootstrapApiTrust(cap));
});
for (const mode of ['missing', 'directory', 'symlink', 'changed', 'oversize']) {
  test(`fixed seed ${mode} fails closed with no fallback or leaked path`, async t => {
    const source = await sourceFixture(t, mode); const issuer = await issuerFixture(t);
    await denied(source.module.createBootstrapApiTrust({ issuer }));
    assert.equal(issuer.summary().tokensIssued, 0); assert.equal(issuer.summary().clientFetches, 1);
    // Neither a repaired source nor another cap may reuse consumed API role.
    if (mode === 'changed') await writeFile(source.seedPath, source.good);
    await denied(source.module.createBootstrapApiTrust({ issuer }));
    const publicRole = await claimBootstrapIssuerPublicJwks(issuer);
    assert.equal(typeof publicRole.publicJwksText, 'string'); assert.equal(issuer.summary().clientFetches, 1);
  });
}
test('source tamper after handoff cannot replace immutable public seed bytes already admitted', async t => {
  const source = await sourceFixture(t, 'good'); const issuer = await issuerFixture(t);
  const cap = await source.module.createBootstrapApiTrust({ issuer });
  await writeFile(source.seedPath, '[]');
  const identity = source.module.claimBootstrapApiTrust(cap);
  assert.equal(sha(identity.seedStatementsJson), SEED_SHA); assert.equal(JSON.parse(identity.seedStatementsJson).length, 15);
});
