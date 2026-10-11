import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(new URL('../../../server/package.json', import.meta.url));
const ts = require('typescript');
const ERROR = 'Fresh bootstrap API process rejected; private details withheld.';
const denied = value => assert.rejects(value, error => error.message === ERROR && error.cause === undefined);
const deniedSync = value => assert.throws(value, error => error.message === ERROR && error.cause === undefined);
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(predicate) {
  for (let i = 0; i < 100; i++) { if (predicate()) return; await delay(5); }
  assert.fail('Fresh fixture did not reach the required aggregate state.');
}
function profile(issuer) {
  const namespace = 'a'.repeat(24);
  const db = `postgres://fncp_fresh_${'b'.repeat(24)}:${'c'.repeat(64)}@fncp-fresh-pg-${namespace}:5432/fncp_fresh_${'d'.repeat(24)}`;
  return { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C', FNCP_FRESH_BOOTSTRAP_LOCAL_ONLY: 'true', NODE_ENV: 'production',
    DEV_MODE: 'false', TESTING: 'false', ENABLE_TELEMETRY: 'false', USE_NETWORK_HOST: 'false',
    SHOULD_USE_TRANSLATION_API: 'false', BACKFILL_COMMENT_LANG_DETECTION: 'false', RUN_PERIODIC_EXPORT_TESTS: 'false',
    SERVER_LOG_TO_FILE: 'false', EMAIL_TRANSPORT_TYPES: 'disabled', ADMIN_EMAILS: '[]', ADMIN_UIDS: '[]',
    API_SERVER_PORT: '5000', DATABASE_SSL: 'true', AUTH_AUDIENCE: 'fncp-fresh-synthetic-bootstrap', AUTH_ISSUER: issuer,
    FNCP_BOOTSTRAP_DATABASE_CERTIFICATE_SHA256: 'e'.repeat(64), FNCP_BOOTSTRAP_JWKS_CERTIFICATE_SHA256: 'f'.repeat(64),
    LOGIN_CODE_PEPPER: '1'.repeat(64), ENCRYPTION_PASSWORD_00001: '2'.repeat(64), DATABASE_URL: db, READ_ONLY_DATABASE_URL: db,
    JWKS_URI: `https://fncp-fresh-jwks-${namespace}:8444/.well-known/jwks.json`, API_PROD_HOSTNAME: `fncp-fresh-api-${namespace}:8443`,
    DOMAIN_OVERRIDE: `fncp-fresh-api-${namespace}:8443`, POLIS_JWT_ISSUER: `https://${`fncp-fresh-api-${namespace}:8443`}/`,
    POLIS_JWT_AUDIENCE: 'fncp-fresh-synthetic-participants', JWT_PRIVATE_KEY_PATH: '/run/fncp/bootstrap/participant-private.pem',
    JWT_PUBLIC_KEY_PATH: '/run/fncp/bootstrap/participant-public.pem' };
}
function stub(mode) {
  return `const {copyFreshBootstrapChildEnvironment}=require('./child-profile.js');
const mode=${JSON.stringify(mode)};
const state={calls:0,closeCalls:0,closed:false,failed:false,closeAcknowledged:false};exports.state=state;
exports.createBootstrapChildOwner=async function(options){
  state.calls++;state.input=options;
  copyFreshBootstrapChildEnvironment(options.environment);
  if(options.environment.AUTH_ISSUER!==options.trust.issuer)throw Error('private mismatch');
  if(mode==='throws')throw Error('private sentinel');
  const owner={
    configuration(){if(mode==='config-throws')throw Error('private sentinel');if(state.closed)throw Error('closed');
      if(mode==='bad-config')return {...state.config,token:'private sentinel'};return state.config;},
    close(){state.closeCalls++;if(mode==='close-fails')return Promise.reject(Error('private sentinel'));
      state.closed=true;
      if(mode==='close-held')return new Promise(resolve=>{state.resolveClose=()=>{state.closeAcknowledged=true;resolve();};});
      if(mode==='sync-close')return undefined;
      state.closeAcknowledged=true;return Promise.resolve();},
    summary(){if(mode==='summary-throws')throw Error('private sentinel');
      const value={spawnAttempted:true,ready:true,closed:state.closed,failed:state.failed,childExitVerified:state.closeAcknowledged,
        ipcDisconnected:state.closeAcknowledged,listenerClosureVerified:state.closeAcknowledged,
        exitCode:state.closeAcknowledged?0:null,signalCode:null,databaseOwnershipVerified:false,containerOwnershipVerified:false,activationGranted:false};
      return mode==='bad-summary'?{...value,private:'sentinel'}:value;}}
  if(mode==='bad-return')return {...owner,private:'sentinel'};
  if(mode==='bad-method')return {...owner,configuration:4};
  if(mode==='return-proxy')return new Proxy(owner,{get(_target,key){if(key==='then'){state.promiseThenReads=(state.promiseThenReads||0)+1;return undefined;}state.proxyReads=(state.proxyReads||0)+1;throw Error('private sentinel');}});
  if(mode==='held')return new Promise(resolve=>{state.resolveOwner=()=>resolve(owner);});
  return owner;
};`;
}
// Copy only PUBLIC source into a new fixture tree. The bridge then uses its
// unchanged literal relative owner import, which lands on this compiled stub.
// No existing server/dist, retained config, real Pol.is app or child is read,
// written, imported or started. Issuer/JWKS TLS and cap branding remain real.
async function fixture(t, mode = 'ready') {
  const root = await mkdtemp(join(tmpdir(), 'fncp-api-process-fixture-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const fresh = join(root, 'deploy/fncp/fresh-runtime');
  const ownerDirectory = join(root, 'server/dist/src/bootstrap');
  await mkdir(fresh, { recursive: true }); await mkdir(ownerDirectory, { recursive: true });
  await mkdir(join(root, 'server/dist/src/auth'));
  for (const name of ['bootstrap-api-process.mjs', 'bootstrap-api-trust.mjs', 'bootstrap-issuer.mjs'])
    await writeFile(join(fresh, name), await readFile(new URL(name, import.meta.url)), { flag: 'wx', mode: 0o600 });
  await writeFile(join(root, 'deploy/fncp/seed-statements.json'), await readFile(new URL('../seed-statements.json', import.meta.url)), { flag: 'wx', mode: 0o600 });
  for (const file of ['src/bootstrap/child-profile.ts', 'src/auth/fncp-bootstrap-startup.ts']) {
    const source = await readFile(new URL(`../../../server/${file}`, import.meta.url), 'utf8');
    await writeFile(join(root, 'server/dist', file.replace(/\.ts$/u, '.js')), ts.transpileModule(source, {
      compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
    }).outputText, { flag: 'wx', mode: 0o600 });
  }
  const ownerPath = join(ownerDirectory, 'child-owner.js');
  if (mode !== 'missing-module') await writeFile(ownerPath,
    mode === 'module-throws' ? "throw Error('private module sentinel');" :
    mode === 'missing-export' ? 'exports.unrelated=()=>{};' : stub(mode), { flag: 'wx', mode: 0o600 });
  const issuerModule = await import(pathToFileURL(join(fresh, 'bootstrap-issuer.mjs')).href);
  const trustModule = await import(pathToFileURL(join(fresh, 'bootstrap-api-trust.mjs')).href);
  const processModule = await import(pathToFileURL(join(fresh, 'bootstrap-api-process.mjs')).href);
  const issuer = await issuerModule.createBootstrapIssuer(); t.after(() => issuer.close());
  const trust = await trustModule.createBootstrapApiTrust({ issuer });
  const configuration = issuer.configuration();
  let state;
  if (!['missing-module', 'module-throws', 'missing-export'].includes(mode)) {
    ({ state } = await import(pathToFileURL(ownerPath).href));
    state.config = Object.freeze({ origin: configuration.issuer.slice(0, -1), certificatePem: configuration.certificatePem,
      certificateSha256: '1'.repeat(64) });
  }
  const f = { issuer, trust, state, ...processModule, issuerModule, trustModule, environment: profile(configuration.issuer) };
  f.start = () => f.createBootstrapApiProcess({ trust, environment: f.environment });
  return f;
}

test('genuine trust binds the fixed compiled owner and passes only public identity plus original signal', async t => {
  const f = await fixture(t); const process = await f.start(); t.after(() => process.close());
  const publicRole = await f.issuerModule.claimBootstrapIssuerPublicJwks(f.issuer);
  assert.deepEqual(Object.keys(f.state.input), ['environment', 'trust', 'signal']);
  assert.deepEqual(Object.keys(f.state.input.trust), ['issuer', 'publicJwk', 'seedStatementsJson']);
  assert.equal(f.state.input.signal, publicRole.signal);
  assert.deepEqual(f.state.input.trust.publicJwk, JSON.parse(publicRole.publicJwksText).keys[0]);
  assert.equal(f.issuer.summary().tokensIssued, 0); assert.equal(f.issuer.summary().clientFetches, 1);
  assert.ok(Object.isFrozen(f.state.input)); assert.ok(Object.isFrozen(f.state.input.environment));
  assert.ok(Object.isFrozen(f.state.input.trust)); assert.equal(process.assertActive(), undefined);
});
test('configuration is explicitly private while summary returns fixed aggregate-only scope facts', async t => {
  const f = await fixture(t); const process = await f.start(); t.after(() => process.close());
  const config = process.configuration(); assert.deepEqual(config, f.state.config); assert.ok(Object.isFrozen(config));
  const summary = process.summary(); assert.ok(Object.isFrozen(summary)); assert.ok(Object.isFrozen(summary.owner));
  assert.equal(summary.classification, 'ORIGINAL_ISSUER_BOUND_API_CHILD_BRIDGE');
  assert.equal(summary.tokensMintedByBridge, 0); assert.equal(summary.issuerOwnershipClaimed, false);
  assert.equal(summary.imageAttestationVerified, false); assert.equal(summary.databaseOwnershipVerified, false);
  assert.equal(summary.containerOwnershipVerified, false); assert.equal(summary.activationGranted, false);
  assert.equal(summary.activityWatchActive, true); assert.equal(summary.ownerCreationAttempted, true);
  assert.doesNotMatch(JSON.stringify(summary), /https:|PRIVATE KEY|certificatePem|publicJwk|DATABASE_URL|LOGIN_CODE_PEPPER/u);
});
test('caller environment mutation after dispatch cannot change the owner input snapshot', async t => {
  const f = await fixture(t); const expected = { ...f.environment }; const pending = f.start();
  f.environment.AUTH_ISSUER = 'https://external.invalid/'; f.environment.NODE_OPTIONS = '--inspect';
  const process = await pending; t.after(() => process.close());
  assert.deepEqual(f.state.input.environment, expected); assert.notEqual(f.state.input.environment, f.environment);
});
test('malformed options, selectors, getters, proxies and environment value coercion never invoke the owner', async t => {
  const f = await fixture(t); let touched = 0;
  const accessor = { trust: f.trust, get environment() { touched++; throw Error('private'); } };
  const proxy = new Proxy({}, { get() { touched++; }, ownKeys() { touched++; } });
  for (const input of [undefined, null, {}, accessor, proxy,
    { trust: f.trust, environment: f.environment, loader: () => {} },
    { trust: f.trust, environment: f.environment, ownerPath: '/retained/private' },
    { trust: f.trust, environment: new Proxy(f.environment, { get() { touched++; } }) },
    { trust: f.trust, environment: { ...f.environment, PATH: { toString() { touched++; } } } },
    { trust: f.trust, environment: { ...f.environment, [Symbol('private')]: 'hidden' } },
    { trust: f.trust, environment: { ...f.environment, PATH: 'x'.repeat(1025) } }]) await denied(f.createBootstrapApiProcess(input));
  await denied(f.createBootstrapApiProcess({ trust: f.trust, environment: f.environment }, undefined));
  assert.equal(touched, 0); assert.equal(f.state.calls, 0); assert.equal(f.trust.summary().listenerHandoffClaimed, false);
});
test('fabricated, copied and proxied trust capabilities cannot trigger the fixed owner', async t => {
  const f = await fixture(t); let touched = 0;
  for (const trust of [{}, { ...f.trust }, new Proxy(f.trust, { get() { touched++; } }), { get summary() { touched++; } }])
    await denied(f.createBootstrapApiProcess({ trust, environment: f.environment }));
  assert.equal(touched, 0); assert.equal(f.state.calls, 0);
});
test('one trust capability cannot launch a second owner or be replayed after closure', async t => {
  const f = await fixture(t); const process = await f.start(); t.after(() => process.close());
  await denied(f.start()); assert.equal(f.state.calls, 1);
  await process.close(); await denied(f.start()); assert.equal(f.state.calls, 1); assert.equal(f.state.closeCalls, 1);
});
test('fixed owner performs exact profile validation and rejection still consumes admitted trust', async t => {
  const f = await fixture(t); f.environment.PATH = '/usr/bin:/bin:';
  await denied(f.start()); assert.equal(f.state.calls, 1); assert.equal(f.trust.summary().listenerHandoffClaimed, true);
  f.environment.PATH = '/usr/bin:/bin'; await denied(f.start()); assert.equal(f.state.calls, 1);
});
for (const mode of ['missing-module', 'module-throws', 'missing-export']) {
  test(`fixed owner ${mode} fails closed without fallback and consumes trust once`, async t => {
    const f = await fixture(t, mode); await denied(f.start());
    assert.equal(f.trust.summary().listenerHandoffClaimed, true); await denied(f.start());
    assert.equal(f.issuer.summary().tokensIssued, 0);
  });
}
for (const mode of ['bad-return', 'bad-method', 'bad-config', 'config-throws', 'bad-summary', 'summary-throws']) {
  test(`malformed trusted owner ${mode} is rejected and its safe known close is acknowledged once`, async t => {
    const f = await fixture(t, mode); await denied(f.start());
    assert.equal(f.state.calls, 1); assert.equal(f.state.closeCalls, 1); assert.equal(f.state.closeAcknowledged, true);
    await denied(f.start()); assert.equal(f.state.closeCalls, 1);
  });
}
test('a proxy owner return is rejected without reading candidate methods or adopting cleanup authority', async t => {
  const f = await fixture(t, 'return-proxy'); await denied(f.start());
  // Promise resolution itself reads `then` before the bridge can receive a
  // trusted asynchronous factory result. No candidate owner method is read.
  assert.ok(f.state.promiseThenReads > 0);
  assert.equal(f.state.proxyReads || 0, 0); assert.equal(f.state.closeCalls, 0);
});
test('throwing owner creation is not replayed and exposes no implementation error', async t => {
  const f = await fixture(t, 'throws'); await denied(f.start()); await denied(f.start());
  assert.equal(f.state.calls, 1); assert.equal(f.state.closeCalls, 0);
});
test('issuer cancellation before queued import/creation completes prevents owner invocation', async t => {
  const f = await fixture(t); const pending = denied(f.start());
  await f.issuer.close(); await pending; assert.equal(f.state.calls, 0);
});
test('late owner after issuer abort is closed once before the rejected factory settles', async t => {
  const f = await fixture(t, 'held'); let settled = false;
  const pending = denied(f.start()).then(() => { settled = true; });
  await until(() => !!f.state.resolveOwner); await f.issuer.close(); await delay(10);
  assert.equal(settled, false); assert.equal(f.state.closeCalls, 0);
  f.state.resolveOwner(); await pending;
  assert.equal(f.state.closeCalls, 1); assert.equal(f.state.closeAcknowledged, true); assert.equal(settled, true);
});
test('closing bridge is idempotent, waits for the original close acknowledgement and leaves issuer live', async t => {
  const f = await fixture(t, 'close-held'); const process = await f.start();
  const one = process.close(); const two = process.close(); assert.equal(one, two);
  deniedSync(() => process.configuration()); deniedSync(() => process.assertActive());
  await until(() => !!f.state.resolveClose);
  assert.equal(f.state.closeCalls, 1); assert.equal(process.summary().ownerClosureAcknowledged, false);
  assert.equal(process.summary().activityWatchActive, false);
  f.state.resolveClose(); await one;
  assert.equal(process.summary().ownerClosureAcknowledged, true); assert.equal(f.issuer.summary().closed, false);
});
test('original issuer closure immediately denies public authority and closes child independently', async t => {
  const f = await fixture(t); const process = await f.start(); t.after(() => process.close());
  await f.issuer.close(); deniedSync(() => process.assertActive()); deniedSync(() => process.configuration());
  await process.close(); assert.equal(f.state.closeCalls, 1); assert.equal(process.summary().activityWatchActive, false);
  assert.equal(process.summary().ownerClosureAcknowledged, true);
});
test('original backwards clock is detected by activity watch with no second lifetime', async t => {
  const f = await fixture(t); const process = await f.start(); t.after(() => process.close());
  const now = Date.now; const earlier = now() - 120001;
  try { Date.now = () => earlier; await until(() => process.summary().closed); }
  finally { Date.now = now; }
  await process.close(); assert.equal(f.issuer.summary().closed, true);
  assert.equal(f.state.closeCalls, 1); assert.equal(process.summary().activityWatchActive, false);
});
test('underlying child failure cannot leave bridge activity or configuration usable', async t => {
  const f = await fixture(t); const process = await f.start(); t.after(() => process.close());
  f.state.failed = true; deniedSync(() => process.assertActive()); await process.close();
  assert.equal(process.summary().failed, true); assert.equal(process.summary().ownerClosureAcknowledged, true);
});
test('uncertain child close failure is preserved and never retried or misreported acknowledged', async t => {
  const f = await fixture(t, 'close-fails'); const process = await f.start();
  await denied(process.close()); await denied(process.close()); assert.equal(f.state.closeCalls, 1);
  assert.equal(process.summary().ownerClosureAcknowledged, false); assert.equal(process.summary().activityWatchActive, false);
});
test('synchronous non-promise close is not an acknowledged owner cleanup', async t => {
  const f = await fixture(t, 'sync-close'); const process = await f.start();
  await denied(process.close()); assert.equal(f.state.closeCalls, 1); assert.equal(process.summary().ownerClosureAcknowledged, false);
});
test('extra method arguments fail without changing admitted process authority', async t => {
  const f = await fixture(t); const process = await f.start(); t.after(() => process.close());
  for (const method of ['configuration', 'summary', 'assertActive']) deniedSync(() => process[method](undefined));
  await denied(process.close(undefined)); assert.equal(process.assertActive(), undefined); assert.equal(f.state.closeCalls, 0);
});
