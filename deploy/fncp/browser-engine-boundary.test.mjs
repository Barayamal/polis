/** Ordinary Node tests: no browser package import/launch or downloads. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { nativeRequestAllowed } from './browser-engine/native-policy.mjs';
import { runNativeUiProof } from './browser-engine/native-ui-proof.mjs';
import { runBrowserEngineProof } from './browser-engine/engine-proof.mjs';

const origin = 'http://127.0.0.1:49152';
for (const [path, method] of [['/', 'GET'], ['/app.js', 'GET'], ['/style.css', 'GET'], ['/api/session', 'GET'],
  ['/api/oidc/start', 'POST'], ['/api/oidc/callback', 'POST'], ['/api/registration', 'POST'],
  ['/api/redeem', 'POST'], ['/api/participation-init', 'GET'], ['/api/next-comment', 'GET'], ['/api/votes', 'POST'], ['/api/logout', 'POST']]) {
  test(`native browser fixture allows exact method/path ${method} ${path}`, () => assert.equal(nativeRequestAllowed(origin, origin + path, method), true));
}
for (const [label, url, method] of [
  ['external', 'https://example.invalid/', 'GET'], ['different port', 'http://127.0.0.1:49153/', 'GET'],
  ['alias', 'http://localhost:49152/', 'GET'], ['different loopback', 'http://127.0.0.2:49152/', 'GET'],
  ['userinfo', 'http://user@127.0.0.1:49152/', 'GET'], ['query', origin + '/api/session?token=invented', 'GET'],
  ['fragment', origin + '/#token', 'GET'], ['websocket', 'ws://127.0.0.1:49152/', 'GET'],
  ['unknown path', origin + '/admin', 'GET'], ['wrong method', origin + '/api/registration', 'GET'],
  ['lowercase method', origin + '/api/votes', 'post'], ['normalization', origin + '/x/../', 'GET'],
  ['whitespace', ' ' + origin + '/', 'GET'], ['missing', undefined, 'GET'], ['non-string', {}, 'GET'],
  ['missing method', origin + '/unknown', undefined], ['empty query', origin + '/?', 'GET'],
  ['empty fragment', origin + '/#', 'GET'], ['encoded path', origin + '/%61pp.js', 'GET'],
]) test(`native browser fixture refuses ${label}`, () => assert.equal(nativeRequestAllowed(origin, url, method), false));
for (const invalid of ['http://127.0.0.1', 'http://127.0.0.1:65536', 'https://127.0.0.1:49152', 'http://localhost:49152', origin + '/', null]) {
  test(`native browser fixture refuses invalid origin ${String(invalid)}`, () => assert.equal(nativeRequestAllowed(invalid, origin + '/', 'GET'), false));
}
test('browser engines require explicit caller-supplied installed dependencies', async () => {
  await assert.rejects(runNativeUiProof(), /Explicit installed test browser required/u);
  await assert.rejects(runBrowserEngineProof(), /Explicit installed test browser required/u);
});
test('native browser launch failure is sanitized and fresh application closes independently', async () => {
  const result = await runNativeUiProof({ chromium: { async launch() { throw new Error('private_synthetic_sentinel'); } }, executablePath: '/invented/browser' });
  assert.equal(result.outcome, 'FAIL'); assert.equal(result.browserStarted, false);
  assert.equal(result.browserClosed, false); assert.equal(result.applicationStarted, true);
  assert.equal(result.applicationClosed, true); assert.equal(result.listenerIndependentlyRefused, true);
  assert.equal(result.browserEngineTested, false); assert.equal(JSON.stringify(result).includes('private_synthetic_sentinel'), false);
});
test('native engine source preserves containment and never manufactures browser security headers or cookies', () => {
  const source = readFileSync(new URL('./browser-engine/native-ui-proof.mjs', import.meta.url), 'utf8');
  assert.match(source, /await route\.continue\(\)/u); assert.match(source, /nativeRequestAllowed/u);
  assert.match(source, /routeWebSocket/u); assert.match(source, /ignoreHTTPSErrors: false/u);
  assert.doesNotMatch(source, /addCookies\(|setExtraHTTPHeaders\(|launchPersistentContext\(|ignore-certificate-errors|NODE_TLS_REJECT_UNAUTHORIZED/u);
  assert.match(source, /requestCount > 120/u); assert.match(source, /120000/u);
  assert.match(source, /counters\.agree === 5 && counters\.disagree === 5 && counters\.pass === 5/u);
});
