/** Ordinary tests never launch a browser or create profile/listener state. */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { runNativeHttpsProof } from './native-https-proof.mjs';
test('native HTTPS proof rejects missing dependencies or caller-selected issuer flow before setup', async () => {
  await assert.rejects(runNativeHttpsProof(), /Explicit installed full test browser required/u);
  await assert.rejects(runNativeHttpsProof({ chromium: { launch() {} }, executablePath: '/invented' }));
  await assert.rejects(runNativeHttpsProof({ chromium: { launchPersistentContext() { throw new Error('MUST_NOT_RUN'); } },
    executablePath: '/invented', issuerFlow: 'REAL_PROVIDER' }), /Fixed synthetic issuer flow required/u);
  await assert.rejects(runNativeHttpsProof({ chromium: { launchPersistentContext() { throw new Error('MUST_NOT_RUN'); } },
    executablePath: '/invented', composition: 'PRODUCTION' }), /Fixed synthetic composition required/u);
});
test('strict native branch uses real service control and a displayed statement for warm denial', () => {
  const source = readFileSync(new URL('./native-https-proof.mjs', import.meta.url), 'utf8');
  assert.match(source, /createStrictNativeFixture\(\{ lab, seeds \}\)/u);
  assert.match(source, /await strictFixture\.approve\(\)/u);
  assert.match(source, /await strictFixture\.openAndIssue\(\)/u);
  assert.match(source, /await strictFixture\.revoke\(\)/u);
  assert.match(source, /providerCalls === beforeDeniedVote\.providerCalls/u);
  assert.match(source, /ports\.length === \(strict \? 6 : 4\)/u);
});
test('native HTTPS runner has no metadata/cookie/TLS bypass or response fabrication', () => {
  const source = readFileSync(new URL('./native-https-proof.mjs', import.meta.url), 'utf8');
  assert.match(source, /await route\.continue\(\)/u);
  assert.match(source, /ignoreHTTPSErrors: false/u);
  assert.match(source, /ERR_CERT_AUTHORITY_INVALID/u); assert.match(source, /ERR_CERT_COMMON_NAME_INVALID/u);
  assert.match(source, /result\.browserVersion === '149\.0\.7827\.55'/u);
  assert.doesNotMatch(source, /route\.fulfill\(|addCookies\(|setExtraHTTPHeaders\(|ignore-certificate-errors|NODE_TLS_REJECT_UNAUTHORIZED|Security\.setIgnoreCertificateErrors/u);
  assert.match(source, /http\.server\.request\.start/u);
});
test('native HTTPS runner has bounded requests/time and cleanup cannot infer launch failure is closed', () => {
  const source = readFileSync(new URL('./native-https-proof.mjs', import.meta.url), 'utf8');
  assert.match(source, /requestCount > 120/u); assert.match(source, /120000/u);
  assert.match(source, /context\.close\(\)\.catch/u);
  assert.match(source, /result\.browserClosed \|\| !launchAttempted/u);
  assert.match(source, /ownedProfileCleanupRequired/u);
  assert.match(source, /ports\.map\(refused\)/u);
  assert.match(source, /serverRequests\.unsubscribe\(onServerRequest\)/u);
  assert.match(source, /if \(lifetimeExpired \|\| routingErrors \|\| pageErrors \|\| unexpectedRequests \|\| requestCount > 120/u);
});
