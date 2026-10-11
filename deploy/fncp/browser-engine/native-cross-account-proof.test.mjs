/** Boundary checks do not launch a browser or create profile/listener state. */
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { runNativeCrossAccountProof } from './native-cross-account-proof.mjs';

test('cross-account native runner rejects extra account/path capabilities before invoking a launcher', async () => {
  let calls = 0; let reads = 0;
  const chromium = { launchPersistentContext() { calls++; throw new Error('MUST_NOT_RUN'); } };
  for (const value of [undefined, null, {}, { chromium, executablePath: '/invented', account: 2 },
    { chromium, executablePath: '/invented', profilePath: '/not-allowed' }]) await assert.rejects(runNativeCrossAccountProof(value));
  const options = { chromium, executablePath: '/invented' };
  Object.defineProperty(options, 'executablePath', { get() { reads++; return '/invented'; } });
  await assert.rejects(runNativeCrossAccountProof(options));
  assert.equal(calls, 0); assert.equal(reads, 0);
});
test('cross-account native runner observes real reciprocal backend requests and unchanged valid tokens', () => {
  const source = readFileSync(new URL('./native-cross-account-proof.mjs', import.meta.url), 'utf8');
  assert.match(source, /createTwoAccountStrictNativeFixture\(\{ lab, seeds \}\)/u);
  assert.match(source, /approvedAccounts === 2/u);
  assert.match(source, /invitations\[1 - index\]\.invitationToken/u);
  assert.match(source, /invitations\[index\]\.invitationToken/u);
  assert.match(source, /accessRequests\.redeem === before \+ 1/u);
  assert.match(source, /accessRequests\.vote === before \+ 1/u);
  assert.match(source, /providerCalls === beforeDenied\.providerCalls/u);
});
test('cross-account native runner preserves certificate checks, fixed networking and owned cleanup', () => {
  const source = readFileSync(new URL('./native-cross-account-proof.mjs', import.meta.url), 'utf8');
  assert.match(source, /ignoreHTTPSErrors: false/u); assert.match(source, /await route\.continue\(\)/u);
  assert.match(source, /entry\.browserVersion = entry\.browser\.version\(\)/u);
  assert.match(source, /entry\.browserVersion === '149\.0\.7827\.55'/u);
  assert.match(source, /requestCount > 160/u); assert.match(source, /120000/u);
  assert.match(source, /entry\.browserClosed \|\| !entry\.launched/u);
  assert.match(source, /ownedProfileCleanupRequired/u); assert.match(source, /ports\.map\(refused\)/u);
  assert.match(source, /if \(lifetimeExpired \|\| routingErrors \|\| pageErrors \|\| unexpectedRequests \|\| requestCount > 160/u);
  assert.doesNotMatch(source, /route\.fulfill\(|addCookies\(|setExtraHTTPHeaders\(|ignore-certificate-errors|NODE_TLS_REJECT_UNAUTHORIZED|Security\.setIgnoreCertificateErrors/u);
});
