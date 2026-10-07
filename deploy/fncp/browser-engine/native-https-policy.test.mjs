import assert from 'node:assert/strict';
import test from 'node:test';
import { nativeHttpsRequestAllowed as allowed, nativeCrossAccountRequestAllowed } from './native-https-policy.mjs';
const config = { appOrigin: 'https://browser.example.invalid:34567', issuerOrigin: 'https://identity.issuer.invalid:34568',
  untrustedOrigin: 'https://browser.example.invalid:34569', wrongHostOrigin: 'https://wrong.example.invalid:34567' };
test('two-account browser boundary admits only its exact application and issuer destinations', () => {
  assert.equal(nativeCrossAccountRequestAllowed(config, config.appOrigin + '/', 'GET'), true);
  assert.equal(nativeCrossAccountRequestAllowed(config, config.appOrigin + '/api/redeem', 'POST'), true);
  for (const raw of [config.untrustedOrigin + '/', config.wrongHostOrigin + '/', config.issuerOrigin + '/token',
    config.appOrigin + '/api/registration?x=1', config.appOrigin + '/#', 'https://example.com/',
    config.appOrigin + '/unknown/../', config.appOrigin.replace('://', '://user@') + '/', config.appOrigin + '/?']) {
    assert.equal(nativeCrossAccountRequestAllowed(config, raw, 'GET'), false);
  }
});
test('two-account browser policy rejects changed host contracts and ambiguous authorization inputs', () => {
  for (const invalid of [{ appOrigin: 'https://example.com:1234' }, { issuerOrigin: 'https://example.com:1234' },
    { appOrigin: config.appOrigin + '/' }, { issuerOrigin: 'https://identity.issuer.invalid' }]) {
    assert.equal(nativeCrossAccountRequestAllowed({ ...config, ...invalid }, config.appOrigin + '/', 'GET'), false);
  }
  const callback = config.appOrigin + '/oidc/callback?code=invented&iss=invented&state=invented';
  assert.equal(nativeCrossAccountRequestAllowed(config, callback, 'GET'), true);
  for (const suffix of ['&sub=invented', '&state=invented', '#', '&state=']) {
    assert.equal(nativeCrossAccountRequestAllowed(config, callback + suffix, 'GET'), false);
  }
  assert.equal(nativeCrossAccountRequestAllowed(config, callback, 'POST'), false);
});
test('native HTTPS test allowlist permits exact app requests and bounded TLS-negative roots', () => {
  for (const path of ['/', '/app.js', '/style.css', '/favicon.ico', '/api/session', '/api/participation-init', '/api/next-comment']) assert.equal(allowed(config, config.appOrigin + path, 'GET'), true);
  for (const path of ['/api/oidc/start', '/api/registration', '/api/redeem', '/api/logout', '/api/votes']) assert.equal(allowed(config, config.appOrigin + path, 'POST'), true);
  for (const origin of [config.untrustedOrigin, config.wrongHostOrigin]) assert.equal(allowed(config, origin + '/', 'GET'), true);
});
test('native HTTPS test allowlist rejects unapproved origins, methods, paths and URL ambiguity', () => {
  for (const raw of ['https://example.com/', 'http://127.0.0.1:34567/', config.appOrigin + '/api/session?x=1', config.appOrigin + '/#secret',
    config.appOrigin + '/unknown/../', config.appOrigin + '/api/oidc/callback', config.issuerOrigin + '/token', config.untrustedOrigin + '/app.js',
    config.wrongHostOrigin + '/api/session', config.appOrigin + '/?', config.appOrigin + '/#', config.appOrigin + '/' + 'x'.repeat(8192),
    config.appOrigin.replace(':34567', ':34570') + '/', config.appOrigin.replace('://', '://user@') + '/']) {
    assert.equal(allowed(config, raw, 'GET'), false);
  }
  for (const method of ['POST', 'TRACE', 'DELETE', 'HEAD']) assert.equal(allowed(config, config.appOrigin + '/', method), false);
});
test('native HTTPS policy rejects caller-selected external or overlapping origins', () => {
  for (const invalid of [
    { appOrigin: 'https://example.com:34567' }, { issuerOrigin: 'https://example.com:34568' },
    { untrustedOrigin: config.appOrigin }, { wrongHostOrigin: 'https://wrong.example.invalid:34570' },
    { appOrigin: config.appOrigin + '/' }, { issuerOrigin: 'https://identity.issuer.invalid' },
  ]) assert.equal(allowed({ ...config, ...invalid }, config.appOrigin + '/', 'GET'), false);
});
test('native HTTPS test allowlist allows exact redirect key sets but rejects duplicate and extra keys', () => {
  const callback = config.appOrigin + '/oidc/callback?code=invented&iss=invented&state=invented';
  const authorize = config.issuerOrigin + '/authorize?' + new URLSearchParams(Object.fromEntries(
    ['client_id', 'redirect_uri', 'response_type', 'response_mode', 'scope', 'code_challenge', 'code_challenge_method', 'state', 'nonce'].map(key => [key, 'invented'])));
  for (const raw of [callback, authorize]) {
    assert.equal(allowed(config, raw, 'GET'), true);
    assert.equal(allowed(config, raw + '&state=duplicate', 'GET'), false);
    assert.equal(allowed(config, raw + '&extra=1', 'GET'), false);
    assert.equal(allowed(config, raw, 'POST'), false);
  }
});
