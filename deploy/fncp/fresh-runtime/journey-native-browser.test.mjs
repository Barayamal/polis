import test from 'node:test';
import assert from 'node:assert/strict';
import { nativeJourneyRequestAllowed, exerciseNativeWordPressJourney } from './journey-native-browser.mjs';
const origin = 'http://127.0.0.1:8100';

test('native browser permits only fixed observed UI requests', () => {
  for (const [path, method] of [['/', 'GET'], ['/app.js', 'GET'], ['/style.css', 'GET'],
    ['/api/oidc/start', 'POST'], ['/api/oidc/callback', 'POST'], ['/api/registration', 'POST'],
    ['/api/redeem', 'POST'], ['/api/participation-init', 'GET'], ['/api/next-comment', 'GET'], ['/api/votes', 'POST']]) {
    assert.equal(nativeJourneyRequestAllowed(origin, origin + path, method), true);
    assert.equal(nativeJourneyRequestAllowed(origin, origin + path, method === 'POST' ? 'GET' : 'POST'), false);
  }
});

test('native routing blocks unrelated loopback services, external targets and admin routes', () => {
  for (const target of ['https://identity.example.invalid/authorize', 'http://127.0.0.1:8103/',
    'http://127.0.0.1:5500/api/v3/votes', 'http://localhost:8100/', origin + '/test-admin/status',
    origin + '/api/login', origin + '/api/registration?identity=synthetic', origin + '/#invite=secret',
    'http://user:password@127.0.0.1:8100/', 'file:///etc/passwd', 'data:text/plain,test']) {
    assert.equal(nativeJourneyRequestAllowed(origin, target, 'GET'), false);
    assert.equal(nativeJourneyRequestAllowed(origin, target, 'POST'), false);
  }
  assert.equal(nativeJourneyRequestAllowed('http://127.0.0.1:8102', 'http://127.0.0.1:8102/', 'GET'), false);
});

test('native container runner rejects wrong host before loading browser dependencies', {
  skip: process.platform === 'linux' && process.getuid?.() === 1000,
}, async () => {
  await assert.rejects(exerciseNativeWordPressJourney({ origin, injectLogin() {}, operator: { decide() {} },
    setRoundOpen() {}, issueInvitation() {} }), /PLATFORM/);
});
