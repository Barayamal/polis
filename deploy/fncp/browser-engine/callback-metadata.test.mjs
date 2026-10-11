import test from 'node:test';
import assert from 'node:assert/strict';
import { createCallbackMetadataCollector as create } from './callback-metadata.mjs';

const origin = 'https://browser.example.invalid:34567';
const callbackUrl = origin + '/oidc/callback?code=never-retain-this-code&state=never-retain-this-state&iss=synthetic';
const secret = 'never-retain-this-cookie-value';
const request = (url, extra = {}) => ({ requestId: 'owned.1', request: { url }, ...extra });
const extra = headers => ({ requestId: 'owned.1', headers });
const response = flag => ({ requestId: 'owned.1', hasExtraInfo: flag });
const callbackHeaders = { 'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'document',
  Cookie: '__Host-fncp_oidc_tx=' + secret };
const expected = { site: 'cross-site', mode: 'navigate', dest: 'document', appCookiePresent: false, transactionCookiePresent: true };
const begin = request('https://identity.issuer.invalid:34568/authorize?state=synthetic');
const callback = flag => request(callbackUrl, { redirectResponse: {}, redirectHasExtraInfo: flag });
const landing = flag => request(origin + '/', { redirectResponse: {}, redirectHasExtraInfo: flag });
function apply(collector, events) { for (const [kind, event] of events) collector[kind](event); return collector.observations(); }
const completeEvents = () => [['request', request(callbackUrl)], ['extra', extra(callbackHeaders)], ['response', response(true)]];

test('collector constructor permits only the exact normalized invented HTTPS app origin', () => {
  for (const value of [undefined, null, {}, 'http://browser.example.invalid:34567', 'https://browser.example.invalid',
    'https://browser.example.invalid:443', 'https://browser.example.invalid:0', 'https://browser.example.invalid:034567',
    'https://browser.example.invalid:65536', 'https://example.com:34567', origin + '/', origin + '?a=1', origin + '#a']) {
    assert.throws(() => create(value), /Exact synthetic browser origin/u);
  }
  assert.throws(() => create(origin, {})); assert.ok(Object.isFrozen(create(origin)));
});

test('single callback evidence is withheld until final presence and headers are known', () => {
  const c = create(origin); c.request(request(callbackUrl));
  assert.equal(c.observations().complete, false);
  c.extra(extra(callbackHeaders)); assert.equal(c.observations().complete, false);
  c.response(response(true)); const observed = c.observations();
  assert.equal(observed.complete, true); assert.deepEqual(observed.callbacks, [expected]);
  assert.equal(observed.pendingEvents, 0); assert.equal(observed.callbackCount, 1);
  assert.ok(Object.isFrozen(observed) && Object.isFrozen(observed.callbacks) && Object.isFrozen(observed.callbacks[0]));
});

function interleavings(a, b) {
  if (!a.length) return [b]; if (!b.length) return [a];
  return [...interleavings(a.slice(1), b).map(rest => [a[0], ...rest]),
    ...interleavings(a, b.slice(1)).map(rest => [b[0], ...rest])];
}
test('all 35 order-preserving request/ExtraInfo interleavings correlate three redirect legs', () => {
  const requests = [['request', begin], ['request', callback(true)], ['request', landing(true)], ['response', response(true)]];
  const extras = [['extra', extra({ 'Sec-Fetch-Site': 'same-origin' })], ['extra', extra(callbackHeaders)],
    ['extra', extra({ Cookie: '__Host-fncp_browser=' + secret, 'Sec-Fetch-Site': 'same-origin' })]];
  const orders = interleavings(requests, extras); assert.equal(orders.length, 35);
  for (const events of orders) {
    const observed = apply(create(origin), events);
    assert.equal(observed.complete, true); assert.deepEqual(observed.callbacks, [expected]); assert.equal(observed.pendingEvents, 0);
  }
});

test('false ExtraInfo flags skip legs without consuming a later callback header record', () => {
  const c = create(origin);
  const observed = apply(c, [['extra', extra(callbackHeaders)], ['request', begin], ['request', callback(false)],
    ['request', landing(true)], ['response', response(false)]]);
  assert.equal(observed.complete, true); assert.deepEqual(observed.callbacks, [expected]); assert.equal(observed.pendingEvents, 0);
});

test('an error-only unrelated request does not fabricate or prevent completed callback evidence', () => {
  const c = create(origin); c.request({ requestId: 'negative.1', request: { url: 'https://wrong.example.invalid:34567/' } });
  assert.equal(c.observations().complete, false); const observed = apply(c, completeEvents());
  assert.equal(observed.complete, true); assert.equal(observed.pendingEvents, 1); assert.deepEqual(observed.callbacks, [expected]);
});

test('two completed callbacks retain separate immutable aggregate observations', () => {
  const c = create(origin); const first = apply(c, completeEvents());
  for (const [kind, event] of completeEvents()) c[kind]({ ...event, requestId: 'owned.2' });
  assert.equal(c.observations().callbackCount, 2); assert.equal(first.callbackCount, 1);
});

for (const [name, events] of [
  ['missing final flag', [['request', request(callbackUrl)], ['extra', extra(callbackHeaders)], ['response', { requestId: 'owned.1' }]]],
  ['missing redirect flag', [['request', begin], ['request', request(callbackUrl, { redirectResponse: {} })]]],
  ['nonboolean redirect flag', [['request', begin], ['request', callback('true')]]],
  ['nonboolean final flag', [['request', request(callbackUrl)], ['response', response('true')]]],
  ['missing ExtraInfo', [['request', request(callbackUrl)], ['response', response(true)]]],
  ['callback explicitly has no ExtraInfo', [['request', request(callbackUrl)], ['response', response(false)]]],
  ['surplus ExtraInfo', [['request', request(callbackUrl)], ['extra', extra(callbackHeaders)], ['extra', extra(callbackHeaders)], ['response', response(true)]]],
  ['duplicated completed ExtraInfo', [...completeEvents(), ['extra', extra(callbackHeaders)]]],
  ['duplicated final response', [...completeEvents(), ['response', response(true)]]],
  ['duplicated initial request', [['request', request(callbackUrl)], ['request', request(callbackUrl)]]],
  ['redirect arrives without preceding leg', [['request', callback(true)]]],
  ['response arrives without request', [['response', response(true)]]],
  ['new redirect after final response', [...completeEvents(), ['request', landing(true)]]],
  ['false flag with surplus headers', [['request', begin], ['extra', extra({})], ['request', callback(false)], ['extra', extra(callbackHeaders)], ['response', response(true)]]],
  ['missing header in middle of chain', [['request', begin], ['extra', extra({})], ['request', callback(true)], ['request', landing(true)], ['extra', extra({})], ['response', response(true)]]],
]) test(`incomplete or ambiguous evidence fails shut: ${name}`, () => {
  const c = create(origin); const observed = apply(c, events);
  assert.equal(observed.complete, false); assert.deepEqual(observed.callbacks, []);
  assert.ok(observed.pendingEvents <= 120);
});

test('malformed events latch failure without throwing into browser event handlers', () => {
  for (const event of [null, {}, { requestId: {} }, { requestId: 'x'.repeat(129) },
    request(origin + '/unknown/../oidc/callback'), request(origin + '/oidc/callback#fragment')]) {
    const c = create(origin); assert.doesNotThrow(() => c.request(event));
    apply(c, completeEvents()); assert.equal(c.observations().complete, false);
  }
});

test('raw URL, cookie values and other headers never enter returned observations', () => {
  const c = create(origin);
  apply(c, [['request', request(callbackUrl)], ['extra', extra({ ...callbackHeaders, Authorization: secret,
    Referer: callbackUrl, 'x-private': secret })], ['response', response(true)]]);
  const text = JSON.stringify(c.observations());
  for (const value of [origin, 'never-retain', callbackUrl, secret, 'Authorization', 'Referer']) assert.equal(text.includes(value), false);
  assert.deepEqual(c.observations().callbacks, [expected]);
});

test('cookie presence uses exact names, records observed Strict presence, and rejects ambiguous duplicates', () => {
  const c = create(origin);
  const headers = { ...callbackHeaders, Cookie: 'unrelated=value__Host-fncp_browser=' + secret + '; __Host-fncp_oidc_tx=' + secret };
  assert.deepEqual(apply(c, [['request', request(callbackUrl)], ['extra', extra(headers)], ['response', response(true)]]).callbacks, [expected]);
  const both = { ...callbackHeaders, Cookie: '__Host-fncp_browser=' + secret + '; __Host-fncp_oidc_tx=' + secret };
  assert.equal(apply(create(origin), [['request', request(callbackUrl)], ['extra', extra(both)], ['response', response(true)]]).callbacks[0].appCookiePresent, true);
  for (const invalid of [{ ...callbackHeaders, cookie: secret }, { ...callbackHeaders, Cookie: '__Host-fncp_oidc_tx=a; __Host-fncp_oidc_tx=b' }]) {
    assert.equal(apply(create(origin), [['request', request(callbackUrl)], ['extra', extra(invalid)], ['response', response(true)]]).complete, false);
  }
});

test('event and selected-header accessors are rejected without evaluation', () => {
  let calls = 0;
  const event = { requestId: 'owned.1', get request() { calls++; return { url: callbackUrl }; } };
  const c = create(origin); c.request(event); assert.equal(c.observations().complete, false);
  const headers = { get Cookie() { calls++; return secret; } };
  const d = create(origin); d.extra(extra(headers)); assert.equal(d.observations().complete, false); assert.equal(calls, 0);
});

test('pending evidence, request IDs and redirect-leg storage all have hard 120 limits', () => {
  const ids = create(origin);
  for (let i = 0; i < 121; i++) ids.extra({ requestId: 'owned.' + i, headers: {} });
  assert.equal(ids.observations().requestIds, 120); assert.equal(ids.observations().pendingEvents, 120);
  assert.equal(ids.observations().complete, false); assert.equal(ids.observations().rejectedEvents, 1);
  const headers = create(origin);
  for (let i = 0; i < 121; i++) headers.extra(extra({}));
  assert.equal(headers.observations().pendingEvents, 120); assert.equal(headers.observations().rejectedEvents, 1);
  const redirects = create(origin); redirects.request(begin);
  for (let i = 0; i < 120; i++) redirects.request(request(origin + '/', { redirectResponse: {}, redirectHasExtraInfo: false }));
  assert.equal(redirects.observations().requestEvents, 120); assert.equal(redirects.observations().rejectedEvents, 1);
  assert.ok(redirects.observations().pendingEvents <= 120);
});
