import assert from 'node:assert/strict';
import test from 'node:test';
import { validateOidcRelayRoute, validateTransportRelay } from './relay-route.mjs';
import { createTestIssuer } from './test-support/https-issuer.mjs';

const route = () => ({ profile: 'OIDC_FIXED_RELAY_V1', host: 'oidc-relay', tokenPort: 8445, jwksPort: 8446, policySha256: 'a'.repeat(64) });
test('production relay route has one fixed host, ports and policy binding; returns a copied frozen value', () => {
  const input = route(), out = validateOidcRelayRoute(input);
  input.host = 'attacker.invalid'; assert.equal(out.host, 'oidc-relay'); assert.ok(Object.isFrozen(out));
});
test('production route rejects unknown fields, getters, synthetic routes and every target override', () => {
  for (const value of [{ ...route(), host: 'attacker.invalid' }, { ...route(), tokenPort: 443 },
    { ...route(), jwksPort: 8445 }, { ...route(), policySha256: 'wrong' }, { ...route(), proxy: 'https://elsewhere.invalid' },
    { ...route(), profile: 'OIDC_SYNTHETIC_RELAY_V1' }, { ...route(), get host() { throw Error('getter invoked'); } }]) {
    assert.throws(() => validateOidcRelayRoute(value), { message: 'OIDC relay configuration rejected.' });
  }
});
test('named transport fixture cannot route a nonloopback identity provider', () => {
  const fixture = { profile: 'OIDC_SYNTHETIC_RELAY_V1', host: '127.0.0.1', tokenPort: 18445, jwksPort: 18446 };
  assert.ok(Object.isFrozen(validateTransportRelay(fixture, 'https://localhost/token', 'https://127.0.0.1/jwks')));
  assert.throws(() => validateTransportRelay(fixture, 'https://provider.example.invalid/token', 'https://127.0.0.1/jwks'));
  assert.throws(() => validateTransportRelay({ ...fixture, host: 'elsewhere.invalid' }, 'https://localhost/token', 'https://localhost/jwks'));
  let calls = 0;
  assert.throws(() => validateTransportRelay({ ...fixture, get profile() { calls++; return 'OIDC_SYNTHETIC_RELAY_V1'; } }, 'https://localhost/token', 'https://localhost/jwks'));
  assert.equal(calls, 0);
});
test('production identity cannot accept the named synthetic transport route', async t => {
  const h = await createTestIssuer(); t.after(() => h.close());
  assert.throws(() => h.createAdapter({ relay: { profile: 'OIDC_SYNTHETIC_RELAY_V1', host: '127.0.0.1', tokenPort: 18445, jwksPort: 18446 } }));
  assert.equal(h.calls.length, 0);
});
