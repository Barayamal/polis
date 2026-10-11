import assert from 'node:assert/strict';
import test from 'node:test';
import { createProductionEgressPolicy, validateProductionEgressPolicy, isProductionEgressPolicy,
  isPublicNumericAddress } from './policy.mjs';
import { createFixedOidcRelay } from './relay.mjs';
import { createSyntheticEgressPolicy, createSyntheticFixedOidcRelay } from './test-support/synthetic-relay.mjs';

const input = () => ({ tokenEndpoint: 'https://identity.example.invalid/token',
  jwksUri: 'https://keys.example.invalid/jwks', targets: { token: '8.8.8.8', jwks: '2606:4700:4700::1111' } });
const denied = { message: 'OIDC egress policy rejected.' };
test('production policy freezes exact token/JWKS destinations and fixed ports with a reproducible hash', () => {
  const policy = createProductionEgressPolicy(input());
  assert.equal(policy.profile, 'FNCP_OIDC_FIXED_RELAY_V1');
  assert.equal(policy.routes.token.listenPort, 8445); assert.equal(policy.routes.jwks.listenPort, 8446);
  assert.equal(policy.routes.token.targetPort, 443); assert.equal(policy.routes.jwks.targetPort, 443);
  assert.match(policy.policySha256, /^[a-f0-9]{64}$/u);
  assert.ok(Object.isFrozen(policy) && Object.isFrozen(policy.routes.token));
  assert.equal(isProductionEgressPolicy(policy), true);
  const copied = JSON.parse(JSON.stringify(policy)); assert.equal(isProductionEgressPolicy(copied), false);
  assert.deepEqual(validateProductionEgressPolicy(copied), policy);
  const changed = input(); changed.targets.token = '1.1.1.1';
  assert.notEqual(createProductionEgressPolicy(changed).policySha256, policy.policySha256);
});
test('descriptor tampering, unknown fields and accessor inputs are rejected', () => {
  for (const change of [p => p.policySha256 = '0'.repeat(64), p => p.routes.token.targetPort = 80,
    p => p.routes.token.listenPort = 8000, p => p.routes.token.targetAddress = '127.0.0.1',
    p => p.routes.jwks.endpoint += '?a=1', p => p.routes.token.extra = true, p => p.extra = true]) {
    const p = JSON.parse(JSON.stringify(createProductionEgressPolicy(input()))); change(p);
    assert.throws(() => validateProductionEgressPolicy(p), denied);
  }
  const accessor = input(); Object.defineProperty(accessor, 'tokenEndpoint', { get() { throw new Error('Never invoke'); } });
  assert.throws(() => createProductionEgressPolicy(accessor), denied);
  assert.throws(() => createProductionEgressPolicy({ ...input(), fetch: () => {} }), denied);
  assert.throws(() => createProductionEgressPolicy(Object.assign(Object.create({}), input())), denied);
});
test('production numeric destination validation rejects DNS, aliases and special-purpose ranges', () => {
  for (const address of ['localhost', 'example.com', '8.8.8.8:443', '008.8.8.8', '0.1.2.3', '10.0.0.1',
    '100.64.0.1', '127.0.0.1', '169.254.169.254', '172.16.1.1', '172.31.255.255', '192.168.0.1',
    '192.0.0.1', '192.0.2.1', '192.88.99.1', '198.18.0.1', '198.51.100.1', '203.0.113.1',
    '224.0.0.1', '255.255.255.255', '::', '::1', '::ffff:8.8.8.8', 'fc00::1', 'fe80::1',
    'ff00::1', '2001:db8::1', '2001::1', '2002:808:808::1', '3fff::1', '2606:4700:4700::1111%eth0',
    '2606:4700:4700:0:0:0:0:1111', '2606:4700:4700::ABCD']) {
    assert.equal(isPublicNumericAddress(address), false, address);
    const c = input(); c.targets.token = address; assert.throws(() => createProductionEgressPolicy(c), denied, address);
  }
  for (const address of ['1.1.1.1', '8.8.8.8', '172.15.0.1', '172.32.0.1', '2606:4700:4700::1111']) {
    assert.equal(isPublicNumericAddress(address), true, address);
  }
});
test('endpoint validation denies HTTP, alternate ports, credentials, query, fragment and aliases', () => {
  for (const value of ['http://identity.example.invalid/token', 'https://identity.example.invalid:8443/token',
    'https://identity.example.invalid:443/token', 'https://user@identity.example.invalid/token',
    'https://identity.example.invalid/token?a=1', 'https://identity.example.invalid/token#x',
    'https://IDENTITY.example.invalid/token', 'https://identity.example.invalid/a/../token',
    'https://identity.example.invalid/token\n']) {
    const c = input(); c.tokenEndpoint = value; assert.throws(() => createProductionEgressPolicy(c), denied);
  }
  const c = input(); c.tokenEndpoint = c.jwksUri; assert.throws(() => createProductionEgressPolicy(c), denied);
});
test('production relay rejects wildcard/loopback bind addresses and copied/synthetic policies before start', () => {
  const p = createProductionEgressPolicy(input());
  for (const listenHost of ['0.0.0.0', '::', '127.0.0.1', '::1', '8.8.8.8', 'localhost']) {
    assert.throws(() => createFixedOidcRelay({ policy: p, listenHost }), { message: 'OIDC relay unavailable.' });
  }
  assert.throws(() => createFixedOidcRelay({ policy: JSON.parse(JSON.stringify(p)), listenHost: '172.30.0.2' }));
  const synthetic = createSyntheticEgressPolicy({ tokenEndpoint: 'https://localhost:1234/token',
    jwksUri: 'https://localhost:1234/jwks', targets: { token: { address: '127.0.0.1', port: 1234 }, jwks: { address: '127.0.0.1', port: 1234 } } });
  assert.throws(() => createFixedOidcRelay({ policy: synthetic, listenHost: '172.30.0.2' }));
  assert.throws(() => validateProductionEgressPolicy(synthetic), denied);
  assert.throws(() => createSyntheticFixedOidcRelay({ policy: p, listenHost: '127.0.0.1' }));
});
