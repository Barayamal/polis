import assert from 'node:assert/strict';
import test from 'node:test';
import { createOidcHttpsTransport } from './https-transport.mjs';
import { createTestIssuer } from './test-support/https-issuer.mjs';
import { createSyntheticEgressPolicy, createSyntheticFixedOidcRelay } from '../production-egress/test-support/synthetic-relay.mjs';

async function fixture(t, overrides = {}) {
  const h = await createTestIssuer(overrides); t.after(() => h.close());
  const target = { address: '127.0.0.1', port: Number(new URL(h.options.tokenEndpoint).port) };
  const policy = createSyntheticEgressPolicy({ tokenEndpoint: h.options.tokenEndpoint, jwksUri: h.options.jwksUri, targets: { token: target, jwks: target } });
  const relay = createSyntheticFixedOidcRelay({ policy, listenHost: '127.0.0.1' });
  t.after(() => relay.close()); const started = await relay.start();
  const route = { profile: 'OIDC_SYNTHETIC_RELAY_V1', host: '127.0.0.1', tokenPort: started.listeners.token.port, jwksPort: started.listeners.jwks.port };
  const transport = createOidcHttpsTransport({ tokenEndpoint: h.options.tokenEndpoint, jwksUri: h.options.jwksUri, ca: h.options.ca, relay: route });
  t.after(() => transport.close()); return { h, relay, transport, route };
}

test('opaque relay preserves provider TLS verification, original Host and SNI at different socket ports', async t => {
  const { h, relay, transport, route } = await fixture(t, { host: 'localhost' });
  assert.notEqual(route.jwksPort, Number(new URL(h.options.jwksUri).port));
  assert.equal((await (await transport.fetch(h.options.jwksUri)).json()).keys.length, 1);
  assert.equal(h.calls[0].host, new URL(h.options.jwksUri).host);
  assert.equal(h.calls[0].servername, 'localhost');
  assert.ok(relay.snapshot().accepted >= 1);
});
for (const [name, options] of [['wrong CA', { wrongCa: true }], ['wrong provider certificate name', { wrongHost: true }]]) {
  test(`relay does not bypass ${name}`, async t => {
    const { h, transport } = await fixture(t, options);
    await assert.rejects(transport.fetch(h.options.jwksUri), { message: 'OIDC transport unavailable.' });
    assert.equal(h.calls.length, 0);
  });
}
test('relay outage, redirect and arbitrary endpoint/header all fail with generic errors', async t => {
  const { h, relay, transport } = await fixture(t);
  await assert.rejects(transport.fetch(h.options.authorizationEndpoint));
  await assert.rejects(transport.fetch(h.options.jwksUri, { headers: { host: 'other.invalid' } }));
  assert.equal(h.calls.length, 0);
  h.setBehavior('redirect'); await assert.rejects(transport.fetch(h.options.jwksUri));
  assert.equal(h.calls.length, 1);
  await relay.close(); await assert.rejects(transport.fetch(h.options.jwksUri));
  assert.equal(h.calls.length, 1);
});
