import test from 'node:test';
import assert from 'node:assert/strict';
import { dockerNetworkInternalArguments } from './install-closed.mjs';

test('network creation preserves the validated internal boundary exactly', () => {
  assert.deepEqual(dockerNetworkInternalArguments({ internal: true }), ['--internal']);
  assert.deepEqual(dockerNetworkInternalArguments({ internal: false }), []);
  for (const network of [{}, { internal: null }, { internal: 'false' }]) {
    assert.throws(() => dockerNetworkInternalArguments(network), /FNCP_CLOSED_INSTALL_REJECTED:NETWORK_DESCRIPTOR/u);
  }
});
