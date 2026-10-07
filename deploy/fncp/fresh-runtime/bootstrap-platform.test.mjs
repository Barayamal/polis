// Source-contract portability checks, NOT Linux executable/image tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

for (const name of ['bootstrap-issuer.mjs', 'bootstrap-jwks-service.mjs']) {
  test(`${name} selects fixed OpenSSL paths and rejects unsupported platforms`, async () => {
    const source = await readFile(new URL(name, import.meta.url), 'utf8');
    assert.match(source, /process\.platform === 'darwin' \? '\/opt\/homebrew\/bin\/openssl'/u);
    assert.match(source, /process\.platform === 'linux' \? '\/usr\/bin\/openssl' : undefined/u);
    assert.match(source, /if \(!executable\) throw failure\(\);/u);
    assert.match(source, /spawnSync\(executable,/u);
    assert.match(source, /env: \{ PATH: '\/usr\/bin:\/bin', LANG: 'C', LC_ALL: 'C', OPENSSL_CONF: '\/dev\/null' \}/u);
    assert.doesNotMatch(source, /env:\s*process\.env|\.\.\.process\.env/u);
  });
}
