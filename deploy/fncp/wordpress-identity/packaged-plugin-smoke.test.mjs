/** Actual PHP CLI loading from independently validated ZIP bytes; WordPress functions are inert stubs. */
import assert from 'node:assert/strict';
import test from 'node:test';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assembleWordPressBundle } from './package-check.mjs';
import { buildWordPressReviewBundle, validateWordPressReviewArchive } from './review-bundle.mjs';

const helper = fileURLToPath(new URL('./packaged-plugin-smoke.php', import.meta.url));
const modes = ['disabled-default', 'synthetic-false', 'fresh-false', 'nonlocal-environment',
  'external-origin', 'https-origin', 'missing-secret', 'duplicate-secret', 'malformed-secret',
  'legacy-plugin', 'enabled-local', 'wrong-method', 'wrong-host', 'wrong-remote',
  'wrong-origin', 'authorization-header', 'file-upload', 'wrong-content-type', 'cross-site', 'oversized-body'];

for (const [index, mode] of modes.entries()) test(`packaged PHP bootstrap: ${mode} preserves its gate without storage/network`, () => {
  const { archive } = buildWordPressReviewBundle(assembleWordPressBundle());
  const { files } = validateWordPressReviewArchive(archive);
  const root = mkdtempSync(join(realpathSync(tmpdir()), 'fncp-packaged-smoke-'));
  try {
    assert.equal(files.size, 5);
    for (const [path, source] of files) {
      assert.match(path, /^(wordpress-identity|wordpress-local)\/[a-z-]+\.php$/u);
      const output = join(root, path);
      mkdirSync(dirname(output), { recursive: true, mode: 0o700 });
      writeFileSync(output, source, { flag: 'wx', mode: 0o600 });
    }
    const stdout = execFileSync('php', ['-d', 'auto_prepend_file=', '-d', 'auto_append_file=', helper, root, mode], { encoding: 'utf8', timeout: 5000,
      maxBuffer: 4096, stdio: ['ignore', 'pipe', 'pipe'] });
    const expected = index < 10 ? 503 : mode === 'enabled-local' ? 200
      : mode === 'wrong-content-type' ? 415 : mode === 'oversized-body' ? 413 : 403;
    assert.deepEqual(JSON.parse(stdout), { ok: true, mode: 'SYNTHETIC_ONLY', classesLoaded: 4,
      hooksRegistered: 11, httpGateStatus: expected, adminGateStatus: expected === 200 ? 403 : expected,
      networkCalls: 0, storageCalls: 0, wordpressInstalled: false, productionReady: false });
  } finally { rmSync(root, { recursive: true, force: false }); }
});
