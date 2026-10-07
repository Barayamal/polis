import assert from 'node:assert/strict';
import test from 'node:test';
import {mkdtemp, readFile, writeFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {rewriteSyntheticBootstrapBinding} from './rewrite-synthetic-bootstrap-binding.mjs';

test('fixed seed fixture contains fifteen nonempty unique statements', async () => {
  const seeds = JSON.parse(await readFile(new URL('./seed-statements.json', import.meta.url), 'utf8'));
  assert.equal(seeds.length, 15);
  assert.equal(new Set(seeds).size, 15);
  assert.ok(seeds.every(s => typeof s === 'string' && s.length > 0));
});

for (const [name, ids] of [
  ['absent', undefined], ['too few', [1]],
  ['duplicate', Array(15).fill(1)],
  ['negative', [-1, ...Array.from({length: 14}, (_, i) => i)]],
  ['fraction', [0.5, ...Array.from({length: 14}, (_, i) => i + 1)]],
  ['string', ['0', ...Array.from({length: 14}, (_, i) => i + 1)]],
]) {
  test(`bootstrap refuses ${name} manifest without changing environment`, async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fncp-fixed-seed-test-'));
    try {
      const envPath = join(dir, '.env.staging');
      const responsePath = join(dir, 'response.json');
      const initial = `FNCP_SYNTHETIC_BOOTSTRAP_COMPLETE=false\nFNCP_GATEWAY_CONVERSATION_ID=9fncpBootstrap${'a'.repeat(48)}\nFNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID=9fncpBootstrap${'a'.repeat(48)}\nFNCP_FIXED_STATEMENT_IDS=\n`;
      await writeFile(envPath, initial);
      await writeFile(responsePath, JSON.stringify({conversation_id: '4syntheticConversation2026', statement_ids: ids}));
      await assert.rejects(rewriteSyntheticBootstrapBinding(envPath, responsePath));
      assert.equal(await readFile(envPath, 'utf8'), initial);
    } finally {
      await rm(dir, {recursive: true});
    }
  });
}
