import test from 'node:test';
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const source = fileURLToPath(new URL('./', import.meta.url));
const listen = (server, port = 0) => new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(port, '127.0.0.1', () => resolve(server.address().port));
});
const close = (server) => new Promise((resolve) => server.close(resolve));

test('partial receiver bind failure releases the API and exits without leaking credentials', { timeout: 10_000 }, async () => {
  // Copy only source into an isolated temporary fixture. Never read the real
  // .env.staging/.runtime, bind the real service ports, or call Pol.is.
  const directory = await mkdtemp(path.join(tmpdir(), 'fncp-startup-failure-'));
  const harness = path.join(directory, 'local-access');
  const occupied = createServer();
  let child;
  let exited;
  try {
    const occupiedPort = await listen(occupied);
    await mkdir(harness, { mode: 0o700 });
    for (const file of ['access-server.mjs', 'staging-config.mjs', 'wordpress-events.mjs', 'wordpress-receiver.mjs']) {
      await copyFile(path.join(source, file), path.join(harness, file));
    }
    const gatewaySecret = randomBytes(32).toString('base64url');
    const providerSecret = randomBytes(32).toString('base64url');
    await writeFile(path.join(directory, '.env.staging'), [
      'FNCP_SYNTHETIC_BOOTSTRAP_COMPLETE=true',
      'FNCP_GATEWAY_ENFORCEMENT=true',
      'FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT=true',
      'FNCP_GATEWAY_CONVERSATION_ID=7syntheticStartupFixture',
      'FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID=7syntheticStartupFixture',
      `FNCP_GATEWAY_SHARED_SECRET=${gatewaySecret}`,
      `FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL=${providerSecret}`,
    ].join('\n'), { mode: 0o600 });
    const original = await readFile(path.join(source, 'start.mjs'), 'utf8');
    assert.equal(original.split('await app.listen(8099)').length, 2);
    assert.equal(original.split('await receiver.listen(8101)').length, 2);
    // Only port allocation and a test-only IPC observation change. Startup,
    // configuration, database creation and failure cleanup are the actual source.
    const instrumented = original
      .replace('const address = await app.listen(8099);', 'const address = await app.listen(0); process.send({ apiAddress: address });')
      .replace('await receiver.listen(8101)', `await receiver.listen(${occupiedPort})`);
    await writeFile(path.join(harness, 'start.mjs'), instrumented, { mode: 0o600 });
    const networkGuard = path.join(directory, 'no-provider-fetch.mjs');
    await writeFile(networkGuard, 'globalThis.fetch = () => { throw new Error("Provider requests forbidden by startup fixture"); };\n', { mode: 0o600 });
    child = fork(path.join(harness, 'start.mjs'), [], {
      cwd: directory,
      env: { FNCP_LOCAL_SYNTHETIC_MODE: 'fixture-only' },
      execArgv: ['--import', networkGuard],
      silent: true,
    });
    exited = once(child, 'exit');
    let output = '';
    let apiAddress;
    child.stdout.on('data', (chunk) => { output += chunk.toString(); });
    child.stderr.on('data', (chunk) => { output += chunk.toString(); });
    child.on('message', (message) => { apiAddress = message.apiAddress; });
    let timer;
    try {
      const result = await Promise.race([
        exited,
        new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Failed startup left the child running')), 3000); }),
      ]);
      assert.deepEqual(result, [1, null]);
    } finally { clearTimeout(timer); }
    assert.match(apiAddress, /^http:\/\/127\.0\.0\.1:\d+$/u);
    assert.match(output, /Local access proof could not start/u);
    assert.doesNotMatch(output, /SYNTHETIC-ONLY API running/u);
    const { adminSecret } = JSON.parse(await readFile(path.join(harness, '.runtime/admin.json'), 'utf8'));
    const { secret: eventSecret } = JSON.parse(await readFile(path.join(harness, '.runtime/wordpress-secret.json'), 'utf8'));
    for (const secret of [gatewaySecret, providerSecret, adminSecret, eventSecret]) assert.ok(!output.includes(secret));
    const rebound = createServer();
    try { await listen(rebound, Number(new URL(apiAddress).port)); }
    finally { await close(rebound); }
  } finally {
    if (child && child.exitCode === null && child.signalCode === null) {
      child.kill('SIGKILL');
      await exited;
    }
    await close(occupied);
    await rm(directory, { recursive: true, force: true });
  }
});
