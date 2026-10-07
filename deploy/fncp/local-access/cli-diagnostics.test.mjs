/** Copied-source subprocess checks. Invented private files only; fetch is stubbed. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, copyFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const syntheticAdmin = 'SYNTHETIC_PRIVATE_ADMIN_SENTINEL_'.repeat(3);
const fixtureSecret = 'SYNTHETIC_PRIVATE_FIXTURE_SENTINEL_'.repeat(3);
const responseSentinel = 'SYNTHETIC_PRIVATE_RESPONSE_SENTINEL_'.repeat(3);
const fixture = 'synthetic_diagnostics';

function harness(t, { admin = JSON.stringify({ adminSecret: syntheticAdmin }), credential } = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'fncp-cli-diagnostics-'));
  t.after(() => rmSync(directory, { recursive: true }));
  for (const file of ['capture-mail.mjs', 'round-control.mjs', 'wordpress-events.mjs']) {
    copyFileSync(new URL(file, import.meta.url), join(directory, file));
  }
  const runtime = join(directory, '.runtime'); const mailbox = join(runtime, 'captured-mail');
  mkdirSync(mailbox, { recursive: true, mode: 0o700 });
  writeFileSync(join(runtime, 'admin.json'), admin, { mode: 0o600 });
  const fixtureFile = join(mailbox, fixture + '.json');
  if (credential !== undefined) writeFileSync(fixtureFile, credential, { mode: 0o600 });
  const called = join(directory, 'fetch-called');
  const preload = join(directory, 'deny-real-network.mjs');
  // No socket is opened. A child observes malformed JSON as though a local
  // service returned it, without contacting 8099 or any running application.
  writeFileSync(preload, `import {writeFileSync} from 'node:fs';
globalThis.fetch = async (url, options) => {
  if (!['http://127.0.0.1:8099/test-admin/fixtures', 'http://127.0.0.1:8099/test-admin/invitations',
    'http://127.0.0.1:8099/test-admin/status', 'http://127.0.0.1:8099/test-admin/round'].includes(url) ||
    options.redirect !== 'error') throw new Error('Unexpected fixture transport.');
  writeFileSync(${JSON.stringify(called)}, 'stubbed only', {mode:0o600});
  return new Response(${JSON.stringify(responseSentinel)}, {status:200, headers:{'Content-Type':'application/json'}});
};
`, { mode: 0o600 });
  const run = (script, args) => spawnSync(process.execPath, ['--import', preload, join(directory, script), ...args], {
    cwd: directory, encoding: 'utf8', timeout: 5000,
    env: { ...process.env, FNCP_LOCAL_SYNTHETIC_MODE: 'fixture-only' },
  });
  return { run, called, fixtureFile };
}

function redacted(result) {
  assert.equal(result.status, 1, 'uncertain operation must exit nonzero');
  assert.equal(result.signal, null);
  const output = result.stdout + result.stderr;
  for (const sentinel of [syntheticAdmin, fixtureSecret, responseSentinel, 'SYNTHETIC_PRIVATE_', 'SyntaxError', 'JSON.parse', 'at file:']) {
    assert.equal(output.includes(sentinel), false, 'diagnostic must not include an input excerpt or stack');
  }
  assert.match(result.stderr, /could not be confirmed/u);
  assert.match(result.stderr, /No credentials/u);
  assert.equal(result.stdout, '');
}

test('capture CLI malformed administrator JSON is redacted before any transport', (t) => {
  const h = harness(t, { admin: syntheticAdmin });
  redacted(h.run('capture-mail.mjs', ['register', fixture]));
  assert.equal(existsSync(h.called), false); assert.equal(existsSync(h.fixtureFile), false);
});

test('capture CLI malformed private fixture JSON is redacted and preserved without transport', (t) => {
  const h = harness(t, { credential: fixtureSecret });
  redacted(h.run('capture-mail.mjs', ['capture-invitation', fixture]));
  assert.equal(existsSync(h.called), false);
  assert.equal(readFileSync(h.fixtureFile, 'utf8'), fixtureSecret);
});

test('capture CLI malformed response is redacted and does not overwrite the private fixture file', (t) => {
  const credential = JSON.stringify({ mode: 'SYNTHETIC_ONLY', fixture, fixtureSecret });
  const h = harness(t, { credential });
  redacted(h.run('capture-mail.mjs', ['capture-invitation', fixture]));
  assert.equal(existsSync(h.called), true);
  assert.equal(readFileSync(h.fixtureFile, 'utf8'), credential);
});

test('round CLI malformed administrator JSON is redacted before any transport', (t) => {
  const h = harness(t, { admin: syntheticAdmin });
  redacted(h.run('round-control.mjs', ['status']));
  assert.equal(existsSync(h.called), false);
});

test('round CLI malformed response is redacted without contacting the real local service', (t) => {
  const h = harness(t);
  redacted(h.run('round-control.mjs', ['status']));
  assert.equal(existsSync(h.called), true);
});
