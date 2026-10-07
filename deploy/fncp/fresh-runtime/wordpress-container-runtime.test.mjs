import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { validateContainerWordPressInput, containerWordPressTemplates, createFreshContainerWordPress } from './wordpress-container-runtime.mjs';

const input = () => ({ database: 'synthetic_new_001', user: 'synthetic_user_001', password: 'p'.repeat(48),
  eventSecret: 'e'.repeat(48), challengeSecret: 'c'.repeat(48), registrationSecret: 'r'.repeat(48) });
const templates = () => containerWordPressTemplates(input(), 'synthetic_admin_' + 'a'.repeat(20), 'b'.repeat(64));

test('fixed loopback database ports and independent private credentials', () => {
  assert.equal(validateContainerWordPressInput(input()).port, 3306);
  assert.equal(validateContainerWordPressInput({ ...input(), port: 33080 }).port, 33080);
  for (const port of [3307, '3306', 0, null]) assert.throws(() => validateContainerWordPressInput({ ...input(), port }));
  assert.throws(() => validateContainerWordPressInput({ ...input(), eventSecret: input().password }));
  assert.throws(() => validateContainerWordPressInput({ ...input(), database: 'other-db;DROP TABLE users' }));
  assert.throws(() => validateContainerWordPressInput({ ...input(), host: 'database.example.com' }));
});

test('input rejects proxies and accessors without invoking them', () => {
  let touched = 0; const value = input();
  Object.defineProperty(value, 'password', { get() { touched++; return 'secret'; }, enumerable: true });
  assert.throws(() => validateContainerWordPressInput(value));
  assert.throws(() => validateContainerWordPressInput(new Proxy(input(), { get() { touched++; } })));
  assert.equal(touched, 0);
});

test('fresh Linux runtime rejects wrong platform before filesystem access', { skip: process.platform === 'linux' && process.getuid?.() === 1000 }, async () => {
  await assert.rejects(createFreshContainerWordPress(input()), /platform failed/);
});

test('generated PHP configuration and lifecycle scripts parse with actual PHP', () => {
  const directory = mkdtempSync(join(tmpdir(), 'fncp-wordpress-container-template-'));
  try {
    const generated = templates();
    for (const field of ['config', 'muPlugin', 'installer', 'router']) {
      const path = join(directory, field + '.php'); writeFileSync(path, generated[field], { mode: 0o600 });
      execFileSync('php', ['-n', '-l', path], { stdio: 'pipe', timeout: 10_000 });
    }
    assert.deepEqual(JSON.parse(generated.credentials), { password: input().password,
      adminUsername: 'synthetic_admin_' + 'a'.repeat(20), adminPassword: 'b'.repeat(64) });
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('PHP router denies credential paths and nonlocal hosts', () => {
  const directory = mkdtempSync(join(tmpdir(), 'fncp-wordpress-router-check-'));
  try {
    // Execute the generated guard under CLI with its server-SAPI condition
    // explicitly removed; request inputs and the complete path regex are real.
    const router = templates().router.replace("PHP_SAPI !== 'cli-server' || ", '');
    for (const [host, path, status] of [
      ['127.0.0.1:8103', '/wp-login.php', 200], ['evil.invalid', '/wp-login.php', 403],
      ['127.0.0.1:8103', '/wp-config.php', 403], ['127.0.0.1:8103', '/secret.json', 403],
      ['127.0.0.1:8103', '/../wordpress-credentials.json', 403], ['127.0.0.1:8103', '/%2e%2e/secret', 403],
    ]) {
      const script = join(directory, 'router.php');
      writeFileSync(script, `<?php
http_response_code(200);
register_shutdown_function(function() { echo ' STATUS=' . http_response_code(); });
$_SERVER = ${phpArray(host, path)};
?>` + router, { mode: 0o600 });
      const output = execFileSync('php', ['-n', script], { encoding: 'utf8', timeout: 10_000,
        env: { PATH: process.env.PATH, FNCP_LOCAL_SYNTHETIC_MODE: 'fixture-only' } });
      assert.match(output, new RegExp('STATUS=' + status + '$'));
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

function phpArray(host, path) {
  const quote = value => "'" + value.replaceAll('\\', '\\\\').replaceAll("'", "\\'") + "'";
  return `['HTTP_HOST'=>${quote(host)}, 'REMOTE_ADDR'=>'127.0.0.1', 'REQUEST_URI'=>${quote(path)}]`;
}
