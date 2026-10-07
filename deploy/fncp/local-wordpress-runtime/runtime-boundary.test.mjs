import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, copyFileSync, statSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

// Execute a copy against disposable fake WordPress source. Never inspect the
// prepared runtime, start a service, contact a database or send an event.
function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'fncp-wp-config-test-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const directory = join(root, 'local-wordpress-runtime');
  mkdirSync(join(directory, '.runtime', 'wordpress'), { recursive: true });
  mkdirSync(join(root, 'local-access', '.runtime'), { recursive: true });
  copyFileSync(new URL('./prepare.mjs', import.meta.url), join(directory, 'prepare.mjs'));
  writeFileSync(join(directory, '.runtime', 'wordpress', 'wp-settings.php'), '<?php // inert fixture');
  const secret = 'synthetic_configuration_test_key_'.repeat(3);
  writeFileSync(join(root, 'local-access', '.runtime', 'wordpress-secret.json'), JSON.stringify({ secret }));
  return { root, directory, secret,
    run: (mode = 'fixture-only') => spawnSync(process.execPath, [join(directory, 'prepare.mjs')], {
      encoding: 'utf8', env: { PATH: process.env.PATH, FNCP_LOCAL_SYNTHETIC_MODE: mode },
    }),
    path: (name) => join(directory, '.runtime', name),
  };
}

test('WordPress preparation refuses absent explicit fixture mode before generating private state', (t) => {
  const f = fixture(t); const result = f.run('');
  assert.notEqual(result.status, 0);
  assert.equal(existsSync(f.path('credentials.json')), false);
});

test('generated WordPress configuration is private and binds only the synthetic local services', (t) => {
  const f = fixture(t); const result = f.run(); assert.equal(result.status, 0);
  for (const name of ['credentials.json', 'db-password', 'root-password', 'wordpress/wp-config.php', 'wordpress/wp-content/mu-plugins/fncp-local-runtime.php']) {
    assert.equal(statSync(f.path(name)).mode & 0o777, 0o600);
  }
  const source = readFileSync(f.path('wordpress/wp-config.php'), 'utf8');
  for (const expected of ["'DB_NAME', 'fncp_wp_synthetic'", "'DB_HOST', '127.0.0.1:33079'",
    "'WP_SITEURL', 'http://127.0.0.1:8102'", "'WP_ENVIRONMENT_TYPE', 'local'", "'FNCP_WP_SYNTHETIC_ONLY', true",
    "'DISABLE_WP_CRON', true", "'DISALLOW_FILE_MODS', true", "'WP_HTTP_BLOCK_EXTERNAL', true"]) assert.ok(source.includes(expected));
  const privateValues = JSON.parse(readFileSync(f.path('credentials.json'), 'utf8'));
  for (const value of [f.secret, privateValues.dbPassword, privateValues.rootPassword, privateValues.adminPassword]) {
    assert.ok(!(result.stdout + result.stderr).includes(value));
  }
});

test('WordPress runtime suppresses mail and restricts HTTP to the exact signed receiver', (t) => {
  const f = fixture(t); assert.equal(f.run().status, 0);
  const source = readFileSync(f.path('wordpress/wp-content/mu-plugins/fncp-local-runtime.php'), 'utf8');
  assert.match(source, /add_filter\('pre_wp_mail', function \(\) \{ return false; \}, PHP_INT_MAX\)/u);
  assert.match(source, /\$url === 'http:\/\/127\.0\.0\.1:8101\/internal\/wordpress\/events'/u);
  assert.match(source, /return new WP_Error\('fncp_local_no_external_http'/u);
  assert.match(source, /add_filter\('get_avatar_url', function \(\) \{ return ''; \}\)/u);
});

test('repeated preparation preserves exact credentials and installed WordPress configuration', (t) => {
  const f = fixture(t); assert.equal(f.run().status, 0);
  const names = ['credentials.json', 'db-password', 'root-password', 'wordpress/wp-config.php'];
  const before = names.map((name) => readFileSync(f.path(name), 'utf8'));
  assert.equal(f.run().status, 0);
  assert.deepEqual(names.map((name) => readFileSync(f.path(name), 'utf8')), before);
});

test('WordPress configuration drift fails closed and preserves the divergent file', (t) => {
  const f = fixture(t); assert.equal(f.run().status, 0);
  const name = f.path('wordpress/wp-config.php');
  const changed = readFileSync(name, 'utf8').replace('127.0.0.1:33079', '127.0.0.1:33080');
  writeFileSync(name, changed);
  const result = f.run(); assert.notEqual(result.status, 0);
  assert.equal(readFileSync(name, 'utf8'), changed);
  assert.ok(!(result.stdout + result.stderr).includes(f.secret));
});

test('synthetic database secret-file drift fails without overwriting it', (t) => {
  const f = fixture(t); assert.equal(f.run().status, 0);
  writeFileSync(f.path('db-password'), 'different-invented-secret');
  assert.notEqual(f.run().status, 0);
  assert.equal(readFileSync(f.path('db-password'), 'utf8'), 'different-invented-secret');
});

test('malformed private configuration cannot leak its contents through errors', (t) => {
  const f = fixture(t);
  const sentinel = 'invented_private_parser_sentinel';
  writeFileSync(f.path('credentials.json'), `{"secret":"${sentinel}", broken`);
  const result = f.run(); assert.notEqual(result.status, 0);
  assert.ok(!(result.stdout + result.stderr).includes(sentinel));
  assert.match(result.stderr, /Local WordPress preparation failed/u);
});

test('malformed event secret and disabled local guard are rejected without disclosure or replacement', (t) => {
  const f = fixture(t); assert.equal(f.run().status, 0);
  const configPath = f.path('wordpress/wp-config.php');
  const changed = readFileSync(configPath, 'utf8').replace("'WP_HTTP_BLOCK_EXTERNAL', true", "'WP_HTTP_BLOCK_EXTERNAL', false");
  writeFileSync(configPath, changed); assert.notEqual(f.run().status, 0);
  assert.equal(readFileSync(configPath, 'utf8'), changed);
  const sentinel = 'invented_receiver_parser_sentinel';
  writeFileSync(join(f.root, 'local-access', '.runtime', 'wordpress-secret.json'), `{"secret":"${sentinel}", broken`);
  const result = f.run(); assert.notEqual(result.status, 0);
  assert.ok(!(result.stdout + result.stderr).includes(sentinel));
});
