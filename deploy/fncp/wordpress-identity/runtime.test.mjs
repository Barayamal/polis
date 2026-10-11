/** Preparation/model boundaries only: no Docker, PHP server, database or WP install. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, stat, rm, access, symlink, link, realpath } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const exec = promisify(execFile);
const expectedArchiveHash = '05a5f89138f632b7329f1202f2a0553c5f7fe4daf8e4b9ca7ebae9b9466b9e86';
const values = { eventSecret: 'synthetic_event_'.repeat(4), challengeSecret: 'synthetic_challenge_'.repeat(4),
  registrationSecret: 'synthetic_registration_'.repeat(4) };
const exists = async path => { try { await access(path); return true; } catch { return false; } };
const denied = error => /^Synthetic WordPress identity [A-Za-z ]+ failed; private new state preserved\.$/u.test(error.message);

async function fixture(t) {
  const directory = await realpath(await mkdtemp(join(tmpdir(), 'fncp-identity-runtime-model-')));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const priorMode = process.env.FNCP_LOCAL_SYNTHETIC_MODE;
  process.env.FNCP_LOCAL_SYNTHETIC_MODE = 'fixture-only';
  t.after(() => { if (priorMode === undefined) delete process.env.FNCP_LOCAL_SYNTHETIC_MODE; else process.env.FNCP_LOCAL_SYNTHETIC_MODE = priorMode; });
  const root = join(directory, 'wordpress-identity'); const source = join(directory, 'inert-source');
  const oldRuntime = join(directory, 'local-wordpress-runtime', '.runtime');
  await mkdir(root); await mkdir(oldRuntime, { recursive: true });
  await mkdir(join(source, 'wordpress', 'wp-includes'), { recursive: true });
  await mkdir(join(source, 'wordpress', 'wp-content', 'uploads'), { recursive: true });
  for (const file of ['wp-load.php', 'wp-settings.php', 'wp-includes/version.php']) {
    await writeFile(join(source, 'wordpress', file), '<?php // Inert invented source. No WordPress install.\n');
  }
  const sentinel = 'synthetic_excluded_old_config_and_content';
  await writeFile(join(source, 'wordpress', 'wp-config.php'), sentinel);
  await writeFile(join(source, 'wordpress', 'wp-content', 'uploads', 'excluded.txt'), sentinel);
  const archivePath = join(oldRuntime, 'wordpress-7.1.tar.gz');
  await exec('tar', ['-czf', archivePath, '-C', source, 'wordpress']);
  const fakeHash = createHash('sha256').update(await readFile(archivePath)).digest('hex');
  const originalSource = await readFile(new URL('./runtime.mjs', import.meta.url), 'utf8');
  assert.equal(originalSource.split(expectedArchiveHash).length, 2);
  // Only this copied test module trusts its inert, newly created archive. The
  // actual module's pinned source hash is never changed or bypassed.
  await writeFile(join(root, 'runtime.mjs'), originalSource.replace(expectedArchiveHash, fakeHash));
  const pristineSource = await readFile(new URL('./pristine-source.mjs', import.meta.url), 'utf8');
  assert.equal(pristineSource.split(expectedArchiveHash).length, 2);
  await writeFile(join(root, 'pristine-source.mjs'), pristineSource.replace(expectedArchiveHash, fakeHash));
  const pristine = await import(pathToFileURL(join(root, 'pristine-source.mjs')).href);
  const bytes = await readFile(archivePath);
  const modelSource = pristine.createPristineWordPressSource(Uint8Array.from(bytes).buffer);
  const module = await import(pathToFileURL(join(root, 'runtime.mjs')).href);
  return { directory, root, archivePath, originalSource, module, modelSource, sentinel,
    prepareFresh: () => module.prepareIdentityWordPressFromPristine({ source: modelSource, ...values }),
    prepare: input => module.prepareIdentityWordPress(input ?? values) };
}

test('preparation requires explicit local mode and exactly three distinct bounded signing secrets', async t => {
  const f = await fixture(t);
  process.env.FNCP_LOCAL_SYNTHETIC_MODE = '';
  await assert.rejects(f.prepare(), denied);
  process.env.FNCP_LOCAL_SYNTHETIC_MODE = 'fixture-only';
  for (const input of [null, [], {}, { ...values, target: 'https://invalid.example.test' },
    { ...values, eventSecret: "synthetic_private_'_parser_sentinel" },
    { ...values, eventSecret: values.challengeSecret }, { ...values, eventSecret: 'x'.repeat(513) }]) {
    await assert.rejects(f.module.prepareIdentityWordPress(input), denied);
  }
  assert.equal(await exists(join(f.root, '.runtime')), false);
});

test('fresh private preparation excludes source wp-config and wp-content and pins all local runtime boundaries', async t => {
  const f = await fixture(t); const instance = await f.prepare();
  assert.equal(Object.isFrozen(instance), true); assert.equal(instance.mode, 'SYNTHETIC_ONLY');
  assert.equal(instance.origin, 'http://127.0.0.1:8103');
  assert.equal(instance.directory.startsWith(join(f.root, '.runtime', 'run-')), true);
  assert.equal((await stat(instance.directory)).mode & 0o777, 0o700);
  assert.equal((await stat(join(f.root, '.runtime'))).mode & 0o777, 0o700);
  assert.equal(await exists(join(instance.wpPath, 'wp-content', 'uploads', 'excluded.txt')), false);
  const configPath = join(instance.wpPath, 'wp-config.php'); const config = await readFile(configPath, 'utf8');
  assert.equal(config.includes(f.sentinel), false);
  for (const entry of ["'DB_HOST', '127.0.0.1:33080'", "'WP_HOME', 'http://127.0.0.1:8103'",
    "'FNCP_WP_IDENTITY_ORIGIN', 'http://127.0.0.1:8103'", "'WP_ENVIRONMENT_TYPE', 'local'",
    "'FNCP_WP_SYNTHETIC_ONLY', true", "'FNCP_WP_IDENTITY_FRESH_INSTANCE', true", "'WP_HTTP_BLOCK_EXTERNAL', true",
    "'DISABLE_WP_CRON', true", "'DISALLOW_FILE_MODS', true", "'DISALLOW_FILE_EDIT', true"]) assert.ok(config.includes(entry));
  for (const [key, value] of Object.entries({ FNCP_WP_LOCAL_EVENT_SECRET: values.eventSecret,
    FNCP_WP_CHALLENGE_SECRET: values.challengeSecret, FNCP_BFF_REGISTRATION_SECRET: values.registrationSecret })) {
    assert.ok(config.includes(`define('${key}', '${value}')`));
  }
  for (const path of [configPath, instance.composePath, instance.installPath, instance.routerPath,
    join(instance.directory, 'credentials.json'), join(instance.directory, 'db-password'), join(instance.directory, 'root-password'),
    join(instance.wpPath, 'wp-content', 'mu-plugins', 'fncp-identity-runtime.php')]) assert.equal((await stat(path)).mode & 0o777, 0o600);
  assert.match(instance.adminUsername, /^synthetic_admin_[a-f0-9]{20}$/u);
  assert.match(instance.adminPassword, /^[a-f0-9]{64}$/u);
});

test('generated compose uses a digest-pinned cached image, random dedicated resources, loopback and private secret files', async t => {
  const f = await fixture(t); const a = await f.prepare(); const b = await f.prepare();
  for (const key of ['directory', 'database', 'project', 'container', 'volume', 'adminUsername', 'adminPassword']) assert.notEqual(a[key], b[key]);
  const config = JSON.parse(await readFile(a.composePath, 'utf8')); const db = config.services.db;
  assert.match(db.image, /^mysql:8\.4\.11@sha256:[a-f0-9]{64}$/u); assert.equal(db.pull_policy, 'never');
  assert.equal(db.container_name, a.container); assert.equal(config.name, a.project);
  assert.equal(db.environment.MYSQL_DATABASE, a.database);
  assert.deepEqual(db.ports, ['127.0.0.1:33080:3306']); assert.deepEqual(db.volumes, ['identity-db:/var/lib/mysql']);
  assert.equal(config.volumes['identity-db'].name, a.volume); assert.equal(db.restart, 'no');
  assert.equal(db.labels['org.barayamal.fncp.identity-run'], a.project);
  assert.equal(db.environment.MYSQL_PASSWORD_FILE, '/run/secrets/db-password');
  assert.equal(config.secrets['db-password'].file, join(a.directory, 'db-password'));
  const serialized = JSON.stringify(config);
  for (const value of Object.values(values)) assert.equal(serialized.includes(value), false);
  assert.equal(serialized.includes(a.adminPassword), false);
});

test('fresh MU plugin suppresses every wp_mail and all HTTP except exact no-redirect local event POST', async t => {
  const f = await fixture(t); const instance = await f.prepare();
  const mu = await readFile(join(instance.wpPath, 'wp-content', 'mu-plugins', 'fncp-identity-runtime.php'), 'utf8');
  assert.match(mu, /add_filter\('pre_wp_mail', function \(\) \{ return false; \}, PHP_INT_MAX\)/u);
  assert.ok(mu.includes("$url === 'http://127.0.0.1:8101/internal/wordpress/events'"));
  assert.ok(mu.includes("($args['method'] ?? '') === 'POST'"));
  assert.ok(mu.includes("($args['redirection'] ?? 0) === 0"));
  assert.ok(mu.includes("return new WP_Error('fncp_identity_no_external_http'"));
  assert.ok(mu.includes(join(f.root, 'fncp-wordpress-identity.php')));
  assert.equal(mu.includes('wordpress-local/fncp-wordpress-local.php'), false);
  const install = await readFile(instance.installPath, 'utf8');
  assert.ok(install.includes("'synthetic_admin@example.test'"));
  assert.ok(install.includes("update_option('users_can_register', '0')"));
  assert.ok(install.includes("update_option('blog_public', '0')"));
  assert.equal(install.includes(instance.adminPassword), false);
  const router = await readFile(instance.routerPath, 'utf8');
  assert.ok(router.includes("!== '127.0.0.1:8103'"));
  assert.ok(router.includes("!== '127.0.0.1'")); assert.ok(router.includes("header('Referrer-Policy: no-referrer')"));
});

test('generated PHP files parse without executing WordPress, installation, database or network code', async t => {
  const f = await fixture(t); const instance = await f.prepare();
  for (const path of [instance.installPath, instance.routerPath, join(instance.wpPath, 'wp-config.php'),
    join(instance.wpPath, 'wp-content', 'mu-plugins', 'fncp-identity-runtime.php')]) {
    // PHP -l parses only; even the inert fixture core is not executed.
    const result = await exec('php', ['-l', path], { timeout: 5000 });
    assert.equal(result.stderr, '');
    for (const value of [...Object.values(values), instance.adminPassword]) assert.equal(result.stdout.includes(value), false);
  }
});

test('archive hash mismatch and linked source fail before a new runtime can be created', async t => {
  const f = await fixture(t);
  await writeFile(f.archivePath, 'invented_changed_archive_private_sentinel');
  await assert.rejects(f.prepare(), denied);
  assert.equal(await exists(join(f.root, '.runtime')), false);
  await link(f.archivePath, join(f.directory, 'archive-alias'));
  await assert.rejects(f.prepare(), denied);
  assert.equal(await exists(join(f.root, '.runtime')), false);
});

test('a symlinked runtime root is rejected without writing into its target', async t => {
  const f = await fixture(t); const target = join(f.directory, 'other-private-directory'); await mkdir(target);
  await symlink(target, join(f.root, '.runtime'));
  await assert.rejects(f.prepare(), denied);
  assert.deepEqual(await import('node:fs/promises').then(fs => fs.readdir(target)), []);
});

test('unknown or copied instances cannot start, stop or run PHP and disclose only fixed failures', async t => {
  const f = await fixture(t); const instance = await f.prepare();
  for (const candidate of [null, {}, Object.freeze({ ...instance }), { directory: 'synthetic_private_path_sentinel' }]) {
    await assert.rejects(f.module.startIdentityWordPress(candidate), denied);
    await assert.rejects(f.module.stopIdentityWordPress(candidate), denied);
    await assert.rejects(f.module.stopIdentityWordPressApplication(candidate), denied);
    await assert.rejects(f.module.recoveryWordPressSource(candidate), denied);
    await assert.rejects(f.module.runIdentityPhp(candidate, instance.installPath), denied);
  }
});

test('application-only stop on a prepared instance preserves all state; an unstarted recovery source is never certified', async t => {
  const f = await fixture(t); const instance = await f.prepare();
  const before = await readFile(instance.composePath, 'utf8');
  assert.deepEqual(await f.module.stopIdentityWordPressApplication(instance), {
    applicationStopped: true, databaseUntouched: true, preserved: true, mode: 'SYNTHETIC_ONLY',
  });
  await assert.rejects(f.module.recoveryWordPressSource(instance), denied);
  assert.equal(await readFile(instance.composePath, 'utf8'), before);
  assert.equal(await exists(instance.wpLoadPath), true);
  const source = f.originalSource;
  assert.ok(source.includes("item.Config?.Labels?.['com.docker.compose.project'] !== state.project"));
  assert.ok(source.includes("item.Config?.Labels?.['com.docker.compose.service'] !== 'db'"));
  assert.ok(source.includes('cached[0].Id !== state.imageId'));
  assert.ok(source.includes('!state.started || !state.attempted || state.phpChild || !state.imageId'));
});

test('changed generated configuration fails before command execution and is preserved', async t => {
  const f = await fixture(t); const instance = await f.prepare();
  const path = instance.composePath; const changed = 'invented_private_configuration_drift_sentinel';
  await writeFile(path, changed);
  await assert.rejects(f.module.startIdentityWordPress(instance), denied);
  await assert.rejects(f.module.runIdentityPhp(instance, instance.installPath), denied);
  assert.equal(await readFile(path, 'utf8'), changed);
  assert.deepEqual(await f.module.stopIdentityWordPress(instance), { stopped: true, preserved: true, mode: 'SYNTHETIC_ONLY' });
  assert.equal(await exists(instance.directory), true);
});

test('PHP helper rejects scripts outside this source/new run, symlinks, other runs and oversized input before execution', async t => {
  const f = await fixture(t); const instance = await f.prepare(); const other = await f.prepare();
  const outside = join(f.directory, 'outside.php'); await writeFile(outside, '<?php exit(0);');
  const alias = join(f.root, 'alias.php'); await symlink(outside, alias);
  for (const path of [outside, alias, other.installPath, instance.composePath]) {
    await assert.rejects(f.module.runIdentityPhp(instance, path), denied);
  }
  await assert.rejects(f.module.runIdentityPhp(instance, instance.installPath, ['x'.repeat(65_537)]), denied);
  await assert.rejects(f.module.runIdentityPhp(instance, instance.installPath, [{ caller: 'arbitrary' }]), denied);
});

test('orchestration source has fixed context/no pulls, startup port guards, private stdin/output and non-destructive stop', async t => {
  const f = await fixture(t); const source = f.originalSource;
  assert.ok(source.includes("const CONTEXT = 'colima-fncp-c-20260913'"));
  assert.ok(source.includes('await requireFreePort(33080); await requireFreePort(8103)'));
  assert.ok(source.includes("'--no-build', '--pull', 'never'"));
  assert.ok(source.includes("['image', 'inspect', MYSQL_IMAGE]"));
  assert.ok(source.includes("['stop', '--time', '5', items[0].Id]"));
  assert.ok(source.includes('child.stdin.end(JSON.stringify(args))'));
  assert.ok(source.includes("stdio: 'ignore'"));
  assert.equal(/console\.(?:log|error|warn)|\bdown['", ]|down -v|\bcolima['", ]|docker['", ]+pull/u.test(source), false);
  assert.equal(/local-access\/\.runtime|readFile\([^\n]*wp-config/u.test(source), false);
  assert.equal(await readFile(new URL('./.gitignore', import.meta.url), 'utf8'), '.runtime/\n');
});

test('separate pristine preparation uses only branded model bytes with no fallback to the legacy archive', async t => {
  const f = await fixture(t);
  // This is the isolated, newly generated inert archive, never a retained path.
  await rm(f.archivePath);
  await assert.rejects(f.prepare(), denied);
  const instance = await f.prepareFresh();
  assert.equal(instance.mode, 'SYNTHETIC_ONLY');
  assert.equal(await exists(instance.wpLoadPath), true);
  assert.equal(await exists(f.archivePath), false);
  assert.equal((await stat(join(instance.directory, 'verified-wordpress.tar.gz'))).mode & 0o777, 0o600);
  assert.equal(await exists(join(instance.wpPath, 'wp-content', 'uploads', 'excluded.txt')), false);
  assert.deepEqual(await f.module.stopIdentityWordPress(instance), { stopped: true, preserved: true, mode: 'SYNTHETIC_ONLY' });
});

test('pristine preparation rejects missing or forged brand even when the legacy model archive is available', async t => {
  const f = await fixture(t);
  for (const source of [undefined, null, {}, { ...f.modelSource }, new Proxy(f.modelSource, {})]) {
    await assert.rejects(f.module.prepareIdentityWordPressFromPristine({ ...values, source }), denied);
  }
  await assert.rejects(f.module.prepareIdentityWordPressFromPristine(), denied);
  await assert.rejects(f.module.prepareIdentityWordPressFromPristine(values), denied);
  assert.equal(await exists(join(f.root, '.runtime')), false);
  assert.equal(await exists(f.archivePath), true);
});

test('pristine preparation rejects extra/symbol/accessor/proxy inputs before reading caller values', async t => {
  const f = await fixture(t); const input = { ...values, source: f.modelSource }; let invoked = 0;
  const accessor = { ...input }; Object.defineProperty(accessor, 'eventSecret', { get() { invoked++; throw Error('private'); } });
  const symbol = { ...input, [Symbol('private')]: 'private' };
  const proxy = new Proxy(input, { getPrototypeOf() { invoked++; throw Error('private'); }, ownKeys() { invoked++; throw Error('private'); } });
  const inherited = Object.assign(Object.create({ private: true }), input);
  for (const bad of [accessor, symbol, proxy, inherited, null, [], { ...input, hash: 'invented' }, { ...input, archivePath: f.archivePath }]) {
    await assert.rejects(f.module.prepareIdentityWordPressFromPristine(bad), denied);
  }
  await assert.rejects(f.module.prepareIdentityWordPressFromPristine(input, 'extra'), denied);
  assert.equal(invoked, 0);
  assert.equal(await exists(join(f.root, '.runtime')), false);
});

test('fresh-only archive and core drift are rejected before any runtime command; stop preserves new files', async t => {
  const f = await fixture(t);
  for (const changedPath of [instance => join(instance.directory, 'verified-wordpress.tar.gz'), instance => instance.wpLoadPath,
    instance => join(instance.wpPath, 'wp-includes', 'added.php')]) {
    const instance = await f.prepareFresh(); const path = changedPath(instance);
    await writeFile(path, 'inert_changed_source_never_executed');
    await assert.rejects(f.module.startIdentityWordPress(instance), denied);
    await assert.rejects(f.module.runIdentityPhp(instance, instance.installPath), denied);
    await assert.rejects(f.module.recoveryWordPressSource(instance), denied);
    assert.equal(await readFile(path, 'utf8'), 'inert_changed_source_never_executed');
    assert.deepEqual(await f.module.stopIdentityWordPress(instance), { stopped: true, preserved: true, mode: 'SYNTHETIC_ONLY' });
  }
});

test('fresh-only linked core file or directory is rejected before command execution without following it', async t => {
  const f = await fixture(t); const instance = await f.prepareFresh();
  const outside = join(f.directory, 'inert-outside-core'); await mkdir(outside);
  await symlink(outside, join(instance.wpPath, 'foreign-directory'));
  await assert.rejects(f.module.runIdentityPhp(instance, instance.installPath), denied);
  await rm(join(instance.wpPath, 'foreign-directory'));
  await link(instance.wpLoadPath, join(instance.wpPath, 'core-alias.php'));
  await assert.rejects(f.module.runIdentityPhp(instance, instance.installPath), denied);
  assert.deepEqual(await import('node:fs/promises').then(fs => fs.readdir(outside)), []);
});
