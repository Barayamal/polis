/** Fresh local synthetic WordPress only. Importing this module starts nothing.
 * Returned instance details and PHP outputs are private: do not log/publish them.
 * Failures retain the new files/volume; stop removes no files, containers or data.
 */
import { readFile, writeFile, mkdir, mkdtemp, chmod, lstat, realpath, readdir } from 'node:fs/promises';
import { randomBytes, createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative, isAbsolute } from 'node:path';
import { spawn, execFile } from 'node:child_process';
import { promisify, types } from 'node:util';
import { createServer } from 'node:net';
import { readPristineWordPressBytes } from './pristine-source.mjs';

const exec = promisify(execFile);
const SOURCE_DIRECTORY = fileURLToPath(new URL('./', import.meta.url));
const RUNTIME_DIRECTORY = join(SOURCE_DIRECTORY, '.runtime');
const ARCHIVE_PATH = fileURLToPath(new URL('../local-wordpress-runtime/.runtime/wordpress-7.1.tar.gz', import.meta.url));
const ARCHIVE_SHA256 = '05a5f89138f632b7329f1202f2a0553c5f7fe4daf8e4b9ca7ebae9b9466b9e86';
const MYSQL_IMAGE = 'mysql:8.4.11@sha256:85b9bf2e29cf836ecb8c2a15a935d4ba0c606631dff1dd79531a11983c638f2a';
const CONTEXT = 'colima-fncp-c-20260913';
const ORIGIN = 'http://127.0.0.1:8103';
const EVENT_URL = 'http://127.0.0.1:8101/internal/wordpress/events';
const PURPOSE = 'synthetic-wordpress-identity-only';
const instances = new WeakMap();
const sha256 = value => createHash('sha256').update(value).digest('hex');
const secret = () => randomBytes(32).toString('hex');
const php = value => "'" + value.replaceAll('\\', '\\\\').replaceAll("'", "\\'") + "'";
const localEnvironment = () => ({ PATH: process.env.PATH ?? '/opt/homebrew/bin:/usr/bin:/bin',
  ...(process.env.HOME === undefined ? {} : { HOME: process.env.HOME }),
  FNCP_LOCAL_SYNTHETIC_MODE: 'fixture-only' });
const failure = operation => new Error(`Synthetic WordPress identity ${operation} failed; private new state preserved.`);
const requireMode = () => { if (process.env.FNCP_LOCAL_SYNTHETIC_MODE !== 'fixture-only') throw failure('mode check'); };
const contained = (parent, candidate) => { const suffix = relative(parent, candidate); return !!suffix && !suffix.startsWith('..') && !isAbsolute(suffix); };
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

async function privateWrite(path, content) {
  await writeFile(path, content, { flag: 'wx', mode: 0o600 });
}
async function regular(path) {
  const info = await lstat(path);
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1) throw failure('file boundary');
}
async function stateOf(instance) {
  const state = instances.get(instance);
  if (!state || await realpath(state.directory) !== state.directory ||
      await realpath(RUNTIME_DIRECTORY) !== dirname(state.directory)) throw failure('instance boundary');
  return state;
}
async function verifyGenerated(state) {
  for (const [path, expected] of state.hashes) {
    await regular(path);
    if (sha256(await readFile(path)) !== expected) throw failure('configuration integrity');
  }
  if (state.pristineTree) {
    const current = await pristineTree(state.wpPath);
    if (current.size !== state.pristineTree.size || [...current].some(([path, hash]) =>
      !state.pristineTree.has(path) || state.pristineTree.get(path) !== hash)) throw failure('source integrity');
  }
}
// Only walks the new owned extraction, never a retained source/runtime. Fresh
// preparations pin the entire resulting core/configuration tree before use.
async function pristineTree(root) {
  const manifest = new Map(); let totalBytes = 0;
  async function visit(path) {
    if (manifest.size >= 10_000) throw failure('source boundary');
    const info = await lstat(path);
    if (info.isSymbolicLink() || await realpath(path) !== path) throw failure('source boundary');
    if (info.isDirectory()) {
      manifest.set(path, null);
      for (const name of (await readdir(path)).sort()) await visit(join(path, name));
    } else {
      if (!info.isFile() || info.nlink !== 1 || !Number.isSafeInteger(info.size) || info.size < 0 ||
          (totalBytes += info.size) > 256 * 1024 * 1024) throw failure('source boundary');
      const bytes = await readFile(path);
      if (bytes.length !== info.size) throw failure('source integrity');
      manifest.set(path, sha256(bytes));
    }
  }
  await visit(root); return manifest;
}
async function docker(args, timeout = 30_000) {
  return exec('docker', ['--context', CONTEXT, ...args], {
    encoding: 'utf8', timeout, maxBuffer: 1024 * 1024, env: localEnvironment(),
  });
}
async function requireFreePort(port) {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen({ host: '127.0.0.1', port, exclusive: true }, resolve);
  });
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
}

function configuration(state, values) {
  const constants = {
    DB_NAME: state.database, DB_USER: state.databaseUser, DB_PASSWORD: values.dbPassword,
    DB_HOST: '127.0.0.1:33080', DB_CHARSET: 'utf8mb4', DB_COLLATE: '',
    WP_HOME: ORIGIN, WP_SITEURL: ORIGIN, WP_ENVIRONMENT_TYPE: 'local',
    FNCP_WP_IDENTITY_ORIGIN: ORIGIN, FNCP_WP_CHALLENGE_SECRET: values.challengeSecret,
    FNCP_BFF_REGISTRATION_SECRET: values.registrationSecret, FNCP_WP_LOCAL_EVENT_SECRET: values.eventSecret,
  };
  const guards = { FNCP_WP_SYNTHETIC_ONLY: true, FNCP_WP_IDENTITY_FRESH_INSTANCE: true,
    WP_DEBUG: false, WP_HTTP_BLOCK_EXTERNAL: true, DISABLE_WP_CRON: true,
    AUTOMATIC_UPDATER_DISABLED: true, DISALLOW_FILE_MODS: true, DISALLOW_FILE_EDIT: true, WP_AUTO_UPDATE_CORE: false };
  const salts = ['AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT'];
  return `<?php
// GENERATED PRIVATE. Fresh synthetic local proof; never a production config.
${Object.entries(constants).map(([key, value]) => `define('${key}', ${php(value)});`).join('\n')}
${Object.entries(guards).map(([key, value]) => `define('${key}', ${value ? 'true' : 'false'});`).join('\n')}
define('WP_ACCESSIBLE_HOSTS', '127.0.0.1');
$table_prefix = 'synthetic_';
${salts.map(key => `define('${key}', ${php(randomBytes(48).toString('hex'))});`).join('\n')}
if (!defined('ABSPATH')) define('ABSPATH', __DIR__ . '/');
require_once ABSPATH . 'wp-settings.php';
`;
}
function muPlugin() {
  return `<?php
if (wp_get_environment_type() !== 'local' || !defined('FNCP_WP_SYNTHETIC_ONLY') || FNCP_WP_SYNTHETIC_ONLY !== true ||
    !defined('FNCP_WP_IDENTITY_FRESH_INSTANCE') || FNCP_WP_IDENTITY_FRESH_INSTANCE !== true) exit;
add_filter('pre_wp_mail', function () { return false; }, PHP_INT_MAX);
add_filter('pre_http_request', function ($pre, $args, $url) {
    if ($url === '${EVENT_URL}' && ($args['method'] ?? '') === 'POST' && ($args['redirection'] ?? 0) === 0) return $pre;
    return new WP_Error('fncp_identity_no_external_http', 'External HTTP disabled in synthetic identity runtime.');
}, PHP_INT_MAX, 3);
add_filter('get_avatar_url', function () { return ''; });
require_once ${php(join(SOURCE_DIRECTORY, 'fncp-wordpress-identity.php'))};
`;
}
function router() {
  return `<?php
if (PHP_SAPI !== 'cli-server' || getenv('FNCP_LOCAL_SYNTHETIC_MODE') !== 'fixture-only' ||
    ($_SERVER['HTTP_HOST'] ?? '') !== '127.0.0.1:8103' || ($_SERVER['REMOTE_ADDR'] ?? '') !== '127.0.0.1') {
    http_response_code(403); exit('Local synthetic proof only.');
}
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; form-action 'self'");
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if (!is_string($path) || preg_match('/wp-config|\\.\\.|%|\\\\\\\\|\\.json|\\.sql|\\.zip|\\.gz/i', $path)) { http_response_code(403); exit; }
return false;
`;
}
function installer(state) {
  return `<?php
if (PHP_SAPI !== 'cli' || getenv('FNCP_LOCAL_SYNTHETIC_MODE') !== 'fixture-only') exit(1);
ini_set('display_errors', '0'); ini_set('log_errors', '0');
try {
    $private = json_decode(file_get_contents(${php(state.credentialsPath)}), true, 32, JSON_THROW_ON_ERROR);
    $connection = new mysqli('127.0.0.1', ${php(state.databaseUser)}, $private['dbPassword'], ${php(state.database)}, 33080);
    $connection->close();
    $_SERVER['HTTP_HOST'] = '127.0.0.1:8103'; $_SERVER['REQUEST_URI'] = '/'; $_SERVER['SERVER_PORT'] = '8103';
    define('WP_INSTALLING', true);
    require ${php(state.wpLoadPath)};
    if (DB_NAME !== ${php(state.database)} || DB_HOST !== '127.0.0.1:33080' || wp_get_environment_type() !== 'local' ||
        FNCP_WP_IDENTITY_FRESH_INSTANCE !== true || FNCP_WP_SYNTHETIC_ONLY !== true) exit(1);
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    if (is_blog_installed()) { echo "PRESERVED_SYNTHETIC_INSTANCE\\n"; exit(0); }
    $installed = wp_install('Community Pulse — synthetic identity proof', ${php(state.adminUsername)},
        'synthetic_admin@example.test', false, '', $private['adminPassword'], 'en_US');
    if (is_wp_error($installed)) exit(1);
    update_option('blog_public', '0'); update_option('users_can_register', '0');
    echo "INSTALLED_SYNTHETIC_INSTANCE\\n";
} catch (Throwable $error) { fwrite(STDERR, "Synthetic identity installation failed.\\n"); exit(1); }
`;
}
function compose(state) {
  const labels = { 'org.barayamal.fncp.purpose': PURPOSE, 'org.barayamal.fncp.identity-run': state.project };
  return JSON.stringify({ name: state.project, services: { db: {
    image: MYSQL_IMAGE, pull_policy: 'never', container_name: state.container, restart: 'no',
    environment: { MYSQL_DATABASE: state.database, MYSQL_USER: state.databaseUser,
      MYSQL_PASSWORD_FILE: '/run/secrets/db-password', MYSQL_ROOT_PASSWORD_FILE: '/run/secrets/root-password' },
    secrets: ['db-password', 'root-password'], ports: ['127.0.0.1:33080:3306'],
    volumes: ['identity-db:/var/lib/mysql'], networks: ['identity-loopback'], labels,
    healthcheck: { test: ['CMD', 'mysqladmin', 'ping', '-h', '127.0.0.1', '--silent'], interval: '2s', timeout: '2s', retries: 30 },
  } }, networks: { 'identity-loopback': { name: state.network, labels,
    driver_opts: { 'com.docker.network.bridge.enable_icc': 'false' } } },
  volumes: { 'identity-db': { name: state.volume, labels } },
  secrets: { 'db-password': { file: join(state.directory, 'db-password') },
    'root-password': { file: join(state.directory, 'root-password') } } }, null, 2);
}

/** Only the three independent synthetic signing secrets are accepted. */
export async function prepareIdentityWordPress(input) {
  try {
    requireMode();
    const keys = ['eventSecret', 'challengeSecret', 'registrationSecret'];
    if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).length !== 3 ||
        keys.some(key => !Object.hasOwn(input, key) || typeof input[key] !== 'string' || !/^[A-Za-z0-9_-]{32,512}$/u.test(input[key])) ||
        new Set(keys.map(key => input[key])).size !== 3) throw failure('input boundary');
    await regular(ARCHIVE_PATH);
    const archive = await readFile(ARCHIVE_PATH);
    return await prepareVerifiedArchive(input, archive, false);
  } catch { throw failure('preparation'); }
}

/** Separate fresh byte-source boundary. No omitted/forged source can select the
 * retained archive. This prepares local files only; it neither acquires a source
 * nor starts WordPress, PHP, Docker or a database.
 */
export async function prepareIdentityWordPressFromPristine(...args) {
  try {
    requireMode();
    const input = args[0]; const keys = ['source', 'eventSecret', 'challengeSecret', 'registrationSecret'];
    if (args.length !== 1 || !input || typeof input !== 'object' || types.isProxy(input) ||
        Object.getPrototypeOf(input) !== Object.prototype) throw failure('input boundary');
    const descriptors = Object.getOwnPropertyDescriptors(input); const ownKeys = Reflect.ownKeys(descriptors);
    if (ownKeys.length !== keys.length || ownKeys.some(key => typeof key !== 'string' || !keys.includes(key)) ||
        keys.some(key => !Object.hasOwn(descriptors, key) || !Object.hasOwn(descriptors[key], 'value'))) throw failure('input boundary');
    const secrets = Object.fromEntries(keys.slice(1).map(key => [key, descriptors[key].value]));
    if (Object.values(secrets).some(value => typeof value !== 'string' || !/^[A-Za-z0-9_-]{32,512}$/u.test(value)) ||
        new Set(Object.values(secrets)).size !== 3) throw failure('input boundary');
    const archive = readPristineWordPressBytes(descriptors.source.value);
    return await prepareVerifiedArchive(secrets, archive, true);
  } catch { throw failure('preparation'); }
}

async function prepareVerifiedArchive(input, archive, freshSource) {
  try {
    if (sha256(archive) !== ARCHIVE_SHA256) throw failure('source integrity');
    await mkdir(RUNTIME_DIRECTORY, { recursive: true, mode: 0o700 });
    if ((await lstat(RUNTIME_DIRECTORY)).isSymbolicLink() || await realpath(RUNTIME_DIRECTORY) !== RUNTIME_DIRECTORY) throw failure('runtime boundary');
    await chmod(RUNTIME_DIRECTORY, 0o700);
    const directory = await mkdtemp(join(RUNTIME_DIRECTORY, 'run-')); await chmod(directory, 0o700);
    const suffix = randomBytes(10).toString('hex');
    const state = { directory, project: 'fncp-wp-identity-' + suffix, container: 'fncp-wp-identity-db-' + suffix,
      volume: 'fncp-wp-identity-data-' + suffix, network: 'fncp-wp-identity-net-' + suffix,
      database: 'fncp_identity_' + suffix, databaseUser: 'fncpi_' + suffix, adminUsername: 'synthetic_admin_' + suffix,
      credentialsPath: join(directory, 'credentials.json'), composePath: join(directory, 'compose.json'),
      wpPath: join(directory, 'wordpress'), wpLoadPath: join(directory, 'wordpress', 'wp-load.php'),
      installPath: join(directory, 'install.php'), routerPath: join(directory, 'router.php'),
      hashes: new Map(), started: false, attempted: false, phpChild: undefined };
    const values = { ...input, dbPassword: secret(), rootPassword: secret(), adminPassword: secret() };
    const archiveCopy = join(directory, 'verified-wordpress.tar.gz'); await privateWrite(archiveCopy, archive);
    if (freshSource) {
      await regular(archiveCopy);
      if (sha256(await readFile(archiveCopy)) !== ARCHIVE_SHA256) throw failure('source integrity');
      state.hashes.set(archiveCopy, ARCHIVE_SHA256);
      const listing = await exec('tar', ['-tzf', archiveCopy],
        { timeout: 30_000, maxBuffer: 1024 * 1024, env: localEnvironment() });
      const names = listing.stdout.replace(/\n$/u, '').split('\n');
      // Directory entries may have exactly one trailing slash; normalize only
      // that final separator, never traversal/absolute/foreign paths.
      const normalized = names.map(name => name.endsWith('/') ? name.slice(0, -1) : name);
      if (names.length > 10_000 || normalized.some(name => !/^wordpress(?:\/[^\\\x00-\x20\x7f]+)*$/u.test(name) ||
          name.split('/').some(part => part === '.' || part === '..'))) throw failure('source boundary');
    }
    // Extract only the verified release's pristine core; never copy an installed
    // wp-config.php, wp-content plugin/configuration, uploads or database.
    await exec('tar', ['-xzf', archiveCopy, '-C', directory, '--exclude=wordpress/wp-content', '--exclude=wordpress/wp-config.php'],
      { timeout: 30_000, maxBuffer: 1024 * 1024, env: localEnvironment() });
    for (const name of ['wp-load.php', 'wp-settings.php', 'wp-includes/version.php']) await regular(join(state.wpPath, name));
    if (freshSource) await pristineTree(state.wpPath);
    await mkdir(join(state.wpPath, 'wp-content', 'mu-plugins'), { recursive: true, mode: 0o700 });
    const files = new Map([
      [state.credentialsPath, JSON.stringify({ mode: 'SYNTHETIC_ONLY', dbPassword: values.dbPassword, rootPassword: values.rootPassword,
        adminUsername: state.adminUsername, adminPassword: values.adminPassword })],
      [join(directory, 'db-password'), values.dbPassword], [join(directory, 'root-password'), values.rootPassword],
      [join(state.wpPath, 'wp-config.php'), configuration(state, values)],
      [join(state.wpPath, 'wp-content', 'mu-plugins', 'fncp-identity-runtime.php'), muPlugin()],
      [state.composePath, compose(state)], [state.installPath, installer(state)], [state.routerPath, router()],
    ]);
    for (const [path, value] of files) { await privateWrite(path, value); state.hashes.set(path, sha256(value)); }
    if (freshSource) state.pristineTree = await pristineTree(state.wpPath);
    const instance = Object.freeze({ mode: 'SYNTHETIC_ONLY', origin: ORIGIN, directory, composePath: state.composePath,
      wpLoadPath: state.wpLoadPath, wpPath: state.wpPath, installPath: state.installPath, routerPath: state.routerPath,
      project: state.project, container: state.container, volume: state.volume, database: state.database,
      adminUsername: state.adminUsername, adminPassword: values.adminPassword });
    instances.set(instance, state); return instance;
  } catch { throw failure('preparation'); }
}

/** Arguments travel on stdin as JSON, never as process arguments. Script must
 * read json_decode(stream_get_contents(STDIN), true). Output is private. */
export async function runIdentityPhp(instance, script, args = []) {
  try {
    requireMode(); const state = await stateOf(instance); await verifyGenerated(state);
    if (typeof script !== 'string' || !script.endsWith('.php') || !Array.isArray(args) || args.length > 32 ||
        args.some(value => typeof value !== 'string' || value.length > 65_536) || JSON.stringify(args).length > 131_072) throw failure('PHP input boundary');
    await regular(script); const exactPath = await realpath(script);
    if (exactPath !== script || (!contained(SOURCE_DIRECTORY, exactPath) && !contained(state.directory, exactPath)) ||
        (contained(RUNTIME_DIRECTORY, exactPath) && !contained(state.directory, exactPath))) throw failure('PHP path boundary');
    const result = await new Promise((resolve, reject) => {
      const child = spawn('php', ['-d', 'display_errors=0', '-d', 'log_errors=0', '-d', 'allow_url_fopen=0',
        '-d', 'sendmail_path=/usr/bin/false', exactPath], { cwd: state.directory, env: { ...localEnvironment(),
        FNCP_IDENTITY_WP_LOAD_PATH: state.wpLoadPath, FNCP_IDENTITY_RUNTIME_PATH: state.directory }, stdio: ['pipe', 'pipe', 'pipe'] });
      let stdout = ''; let stderr = ''; let size = 0;
      const timer = setTimeout(() => child.kill('SIGKILL'), 30_000);
      for (const [stream, collect] of [[child.stdout, text => { stdout += text; }], [child.stderr, text => { stderr += text; }]]) {
        stream.on('data', chunk => { size += chunk.length; if (size > 1024 * 1024) child.kill('SIGKILL'); else collect(chunk.toString()); });
      }
      child.once('error', reject);
      child.once('close', code => { clearTimeout(timer); if (code !== 0 || size > 1024 * 1024) reject(failure('PHP execution')); else resolve({ stdout, stderr }); });
      child.stdin.on('error', () => {}); child.stdin.end(JSON.stringify(args));
    });
    return result;
  } catch { throw failure('PHP execution'); }
}

export async function startIdentityWordPress(instance) {
  try {
    requireMode(); const state = await stateOf(instance); await verifyGenerated(state);
    if (state.started || state.phpChild) throw failure('already started');
    await requireFreePort(33080); await requireFreePort(8103);
    await regular(join(SOURCE_DIRECTORY, 'fncp-wordpress-identity.php'));
    const cached = JSON.parse((await docker(['image', 'inspect', MYSQL_IMAGE])).stdout);
    if (!Array.isArray(cached) || cached.length !== 1 || !/^sha256:[a-f0-9]{64}$/u.test(cached[0].Id)) throw failure('cached image');
    state.imageId = cached[0].Id;
    if (!state.attempted) {
      for (const args of [
        ['ps', '--all', '--filter', 'name=^/' + state.container + '$', '--format', '{{.ID}}'],
        ['volume', 'ls', '--filter', 'name=^' + state.volume + '$', '--format', '{{.Name}}'],
        ['network', 'ls', '--filter', 'name=^' + state.network + '$', '--format', '{{.Name}}'],
      ]) if ((await docker(args)).stdout.trim()) throw failure('fresh resource boundary');
    }
    // Mark the attempt before compose: an uncertain failure may have started a
    // container and must remain eligible for narrowly scoped stop/reconciliation.
    state.attempted = true;
    state.started = true;
    await docker(['compose', '-f', state.composePath, '--project-name', state.project, 'up', '-d', '--no-build', '--pull', 'never']);
    let ready = false;
    for (let attempt = 0; attempt < 60; attempt++) {
      const items = JSON.parse((await docker(['inspect', state.container])).stdout);
      const item = items[0];
      if (items.length !== 1 || item.Image !== state.imageId || item.Config?.Labels?.['org.barayamal.fncp.identity-run'] !== state.project ||
          item.Config?.Labels?.['org.barayamal.fncp.purpose'] !== PURPOSE ||
          JSON.stringify(item.HostConfig?.PortBindings) !== JSON.stringify({ '3306/tcp': [{ HostIp: '127.0.0.1', HostPort: '33080' }] }) ||
          !item.Mounts?.some(m => m.Type === 'volume' && m.Name === state.volume && m.Destination === '/var/lib/mysql')) throw failure('container boundary');
      if (item.State?.Health?.Status === 'healthy') { ready = true; break; }
      await pause(500);
    }
    if (!ready) throw failure('database readiness');
    await runIdentityPhp(instance, state.installPath);
    await requireFreePort(8103);
    state.phpChild = spawn('php', ['-d', 'display_errors=0', '-d', 'log_errors=0', '-d', 'allow_url_fopen=0',
      '-d', 'sendmail_path=/usr/bin/false', '-S', '127.0.0.1:8103', '-t', state.wpPath, state.routerPath],
    { cwd: state.directory, env: localEnvironment(), stdio: 'ignore' });
    state.phpChild.on('error', () => {});
    for (let attempt = 0; attempt < 30; attempt++) {
      if (state.phpChild.exitCode !== null || state.phpChild.signalCode !== null) throw failure('PHP listener');
      try {
        const response = await fetch(ORIGIN + '/wp-login.php', { redirect: 'manual', signal: AbortSignal.timeout(1000) });
        await response.body?.cancel();
        if (response.status === 200) return instance;
      } catch { /* fixed local readiness only */ }
      await pause(200);
    }
    throw failure('PHP readiness');
  } catch { throw failure('startup'); }
}

async function stopPhpChild(state) {
  const child = state.phpChild;
  if (!child) return;
  if (child.pid && child.exitCode === null && child.signalCode === null) await new Promise((resolve, reject) => {
    const timer = setTimeout(() => child.kill('SIGKILL'), 3000);
    const deadline = setTimeout(() => reject(failure('PHP shutdown timeout')), 5000);
    child.once('close', () => { clearTimeout(timer); clearTimeout(deadline); resolve(); }); child.kill('SIGTERM');
  });
  // An uncertain stop retains the exact child handle for later reconciliation.
  if (child.pid && child.exitCode === null && child.signalCode === null) throw failure('PHP shutdown verification');
  state.phpChild = undefined;
}

/** Negative operation only: stops this instance's tracked PHP process, not its
 * database. Other writer processes are the recovery coordinator's responsibility. */
export async function stopIdentityWordPressApplication(instance) {
  try {
    const state = await stateOf(instance); await stopPhpChild(state);
    return Object.freeze({ applicationStopped: true, databaseUntouched: true, preserved: true, mode: 'SYNTHETIC_ONLY' });
  } catch { throw failure('application shutdown'); }
}

/** Private source locator for coordinated recovery. This is not a backup or
 * quiescence certificate: the caller must separately enforce DB read-only mode
 * and stop every other writer. No credentials, hashes or signing keys returned. */
export async function recoveryWordPressSource(instance) {
  try {
    requireMode(); const state = await stateOf(instance); await verifyGenerated(state);
    if (!state.started || !state.attempted || state.phpChild || !state.imageId) throw failure('recovery source state');
    const cached = JSON.parse((await docker(['image', 'inspect', MYSQL_IMAGE])).stdout);
    if (!Array.isArray(cached) || cached.length !== 1 || cached[0].Id !== state.imageId) throw failure('recovery cached image');
    const items = JSON.parse((await docker(['inspect', state.container])).stdout); const item = items[0];
    if (items.length !== 1 || !/^[a-f0-9]{64}$/u.test(item.Id) || item.Name !== '/' + state.container || item.Image !== state.imageId ||
        item.Config?.Labels?.['org.barayamal.fncp.identity-run'] !== state.project ||
        item.Config?.Labels?.['org.barayamal.fncp.purpose'] !== PURPOSE ||
        item.Config?.Labels?.['com.docker.compose.project'] !== state.project || item.Config?.Labels?.['com.docker.compose.service'] !== 'db' ||
        item.State?.Running !== true || item.State?.Health?.Status !== 'healthy' ||
        !Array.isArray(item.Config?.Env) || !item.Config.Env.includes('MYSQL_DATABASE=' + state.database) ||
        !item.Config.Env.includes('MYSQL_USER=' + state.databaseUser) ||
        JSON.stringify(item.HostConfig?.PortBindings) !== JSON.stringify({ '3306/tcp': [{ HostIp: '127.0.0.1', HostPort: '33080' }] }) ||
        !Array.isArray(item.Mounts) || item.Mounts.filter(m => m.Type === 'volume').length !== 1 ||
        !item.Mounts.some(m => m.Type === 'volume' && m.Name === state.volume && m.Destination === '/var/lib/mysql')) throw failure('recovery source boundary');
    return Object.freeze({ directory: state.directory, composePath: state.composePath, containerId: item.Id,
      project: state.project, database: state.database, databaseUser: state.databaseUser, volume: state.volume });
  } catch { throw failure('recovery source verification'); }
}

export async function stopIdentityWordPress(instance) {
  try {
    const state = await stateOf(instance); let failed = false;
    try { await stopPhpChild(state); } catch { failed = true; }
    if (state.started) {
      try {
        const items = JSON.parse((await docker(['inspect', state.container])).stdout);
        if (items.length !== 1 || items[0].Config?.Labels?.['org.barayamal.fncp.identity-run'] !== state.project ||
            items[0].Config?.Labels?.['org.barayamal.fncp.purpose'] !== PURPOSE || !/^[a-f0-9]{64}$/u.test(items[0].Id)) throw failure('stop boundary');
        await docker(['stop', '--time', '5', items[0].Id]); state.started = false;
      } catch { failed = true; }
    }
    if (failed) throw failure('shutdown');
    return { stopped: true, preserved: true, mode: 'SYNTHETIC_ONLY' };
  } catch { throw failure('shutdown'); }
}
