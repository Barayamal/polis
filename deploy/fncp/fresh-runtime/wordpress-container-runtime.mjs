/** Actual fresh synthetic WordPress inside the owned Linux API namespace.
 * No Docker, download, retained archive or existing database adoption. The caller
 * owns MySQL and the surrounding container. Returned operator/recovery values
 * are private capabilities and must never be logged or included in evidence.
 */
import { chmod, copyFile, lstat, mkdir, readdir, realpath, writeFile } from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { join } from 'node:path';
import { types } from 'node:util';

const ROOT = '/run/fncp/journey';
const WP = ROOT + '/wordpress';
const SOURCE = '/opt/fncp/wordpress';
const PHP = '/usr/bin/php84';
const PLUGIN = '/opt/fncp/deploy/fncp/wordpress-identity/fncp-wordpress-identity.php';
const OPERATOR = '/opt/fncp/deploy/fncp/wordpress-identity/operator-proof.php';
const ORIGIN = 'http://127.0.0.1:8103';
const EVENT = 'http://127.0.0.1:8101/internal/wordpress/events';
const ENV = Object.freeze({ PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', TZ: 'UTC',
  FNCP_LOCAL_SYNTHETIC_MODE: 'fixture-only', FNCP_IDENTITY_WP_LOAD_PATH: WP + '/wp-load.php',
  FNCP_IDENTITY_RUNTIME_PATH: ROOT });
const PHP_FLAGS = Object.freeze(['-d', 'display_errors=0', '-d', 'log_errors=0',
  '-d', 'allow_url_fopen=0', '-d', 'sendmail_path=/bin/false']);
const fail = stage => new Error(`Fresh container WordPress ${stage} failed; private state preserved.`);
const quote = value => "'" + value.replaceAll('\\', '\\\\').replaceAll("'", "\\'") + "'";
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

/** Validate private input without invoking getters or accepting endpoint paths. */
export function validateContainerWordPressInput(input) {
  if (!input || typeof input !== 'object' || types.isProxy(input) ||
      Object.getPrototypeOf(input) !== Object.prototype) throw fail('input');
  const required = ['database', 'user', 'password', 'eventSecret', 'challengeSecret', 'registrationSecret'];
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.some(key => typeof key !== 'string' || ![...required, 'port'].includes(key)) ||
      required.some(key => !Object.hasOwn(descriptors, key)) ||
      keys.some(key => !Object.hasOwn(descriptors[key], 'value'))) throw fail('input');
  const value = Object.fromEntries(keys.map(key => [key, descriptors[key].value]));
  if (typeof value.database !== 'string' || !/^[a-z][a-z0-9_]{0,63}$/u.test(value.database) ||
      typeof value.user !== 'string' || !/^[a-z][a-z0-9_]{0,31}$/u.test(value.user) ||
      required.slice(2).some(key => typeof value[key] !== 'string' || !/^[A-Za-z0-9_-]{32,512}$/u.test(value[key])) ||
      new Set(required.slice(2).map(key => value[key])).size !== 4 ||
      (value.port !== undefined && value.port !== 3306 && value.port !== 33080)) throw fail('input');
  return Object.freeze({ ...value, port: value.port ?? 3306 });
}

async function privateWrite(path, text) {
  await writeFile(path, text, { flag: 'wx', mode: 0o600 });
}
async function directory(path, uid) {
  const stat = await lstat(path);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== uid ||
      (stat.mode & 0o022) || await realpath(path) !== path) throw fail('directory');
}
async function regularSource(path) {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== 0 || stat.nlink !== 1 ||
      (stat.mode & 0o022) || await realpath(path) !== path) throw fail('source');
  return stat;
}
async function freePort() {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject); server.listen({ host: '127.0.0.1', port: 8103, exclusive: true }, resolve);
  });
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
}
async function copyPristineCore() {
  let files = 0; let bytes = 0;
  async function copy(from, to, top = false) {
    await directory(from, 0);
    await mkdir(to, { mode: 0o700 });
    for (const name of (await readdir(from)).sort()) {
      if (top && ['wp-content', 'wp-config.php'].includes(name)) continue;
      const src = join(from, name); const dst = join(to, name); const stat = await lstat(src);
      if (stat.isDirectory()) await copy(src, dst);
      else {
        await regularSource(src);
        if (++files > 10_000 || (bytes += stat.size) > 256 * 1024 * 1024) throw fail('source size');
        await copyFile(src, dst, fsConstants.COPYFILE_EXCL); await chmod(dst, 0o600);
      }
    }
  }
  await copy(SOURCE, WP, true);
  for (const name of ['wp-load.php', 'wp-settings.php', 'wp-includes/version.php']) {
    if (!(await lstat(join(WP, name))).isFile()) throw fail('core');
  }
  return Object.freeze({ files, bytes });
}

/** Generated files contain private credentials. Only write to the fresh tmpfs. */
export function containerWordPressTemplates(input, adminUsername, adminPassword) {
  const values = validateContainerWordPressInput(input);
  if (!/^synthetic_admin_[a-f0-9]{20}$/u.test(adminUsername) || !/^[a-f0-9]{64}$/u.test(adminPassword)) throw fail('admin input');
  const constants = {
    DB_NAME: values.database, DB_USER: values.user, DB_PASSWORD: values.password,
    DB_HOST: '127.0.0.1:' + values.port, DB_CHARSET: 'utf8mb4', DB_COLLATE: '',
    WP_HOME: ORIGIN, WP_SITEURL: ORIGIN, WP_ENVIRONMENT_TYPE: 'local',
    FNCP_WP_IDENTITY_ORIGIN: ORIGIN, FNCP_WP_CHALLENGE_SECRET: values.challengeSecret,
    FNCP_BFF_REGISTRATION_SECRET: values.registrationSecret, FNCP_WP_LOCAL_EVENT_SECRET: values.eventSecret,
  };
  const booleans = { FNCP_WP_SYNTHETIC_ONLY: true, FNCP_WP_IDENTITY_FRESH_INSTANCE: true,
    WP_DEBUG: false, WP_HTTP_BLOCK_EXTERNAL: true, DISABLE_WP_CRON: true,
    AUTOMATIC_UPDATER_DISABLED: true, DISALLOW_FILE_MODS: true, DISALLOW_FILE_EDIT: true, WP_AUTO_UPDATE_CORE: false };
  const salts = ['AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT'];
  const config = `<?php
// PRIVATE, SYNTHETIC ONLY, fresh owned container run.
${Object.entries(constants).map(([key, value]) => `define('${key}', ${quote(value)});`).join('\n')}
${Object.entries(booleans).map(([key, value]) => `define('${key}', ${value ? 'true' : 'false'});`).join('\n')}
define('WP_ACCESSIBLE_HOSTS', '127.0.0.1');
$table_prefix = 'synthetic_';
${salts.map(key => `define('${key}', '${randomBytes(48).toString('hex')}');`).join('\n')}
if (!defined('ABSPATH')) define('ABSPATH', __DIR__ . '/');
require_once ABSPATH . 'wp-settings.php';
`;
  const muPlugin = `<?php
if (wp_get_environment_type() !== 'local' || !defined('FNCP_WP_SYNTHETIC_ONLY') || FNCP_WP_SYNTHETIC_ONLY !== true ||
    !defined('FNCP_WP_IDENTITY_FRESH_INSTANCE') || FNCP_WP_IDENTITY_FRESH_INSTANCE !== true) exit;
add_filter('pre_wp_mail', function () { return false; }, PHP_INT_MAX);
add_filter('pre_http_request', function ($pre, $args, $url) {
    if ($url === '${EVENT}' && ($args['method'] ?? '') === 'POST' && ($args['redirection'] ?? 0) === 0) return $pre;
    return new WP_Error('fncp_identity_no_external_http', 'External HTTP disabled in synthetic identity runtime.');
}, PHP_INT_MAX, 3);
add_filter('get_avatar_url', function () { return ''; });
require_once '${PLUGIN}';
`;
  const installer = `<?php
if (PHP_SAPI !== 'cli' || getenv('FNCP_LOCAL_SYNTHETIC_MODE') !== 'fixture-only') exit(1);
ini_set('display_errors', '0'); ini_set('log_errors', '0');
try {
    if (!extension_loaded('mysqli') || !extension_loaded('curl') || !extension_loaded('json')) exit(1);
    $private = json_decode(file_get_contents('${ROOT}/wordpress-credentials.json'), true, 16, JSON_THROW_ON_ERROR);
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
    $db = new mysqli('127.0.0.1', ${quote(values.user)}, $private['password'], ${quote(values.database)}, ${values.port});
    $tables = $db->query('SHOW TABLES');
    if ($tables->num_rows !== 0) exit(1); // Never install over, adopt or resume a database.
    $db->close();
    $_SERVER['HTTP_HOST'] = '127.0.0.1:8103'; $_SERVER['REQUEST_URI'] = '/'; $_SERVER['SERVER_PORT'] = '8103';
    define('WP_INSTALLING', true);
    require '${WP}/wp-load.php';
    if (DB_NAME !== ${quote(values.database)} || DB_HOST !== '127.0.0.1:${values.port}' ||
        wp_get_environment_type() !== 'local' || FNCP_WP_IDENTITY_FRESH_INSTANCE !== true || FNCP_WP_SYNTHETIC_ONLY !== true) exit(1);
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    if (is_blog_installed()) exit(1);
    $installed = wp_install('Community Pulse synthetic identity proof', $private['adminUsername'],
        'synthetic_admin@example.test', false, '', $private['adminPassword'], 'en_US');
    if (is_wp_error($installed)) exit(1);
    update_option('blog_public', '0'); update_option('users_can_register', '0');
    if (!function_exists('fncp_identity_enabled') || !fncp_identity_enabled()) exit(1);
    echo "INSTALLED_SYNTHETIC_INSTANCE\\n";
} catch (Throwable $error) { exit(1); }
`;
  const router = `<?php
if (PHP_SAPI !== 'cli-server' || getenv('FNCP_LOCAL_SYNTHETIC_MODE') !== 'fixture-only' ||
    ($_SERVER['HTTP_HOST'] ?? '') !== '127.0.0.1:8103' || ($_SERVER['REMOTE_ADDR'] ?? '') !== '127.0.0.1') {
    http_response_code(403); exit('Local synthetic proof only.');
}
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; form-action 'self'");
header('Referrer-Policy: no-referrer'); header('X-Content-Type-Options: nosniff');
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if (!is_string($path) || preg_match('/wp-config|\\.\\.|%|\\\\\\\\|\\.json|\\.sql|\\.zip|\\.gz/i', $path)) { http_response_code(403); exit; }
return false;
`;
  return { config, muPlugin, installer, router,
    credentials: JSON.stringify({ password: values.password, adminUsername, adminPassword }) };
}

async function executePhp(script, args) {
  if (![ROOT + '/wordpress-install.php', OPERATOR].includes(script) || !Array.isArray(args) ||
      args.some(value => typeof value !== 'string') || JSON.stringify(args).length > 4096) throw fail('PHP input');
  return new Promise((resolve, reject) => {
    const child = spawn(PHP, [...PHP_FLAGS, script], { cwd: ROOT, env: ENV, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = ''; let size = 0; let expired = false;
    const timer = setTimeout(() => { expired = true; child.kill('SIGKILL'); }, 30_000);
    child.stdout.on('data', bytes => { size += bytes.length; if (size > 65_536) child.kill('SIGKILL'); else stdout += bytes.toString(); });
    child.stderr.on('data', bytes => { size += bytes.length; if (size > 65_536) child.kill('SIGKILL'); });
    child.once('error', () => { clearTimeout(timer); reject(fail('PHP process')); });
    child.once('close', code => {
      clearTimeout(timer);
      if (code !== 0 || expired || size > 65_536) reject(fail('PHP operation'));
      else resolve(stdout);
    });
    child.stdin.on('error', () => {}); child.stdin.end(JSON.stringify(args));
  });
}

/** Prepare, install and start only a new local WordPress instance. */
export async function createFreshContainerWordPress(input) {
  const values = validateContainerWordPressInput(input);
  if (process.platform !== 'linux' || process.getuid?.() !== 1000) throw fail('platform');
  let child; let childClosed; let closing = false; let closePromise; let stage = 'preflight';
  const active = new Set();
  const close = () => {
    closing = true;
    if (!closePromise) closePromise = (async () => {
      await Promise.allSettled([...active]);
      if (child && child.exitCode === null && child.signalCode === null) {
        const killTimer = setTimeout(() => child.kill('SIGKILL'), 2000);
        try { child.kill('SIGTERM'); await childClosed; } finally { clearTimeout(killTimer); }
      } else if (child) await childClosed;
      if (child && child.exitCode === null && child.signalCode === null) throw fail('shutdown');
      await freePort();
      return Object.freeze({ applicationStopped: true, portAvailable: true, databaseUntouched: true, filesPreserved: true });
    })();
    return closePromise;
  };
  try {
    await directory('/run/fncp', 1000);
    await mkdir(ROOT, { recursive: true, mode: 0o700 }); await directory(ROOT, 1000);
    await privateWrite(ROOT + '/wordpress-runner-attempt', 'FRESH_SYNTHETIC_ONLY\n');
    await regularSource(PHP); await regularSource(PLUGIN); await regularSource(OPERATOR);
    await freePort();
    stage = 'source copy'; const source = await copyPristineCore();
    const templates = containerWordPressTemplates(values, 'synthetic_admin_' + randomBytes(10).toString('hex'), randomBytes(32).toString('hex'));
    await mkdir(WP + '/wp-content/mu-plugins', { recursive: true, mode: 0o700 });
    for (const [path, text] of [[WP + '/wp-config.php', templates.config], [WP + '/wp-content/mu-plugins/fncp-identity-runtime.php', templates.muPlugin],
      [ROOT + '/wordpress-install.php', templates.installer], [ROOT + '/wordpress-router.php', templates.router],
      [ROOT + '/wordpress-credentials.json', templates.credentials]]) await privateWrite(path, text);
    stage = 'installation';
    if ((await executePhp(ROOT + '/wordpress-install.php', [])).trim() !== 'INSTALLED_SYNTHETIC_INSTANCE') throw fail(stage);
    stage = 'listener'; await freePort();
    child = spawn(PHP, [...PHP_FLAGS, '-S', '127.0.0.1:8103', '-t', WP, ROOT + '/wordpress-router.php'],
      { cwd: ROOT, env: ENV, stdio: 'ignore' });
    childClosed = new Promise(resolve => { child.once('error', resolve); child.once('close', resolve); });
    let ready = false;
    for (let attempt = 0; attempt < 40; attempt++) {
      if (child.exitCode !== null || child.signalCode !== null) throw fail('listener');
      try {
        const response = await fetch(ORIGIN + '/wp-login.php', { redirect: 'manual', signal: AbortSignal.timeout(500) });
        await response.body?.cancel(); if (response.status === 200) { ready = true; break; }
      } catch { /* Bounded readiness of only the new local listener. */ }
      await sleep(100);
    }
    if (!ready) throw fail('readiness');
    const operation = async name => {
      if (closing || child.exitCode !== null || child.signalCode !== null ||
          !['operator-session', 'aggregate', 'close-guests'].includes(name)) throw fail('operation state');
      const promise = executePhp(OPERATOR, [name]); active.add(promise);
      try {
        const result = JSON.parse(await promise);
        if (!result || typeof result !== 'object' || Array.isArray(result)) throw fail('operation result');
        return result;
      } catch { throw fail('operator ' + name); } finally { active.delete(promise); }
    };
    const runtime = { mode: 'SYNTHETIC_ONLY', origin: ORIGIN,
      operatorSession: () => operation('operator-session'), aggregate: () => operation('aggregate'),
      closeGuests: () => operation('close-guests'), runPhp: operation, close,
      summary: () => Object.freeze({ mode: 'SYNTHETIC_ONLY', sourceFiles: source.files, sourceBytes: source.bytes,
        listenerRunning: !closing && child.exitCode === null && child.signalCode === null, productionReady: false }),
    };
    // Explicit private locator/credential handoff; omitted by ordinary object
    // enumeration/JSON. This is not backup, quiescence or DB ownership proof.
    Object.defineProperty(runtime, 'recoveryContext', { enumerable: false,
      value: Object.freeze({ root: ROOT, wpPath: WP, wpLoadPath: WP + '/wp-load.php',
        database: values.database, user: values.user, password: values.password, port: values.port,
        host: '127.0.0.1', tablePrefix: 'synthetic_' }),
    });
    return Object.freeze(runtime);
  } catch {
    try { await close(); } catch { throw fail(stage + ' and cleanup'); }
    throw fail(stage);
  }
}
