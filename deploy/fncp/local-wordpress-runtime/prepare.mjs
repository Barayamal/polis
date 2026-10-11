/** New disposable local WordPress only. Generates private config; never contacts live WP. */
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
function prepare() {
process.umask(0o077);
if (process.env.FNCP_LOCAL_SYNTHETIC_MODE !== 'fixture-only') throw new Error('Explicit fixture-only mode required.');
const runtime = new URL('./.runtime/', import.meta.url);
mkdirSync(runtime, { recursive: true, mode: 0o700 });
const credentialsPath = new URL('credentials.json', runtime);
if (!existsSync(credentialsPath)) writeFileSync(credentialsPath, JSON.stringify({
  mode: 'SYNTHETIC_ONLY', dbPassword: randomBytes(32).toString('hex'), rootPassword: randomBytes(32).toString('hex'),
  adminPassword: randomBytes(32).toString('hex'), salts: Array.from({ length: 8 }, () => randomBytes(48).toString('hex')),
}), { mode: 0o600, flag: 'wx' });
const config = JSON.parse(readFileSync(credentialsPath, 'utf8'));
if (config.mode !== 'SYNTHETIC_ONLY') throw new Error('Wrong runtime.');
for (const key of ['dbPassword', 'rootPassword', 'adminPassword']) if (!/^[0-9a-f]{64}$/u.test(config[key])) throw new Error('Invalid private fixture config.');
if (config.salts.length !== 8 || !config.salts.every((s) => /^[0-9a-f]{96}$/u.test(s))) throw new Error('Invalid salts.');
const passwordFiles = [['db-password', config.dbPassword], ['root-password', config.rootPassword]];
for (const [name, value] of passwordFiles) {
  const path = new URL(name, runtime);
  if (existsSync(path) && readFileSync(path, 'utf8') !== value) throw new Error('Synthetic database secret-file drift; preserved unchanged.');
}
for (const [name, value] of passwordFiles) {
  const path = new URL(name, runtime); if (!existsSync(path)) writeFileSync(path, value, { mode: 0o600, flag: 'wx' }); chmodSync(path, 0o600);
}
const wp = new URL('wordpress/', runtime);
if (!existsSync(new URL('wp-settings.php', wp))) throw new Error('Download and verify the official WordPress source first.');
const eventSecretPath = fileURLToPath(new URL('../local-access/.runtime/wordpress-secret.json', import.meta.url));
const secret = JSON.parse(readFileSync(eventSecretPath, 'utf8')).secret;
if (!/^[A-Za-z0-9_-]{32,512}$/u.test(secret)) throw new Error('Start local access proof first.');
const configPath = new URL('wp-config.php', wp);
  const salts = ['AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT'];
  const content = `<?php
// GENERATED PRIVATE synthetic runtime. Never copy to production.
define('DB_NAME', 'fncp_wp_synthetic');
define('DB_USER', 'fncp_wp_synthetic');
define('DB_PASSWORD', '${config.dbPassword}');
define('DB_HOST', '127.0.0.1:33079');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');
$table_prefix = 'synthetic_';
define('WP_HOME', 'http://127.0.0.1:8102');
define('WP_SITEURL', 'http://127.0.0.1:8102');
define('WP_ENVIRONMENT_TYPE', 'local');
define('FNCP_WP_SYNTHETIC_ONLY', true);
define('FNCP_WP_LOCAL_EVENT_SECRET', '${secret}');
define('WP_DEBUG', false);
define('WP_HTTP_BLOCK_EXTERNAL', true);
define('WP_ACCESSIBLE_HOSTS', '127.0.0.1');
define('DISABLE_WP_CRON', true);
define('AUTOMATIC_UPDATER_DISABLED', true);
define('DISALLOW_FILE_MODS', true);
define('DISALLOW_FILE_EDIT', true);
define('WP_AUTO_UPDATE_CORE', false);
${salts.map((key, index) => `define('${key}', '${config.salts[index]}');`).join('\n')}
if (!defined('ABSPATH')) define('ABSPATH', __DIR__ . '/');
require_once ABSPATH . 'wp-settings.php';
`;
if (existsSync(configPath) && readFileSync(configPath, 'utf8') !== content) {
  throw new Error('Private generated WordPress configuration drift; preserved unchanged.');
}
if (!existsSync(configPath)) {
  writeFileSync(configPath, content, { mode: 0o600, flag: 'wx' });
}
const mu = new URL('wp-content/mu-plugins/', wp); mkdirSync(mu, { recursive: true });
const pluginPath = fileURLToPath(new URL('../wordpress-local/fncp-wordpress-local.php', import.meta.url));
const muPath = new URL('fncp-local-runtime.php', mu);
// Generated stub is deliberately exact-target, mail-suppressing and source-linked.
writeFileSync(muPath, `<?php
if (wp_get_environment_type() !== 'local' || !defined('FNCP_WP_SYNTHETIC_ONLY') || FNCP_WP_SYNTHETIC_ONLY !== true) exit;
add_filter('pre_wp_mail', function () { return false; }, PHP_INT_MAX);
add_filter('pre_http_request', function ($pre, $args, $url) {
  if ($url === 'http://127.0.0.1:8101/internal/wordpress/events') return $pre;
  return new WP_Error('fncp_local_no_external_http', 'External HTTP disabled in synthetic runtime.');
}, PHP_INT_MAX, 3);
add_filter('get_avatar_url', function () { return ''; });
require_once '${pluginPath}';
`, { mode: 0o600 });
console.log('Private WordPress synthetic config prepared. External WordPress HTTP and all wp_mail delivery disabled.');
}
try { prepare(); } catch {
  // Parser and filesystem exceptions can contain private input. Never echo them.
  console.error('Local WordPress preparation failed. Check fixture-only mode, verified source and private configuration consistency; existing credentials/configuration were preserved.');
  process.exitCode = 1;
}
