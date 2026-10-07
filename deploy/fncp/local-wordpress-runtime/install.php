<?php
// CLI-only, exact new disposable path/database. No live install or credential output.
if (PHP_SAPI !== 'cli' || getenv('FNCP_LOCAL_SYNTHETIC_MODE') !== 'fixture-only') exit(1);
$runtime = __DIR__ . '/.runtime/';
$config = json_decode(file_get_contents($runtime . 'credentials.json'), true, 512, JSON_THROW_ON_ERROR);
try {
    $connection = new mysqli('127.0.0.1', 'fncp_wp_synthetic', $config['dbPassword'], 'fncp_wp_synthetic', 33079);
    $connection->close();
} catch (Throwable $error) { fwrite(STDERR, "Synthetic database is not ready at the fixed loopback port; no install attempted.\n"); exit(1); }
$_SERVER['HTTP_HOST'] = '127.0.0.1:8102';
$_SERVER['REQUEST_URI'] = '/';
$_SERVER['SERVER_PORT'] = '8102';
define('WP_INSTALLING', true);
require $runtime . 'wordpress/wp-load.php';
if (DB_NAME !== 'fncp_wp_synthetic' || DB_HOST !== '127.0.0.1:33079' || wp_get_environment_type() !== 'local') exit(1);
require_once ABSPATH . 'wp-admin/includes/upgrade.php';
if (is_blog_installed()) { echo "Existing synthetic WordPress preserved.\n"; exit(0); }
$result = wp_install('Community Pulse — local synthetic proof', 'synthetic_admin', 'synthetic_admin@example.test', false, '', $config['adminPassword'], 'en_US');
if (is_wp_error($result)) { fwrite(STDERR, "Synthetic WordPress install failed.\n"); exit(1); }
update_option('blog_public', '0');
update_option('users_can_register', '0');
echo "Synthetic WordPress installed; mail blocked; registration disabled; no live content copied.\n";
