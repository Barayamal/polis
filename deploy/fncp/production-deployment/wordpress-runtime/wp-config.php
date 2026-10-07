<?php
// Source-owned configuration loader. All private values live in a separately
// provisioned read-only volume; no runtime PHP is loaded from that volume.
require_once '/opt/fncp-wordpress/material.php';
try { $c = fncp_runtime_configuration(); } catch (Throwable $e) { http_response_code(503); exit('WordPress service unavailable.'); }
define('DB_NAME', $c['databaseName']); define('DB_USER', $c['databaseUser']); define('DB_PASSWORD', $c['databasePassword']);
define('DB_HOST', 'localhost:/run/mysqld/mysqld.sock'); define('DB_CHARSET', 'utf8mb4'); define('DB_COLLATE', '');
$table_prefix = $c['tablePrefix'];
define('WP_HOME', $c['wordpressOrigin']); define('WP_SITEURL', $c['wordpressOrigin']);
define('WP_ENVIRONMENT_TYPE', 'production'); define('FORCE_SSL_ADMIN', true);
define('FNCP_PRODUCTION_WORDPRESS_CONFIG_FILE', '/run/fncp/wordpress/plugin-config.json');
define('WP_DEBUG', false); define('WP_DEBUG_LOG', false); define('WP_DEBUG_DISPLAY', false);
define('DISABLE_WP_CRON', true); define('AUTOMATIC_UPDATER_DISABLED', true);
define('DISALLOW_FILE_MODS', true); define('DISALLOW_FILE_EDIT', true); define('WP_AUTO_UPDATE_CORE', false);
foreach (['AUTH_KEY','SECURE_AUTH_KEY','LOGGED_IN_KEY','NONCE_KEY','AUTH_SALT','SECURE_AUTH_SALT','LOGGED_IN_SALT','NONCE_SALT'] as $index => $name) { define($name, $c['salts'][$index]); }
unset($c);
if (!defined('ABSPATH')) { define('ABSPATH', __DIR__ . '/'); }
require_once ABSPATH . 'wp-settings.php';
