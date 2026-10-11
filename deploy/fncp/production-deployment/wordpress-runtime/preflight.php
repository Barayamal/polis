<?php
declare(strict_types=1);
// This check never installs/upgrades WordPress, creates an account or changes
// any option. An uninitialized/inconsistent site cannot expose an installer.
try {
    if (PHP_SAPI !== 'cli') { throw new RuntimeException(); }
    require_once '/opt/fncp-wordpress/material.php'; $c = fncp_runtime_configuration();
    fncp_runtime_validate_leaf(fncp_runtime_read('server.pem'), fncp_runtime_read('server-key.pem'), $c['wordpressOrigin'], time());
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
    $db = mysqli_init(); $db->options(MYSQLI_OPT_CONNECT_TIMEOUT, 5); $db->real_connect('localhost', $c['databaseUser'], $c['databasePassword'], $c['databaseName'], 0, '/run/mysqld/mysqld.sock');
    $db->query('SET SESSION MAX_STATEMENT_TIME=5');
    $options = [];
    $rows = $db->query('SELECT option_name,option_value FROM `' . $c['tablePrefix'] . "options` WHERE option_name IN ('siteurl','home','db_version','active_plugins')");
    while ($row = $rows->fetch_assoc()) { $options[$row['option_name']] = $row['option_value']; }
    require '/usr/src/wordpress/wp-includes/version.php';
    if (($options['siteurl'] ?? null) !== $c['wordpressOrigin'] || ($options['home'] ?? null) !== $c['wordpressOrigin']
        || ($options['db_version'] ?? null) !== (string)$wp_db_version || ($options['active_plugins'] ?? null) !== 'a:0:{}') { throw new RuntimeException(); }
    if ((int)$db->query('SELECT COUNT(*) AS n FROM `' . $c['tablePrefix'] . 'users`')->fetch_assoc()['n'] < 1) { throw new RuntimeException(); }
    $db->close(); fwrite(STDOUT, "WordPress initialized-site check passed.\n");
} catch (Throwable $e) { fwrite(STDERR, "WordPress initialized-site check rejected.\n"); exit(1); }
