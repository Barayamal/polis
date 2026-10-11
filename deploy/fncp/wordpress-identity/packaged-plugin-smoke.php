<?php
/** CLI test helper only: load packaged PHP with inert WordPress stubs. No WordPress installation. */
declare(strict_types=1);
ini_set('display_errors', '0');
ini_set('log_errors', '0');
set_error_handler(static function (): never { throw new RuntimeException('Packaged smoke rejected.'); });

try {
    $modes = ['disabled-default', 'synthetic-false', 'fresh-false', 'nonlocal-environment',
        'external-origin', 'https-origin', 'missing-secret', 'duplicate-secret', 'malformed-secret',
        'legacy-plugin', 'enabled-local', 'wrong-method', 'wrong-host', 'wrong-remote',
        'wrong-origin', 'authorization-header', 'file-upload', 'wrong-content-type', 'cross-site',
        'oversized-body'];
    if (PHP_SAPI !== 'cli' || $argc !== 3 || !in_array($argv[2], $modes, true)) { throw new RuntimeException(); }
    $root = realpath($argv[1]);
    if ($root === false || $root !== $argv[1] || dirname($root) !== realpath(sys_get_temp_dir())
        || !str_starts_with(basename($root), 'fncp-packaged-smoke-') || is_link($root)
        || (fileperms($root) & 0777) !== 0700) { throw new RuntimeException(); }
    $mode = $argv[2];
    $GLOBALS['fncp_smoke_hooks'] = [];
    $GLOBALS['fncp_smoke_network'] = 0;
    $GLOBALS['fncp_smoke_storage'] = 0;
    $GLOBALS['fncp_smoke_nonce'] = 0;
    function add_action(string $hook, mixed $callback): void { $GLOBALS['fncp_smoke_hooks'][] = $hook; }
    function wp_get_environment_type(): string { return $GLOBALS['mode'] === 'nonlocal-environment' ? 'production' : 'local'; }
    function current_user_can(string $capability): bool { return false; }
    function check_admin_referer(string $action, string $name): never { $GLOBALS['fncp_smoke_nonce']++; throw new RuntimeException(); }
    function wp_remote_post(mixed ...$arguments): never { $GLOBALS['fncp_smoke_network']++; throw new RuntimeException(); }
    function add_option(mixed ...$arguments): never { $GLOBALS['fncp_smoke_storage']++; throw new RuntimeException(); }
    function wp_cache_delete(mixed ...$arguments): never { $GLOBALS['fncp_smoke_storage']++; throw new RuntimeException(); }
    $GLOBALS['wpdb'] = new class {
        public string $options = 'synthetic_options';
        public function __call(string $method, array $arguments): never { $GLOBALS['fncp_smoke_storage']++; throw new RuntimeException(); }
    };
    define('ABSPATH', '/synthetic-not-a-wordpress-install/');
    if ($mode !== 'disabled-default') {
        define('FNCP_WP_SYNTHETIC_ONLY', $mode !== 'synthetic-false');
        define('FNCP_WP_IDENTITY_FRESH_INSTANCE', $mode !== 'fresh-false');
        define('FNCP_WP_IDENTITY_ORIGIN', $mode === 'external-origin' ? 'http://example.invalid:8103'
            : ($mode === 'https-origin' ? 'https://127.0.0.1:8103' : 'http://127.0.0.1:8103'));
        define('FNCP_WP_CHALLENGE_SECRET', str_repeat('a', 40));
        define('FNCP_BFF_REGISTRATION_SECRET', str_repeat($mode === 'duplicate-secret' ? 'a' : 'b', 40));
        if ($mode !== 'missing-secret') { define('FNCP_WP_LOCAL_EVENT_SECRET', $mode === 'malformed-secret' ? 'short' : str_repeat('c', 40)); }
    }
    if ($mode === 'legacy-plugin') { function fncp_wp_local_change(): never { throw new RuntimeException(); } }
    require $root . '/wordpress-identity/fncp-wordpress-identity.php';
    $classes = ['FNCP_Identity_Registry', 'FNCP_Identity_Contract', 'FNCP_Local_Journal', 'FNCP_Local_Contract'];
    foreach ($classes as $class) { if (!class_exists($class, false)) { throw new RuntimeException(); } }
    $disabled = in_array($mode, array_slice($modes, 0, 10), true);
    if (fncp_identity_enabled() === $disabled) { throw new RuntimeException(); }
    $_SERVER = ['REMOTE_ADDR' => '127.0.0.1', 'HTTP_HOST' => '127.0.0.1:8103',
        'REQUEST_METHOD' => 'POST', 'HTTP_ORIGIN' => 'http://127.0.0.1:8103',
        'CONTENT_TYPE' => 'application/x-www-form-urlencoded', 'CONTENT_LENGTH' => '0'];
    $_GET = []; $_POST = []; $_FILES = [];
    switch ($mode) {
        case 'wrong-method': $_SERVER['REQUEST_METHOD'] = 'GET'; break;
        case 'wrong-host': $_SERVER['HTTP_HOST'] = 'example.invalid'; break;
        case 'wrong-remote': $_SERVER['REMOTE_ADDR'] = '192.0.2.1'; break;
        case 'wrong-origin': $_SERVER['HTTP_ORIGIN'] = 'http://example.invalid'; break;
        case 'authorization-header': $_SERVER['HTTP_AUTHORIZATION'] = 'synthetic-invalid'; break;
        case 'file-upload': $_FILES = ['synthetic' => []]; break;
        case 'wrong-content-type': $_SERVER['CONTENT_TYPE'] = 'application/json'; break;
        case 'cross-site': $_SERVER['HTTP_SEC_FETCH_SITE'] = 'cross-site'; break;
        case 'oversized-body': $_SERVER['CONTENT_LENGTH'] = '16385'; break;
    }
    $status = 200;
    try { fncp_identity_http('POST'); } catch (FNCP_Identity_HttpError $error) { $status = $error->status; }
    $expected = $disabled ? 503 : ($mode === 'enabled-local' ? 200
        : ($mode === 'wrong-content-type' ? 415 : ($mode === 'oversized-body' ? 413 : 403)));
    if ($status !== $expected) { throw new RuntimeException(); }
    $adminStatus = 200;
    try { fncp_identity_admin('fncp_identity_decide'); } catch (FNCP_Identity_HttpError $error) { $adminStatus = $error->status; }
    if ($adminStatus !== ($status === 200 ? 403 : $status)) { throw new RuntimeException(); }
    if (count($GLOBALS['fncp_smoke_hooks']) !== 11 || count(array_unique($GLOBALS['fncp_smoke_hooks'])) !== 11
        || $GLOBALS['fncp_smoke_network'] !== 0 || $GLOBALS['fncp_smoke_storage'] !== 0 || $GLOBALS['fncp_smoke_nonce'] !== 0) { throw new RuntimeException(); }
    echo json_encode(['ok' => true, 'mode' => 'SYNTHETIC_ONLY', 'classesLoaded' => 4, 'hooksRegistered' => 11,
        'httpGateStatus' => $status, 'adminGateStatus' => $adminStatus, 'networkCalls' => 0, 'storageCalls' => 0,
        'wordpressInstalled' => false, 'productionReady' => false], JSON_THROW_ON_ERROR) . "\n";
} catch (Throwable $error) {
    echo '{"ok":false,"error":"packaged_smoke_rejected","productionReady":false}' . "\n";
    exit(1);
}
