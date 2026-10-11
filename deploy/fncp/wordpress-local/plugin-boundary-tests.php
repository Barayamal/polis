<?php
/** WP function stubs only: actual WP integration is tested separately. */
declare(strict_types=1);
define('ABSPATH', __DIR__ . '/synthetic-stub/');
define('FNCP_WP_SYNTHETIC_ONLY', true);
define('FNCP_WP_LOCAL_EVENT_SECRET', str_repeat('x', 64));
$GLOBALS['fncp_test_environment'] = 'local';
$GLOBALS['fncp_test_capability'] = false;
$GLOBALS['fncp_test_nonce'] = false;
$GLOBALS['fncp_test_nonce_calls'] = [];
$GLOBALS['fncp_test_hooks'] = [];
$GLOBALS['fncp_test_raw'] = null;
$GLOBALS['fncp_test_http'] = [];
$GLOBALS['fncp_test_http_result'] = 'ack';

final class StubWPError {}
final class StubWPDB {
    public string $options = 'synthetic_options';
    public string $last_error = '';
    public function prepare(string $sql, ...$args): array { return ['sql' => $sql, 'args' => $args]; }
    public function get_var(array $query): ?string { return $GLOBALS['fncp_test_raw']; }
    public function query(array $query): int {
        [$next, $name, $old] = $query['args'];
        if (!str_contains($query['sql'], 'BINARY option_value = %s')) { throw new RuntimeException('Missing byte-exact CAS'); }
        if ($name !== 'fncp_wp_local_journal_v1') { throw new RuntimeException('Wrong option'); }
        if ($old !== $GLOBALS['fncp_test_raw']) { return 0; }
        $GLOBALS['fncp_test_raw'] = $next;
        return 1;
    }
}
$wpdb = new StubWPDB();
function wp_get_environment_type(): string { return $GLOBALS['fncp_test_environment']; }
function current_user_can(string $capability): bool {
    if ($capability !== 'manage_options') { throw new RuntimeException('Wrong capability'); }
    return $GLOBALS['fncp_test_capability'];
}
function wp_die(string $message, string $title = '', array $args = []): void {
    throw new RuntimeException('WP_DIE_' . ($args['response'] ?? 500));
}
function check_admin_referer(string $action, string $field): void {
    $GLOBALS['fncp_test_nonce_calls'][] = [$action, $field];
    if (!$GLOBALS['fncp_test_nonce']) { wp_die('bad nonce', '', ['response' => 403]); }
}
function add_action(string $hook, $callback): void { $GLOBALS['fncp_test_hooks'][] = $hook; }
function add_option(string $name, string $raw, string $legacy, bool $autoload): bool {
    if ($autoload || $GLOBALS['fncp_test_raw'] !== null) { return false; }
    $GLOBALS['fncp_test_raw'] = $raw;
    return true;
}
function wp_cache_delete(string $name, string $group): void {}
function wp_unslash(string $value): string { return stripslashes($value); }
function wp_remote_post(string $url, array $args) {
    $GLOBALS['fncp_test_http'][] = [$url, $args];
    if ($GLOBALS['fncp_test_http_result'] === 'transport') { return new StubWPError(); }
    $event = json_decode($args['body'], true, 8, JSON_THROW_ON_ERROR);
    return ['code' => 200, 'body' => json_encode(['ok' => true, 'event_id' => $event['event_id'],
        'version' => $GLOBALS['fncp_test_http_result'] === 'ack' ? $event['version'] : 999])];
}
function is_wp_error($value): bool { return $value instanceof StubWPError; }
function wp_remote_retrieve_response_code(array $response): int { return $response['code']; }
function wp_remote_retrieve_body(array $response): string { return $response['body']; }
require_once __DIR__ . '/fncp-wordpress-local.php';

$count = 0;
function verify(bool $condition): void { if (!$condition) { throw new RuntimeException('Assertion failed'); } }
function boundaryTest(string $name, callable $operation): void {
    global $count; $operation(); $count++; echo "PASS {$name}\n";
}
function denied(callable $operation, int $status): void {
    try { $operation(); } catch (RuntimeException $error) {
        verify($error->getMessage() === 'WP_DIE_' . $status); return;
    }
    throw new RuntimeException('Expected WP denial');
}

boundaryTest('only authenticated admin hooks registered', static function (): void {
    verify($GLOBALS['fncp_test_hooks'] === ['admin_menu', 'admin_post_fncp_wp_local_change', 'admin_post_fncp_wp_local_retry']);
});
boundaryTest('production and staging disabled even with synthetic flag', static function (): void {
    foreach (['production', 'staging', 'development'] as $environment) {
        $GLOBALS['fncp_test_environment'] = $environment;
        verify(!fncp_wp_local_enabled());
        denied(static fn() => fncp_wp_local_authorize('change'), 503);
    }
    $GLOBALS['fncp_test_environment'] = 'local';
    verify(fncp_wp_local_enabled());
});
boundaryTest('GET cannot change authority', static function (): void {
    $_SERVER['REQUEST_METHOD'] = 'GET'; $GLOBALS['fncp_test_capability'] = true;
    denied(static fn() => fncp_wp_local_authorize('change'), 403);
});
boundaryTest('nonce alone is not administrator authorization', static function (): void {
    $_SERVER['REQUEST_METHOD'] = 'POST'; $GLOBALS['fncp_test_capability'] = false; $GLOBALS['fncp_test_nonce'] = true;
    denied(static fn() => fncp_wp_local_authorize('change'), 403);
});
boundaryTest('administrator capability alone is not CSRF authorization', static function (): void {
    $GLOBALS['fncp_test_capability'] = true; $GLOBALS['fncp_test_nonce'] = false;
    denied(static fn() => fncp_wp_local_authorize('change'), 403);
});
boundaryTest('change and retry have separate nonce actions', static function (): void {
    $GLOBALS['fncp_test_nonce'] = true;
    fncp_wp_local_authorize('change'); fncp_wp_local_authorize('retry');
    verify(array_slice($GLOBALS['fncp_test_nonce_calls'], -2) === [
        ['fncp_wp_local_change', '_fncp_nonce'], ['fncp_wp_local_retry', '_fncp_nonce']]);
});
boundaryTest('extra data rejected before persistence or local send', static function (): void {
    $_POST = ['subject' => 'synthetic_alice', 'round_id' => 'synthetic_round_local', 'state' => 'approved', 'email' => 'forbidden@example.invalid'];
    denied(static fn() => fncp_wp_local_change(), 409);
    verify($GLOBALS['fncp_test_raw'] === null && $GLOBALS['fncp_test_http'] === []);
});
boundaryTest('array injection rejected before persistence or local send', static function (): void {
    $_POST = ['subject' => ['synthetic_alice'], 'round_id' => 'synthetic_round_local', 'state' => 'approved'];
    denied(static fn() => fncp_wp_local_change(), 409);
    verify($GLOBALS['fncp_test_raw'] === null && $GLOBALS['fncp_test_http'] === []);
});
boundaryTest('local delivery signs exactly the durable outbox body', static function (): void {
    $journal = fncp_wp_local_journal();
    $record = $journal->change('synthetic_round_local', 'synthetic_alice', 'approved');
    verify(fncp_wp_local_deliver($journal, $record));
    [$url, $request] = $GLOBALS['fncp_test_http'][0];
    verify($url === 'http://127.0.0.1:8101/internal/wordpress/events');
    verify($request['redirection'] === 0 && $request['timeout'] === 3 && $request['limit_response_size'] === 4096);
    verify($request['body'] === $record['body'] && $request['cookies'] === []);
    verify($request['headers']['X-FNCP-WP-Event-ID'] === $record['event']['event_id']);
    verify(hash_equals($request['headers']['X-FNCP-WP-Signature'], FNCP_Local_Contract::signature(FNCP_WP_LOCAL_EVENT_SECRET, $request['headers']['X-FNCP-WP-Timestamp'], $record['body'])));
    verify($journal->pending() === []);
});
boundaryTest('already acknowledged record is not resent', static function (): void {
    $journal = fncp_wp_local_journal();
    $record = $journal->change('synthetic_round_local', 'synthetic_alice', 'approved');
    $before = count($GLOBALS['fncp_test_http']);
    verify(fncp_wp_local_deliver($journal, $record));
    verify(count($GLOBALS['fncp_test_http']) === $before);
});
boundaryTest('mismatched ACK remains pending', static function (): void {
    $journal = fncp_wp_local_journal();
    $record = $journal->change('synthetic_round_local', 'synthetic_alice', 'revoked');
    $GLOBALS['fncp_test_http_result'] = 'mismatch';
    verify(!fncp_wp_local_deliver($journal, $record));
    verify($journal->pending()[0]['last_result'] === 'ACK_REJECTED');
});
boundaryTest('transport failure retains immutable retry body', static function (): void {
    $journal = fncp_wp_local_journal(); $record = $journal->pending()[0];
    $GLOBALS['fncp_test_http_result'] = 'transport';
    verify(!fncp_wp_local_deliver($journal, $record));
    $saved = $journal->pending()[0];
    verify($saved['last_result'] === 'TRANSPORT_UNAVAILABLE' && $saved['body'] === $record['body']);
});
boundaryTest('explicit retry ACK clears pending without a new version', static function (): void {
    $journal = fncp_wp_local_journal(); $record = $journal->pending()[0];
    $GLOBALS['fncp_test_http_result'] = 'ack';
    verify(fncp_wp_local_deliver($journal, $record));
    verify($journal->pending() === []);
    verify(count($journal->snapshot()['events']) === 2);
});
echo "WordPress adapter stub/model checks: {$count} passed.\n";
