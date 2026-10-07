<?php
/** Real disposable WordPress + real local receiver, never a live WP installation. */
declare(strict_types=1);

if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
$expected = dirname(__DIR__) . '/local-wordpress-runtime/.runtime/wordpress/wp-load.php';
$supplied = getenv('FNCP_WP_BOOTSTRAP');
if ($supplied === false || realpath($supplied) === false || realpath($supplied) !== realpath($expected)) {
    fwrite(STDERR, "Refusing: FNCP_WP_BOOTSTRAP must name this proof's exact disposable WordPress wp-load.php.\n");
    exit(1);
}
$fixture = getenv('FNCP_WP_TEST_FIXTURE') ?: 'synthetic_wp_integration';
require_once __DIR__ . '/contract.php';
if (!FNCP_Local_Contract::fixture($fixture)) { fwrite(STDERR, "Refusing non-synthetic fixture.\n"); exit(1); }
require $supplied;
if (!function_exists('fncp_wp_local_enabled') || !fncp_wp_local_enabled()
    || parse_url(site_url(), PHP_URL_HOST) !== '127.0.0.1') {
    fwrite(STDERR, "Refusing: local-only plugin/configuration/site binding is absent.\n");
    exit(1);
}

final class FNCP_WP_Test_Denied extends RuntimeException {}
add_filter('wp_die_handler', static fn() => static function ($message, $title = '', $args = []): void {
    throw new FNCP_WP_Test_Denied('WordPress authorization denied.');
});
$checks = 0;
function fncp_wp_integration_check(bool $passed, string $name): void {
    global $checks;
    if (!$passed) { throw new RuntimeException($name); }
    $checks++; echo "PASS {$name}\n";
}
function fncp_wp_integration_denied(callable $operation, string $name): void {
    try { $operation(); } catch (FNCP_WP_Test_Denied $error) { fncp_wp_integration_check(true, $name); return; }
    throw new RuntimeException('Expected denial: ' . $name);
}

try {
    $admins = get_users(['role' => 'administrator', 'number' => 1, 'fields' => 'ID']);
    if (count($admins) !== 1) { throw new RuntimeException('Disposable administrator unavailable.'); }
    $_SERVER['REQUEST_METHOD'] = 'POST';
    wp_set_current_user(0);
    $_REQUEST['_fncp_nonce'] = wp_create_nonce('fncp_wp_local_change');
    fncp_wp_integration_denied(static fn() => fncp_wp_local_authorize('change'), 'actual WordPress anonymous capability denied');

    // Local synthetic role fixture only; wp_insert_user does not request a notice,
    // and the disposable runtime's MU boundary separately blocks all wp_mail.
    $subscriber = get_user_by('login', 'synthetic_wp_subscriber');
    if ($subscriber === false) {
        $subscriberId = wp_insert_user(['user_login' => 'synthetic_wp_subscriber',
            'user_pass' => wp_generate_password(40, true, true), 'user_email' => '', 'role' => 'subscriber']);
        if (is_wp_error($subscriberId)) { throw new RuntimeException('Synthetic subscriber creation failed.'); }
        $subscriber = get_user_by('id', $subscriberId);
    }
    if ($subscriber === false || $subscriber->roles !== ['subscriber']) {
        throw new RuntimeException('Synthetic subscriber role binding differs.');
    }
    wp_set_current_user((int) $subscriber->ID);
    $_REQUEST['_fncp_nonce'] = wp_create_nonce('fncp_wp_local_change');
    fncp_wp_integration_denied(static fn() => fncp_wp_local_authorize('change'), 'actual WordPress subscriber with valid nonce capability denied');

    wp_set_current_user((int) $admins[0]);
    $_REQUEST['_fncp_nonce'] = 'invalid';
    fncp_wp_integration_denied(static fn() => fncp_wp_local_authorize('change'), 'actual WordPress administrator invalid nonce denied');
    $_REQUEST['_fncp_nonce'] = wp_create_nonce('fncp_wp_local_change');
    $_SERVER['REQUEST_METHOD'] = 'GET';
    fncp_wp_integration_denied(static fn() => fncp_wp_local_authorize('change'), 'actual WordPress GET mutation denied');
    $_SERVER['REQUEST_METHOD'] = 'POST';
    fncp_wp_local_authorize('change');
    fncp_wp_integration_check(true, 'actual WordPress administrator and nonce authorized');
    fncp_wp_integration_denied(static fn() => fncp_wp_local_authorize('retry'), 'actual WordPress change nonce cannot authorize retry');

    // Render with the real WP submit_button implementation. A default named
    // submit control previously added an unrecognised field to browser POSTs.
    require_once ABSPATH . 'wp-admin/includes/template.php';
    $_SERVER['REQUEST_URI'] = '/wp-admin/tools.php?page=fncp-local-approval';
    ob_start();
    fncp_wp_local_page();
    $page = ob_get_clean();
    $previousXmlErrors = libxml_use_internal_errors(true);
    $dom = new DOMDocument();
    $dom->loadHTML($page);
    libxml_clear_errors();
    libxml_use_internal_errors($previousXmlErrors);
    $xpath = new DOMXPath($dom);
    $forms = $xpath->query('//form');
    fncp_wp_integration_check($forms->length === 2, 'actual WordPress page renders exactly two mutation forms');
    $expectedNames = [
        ['action', '_fncp_nonce', '_wp_http_referer', 'round_id', 'subject', 'state'],
        ['action', '_fncp_nonce', '_wp_http_referer'],
    ];
    foreach ($forms as $index => $form) {
        $names = [];
        foreach ($xpath->query('.//input[@name] | .//select[@name] | .//textarea[@name] | .//button[@name]', $form) as $control) {
            $names[] = $control->getAttribute('name');
        }
        sort($names);
        sort($expectedNames[$index]);
        fncp_wp_integration_check($names === $expectedNames[$index], 'actual WordPress ' . ($index === 0 ? 'change' : 'retry') . ' rendered form matches exact POST whitelist');
    }

    if (getenv('FNCP_WP_AUTH_CHECK_ONLY') === '1') {
        echo "Real disposable WordPress authorization checks: {$checks} passed. No approval events were sent.\n";
        exit(0);
    }

    $journal = fncp_wp_local_journal();
    $key = 'synthetic_round_local:' . $fixture;
    if (isset($journal->snapshot()['subjects'][$key])) {
        throw new RuntimeException('Test fixture already has journal history; use a fresh pre-provisioned synthetic fixture.');
    }
    $approval = $journal->change('synthetic_round_local', $fixture, 'approved');
    fncp_wp_integration_check($approval['event']['version'] === 1, 'actual wp_options approval version and outbox persisted');
    fncp_wp_integration_check(fncp_wp_local_deliver($journal, $approval), 'actual signed approval acknowledged by local receiver');
    $reloaded = fncp_wp_local_journal();
    $same = $reloaded->change('synthetic_round_local', $fixture, 'approved');
    fncp_wp_integration_check($same['body'] === $approval['body'] && $same['delivered'], 'actual wp_options duplicate decision keeps body version and delivery');

    $revocation = $reloaded->change('synthetic_round_local', $fixture, 'revoked');
    fncp_wp_integration_check($revocation['event']['version'] === 2, 'actual wp_options revocation advances version');
    fncp_wp_integration_check(fncp_wp_local_deliver($reloaded, $revocation), 'actual signed revocation acknowledged by local receiver');
    $final = fncp_wp_local_journal()->snapshot();
    $latest = $final['events'][$final['subjects'][$key]['event_id']];
    fncp_wp_integration_check($latest['event']['state'] === 'revoked' && $latest['delivered'], 'actual restart-style journal read retains acknowledged revocation');
    $rejected = false;
    try { fncp_wp_local_journal()->change('synthetic_round_local', $fixture, 'approved'); } catch (RuntimeException $error) { $rejected = true; }
    fncp_wp_integration_check($rejected, 'actual journal terminal revocation cannot be reapproved');
    echo "Real disposable WordPress/local receiver checks: {$checks} passed. No email or public service used.\n";
} catch (Throwable $error) {
    fwrite(STDERR, "FAIL disposable WordPress integration: " . $error->getMessage() . "\n");
    fwrite(STDERR, "Synthetic journal evidence retained. Inspect/retry pending local revocation before reuse.\n");
    exit(1);
}
