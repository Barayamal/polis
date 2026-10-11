<?php
/**
 * Plugin Name: FNCP Synthetic Registered Identity (FRESH LOCAL ONLY)
 * Description: Disposable signed registration receipts and registered-reference approvals. No real participants, heritage verification, email or launch authority.
 * Version: 0.1.0
 * Requires at least: 6.2
 * Requires PHP: 8.1
 * License: AGPL-3.0-or-later
 */
declare(strict_types=1);
if (!defined('ABSPATH')) { exit; }
require_once __DIR__ . '/registry.php';
require_once __DIR__ . '/../wordpress-local/journal.php';

const FNCP_IDENTITY_COOKIE = 'fncp_wp_identity';
const FNCP_IDENTITY_REGISTRY = 'fncp_wp_identity_registry_v1';
const FNCP_IDENTITY_JOURNAL = 'fncp_wp_identity_approval_journal_v1';

final class FNCP_Identity_HttpError extends RuntimeException {
    public int $status;
    public function __construct(int $status) { parent::__construct('Synthetic registration request rejected.'); $this->status = $status; }
}
function fncp_identity_enabled(): bool {
    if (!defined('FNCP_WP_SYNTHETIC_ONLY') || FNCP_WP_SYNTHETIC_ONLY !== true
        || !defined('FNCP_WP_IDENTITY_FRESH_INSTANCE') || FNCP_WP_IDENTITY_FRESH_INSTANCE !== true
        || !function_exists('wp_get_environment_type') || wp_get_environment_type() !== 'local'
        || function_exists('fncp_wp_local_change') || !defined('FNCP_WP_IDENTITY_ORIGIN')
        || !is_string(FNCP_WP_IDENTITY_ORIGIN) || preg_match('/\Ahttp:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})\z/D', FNCP_WP_IDENTITY_ORIGIN, $port) !== 1
        || (int) $port[1] > 65535) { return false; }
    foreach (['FNCP_WP_CHALLENGE_SECRET', 'FNCP_BFF_REGISTRATION_SECRET', 'FNCP_WP_LOCAL_EVENT_SECRET'] as $name) {
        if (!defined($name) || !is_string(constant($name)) || !FNCP_Identity_Contract::secret(constant($name))) { return false; }
    }
    return count(array_unique([FNCP_WP_CHALLENGE_SECRET, FNCP_BFF_REGISTRATION_SECRET, FNCP_WP_LOCAL_EVENT_SECRET])) === 3;
}
/** Direct byte-exact CAS: never use an options-cache snapshot as authority. */
function fncp_identity_storage(string $name): array {
    if (!in_array($name, [FNCP_IDENTITY_REGISTRY, FNCP_IDENTITY_JOURNAL], true)) { throw new RuntimeException('Invalid local option.'); }
    global $wpdb;
    $read = static function () use ($wpdb, $name): ?string {
        $raw = $wpdb->get_var($wpdb->prepare("SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", $name));
        if ($wpdb->last_error !== '') { throw new RuntimeException('Local registry read failed.'); }
        return $raw === null ? null : (string) $raw;
    };
    $swap = static function (string $old, string $next) use ($wpdb, $name): bool {
        $changed = $wpdb->query($wpdb->prepare("UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s AND BINARY option_value = %s", $next, $name, $old));
        if ($changed === false) { throw new RuntimeException('Local registry write failed.'); }
        wp_cache_delete($name, 'options'); return $changed === 1;
    };
    return [$read, $swap, static fn(string $raw): bool => add_option($name, $raw, '', false)];
}
function fncp_identity_registry(): FNCP_Identity_Registry { return new FNCP_Identity_Registry(...fncp_identity_storage(FNCP_IDENTITY_REGISTRY)); }
function fncp_identity_journal(): FNCP_Local_Journal { return new FNCP_Local_Journal(...fncp_identity_storage(FNCP_IDENTITY_JOURNAL)); }

function fncp_identity_http(string $method): void {
    if (!fncp_identity_enabled()) { throw new FNCP_Identity_HttpError(503); }
    if (($_SERVER['REMOTE_ADDR'] ?? '') !== '127.0.0.1' || ($_SERVER['HTTP_HOST'] ?? '') !== substr(FNCP_WP_IDENTITY_ORIGIN, 7)
        || ($_SERVER['REQUEST_METHOD'] ?? '') !== $method || !empty($_FILES)
        || isset($_SERVER['HTTP_AUTHORIZATION']) || isset($_SERVER['HTTP_X_FNCP_GATEWAY_KEY'])) { throw new FNCP_Identity_HttpError(403); }
    $site = $_SERVER['HTTP_SEC_FETCH_SITE'] ?? null;
    if ($site !== null && !in_array($site, ['same-origin', 'none'], true)) { throw new FNCP_Identity_HttpError(403); }
    if (isset($_SERVER['HTTP_ORIGIN']) && $_SERVER['HTTP_ORIGIN'] !== FNCP_WP_IDENTITY_ORIGIN) { throw new FNCP_Identity_HttpError(403); }
    if ($method === 'POST') {
        $type = trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? '')[0]);
        if (($_SERVER['HTTP_ORIGIN'] ?? '') !== FNCP_WP_IDENTITY_ORIGIN || !empty($_GET)) { throw new FNCP_Identity_HttpError(403); }
        if ($type !== 'application/x-www-form-urlencoded') { throw new FNCP_Identity_HttpError(415); }
        if (!isset($_SERVER['CONTENT_LENGTH']) || !ctype_digit((string) $_SERVER['CONTENT_LENGTH'])
            || (int) $_SERVER['CONTENT_LENGTH'] > 16384) { throw new FNCP_Identity_HttpError(413); }
    }
}
function fncp_identity_fields(array $fields, string $action, array $required, array $optional = []): void {
    if (($fields['action'] ?? null) !== $action || array_diff(array_keys($fields), array_merge(['action'], $required, $optional))) {
        throw new FNCP_Identity_HttpError(400);
    }
    foreach ($required as $name) { if (!isset($fields[$name]) || !is_string($fields[$name])) { throw new FNCP_Identity_HttpError(400); } }
    foreach ($optional as $name) { if (isset($fields[$name]) && !is_string($fields[$name])) { throw new FNCP_Identity_HttpError(400); } }
}
function fncp_identity_field(string $name): string { return wp_unslash($_POST[$name]); }
function fncp_identity_binding(): ?string {
    $matches = [];
    foreach (explode(';', $_SERVER['HTTP_COOKIE'] ?? '') as $part) {
        $part = trim($part);
        if (str_starts_with($part, FNCP_IDENTITY_COOKIE . '=')) { $matches[] = substr($part, strlen(FNCP_IDENTITY_COOKIE) + 1); }
    }
    if (count($matches) > 1 || (count($matches) === 1 && !FNCP_Identity_Contract::opaque($matches[0]))) { throw new FNCP_Identity_HttpError(400); }
    return $matches ? hash('sha256', $matches[0]) : null;
}
function fncp_identity_current_binding(): string {
    $binding = fncp_identity_binding(); if ($binding === null) { throw new FNCP_Identity_HttpError(403); } return $binding;
}
function fncp_identity_cookie(string $cookie): void {
    if (!setcookie(FNCP_IDENTITY_COOKIE, $cookie, ['expires' => time() + 300, 'path' => '/', 'httponly' => true, 'samesite' => 'Strict', 'secure' => false])) {
        throw new RuntimeException('Local guest cookie could not be delivered.');
    }
}
function fncp_identity_json(array $value, int $status = 200): void {
    header('Cache-Control: no-store, private'); header('Pragma: no-cache'); header('Referrer-Policy: no-referrer');
    header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'"); header('X-Content-Type-Options: nosniff');
    wp_send_json(['mode' => 'SYNTHETIC_ONLY'] + $value, $status);
}
function fncp_identity_endpoint(callable $operation): void {
    $status = 200;
    try { $value = $operation(); }
    catch (Throwable $error) { $status = $error instanceof FNCP_Identity_HttpError ? $error->status
        : (($error instanceof FNCP_Identity_Denied || $error instanceof InvalidArgumentException || $error instanceof JsonException) ? 403 : 409);
        $value = ['error' => 'Synthetic local operation rejected. No voting authority was granted.']; }
    fncp_identity_json($value, $status);
}
function fncp_identity_session(): void {
    fncp_identity_endpoint(static function (): array {
        fncp_identity_http('GET'); fncp_identity_fields($_GET, 'fncp_identity_session', []);
        $cookie = FNCP_Identity_Contract::random();
        $session = fncp_identity_registry()->session(fncp_identity_binding(), hash('sha256', $cookie), FNCP_Identity_Contract::random());
        if ($session['created']) { fncp_identity_cookie($cookie); }
        return ['csrfToken' => $session['csrfToken']];
    });
}
function fncp_identity_challenge(): void {
    fncp_identity_endpoint(static function (): array {
        fncp_identity_http('POST'); fncp_identity_fields($_POST, 'fncp_identity_challenge', ['csrfToken']);
        return ['challenge' => fncp_identity_registry()->challenge(fncp_identity_current_binding(), fncp_identity_field('csrfToken'), FNCP_WP_CHALLENGE_SECRET)];
    });
}
function fncp_identity_register(): void {
    fncp_identity_endpoint(static function (): array {
        fncp_identity_http('POST'); fncp_identity_fields($_POST, 'fncp_identity_register', ['csrfToken', 'receipt']);
        $raw = fncp_identity_field('receipt');
        if (strlen($raw) > 10000) { throw new FNCP_Identity_HttpError(413); }
        $receipt = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        if (!is_array($receipt)) { throw new FNCP_Identity_HttpError(400); }
        $cookie = FNCP_Identity_Contract::random(); $csrf = FNCP_Identity_Contract::random();
        $result = fncp_identity_registry()->register(fncp_identity_current_binding(), fncp_identity_field('csrfToken'), $receipt,
            FNCP_WP_CHALLENGE_SECRET, FNCP_BFF_REGISTRATION_SECRET, hash('sha256', $cookie), $csrf);
        fncp_identity_cookie($cookie);
        return ['registered' => true, 'registrationId' => $result['registrationId'], 'csrfToken' => $result['csrfToken']];
    });
}
function fncp_identity_admin(string $action): void {
    fncp_identity_http('POST');
    if (!current_user_can('manage_options')) { throw new FNCP_Identity_HttpError(403); }
    check_admin_referer($action, '_fncp_nonce');
}
function fncp_identity_deliver(FNCP_Local_Journal $journal, array $record): bool {
    if (!fncp_identity_enabled()) { throw new RuntimeException('Synthetic identity bridge disabled.'); }
    FNCP_Local_Contract::assertEvent($record['event']);
    if ($record['body'] !== FNCP_Local_Contract::encode($record['event'])) { throw new RuntimeException('Immutable outbox mismatch.'); }
    if ($record['delivered']) { return true; }
    $stamp = (string) time();
    $response = wp_remote_post(FNCP_Local_Contract::TARGET, ['timeout' => 3, 'redirection' => 0, 'blocking' => true,
        'cookies' => [], 'limit_response_size' => 4096, 'data_format' => 'body',
        'headers' => ['Content-Type' => 'application/json', 'X-FNCP-WP-Timestamp' => $stamp,
            'X-FNCP-WP-Event-ID' => $record['event']['event_id'], 'X-FNCP-WP-Signature' => FNCP_Local_Contract::signature(FNCP_WP_LOCAL_EVENT_SECRET, $stamp, $record['body'])],
        'body' => $record['body']]);
    $accepted = !is_wp_error($response) && FNCP_Local_Contract::acknowledged((int) wp_remote_retrieve_response_code($response), (string) wp_remote_retrieve_body($response), $record['event']);
    $journal->deliveryResult($record['event']['event_id'], $accepted, $accepted ? 'ACKNOWLEDGED' : (is_wp_error($response) ? 'TRANSPORT_UNAVAILABLE' : 'ACK_REJECTED'));
    return $accepted;
}
function fncp_identity_decide(): void {
    fncp_identity_endpoint(static function (): array {
        fncp_identity_admin('fncp_identity_decide');
        fncp_identity_fields($_POST, 'fncp_identity_decide', ['_fncp_nonce', 'registration_id', 'state'], ['_wp_http_referer']);
        $registration = fncp_identity_registry()->registration(fncp_identity_field('registration_id'));
        $journal = fncp_identity_journal();
        $record = $journal->change($registration['roundId'], $registration['fixture'], fncp_identity_field('state'));
        return ['outcome' => fncp_identity_deliver($journal, $record) ? 'ACKNOWLEDGED' : 'PENDING'];
    });
}
function fncp_identity_retry(): void {
    fncp_identity_endpoint(static function (): array {
        fncp_identity_admin('fncp_identity_retry'); fncp_identity_fields($_POST, 'fncp_identity_retry', ['_fncp_nonce'], ['_wp_http_referer']);
        $journal = fncp_identity_journal(); $pending = false;
        foreach ($journal->pending() as $record) { if (!fncp_identity_deliver($journal, $record)) { $pending = true; } }
        return ['outcome' => $pending || count($journal->pending()) > 0 ? 'PENDING' : 'ACKNOWLEDGED'];
    });
}
function fncp_identity_page(): void {
    if (!current_user_can('manage_options')) { wp_die('Local administrator permission required.', '', ['response' => 403]); }
    echo '<div class="wrap"><h1>Synthetic registered identities — FRESH LOCAL ONLY</h1>';
    echo '<p>Registration records self-attestation, not heritage or age verification. A signed receipt grants no voting access. No email or participant message is sent. No unlink or deletion action is provided.</p>';
    if (!fncp_identity_enabled()) { echo '<p>Disabled: explicit fresh synthetic instance and independent local keys required.</p></div>'; return; }
    try { $registrations = fncp_identity_registry()->snapshot()['registrations']; $journal = fncp_identity_journal()->snapshot(); }
    catch (Throwable $error) { echo '<p>Registry unavailable. No changes permitted.</p></div>'; return; }
    echo '<p>Approvals remain pending until acknowledged. Failed revocation delivery does not prove provider removal: close the local round while resolving it. These decisions are not launch authority.</p>';
    echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '"><input type="hidden" name="action" value="fncp_identity_decide">';
    wp_nonce_field('fncp_identity_decide', '_fncp_nonce');
    echo '<label>Registered reference <select name="registration_id" required>';
    foreach ($registrations as $id => $entry) { echo '<option value="' . esc_attr($id) . '">' . esc_html($id) . '</option>'; }
    echo '</select></label><label> Decision <select name="state"><option value="approved">Approve synthetic registration</option><option value="revoked">Revoke synthetic registration</option></select></label>';
    submit_button('Record and deliver locally', 'primary', ''); echo '</form>';
    echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '"><input type="hidden" name="action" value="fncp_identity_retry">';
    wp_nonce_field('fncp_identity_retry', '_fncp_nonce'); submit_button('Retry immutable local outbox', 'secondary', ''); echo '</form>';
    echo '<h2>Registered references</h2><table class="widefat"><thead><tr><th>Reference</th><th>Round</th><th>Consent notice</th><th>Decision / delivery</th></tr></thead><tbody>';
    foreach ($registrations as $id => $entry) {
        $subject = $journal['subjects'][$entry['roundId'] . ':' . $entry['fixture']] ?? null;
        $event = $subject === null ? null : $journal['events'][$subject['event_id']];
        echo '<tr><td>' . esc_html($id) . '</td><td>' . esc_html($entry['roundId']) . '</td><td>' . esc_html($entry['consentVersion']) . '</td><td>'
            . esc_html($event === null ? 'NOT_APPROVED' : $event['event']['state'] . ' / ' . $event['last_result']) . '</td></tr>';
    }
    echo '</tbody></table></div>';
}

add_action('admin_menu', static function (): void { add_management_page('Synthetic registrations', 'Synthetic registrations', 'manage_options', 'fncp-identity-registration', 'fncp_identity_page'); });
foreach (['session', 'challenge', 'register'] as $operation) {
    add_action('admin_post_fncp_identity_' . $operation, 'fncp_identity_' . $operation);
    add_action('admin_post_nopriv_fncp_identity_' . $operation, 'fncp_identity_' . $operation);
}
add_action('admin_post_fncp_identity_decide', 'fncp_identity_decide');
add_action('admin_post_fncp_identity_retry', 'fncp_identity_retry');
// These anonymous hooks only reach the same mandatory administrator check.
add_action('admin_post_nopriv_fncp_identity_decide', 'fncp_identity_decide');
add_action('admin_post_nopriv_fncp_identity_retry', 'fncp_identity_retry');
