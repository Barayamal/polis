<?php
/**
 * Plugin Name: FNCP Synthetic Approval Bridge (LOCAL ONLY)
 * Description: Disposable local fixture approvals and signed local outbox. No registration, emails, eligibility or live participant data.
 * Version: 0.1.0
 * Requires at least: 6.2
 * Requires PHP: 8.1
 * License: AGPL-3.0-or-later
 */
declare(strict_types=1);
if (!defined('ABSPATH')) {
    exit;
}
require_once __DIR__ . '/journal.php';

const FNCP_WP_LOCAL_JOURNAL = 'fncp_wp_local_journal_v1';

function fncp_wp_local_enabled(): bool {
    return defined('FNCP_WP_SYNTHETIC_ONLY') && FNCP_WP_SYNTHETIC_ONLY === true
        && function_exists('wp_get_environment_type') && wp_get_environment_type() === 'local'
        && defined('FNCP_WP_LOCAL_EVENT_SECRET') && is_string(FNCP_WP_LOCAL_EVENT_SECRET)
        && preg_match('/\A[!-~]{32,256}\z/D', FNCP_WP_LOCAL_EVENT_SECRET) === 1;
}

function fncp_wp_local_journal(): FNCP_Local_Journal {
    global $wpdb;
    $read = static function () use ($wpdb): ?string {
        $raw = $wpdb->get_var($wpdb->prepare("SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", FNCP_WP_LOCAL_JOURNAL));
        if ($wpdb->last_error !== '') {
            throw new RuntimeException('Local journal read failed.');
        }
        return $raw === null ? null : (string) $raw;
    };
    $swap = static function (string $old, string $next) use ($wpdb): bool {
        $changed = $wpdb->query($wpdb->prepare(
            "UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s AND BINARY option_value = %s",
            $next, FNCP_WP_LOCAL_JOURNAL, $old
        ));
        if ($changed === false) {
            throw new RuntimeException('Local journal write failed.');
        }
        wp_cache_delete(FNCP_WP_LOCAL_JOURNAL, 'options');
        return $changed === 1;
    };
    return new FNCP_Local_Journal($read, $swap, static fn(string $raw): bool => add_option(FNCP_WP_LOCAL_JOURNAL, $raw, '', false));
}

function fncp_wp_local_authorize(string $operation): void {
    if (!fncp_wp_local_enabled()) {
        wp_die('Synthetic local bridge is disabled.', '', ['response' => 503]);
    }
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || !current_user_can('manage_options')) {
        wp_die('Local administrator POST permission is required.', '', ['response' => 403]);
    }
    check_admin_referer('fncp_wp_local_' . $operation, '_fncp_nonce');
}

function fncp_wp_local_deliver(FNCP_Local_Journal $journal, array $record): bool {
    if (!fncp_wp_local_enabled()) {
        throw new RuntimeException('Synthetic local bridge is disabled.');
    }
    FNCP_Local_Contract::assertEvent($record['event']);
    if ($record['body'] !== FNCP_Local_Contract::encode($record['event'])) {
        throw new RuntimeException('Immutable synthetic outbox body mismatch.');
    }
    if ($record['delivered']) {
        return true;
    }
    $timestamp = (string) time();
    $response = wp_remote_post(FNCP_Local_Contract::TARGET, [
        'timeout' => 3, 'redirection' => 0, 'blocking' => true, 'cookies' => [],
        'limit_response_size' => 4096, 'data_format' => 'body',
        'headers' => [
            'Content-Type' => 'application/json',
            'X-FNCP-WP-Timestamp' => $timestamp,
            'X-FNCP-WP-Event-ID' => $record['event']['event_id'],
            'X-FNCP-WP-Signature' => FNCP_Local_Contract::signature(FNCP_WP_LOCAL_EVENT_SECRET, $timestamp, $record['body']),
        ],
        'body' => $record['body'],
    ]);
    $accepted = !is_wp_error($response) && FNCP_Local_Contract::acknowledged(
        (int) wp_remote_retrieve_response_code($response), (string) wp_remote_retrieve_body($response), $record['event']
    );
    $result = $accepted ? 'ACKNOWLEDGED' : (is_wp_error($response) ? 'TRANSPORT_UNAVAILABLE' : 'ACK_REJECTED');
    $journal->deliveryResult($record['event']['event_id'], $accepted, $result);
    return $accepted;
}

function fncp_wp_local_field(string $name): string {
    if (!isset($_POST[$name]) || !is_string($_POST[$name])) {
        throw new InvalidArgumentException('Missing or invalid synthetic field.');
    }
    return wp_unslash($_POST[$name]);
}

function fncp_wp_local_change(): void {
    fncp_wp_local_authorize('change');
    try {
        $allowed = ['action', '_fncp_nonce', '_wp_http_referer', 'round_id', 'subject', 'state'];
        if (array_diff(array_keys($_POST), $allowed)) {
            throw new InvalidArgumentException('Only synthetic approval fields are accepted.');
        }
        $journal = fncp_wp_local_journal();
        $record = $journal->change(fncp_wp_local_field('round_id'), fncp_wp_local_field('subject'), fncp_wp_local_field('state'));
        $accepted = fncp_wp_local_deliver($journal, $record);
        wp_safe_redirect(admin_url('tools.php?page=fncp-local-approval&result=' . ($accepted ? 'acknowledged' : 'pending')));
        exit;
    } catch (Throwable $error) {
        // Never echo submitted fields, secrets, provider content, or raw database errors.
        wp_die('Local operation did not complete. Review the synthetic journal and retry only the pending operation.', '', ['response' => 409]);
    }
}

function fncp_wp_local_retry(): void {
    fncp_wp_local_authorize('retry');
    try {
        if (array_diff(array_keys($_POST), ['action', '_fncp_nonce', '_wp_http_referer'])) {
            throw new InvalidArgumentException('Retry accepts no participant fields.');
        }
        $journal = fncp_wp_local_journal();
        foreach ($journal->pending() as $record) {
            fncp_wp_local_deliver($journal, $record);
        }
        wp_safe_redirect(admin_url('tools.php?page=fncp-local-approval'));
        exit;
    } catch (Throwable $error) {
        wp_die('Local retry did not complete. Existing journal entries were preserved.', '', ['response' => 409]);
    }
}

function fncp_wp_local_page(): void {
    if (!current_user_can('manage_options')) {
        wp_die('Local administrator permission is required.', '', ['response' => 403]);
    }
    echo '<div class="wrap"><h1>FNCP synthetic approvals — LOCAL ONLY</h1>';
    echo '<p>This is not registration or heritage verification. Do not enter names, email addresses, evidence, or live participant information. Nothing is emailed. Only the fixed local receiver is used.</p>';
    if (!fncp_wp_local_enabled()) {
        echo '<p><strong>Disabled.</strong> The explicit synthetic flag, local environment and signing secret must all be configured in this disposable instance.</p></div>';
        return;
    }
    try {
        $snapshot = fncp_wp_local_journal()->snapshot();
    } catch (Throwable $error) {
        echo '<p>Journal unavailable. No changes are permitted.</p></div>';
        return;
    }
    echo '<p>Approvals are <strong>pending</strong> until the local receiver acknowledges them. A failed revocation delivery is not evidence that provider access has been removed. Close the local round while resolving any revocation delivery failure.</p>';
    echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
    echo '<input type="hidden" name="action" value="fncp_wp_local_change">';
    wp_nonce_field('fncp_wp_local_change', '_fncp_nonce');
    echo '<input type="hidden" name="round_id" value="synthetic_round_local"><p>Round: <code>synthetic_round_local</code></p>';
    echo '<p><label>Synthetic account <input name="subject" required pattern="synthetic_[a-z][a-z0-9_]{0,39}" maxlength="50" placeholder="synthetic_alice"></label></p>';
    echo '<p><label>Decision <select name="state"><option value="approved">Approve synthetic fixture</option><option value="revoked">Revoke synthetic fixture</option></select></label></p>';
    // WordPress defaults the button name to "submit". Keep it nameless so the
    // browser's successful controls match the narrow POST schema exactly.
    submit_button('Record and deliver locally', 'primary', '');
    echo '</form><form method="post" action="' . esc_url(admin_url('admin-post.php')) . '"><input type="hidden" name="action" value="fncp_wp_local_retry">';
    wp_nonce_field('fncp_wp_local_retry', '_fncp_nonce');
    submit_button('Retry pending local outbox', 'secondary', '');
    echo '</form><h2>Synthetic journal</h2><table class="widefat"><thead><tr><th>Round</th><th>Fixture</th><th>Version</th><th>Decision</th><th>Delivery</th></tr></thead><tbody>';
    foreach ($snapshot['subjects'] as $subject) {
        $record = $snapshot['events'][$subject['event_id']];
        $event = $record['event'];
        echo '<tr><td>' . esc_html($event['round_id']) . '</td><td>' . esc_html($event['subject']) . '</td><td>' . esc_html((string) $event['version']) . '</td><td>' . esc_html($event['state']) . '</td><td>' . esc_html($record['last_result']) . '</td></tr>';
    }
    echo '</tbody></table><p>No cleanup or deletion button is provided. This bounded local journal preserves synthetic evidence.</p></div>';
}

add_action('admin_menu', static function (): void {
    add_management_page('FNCP synthetic approvals', 'FNCP synthetic approvals', 'manage_options', 'fncp-local-approval', 'fncp_wp_local_page');
});
add_action('admin_post_fncp_wp_local_change', 'fncp_wp_local_change');
add_action('admin_post_fncp_wp_local_retry', 'fncp_wp_local_retry');
