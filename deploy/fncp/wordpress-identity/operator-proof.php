<?php
/** Private CLI setup for HTTP boundary tests. NOT a real operator login proof. */
declare(strict_types=1);
if (PHP_SAPI !== 'cli' || getenv('FNCP_LOCAL_SYNTHETIC_MODE') !== 'fixture-only') { exit(1); }
$load = getenv('FNCP_IDENTITY_WP_LOAD_PATH');
$root = getenv('FNCP_IDENTITY_RUNTIME_PATH');
if (!$load || !$root || realpath($load) !== $root . '/wordpress/wp-load.php') { exit(1); }
require $load;
if (!defined('FNCP_WP_IDENTITY_FRESH_INSTANCE') || FNCP_WP_IDENTITY_FRESH_INSTANCE !== true || wp_get_environment_type() !== 'local') { exit(1); }
$input = json_decode(stream_get_contents(STDIN), true, 16, JSON_THROW_ON_ERROR);
if (!is_array($input) || count($input) !== 1 || !in_array($input[0], ['operator-session', 'aggregate', 'close-guests'], true)) { exit(1); }
if ($input[0] === 'operator-session') {
    $admins = get_users(['role' => 'administrator', 'number' => 2]);
    if (count($admins) !== 1) { exit(1); }
    $id = (int) $admins[0]->ID;
    $expiry = time() + 300;
    $token = WP_Session_Tokens::get_instance($id)->create($expiry);
    $auth = wp_generate_auth_cookie($id, $expiry, 'auth', $token);
    $logged = wp_generate_auth_cookie($id, $expiry, 'logged_in', $token);
    $_COOKIE[LOGGED_IN_COOKIE] = $logged;
    wp_set_current_user($id);
    echo json_encode(['cookie' => AUTH_COOKIE . '=' . $auth . '; ' . LOGGED_IN_COOKIE . '=' . $logged,
        'nonce' => wp_create_nonce('fncp_identity_decide')], JSON_THROW_ON_ERROR);
} elseif ($input[0] === 'close-guests') {
    $registry = fncp_identity_registry()->snapshot(); $journal = fncp_identity_journal()->snapshot();
    $admins = get_users(['role' => 'administrator', 'number' => 2]);
    if (count($admins) !== 1 || count($registry['registrations']) !== 2 || count($journal['subjects']) !== 2
        || count(fncp_identity_journal()->pending()) !== 0) { exit(1); }
    foreach ($registry['registrations'] as $registration) {
        $subjectKey = $registration['roundId'] . ':' . $registration['fixture'];
        $head = $journal['subjects'][$subjectKey] ?? null;
        $entry = $head ? ($journal['events'][$head['event_id']] ?? null) : null;
        if (!$entry || $entry['event']['state'] !== 'revoked' || $entry['delivered'] !== true) { exit(1); }
    }
    $closed = fncp_identity_registry()->closeGuests();
    WP_Session_Tokens::get_instance((int)$admins[0]->ID)->destroy_all();
    if (WP_Session_Tokens::get_instance((int)$admins[0]->ID)->get_all() !== []) { exit(1); }
    echo json_encode($closed + ['operatorSessionsClosed' => true, 'terminalOnly' => true], JSON_THROW_ON_ERROR);
} else {
    // Aggregate only. The fresh instance is not live page 12064 / form 12069.
    global $wpdb;
    $registry = fncp_identity_registry()->snapshot();
    $journal = fncp_identity_journal()->snapshot();
    $terminal = 0;
    foreach ($journal['subjects'] as $subject) {
        $event = $journal['events'][$subject['event_id']];
        if ($event['event']['state'] === 'revoked' && $event['delivered'] === true) { $terminal++; }
    }
    echo json_encode(['freshInstance' => true, 'users' => (int)$wpdb->get_var("SELECT count(*) FROM {$wpdb->users}"),
        'registrations' => count($registry['registrations']), 'approvalSubjects' => count($journal['subjects']),
        'acknowledgedTerminalSubjects' => $terminal, 'pendingEvents' => count(fncp_identity_journal()->pending()),
        'legacyHandlerAbsent' => has_action('admin_post_fncp_wp_local_change') === false,
        'externalMailBlocked' => wp_mail('nobody@example.invalid', 'synthetic blocked', 'synthetic blocked') === false], JSON_THROW_ON_ERROR);
}
