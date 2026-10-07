<?php
/**
 * Plugin Name: FNCP Production Registration Bridge
 * Description: Configured-only immutable registrations, separate operator decisions and durable signed outbox. Does not open participation or send invitations.
 * Version: 1.0.0
 * Requires PHP: 8.2
 */
declare(strict_types=1);
if (!defined('ABSPATH')) { exit; }
require_once __DIR__ . '/store.php';
const FNCP_PRODUCTION_OPTION = 'fncp_production_wordpress_v1';
const FNCP_PRODUCTION_CAPABILITY = 'fncp_manage_registrations';

/** Configuration is private deployment material, never an option or HTTP input. */
function fncp_production_configuration(): array {
    if (!defined('FNCP_PRODUCTION_WORDPRESS_CONFIG_FILE') || !is_string(FNCP_PRODUCTION_WORDPRESS_CONFIG_FILE)) { FNCP_Production_Contract::deny(); }
    $path = FNCP_PRODUCTION_WORDPRESS_CONFIG_FILE; $s = @lstat($path);
    if (!str_starts_with($path, '/') || !$s || ($s['mode'] & 0170000) !== 0100000 || is_link($path) || realpath($path) !== $path
        || !in_array($s['mode'] & 0777, [0400,0600], true) || $s['size'] < 2 || $s['size'] > 16384 || !is_readable($path)) { FNCP_Production_Contract::deny(); }
    $raw = file_get_contents($path); $after = @lstat($path);
    if ($raw === false || !$after || $s['ino'] !== $after['ino'] || $s['dev'] !== $after['dev'] || strlen($raw) !== $s['size']) { FNCP_Production_Contract::deny(); }
    $c = json_decode($raw, true, 4, JSON_THROW_ON_ERROR); if (!is_array($c)) { FNCP_Production_Contract::deny(); } $c = FNCP_Production_Contract::configuration($c);
    $ca = $c['caFile']; $cs = @lstat($ca);
    if (!$cs || ($cs['mode'] & 0170000) !== 0100000 || is_link($ca) || realpath($ca) !== $ca || ($cs['mode'] & 0022) !== 0 || $cs['size'] < 1 || $cs['size'] > 65536 || !is_readable($ca)) { FNCP_Production_Contract::deny(); }
    $pem = file_get_contents($ca);
    if (!is_string($pem) || preg_match('/\A(?:-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+\/=\n]+\n-----END CERTIFICATE-----\n?)+\z/D', $pem) !== 1 || !function_exists('openssl_x509_read')) { FNCP_Production_Contract::deny(); }
    preg_match_all('/-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+\/=\n]+\n-----END CERTIFICATE-----/', $pem, $certs);
    foreach ($certs[0] as $certificate) { if (@openssl_x509_read($certificate) === false) { FNCP_Production_Contract::deny(); } }
    return $c;
}
function fncp_production_store(array $c): FNCP_Production_Store {
    global $wpdb; $name = FNCP_PRODUCTION_OPTION;
    $read = static function () use ($wpdb,$name): ?string {
        $v = $wpdb->get_var($wpdb->prepare("SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", $name));
        if ($wpdb->last_error !== '') { FNCP_Production_Contract::deny(); } return $v === null ? null : (string) $v;
    };
    $swap = static function (string $old,string $next) use ($wpdb,$name): bool {
        $n = $wpdb->query($wpdb->prepare("UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s AND BINARY option_value = %s", $next,$name,$old));
        if ($n === false) { FNCP_Production_Contract::deny(); } wp_cache_delete($name,'options'); return $n === 1;
    };
    return new FNCP_Production_Store($c,$read,$swap,static fn(string $raw): bool => add_option($name,$raw,'',false));
}
function fncp_production_https(array $c): void {
    $p = parse_url($c['wordpressOrigin']); $host = $p['host'] . (isset($p['port']) ? ':' . $p['port'] : '');
    if (!is_ssl() || ($_SERVER['HTTP_HOST'] ?? '') !== $host) { FNCP_Production_Contract::deny(); }
}
function fncp_production_rpc($request, string $action) {
    try {
        $c = fncp_production_configuration(); fncp_production_https($c);
        if ($request->get_method() !== 'POST' || $request->get_route() !== '/fncp/v1/' . $action || $request->get_query_params() !== []
            || $request->get_header('content-type') !== 'application/json' || $request->get_header('cookie') !== null || $request->get_header('origin') !== null
            || $request->get_header('sec-fetch-site') !== null || $request->get_header('authorization') !== null || !empty($_FILES)) { FNCP_Production_Contract::deny(); }
        $raw = $request->get_body(); $stamp = $request->get_header('x-fncp-timestamp'); $signature = $request->get_header('x-fncp-signature');
        // Authenticate before creating or changing durable state, then authenticate
        // again under the store's persisted clock and CAS authority. The outer
        // check intentionally does not read wall time: authenticated stale requests
        // still reach the durable rollback guard before freshness is rejected.
        FNCP_Production_Contract::authenticate($action,$raw,$stamp,$signature,$c);
        $value = fncp_production_store($c)->rpc($action,$raw,$stamp,$signature);
        return new WP_REST_Response($value,200,['Cache-Control'=>'no-store, private','Referrer-Policy'=>'no-referrer','X-Content-Type-Options'=>'nosniff']);
    } catch (Throwable $e) { return new WP_REST_Response(['error'=>'registration_unavailable'],503,['Cache-Control'=>'no-store, private']); }
}
function fncp_production_authorize(string $action,array $c): void {
    fncp_production_https($c);
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || !current_user_can(FNCP_PRODUCTION_CAPABILITY)
        || ($_SERVER['HTTP_ORIGIN'] ?? '') !== $c['wordpressOrigin'] || !empty($_GET) || !empty($_FILES)) { FNCP_Production_Contract::deny(); }
    check_admin_referer($action,'_fncp_nonce');
}
function fncp_production_deliver(FNCP_Production_Store $store,string $id,array $c): bool {
    $attempt = $store->delivery($id); if ($attempt === null) { return true; }
    $response = wp_remote_post($c['eventEndpoint'],['timeout'=>3,'redirection'=>0,'blocking'=>true,'sslverify'=>true,'sslcertificates'=>$c['caFile'],
        'cookies'=>[],'compress'=>false,'decompress'=>false,'limit_response_size'=>4096,'data_format'=>'body','stream'=>false,
        'headers'=>['Content-Type'=>'application/json','X-FNCP-Timestamp'=>$attempt['timestamp'],'X-FNCP-Event-ID'=>$attempt['event']['eventId'],'X-FNCP-Signature'=>$attempt['signature']],
        'body'=>$attempt['body']]);
    $ok = !is_wp_error($response) && FNCP_Production_Contract::acknowledged((int) wp_remote_retrieve_response_code($response),(string) wp_remote_retrieve_body($response),$attempt['event']);
    $store->deliveryResult($id,$ok,$ok ? 'ACKNOWLEDGED' : (is_wp_error($response) ? 'TRANSPORT_UNAVAILABLE' : 'ACK_REJECTED')); return $ok;
}
function fncp_production_admin_fields(array $required): void {
    $allowed = array_merge(['action','_fncp_nonce','_wp_http_referer'],$required);
    if (array_diff(array_keys($_POST),$allowed)) { FNCP_Production_Contract::deny(); }
    foreach (array_merge(['action','_fncp_nonce'],$required) as $k) { if (!isset($_POST[$k]) || !is_string($_POST[$k])) { FNCP_Production_Contract::deny(); } }
}
function fncp_production_decide(): void {
    try { $c=fncp_production_configuration(); fncp_production_authorize('fncp_production_decide',$c); fncp_production_admin_fields(['registration_id','state']);
        if ($_POST['action'] !== 'fncp_production_decide') { FNCP_Production_Contract::deny(); }
        $store=fncp_production_store($c); $record=$store->decide(wp_unslash($_POST['registration_id']),wp_unslash($_POST['state']));
        $ok=fncp_production_deliver($store,$record['event']['eventId'],$c); $value=['outcome'=>$ok?'ACKNOWLEDGED':'PENDING'];
    } catch (Throwable $e) { wp_send_json(['error'=>'registration_unavailable'],503); return; }
    nocache_headers(); wp_send_json($value,200);
}
function fncp_production_retry(): void {
    try { $c=fncp_production_configuration(); fncp_production_authorize('fncp_production_retry',$c); fncp_production_admin_fields([]);
        if ($_POST['action'] !== 'fncp_production_retry') { FNCP_Production_Contract::deny(); }
        $store=fncp_production_store($c); $pending=false;
        // One request handles at most four events: bounded12 seconds of transport.
        foreach (array_slice($store->pending(),0,4) as $record) { if (!fncp_production_deliver($store,$record['event']['eventId'],$c)) { $pending=true; } }
        $value=['outcome'=>$pending || count($store->pending())>0 ? 'PENDING':'ACKNOWLEDGED'];
    } catch (Throwable $e) { wp_send_json(['error'=>'registration_unavailable'],503); return; }
    nocache_headers(); wp_send_json($value,200);
}
function fncp_production_page(): void {
    if (!current_user_can(FNCP_PRODUCTION_CAPABILITY)) { wp_die('Registration permission required.','',['response'=>403]); return; }
    echo '<div class="wrap"><h1>Registration decisions</h1>';
    try { $c=fncp_production_configuration(); fncp_production_https($c); $rows=fncp_production_store($c)->adminRows(); }
    catch (Throwable $e) { echo '<p>Registration administration is unavailable. Participation remains subject to independent access controls.</p></div>'; return; }
    echo '<p>Registration records consent and self-attestation. It does not verify eligibility or Indigenous heritage. Approval is separate from invitation and round opening. Revocation is permanent for this round.</p>';
    echo '<p>A pending delivery is not an acknowledgement. Revoked registrations remain revoked while delivery is retried. No invitation or email is sent here.</p>';
    echo '<form method="post" action="'.esc_url(admin_url('admin-post.php')).'"><input type="hidden" name="action" value="fncp_production_decide">';
    wp_nonce_field('fncp_production_decide','_fncp_nonce'); echo '<label>Registered reference <select name="registration_id" required>';
    foreach ($rows as $r) { echo '<option value="'.esc_attr($r['registrationId']).'">'.esc_html($r['registrationId']).'</option>'; }
    echo '</select></label><label>Decision <select name="state"><option value="approved">Approve</option><option value="revoked">Revoke permanently</option></select></label>';
    submit_button('Record decision','primary',''); echo '</form><form method="post" action="'.esc_url(admin_url('admin-post.php')).'"><input type="hidden" name="action" value="fncp_production_retry">';
    wp_nonce_field('fncp_production_retry','_fncp_nonce'); submit_button('Retry pending delivery','secondary',''); echo '</form>';
    echo '<table class="widefat"><thead><tr><th>Reference</th><th>Notice version</th><th>Decision</th><th>Delivery</th></tr></thead><tbody>';
    foreach ($rows as $r) { echo '<tr><td>'.esc_html($r['registrationId']).'</td><td>'.esc_html($r['consentVersion']).'</td><td>'.esc_html($r['state']).'</td><td>'.esc_html($r['delivery']).'</td></tr>'; }
    echo '</tbody></table></div>';
}
add_action('rest_api_init',static function (): void {
    foreach (['register','status'] as $action) { register_rest_route('fncp/v1','/'.$action,['methods'=>'POST','permission_callback'=>'__return_true','callback'=>static fn($request)=>fncp_production_rpc($request,$action)]); }
});
add_action('admin_menu',static function (): void { add_management_page('Registration decisions','Registration decisions',FNCP_PRODUCTION_CAPABILITY,'fncp-production-registration','fncp_production_page'); });
add_action('admin_post_fncp_production_decide','fncp_production_decide');
add_action('admin_post_fncp_production_retry','fncp_production_retry');
// No anonymous decision hooks, activation side effects, cron, invitation or mail handlers.
