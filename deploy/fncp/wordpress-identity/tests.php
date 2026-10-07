<?php
/** Pure PHP/CAS models and WP function stubs. No actual WP, files, DB or network. */
declare(strict_types=1);
ob_start();
require_once __DIR__ . '/registry.php';
const TEST_CHALLENGE_KEY = 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC';
const TEST_RECEIPT_KEY = 'RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR';
const TEST_FIXTURE = 'synthetic_iaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
$count = 0;
function verify(bool $condition): void { if (!$condition) { throw new RuntimeException('Synthetic assertion failed.'); } }
function rejects(callable $fn): void { try { $fn(); } catch (Throwable $error) { return; } throw new RuntimeException('Expected synthetic rejection.'); }
function runTest(string $name, callable $fn): void { global $count; $fn(); $count++; echo "PASS {$name}\n"; }

final class TestRegistryStore {
    public ?string $raw = null; public int $now = 1000; public $hook = null; public int $writes = 0;
    public function registry(): FNCP_Identity_Registry {
        return new FNCP_Identity_Registry(fn() => $this->raw,
            function (string $old, string $next): bool {
                if ($this->hook) { $hook = $this->hook; $this->hook = null; $hook(); }
                if ($old !== $this->raw) { return false; } $this->raw = $next; $this->writes++; return true;
            }, function (string $raw): bool { if ($this->raw !== null) { return false; } $this->raw = $raw; return true; }, fn() => $this->now);
    }
}
function guest(FNCP_Identity_Registry $registry): array {
    $binding = hash('sha256', FNCP_Identity_Contract::random()); $csrf = FNCP_Identity_Contract::random();
    verify($registry->session(null, $binding, $csrf)['created'] === true);
    return ['binding' => $binding, 'csrf' => $csrf];
}
function makeReceipt(array $challenge, string $binding, int $now, array $changes = []): array {
    $c = FNCP_Identity_Contract::readChallenge($challenge, TEST_CHALLENGE_KEY, $binding, $now);
    return FNCP_Identity_Contract::sign(array_replace(['schemaVersion' => 1, 'purpose' => 'wordpress-registration-receipt',
        'audience' => 'fncp-synthetic-wordpress', 'assertionId' => FNCP_Local_Contract::uuid(),
        'challengeId' => $c['challengeId'], 'browserBinding' => $binding,
        'challengeDigest' => hash('sha256', FNCP_Identity_Contract::canonical($challenge)), 'fixture' => TEST_FIXTURE,
        'roundId' => 'synthetic_round_local', 'issuedAt' => $now, 'expiresAt' => min($now + 60, $c['expiresAt']),
        'consentVersion' => 'synthetic-registration-v1', 'adultSelfAttested' => true, 'eligibilitySelfAttested' => true,
        'registrationConsent' => true], $changes), TEST_RECEIPT_KEY, FNCP_Identity_Contract::RECEIPT_DOMAIN);
}
function claim(FNCP_Identity_Registry $r, array $g, array $receipt): array {
    return $r->register($g['binding'], $g['csrf'], $receipt, TEST_CHALLENGE_KEY, TEST_RECEIPT_KEY,
        hash('sha256', FNCP_Identity_Contract::random()), FNCP_Identity_Contract::random());
}
function prepared(): array {
    $store = new TestRegistryStore(); $r = $store->registry(); $g = guest($r);
    $challenge = $r->challenge($g['binding'], $g['csrf'], TEST_CHALLENGE_KEY);
    return [$store, $r, $g, $challenge, makeReceipt($challenge, $g['binding'], $store->now)];
}

runTest('canonical signing uses sorted JSON and domain plus base64url payload', static function (): void {
    verify(FNCP_Identity_Contract::canonical(['z' => 1, 'a' => ['z' => true, 'a' => 2]]) === '{"a":{"a":2,"z":true},"z":1}');
    $signed = FNCP_Identity_Contract::sign(['b' => 2, 'a' => 1], TEST_CHALLENGE_KEY, FNCP_Identity_Contract::CHALLENGE_DOMAIN);
    verify($signed['payload'] === 'eyJhIjoxLCJiIjoyfQ');
    verify($signed['signature'] === hash_hmac('sha256', "FNCP_WP_CHALLENGE_SYNTHETIC_V1\neyJhIjoxLCJiIjoyfQ", TEST_CHALLENGE_KEY));
    verify(FNCP_Identity_Contract::verify($signed, TEST_CHALLENGE_KEY, FNCP_Identity_Contract::CHALLENGE_DOMAIN) === ['a' => 1, 'b' => 2]);
});
runTest('wrong key or domain, padded encoding, duplicate/noncanonical claims are denied', static function (): void {
    $envelope = FNCP_Identity_Contract::challenge(str_repeat('a', 64), 1000, TEST_CHALLENGE_KEY);
    rejects(static fn() => FNCP_Identity_Contract::verify($envelope, TEST_RECEIPT_KEY, FNCP_Identity_Contract::CHALLENGE_DOMAIN));
    rejects(static fn() => FNCP_Identity_Contract::verify($envelope, TEST_CHALLENGE_KEY, FNCP_Identity_Contract::RECEIPT_DOMAIN));
    foreach (['{"a":1,"a":2}', '{ "a":1}', '[1, 2]'] as $raw) {
        $payload = rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
        $bad = ['payload' => $payload, 'signature' => hash_hmac('sha256', FNCP_Identity_Contract::CHALLENGE_DOMAIN . $payload, TEST_CHALLENGE_KEY)];
        rejects(static fn() => FNCP_Identity_Contract::verify($bad, TEST_CHALLENGE_KEY, FNCP_Identity_Contract::CHALLENGE_DOMAIN));
    }
    $envelope['payload'] .= '='; rejects(static fn() => FNCP_Identity_Contract::verify($envelope, TEST_CHALLENGE_KEY, FNCP_Identity_Contract::CHALLENGE_DOMAIN));
});
runTest('successful atomic claim records consent time and rotates session without decision or personal content', static function (): void {
    [$store, $r, $g, $challenge, $receipt] = prepared(); $store->now += 4; $result = claim($r, $g, $receipt);
    $snapshot = $r->snapshot(); $entry = $r->registration($result['registrationId']);
    verify(count($snapshot['registrations']) === 1 && count($snapshot['assertions']) === 1 && count($snapshot['sessions']) === 1);
    verify(!isset($snapshot['sessions'][$g['binding']]) && $entry['acceptedAt'] === 1000 && $entry['createdAt'] === 1004);
    verify($entry['fixture'] === TEST_FIXTURE && $entry['registrationConsent'] === true);
    verify(!preg_match('/email|heritage|document|approved|password/i', FNCP_Identity_Contract::canonical($entry)));
    verify(current($snapshot['challenges'])['consumed'] === true);
    rejects(static fn() => claim($r, $g, $receipt)); verify(count($r->snapshot()['registrations']) === 1);
});
runTest('another guest cookie and copied CSRF cannot claim a signed receipt', static function (): void {
    [$store, $r, $g, $challenge, $receipt] = prepared(); $other = guest($r);
    rejects(static fn() => claim($r, $other, $receipt));
    rejects(static fn() => claim($r, ['binding' => $g['binding'], 'csrf' => $other['csrf']], $receipt));
    verify(count($r->snapshot()['registrations']) === 0); verify(isset(claim($r, $g, $receipt)['registrationId']));
});
runTest('reissued challenge burns old challenge without burning the new claim', static function (): void {
    [$store, $r, $g, $challenge, $receipt] = prepared(); $replacement = $r->challenge($g['binding'], $g['csrf'], TEST_CHALLENGE_KEY);
    rejects(static fn() => claim($r, $g, $receipt));
    verify(isset(claim($r, $g, makeReceipt($replacement, $g['binding'], $store->now))['registrationId']));
});
runTest('expiry, future issue, extended lifetime, wrong scope and false/string/array consent are rejected', static function (): void {
    [$store, $r, $g, $challenge] = prepared();
    foreach ([['issuedAt' => 1001], ['expiresAt' => 1061], ['expiresAt' => 1000], ['roundId' => 'wrong'],
        ['audience' => 'wrong'], ['purpose' => 'wordpress-registration-challenge'], ['consentVersion' => 'other'],
        ['adultSelfAttested' => false], ['eligibilitySelfAttested' => 'true'], ['registrationConsent' => ['true']],
        ['fixture' => 'synthetic_arbitrary'], ['challengeDigest' => str_repeat('f', 64)], ['email' => 'forbidden']] as $changes) {
        rejects(static fn() => claim($r, $g, makeReceipt($challenge, $g['binding'], $store->now, $changes)));
    }
    $receipt = makeReceipt($challenge, $g['binding'], $store->now); $store->now = 1060;
    rejects(static fn() => claim($r, $g, $receipt)); $store->now = 1120;
    rejects(static fn() => FNCP_Identity_Contract::readChallenge($challenge, TEST_CHALLENGE_KEY, $g['binding'], $store->now));
    verify(count($r->snapshot()['registrations']) === 0);
});
runTest('existing fixture and round cannot acquire another registration or be overwritten', static function (): void {
    [$store, $r, $g, $challenge, $receipt] = prepared(); $first = claim($r, $g, $receipt); $before = $r->registration($first['registrationId']);
    $other = guest($r); $c = $r->challenge($other['binding'], $other['csrf'], TEST_CHALLENGE_KEY);
    rejects(static fn() => claim($r, $other, makeReceipt($c, $other['binding'], $store->now)));
    verify($r->registration($first['registrationId']) === $before && count($r->snapshot()['registrations']) === 1);
});
runTest('CAS interleaving creates exactly one immutable registration for concurrent claims', static function (): void {
    [$store, $r, $g, $challenge, $receipt] = prepared(); $winner = null;
    $store->hook = static function () use ($r, $g, $receipt, &$winner): void { $winner = claim($r, $g, $receipt); };
    rejects(static fn() => claim($r, $g, $receipt));
    verify($winner !== null && count($r->snapshot()['registrations']) === 1 && count($r->snapshot()['assertions']) === 1);
});
runTest('pre-commit crash does not consume receipt; post-commit lost reply cannot duplicate registration', static function (): void {
    [$store, $r, $g, $challenge, $receipt] = prepared(); $before = $store->raw;
    $store->hook = static function (): void { throw new RuntimeException('Synthetic interruption.'); };
    rejects(static fn() => claim($r, $g, $receipt)); verify($before === $store->raw);
    claim($r, $g, $receipt); // Discard response as a simulated lost reply.
    rejects(static fn() => claim($r, $g, $receipt)); verify(count($r->snapshot()['registrations']) === 1);
});
runTest('clock expiry during CAS retry denies the formerly valid receipt', static function (): void {
    [$store, $r, $g, $challenge, $receipt] = prepared();
    $store->hook = static function () use ($store, $r): void { guest($r); $store->now = 1061; };
    rejects(static fn() => claim($r, $g, $receipt)); verify(count($r->snapshot()['registrations']) === 0);
});
runTest('guest capacity is bounded and expired sessions can be replaced without adoption', static function (): void {
    $store = new TestRegistryStore(); $r = $store->registry();
    for ($i = 0; $i < 64; $i++) { guest($r); }
    rejects(static fn() => guest($r)); verify(count($r->snapshot()['sessions']) === 64);
    $store->now += 301; guest($r); verify(count($r->snapshot()['sessions']) === 1);
});
runTest('registration capacity preserves existing immutable rows and rejects a twenty-first claim', static function (): void {
    $store = new TestRegistryStore(); $r = $store->registry();
    for ($i = 0; $i < 20; $i++) {
        $g = guest($r); $c = $r->challenge($g['binding'], $g['csrf'], TEST_CHALLENGE_KEY);
        claim($r, $g, makeReceipt($c, $g['binding'], $store->now, ['fixture' => 'synthetic_i' . substr(hash('sha256', 'invented' . $i), 0, 39)]));
    }
    $g = guest($r); $c = $r->challenge($g['binding'], $g['csrf'], TEST_CHALLENGE_KEY);
    rejects(static fn() => claim($r, $g, makeReceipt($c, $g['binding'], $store->now)));
    verify(count($r->snapshot()['registrations']) === 20);
});
runTest('corrupted index or registration facts fail closed rather than repairing authority', static function (): void {
    [$store, $r, $g, $challenge, $receipt] = prepared(); $registered = claim($r, $g, $receipt);
    $original = $store->raw; $value = json_decode($original, true, 16, JSON_THROW_ON_ERROR); $value['fixtureIndex'] = [];
    $store->raw = FNCP_Identity_Contract::canonical($value); rejects(static fn() => $r->snapshot());
    $value = json_decode($original, true, 16, JSON_THROW_ON_ERROR); $value['registrations'][$registered['registrationId']]['registrationConsent'] = false;
    $store->raw = FNCP_Identity_Contract::canonical($value); rejects(static fn() => $r->snapshot());
});

runTest('private guest quiescence preserves even expired replay evidence and immutable rows', static function (): void {
    [$store, $r, $g, $challenge, $receipt] = prepared(); claim($r, $g, $receipt);
    $extra = guest($r); $r->challenge($extra['binding'], $extra['csrf'], TEST_CHALLENGE_KEY);
    $before = $r->snapshot(); $store->now += 1000;
    $out = $r->closeGuests(); $after = $r->snapshot();
    verify($out['guestSessionsClosed'] === 2 && $after['sessions'] === []);
    foreach (['registrations', 'fixtureIndex', 'assertions'] as $key) { verify($after[$key] === $before[$key]); }
    verify(count($after['challenges']) === 2);
    foreach ($after['challenges'] as $c) { verify($c['consumed'] === true); }
    verify($r->closeGuests()['guestSessionsClosed'] === 0);
    rejects(static fn() => claim($r, $g, $receipt));
});
runTest('private guest quiescence preserves concurrent registration during CAS retry', static function (): void {
    [$store, $r, $g, $challenge, $receipt] = prepared();
    $store->hook = static function () use ($r, $g, $receipt): void { claim($r, $g, $receipt); };
    $r->closeGuests(); $after = $r->snapshot();
    verify(count($after['registrations']) === 1 && count($after['assertions']) === 1 && $after['sessions'] === []);
});

// WordPress boundary stubs: no WordPress installation or transport is used.
define('ABSPATH', __DIR__ . '/stub-only/'); define('FNCP_WP_SYNTHETIC_ONLY', true); define('FNCP_WP_IDENTITY_FRESH_INSTANCE', true);
define('FNCP_WP_IDENTITY_ORIGIN', 'http://127.0.0.1:18102'); define('FNCP_WP_CHALLENGE_SECRET', TEST_CHALLENGE_KEY);
define('FNCP_BFF_REGISTRATION_SECRET', TEST_RECEIPT_KEY); define('FNCP_WP_LOCAL_EVENT_SECRET', str_repeat('E', 64));
$GLOBALS['identity_environment'] = 'local'; $GLOBALS['identity_capability'] = false; $GLOBALS['identity_nonce'] = false;
$GLOBALS['identity_hooks'] = []; $GLOBALS['identity_options'] = []; $GLOBALS['identity_http'] = []; $GLOBALS['identity_result'] = 'ack';
final class IdentityStubJson extends RuntimeException { public function __construct(public array $body, public int $status) { parent::__construct('Stub response.'); } }
final class IdentityStubWpError {}
final class IdentityStubDb {
    public string $options = 'synthetic_options'; public string $last_error = '';
    public function prepare(string $sql, ...$args): array { return ['sql' => $sql, 'args' => $args]; }
    public function get_var(array $q): ?string { return $GLOBALS['identity_options'][$q['args'][0]] ?? null; }
    public function query(array $q): int {
        verify(str_contains($q['sql'], 'AND BINARY option_value = %s'));
        [$next, $name, $old] = $q['args']; if (($GLOBALS['identity_options'][$name] ?? null) !== $old) { return 0; }
        $GLOBALS['identity_options'][$name] = $next; return 1;
    }
}
$wpdb = new IdentityStubDb();
function wp_get_environment_type(): string { return $GLOBALS['identity_environment']; }
function current_user_can(string $cap): bool { verify($cap === 'manage_options'); return $GLOBALS['identity_capability']; }
function check_admin_referer(string $action, string $name): void {
    verify(in_array($action, ['fncp_identity_decide', 'fncp_identity_retry'], true) && $name === '_fncp_nonce');
    if (!$GLOBALS['identity_nonce']) { throw new FNCP_Identity_HttpError(403); }
}
function wp_send_json(array $value, int $status): void { throw new IdentityStubJson($value, $status); }
function wp_die(string $message, string $title = '', array $args = []): void { throw new FNCP_Identity_HttpError($args['response'] ?? 500); }
function add_action(string $hook, $fn): void { $GLOBALS['identity_hooks'][$hook] = $fn; }
function add_option(string $name, string $raw, string $legacy, bool $autoload): bool {
    verify(!$autoload); if (isset($GLOBALS['identity_options'][$name])) { return false; } $GLOBALS['identity_options'][$name] = $raw; return true;
}
function wp_cache_delete(string $name, string $group): void {}
function wp_unslash(string $v): string { return stripslashes($v); }
function is_wp_error($v): bool { return $v instanceof IdentityStubWpError; }
function wp_remote_retrieve_response_code(array $v): int { return $v['status']; }
function wp_remote_retrieve_body(array $v): string { return $v['body']; }
function wp_remote_post(string $url, array $options) {
    $GLOBALS['identity_http'][] = [$url, $options]; if ($GLOBALS['identity_result'] === 'transport') { return new IdentityStubWpError(); }
    $event = json_decode($options['body'], true, 8, JSON_THROW_ON_ERROR);
    return ['status' => 200, 'body' => json_encode(['ok' => true, 'event_id' => $event['event_id'], 'version' => $GLOBALS['identity_result'] === 'ack' ? $event['version'] : 999])];
}
function esc_html(string $v): string { return htmlspecialchars($v, ENT_QUOTES); }
function esc_attr(string $v): string { return esc_html($v); }
function esc_url(string $v): string { return esc_html($v); }
function admin_url(string $path): string { return FNCP_WP_IDENTITY_ORIGIN . '/wp-admin/' . $path; }
function wp_nonce_field(string $action, string $name): void { echo '<input name="' . $name . '" value="synthetic-nonce">'; }
function submit_button(string $title, string $class, string $name): void { verify($name === ''); echo '<button>' . esc_html($title) . '</button>'; }
require_once __DIR__ . '/fncp-wordpress-identity.php';
function webContext(string $method = 'POST'): void {
    $_GET = []; $_POST = []; $_FILES = [];
    $_SERVER = ['REQUEST_METHOD' => $method, 'REMOTE_ADDR' => '127.0.0.1', 'HTTP_HOST' => '127.0.0.1:18102',
        'HTTP_ORIGIN' => FNCP_WP_IDENTITY_ORIGIN, 'CONTENT_TYPE' => 'application/x-www-form-urlencoded;charset=UTF-8', 'CONTENT_LENGTH' => '256', 'HTTP_SEC_FETCH_SITE' => 'same-origin'];
}
function response(callable $fn): IdentityStubJson {
    try { $fn(); } catch (IdentityStubJson $res) { return $res; } throw new RuntimeException('Missing stub response.');
}
runTest('new plugin has no legacy arbitrary-subject hook; anonymous decisions use guarded deny handlers', static function (): void {
    verify(!isset($GLOBALS['identity_hooks']['admin_post_fncp_wp_local_change']) && !function_exists('fncp_wp_local_change'));
    foreach (['session', 'challenge', 'register', 'decide', 'retry'] as $name) {
        verify(isset($GLOBALS['identity_hooks']['admin_post_fncp_identity_' . $name], $GLOBALS['identity_hooks']['admin_post_nopriv_fncp_identity_' . $name]));
    }
});
runTest('environment guard refuses production, staging and development', static function (): void {
    foreach (['production', 'staging', 'development'] as $environment) { $GLOBALS['identity_environment'] = $environment; verify(!fncp_identity_enabled()); }
    $GLOBALS['identity_environment'] = 'local'; verify(fncp_identity_enabled());
});
runTest('exact local Origin/Host, form content type and POST body limit are enforced', static function (): void {
    foreach ([['HTTP_ORIGIN', 'http://evil.invalid'], ['HTTP_HOST', 'localhost:18102'], ['REMOTE_ADDR', '::1'],
        ['HTTP_SEC_FETCH_SITE', 'same-site'], ['CONTENT_TYPE', 'application/json'], ['CONTENT_LENGTH', '16385']] as [$key, $value]) {
        webContext(); $_SERVER[$key] = $value; rejects(static fn() => fncp_identity_http('POST'));
    }
    webContext(); fncp_identity_http('POST'); $_GET = ['action' => 'duplicated']; rejects(static fn() => fncp_identity_http('POST'));
});
runTest('duplicate guest cookies, unapproved fields and array injection fail closed', static function (): void {
    webContext(); $cookie = FNCP_Identity_Contract::random(); $_SERVER['HTTP_COOKIE'] = "fncp_wp_identity={$cookie}; fncp_wp_identity={$cookie}";
    rejects(static fn() => fncp_identity_binding());
    rejects(static fn() => fncp_identity_fields(['action' => 'fncp_identity_challenge', 'csrfToken' => []], 'fncp_identity_challenge', ['csrfToken']));
    rejects(static fn() => fncp_identity_fields(['action' => 'fncp_identity_decide', '_fncp_nonce' => 'x', 'registration_id' => 'x', 'state' => 'approved', 'subject' => TEST_FIXTURE], 'fncp_identity_decide', ['_fncp_nonce', 'registration_id', 'state']));
});
runTest('guest CSRF and forged receipt failures are deliberate403 with no registration or send', static function (): void {
    webContext(); $cookie = FNCP_Identity_Contract::random(); $csrf = FNCP_Identity_Contract::random(); $binding = hash('sha256', $cookie);
    fncp_identity_registry()->session(null, $binding, $csrf); $_SERVER['HTTP_COOKIE'] = 'fncp_wp_identity=' . $cookie;
    $_POST = ['action' => 'fncp_identity_challenge', 'csrfToken' => str_repeat('x', 43)]; verify(response('fncp_identity_challenge')->status === 403);
    $_POST['csrfToken'] = $csrf; $challenge = response('fncp_identity_challenge')->body['challenge'];
    $receipt = makeReceipt($challenge, $binding, time()); $receipt['signature'] = str_repeat('0', 64);
    $_POST = ['action' => 'fncp_identity_register', 'csrfToken' => $csrf, 'receipt' => addslashes(json_encode($receipt))];
    verify(response('fncp_identity_register')->status === 403);
    verify(fncp_identity_registry()->snapshot()['registrations'] === [] && $GLOBALS['identity_http'] === []);
});
runTest('subscriber and administrator without nonce cannot make a decision', static function (): void {
    webContext(); $_POST = ['action' => 'fncp_identity_decide', '_fncp_nonce' => 'x', 'registration_id' => FNCP_Local_Contract::uuid(), 'state' => 'approved'];
    $GLOBALS['identity_capability'] = false; $GLOBALS['identity_nonce'] = true; verify(response('fncp_identity_decide')->status === 403);
    $GLOBALS['identity_capability'] = true; $GLOBALS['identity_nonce'] = false; verify(response('fncp_identity_decide')->status === 403);
    $GLOBALS['identity_nonce'] = true; verify(response('fncp_identity_decide')->status === 409);
    verify($GLOBALS['identity_http'] === []);
});
runTest('registration endpoint persists only validated facts and admin lookup signs immutable outbox event', static function (): void {
    webContext(); $cookie = FNCP_Identity_Contract::random(); $csrf = FNCP_Identity_Contract::random(); $binding = hash('sha256', $cookie);
    fncp_identity_registry()->session(null, $binding, $csrf); $_SERVER['HTTP_COOKIE'] = 'fncp_wp_identity=' . $cookie;
    $_POST = ['action' => 'fncp_identity_challenge', 'csrfToken' => $csrf]; $challenge = response('fncp_identity_challenge')->body['challenge'];
    $_POST = ['action' => 'fncp_identity_register', 'csrfToken' => $csrf, 'receipt' => addslashes(json_encode(makeReceipt($challenge, $binding, time())))];
    $registered = response('fncp_identity_register'); verify($registered->status === 200 && $registered->body['registered'] === true);
    verify(!isset($registered->body['fixture']) && $registered->body['csrfToken'] !== $csrf && $GLOBALS['identity_http'] === []);
    verify(response('fncp_identity_register')->status === 403);
    $_POST = ['action' => 'fncp_identity_decide', '_fncp_nonce' => 'synthetic-nonce', 'registration_id' => $registered->body['registrationId'], 'state' => 'approved'];
    $decision = response('fncp_identity_decide'); verify($decision->status === 200 && $decision->body['outcome'] === 'ACKNOWLEDGED');
    [$target, $request] = $GLOBALS['identity_http'][0]; verify($target === FNCP_Local_Contract::TARGET && $request['redirection'] === 0 && $request['cookies'] === []);
    verify($request['headers']['X-FNCP-WP-Signature'] === FNCP_Local_Contract::signature(FNCP_WP_LOCAL_EVENT_SECRET, $request['headers']['X-FNCP-WP-Timestamp'], $request['body']));
    $event = json_decode($request['body'], true, 8, JSON_THROW_ON_ERROR); verify($event['subject'] === TEST_FIXTURE && $event['version'] === 1);
    response('fncp_identity_decide'); verify(count($GLOBALS['identity_http']) === 1);
    $GLOBALS['identity_result'] = 'transport'; $_POST['state'] = 'revoked'; verify(response('fncp_identity_decide')->body['outcome'] === 'PENDING');
    $_POST['state'] = 'approved'; verify(response('fncp_identity_decide')->status === 409);
    $GLOBALS['identity_result'] = 'ack'; $_POST = ['action' => 'fncp_identity_retry', '_fncp_nonce' => 'synthetic-nonce'];
    verify(response('fncp_identity_retry')->body['outcome'] === 'ACKNOWLEDGED');
    verify($GLOBALS['identity_http'][1][1]['body'] === $GLOBALS['identity_http'][2][1]['body']);
});
runTest('admin UI offers only registered references and does not disclose fixture or arbitrary-subject input', static function (): void {
    ob_start(); fncp_identity_page(); $html = ob_get_clean();
    verify(str_contains($html, 'name="registration_id"') && !str_contains($html, 'name="subject"') && !str_contains($html, TEST_FIXTURE));
    verify(str_contains($html, 'fncp_identity_decide') && str_contains($html, 'fncp_identity_retry') && str_contains($html, 'not heritage'));
});
echo "PASS total={$count}; pure PHP and WordPress-stub evidence only; no network or live records\n";
ob_end_flush();
