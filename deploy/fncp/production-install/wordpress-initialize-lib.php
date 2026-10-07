<?php
declare(strict_types=1);
/** Maintenance-only, side-effect-free validation. Never loaded by normal HTTP. */
function fncp_initialize_deny(): never { throw new RuntimeException('initialization_rejected'); }
function fncp_initialize_exact(array $value, array $keys): void {
    $actual = array_keys($value); sort($actual); sort($keys); if ($actual !== $keys) { fncp_initialize_deny(); }
}
function fncp_initialize_canonical(array $value): string {
    $sort = static function ($v) use (&$sort) { if (!is_array($v)) { return $v; } if (!array_is_list($v)) { ksort($v, SORT_STRING); } foreach ($v as $k => $x) { $v[$k] = $sort($x); } return $v; };
    return json_encode($sort($value), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
}
function fncp_initialize_json(string $raw): array {
    $c = json_decode($raw, true, 12, JSON_THROW_ON_ERROR);
    // Canonical bytes reject duplicate keys, unknown whitespace and alternate encodings.
    if (!is_array($c) || array_is_list($c) || fncp_initialize_canonical($c) . "\n" !== $raw) { fncp_initialize_deny(); } return $c;
}
function fncp_initialize_token($value): bool {
    if (!is_string($value) || preg_match('/\A[A-Za-z0-9_-]{43}\z/D', $value) !== 1) { return false; }
    $decoded = base64_decode(strtr($value, '-_', '+/'), true);
    return is_string($decoded) && strlen($decoded) === 32 && rtrim(strtr(base64_encode($decoded), '+/', '-_'), '=') === $value;
}
function fncp_initialize_configuration(array $c, array $plugin, array $owner): void {
    fncp_initialize_exact($c, ['profile','wordpressOrigin','databaseName','databaseUser','databasePassword','tablePrefix','salts']);
    fncp_initialize_exact($owner, ['profile','siteTitle','operatorLogin','operatorEmail','operatorPassword']);
    if ($c['profile'] !== 'FNCP_WORDPRESS_RUNTIME_V1' || !is_string($c['wordpressOrigin'])
        || preg_match('/\Ahttps:\/\/[a-z0-9][a-z0-9.-]*(?::[1-9][0-9]{0,4})?\z/D', $c['wordpressOrigin']) !== 1
        || !is_string($c['databaseName']) || preg_match('/\A[a-z][a-z0-9_]{2,62}\z/D', $c['databaseName']) !== 1
        || !is_string($c['databaseUser']) || preg_match('/\A[a-z][a-z0-9_]{2,31}\z/D', $c['databaseUser']) !== 1
        || !is_string($c['tablePrefix']) || preg_match('/\A[a-z][a-z0-9_]{1,24}_\z/D', $c['tablePrefix']) !== 1
        || !fncp_initialize_token($c['databasePassword']) || !is_array($c['salts']) || !array_is_list($c['salts']) || count($c['salts']) !== 8
        || $owner['profile'] !== 'FNCP_WORDPRESS_INITIALIZE_V1'
        || !is_string($owner['siteTitle']) || strlen($owner['siteTitle']) < 1 || strlen($owner['siteTitle']) > 120
        || trim($owner['siteTitle']) !== $owner['siteTitle'] || preg_match('/[\x00-\x1f\x7f<>]/', $owner['siteTitle']) || preg_match('//u', $owner['siteTitle']) !== 1
        || !is_string($owner['operatorLogin']) || preg_match('/\A[a-z][a-z0-9_]{2,31}\z/D', $owner['operatorLogin']) !== 1
        || !is_string($owner['operatorEmail']) || strlen($owner['operatorEmail']) > 254 || !filter_var($owner['operatorEmail'], FILTER_VALIDATE_EMAIL)
        || strtolower($owner['operatorEmail']) !== $owner['operatorEmail'] || !fncp_initialize_token($owner['operatorPassword'])) { fncp_initialize_deny(); }
    $plugin = FNCP_Production_Contract::configuration($plugin);
    if ($plugin['wordpressOrigin'] !== $c['wordpressOrigin'] || $plugin['caFile'] !== '/run/fncp/wordpress/receiver-ca.pem') { fncp_initialize_deny(); }
    $secrets = array_merge([$c['databasePassword'], $owner['operatorPassword']], $c['salts'], [$plugin['serviceRequestKey'],$plugin['serviceResponseKey'],$plugin['eventKey']]);
    foreach ($secrets as $secret) { if (!fncp_initialize_token($secret)) { fncp_initialize_deny(); } }
    if (count(array_unique($secrets)) !== count($secrets)) { fncp_initialize_deny(); }
}
function fncp_initialize_private_read(string $parent, string $name): string {
    if (!in_array($parent, ['/run/fncp/wordpress','/run/fncp/wordpress-initialize'], true)
        || !in_array($name, ['config.json','plugin-config.json','owner.json'], true)) { fncp_initialize_deny(); }
    $path = $parent . '/' . $name; clearstatcache(); $p = @lstat($parent); $s = @lstat($path);
    if (!$p || !$s || realpath($parent) !== $parent || realpath($path) !== $path || ($p['mode'] & 0170000) !== 0040000 || ($p['mode'] & 07777) !== 0700 || $p['uid'] !== 33
        || ($s['mode'] & 0170000) !== 0100000 || !in_array($s['mode'] & 07777, [0400,0600], true) || $s['uid'] !== 33 || $s['nlink'] !== 1 || $s['size'] < 2 || $s['size'] > 16384) { fncp_initialize_deny(); }
    $raw = file_get_contents($path); clearstatcache(); $after = @lstat($path); $ap = @lstat($parent);
    if (!is_string($raw) || strlen($raw) !== $s['size'] || !$after || !$ap || $ap['ino'] !== $p['ino'] || $ap['dev'] !== $p['dev'] || $ap['mode'] !== $p['mode'] || $ap['uid'] !== 33
        || $after['ino'] !== $s['ino'] || $after['dev'] !== $s['dev'] || $after['mode'] !== $s['mode'] || $after['uid'] !== 33 || $after['nlink'] !== 1
        || $after['size'] !== $s['size'] || $after['mtime'] !== $s['mtime'] || $after['ctime'] !== $s['ctime']) { fncp_initialize_deny(); }
    return $raw;
}
function fncp_initialize_receipt(array $c, array $plugin, array $owner): array {
    return ['profile'=>'FNCP_WORDPRESS_INITIALIZED_V1', 'configurationDigest'=>hash('sha256', fncp_initialize_canonical($c)),
        'pluginDigest'=>hash('sha256', fncp_initialize_canonical($plugin)), 'ownerDigest'=>hash('sha256', fncp_initialize_canonical($owner)),
        'operatorCount'=>1,'registrationCount'=>0,'eventCount'=>0,'mailSent'=>false,'participationOpened'=>false];
}
function fncp_initialize_assert_snapshot(array $snapshot, array $c, array $plugin, array $owner, string $version): void {
    fncp_initialize_exact($snapshot, ['options','users','bridge']);
    $expected = ['siteurl'=>$c['wordpressOrigin'],'home'=>$c['wordpressOrigin'],'db_version'=>$version,'active_plugins'=>'a:0:{}',
        'blog_public'=>'0','users_can_register'=>'0','default_comment_status'=>'closed','default_ping_status'=>'closed','permalink_structure'=>'/%postname%/',
        'fncp_fresh_install_v1'=>fncp_initialize_canonical(fncp_initialize_receipt($c,$plugin,$owner))];
    if ($snapshot['options'] !== $expected || !is_array($snapshot['users']) || count($snapshot['users']) !== 1) { fncp_initialize_deny(); }
    $user = $snapshot['users'][0]; fncp_initialize_exact($user, ['login','email','capabilities']);
    if ($user['login'] !== $owner['operatorLogin'] || $user['email'] !== $owner['operatorEmail']
        || $user['capabilities'] !== ['administrator'=>true,'fncp_manage_registrations'=>true]) { fncp_initialize_deny(); }
    $empty = ['schemaVersion'=>1,'configurationDigest'=>hash('sha256', fncp_initialize_canonical($plugin)), 'lastObservedMs'=>0,'clockClosed'=>false,'registrations'=>[],'events'=>[]];
    if ($snapshot['bridge'] !== fncp_initialize_canonical($empty)) { fncp_initialize_deny(); }
}

/** Validate the persisted core route map without bootstrapping WordPress. */
function fncp_initialize_assert_rewrites(string $raw): void {
    if (strlen($raw) < 1 || strlen($raw) > 1048576) { fncp_initialize_deny(); }
    $rules = @unserialize($raw, ['allowed_classes'=>false]);
    if (!is_array($rules) || count($rules) > 1000 || serialize($rules) !== $raw) { fncp_initialize_deny(); }
    foreach ($rules as $pattern=>$target) {
        if (!is_string($pattern) || !is_string($target) || strlen($pattern)>8192 || strlen($target)>8192) { fncp_initialize_deny(); }
    }
    if (($rules['^wp-json/?$'] ?? null) !== 'index.php?rest_route=/'
        || ($rules['^wp-json/(.*)?'] ?? null) !== 'index.php?rest_route=/$matches[1]') { fncp_initialize_deny(); }
}
