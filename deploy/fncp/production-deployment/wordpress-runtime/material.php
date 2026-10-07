<?php
declare(strict_types=1);
function fncp_runtime_read(string $name, int $limit = 65536): string {
    $parent = '/run/fncp/wordpress'; $path = $parent . '/' . $name;
    $p = @lstat($parent); $s = @lstat($path);
    if (!function_exists('posix_geteuid') || posix_geteuid() !== 33 || !$p || !$s || realpath($parent) !== $parent || realpath($path) !== $path
        || ($p['mode'] & 0170000) !== 0040000 || ($p['mode'] & 07777) !== 0700 || $p['uid'] !== 33
        || ($s['mode'] & 0170000) !== 0100000 || !in_array($s['mode'] & 07777, [0400,0600], true) || $s['uid'] !== 33 || $s['nlink'] !== 1
        || $s['size'] < 1 || $s['size'] > $limit) { throw new RuntimeException('runtime_material'); }
    $raw = file_get_contents($path); clearstatcache(true, $path); $after = @lstat($path); $ap = @lstat($parent);
    if (!is_string($raw) || strlen($raw) !== $s['size'] || !$after || !$ap || $ap['ino'] !== $p['ino'] || $ap['dev'] !== $p['dev']
        || ($ap['mode'] & 0170000) !== 0040000 || ($ap['mode'] & 07777) !== 0700 || $ap['uid'] !== 33
        || $after['ino'] !== $s['ino'] || $after['dev'] !== $s['dev'] || $after['mode'] !== $s['mode'] || $after['uid'] !== 33 || $after['nlink'] !== 1
        || $after['size'] !== $s['size'] || $after['mtime'] !== $s['mtime'] || $after['ctime'] !== $s['ctime']) { throw new RuntimeException('runtime_material'); }
    return $raw;
}
function fncp_runtime_configuration(): array {
    $c = json_decode(fncp_runtime_read('config.json', 16384), true, 8, JSON_THROW_ON_ERROR);
    $keys = is_array($c) ? array_keys($c) : []; sort($keys);
    $expected = ['profile','wordpressOrigin','databaseName','databaseUser','databasePassword','tablePrefix','salts']; sort($expected);
    if ($keys !== $expected || $c['profile'] !== 'FNCP_WORDPRESS_RUNTIME_V1'
        || !is_string($c['wordpressOrigin']) || preg_match('/\Ahttps:\/\/[A-Za-z0-9][A-Za-z0-9.-]*(?::[1-9][0-9]{0,4})?\z/D', $c['wordpressOrigin']) !== 1
        || !is_string($c['databaseName']) || preg_match('/\A[a-z][a-z0-9_]{2,62}\z/D', $c['databaseName']) !== 1
        || !is_string($c['databaseUser']) || preg_match('/\A[a-z][a-z0-9_]{2,31}\z/D', $c['databaseUser']) !== 1
        || !is_string($c['tablePrefix']) || preg_match('/\A[a-z][a-z0-9_]{1,24}_\z/D', $c['tablePrefix']) !== 1
        || !is_string($c['databasePassword']) || preg_match('/\A[A-Za-z0-9_-]{43}\z/D', $c['databasePassword']) !== 1
        || !is_array($c['salts']) || !array_is_list($c['salts']) || count($c['salts']) !== 8 || count(array_unique($c['salts'])) !== 8) { throw new RuntimeException('runtime_configuration'); }
    foreach ($c['salts'] as $value) { if (!is_string($value) || preg_match('/\A[A-Za-z0-9_-]{43}\z/D', $value) !== 1 || $value === $c['databasePassword']) { throw new RuntimeException('runtime_configuration'); } }
    require_once '/usr/src/wordpress/wp-content/mu-plugins/fncp-production/contract.php';
    $plugin = FNCP_Production_Contract::configuration(json_decode(fncp_runtime_read('plugin-config.json', 16384), true, 8, JSON_THROW_ON_ERROR));
    if ($plugin['wordpressOrigin'] !== $c['wordpressOrigin'] || $plugin['caFile'] !== '/run/fncp/wordpress/receiver-ca.pem') { throw new RuntimeException('runtime_binding'); }
    foreach (['serviceRequestKey','serviceResponseKey','eventKey'] as $key) { if ($plugin[$key] === $c['databasePassword'] || in_array($plugin[$key], $c['salts'], true)) { throw new RuntimeException('runtime_keys'); } }
    fncp_runtime_validate_ca(fncp_runtime_read('receiver-ca.pem'), time());
    return $c;
}

function fncp_runtime_validate_ca(string $pem, int $now): void {
    if (strlen($pem) > 65536 || preg_match('/\A(?:-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+\/=\n]+\n-----END CERTIFICATE-----\n?)+\z/D', $pem) !== 1) { throw new RuntimeException('runtime_ca'); }
    preg_match_all('/-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+\/=\n]+\n-----END CERTIFICATE-----/', $pem, $certificates);
    if (count($certificates[0]) > 16) { throw new RuntimeException('runtime_ca'); }
    foreach ($certificates[0] as $raw) {
        $cert = @openssl_x509_read($raw); $details = $cert ? openssl_x509_parse($cert) : false;
        if (!$details || !str_contains($details['extensions']['basicConstraints'] ?? '', 'CA:TRUE')
            || ($details['validFrom_time_t'] ?? PHP_INT_MAX) > $now || ($details['validTo_time_t'] ?? 0) <= $now) { throw new RuntimeException('runtime_ca'); }
    }
}
function fncp_runtime_validate_leaf(string $pem, string $private, string $origin, int $now): void {
    $certificate = @openssl_x509_read($pem); $key = @openssl_pkey_get_private($private);
    $details = $certificate ? openssl_x509_parse($certificate) : false; $host = parse_url($origin, PHP_URL_HOST);
    if (!$certificate || !$key || !$details || !is_string($host) || !openssl_x509_check_private_key($certificate, $key)
        || str_contains($details['extensions']['basicConstraints'] ?? '', 'CA:TRUE')
        || ($details['validFrom_time_t'] ?? PHP_INT_MAX) > $now || ($details['validTo_time_t'] ?? 0) <= $now) { throw new RuntimeException('runtime_tls'); }
    // This deployment profile supports exact DNS/IPv4 SANs. It deliberately
    // excludes wildcard/CN-only certificates instead of inventing a matcher.
    $prefix = filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? 'IP Address:' : 'DNS:'; $matched = false;
    foreach (explode(',', $details['extensions']['subjectAltName'] ?? '') as $entry) {
        $entry = trim($entry); if (str_starts_with($entry, $prefix) && strtolower(substr($entry, strlen($prefix))) === strtolower($host)) { $matched = true; }
    }
    if (!$matched) { throw new RuntimeException('runtime_tls_hostname'); }
}
