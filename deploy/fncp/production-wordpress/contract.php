<?php
declare(strict_types=1);

/** Production WordPress bridge primitives. No WordPress, network or filesystem side effects. */
final class FNCP_Production_Denied extends RuntimeException {}
final class FNCP_Production_Contract {
    public const PROFILE = 'FNCP_PRODUCTION_WORDPRESS_V1';
    public const REQUEST_DOMAIN = "FNCP_WP_REQUEST_V1\n";
    public const RESPONSE_DOMAIN = "FNCP_WP_RESPONSE_V1\n";
    public const EVENT_DOMAIN = "FNCP_WP_EVENT_V1\n";
    public static function deny(): never { throw new FNCP_Production_Denied('Registration operation unavailable.'); }
    public static function exact(array $value, array $keys): void {
        $actual = array_keys($value); sort($actual); sort($keys); if ($actual !== $keys) { self::deny(); }
    }
    public static function token($v): bool { return is_string($v) && preg_match('/\A[A-Za-z0-9_-]{43}\z/D', $v) === 1; }
    public static function digest($v): bool { return is_string($v) && preg_match('/\A[0-9a-f]{64}\z/D', $v) === 1; }
    public static function uuid($v): bool { return is_string($v) && preg_match('/\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/D', $v) === 1; }
    public static function account($v): bool { return is_string($v) && preg_match('/\Aacct_[A-Za-z0-9_-]{43}\z/D', $v) === 1; }
    public static function identifier($v): bool { return is_string($v) && preg_match('/\A[A-Za-z0-9_-]{1,128}\z/D', $v) === 1; }
    public static function canonical(array $value): string {
        $sort = static function ($v) use (&$sort) { if (!is_array($v)) { return $v; } if (!array_is_list($v)) { ksort($v, SORT_STRING); } foreach ($v as $k => $x) { $v[$k] = $sort($x); } return $v; };
        return json_encode($sort($value), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
    public static function uuid4(): string {
        $bytes = random_bytes(16); $bytes[6] = chr((ord($bytes[6]) & 15) | 64); $bytes[8] = chr((ord($bytes[8]) & 63) | 128); $h = bin2hex($bytes);
        return substr($h, 0, 8) . '-' . substr($h, 8, 4) . '-' . substr($h, 12, 4) . '-' . substr($h, 16, 4) . '-' . substr($h, 20);
    }
    public static function https($v, bool $origin = false): bool {
        if (!is_string($v) || strlen($v) > 2048 || preg_match('/[\x00-\x20\x7f\\\\]/', $v)) { return false; }
        $p = parse_url($v);
        if (!is_array($p) || ($p['scheme'] ?? '') !== 'https' || empty($p['host']) || isset($p['user']) || isset($p['pass']) || isset($p['query']) || isset($p['fragment'])
            || strtolower($p['host']) !== $p['host'] || preg_match('/\A(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\z/D', $p['host']) !== 1
            || (isset($p['port']) && ($p['port'] < 1 || $p['port'] > 65535 || $p['port'] === 443))) { return false; }
        $base = 'https://' . $p['host'] . (isset($p['port']) ? ':' . $p['port'] : '');
        return $origin ? $v === $base : $v === $base . '/internal/wordpress/events';
    }
    public static function configuration(array $c): array {
        self::exact($c, ['profile','deploymentId','conversationId','wordpressOrigin','eventEndpoint','consentVersion','noticeSha256','serviceRequestKey','serviceResponseKey','eventKey','caFile']);
        if ($c['profile'] !== self::PROFILE || !self::identifier($c['deploymentId']) || !self::identifier($c['conversationId']) || !self::https($c['wordpressOrigin'], true)
            || !self::https($c['eventEndpoint']) || !self::identifier($c['consentVersion']) || !self::digest($c['noticeSha256'])
            || !self::token($c['serviceRequestKey']) || !self::token($c['serviceResponseKey']) || !self::token($c['eventKey'])
            || count(array_unique([$c['serviceRequestKey'], $c['serviceResponseKey'], $c['eventKey']])) !== 3
            || !is_string($c['caFile']) || !str_starts_with($c['caFile'], '/') || str_contains($c['caFile'], "\0") || strlen($c['caFile']) > 4096) { self::deny(); }
        foreach (['serviceRequestKey','serviceResponseKey','eventKey'] as $k) {
            $bytes = base64_decode(strtr($c[$k], '-_', '+/'), true);
            if ($bytes === false || strlen($bytes) !== 32 || rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=') !== $c[$k]) { self::deny(); }
        }
        return $c;
    }
    /** Keys are decoded 32-byte values, never HMACed as their transport encoding. */
    public static function mac(string $message, string $key): string { return hash_hmac('sha256', $message, base64_decode(strtr($key, '-_', '+/'), true)); }
    public static function signedResponse(string $action, array $payload, array $c): array {
        if (!in_array($action, ['register','status'], true)) { self::deny(); }
        $encoded = rtrim(strtr(base64_encode(self::canonical($payload)), '+/', '-_'), '=');
        return ['payload' => $encoded, 'signature' => self::mac(self::RESPONSE_DOMAIN . $action . "\n" . $encoded, $c['serviceResponseKey'])];
    }
    public static function authenticate(string $action, string $raw, string $timestamp, string $signature, array $c): void {
        if (!in_array($action, ['register','status'], true) || strlen($raw) > 8192 || !preg_match('/\A[0-9]{10}\z/D', $timestamp)
            || !preg_match('/\Asha256=[0-9a-f]{64}\z/D', $signature)
            || !hash_equals('sha256=' . self::mac(self::REQUEST_DOMAIN . $action . "\n" . $timestamp . '.' . $raw, $c['serviceRequestKey']), $signature)) { self::deny(); }
    }
    public static function request(string $action, string $raw, string $timestamp, string $signature, array $c, int $nowMs): array {
        self::authenticate($action, $raw, $timestamp, $signature, $c);
        if ($nowMs < 0 || abs(intdiv($nowMs, 1000) - (int) $timestamp) > 30) { self::deny(); }
        $body = json_decode($raw, true, 8, JSON_THROW_ON_ERROR); if (!is_array($body)) { self::deny(); }
        // Canonical wire JSON also rejects duplicate object keys and ambiguous encodings.
        if (self::canonical($body) !== $raw) { self::deny(); }
        if ($action === 'register') { self::registration($body, $c, intdiv($nowMs, 1000), true); }
        else { self::exact($body, ['schemaVersion','deploymentId','conversationId','accountId','nonce']); self::binding($body, $c); if (!self::account($body['accountId']) || !self::token($body['nonce'])) { self::deny(); } }
        return $body;
    }
    public static function binding(array $body, array $c): void {
        if (($body['schemaVersion'] ?? null) !== 1 || ($body['deploymentId'] ?? null) !== $c['deploymentId'] || ($body['conversationId'] ?? null) !== $c['conversationId']) { self::deny(); }
    }
    public static function registration(array $b, array $c, int $now, bool $allowExpired = false): void {
        self::exact($b, ['schemaVersion','deploymentId','conversationId','receiptId','accountId','consentVersion','noticeSha256','adultSelfAttested','eligibilitySelfAttested','registrationConsent','issuedAt','expiresAt']); self::binding($b, $c);
        if (!self::uuid($b['receiptId']) || !self::account($b['accountId']) || $b['consentVersion'] !== $c['consentVersion'] || $b['noticeSha256'] !== $c['noticeSha256']
            || $b['adultSelfAttested'] !== true || $b['eligibilitySelfAttested'] !== true || $b['registrationConsent'] !== true
            || !is_int($b['issuedAt']) || !is_int($b['expiresAt']) || $b['issuedAt'] < 0 || $b['issuedAt'] > $now || (!$allowExpired && $b['expiresAt'] <= $now)
            || $b['expiresAt'] <= $b['issuedAt'] || $b['expiresAt'] - $b['issuedAt'] > 60) { self::deny(); }
    }
    public static function event(array $e, array $c): void {
        self::exact($e, ['schemaVersion','eventId','deploymentId','conversationId','registrationId','accountId','version','state','occurredAt']); self::binding($e, $c);
        if (!self::uuid($e['eventId']) || !self::uuid($e['registrationId']) || !self::account($e['accountId']) || !is_int($e['occurredAt']) || $e['occurredAt'] < 0
            || !(($e['version'] === 1 && $e['state'] === 'approved') || ($e['version'] === 2 && $e['state'] === 'revoked'))) { self::deny(); }
    }
    public static function acknowledged(int $status, string $raw, array $event): bool {
        try { if ($status !== 200 || strlen($raw) > 4096) { return false; } $a = json_decode($raw, true, 4, JSON_THROW_ON_ERROR); if (!is_array($a)) { return false; }
            self::exact($a, ['ok','eventId','version']); return $a['ok'] === true && $a['eventId'] === $event['eventId'] && $a['version'] === $event['version'];
        } catch (Throwable $e) { return false; }
    }
}
