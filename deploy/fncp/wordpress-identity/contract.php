<?php
/** Synthetic registration receipt contract only. No WordPress/network side effects. */
declare(strict_types=1);
require_once __DIR__ . '/../wordpress-local/contract.php';
final class FNCP_Identity_Denied extends RuntimeException {}

final class FNCP_Identity_Contract {
    public const CHALLENGE_DOMAIN = "FNCP_WP_CHALLENGE_SYNTHETIC_V1\n";
    public const RECEIPT_DOMAIN = "FNCP_BFF_REGISTRATION_SYNTHETIC_V1\n";
    public const ROUND = 'synthetic_round_local';
    public const CONSENT = 'synthetic-registration-v1';

    public static function exact(array $value, array $keys): void {
        $actual = array_keys($value); sort($actual); sort($keys);
        if ($actual !== $keys) { throw new InvalidArgumentException('Invalid synthetic schema.'); }
    }
    public static function secret(string $value): bool { return preg_match('/\A[A-Za-z0-9_-]{32,256}\z/D', $value) === 1; }
    public static function opaque(string $value): bool { return preg_match('/\A[A-Za-z0-9_-]{43}\z/D', $value) === 1; }
    public static function digest(string $value): bool { return preg_match('/\A[0-9a-f]{64}\z/D', $value) === 1; }
    public static function uuid(string $value): bool { return preg_match('/\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/D', $value) === 1; }
    public static function fixture(string $value): bool { return preg_match('/\Asynthetic_i[0-9a-f]{39}\z/D', $value) === 1; }
    public static function random(): string { return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '='); }
    public static function canonical(array $value): string {
        $sort = static function ($item) use (&$sort) {
            if (!is_array($item)) { return $item; }
            if (!array_is_list($item)) { ksort($item, SORT_STRING); }
            foreach ($item as $key => $child) { $item[$key] = $sort($child); }
            return $item;
        };
        return json_encode($sort($value), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
    public static function sign(array $claims, string $secret, string $domain): array {
        if (!self::secret($secret) || !in_array($domain, [self::CHALLENGE_DOMAIN, self::RECEIPT_DOMAIN], true)) {
            throw new InvalidArgumentException('Invalid synthetic signing configuration.');
        }
        $payload = rtrim(strtr(base64_encode(self::canonical($claims)), '+/', '-_'), '=');
        return ['payload' => $payload, 'signature' => hash_hmac('sha256', $domain . $payload, $secret)];
    }
    public static function verify(array $envelope, string $secret, string $domain): array {
        self::exact($envelope, ['payload', 'signature']);
        if (!self::secret($secret) || !in_array($domain, [self::CHALLENGE_DOMAIN, self::RECEIPT_DOMAIN], true)
            || !is_string($envelope['payload']) || strlen($envelope['payload']) > 8192
            || preg_match('/\A[A-Za-z0-9_-]+\z/D', $envelope['payload']) !== 1
            || !is_string($envelope['signature']) || !self::digest($envelope['signature'])
            || !hash_equals(hash_hmac('sha256', $domain . $envelope['payload'], $secret), $envelope['signature'])) {
            throw new InvalidArgumentException('Synthetic signature rejected.');
        }
        $raw = base64_decode(strtr($envelope['payload'], '-_', '+/'), true);
        if ($raw === false || rtrim(strtr(base64_encode($raw), '+/', '-_'), '=') !== $envelope['payload']) {
            throw new InvalidArgumentException('Invalid synthetic payload encoding.');
        }
        $claims = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        if (!is_array($claims) || self::canonical($claims) !== $raw) { throw new InvalidArgumentException('Canonical synthetic claims required.'); }
        return $claims;
    }
    private static function times(array $claims, int $now, int $ttl): void {
        if ($now < 0 || !is_int($claims['issuedAt']) || !is_int($claims['expiresAt'])
            || $claims['issuedAt'] < 0 || $claims['issuedAt'] > $now || $claims['expiresAt'] <= $now
            || $claims['expiresAt'] <= $claims['issuedAt'] || $claims['expiresAt'] - $claims['issuedAt'] > $ttl) {
            throw new InvalidArgumentException('Synthetic receipt time rejected.');
        }
    }
    public static function challenge(string $binding, int $now, string $secret): array {
        if (!self::digest($binding) || $now < 0) { throw new InvalidArgumentException('Invalid synthetic binding.'); }
        return self::sign(['schemaVersion' => 1, 'purpose' => 'wordpress-registration-challenge',
            'audience' => 'fncp-synthetic-bff', 'challengeId' => FNCP_Local_Contract::uuid(),
            'browserBinding' => $binding, 'roundId' => self::ROUND, 'issuedAt' => $now, 'expiresAt' => $now + 120], $secret, self::CHALLENGE_DOMAIN);
    }
    public static function readChallenge(array $envelope, string $secret, string $binding, int $now): array {
        $claims = self::verify($envelope, $secret, self::CHALLENGE_DOMAIN);
        self::exact($claims, ['schemaVersion', 'purpose', 'audience', 'challengeId', 'browserBinding', 'roundId', 'issuedAt', 'expiresAt']);
        if ($claims['schemaVersion'] !== 1 || $claims['purpose'] !== 'wordpress-registration-challenge'
            || $claims['audience'] !== 'fncp-synthetic-bff' || $claims['roundId'] !== self::ROUND
            || !is_string($claims['challengeId']) || !self::uuid($claims['challengeId'])
            || !is_string($claims['browserBinding']) || !self::digest($claims['browserBinding'])
            || !hash_equals($binding, $claims['browserBinding'])) { throw new InvalidArgumentException('Synthetic challenge binding rejected.'); }
        self::times($claims, $now, 120);
        return $claims;
    }
    public static function readReceipt(array $envelope, string $secret, array $challengeEnvelope, array $challenge, int $now): array {
        $claims = self::verify($envelope, $secret, self::RECEIPT_DOMAIN);
        self::exact($claims, ['schemaVersion', 'purpose', 'audience', 'assertionId', 'challengeId', 'browserBinding',
            'challengeDigest', 'fixture', 'roundId', 'issuedAt', 'expiresAt', 'consentVersion',
            'adultSelfAttested', 'eligibilitySelfAttested', 'registrationConsent']);
        if ($claims['schemaVersion'] !== 1 || $claims['purpose'] !== 'wordpress-registration-receipt'
            || $claims['audience'] !== 'fncp-synthetic-wordpress' || $claims['roundId'] !== self::ROUND
            || !is_string($claims['assertionId']) || !self::uuid($claims['assertionId'])
            || $claims['challengeId'] !== $challenge['challengeId'] || $claims['browserBinding'] !== $challenge['browserBinding']
            || $claims['challengeDigest'] !== hash('sha256', self::canonical($challengeEnvelope))
            || !is_string($claims['fixture']) || !self::fixture($claims['fixture'])
            || $claims['consentVersion'] !== self::CONSENT || $claims['adultSelfAttested'] !== true
            || $claims['eligibilitySelfAttested'] !== true || $claims['registrationConsent'] !== true) {
            throw new InvalidArgumentException('Synthetic registration receipt rejected.');
        }
        self::times($claims, $now, 60);
        if ($claims['issuedAt'] < $challenge['issuedAt'] || $claims['expiresAt'] > $challenge['expiresAt']) {
            throw new InvalidArgumentException('Synthetic receipt exceeded its challenge.');
        }
        return $claims;
    }
}
