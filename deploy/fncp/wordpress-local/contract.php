<?php
/** Synthetic-only wire contract. No WordPress or network side effects. */
declare(strict_types=1);

final class FNCP_Local_Contract {
    public const TARGET = 'http://127.0.0.1:8101/internal/wordpress/events';
    public const MAX_SUBJECTS = 20;
    public const MAX_EVENTS = 200;

    public static function fixture(string $subject): bool {
        return preg_match('/\Asynthetic_[a-z][a-z0-9_]{0,39}\z/D', $subject) === 1;
    }

    public static function round(string $round): bool {
        return $round === 'synthetic_round_local';
    }

    public static function validate(string $round, string $subject, string $state): void {
        if (!self::round($round) || !self::fixture($subject) || !in_array($state, ['approved', 'revoked'], true)) {
            throw new InvalidArgumentException('Only bounded synthetic round/account keys and approval states are accepted.');
        }
    }

    public static function uuid(): string {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
        $hex = bin2hex($bytes);
        return substr($hex, 0, 8) . '-' . substr($hex, 8, 4) . '-' . substr($hex, 12, 4) . '-' . substr($hex, 16, 4) . '-' . substr($hex, 20);
    }

    public static function event(string $round, string $subject, string $state, int $version): array {
        self::validate($round, $subject, $state);
        if ($version < 1 || $version > 9007199254740991) {
            throw new InvalidArgumentException('Version must be a positive safe integer.');
        }
        return [
            'schema_version' => 1,
            'event_id' => self::uuid(),
            'subject' => $subject,
            'round_id' => $round,
            'version' => $version,
            'state' => $state,
            'occurred_at' => gmdate('Y-m-d\TH:i:s\Z'),
        ];
    }

    public static function encode(array $value): string {
        return json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    public static function assertEvent(array $event): void {
        $keys = array_keys($event);
        sort($keys);
        $expected = ['schema_version', 'event_id', 'subject', 'round_id', 'version', 'state', 'occurred_at'];
        sort($expected);
        if ($keys !== $expected || ($event['schema_version'] ?? null) !== 1
            || !is_string($event['event_id']) || preg_match('/\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/D', $event['event_id']) !== 1
            || !is_string($event['subject']) || !is_string($event['round_id']) || !is_string($event['state'])
            || !is_int($event['version']) || $event['version'] < 1 || $event['version'] > 9007199254740991
            || !is_string($event['occurred_at']) || preg_match('/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\z/D', $event['occurred_at']) !== 1) {
            throw new InvalidArgumentException('Synthetic event schema is invalid.');
        }
        self::validate($event['round_id'], $event['subject'], $event['state']);
    }

    public static function signature(string $secret, string $timestamp, string $body): string {
        if (preg_match('/\A[!-~]{32,256}\z/D', $secret) !== 1 || preg_match('/\A[0-9]{10}\z/D', $timestamp) !== 1) {
            throw new InvalidArgumentException('Local signing configuration is invalid.');
        }
        return 'sha256=' . hash_hmac('sha256', $timestamp . '.' . $body, $secret);
    }

    public static function acknowledged(int $status, string $body, array $event): bool {
        if ($status !== 200 || strlen($body) > 4096) {
            return false;
        }
        try {
            $reply = json_decode($body, true, 8, JSON_THROW_ON_ERROR);
            return is_array($reply) && ($reply['ok'] ?? null) === true
                && ($reply['event_id'] ?? null) === $event['event_id']
                && ($reply['version'] ?? null) === $event['version'];
        } catch (JsonException $error) {
            return false;
        }
    }
}
