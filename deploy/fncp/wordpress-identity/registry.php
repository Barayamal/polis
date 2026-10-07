<?php
/** One CAS value: guest sessions, one-use claims, immutable synthetic registrations. */
declare(strict_types=1);
require_once __DIR__ . '/contract.php';

final class FNCP_Identity_Registry {
    private Closure $read; private Closure $swap; private Closure $create; private Closure $clock;
    public const MAX_SESSIONS = 64;
    public const MAX_CHALLENGES = 128;
    public const MAX_REGISTRATIONS = 20;
    public function __construct(callable $read, callable $swap, callable $create, ?callable $clock = null) {
        $this->read = Closure::fromCallable($read); $this->swap = Closure::fromCallable($swap);
        $this->create = Closure::fromCallable($create); $this->clock = Closure::fromCallable($clock ?? 'time');
    }
    public static function emptyRegistry(): array {
        return ['schemaVersion' => 1, 'sessions' => [], 'challenges' => [], 'assertions' => [], 'registrations' => [], 'fixtureIndex' => []];
    }
    private function decode(string $raw): array {
        $r = json_decode($raw, true, 12, JSON_THROW_ON_ERROR);
        if (!is_array($r)) { throw new RuntimeException('Invalid synthetic registry.'); }
        FNCP_Identity_Contract::exact($r, ['schemaVersion', 'sessions', 'challenges', 'assertions', 'registrations', 'fixtureIndex']);
        if ($r['schemaVersion'] !== 1) { throw new RuntimeException('Invalid synthetic registry version.'); }
        foreach (['sessions', 'challenges', 'assertions', 'registrations', 'fixtureIndex'] as $name) {
            if (!is_array($r[$name])) { throw new RuntimeException('Invalid synthetic registry collection.'); }
        }
        if (count($r['sessions']) > self::MAX_SESSIONS || count($r['challenges']) > self::MAX_CHALLENGES
            || count($r['assertions']) > self::MAX_CHALLENGES || count($r['registrations']) > self::MAX_REGISTRATIONS
            || count($r['registrations']) !== count($r['fixtureIndex'])) { throw new RuntimeException('Invalid registry capacity.'); }
        foreach ($r['sessions'] as $binding => $s) {
            if (!is_string($binding) || !FNCP_Identity_Contract::digest($binding) || !is_array($s)) { throw new RuntimeException('Invalid guest session.'); }
            FNCP_Identity_Contract::exact($s, ['csrfToken', 'createdAt', 'expiresAt', 'challengeId', 'registrationId']);
            if (!is_string($s['csrfToken']) || !FNCP_Identity_Contract::opaque($s['csrfToken']) || !is_int($s['createdAt']) || !is_int($s['expiresAt'])
                || $s['createdAt'] < 0 || $s['expiresAt'] <= $s['createdAt'] || $s['expiresAt'] - $s['createdAt'] > 300
                || ($s['challengeId'] !== null && (!is_string($s['challengeId']) || !isset($r['challenges'][$s['challengeId']])) )
                || ($s['registrationId'] !== null && (!is_string($s['registrationId']) || !isset($r['registrations'][$s['registrationId']])))) {
                throw new RuntimeException('Invalid guest session record.');
            }
        }
        foreach ($r['challenges'] as $id => $c) {
            if (!is_string($id) || !FNCP_Identity_Contract::uuid($id) || !is_array($c)) { throw new RuntimeException('Invalid challenge record.'); }
            FNCP_Identity_Contract::exact($c, ['envelope', 'expiresAt', 'consumed']);
            if (!is_array($c['envelope']) || !is_int($c['expiresAt']) || $c['expiresAt'] < 1 || !is_bool($c['consumed'])) { throw new RuntimeException('Invalid challenge record.'); }
            FNCP_Identity_Contract::exact($c['envelope'], ['payload', 'signature']);
            if (!is_string($c['envelope']['payload']) || strlen($c['envelope']['payload']) > 8192 || !is_string($c['envelope']['signature'])
                || !FNCP_Identity_Contract::digest($c['envelope']['signature'])) { throw new RuntimeException('Invalid challenge envelope.'); }
        }
        foreach ($r['assertions'] as $id => $expiry) {
            if (!is_string($id) || !FNCP_Identity_Contract::uuid($id) || !is_int($expiry) || $expiry < 1) { throw new RuntimeException('Invalid assertion tombstone.'); }
        }
        foreach ($r['registrations'] as $id => $entry) {
            self::validateRegistration($entry);
            if ($id !== $entry['registrationId'] || ($r['fixtureIndex'][$entry['fixture'] . ':' . $entry['roundId']] ?? null) !== $id) {
                throw new RuntimeException('Immutable registration index mismatch.');
            }
        }
        return $r;
    }
    public static function validateRegistration($entry): void {
        if (!is_array($entry)) { throw new RuntimeException('Invalid registration.'); }
        FNCP_Identity_Contract::exact($entry, ['registrationId', 'fixture', 'roundId', 'createdAt', 'acceptedAt', 'consentVersion',
            'adultSelfAttested', 'eligibilitySelfAttested', 'registrationConsent']);
        if (!is_string($entry['registrationId']) || !FNCP_Identity_Contract::uuid($entry['registrationId'])
            || !is_string($entry['fixture']) || !FNCP_Identity_Contract::fixture($entry['fixture']) || $entry['roundId'] !== FNCP_Identity_Contract::ROUND
            || !is_int($entry['createdAt']) || $entry['createdAt'] < 0 || !is_int($entry['acceptedAt'])
            || $entry['acceptedAt'] < 0 || $entry['acceptedAt'] > $entry['createdAt'] || $entry['consentVersion'] !== FNCP_Identity_Contract::CONSENT
            || $entry['adultSelfAttested'] !== true || $entry['eligibilitySelfAttested'] !== true || $entry['registrationConsent'] !== true) {
            throw new RuntimeException('Invalid immutable registration facts.');
        }
    }
    public function snapshot(): array { $raw = ($this->read)(); return $raw === null ? self::emptyRegistry() : $this->decode($raw); }
    /** Private CLI quiescence only; caller proves all registrations terminal.
     * Preserve registration and replay evidence, including expired tombstones. */
    public function closeGuests(): array {
        for ($attempt = 0; $attempt < 8; $attempt++) {
            $raw = ($this->read)();
            if ($raw === null) { throw new RuntimeException('Existing synthetic registry required.'); }
            $r = $this->decode($raw); $closed = count($r['sessions']);
            $r['sessions'] = [];
            foreach ($r['challenges'] as &$challenge) { $challenge['consumed'] = true; } unset($challenge);
            $next = FNCP_Identity_Contract::canonical($r);
            if ($next === $raw || ($this->swap)($raw, $next)) {
                return ['guestSessionsClosed' => $closed, 'remainingGuestSessions' => 0,
                    'registrationsPreserved' => count($r['registrations']), 'assertionsPreserved' => count($r['assertions'])];
            }
        }
        throw new RuntimeException('Concurrent synthetic quiescence denied.');
    }
    private static function prune(array &$r, int $now): void {
        foreach ($r['sessions'] as $key => $s) { if ($s['expiresAt'] <= $now || $s['createdAt'] > $now) { unset($r['sessions'][$key]); } }
        foreach ($r['challenges'] as $id => $c) { if ($c['expiresAt'] <= $now) { unset($r['challenges'][$id]); } }
        foreach ($r['sessions'] as &$s) { if ($s['challengeId'] !== null && !isset($r['challenges'][$s['challengeId']])) { $s['challengeId'] = null; } } unset($s);
        foreach ($r['assertions'] as $id => $expiry) { if ($expiry <= $now) { unset($r['assertions'][$id]); } }
    }
    private function mutate(callable $fn) {
        for ($attempt = 0; $attempt < 8; $attempt++) {
            $raw = ($this->read)();
            if ($raw === null) { ($this->create)(FNCP_Identity_Contract::canonical(self::emptyRegistry())); continue; }
            $r = $this->decode($raw); $now = ($this->clock)();
            if (!is_int($now) || $now < 0) { throw new RuntimeException('Invalid synthetic clock.'); }
            self::prune($r, $now); $result = $fn($r, $now);
            $next = FNCP_Identity_Contract::canonical($r);
            if ($next === $raw || ($this->swap)($raw, $next)) { return $result; }
        }
        throw new RuntimeException('Concurrent synthetic registration; retry with current session.');
    }
    private static function current(array $r, string $binding, string $csrf): array {
        $s = $r['sessions'][$binding] ?? null;
        if (!FNCP_Identity_Contract::digest($binding) || !FNCP_Identity_Contract::opaque($csrf) || !$s || !hash_equals($s['csrfToken'], $csrf)) {
            throw new FNCP_Identity_Denied('Current synthetic guest session required.');
        }
        return $s;
    }
    public function session(?string $binding, string $newBinding, string $csrf): array {
        if (!FNCP_Identity_Contract::digest($newBinding) || !FNCP_Identity_Contract::opaque($csrf)) { throw new InvalidArgumentException('Invalid guest session material.'); }
        return $this->mutate(static function (array &$r, int $now) use ($binding, $newBinding, $csrf): array {
            if ($binding !== null && isset($r['sessions'][$binding])) { return ['created' => false, 'csrfToken' => $r['sessions'][$binding]['csrfToken']]; }
            if (count($r['sessions']) >= self::MAX_SESSIONS || isset($r['sessions'][$newBinding])) { throw new RuntimeException('Synthetic guest capacity reached.'); }
            $r['sessions'][$newBinding] = ['csrfToken' => $csrf, 'createdAt' => $now, 'expiresAt' => $now + 300, 'challengeId' => null, 'registrationId' => null];
            return ['created' => true, 'csrfToken' => $csrf];
        });
    }
    public function challenge(string $binding, string $csrf, string $secret): array {
        return $this->mutate(static function (array &$r, int $now) use ($binding, $csrf, $secret): array {
            $s = self::current($r, $binding, $csrf);
            if ($s['registrationId'] !== null) { throw new RuntimeException('This guest session has already registered.'); }
            if ($s['challengeId'] !== null) { unset($r['challenges'][$s['challengeId']]); }
            if (count($r['challenges']) >= self::MAX_CHALLENGES) { throw new RuntimeException('Synthetic challenge capacity reached.'); }
            $envelope = FNCP_Identity_Contract::challenge($binding, $now, $secret);
            $claims = FNCP_Identity_Contract::readChallenge($envelope, $secret, $binding, $now);
            $r['challenges'][$claims['challengeId']] = ['envelope' => $envelope, 'expiresAt' => $claims['expiresAt'], 'consumed' => false];
            $r['sessions'][$binding]['challengeId'] = $claims['challengeId'];
            return $envelope;
        });
    }
    public function register(string $binding, string $csrf, array $receipt, string $challengeSecret, string $receiptSecret, string $newBinding, string $newCsrf): array {
        if ($challengeSecret === $receiptSecret || !FNCP_Identity_Contract::digest($newBinding) || !FNCP_Identity_Contract::opaque($newCsrf)) {
            throw new InvalidArgumentException('Independent registration authority required.');
        }
        return $this->mutate(static function (array &$r, int $now) use ($binding, $csrf, $receipt, $challengeSecret, $receiptSecret, $newBinding, $newCsrf): array {
            $s = self::current($r, $binding, $csrf); $c = $s['challengeId'] === null ? null : ($r['challenges'][$s['challengeId']] ?? null);
            if (!$c || $c['consumed'] || $s['registrationId'] !== null || isset($r['sessions'][$newBinding])) { throw new FNCP_Identity_Denied('Unused current challenge required.'); }
            $challenge = FNCP_Identity_Contract::readChallenge($c['envelope'], $challengeSecret, $binding, $now);
            if ($challenge['challengeId'] !== $s['challengeId'] || $challenge['expiresAt'] !== $c['expiresAt']) { throw new RuntimeException('Stored challenge mismatch.'); }
            $claims = FNCP_Identity_Contract::readReceipt($receipt, $receiptSecret, $c['envelope'], $challenge, $now);
            $index = $claims['fixture'] . ':' . $claims['roundId'];
            if (isset($r['assertions'][$claims['assertionId']]) || isset($r['fixtureIndex'][$index])) { throw new RuntimeException('Registration receipt already claimed.'); }
            if (count($r['registrations']) >= self::MAX_REGISTRATIONS || count($r['assertions']) >= self::MAX_CHALLENGES) { throw new RuntimeException('Synthetic registration capacity reached.'); }
            $id = FNCP_Local_Contract::uuid();
            $entry = ['registrationId' => $id, 'fixture' => $claims['fixture'], 'roundId' => $claims['roundId'], 'createdAt' => $now, 'acceptedAt' => $claims['issuedAt'],
                'consentVersion' => $claims['consentVersion'], 'adultSelfAttested' => true, 'eligibilitySelfAttested' => true, 'registrationConsent' => true];
            $r['registrations'][$id] = $entry; $r['fixtureIndex'][$index] = $id;
            $r['challenges'][$s['challengeId']]['consumed'] = true;
            $r['assertions'][$claims['assertionId']] = $claims['expiresAt'];
            unset($r['sessions'][$binding]);
            $r['sessions'][$newBinding] = ['csrfToken' => $newCsrf, 'createdAt' => $now, 'expiresAt' => $now + 300, 'challengeId' => null, 'registrationId' => $id];
            return ['registrationId' => $id, 'csrfToken' => $newCsrf];
        });
    }
    public function registration(string $id): array {
        if (!FNCP_Identity_Contract::uuid($id)) { throw new InvalidArgumentException('Registered reference required.'); }
        $record = $this->snapshot()['registrations'][$id] ?? null;
        if ($record === null) { throw new RuntimeException('Registered reference required.'); }
        return $record;
    }
}
