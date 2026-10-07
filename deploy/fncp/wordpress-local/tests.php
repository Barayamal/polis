<?php
/** Pure deterministic/model checks; these do not claim an installed WP integration. */
declare(strict_types=1);
require_once __DIR__ . '/journal.php';

$count = 0;
function check(bool $condition, string $message = 'Assertion failed'): void {
    if (!$condition) { throw new RuntimeException($message); }
}
function rejects(callable $operation): void {
    try { $operation(); } catch (Throwable $error) { return; }
    throw new RuntimeException('Expected rejection.');
}
function test(string $name, callable $operation): void {
    global $count;
    $operation();
    $count++;
    echo "PASS {$name}\n";
}
function memoryJournal(?string &$raw, ?Closure $race = null): FNCP_Local_Journal {
    return new FNCP_Local_Journal(
        static function () use (&$raw): ?string { return $raw; },
        static function (string $old, string $next) use (&$raw, $race): bool {
            if ($race !== null && $race($old, $next, $raw)) { return false; }
            if ($raw !== $old) { return false; }
            $raw = $next;
            return true;
        },
        static function (string $next) use (&$raw): bool {
            if ($raw !== null) { return false; }
            $raw = $next;
            return true;
        }
    );
}

test('contract accepts canonical synthetic fixture only', static function (): void {
    check(FNCP_Local_Contract::fixture('synthetic_alice'));
    foreach (['alice', 'synthetic_1', 'synthetic_Alice', 'synthetic_alice@example.invalid', 'synthetic_a/b', 'synthetic_a ', "synthetic_a\n", 'synthetic_' . str_repeat('a', 41)] as $bad) {
        check(!FNCP_Local_Contract::fixture($bad));
    }
});
test('round is exactly the disposable fixed round', static function (): void {
    check(FNCP_Local_Contract::round('synthetic_round_local'));
    check(!FNCP_Local_Contract::round('synthetic_round_other'));
});
test('event has exact schema and UUID v4', static function (): void {
    $event = FNCP_Local_Contract::event('synthetic_round_local', 'synthetic_alice', 'approved', 1);
    check(array_keys($event) === ['schema_version', 'event_id', 'subject', 'round_id', 'version', 'state', 'occurred_at']);
    check(preg_match('/\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/', $event['event_id']) === 1);
    check(preg_match('/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\z/', $event['occurred_at']) === 1);
});
test('invalid event states and versions rejected', static function (): void {
    foreach (['pending', 'yes', 'APPROVED'] as $state) { rejects(static fn() => FNCP_Local_Contract::event('synthetic_round_local', 'synthetic_alice', $state, 1)); }
    foreach ([0, -1, 9007199254740992] as $version) { rejects(static fn() => FNCP_Local_Contract::event('synthetic_round_local', 'synthetic_alice', 'approved', $version)); }
});
test('HMAC binds exact raw bytes and timestamp', static function (): void {
    $key = str_repeat('k', 64);
    $body = '{"a":1}';
    $signature = FNCP_Local_Contract::signature($key, '1789270000', $body);
    check($signature === 'sha256=' . hash_hmac('sha256', '1789270000.' . $body, $key));
    check($signature !== FNCP_Local_Contract::signature($key, '1789270001', $body));
    check($signature !== FNCP_Local_Contract::signature($key, '1789270000', $body . ' '));
});
test('signing rejects weak configuration', static function (): void {
    rejects(static fn() => FNCP_Local_Contract::signature('short', '1789270000', '{}'));
    rejects(static fn() => FNCP_Local_Contract::signature(str_repeat('k', 64), 'tomorrow', '{}'));
});
test('delivery ACK binds event and numeric version', static function (): void {
    $event = FNCP_Local_Contract::event('synthetic_round_local', 'synthetic_alice', 'approved', 1);
    $ack = ['ok' => true, 'event_id' => $event['event_id'], 'version' => 1];
    check(FNCP_Local_Contract::acknowledged(200, FNCP_Local_Contract::encode($ack), $event));
    check(!FNCP_Local_Contract::acknowledged(202, FNCP_Local_Contract::encode($ack), $event));
    $ack['version'] = '1';
    check(!FNCP_Local_Contract::acknowledged(200, FNCP_Local_Contract::encode($ack), $event));
    check(!FNCP_Local_Contract::acknowledged(200, 'OK', $event));
    check(!FNCP_Local_Contract::acknowledged(200, str_repeat('a', 4097), $event));
});
test('empty read does not create evidence', static function (): void {
    $raw = null; $journal = memoryJournal($raw);
    check($journal->snapshot() === FNCP_Local_Journal::emptyJournal());
    check($raw === null);
});
test('approval version and immutable outbox are one persisted record', static function (): void {
    $raw = null; $journal = memoryJournal($raw);
    $record = $journal->change('synthetic_round_local', 'synthetic_alice', 'approved');
    $snapshot = $journal->snapshot();
    check($record['event']['version'] === 1 && !$record['delivered']);
    check(count($snapshot['subjects']) === 1 && count($snapshot['events']) === 1);
    check(json_decode($record['body'], true) === $record['event']);
});
test('replayed same decision preserves event ID body and version', static function (): void {
    $raw = null; $journal = memoryJournal($raw);
    $first = $journal->change('synthetic_round_local', 'synthetic_alice', 'approved');
    $second = $journal->change('synthetic_round_local', 'synthetic_alice', 'approved');
    check($first === $second && count($journal->snapshot()['events']) === 1);
});
test('revocation advances version and preserves prior outbox', static function (): void {
    $raw = null; $journal = memoryJournal($raw);
    $journal->change('synthetic_round_local', 'synthetic_alice', 'approved');
    $record = $journal->change('synthetic_round_local', 'synthetic_alice', 'revoked');
    check($record['event']['version'] === 2);
    check(count($journal->snapshot()['events']) === 2);
    check($journal->pending()[0]['event']['state'] === 'revoked');
});
test('revocation terminal and repeated revocation idempotent', static function (): void {
    $raw = null; $journal = memoryJournal($raw);
    $one = $journal->change('synthetic_round_local', 'synthetic_alice', 'revoked');
    check($one === $journal->change('synthetic_round_local', 'synthetic_alice', 'revoked'));
    rejects(static fn() => $journal->change('synthetic_round_local', 'synthetic_alice', 'approved'));
});
test('delivery failure preserves raw body for signed retry', static function (): void {
    $raw = null; $journal = memoryJournal($raw);
    $record = $journal->change('synthetic_round_local', 'synthetic_alice', 'approved');
    $journal->deliveryResult($record['event']['event_id'], false, 'TRANSPORT_UNAVAILABLE');
    $retry = $journal->pending()[0];
    check($retry['body'] === $record['body'] && $retry['event'] === $record['event']);
    check($retry['attempts'] === 1 && !$retry['delivered']);
});
test('acknowledged delivery survives a late failed retry', static function (): void {
    $raw = null; $journal = memoryJournal($raw);
    $record = $journal->change('synthetic_round_local', 'synthetic_alice', 'approved');
    $id = $record['event']['event_id'];
    $journal->deliveryResult($id, true, 'ACKNOWLEDGED');
    $journal->deliveryResult($id, false, 'TRANSPORT_UNAVAILABLE');
    $saved = $journal->snapshot()['events'][$id];
    check($saved['delivered'] && $saved['last_result'] === 'ACKNOWLEDGED' && $saved['attempts'] === 2);
    check($journal->pending() === []);
});
test('unknown result and event cannot mutate journal', static function (): void {
    $raw = null; $journal = memoryJournal($raw);
    $journal->change('synthetic_round_local', 'synthetic_alice', 'approved');
    $before = $raw;
    rejects(static fn() => $journal->deliveryResult('absent', true, 'ACKNOWLEDGED'));
    rejects(static fn() => $journal->deliveryResult('absent', true, 'user-controlled-secret'));
    check($raw === $before);
});
test('invalid data and round never stored', static function (): void {
    $raw = null; $journal = memoryJournal($raw);
    rejects(static fn() => $journal->change('synthetic_round_local', 'somebody@example.invalid', 'approved'));
    rejects(static fn() => $journal->change('live_round', 'synthetic_alice', 'approved'));
    check($raw === null);
});
test('20 fixture limit fails closed without overwriting', static function (): void {
    $raw = null; $journal = memoryJournal($raw);
    for ($i = 0; $i < 20; $i++) { $journal->change('synthetic_round_local', 'synthetic_person' . $i, 'approved'); }
    $before = $raw;
    rejects(static fn() => $journal->change('synthetic_round_local', 'synthetic_extra', 'approved'));
    check($before === $raw);
});
test('restart retains decisions and retry bodies', static function (): void {
    $raw = null; $journal = memoryJournal($raw);
    $first = $journal->change('synthetic_round_local', 'synthetic_alice', 'approved');
    $restarted = memoryJournal($raw);
    check($restarted->pending()[0] === $first);
});
test('CAS collision rereads before committing', static function (): void {
    $raw = null; $collisions = 0;
    $journal = memoryJournal($raw, static function (string $old, string $next, ?string &$current) use (&$collisions): bool {
        if ($collisions++ !== 0) { return false; }
        $other = memoryJournal($current);
        $other->change('synthetic_round_local', 'synthetic_other', 'approved');
        return true;
    });
    $journal->change('synthetic_round_local', 'synthetic_alice', 'approved');
    check(count($journal->snapshot()['subjects']) === 2);
    check(count($journal->snapshot()['events']) === 2);
});
test('persistent CAS contention never sends or loses history', static function (): void {
    $raw = FNCP_Local_Contract::encode(FNCP_Local_Journal::emptyJournal());
    $before = $raw;
    $journal = memoryJournal($raw, static fn() => true);
    rejects(static fn() => $journal->change('synthetic_round_local', 'synthetic_alice', 'approved'));
    check($raw === $before);
});
test('corrupt journal fails closed', static function (): void {
    $raw = '{"schema_version":999}'; $journal = memoryJournal($raw);
    rejects(static fn() => $journal->snapshot());
    rejects(static fn() => $journal->change('synthetic_round_local', 'synthetic_alice', 'approved'));
});
test('changed stored body rejected before retry', static function (): void {
    $raw = null; $journal = memoryJournal($raw);
    $record = $journal->change('synthetic_round_local', 'synthetic_alice', 'approved');
    $corrupted = $journal->snapshot();
    $corrupted['events'][$record['event']['event_id']]['body'] .= ' ';
    $raw = FNCP_Local_Contract::encode($corrupted);
    rejects(static fn() => $journal->pending());
});
test('extra event fields rejected before signing or storage', static function (): void {
    $event = FNCP_Local_Contract::event('synthetic_round_local', 'synthetic_alice', 'approved', 1);
    $event['email'] = 'forbidden@example.invalid';
    rejects(static fn() => FNCP_Local_Contract::assertEvent($event));
});
echo "Synthetic contract/journal model checks: {$count} passed.\n";
