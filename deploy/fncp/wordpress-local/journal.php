<?php
/** Atomic single-record journal: subject version and outbox body commit together. */
declare(strict_types=1);
require_once __DIR__ . '/contract.php';

final class FNCP_Local_Journal {
    private Closure $read;
    private Closure $compareSwap;
    private Closure $create;

    public function __construct(callable $read, callable $compareSwap, callable $create) {
        $this->read = Closure::fromCallable($read);
        $this->compareSwap = Closure::fromCallable($compareSwap);
        $this->create = Closure::fromCallable($create);
    }

    public static function emptyJournal(): array {
        return ['schema_version' => 1, 'subjects' => [], 'events' => []];
    }

    private static function decode(string $raw): array {
        $journal = json_decode($raw, true, 16, JSON_THROW_ON_ERROR);
        if (!is_array($journal) || ($journal['schema_version'] ?? null) !== 1
            || !is_array($journal['subjects'] ?? null) || !is_array($journal['events'] ?? null)
            || count($journal['subjects']) > FNCP_Local_Contract::MAX_SUBJECTS
            || count($journal['events']) > FNCP_Local_Contract::MAX_EVENTS) {
            throw new RuntimeException('Synthetic journal is invalid; no change was made.');
        }
        foreach ($journal['events'] as $id => $record) {
            if (!is_array($record) || !is_array($record['event'] ?? null)) {
                throw new RuntimeException('Synthetic outbox is invalid; no change was made.');
            }
            FNCP_Local_Contract::assertEvent($record['event']);
            if ($id !== $record['event']['event_id'] || ($record['body'] ?? null) !== FNCP_Local_Contract::encode($record['event'])
                || !is_bool($record['delivered'] ?? null) || !is_int($record['attempts'] ?? null) || $record['attempts'] < 0
                || !in_array($record['last_result'] ?? null, ['PENDING', 'ACKNOWLEDGED', 'TRANSPORT_UNAVAILABLE', 'ACK_REJECTED'], true)
                || ($record['delivered'] && $record['last_result'] !== 'ACKNOWLEDGED')) {
                throw new RuntimeException('Synthetic outbox body or delivery metadata is invalid.');
            }
        }
        foreach ($journal['subjects'] as $key => $subject) {
            $event = $journal['events'][$subject['event_id'] ?? '']['event'] ?? null;
            if (!is_array($subject) || !is_array($event) || $key !== $event['round_id'] . ':' . $event['subject']
                || ($subject['version'] ?? null) !== $event['version'] || ($subject['state'] ?? null) !== $event['state']) {
                throw new RuntimeException('Synthetic subject authority is invalid.');
            }
        }
        return $journal;
    }

    public function snapshot(): array {
        $raw = ($this->read)();
        return $raw === null ? self::emptyJournal() : self::decode($raw);
    }

    private function mutate(callable $mutation) {
        for ($attempt = 0; $attempt < 8; $attempt++) {
            $raw = ($this->read)();
            if ($raw === null) {
                ($this->create)(FNCP_Local_Contract::encode(self::emptyJournal()));
                continue;
            }
            $journal = self::decode($raw);
            $result = $mutation($journal);
            $next = FNCP_Local_Contract::encode($journal);
            if ($next === $raw || ($this->compareSwap)($raw, $next)) {
                return $result;
            }
        }
        throw new RuntimeException('Concurrent journal update; retry this local operation.');
    }

    public function change(string $round, string $subject, string $state): array {
        FNCP_Local_Contract::validate($round, $subject, $state);
        return $this->mutate(static function (array &$journal) use ($round, $subject, $state): array {
            $key = $round . ':' . $subject;
            $previous = $journal['subjects'][$key] ?? null;
            if ($previous !== null && $previous['state'] === $state) {
                return $journal['events'][$previous['event_id']];
            }
            if ($previous !== null && $previous['state'] === 'revoked') {
                throw new RuntimeException('Reapproval is unavailable in this synthetic proof. Use a new fixture/round.');
            }
            if ($previous === null && count($journal['subjects']) >= FNCP_Local_Contract::MAX_SUBJECTS) {
                throw new RuntimeException('Synthetic account capacity reached.');
            }
            if (count($journal['events']) >= FNCP_Local_Contract::MAX_EVENTS) {
                throw new RuntimeException('Synthetic journal capacity reached. Existing evidence was preserved.');
            }
            $event = FNCP_Local_Contract::event($round, $subject, $state, $previous === null ? 1 : $previous['version'] + 1);
            $record = ['event' => $event, 'body' => FNCP_Local_Contract::encode($event), 'delivered' => false,
                'attempts' => 0, 'last_attempt_at' => null, 'last_result' => 'PENDING'];
            $journal['subjects'][$key] = ['version' => $event['version'], 'state' => $state, 'event_id' => $event['event_id']];
            $journal['events'][$event['event_id']] = $record;
            return $record;
        });
    }

    public function deliveryResult(string $eventId, bool $accepted, string $result): void {
        if (!in_array($result, ['ACKNOWLEDGED', 'TRANSPORT_UNAVAILABLE', 'ACK_REJECTED'], true)) {
            throw new InvalidArgumentException('Invalid delivery result.');
        }
        $this->mutate(static function (array &$journal) use ($eventId, $accepted, $result): void {
            if (!isset($journal['events'][$eventId])) {
                throw new RuntimeException('Unknown synthetic event.');
            }
            $record =& $journal['events'][$eventId];
            $record['attempts']++;
            $record['last_attempt_at'] = gmdate('Y-m-d\TH:i:s\Z');
            // A late failed retry must not downgrade a previously verified ACK.
            if (!$record['delivered']) {
                $record['delivered'] = $accepted;
                $record['last_result'] = $result;
            }
        });
    }

    public function pending(int $limit = 20): array {
        $snapshot = $this->snapshot();
        $records = array_values(array_filter($snapshot['events'], static fn(array $record): bool => !$record['delivered']));
        // Deliver revocation/newer authority first. Receiver must reject stale replay.
        usort($records, static fn(array $left, array $right): int => $right['event']['version'] <=> $left['event']['version']);
        return array_slice($records, 0, max(0, min(20, $limit)));
    }
}
