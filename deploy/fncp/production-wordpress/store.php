<?php
declare(strict_types=1);
require_once __DIR__ . '/contract.php';

/** Complete bounded state is one CAS record. No network call occurs in a mutation. */
final class FNCP_Production_Store {
    private Closure $read; private Closure $swap; private Closure $create; private Closure $clock;
    private array $configuration; private string $binding; private bool $clockFault = false;
    public function __construct(array $configuration, callable $read, callable $swap, callable $create, ?callable $clock = null) {
        $this->configuration = FNCP_Production_Contract::configuration($configuration);
        $this->binding = hash('sha256', FNCP_Production_Contract::canonical($configuration));
        $this->read = Closure::fromCallable($read); $this->swap = Closure::fromCallable($swap); $this->create = Closure::fromCallable($create);
        $this->clock = Closure::fromCallable($clock ?? static fn(): int => (int) floor(microtime(true) * 1000));
    }
    private function empty(): array { return ['schemaVersion'=>1,'configurationDigest'=>$this->binding,'lastObservedMs'=>0,'clockClosed'=>false,'registrations'=>[],'events'=>[]]; }
    private function decode(string $raw): array {
        $s = json_decode($raw, true, 16, JSON_THROW_ON_ERROR); if (!is_array($s)) { FNCP_Production_Contract::deny(); }
        FNCP_Production_Contract::exact($s, ['schemaVersion','configurationDigest','lastObservedMs','clockClosed','registrations','events']);
        if ($s['schemaVersion'] !== 1 || $s['configurationDigest'] !== $this->binding || !is_int($s['lastObservedMs']) || $s['lastObservedMs'] < 0 || $s['lastObservedMs'] > 9007199254740991
            || !is_bool($s['clockClosed']) || !is_array($s['registrations']) || !is_array($s['events']) || count($s['registrations']) > 20 || count($s['events']) > 40
            || FNCP_Production_Contract::canonical($s) !== $raw) { FNCP_Production_Contract::deny(); }
        $accounts = []; $receipts = []; $pairs = [];
        foreach ($s['registrations'] as $id => $r) {
            if (!is_array($r)) { FNCP_Production_Contract::deny(); }
            FNCP_Production_Contract::exact($r, ['registrationId','receipt','receiptDigest','createdAt','state','version','decisionEventId']);
            if (!FNCP_Production_Contract::uuid($id) || $r['registrationId'] !== $id || !is_array($r['receipt']) || !FNCP_Production_Contract::digest($r['receiptDigest'])
                || !is_int($r['createdAt']) || $r['createdAt'] < 0 || $r['createdAt'] > intdiv($s['lastObservedMs'], 1000)) { FNCP_Production_Contract::deny(); }
            FNCP_Production_Contract::registration($r['receipt'], $this->configuration, $r['createdAt']);
            if ($r['receiptDigest'] !== hash('sha256', FNCP_Production_Contract::canonical($r['receipt'])) || isset($accounts[$r['receipt']['accountId']]) || isset($receipts[$r['receipt']['receiptId']])) { FNCP_Production_Contract::deny(); }
            $accounts[$r['receipt']['accountId']] = true; $receipts[$r['receipt']['receiptId']] = true;
            if (!(($r['version'] === 0 && $r['state'] === 'pending' && $r['decisionEventId'] === null)
                || ($r['version'] === 1 && $r['state'] === 'approved' && FNCP_Production_Contract::uuid($r['decisionEventId']))
                || ($r['version'] === 2 && $r['state'] === 'revoked' && FNCP_Production_Contract::uuid($r['decisionEventId'])))) { FNCP_Production_Contract::deny(); }
        }
        foreach ($s['events'] as $id => $record) {
            if (!is_array($record)) { FNCP_Production_Contract::deny(); }
            FNCP_Production_Contract::exact($record, ['event','body','delivered','attempts','lastResult']);
            if (!is_array($record['event'])) { FNCP_Production_Contract::deny(); } $e = $record['event']; FNCP_Production_Contract::event($e, $this->configuration);
            $r = $s['registrations'][$e['registrationId']] ?? null; $pair = $e['registrationId'] . ':' . $e['version'];
            if ($id !== $e['eventId'] || !is_string($record['body']) || FNCP_Production_Contract::canonical($e) !== $record['body']
                || !is_bool($record['delivered']) || !is_int($record['attempts']) || $record['attempts'] < 0
                || !in_array($record['lastResult'], ['PENDING','ACKNOWLEDGED','TRANSPORT_UNAVAILABLE','ACK_REJECTED'], true)
                || $record['delivered'] !== ($record['lastResult'] === 'ACKNOWLEDGED') || !$r || $e['accountId'] !== $r['receipt']['accountId']
                || $e['version'] > $r['version'] || $e['occurredAt'] < $r['createdAt'] || $e['occurredAt'] > intdiv($s['lastObservedMs'], 1000) || isset($pairs[$pair])) { FNCP_Production_Contract::deny(); }
            $pairs[$pair] = true;
        }
        foreach ($s['registrations'] as $r) {
            if ($r['version'] === 0) { continue; } $e = $s['events'][$r['decisionEventId']]['event'] ?? null;
            if (!$e || $e['registrationId'] !== $r['registrationId'] || $e['state'] !== $r['state'] || $e['version'] !== $r['version']) { FNCP_Production_Contract::deny(); }
        }
        return $s;
    }
    private function mutate(callable $operation) {
        for ($attempt = 0; $attempt < 12; $attempt++) {
            $raw = ($this->read)(); if ($raw !== null && !is_string($raw)) { FNCP_Production_Contract::deny(); }
            if ($raw === null) { ($this->create)(FNCP_Production_Contract::canonical($this->empty())); continue; }
            $s = $this->decode($raw); $error = null; $result = null; $now = null;
            try { $now = ($this->clock)(); } catch (Throwable $e) { $this->clockFault = true; }
            if (!is_int($now) || $now < $s['lastObservedMs'] || $now < 0 || $now > 9007199254740991) { $this->clockFault = true; }
            else { $s['lastObservedMs'] = $now; }
            $this->clockFault = $this->clockFault || $s['clockClosed'];
            $s['clockClosed'] = $this->clockFault;
            if ($s['clockClosed']) { $error = new FNCP_Production_Denied('Registration operation unavailable.'); }
            else { $beforeOperation = $s; try { $result = $operation($s, intdiv($now, 1000)); } catch (Throwable $e) { $s = $beforeOperation; $error = $e; } }
            $next = FNCP_Production_Contract::canonical($s); $this->decode($next);
            if ($next === $raw || ($this->swap)($raw, $next)) { if ($error !== null) { throw $error; } return $result; }
        }
        FNCP_Production_Contract::deny();
    }
    public function rpc(string $action, string $raw, string $timestamp, string $signature): array {
        return $this->mutate(function (array &$s, int $now) use ($action, $raw, $timestamp, $signature): array {
            $b = FNCP_Production_Contract::request($action, $raw, $timestamp, $signature, $this->configuration, $s['lastObservedMs']);
            if ($action === 'status') { return FNCP_Production_Contract::signedResponse($action, $this->status($s, $b, $now), $this->configuration); }
            $digest = hash('sha256', FNCP_Production_Contract::canonical($b));
            foreach ($s['registrations'] as $r) {
                if ($r['receipt']['accountId'] === $b['accountId'] || $r['receipt']['receiptId'] === $b['receiptId']) {
                    if ($r['receipt']['accountId'] !== $b['accountId'] || $r['receipt']['receiptId'] !== $b['receiptId'] || !hash_equals($r['receiptDigest'], $digest)) { FNCP_Production_Contract::deny(); }
                    return FNCP_Production_Contract::signedResponse($action, $this->registrationResponse($r), $this->configuration);
                }
            }
            FNCP_Production_Contract::registration($b, $this->configuration, $now);
            if (count($s['registrations']) >= 20) { FNCP_Production_Contract::deny(); }
            $id = FNCP_Production_Contract::uuid4(); if (isset($s['registrations'][$id])) { FNCP_Production_Contract::deny(); }
            $r = ['registrationId'=>$id,'receipt'=>$b,'receiptDigest'=>$digest,'createdAt'=>$now,'state'=>'pending','version'=>0,'decisionEventId'=>null];
            $s['registrations'][$id] = $r; return FNCP_Production_Contract::signedResponse($action, $this->registrationResponse($r), $this->configuration);
        });
    }
    private function registrationResponse(array $r): array { return ['schemaVersion'=>1,'deploymentId'=>$this->configuration['deploymentId'],'conversationId'=>$this->configuration['conversationId'],
        'receiptId'=>$r['receipt']['receiptId'],'registrationId'=>$r['registrationId'],'status'=>'SUBMITTED_NOT_APPROVED']; }
    private function status(array $s, array $b, int $now): array {
        $r = null; foreach ($s['registrations'] as $candidate) { if ($candidate['receipt']['accountId'] === $b['accountId']) { $r = $candidate; break; } }
        $e = $r && $r['decisionEventId'] !== null ? $s['events'][$r['decisionEventId']] : null;
        return ['schemaVersion'=>1,'deploymentId'=>$this->configuration['deploymentId'],'conversationId'=>$this->configuration['conversationId'],'accountId'=>$b['accountId'],'nonce'=>$b['nonce'],
            'registrationId'=>$r['registrationId'] ?? null,'state'=>$r['state'] ?? 'unregistered','version'=>$r['version'] ?? 0,
            'decisionEventId'=>$r['decisionEventId'] ?? null,'deliveryPending'=>$e !== null && !$e['delivered'],'observedAt'=>$now];
    }
    public function decide(string $registrationId, string $state): array {
        if (!FNCP_Production_Contract::uuid($registrationId) || !in_array($state, ['approved','revoked'], true)) { FNCP_Production_Contract::deny(); }
        return $this->mutate(function (array &$s, int $now) use ($registrationId, $state): array {
            if (!isset($s['registrations'][$registrationId])) { FNCP_Production_Contract::deny(); } $r =& $s['registrations'][$registrationId];
            if ($r['state'] === $state) { return $s['events'][$r['decisionEventId']]; }
            if ($r['state'] === 'revoked') { FNCP_Production_Contract::deny(); }
            $version = $state === 'revoked' ? 2 : 1; $id = FNCP_Production_Contract::uuid4();
            if (isset($s['events'][$id]) || count($s['events']) >= 40) { FNCP_Production_Contract::deny(); }
            $e = ['schemaVersion'=>1,'eventId'=>$id,'deploymentId'=>$this->configuration['deploymentId'],'conversationId'=>$this->configuration['conversationId'],
                'registrationId'=>$registrationId,'accountId'=>$r['receipt']['accountId'],'version'=>$version,'state'=>$state,'occurredAt'=>$now];
            $record = ['event'=>$e,'body'=>FNCP_Production_Contract::canonical($e),'delivered'=>false,'attempts'=>0,'lastResult'=>'PENDING'];
            $r['state'] = $state; $r['version'] = $version; $r['decisionEventId'] = $id; $s['events'][$id] = $record; return $record;
        });
    }
    /** Capture the exact pending event just before transport; call again on every retry. */
    public function delivery(string $eventId): ?array {
        return $this->mutate(function (array &$s, int $now) use ($eventId): ?array {
            $r = $s['events'][$eventId] ?? null; if (!$r) { FNCP_Production_Contract::deny(); } if ($r['delivered']) { return null; }
            $stamp = (string) $now;
            return ['event'=>$r['event'],'body'=>$r['body'],'timestamp'=>$stamp,'signature'=>'sha256=' . FNCP_Production_Contract::mac(FNCP_Production_Contract::EVENT_DOMAIN . $stamp . '.' . $r['body'], $this->configuration['eventKey'])];
        });
    }
    public function deliveryResult(string $eventId, bool $accepted, string $result): void {
        if (!in_array($result, ['ACKNOWLEDGED','TRANSPORT_UNAVAILABLE','ACK_REJECTED'], true) || $accepted !== ($result === 'ACKNOWLEDGED')) { FNCP_Production_Contract::deny(); }
        $this->mutate(static function (array &$s, int $now) use ($eventId, $accepted, $result): void {
            if (!isset($s['events'][$eventId])) { FNCP_Production_Contract::deny(); } $r =& $s['events'][$eventId];
            $r['attempts'] = min(PHP_INT_MAX - 1, $r['attempts']) + 1;
            if (!$r['delivered']) { $r['delivered'] = $accepted; $r['lastResult'] = $result; }
        });
    }
    public function pending(): array { return $this->mutate(static function (array &$s, int $now): array {
        $p = array_values(array_filter($s['events'], static fn(array $r): bool => !$r['delivered']));
        usort($p, static fn(array $a, array $b): int => $b['event']['version'] <=> $a['event']['version']); return $p;
    }); }
    /** Administrative projection excludes accounts, receipt claims and all signing keys. */
    public function adminRows(): array { return $this->mutate(static function (array &$s, int $now): array {
        $rows = []; foreach ($s['registrations'] as $r) { $event = $r['decisionEventId'] === null ? null : $s['events'][$r['decisionEventId']];
            $rows[] = ['registrationId'=>$r['registrationId'],'consentVersion'=>$r['receipt']['consentVersion'],'noticeSha256'=>$r['receipt']['noticeSha256'],
                'createdAt'=>$r['createdAt'],'state'=>$r['state'],'version'=>$r['version'],'delivery'=>$event['lastResult'] ?? 'NOT_DECIDED']; }
        return $rows;
    }); }
}
