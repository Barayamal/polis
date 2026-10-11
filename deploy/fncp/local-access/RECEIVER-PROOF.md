# Synthetic WordPress receiver admission and shutdown proof

Local-only increment, 13 September 2026. This strengthens Barayamal's custom
receiver around self-hosted Pol.is; it is not an upstream Pol.is feature or
production-readiness claim.

## Changes

- One fixed 32-request admission limit spans body collection and the complete
  `ingest` promise. Capacity is reserved before any body read. Overflow returns
  503 without reading the event body or calling ingest. Incomplete requests that
  can still receive a response are marked `Connection: close`.
- Request timestamps are checked against a nonnegative, safe-integer millisecond
  clock both before body collection and immediately before ingest. Invalid,
  unavailable, backwards-shifted or expired clocks/signatures fail closed.
  The existing inclusive 300-second signature window remains unchanged.
- An incomplete, aborted or disconnected request cannot start ingest. Response
  writes are suppressed after the peer is gone or a response is already ended;
  acknowledgement serialization happens before committing response headers.
- Once ingest starts, an exception means its outcome is **unconfirmed**, not
  necessarily unapplied. The response instructs the sender to retain and retry
  the exact same event. The receiver neither retries nor imposes a timeout on a
  potentially already-applied side effect.
- Closing rejects new admission, including a pipelined request on an existing
  socket, and waits for admitted requests and ingests to settle. Disconnecting a
  client does not release its unsettled ingest slot. Close is idempotent and a
  closed receiver object cannot reopen. Replies during shutdown close their
  connections. Unexpected server-close errors reject; only an already-stopped
  server is treated as a completed close.

The existing `fixture-only` mode, loopback-only address and exact Host/path/method
checks, browser-header exclusions, JSON requirement, 4,096-byte body maximum,
raw-body HMAC, exact event-ID match, synthetic event schema, 12-second Node
request timeout and five-second header timeout remain in place. Existing event
gate idempotency and terminal-revocation rules are unchanged.

## Verification

Executed successfully on Node **24.21.0** and **26.8.2**:

```sh
node --test deploy/fncp/local-access/wordpress-receiver-hardening.test.mjs \
  deploy/fncp/local-access/wordpress-events.test.mjs
```

**37/37 per runtime:** 25 new receiver-hardening tests and 12 existing
event-gate/receiver tests. Zero failures, cancellations or skips. Running the
same suite twice does not double the unique coverage.

New tests exercise invalid clocks, freshness changes during partial-body reads,
both exact time-window boundaries, 32 held body readers, 32 unsettled ingests,
overflow with no ingest, recovery after abort, malformed-request slot release,
incomplete-body rejection, ambiguous ingest/acknowledgement failure, and close
drain/refusal. A real loopback TCP pipeline verifies that a second request on an
already-active socket cannot ingest after close begins while the first receives
its acknowledgement with `Connection: close`. The closing socket may prevent a
queued second rejection response from reaching the client; no second successful
acknowledgement is produced.

One test uses a fresh **in-memory SQLite event gate**: the client disconnects
before its acknowledgement, the original ingest finishes, and the identical
event retry returns `IDEMPOTENT_NO_OP` with exactly one applied operation and one
applied journal row. This is not evidence about a retained registration store.

## Boundaries and limitations

All HTTP/TCP tests bind fresh ephemeral `127.0.0.1` ports and use invented signed
events. No Docker, WordPress installation, retained stores, private keys,
provider calls, real identities or public surfaces were accessed. Tests clean
up only their own connections and in-memory database.

Admission is per process, not a distributed lock or production load benchmark.
The Node request/header timeouts limit request reception; they are not an
application-level deadline for ingestion. An ingest that never settles occupies
its slot and keeps graceful shutdown pending deliberately, because the receiver
cannot safely infer whether a side effect happened. Operational cancellation,
crash reconciliation, real authentication, deployment integration and production
assurance remain separate work. Existing synthetic approval still does not
verify Indigenous heritage.
