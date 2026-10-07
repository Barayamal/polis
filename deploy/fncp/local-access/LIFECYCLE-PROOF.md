# Graceful local shutdown — not provider round closure

13 September 2026. **SYNTHETIC_ONLY / KEEP_CLOSED**.

The access and browser services now latch their stopping state synchronously.
Once `close()` starts, a new HTTP handler cannot reserve admission, all three
access in-process entry points reject with a sanitized 503, and `listen()` cannot
reopen that same instance. Repeated `close()` calls share the same drain promise;
closing an instance that was never listening is supported.

Previously the direct entry points could append work while shutdown awaited an
earlier queue snapshot, potentially running after SQLite had been closed. The
latch eliminates that admission race. Already admitted requests/operations drain
in their existing serial order before database closure and in-memory capability
cleanup. Responses finishing during shutdown use `Connection: close`, avoiding
an unnecessary keep-alive delay without interrupting their result.

## Verification

```sh
node --test deploy/fncp/local-access/lifecycle.test.mjs
node --test deploy/fncp/local-access/start-close-race.test.mjs
```

Eight tests cover close-before-listen, repeated idle close, independently refused
listeners, closed direct entry points without verifier calls, an admitted provider
operation plus queued read, a failed operation without retry, and an actual
browser HTTP response draining before shutdown. Models use fresh in-memory
SQLite and ephemeral loopback listeners only. No retained store is opened and no
actual provider operation, vote, registration or external request occurs.

An independent review also reproduced immediate `listen(); close()` leaving the
startup promise unsettled. All three services now explicitly reject that pending
startup, remove its listening/error handlers on every path, refuse overlapping
starts and support retry after a genuine bind failure. Twelve additional tests
cover that race, exact-port reclamation, concurrent starts, repeated occupied-port
failures and invalid ports. This is 20 lifecycle/startup tests in total, separate
from the receiver's 25 new transport/ingest checks.

The [receiver proof](RECEIVER-PROOF.md) separately covers signed WordPress events,
including an ingest still running after its HTTP peer disconnects.

## Limits

- Shutdown is **not** a round-close command or provider allowlist revocation.
  A real deployment needs its separate verified close/reconciliation procedure.
- Admitted work retains its outcome. An already started provider side effect is
  not cancelled or automatically retried to make shutdown appear complete.
- A never-settling operation can keep graceful shutdown pending. No bounded
  shutdown SLA, forced process termination or distributed coordination is proved.
- This is graceful local lifecycle testing; the earlier SIGKILL browser tests are
  separate. Neither proves full restored WordPress/Pol.is application recovery.

Reference: [Node HTTP server lifecycle](https://nodejs.org/api/http.html#serverclosecallback).
