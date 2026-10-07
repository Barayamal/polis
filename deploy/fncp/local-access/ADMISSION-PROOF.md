# Local gateway admission proof

Status: **SYNTHETIC_ONLY / KEEP_CLOSED**. This is finite in-process admission,
not production load assurance, a distributed rate limiter or GO authority.

## Changes

- The local access service has one fixed **32-operation** budget shared by HTTP
  requests that are reading a body, HTTP requests waiting/running in its serial
  queue, and the direct `authenticateIdentity`, `registrationIdentity` and
  `ingestWordPressEvent` entry points.
- The local browser service has a separate fixed **32-request** budget. A slot is
  reserved before collecting a body, so incomplete POSTs cannot bypass the
  previous queue-only check. Static requests also briefly use that same budget.
- Excess work receives only a sanitized **503 / Local request capacity reached.**
  It is not enqueued and does not call a provider, verify an identity, create a
  browser session or write the access database.
- An early rejection with an incomplete body sends `Connection: close`; writing
  a response to an already destroyed client is avoided. An admitted slot is
  released on completion, rejection or body-read abort using `finally`.
- Existing serial dispatch order, identity/approval/activation checks, terminal
  revocation rules, body-size limits and no-automatic-vote-retry rules remain in
  place. These budgets do not open a round or create a new route.

## Reproducible checks

From the local Pol.is clone:

```sh
node --test deploy/fncp/local-access/admission.test.mjs
```

Seven tests use newly created synthetic SQLite fixtures and agent-owned ephemeral
`127.0.0.1` listeners, with model providers only. They establish:

1. Thirty-two incomplete access bodies occupy the bound; the next HTTP and direct
   operation is rejected, and aborting a reader restores capacity.
2. Thirty-two incomplete browser bodies occupy its separate bound; excess work
   is rejected and abort restores capacity.
3. A paused browser backend operation and 31 waiting operations share the same
   bound; excess work makes no additional backend call and completion recovers.
4. A paused access operation and 31 waiting direct reads share the HTTP/direct
   bound. All three excess direct entry points and excess HTTP work return 503;
   the SQLite snapshot, verifier count and provider count remain unchanged by
   that overflow. Previously admitted work completes in order after release.
5. Malformed and origin-denied access requests do not leak admission slots.
6. Malformed and origin-denied browser requests do not leak admission slots.
7. Rejected direct operations do not leak slots or retain synthetic database
   changes.

The tests close only their listeners and remove only their exact `mkdtemp`
directories. They do not use retained original stores, Docker, an actual Pol.is
origin, a real identity provider, WordPress administration or public surfaces.

## Boundaries and recovery semantics

- This bounds admitted application handlers, **not** pre-header TCP connections,
  keep-alive sockets, another process or the separate WordPress HTTP receiver's
  body readers. Production reverse-proxy limits still need separate design and
  testing.
- It does not add a provider-operation deadline, cancel a provider side effect
  already started, interrupt existing serial operations, or make shutdown
  instantaneous. Existing transport deadlines and outcome-uncertainty rules
  still apply. There is no automatic resubmission.
- A full queue can reject a new WordPress event, including a revocation. A 503
  is **not an acknowledgement** and must not be recorded as applied. Retain the
  exact event identity and its existing pending/reconciliation state; use the
  established same-event retry procedure when capacity is available. No event
  is reordered around already admitted operations.
- Counts and outcomes here are local model checks, not a new end-to-end Pol.is
  run, a public traffic test, a production security certification, or evidence
  of Indigenous heritage verification.
