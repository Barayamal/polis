# Identity response deadlines — local fail-closed proof

13 September 2026. No real identity provider, browser, external send or runtime
store is involved. Existing synthetic-only configuration remains unchanged.

## Corrected defect

The maintained client's five-second timeout signals cancellation, but a supplied
transport can ignore that signal. The previous adapter also awaited body reads
and stream cancellation without its own deadline. Such responses could leave a
login incomplete indefinitely.

`bounded-response.mjs` now enforces an independent, monotonic **five-second
budget per response**, from transport invocation through the last body chunk.
Token and JWKS requests each receive their own budget: this is not a five-second
whole-login guarantee. The identity factory exposes no budget override.

- Parent cancellation is propagated and also independently stops the wait.
- Late response/rejection is handled, discarded and best-effort cancelled; it
  cannot resume authentication or automatically redeem a code again.
- Body size stays at 65,536 bytes. Stored chunks are copied, empty chunks are not
  accumulated, and deadline checks also bound a stream of immediately available
  empty chunks while the event loop's timer cannot run.
- Cleanup never awaits an uncooperative cancellation. Timers and abort listeners
  are cleaned up; errors remain generic and reveal no token/provider details.
- Endpoint allowlisting, no redirects, omitted cookies, JSON-only responses,
  signature verification, synthetic mode and one-use callbacks are preserved.

JavaScript deadlines cannot interrupt synchronous adapter code or forcibly kill
I/O owned by a transport that ignores abort. This change fences authentication
completion; process supervision and a cooperative, reviewed production adapter
remain required. It is not a general resource-isolation or production SLA claim.

## Reproduce

From the source checkout with isolated identity dependencies already installed:

```sh
node --test deploy/fncp/identity-foundation/bounded-response.test.mjs
```

The **25 tests** include actual foundation completion with noncooperative token,
token-body and JWKS responses. Those three checks exercise the real fixed
five-second deadline concurrently, then prove the old callback is denied and a
fresh login succeeds. Shorter budgets are confined to the internal primitive's
isolated tests. The first test-run cancellation was a test-parent concurrency
configuration error; it was corrected and the complete suite rerun successfully.

The separate [TLS lab](TLS-PROOF.md) proves real encrypted loopback transport;
these deadline tests deliberately include adapters that ignore cancellation.
Neither proves a real issuer, cross-site browser redirect, mailbox ownership,
Indigenous heritage or approval to participate.

Sources: [openid-client custom transport](https://github.com/panva/openid-client/blob/main/docs/variables/customFetch.md)
and [Node AbortController documentation](https://nodejs.org/api/globals.html#class-abortcontroller).
