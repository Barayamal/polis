# Previously valid browser cookies after a BFF process crash

Scope: **local synthetic assurance only; keep production closed**.

`browser-restart.test.mjs` runs the unchanged `createLocalBrowser` HTTP handler in
two different OS child processes. The injected backend and fixture-password
authentication are **in-memory models**, not Pol.is or a real identity provider.

For each visitor, authenticated-account and participant phase, the test:

1. Allocates an ephemeral `127.0.0.1` port and invents all credentials in memory.
2. Obtains an actual cookie and CSRF value through the BFF HTTP routes. It checks
   that the exact retained values are live before the crash, including a
   mutation that passes CSRF verification but intentionally fails body validation
   without a backend call (a different CSRF is denied earlier); participant mode
   additionally initializes participation and reads a fixed synthetic statement.
3. Kills that exact child with `SIGKILL`, bypassing graceful session cleanup, and
   verifies that its listener has closed.
4. Starts a new PID on the **same origin and port**, with the same modeled backend
   credentials. It does not copy the BFF's private in-memory session map.
5. Replays seven operations with the **exact previously accepted cookie and CSRF**.
   All return 401 before any backend call, including login, invitation redemption,
   participation, a modeled vote route, registration and logout.
6. Verifies that `/api/session` replaces—not adopts—the old cookie with a fresh
   visitor. The old CSRF fails, the visitor cannot participate, and registration
   is not enabled. Replacement-process backend and vote counters remain zero.
7. Stops the replacement and independently checks that its port is closed.

A fourth test rejects running the child helper without its private test IPC
channel. Child environments and Node preload flags are not inherited. IPC is
limited to start, aggregate counters and stop. Neither child prints credentials
or writes files. HTTP request failures are not retried.

Run from the repository root with Node 24 or 26:

```sh
node --test deploy/fncp/local-browser/browser-restart.test.mjs
```

## What this does not prove

- No real browser is driven; this is actual HTTP protocol and process evidence,
  not rendering, browser crash recovery or cross-device behavior.
- It does not run the strict signed-synthetic OIDC route. The existing fixture
  authentication route remains explicitly labeled `SIMULATED_NOT_VERIFIED`.
- It proves that **browser cookies** cannot recover the BFF's old server-side
  capability map. It does not claim that old underlying access-service tokens
  were revoked by this BFF-only crash; the model deliberately retains them.
- No Docker, WordPress, Pol.is provider, real IdP, saved runtime, database, key
  file, email/SMS delivery, real participant or public surface is touched.
- It does not replay historical original-store credentials or extend the
  four-store restoration result into full application/disaster recovery.
- This is not release, deployment, eligibility-verification or launch authority.

The separate actual four-store proof remains responsible for restored
access/activation state. These two evidence levels must not be merged into a
claim that the entire production application has been recovered and validated.
