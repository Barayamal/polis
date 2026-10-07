# Option C — preparatory startup and application TLS

Checkpoint: **2026-09-13T23:54:33+10:00. LOCAL_ONLY / KEEP_CLOSED.**

The local code now has a validated synthetic bootstrap profile, explicit startup-effect suppression, strict application PostgreSQL/JWKS trust, and more reliable cancellation cleanup. **The actual self-hosted stack is not complete or running.** The ordinary HTTP entrypoint deliberately refuses the fresh profile; an owned HTTPS entrypoint and concrete ordinary-helper launcher still need implementation.

## Completed

- [Startup profile](../../server/src/auth/fncp-bootstrap-startup.ts): checks coherent fresh database/user shapes, service-DNS namespace, issuer/audience, explicit TLS pins, independent synthetic secrets and fixed future key locations. Rejects dedicated-release/gateway overrides, external integration inputs, unsafe Node/PG configuration and missing disabled-effect flags. Returned metadata contains no database password or private keys. Shape checks do not prove freshness or resource ownership.
- [App](../../server/app.ts) bypasses dotenv when the opt-in is already present and validates before application imports. [Ordinary entrypoint](../../server/index.ts) rejects it before app import and again before listening. These order checks exercise the existing CommonJS compilation, not an ESM rewrite.
- [Akismet](../../server/src/server.ts) does not construct/verify a client in this profile, or verify an absent key in ordinary mode. [Email](../../server/src/email/senders.ts) is lazy and all three public sender functions reject before recipient traversal/logging/SDK construction. [Notification loop](../../server/src/routes/notify.ts) is suppressed in the profile. [Auth0 management](../../server/src/routes/comments.ts) is lazy and forbidden before owner-data lookup in the profile. Existing configured ordinary branches are covered with mocks.
- [Application TLS](../../server/src/auth/fncp-bootstrap-tls.ts): explicit CA, normal DNS SAN validation and exact leaf pinning. The installed pg client withholds startup identifiers until verified native PostgreSQL TLS. Both [pools](../../server/src/db/pg-query.ts) use this client in the profile; acquisition/connection deadlines are 2s, client query timeout 3s, server statement and idle-transaction settings 2s and lock setting 1s. Server-side settings are requested, not proven enforced by a PostgreSQL engine.
- Both [JWT validators](../../server/src/auth/jwt-middleware.ts) use a fixed-target HTTPS JWKS fetcher: 2s whole-request deadline, 8KiB response/header bounds, at most two concurrent fetches, no redirect/retry or default trust fallback, one canonical public RSA2048 key. Fresh signing-key errors are sanitized. Fixed certificate reads are nonblocking, byte-bounded and checked before/after reading.
- [Owned-session cleanup](./fresh-runtime/bootstrap-owned-session.mjs) starts local transport/database-executor/issuer closure without waiting for stalled helper callbacks. Shared close promises prevent duplicate closure and require acknowledgement. Late-created components still close. Helper/resource closure is never inferred from client closure; unresolved callbacks still prevent successful overall completion.
- Corrected undefined pool-release handling and an ignored rejecting query promise. Removed an unsupported CSV generic type argument without changing parsing options. Updated a stale Morgan contract assertion to the already-declared/locked 1.12.1; no dependency was installed or changed.

## Verification and the remaining failure

| Check | Node 26.8.2 | Node 24.21.0 | Scope |
| --- | --- | --- | --- |
| Foundation/model/transport suite | 1,797 PASS; 24,829.182792ms | 1,797 PASS; 22,807.497375ms | Nine new cleanup cases included |
| Server unit suite | 335 PASS; 8.546s | 335 PASS; 7.833s | 18 suites, including 181 bootstrap cases |
| CSV compatibility | **9 PASS / 3 FAIL** | **9 PASS / 3 FAIL** | Installed 5.6.0 differs from declared/locked 7.0.2 |
| Separate PHP checks | 59 PASS total | Not a Node-dependent suite | Identity23 + journal23 + WordPress stubs13 |

Bootstrap subset: startup121 + side effects21 + TLS32 + wiring7 =181; these are included in 335, not extra unique tests. The foundation suite and server suite are separate test files, not certification of a deployed service. TypeScript `--noEmit` and `git diff --check` pass.

The three CSV failures concern whitespace trimming and prototype-shaped column handling. They are **not waived**. The existing CSV7 tests were not weakened to accept the installed older implementation. A fresh lockfile-aligned installation and complete dependency/image review remain necessary before runtime use. This task did not run package installation, lifecycle scripts or an image build.

TLS tests use actual fresh loopback HTTPS and the installed pg JavaScript client with a synthetic PostgreSQL-wire server. Test-only socket mapping preserves expected DNS/SNI/CA/leaf checks; it does not establish container DNS. No real PostgreSQL engine executes SQL or SCRAM authentication; no full Pol.is/WordPress app or browser integration runs. Side-effect and pool/JWT wiring tests mock consequential dependencies before importing their modules.

[Aggregate evidence](./evidence/bootstrap-startup-continuation-2026-09-13.json) and [selected source inventory](./evidence/bootstrap-startup-source-inventory-2026-09-13.json) record 23 source/test/manifest files (760,428 bytes) and 14 selected installed-dependency files (73,403 bytes). This is not a complete release closure. The separate 27-file/230,564-byte limited proof graph still matches; previous inventories remain dated snapshots.

## Next steps — in order

Final independent artifact audit matched all 37 inventory entries and resolved all 170 local link targets across eight updated documents. Test arithmetic and the CSV dependency mismatch were independently confirmed. No full-runtime completion claim was found in the latest summaries.

1. **Reconcile dependencies in a fresh build environment.** Verify the complete reviewed lockfile, obtain exactly its dependency bytes without reusing retained runtime state, review lifecycle scripts before execution and rerun CSV plus all relevant tests. Preserve the current dirty worktree and previous evidence. Do not build a runtime from the stale installed CSV 5 tree.
2. **Implement the separate owned HTTPS bootstrap entrypoint.** Validate before importing the app; admit only the bounded bootstrap request sequence, sanitize logs/errors, deny unrelated endpoints and close listeners on failure. Do not remove the ordinary-entrypoint refusal to get a plaintext server running.
3. **Implement public-only JWKS and native PostgreSQL TLS roles.** Keep the one-shot RSA signer/token on the host; export only the branded public key to a fresh static HTTPS service. Generate separate DNS/IP-SAN certificates and verify PostgreSQL key permissions against its actual container UID. Never weaken permissions or global trust as a workaround.
4. **Implement the actual resource-set owner and image pins.** Use a separately reviewed ordinary image, not the dedicated gated image. Record exact new network/volume/database/helper IDs and bounded create/inspect/stop outcomes. Distinguish stopped helper/closed clients from database/network/volume ownership or transfer; ambiguous IDs remain unknown.
5. **Prove topology before application mutation.** Verify the exact isolated Colima bridge, host forwarding and denied DNS/external/host-gateway routes. If isolated publishing fails, design an isolated in-network coordinator; do not fall back to a broadly connected bridge. No VM or Docker availability was queried this increment.
6. **Run a real fresh synthetic bootstrap.** Verify migrations/catalog/authentication, actual OIDC-to-user mapping and returned conversation/PID/statement IDs. Independently check both 15-row raw/latest seed-owner Pass baselines and closed flags, then stop the exact helper. Keep token lifetime 120s/no silent refresh; resource preparation must not consume the available token lifetime unknowingly.
7. **Join actual WordPress, access controls and Pol.is.** Then test rightful invitations, valid forwarded-link denial, selective and terminal warm-session revocation, recovery and cleanup with invented people only. A WordPress approval is not proof of Indigenous heritage.
8. **Keep the production decision separate.** C remains the selected local direction. C1/C2/C3 are unselected, costs NOT COSTED and A$0 approved. Real identity, delivery, hosting, external communications and participant/deployment activity need their own evidence and exact approval.

## Important limits

The future launcher must supply fixed executable/arguments and a clean environment. JavaScript validation cannot undo a Node preload, CLI `--env-file` or trust setting already applied before the guard. An opt-in supplied only through ordinary dotenv is read before the later refusal; it is not a valid fresh-only launch route.

These profile guards are not a complete outbound-network sandbox, full route/logging audit, production identity flow, image approval or runtime ownership proof. Ordinary non-profile database TLS behavior was deliberately not silently changed. JWKS cache semantics remain: closing a fetcher does not revoke a previously cached key/token immediately; expiry and exact helper shutdown are separate requirements.

Test-owned fixtures/listeners use their test cleanup paths. No retained configuration, keys, certificates, stores, WordPress archives or databases were opened; no Docker/VM, native browser, install, image pull/build, public change, external message, Git commit/push/PR, remote CI, deployment, retention action or spending occurred.

## Source guidance

The official [Pol.is source and Docker instructions](https://github.com/compdemocracy/polis/blob/stable/README.md) and [configuration guide](https://github.com/compdemocracy/polis/blob/stable/docs/configuration.md) supply the upstream setup. The local source audit found that configuration switches alone did not suppress all startup side effects; the changes above are Barayamal-specific preparatory code, not an upstream guarantee.

[PostgreSQL native TLS protocol](https://www.postgresql.org/docs/17/protocol-flow.html#PROTOCOL-FLOW-SSL), [server TLS configuration](https://www.postgresql.org/docs/17/ssl-tcp.html), [node-postgres SSL](https://node-postgres.com/features/ssl) and [Docker gateway modes](https://docs.docker.com/engine/network/port-publishing/#gateway-modes) describe the underlying mechanisms. Documentation is not evidence that the proposed local topology has run.
