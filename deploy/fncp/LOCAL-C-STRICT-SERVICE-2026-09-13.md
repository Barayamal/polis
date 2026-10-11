# C — dedicated strict local service

> Portability note — 7 October 2026: workstation paths were removed, and artifacts outside this source snapshot are labelled retained local evidence. Dated results below remain historical; this edit adds no runtime or release claim.

Recorded: 2026-09-13T17:24:31+10:00 (Australia/Sydney). **KEEP CLOSED; uncommitted local work, not a release.**

## Completed

A dedicated [programmatic strict-local entrypoint](./strict-service/README.md) now composes the access service, mandatory activation, signed WordPress receiver, browser service and optional registration bridge. Runtime composition is separate from the test harness: it imports no synthetic signer, identity injector, test client or model provider.

The [strict HTTP profile](./local-access/STRICT-SERVICE-PROOF.md) denies all test-administration and fixture-authentication paths even with the old administrator bearer. Status, round control and invitation issuance are available only through a narrow private in-process operator capability. Approval and revocation still require signed WordPress events; login alone grants neither.

The [lifecycle supervisor](./strict-service/supervisor-proof.md) owns sequential startup, all-service rollback, immediate authority closure and graceful drains. It handles startup/close races, duplicate calls and partial failure without exposing credentials or abandoning later cleanup. No forced termination or side-effect retry was added.

Provider conversation binding is checked before and after every operation, including rejected operations. Observed mismatch or unreadable metadata latches denial and closes activation. Resetting the metadata does not clear the latch. A side effect that already happened cannot be undone or described as definitely unapplied.

## Verification

- **1,154/1,154 Node tests passed on each of Node 24.21.0 and 26.8.2**; zero failures, cancellations or skips. These are the same tests repeated, not 2,308 unique tests.
- **59 separate PHP checks passed**: 23 identity, 23 journal and 13 adapter checks, using PHP/stubs rather than live WordPress.
- **142 new Node tests**: 31 strict HTTP-profile, 36 composition, 72 supervisor and three additional source-closure tests.
- The composed signature/protocol test covers invented login, signed model approval, account-bound invitation, one model vote and warm-session revocation. Separate registration tests prove same-principal binding and pending-only results. These do not claim a new actual Pol.is/WordPress runtime run or rendered-browser proof.
- The reviewed pinned graph now covers **26 files, 20 modules, four browser assets, two dependency inputs, 30 import edges and four asset edges**. It includes the new programmatic root but does not attest arbitrary injected adapters or the full release.
- CI source includes the new strict-service suite after isolated identity dependency installation. No remote CI, commit, push or PR submission occurred.

Aggregate evidence (retained local evidence, `evidence/strict-service-continuation-2026-09-13.json`; not included in this source snapshot) · Current pinned source graph (retained local evidence, `evidence/strict-service-source-closure-2026-09-13.json`; not included in this source snapshot). Earlier evidence files remain unchanged.

At the recorded closure check, `fncp-c-20260913` was **Stopped** and all 12 fixed test ports refused connections: 3000, 5500, 5501, 8088, 8099, 8100, 8101, 8102, 8103, 33079, 33080 and 8114. Test-owned ephemeral listeners were closed. No VM/container was started.

## What is still not complete

The underlying identity foundation and browser callback protocol remain **SYNTHETIC_ONLY**. This is a dedicated local composition, not a production command-line launcher or deployable image. The legacy standalone launchers remain fixtures. Neither deleting local-only guards nor serializing opaque principal objects supplies production authentication.

Real browser login redirects/callback sessions, operator authentication/MFA, approved message delivery, secret/key custody, production target/images, complete release security and full restored-application assurance remain outstanding. Injected adapters are trusted operator code, not untrusted user inputs or sandboxed implementations. Self-attestation and round approval are not Indigenous heritage verification.

## Next steps in order

1. Review the updated owner guide (retained local evidence, `C-SELF-HOSTING-GUIDE.md`; outside this repository) and the [strict-service API/runbook](./strict-service/README.md). Keep the public sites closed.
2. Continue locally with a real browser authorization/callback adapter and a separately authenticated operator boundary. Preserve the shared principal authority; do not expose the private operator capability as an unauthenticated HTTP bridge.
3. Use the production decision pack (retained local evidence, `C-PRODUCTION-DECISIONS.md`; outside this repository) to choose the hosting/login target and approve complete costs. C1/C2/C3 remains unselected and NOT COSTED; no spending or provider selection is inferred.
4. Build and review the exact deployment candidate, durable storage/key custody, operational runbooks, synthetic assurance and whole-service recovery. Source graph checks are not image or dependency security clearance.
5. Obtain exact approval before external submission, provisioning, publication, message delivery or participant testing. Launch requires its own GO decision; PR #27 is not that authority. Historical registration retention stays separate.

No external message, public edit, real account, participant action, provisioning, spending, retention operation, image build/scan or original-store/archive modification occurred. Public closure was not freshly inspected; the surfaces were left untouched. Earlier actual provider/recovery counts remain historical, not current counts.

## Official guidance

Reviewed [Pol.is stable self-hosting/source instructions](https://github.com/compdemocracy/polis/blob/stable/README.md) and [configuration guidance](https://github.com/compdemocracy/polis/blob/stable/docs/configuration.md). They describe upstream Docker and configuration. The strict WordPress/identity/activation integration remains custom Barayamal work requiring its own assurance.
