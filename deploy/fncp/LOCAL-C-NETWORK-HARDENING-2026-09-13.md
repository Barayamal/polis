# C — response deadlines, loopback TLS and gateway admission

> Portability note — 7 October 2026: workstation paths were removed, and artifacts outside this source snapshot are labelled retained local evidence. Dated results below remain historical; this edit adds no runtime or release claim.

13 September 2026 · Local implementation · **Production / launch HOLD**.

## Completed

**918/918 tests passed on each of Node 24.21.0 and 26.8.2**, plus the three
separate PHP suites' **59 checks**. Same Node coverage repeated, not 1,836 unique
checks. This increment adds **54 tests**: 25 response-deadline, 22 actual TLS and
7 gateway-admission tests. No Docker, retained application store, live site,
real account, external correspondence or infrastructure was used or changed.

### Identity transport now fails within its response budget

The old wrapper relied on the OIDC client's cancellation signal but could wait
indefinitely if the injected adapter ignored it, if the body stalled, or if stream
cancellation never resolved. The new internal response primitive independently
bounds the complete header/body operation to **five seconds per response**.
Token and JWKS responses have separate budgets; this is not a whole-login SLA.

Late results cannot revive authentication, failed callbacks remain one-use and
a new login can succeed. Responses remain JSON-only and limited to 65,536 bytes.
Empty chunks are not accumulated, stored chunks are copied, cleanup cannot block
failure, and no redirect, ambient cookie or automatic retry was introduced.

[Deadline proof and command](identity-foundation/DEADLINE-PROOF.md).
JavaScript cannot interrupt synchronous adapter code or forcibly stop an adapter
that ignores cancellation; the fix fences authentication completion.

### Actual local HTTPS token and signing-key exchange

The new test-only adapter maps two fixed invented HTTPS endpoints to its own
ephemeral **127.0.0.1** TLS listener. Each request trusts only the freshly generated
test certificate, retains default hostname verification and rejects wrong trust
or hostname. No system CA installation or global TLS-disable setting is used.

Tests cover success, wrong CA/SAN, redirects on both endpoints, slow headers,
stalled/oversized/non-JSON/truncated bodies, abort, PKCE/code substitution and
callback replay/concurrency. Listener shutdown is independently checked; only
new test-owned certificate/key files and fixtures are removed.

[TLS lab and exact limits](identity-foundation/TLS-PROOF.md).
This is real encrypted token/JWKS transport, but the issuer and callback injection
remain synthetic. It is **not** a real identity provider, public certificate,
cross-site browser redirect, mailbox check or Indigenous-heritage verification.

### Request capacity is reserved before collecting bodies

The access service now shares a **32-slot** budget across body readers, its serial
HTTP queue and all three direct entry points. The browser service's separate
**32-slot** budget now begins before body collection. Previously, incomplete
POSTs bypassed the browser limit and the access queue was unbounded.

Excess work receives a sanitized 503 without further provider/verifier calls or
access-database changes. Body abort, rejection and completion release capacity.
Serial ordering and all existing authorization/closure guards remain intact.

[Admission proof and command](local-access/ADMISSION-PROOF.md).
This is not production load certification or a bound on pre-header TCP sockets.
It neither preempts an admitted provider operation nor covers the separate
WordPress receiver's readers. A capacity-rejected revocation is **not applied or
acknowledged**: its existing exact-event pending/retry process remains required.

## Verification and preservation

| Check | Result |
| --- | --- |
| Full local suite — Node 24.21.0 / macOS ARM64 | 918 PASS; no failures, skips or cancellations |
| Same suite — Node 26.8.2 | 918 PASS; same coverage repeated |
| Existing PHP suites — PHP 8.5.10 | 23 identity + 23 journal + 13 adapter = 59 PASS |
| Bounded source inventory | 56 fixed entries; KEEP_CLOSED; no private state or services read/started |
| Git whitespace check | PASS |
| Dedicated local VM | Stopped; no VM/container startup in this increment |
| Fixed local ports | All 12 refused connections at 2026-09-13T16:40:29.809+10:00 |

The first deadline test run exposed a serial test-parent scheduling mistake;
the concurrency setting was corrected, independent review corrected empty-chunk
metadata accumulation, and both complete suites then passed. No product guard
was weakened to make a test pass.

The source inventory now includes the new identity runtime dependency. It is
**56 selected source entries, not an exhaustive release snapshot or SBOM**.
Its digest is `947ff18ae339acfc6125b48e031be8b4eaeac4fe822a2b2c12a6ac9ee8126f61`.
CI source explicitly checks OpenSSL availability; existing wildcards include the
new tests. No workflow was submitted or run remotely, and no image was rebuilt,
rescanned or asserted to include these host-side changes.

- Aggregate evidence (retained local evidence, `evidence/network-hardening-continuation-2026-09-13.json`; not included in this source snapshot)
- Fixed-source inventory (retained local evidence, `evidence/network-hardening-source-inventory-2026-09-13.json`; not included in this source snapshot)
- [Earlier source-review ZIP and crash proof](LOCAL-C-REVIEW-BUNDLE-2026-09-13.md)

The saved WordPress review ZIP, original keys/stores and earlier recovery evidence
are preserved. Earlier provider counts and actual recovery were **not rerun**.
Public surfaces were untouched, not freshly inspected for closure in this turn.

## Next steps, in order

1. Review this increment and the local diff. The owner guide (retained local evidence, `C-SELF-HOSTING-GUIDE.md`; outside this repository) has the complete reproducible test commands and existing process walkthrough. These checks do not require Docker.
2. Use the existing C1/C2/C3 decision pack (retained local evidence, `C-PRODUCTION-DECISIONS.md`; outside this repository) when selecting the production hosting/login target and operator. No selection, cost ceiling or account was inferred from “continue”.
3. Implement and review that target's actual identity callback, operator MFA, secure cookie/session deployment, full-service packaging, private-network/proxy limits, durable storage and coordinated recovery. A production adapter must not simply remove the synthetic guards.
4. Cost the exact bill of materials and review the whole candidate, current source/images and required CI. Sending, submitting a PR, provisioning and spending each remain approval-gated.
5. Only after separate approval, provision a **closed** environment and perform approved invented-account assurance. A public round, real invitations and participant testing need their own later approval. PR #27 remains not GO authority; October dates remain provisional.

This work follows [official Pol.is self-hosting source/instructions](https://github.com/compdemocracy/polis)
and [TLS guidance](https://github.com/compdemocracy/polis/blob/stable/docs/ssl.md).
Those documents describe upstream operation; they do not certify Barayamal's
custom eligibility, identity, gateway or production design.
