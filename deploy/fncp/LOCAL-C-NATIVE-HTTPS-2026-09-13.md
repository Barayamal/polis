# Option C — native HTTPS and shutdown assurance

> Portability note — 7 October 2026: workstation paths were removed, and artifacts outside this source snapshot are labelled retained local evidence. Dated results below remain historical; this edit adds no runtime or release claim.

Historical20:11:24 milestone. The later [strict-service native HTTPS checkpoint](./LOCAL-C-STRICT-NATIVE-HTTPS-2026-09-13.md) joins the browser to real local access/activation controls while retaining model WordPress/Pol.is. The results below remain dated, not overwritten.

**KEEP_CLOSED / SYNTHETIC_ONLY · 2026-09-13T20:11:24+10:00 · Australia/Sydney**

The local self-hosted build now has genuine browser-native HTTPS sign-in evidence, not just a modelled cookie jar or an intercepted network response. Two lifecycle defects are fixed. This completes the next local assurance increment; it is **not** production authentication, deployment or participant-test approval.

## Completed and verified

- Fixed queued requests executing after shutdown started. All browser-session authority is revoked synchronously; queued or disconnected work is rejected before adapter dispatch. Late identity, registration, invitation and vote replies cannot restore authority. Already-started effects drain once and are reported as unconfirmed where necessary—not automatically retried or described as rolled back.
- Fixed identity-cancellation exceptions leaving a listener open. Repeated/re-entrant close calls now share one result; native listener closure and work drainage are still attempted even if cancellation fails. Cleanup failures remain observable.
- Added 12 deterministic lifecycle tests; revised one older test that incorrectly required a late successful login after closure.
- Added a disposable Chrome149 profile-only certificate bootstrap, strict local network allowlist and independently checked browser/server callback evidence. Certificates are freshly generated; no personal browser profile, OS certificate store, keychain or system DNS/hosts changes.
- Added both immediate-redirect and committed-issuer-document browser journeys, using the actual BFF/assets and signed invented identity. Registration, approval, invitation and voting services are **in-memory models**, not real WordPress/Pol.is in these runs.
- Added the ordinary browser-harness tests to the local CI definition. **No remote CI, submission, commit, push or PR occurred.**

| Verification | Final result | Scope |
| --- | --- | --- |
| Ordinary Node suite | **1,483 / 1,483 on each of Node24.21.0 and26.8.2** | 92 additional tests since the 1,391 checkpoint; overlapping scopes are not additive assurance |
| PHP checks | **59 / 59** (23 + 23 + 13) | PHP and WordPress stubs; not a fresh actual WordPress runtime |
| Native HTTPS immediate redirect | **27 / 27 on each Node runtime** | Real Chrome149 / TLS1.3; invented issuer and in-memory application model |
| Native HTTPS committed issuer page | **31 / 31 on each Node runtime** | Real cross-site document, Secure/Lax/Strict cookies, cancellation and replay |
| Earlier native HTTP UI runner, rerun | **28 / 28 on each Node runtime** | Signed invented manual JSON callback; layout/focus/15-model-vote regression |
| Limited pinned first-party closure | **27 files / 230,564 bytes / match** | Not full release closure; test harness measured separately |
| Cleanup | **PASS** | Browser processes/context closed, new trust profiles removed, four ephemeral TLS ports independently refused per HTTPS run |

Each browser journey submits one invented registration and 15 in-memory responses: five Agree, five Disagree and five Pass. No participant data or existing retained registration/vote stores were read. Colima `fncp-c-20260913` remains not running; all 12 fixed local test ports were refused. No new image build, image scan or actual WordPress/Pol.is integration is claimed.

## Important cookie finding

Do not assume that `Sec-Fetch-Site: cross-site` means a Strict cookie will always be absent.

| Actual Chrome149 navigation | App Strict cookie | Transaction Lax cookie | Result |
| --- | --- | --- | --- |
| App → immediate issuer303 → callback | Present | Present | Bound sign-in succeeds |
| App → loaded issuer page → click callback | Absent | Present | Bound sign-in succeeds |
| Logged-out replay of spent callback | Present | Absent | No new authentication |
| Loaded issuer page returns after cancellation in another tab | Absent | Absent | No new authentication or token exchange |

The first behavior is explained by Chromium149's disabled-by-default redirect-chain cookie feature and same-site original initiator. Fetch Metadata considers the redirect chain separately. Both CDP final-header events and the receiving Node HTTPS server independently produced the same aggregate observations. The callback uses the one-use transaction/state binding; **the application cookie is not callback authority**. No cookie was injected, removed or rewritten, and no browser feature was changed to force a test result. [Chromium feature default](https://chromium.googlesource.com/chromium/src/+/refs/tags/149.0.7827.55/net/base/features.cc), [cookie calculation](https://chromium.googlesource.com/chromium/src/+/refs/tags/149.0.7827.55/net/cookies/cookie_util.cc), [Fetch Metadata calculation](https://chromium.googlesource.com/chromium/src/+/refs/tags/149.0.7827.55/services/network/sec_header_helpers.cc).

The evidence collector handles omitted/independently ordered CDP ExtraInfo legs using explicit presence flags. Missing, ambiguous or duplicate evidence cannot produce a successful match. Only cookie-name presence and fixed metadata values are recorded; no callback URLs, cookie/token values, private keys, invitation values, HAR or trace were retained.

## Trust, compatibility and failed attempts

The test profile contains two public, self-signed synthetic certificates. Its database schema is pinned to full Chrome for Testing **149.0.7827.55**. This is **internal-schema QA bootstrapping, not an official public provisioning API or a production trust setup**. The certificates have CA capability; their displayed test hostnames must not be mistaken for CA name constraints. Routing is independently restricted to fixed invented hosts and loopback ports. The browser genuinely rejects an untrusted same-host certificate and the wrong hostname on a trusted certificate. Certificate-error exemptions are not used. [Chromium certificate database](https://chromium.googlesource.com/chromium/src/+/refs/tags/149.0.7827.55/components/server_certificate_database/server_certificate_database.cc), [trust metadata](https://chromium.googlesource.com/chromium/src/+/refs/tags/149.0.7827.55/components/server_certificate_database/server_certificate_database.proto).

Playwright **1.62.1** and the installed Chrome149 executable were selected explicitly. No download occurred. This is not a supported matching-version or cross-browser/platform matrix. Network routing and process-specific proxy/DNS limits are not an OS sandbox or proof of every browser background packet.

Failed investigations remain documented: the old intercepted-HTTPS adapter failed safely; early native attempts encountered an error-page navigation race; a Strict-cookie-absence assertion was incorrect for the immediate bounce; and one prior shutdown test expected a now-prohibited late login success. The fixes were tested rather than relabelling those attempts as passes. Separate task-owned tabs now isolate negative certificate navigations. All investigative browser/profile/listener cleanup completed.

## Evidence and reproduction

- Aggregate run evidence and current source hashes (retained local evidence, `evidence/native-https-continuation-2026-09-13.json`; not included in this source snapshot).
- Fresh limited runtime closure (retained local evidence, `evidence/native-https-source-closure-2026-09-13.json`; not included in this source snapshot).
- [Exact opt-in commands and boundaries](./browser-engine/README.md).
- [Earlier HTTP proof and historical failed interception](./LOCAL-C-NATIVE-BROWSER-2026-09-13.md).

The source closure hash is `e93ec98d8ee05b0ba0327327f7391d118b98b16b3aef480d179ad23c13f320bd`. It verifies only its explicitly listed source graph. The separate TLS lab, profile helper, browser runner and test code have independent hashes in the evidence; they are not silently promoted into the runtime graph.

## Next steps, in order

1. **Review this local checkpoint.** The browser-to-BFF HTTPS gap is now covered for the pinned synthetic test environment. Do not combine it with earlier actual-database evidence to claim a fresh end-to-end production run.
2. **Choose a production-specific target using the existing owner pack.** Dean/Barayamal owns this decision because it changes cost and operating responsibility. C1 managed databases/identity is recommended; C2 is a simpler single host with more database operation; C3 adds self-operated identity. The pack gives benefits, risks, next actions and exact reply options. None is selected; all totals remain NOT COSTED. Owner decision pack (retained local evidence, `C-PRODUCTION-DECISIONS.md`; outside this repository).
3. **Implement genuine participant/operator authentication and production persistence/entrypoint for that selected target.** Retain separate registration, self-attestation, Barayamal round approval, single-use account-bound invitations, immediate denial on revoked authority, and scoped opaque XIDs. Authentication/email ownership is not verification of Indigenous heritage. Do not remove synthetic guards to make test services public.
4. **Prove the exact integrated release while closed.** Use fresh invented accounts with the actual WordPress/Pol.is services, genuine browser TLS at the chosen boundary, deployment-bound activation, operator authentication, warm-session revocation, failure/restore tests and complete source/image/CI evidence. Review key custody, monitoring and recovery with the named operator before any activation decision.
5. **Request separate exact approvals for consequential actions.** Provider messages, code submission, provisioning, spending, real mail, live WordPress installation, deployment and participant testing remain paused. Public Pulse/results/WordPress closure/fallback were not modified or freshly rechecked. Retention remains a separate scope. PR#27 and the owner pack are not GO authority.

Pol.is supplies Docker infrastructure, source, configuration and a development identity simulator. Its [official self-hosting guide](https://github.com/compdemocracy/polis/blob/stable/README.md) remains the upstream starting point. The documented development certificate installation affects broader trust; it was not executed here. The custom Barayamal access, WordPress, production identity and activation boundaries require their own implementation and assurance.
