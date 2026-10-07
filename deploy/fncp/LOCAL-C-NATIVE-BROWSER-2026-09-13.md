# Option C — native browser continuation, 13 September 2026

> Portability note — 7 October 2026: workstation paths were removed, and artifacts outside this source snapshot are labelled retained local evidence. Dated results below remain historical; this edit adds no runtime or release claim.

Status: **KEEP_CLOSED / SYNTHETIC_ONLY**. Recorded **2026-09-13T19:35:35+10:00** (Australia/Sydney).

Historical checkpoint: the later [native HTTPS continuation](./LOCAL-C-NATIVE-HTTPS-2026-09-13.md) now verifies real browser TLS and both cross-site redirect variants in a disposable synthetic profile. Statements below about that gap being unverified describe this earlier checkpoint. The failed interception experiment remains failed evidence.

The local participant page now has repeatable real-browser UI evidence. This is not a production deployment, real identity-provider login, verified Indigenous heritage, or a new actual WordPress/Pol.is integration run.

## Completed

- Added an opt-in isolated Chromium runner for the actual local BFF and HTML/CSS/JavaScript, using native loopback HTTP. It performs signed invented OIDC verification through the existing private JSON-callback test driver. The registration, separate approval, invitation and voting backend are explicitly in-memory models.
- Verified 28 browser checks on both Node 24.21.0 and 26.8.2: HttpOnly/Strict local cookies, post-login cookie rotation, callback clearing, initially unchecked declarations, native required-field validation, wrong-CSRF rejection, pending-not-approved registration, approval-gated model redemption, all 15 fixed statements (5 Agree / 5 Disagree / 5 Pass), keyboard focus, logout/reload and empty page storage.
- Reviewed and pinned the current mode-specific sign-in help and error/completion focus improvements. Added 42 ordinary regression checks: 40 test-containment/setup/source checks and two sign-in-help tests. These do not inflate the separate browser count.
- Restricted browser requests to exact loopback origin, paths and methods; requests continue unchanged. No fabricated Cookie, Origin or Fetch Metadata headers. Other destinations and WebSockets are blocked; service workers/downloads are disabled. Fresh browser context, 120-request ceiling, two-minute run ceiling, independent cleanup and listener-refusal checks.
- Visually inspected desktop pending-registration and mobile registration/completion screenshots. No horizontal overflow at 1280px or 390px was observed. This is not an accessibility certification or cross-browser matrix.
- Refreshed the 27-file first-party source closure after reviewing the two UI assets. The separate opt-in browser harness is measured in the evidence, **not included in that limited runtime closure**.

## Evidence and limits

| Check | Result | What it does not prove |
| --- | --- | --- |
| Ordinary Node suite | **1,391 / 1,391** on each of Node 24.21.0 and 26.8.2 | Tests overlap previous scopes; not launch authority |
| PHP / WordPress-stub checks | **59 / 59** (23 + 23 + 13) | Not a fresh actual WordPress runtime |
| Native Chromium UI journey | **28 / 28** on each Node runtime; one invented registration and 15 model votes per run | No actual WordPress/Pol.is database write; no browser cross-site HTTPS |
| HTTPS interception experiment | **FAIL at initial page / 0 completed browser checks** | Cannot support browser-authentication assurance |
| Limited first-party source closure | **27 files / 228,500 bytes / match** | Not a complete deployable release |
| Cleanup | Test browsers and ephemeral services closed; native listener independently refused; VM not running; 12 fixed test ports refused | No new live-system/public-site check |

The installed combination was Playwright **1.62.1** with an explicitly selected existing Chromium **149.0.7827.55** executable. No package or browser was downloaded. The bundled default executable was unavailable; these results do not claim an officially matched Playwright/browser version pair.

The HTTPS experiment is deliberately retained as failed evidence. At this interception stage Chromium's final Fetch Metadata headers were absent; the BFF rejected the API calls. Headers were not manufactured and certificate validation was not disabled. The earlier certificate-verified Node/TLS protocol tests still pass, but **browser-native TLS trust and cross-site Secure/Lax/Strict cookie/redirect behaviour remain unverified**. The native HTTP proof uses a non-Secure local cookie and private manual test callback; it is not a workaround to ship.

- Aggregate machine-readable evidence (retained local evidence, `evidence/native-browser-continuation-2026-09-13.json`; not included in this source snapshot)
- Fresh limited source-closure record (retained local evidence, `evidence/native-browser-source-closure-2026-09-13.json`; not included in this source snapshot)
- [Run instructions and test boundaries](./browser-engine/README.md)
- [Mobile registration](./browser-engine/evidence-2026-09-13/registration-mobile.png)
- [Desktop pending registration](./browser-engine/evidence-2026-09-13/registration-pending-desktop.png)
- [Mobile completion](./browser-engine/evidence-2026-09-13/completion-mobile.png)

## Next steps

1. **Keep every public surface closed.** No deployment, provider message, Git submission, participant test, live WordPress change or retention action was taken. Historical evidence/stores/archives remain separate.
2. **Finish browser-native HTTPS assurance in an isolated test environment.** Require exact local-only routing and trusted test certificates without weakening system/browser controls. Then repeat real top-level redirects, transaction-cookie handling, cancellation, replay and logout. Do not relabel the failed interception adapter as a pass.
3. **Choose the production-specific target before adapting real services.** Dean/Barayamal owns this decision; C1 remains recommended, C2/C3 remain alternatives and none is selected. The owner decision pack (retained local evidence, `C-PRODUCTION-DECISIONS.md`; outside this repository) records benefits, trade-offs and exact replies. Shared local tests can continue; accounts, sending, provisioning and spending stay paused.
4. **Build genuine participant/operator authentication and a production entrypoint**, then prove deployment-bound activation, key custody, closed recovery and release/CI evidence. Use the [official Pol.is self-hosting/source guide](https://github.com/compdemocracy/polis/blob/stable/README.md) for upstream operation; the custom Barayamal access boundary needs its own assurance. The existing synthetic guards must not simply be removed.

The existing owner pack and PR #27 are not GO authority. No launch date or price has been approved by this continuation.
