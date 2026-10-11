# C — HTTPS sign-in redirect continuation

> Portability note — 7 October 2026: workstation paths were removed, and artifacts outside this source snapshot are labelled retained local evidence. Dated results below remain historical; this edit adds no runtime or release claim.

Recorded: **2026-09-13T17:47:55+10:00**, Australia/Sydney. **KEEP CLOSED. Local uncommitted work, not a release.**

## Outcome

The strict local service now supports an explicit HTTPS authorization-code redirect profile. It connects the existing signed-identity foundation to the browser-facing service without exposing the synthetic callback injector. The original HTTP fixture profile remains available and unchanged in purpose.

This is a working **local HTTPS protocol implementation with invented identities**, not verified real-provider login, rendered-browser assurance or a production installation. Pol.is remains the response engine; Barayamal's registration, approval and access boundary is custom integration.

## What changed

| Boundary | New behaviour |
| --- | --- |
| Login start | Same-origin JSON POST requires the current session and CSRF token. The server returns only its validated authorization URL; the actual app script explicitly navigates with `location.assign`. Fetch never follows the redirect. |
| Transaction | A separate opaque `__Host-` cookie is Secure, HttpOnly, SameSite=Lax, host-only and limited to five minutes. It identifies server-side state, not an account or access token. |
| Callback | Only the exact HTTPS GET callback accepts top-level navigation metadata and callback query parameters. The one-use transaction and identity foundation enforce state, nonce, issuer, PKCE and signed-token checks. |
| Application session | The same foundation instance verifies the opaque principal before a separate Secure, HttpOnly, SameSite=Strict cookie is rotated. Backend credentials and claims remain server-side. Login is not round approval. |
| Return path | Success and processed authentication failure return to fixed `/`, without reflecting callback credentials or following provider error URLs. Unknown or stale callbacks do not clear a newer login's cookies. Ordinary API/origin checks remain intact. |
| Lifecycle | Logout/new login cancel older completions. Disconnected callbacks cannot begin late backend authentication, and admitted callback work remains part of shutdown's drain. |
| Composition | HTTPS is an explicit fixed-host/port opt-in with copied TLS configuration. It cannot silently downgrade to HTTP. Runtime service code imports no test issuer, signer or injection helper. |

Two review findings were repaired and regression-tested: stale callback cookie deletion and disconnected callback work escaping the shutdown drain. No automatic retry, global trust exception or remote endpoint discovery was added.

The test issuer and app use **different invented logical sites**, mapped to loopback only inside a scoped TLS test adapter. CA, SNI and certificate hostname validation remain enabled. No hosts file, DNS or system trust store was changed.

## Verified evidence

- **1,349/1,349 Node tests pass on each of Node 24.21.0 and 26.8.2**, with zero failures, cancellations or skips. These are the same suite twice, not 2,698 unique tests.
- **195 new tests:** 70 redirect coordinator, 25 TLS lab, 66 strict-service/supervisor, 26 HTTPS BFF protocol, six script/DOM-model and two source-closure checks.
- **59 separate PHP checks pass:** 23 identity, 23 journal and 13 adapter checks. These use PHP/stubs, not live WordPress.
- Actual local TLS covers authorization → 303 callback → token/JWKS exchange → authenticated BFF session. A model backend then exercises registration-pending, account-bound invitation and one fixed-statement response. Separately, the composed strict service preserves its closed round and makes zero provider calls during its HTTPS wiring test. These scopes are not one new actual Pol.is/WordPress runtime journey.
- Cookie/navigation behaviour and the app script are model-tested. **`realBrowserEngineTested=false`**: no real browser engine, real identity account or mailbox was exercised.
- Reviewed source graph: **27 files, 21 JavaScript modules, four assets, two dependency inputs, 30 import edges and four asset edges**. The pure redirect coordinator is an explicit fifth root. Arbitrary injected adapters, installed dependency bytes and full release images remain outside this graph.

Aggregate evidence (retained local evidence, `evidence/https-redirect-continuation-2026-09-13.json`; not included in this source snapshot) · Pinned source graph (retained local evidence, `evidence/https-redirect-source-closure-2026-09-13.json`; not included in this source snapshot) · [Driver contract](./identity-foundation/HTTPS-REDIRECT-PROOF.md) · [Strict service configuration](./strict-service/README.md).

At the recorded closure check, the dedicated `fncp-c-20260913` VM was **Stopped** and all 12 fixed test ports refused connections: 3000, 5500, 5501, 8088, 8099, 8100, 8101, 8102, 8103, 33079, 33080 and 8114. Test-owned ephemeral listeners were closed. Only fresh generated test fixtures were cleaned.

## Step-by-step next work

1. **Review locally.** Start with the owner self-hosting guide (retained local evidence, `C-SELF-HOSTING-GUIDE.md`; outside this repository) and this report. The earlier [strict-service report](./LOCAL-C-STRICT-SERVICE-2026-09-13.md) remains a dated historical snapshot.
2. **Repeat the focused checks without Docker.** In the isolated clone, run:

   ```sh
   node --test deploy/fncp/identity-foundation/https-redirect-driver.test.mjs deploy/fncp/identity-foundation/redirect-tls-lab.test.mjs deploy/fncp/strict-service/https-redirect-browser.test.mjs
   node deploy/fncp/release-review/proof-closure.mjs
   ```

   These commands use invented test accounts, start temporary loopback TLS endpoints and close them. They do not provide a lasting browser preview URL. The `.invalid` lab addresses are not public services or URLs to share. The owner guide contains the full-suite command.
3. **Complete real-browser assurance locally.** Exercise navigation, cookies, cancellation, reload/back navigation and callback failures using a browser-scoped, isolated trust/routing arrangement. Do not install a global CA, disable certificate verification or reinterpret this wire model as a completed browser run. No production provider account is necessary for that next local assurance step.
4. **Implement the separate operator authentication boundary.** Protect administrative approval, activation and recovery with the chosen authentication/MFA arrangement. Do not expose the current private in-process operator object through an unauthenticated web route.
5. **Choose the production-specific target before creating resources.** Dean/Barayamal's decision and cost pack (retained local evidence, `C-PRODUCTION-DECISIONS.md`; outside this repository) contains C1/C2/C3 choices and exact scope-only replies. All remain unselected and NOT COSTED. Generic local implementation and tests can continue without a hosting purchase.
6. **Review the exact deployment candidate and recovery.** Real issuer behaviour, account recovery, key custody, durable state, monitoring, release/image security and whole-application restore need evidence. Mail delivery remains disabled until its mechanism and exact send are approved.
7. **Approve external actions separately.** Submission, provisioning, installation, publication, messaging and participant testing require exact approval. Keep all public surfaces closed. Launch needs its own GO decision; PR #27 is not that authority. October dates remain provisional. Retention remains a separate workflow.

Authentication and self-attestation do not verify Indigenous heritage. No ancestry evidence, participant information, historical registration count or deletion authority was introduced.

## Official technical guidance

The implementation continues from [Pol.is stable source/self-hosting instructions](https://github.com/compdemocracy/polis/blob/stable/README.md). Upstream Docker quick-start guidance is not a production certificate for this custom integration. The new login work follows the existing library's [authorization-code grant API](https://github.com/panva/openid-client/blob/main/docs/functions/authorizationCodeGrant.md), [OpenID Connect authentication flow](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest), [OAuth security guidance](https://www.rfc-editor.org/rfc/rfc9700.html) and [issuer identification](https://www.rfc-editor.org/rfc/rfc9207.html).

No external message, public edit, real account, participant action, provisioning, spending, retention operation, image build/scan, commit, push or PR submission occurred. Public surfaces were untouched, not freshly inspected. Original retained stores, private configuration/keys and archives remain untouched; earlier evidence is preserved.
