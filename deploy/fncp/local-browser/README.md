# Local browser journey — Option C

**SYNTHETIC ONLY. NOT PUBLIC, NOT LAUNCH AUTHORITY.**

This folder adds a small browser-facing server to the local Pol.is proof. It is
Barayamal proof code, not an upstream Pol.is product or a production WordPress
integration. It sends **no email, SMS, telemetry or external requests**. Use only
invented fixture credentials and the fifteen existing synthetic seed statements.
Mailbox ownership and Indigenous heritage remain **not verified**.

Later [request admission](../local-access/ADMISSION-PROOF.md) and
[shutdown checks](../local-access/LIFECYCLE-PROOF.md) bound local work and prevent
reuse of stopped instances. See the [source-closure review](../release-review/PROOF-CLOSURE.md)
before packaging: the standalone launcher is still the legacy fixture path,
not the strict in-process identity/activation composition.

## HTTPS redirect profile — latest local addition

The explicit `SYNTHETIC_HTTPS_REDIRECT` option now supports a fixed loopback TLS
browser origin and the [pure redirect coordinator](../identity-foundation/HTTPS-REDIRECT-PROOF.md).
The application script navigates to its server-validated invented issuer. A
separate Secure/HttpOnly/Lax transaction cookie binds the top-level callback;
the authenticated application cookie remains Secure/HttpOnly/Strict. Callback
queries are accepted only on the exact callback route and replaced with a clean
fixed return path. Old callbacks cannot cancel a newer cookie; disconnected
callback work remains part of shutdown's drain. No test injection route is
enabled in this profile.

Actual TLS wire checks and a script/cookie/navigation model pass; no real browser
engine or real provider has been tested. See the [current report and commands](../LOCAL-C-HTTPS-REDIRECT-2026-09-13.md)
and [strict-service configuration](../strict-service/README.md). No global CA,
hosts-file or DNS changes are required by these tests. The `.invalid` addresses
are test-adapter mappings, not permanent preview URLs. The legacy defaults and
boundaries below are preserved, not silently upgraded to HTTPS or production.

## Earlier strict synthetic OIDC JSON-callback path

The [integrated journey](../integrated-journey/README.md) now supplies a signed
synthetic OIDC driver and strict identity backend to this BFF. That mode disables
the fixture-password login route. The private driver injects an invented signed
response explicitly; no public identity-injection endpoint or automatic grant
exists. The callback is delivered as same-origin, CSRF-protected JSON, not a real
HTTPS redirect. Browser cookies/CSRF rotate on start, authentication and redemption.
Principal and browser-session expiry are checked before and after asynchronous
operations. Pending login can be cancelled. The default startup below remains
the preserved legacy proof; it is not silently converted to the strict path.

New integration evidence is HTTP-cookie/CSRF protocol evidence, not a rendered
browser, real issuer, mailbox-ownership or live WordPress test. Do not deploy
either local mode as a production service.

## Boundary

- Browser: `http://127.0.0.1:8100/`, loopback only. No configurable public host.
- Fixed server-to-server backend: `http://127.0.0.1:8099`; it is not exposed through
  a general proxy. No administrative route is available from this UI.
- The existing local-access API still rejects browser Origin, Cookie and Fetch
  Metadata. The BFF constructs a narrow independent server request and never
  forwards browser headers or authority.
- Random HttpOnly, SameSite=Strict, host-only session cookie; unrelated random
  per-session CSRF token; session and CSRF rotate at login and invitation redemption.
  Mutations require the exact Host, Origin and same-origin Fetch Metadata.
- Backend fixture-auth and participation tokens live only in bounded server
  memory (64 sessions by default). They never enter browser JSON, HTML, cookies,
  browser storage, files, logs or URLs. The UI receives only a small projected
  statement object with a TID and an exact known synthetic seed text.
- Fifteen-minute absolute browser sessions; restart discards all browser sessions.
  Expiry/restart drops access at this BFF, **not** a claim that all backend sessions
  have been revoked. Backend tokens expire independently. Logout attempts the
  backend logout after local denial and reports if that could not be confirmed.
- Only Agree = `-1`, Disagree = `1`, Pass = `0` for the displayed statement.
  No suggestions, uploads or free text. Pol.is also enforces its exact fifteen-TID
  manifest. A failed/uncertain vote is never retried automatically.
- CSP and assets are same-origin only; no third-party fonts, scripts or images.
  Text is inserted with `textContent`, not HTML. No CORS access is enabled.

The cookie intentionally does not claim Secure on an HTTP loopback demo. This
is **not suitable for an internet deployment**, a shared host, a genuine participant
account, or untrusted local software. Do not forward these ports or put this BFF
behind a tunnel. Production HTTPS, secure-cookie deployment, distributed session
control, genuine mailbox verification and approved heritage/eligibility decisions
remain separate work. This service never opens or closes a public round.

## Start

Use Node 26, matching the existing local-access proof. From the clone root, after
the isolated synthetic Pol.is stack is bootstrapped:

```sh
FNCP_LOCAL_SYNTHETIC_MODE=fixture-only node deploy/fncp/local-access/start.mjs
```

In another terminal:

```sh
FNCP_LOCAL_SYNTHETIC_MODE=fixture-only node deploy/fncp/local-browser/start.mjs
```

The browser service first verifies that the fixed backend declares itself
synthetic-only, not production-ready, with no heritage verification or real email.
Open [the local browser proof](http://127.0.0.1:8100/). `localhost` is intentionally
not an accepted alias. Stop with Ctrl-C; no browser-session file needs deletion.

## Manual synthetic test

1. The local operator creates an invented fixture, approves it for the disposable
   round, opens only the local test gateway and issues a bound invitation using
   the existing API/private local capture workflow. No public mailbox is provided.
2. Receive the fixture name and fixture secret through the operator's **private
   local synthetic file**, not a public unauthenticated endpoint. Do not paste
   credentials into chat, screenshots, logs or Git.
3. Enter the fixture and secret on the first form. This simulates account login;
   it does not prove email ownership or Indigenous heritage.
4. Paste the matching invitation into the second form and choose **Redeem**.
   Optionally the operator may provide a local URL fragment of the form
   `http://127.0.0.1:8100/#invite=<LOCAL_SYNTHETIC_INVITATION>`. The fragment is
   cleared immediately by the first client code, before any request or submission;
   it is not stored in browser storage. It is never a query string. Clear fragments
   and credential fields before taking any screenshot.
5. Respond to an invented fixed statement. There is no free-text suggestion form.
   **Check next statement** exercises the independent next-comment path. On an
   uncertain vote error, do not repeat the submission automatically; use the
   next-statement check or ask the local operator to inspect aggregate proof state.
6. Revoke the same fixture through the local operator path. Its existing browser
   session must be denied on its next participation request and cleared locally.
7. Log out. Public Pulse, results, WordPress closure and fallback surfaces remain
   unchanged throughout. This is not whole-provider round-closure assurance.

## Checks and integration helper

```sh
node --test deploy/fncp/local-browser/browser-server.test.mjs
```

These tests use an explicit **model backend**. They cover CSRF, Origin/Host/Fetch
Metadata, cookie fixation/rotation, expiry/capacity, role confusion, strict bodies,
known synthetic text projection, token leakage, forwarded/replayed invitations,
upstream denial and uncertain-outcome/logout handling. Model passing is not an
actual browser test or proof of the real Pol.is stack.

`integration-client.mjs` exports `createBrowserClient()` for a separate authorised
local integration harness. It manages the HttpOnly-cookie protocol and CSRF
internally and returns no cookie or CSRF value:

```js
import { createBrowserClient } from './deploy/fncp/local-browser/integration-client.mjs';
const browser = createBrowserClient();
await browser.session();
await browser.login(fixtureFromPrivateFile, fixtureSecretFromPrivateFile);
await browser.redeem(invitationFromPrivateFile);
const initialized = await browser.initialize();
await browser.next();
// Only after checking the exact returned statement, perform an authorised
// synthetic vote; keep credentials, identifiers and response text out of logs.
await browser.vote(initialized.body.statement.tid, 0);
await browser.logout();
```

The helper performs real HTTP when invoked, so run it only against the explicitly
prepared isolated proof. It does not create approvals, send invitations or delete
data. It is protocol evidence, **not browser rendering/accessibility evidence**.
