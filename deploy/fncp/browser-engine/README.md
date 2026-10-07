# Opt-in local browser-engine checks

> Portability note — 7 October 2026: workstation paths were removed, and artifacts outside this source snapshot are labelled retained local evidence. Dated results below remain historical; this edit adds no runtime or release claim.

These are test runners, not a server CLI or production login.

- `native-cross-account-proof.mjs`: two fixed approved invented accounts in two fresh Chrome149 profiles. Valid forwarded invitations fail at the actual strict backend; unchanged rightful tokens succeed. Both accounts cast one model vote, both are revoked, and each displayed next vote is denied at strict access without provider growth. Passes30 native assertions plus27 nested strict checks on each Node24/26. See the [latest cross-account report](../LOCAL-C-CROSS-ACCOUNT-2026-09-13.md). This does not test revoking only A while B stays approved.
- `native-https-proof.mjs`: full Chrome149 with disposable profile-only trust and both immediate-bounce/committed-issuer-document journeys. Default `BFF_MODEL` passes **27/31 checks** on both Node24 and26; fixed `STRICT_SERVICE` and `STRICT_SERVICE_WARM_REVOKE` compositions each pass **31/35 checks**, plus16 nested fixture assertions. See the [latest strict native HTTPS report](../LOCAL-C-STRICT-NATIVE-HTTPS-2026-09-13.md).
- `strict-native-fixture.mjs`: test-only adapter joining the actual strict BFF/access/activation and signed receipt/event code to invented WordPress/Pol.is models. Both stores are fresh `:memory:`. The existing one-account complete journey records15 model votes; its separate warm journey denies the second displayed vote after signed revocation. A separate fixed two-account factory supports the new native cross-account proof, independent registrations/readbacks and terminal revocations. Not a production adapter.
- `disposable-chrome-trust.mjs`: fresh private profile containing exactly two validated public synthetic certificates. Internal Chromium149 database schema, not an official provisioning API. No OS trust or personal profile changes. Cleanup refuses live locks, symlinks, hard links and path-identity drift.
- `callback-metadata.mjs`: bounded flag-aware CDP correlation; compared against the actual receiving server, with no raw cookies/URLs retained.
- `native-https-policy.mjs`: fixed invented host/origin/method/path allowlist. Separate two-account policy omits TLS-negative origins; no arbitrary external destinations or response/header fabrication.

- `native-ui-proof.mjs`: actual isolated Chromium, actual loopback HTTP BFF and page assets; signed invented identity through the private manual JSON callback; in-memory registration/approval/invitation/voting backend.
- `native-policy.mjs`: exact loopback origin/method/path allowlist, no query, fragment, credentials, aliases or normalization.
- `engine-proof.mjs`: experimental intercepted HTTPS adapter. The recorded installed-browser run **fails safely** because the final browser security metadata is absent at interception. Never manufacture the headers, ignore TLS errors or treat this as verified browser HTTPS.
- `../browser-engine-boundary.test.mjs`: 40 ordinary Node tests, included in the existing `deploy/fncp/*.test.mjs` suite. No browser is downloaded/launched by the ordinary suite; the launch-failure test injects a failing launcher and closes its fresh loopback server.

## Reproduce the native proof with existing installed dependencies

The paths below are placeholders. Replace them with explicit existing installed Playwright and browser paths in a task-owned runtime; the placeholders are not runnable as written. From the local Pol.is clone:

```sh
node --input-type=module -e '
const { chromium } = await import("file:///absolute/task-owned/installed-playwright/index.mjs");
const { runNativeUiProof } = await import("./deploy/fncp/browser-engine/native-ui-proof.mjs");
const result = await runNativeUiProof({
  chromium,
  executablePath: "/absolute/task-owned/installed-chromium-headless-shell"
});
console.log(JSON.stringify(result));
process.exitCode = result.outcome === "PASS" ? 0 : 1;
'
```

On another machine, supply explicit installed Playwright and browser paths. Do not silently download dependencies, attach a personal browser profile, add a real issuer, or change trust/hosts/DNS settings. The recorded installed versions were Playwright 1.62.1 and Chromium 149.0.7827.55; a supported matching-version matrix remains future work.

Optional `screenshotDirectory` is only for a new task-owned local evidence directory. Screenshots are taken at synthetic declaration, pending-registration and completion states, never while callback/invitation fields contain private invented values. Do not use a live directory, overwrite historical evidence, enable tracing/HAR/video, or pass real inputs.

Network routes continue **without** request/header/body/cookie overrides, leaving the browser to send its own security metadata. Only exact loopback routes are allowed; WebSockets, service workers, downloads and other destinations are unavailable. A blocked proxy and DNS exclusion limit the isolated browser process. These controls are not an OS-level sandbox or proof of every browser background packet. Fresh services/context close at the end; the native listener is independently checked for refusal. Nothing is left running for manual use.

The HTTP runner covers 28 assertions and the actual model vote-value distribution. Its scope alone does not test a real mailbox, heritage verification, production operator login, hosted IdP, actual WordPress/Pol.is integration, browser-native cross-site HTTPS, or public release. The separate native HTTPS runner below covers synthetic TLS/redirects and, when explicitly selected, the actual strict local access/activation composition with model WordPress/Pol.is.

## Reproduce native HTTPS in a disposable profile

Run from the local clone, with the existing full Chrome for Testing executable. This command creates and later removes only a fresh task-owned profile with generated public test certificates; do not substitute a personal profile, global certificate installation or certificate-error exemption. Each run is bounded to 120 requests/two minutes and uses only loopback services. If launch/cleanup is uncertain it fails and reports its exact owned profile path for a scoped handoff; do not claim cleanup succeeded or delete a still-running profile.

```sh
node --input-type=module -e '
const { chromium } = await import("file:///absolute/task-owned/installed-playwright/index.mjs");
const { runNativeHttpsProof } = await import("./deploy/fncp/browser-engine/native-https-proof.mjs");
const results = [];
for (const composition of ["BFF_MODEL", "STRICT_SERVICE", "STRICT_SERVICE_WARM_REVOKE"]) {
for (const issuerFlow of ["IMMEDIATE_BOUNCE", "COMMITTED_ISSUER_DOCUMENT"]) {
  results.push(await runNativeHttpsProof({
    chromium,
    executablePath: "/absolute/task-owned/installed-chrome-for-testing",
    issuerFlow,
    composition
  }));
}
}
console.log(JSON.stringify(results));
process.exitCode = results.every(result => result.outcome === "PASS") ? 0 : 1;
'
```

For the Node 24 repeat, invoke the installed Node 24.21.0 executable instead of `node`; no dependency install is required on this machine. The runner rejects a browser version other than 149.0.7827.55 because the test-only profile schema is pinned. A supported version/platform matrix remains future work.

Chrome149 sends Strict+Lax cookies on the immediate app-initiated bounce, but withholds Strict when the issuer document first commits. Both are tested; the callback never treats the app cookie as authentication authority. A spent callback with only the app cookie and a callback after explicit cancellation cannot authenticate. Certificate negatives must be actual native authority/hostname errors, not arbitrary connection failures.

Ordinary tests (no real browser launched): `node --test deploy/fncp/browser-engine-boundary.test.mjs deploy/fncp/browser-engine/*.test.mjs`. This focused scope passes131/131; the full suite now has1,500 tests and includes these overlapping scopes. The local CI definition includes this command; remote CI was not run. Keep earlier failed evidence rather than overwriting it with the new proof.

The command runs six isolated profiles on the selected Node runtime. Repeat with the installed Node24 executable for the twelve-run regression matrix. Each strict run independently checks six closed ephemeral listeners and records the strict supervisor CLOSED. BFF-model runs check four listeners. All use the same fixed TLS/browser boundaries. The16 private fixture assertions overlap the browser checks; do not add them as unique coverage. `authentications` counts verified driver completions, while actual UI progress separately proves backend acceptance. The strict runner observes only aggregate access-vote request counts, never credentials or request bodies. These existing journeys issue one fixed invented subject; use the separate runner below for native two-account evidence.

## Reproduce the two-account native proof

This separate opt-in command creates two new task-owned browser profiles, one fixed two-account committed-document issuer, and fresh in-memory strict stores. It cannot select arbitrary accounts or profiles. It is bounded to160 total browser requests/two minutes across both profiles. Browser requests continue unchanged. It requires the same installed dependencies and profile-only synthetic trust constraints described above.

```sh
node --input-type=module -e '
const { chromium } = await import("file:///absolute/task-owned/installed-playwright/index.mjs");
const { runNativeCrossAccountProof } = await import("./deploy/fncp/browser-engine/native-cross-account-proof.mjs");
const result = await runNativeCrossAccountProof({
  chromium,
  executablePath: "/absolute/task-owned/installed-chrome-for-testing"
});
console.log(JSON.stringify(result));
process.exitCode = result.outcome === "PASS" ? 0 : 1;
'
```

Repeat using the installed Node24 executable for the second runtime. This adds one journey/two profiles per runtime to the six journeys/six profiles above:14 final journeys and16 profiles across both runtimes. All current final results passed; all profiles/processes closed and all ephemeral listeners independently refused. The new proof checks four service ports,30 browser assertions and27 overlapping private fixture assertions. Each denied cross-account POST and warm revoked-vote POST is independently observed at the actual strict backend.

The issuer accepts exactly two authorizations, not a third/recovery login. Both accounts must be approved before valid tokens are exchanged; both original tokens subsequently succeed. Both accounts are revoked before either warm denial is tested. WordPress, Pol.is and the issuer remain models, not fresh actual-runtime assurance. The [fresh actual-runtime plan](../LOCAL-C-FRESH-RUNTIME-PLAN-2026-09-13.md) is source-only NOT_IMPLEMENTED / NOT_RUN; do not substitute the older retained-state scripts.

The approach follows the primary [Playwright network guidance](https://playwright.dev/docs/network) and [isolated browser-context API](https://playwright.dev/docs/api/class-browsercontext). Keep the [dated evidence and next steps](../LOCAL-C-NATIVE-BROWSER-2026-09-13.md) separate from earlier actual-provider/recovery records.
