# Option C — native HTTPS through the strict service

> Portability note — 7 October 2026: workstation paths were removed, and artifacts outside this source snapshot are labelled retained local evidence. Dated results below remain historical; this edit adds no runtime or release claim.

**KEEP_CLOSED / SYNTHETIC_ONLY · 2026-09-13T20:35:38+10:00 · Australia/Sydney**

The real-browser HTTPS journey now runs through the actual strict local service: browser-facing backend (BFF), in-memory access and activation stores, signed registration-receipt bridge and signed WordPress event receiver. The earlier HTTPS journey injected an application model directly into the BFF. This increment joins the browser and strict-access layers without changing runtime access rules.

**WordPress registration, Pol.is and the identity provider remain invented/modelled here. This is not a production deployment, a fresh actual WordPress/Pol.is integration, mailbox verification or Indigenous-heritage verification.**

## Completed

- Added a test-only strict composition adapter with two fresh `:memory:` stores. No retained configuration, keys, stores or archives were accessed.
- Verified startup is closed; opening without signed activation fails. Synthetic activation alone leaves the round closed.
- Native browser sign-in and the three declarations create one pending registration via the real signed receipt bridge. Registration does not grant approval.
- A forged approval fails before provider work. Authentic signed approval applies the model allowlist and verifies readback; an exact duplicate does not repeat it. Approval still cannot issue an invitation while the round is closed.
- Only a separate private local open permits actual invitation issuance. The browser rejects an unrelated token and accepts the issued token for the authenticated invented account. Nothing is emailed or messaged.
- A complete journey records exactly 15 model responses: five Agree, five Disagree and five Pass.
- A separate warm-session journey records one Agree, displays the second unvoted statement, then applies signed revocation. Clicking that displayed vote returns HTTP401/403. Independent server instrumentation confirms the denied POST reaches the actual strict access service, with **zero additional provider calls or votes**.
- Both journeys end with terminal signed revocation and zero active model allowlist entries. Original stale approvals are no-ops; conflicting old event identities and newer attempts to undo revocation are rejected.
- Added seven ordinary tests: six fixture/lifecycle/integration tests and one runner-boundary test. Existing CI test globs include them; no remote CI ran.

Approval legitimately makes two provider-model calls—upsert and readback. The closed-round assertion checks zero **participation**, not zero total provider work. The warm-session assertion deliberately avoids the completed-voting state, which would only demonstrate the displayed-statement guard.

## Verification

Each row describes its own scope. Nested checks and repeated runtimes are not additive unique coverage.

| Check | Node24.21.0 | Node26.8.2 | Scope |
| --- | --- | --- | --- |
| Full ordinary suite | 1,490/1,490 | 1,490/1,490 | Seven new tests included |
| Earlier BFF-model HTTPS regression | 27 immediate /31 committed | 27 immediate /31 committed | Actual BFF/browser, directly injected application model |
| Strict complete HTTPS journey | 31 immediate /35 committed | 31 immediate /35 committed | Actual strict composition, 15 model votes |
| Strict warm-revocation HTTPS journey | 31 immediate /35 committed | 31 immediate /35 committed | Actual strict composition, one model vote; next displayed vote denied |
| Private strict-fixture assertions | 16 per strict run | 16 per strict run | Nested supporting checks, not extra unique browser cases |

All **12 final native HTTPS runs passed**. The installed full Chrome for Testing is 149.0.7827.55 with Playwright 1.62.1. This is a tested local pair, not a supported cross-version/platform matrix. Separate PHP/WordPress-stub checks pass 59/59 (23+23+13). The earlier 28-check native HTTP UI proof was **not rerun in this increment**; its 20:11:24 checkpoint remains dated evidence.

The limited runtime closure remains unchanged: 27 files, 21 modules, 4 browser assets, 2 dependency inputs, 230,564 bytes. Source closure hash:

`e93ec98d8ee05b0ba0327327f7391d118b98b16b3aef480d179ad23c13f320bd`

This is not the complete deployable release, dependency/image closure or SBOM. The test adapter and browser runner are separately hashed in the evidence.

## Cleanup and limits

All final browser contexts/processes closed and fresh trust profiles were removed. Six ephemeral service ports per strict run were independently refused (four per BFF-model run). The strict supervisor records every component CLOSED. The dedicated Colima profile `fncp-c-20260913` is NOT_RUNNING; all 12 known fixed test ports refuse connections. No Docker or historical application runtime was started.

The test uses fresh profile-only trust for two synthetic certificates. It never changes global/keychain trust, system DNS/hosts, certificate verification, a personal browser profile or request/cookie/security metadata. Internal Chrome149 certificate-database bootstrapping is QA support, not an official production provisioning API. Process-level routing limits are not an OS network sandbox.

The existing lab issues one fixed invented subject. The native run does **not** newly establish another account's rejection of the valid invitation. That cross-account case remains separately covered by `strict-service/service.test.mjs` in the ordinary suite. Do not combine the two scopes into a fresh native cross-account claim.

No public surface was modified or freshly rechecked. No external correspondence, real invitation, live WordPress change, Git commit/push/PR, remote CI, image build/scan, spending or deployment occurred. Public closure and historical retention remain separate. PR#27 is not GO authority.

## Next steps

1. **Review this checkpoint and reproduction instructions.** Use [the browser-engine guide](./browser-engine/README.md), aggregate evidence (retained local evidence, `evidence/strict-native-https-continuation-2026-09-13.json`; not included in this source snapshot) and unchanged limited runtime closure (retained local evidence, `evidence/strict-native-https-source-closure-2026-09-13.json`; not included in this source snapshot). Earlier failed interception and earlier passing milestones remain preserved.
2. **Continue shared local engineering without choosing a provider by implication.** Remaining assurance includes a fixed second invented browser account and one fresh integrated browser/actual WordPress/Pol.is run. Preserve closed defaults, invented data, isolated storage and explicit cleanup. The current milestone does not claim these are done.
3. **For provider-specific production implementation, use the existing owner decision pack.** Dean/Barayamal owns the C1/C2/C3 choice because it changes cost and operating responsibility. C1 managed databases/identity remains the recommended candidate; C2 single-host and C3 self-operated identity remain alternatives. No choice, all-inclusive cost or spending is approved. The owner pack (retained local evidence, `C-PRODUCTION-DECISIONS.md`; outside this repository) provides exact replies and trade-offs.
4. **Implement and verify the chosen production boundary while closed.** Real participant/operator authentication, production persistence/key custody, delivery controls, exact deployment activation, integrated restore tests and full release evidence remain outstanding. Email ownership is not heritage verification; the owner scope remains self-attestation plus Barayamal round approval.
5. **Obtain separate exact approval for consequential actions.** External sending, submission, provisioning, spending, live installation, deployment and participant testing remain paused. A local PASS does not authorize any of them.

Pol.is supplies the [Docker-based self-hosting instructions and source](https://github.com/compdemocracy/polis/blob/stable/README.md) and [configuration reference](https://github.com/compdemocracy/polis/blob/stable/docs/configuration.md). Those remain the upstream foundation; they do not supply or certify Barayamal's custom approval, account-bound invitation, operator and activation controls. The quick-start's broader certificate installation was not executed.

[Previous native HTTPS/shutdown milestone](./LOCAL-C-NATIVE-HTTPS-2026-09-13.md).
