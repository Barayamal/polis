# Option C — two approved browser accounts and invitation binding

> Portability note — 7 October 2026: workstation paths were removed, and artifacts outside this source snapshot are labelled retained local evidence. Dated results below remain historical; this edit adds no runtime or release claim.

**KEEP_CLOSED / SYNTHETIC_ONLY · 2026-09-13T20:57:15+10:00 · Australia/Sydney**

Two separate invented accounts now complete native HTTPS sign-in in two fresh Chrome profiles through the actual strict local BFF, access and activation service. Both are approved before they try each other's valid invitation. Each forwarded invitation is rejected by the actual access backend; each original, unchanged invitation then succeeds for its rightful account. After both accounts are revoked, both already-open voting sessions are denied at the strict backend without additional provider calls or votes.

**The WordPress registration adapter, Pol.is provider and issuer remain synthetic models. This increment does not run fresh actual WordPress/Pol.is, verify a mailbox or Indigenous heritage, or authorize production deployment.**

## What changed

- Added a fixed two-account issuer lab. It issues exactly two distinct invented subjects, rejects a third authorization and accepts no caller-selected identity. The previous one-account lab remains separate.
- Added a two-account strict fixture with independent registration sessions, signed registration receipts, approval events, provider readbacks and account-bound invitations. Both access/activation stores are fresh in-memory stores. There is no HTTP test-administration endpoint.
- Added an opt-in two-profile browser runner. Both accounts begin unauthenticated, register with the three declarations and remain pending until private signed approval. Activation, approval and opening remain separate actions.
- Verified two valid cross-account invitation attempts return403 at the actual strict access service. Both rightful redemptions subsequently return200 using the same unchanged tokens. A rejected forwarding attempt therefore does not consume the legitimate invitation.
- Each account casts one model Agree and sees its next statement. Both signed revocations are then applied. Each displayed Disagree attempt reaches the strict access service and is denied; the provider remains at two total votes and zero active allowlist entries. Reload cannot revive either revoked session.
- Compared each native browser's callback metadata with independent receiving-server observations. Both committed cross-site issuer callbacks withhold the application Strict cookie and carry the transaction cookie. No cookie or browser security metadata was fabricated.
- Hardened both native runners' final outcome guards: late page/routing/unexpected-request errors, request-limit violations or cleanup failure cannot leave a PASS result.
- Prepared the [fresh actual-runtime implementation plan](./LOCAL-C-FRESH-RUNTIME-PLAN-2026-09-13.md). Source inspection found retained-state coupling in the older launch paths. The separate fresh-only path is **NOT_IMPLEMENTED / NOT_RUN**, not a ready-to-run command.

This proves both warm sessions are denied **after both revocations**. It does not prove selective revocation of account A while account B stays approved. The nested fixture checks overlap the browser assertions and must not be added as unique coverage.

## Verified results

| Check | Node24.21.0 | Node26.8.2 | Meaning |
| --- | --- | --- | --- |
| Full ordinary suite | 1,500/1,500 | 1,500/1,500 | Ten new tests beyond the earlier1,490 |
| Two-account native HTTPS | 30/30 | 30/30 | Two new profiles per run; committed issuer-document flow |
| Nested two-account strict fixture | 27/27 | 27/27 | Supporting assertions, not additional unique browser cases |
| Earlier BFF-model HTTPS regressions | 27 immediate /31 committed | 27 immediate /31 committed | Includes actual native certificate-authority/hostname negatives |
| Strict complete HTTPS regressions | 31 immediate /35 committed | 31 immediate /35 committed | 15 model votes per journey |
| Strict warm-revocation regressions | 31 immediate /35 committed | 31 immediate /35 committed | One model vote, next displayed vote denied |

All **14 final native journeys** passed using **16 fresh profiles**. Playwright1.62.1 and full Chrome for Testing149.0.7827.55 are the tested local pair, not an officially supported version/platform matrix. PHP/WordPress-stub checks also passed59/59 (23+23+13).

The first Node26 ordinary run passed1,499/1,500: a new source-boundary assertion expected a direct browser-version comparison instead of the runner's stored version variable. The assertion was corrected to verify both the actual version assignment and exact comparison. Both final full suites pass; no runtime code was changed for that correction. Earlier failures remain recorded in the aggregate evidence.

Per final two-account run: two distinct authentications and registrations, four strict invitation POSTs, four strict vote POSTs,12 total provider-model calls, four provider participation calls and two successful Agree votes. Terminal counts: zero approved accounts, zero allowlist entries and zero post-revocation participation. Approval/revocation management calls are intentionally distinct from participation calls.

The earlier28-check native HTTP proof was **not rerun** here; it remains dated20:11:24 evidence. Previous actual WordPress/Pol.is and recovery results remain historical, not refreshed by this synthetic composition.

## Evidence and cleanup

- Current aggregate evidence (retained local evidence, `evidence/cross-account-continuation-2026-09-13.json`; not included in this source snapshot): both complete native matrices, final suite results, the initial test correction, source hashes and limitations. No account identifiers, tokens, cookies, private URLs or response contents are recorded.
- Current limited runtime source closure (retained local evidence, `evidence/cross-account-source-closure-2026-09-13.json`; not included in this source snapshot): unchanged27 files,230,564 bytes; source hash `e93ec98d8ee05b0ba0327327f7391d118b98b16b3aef480d179ad23c13f320bd`. This is not the complete release, installed dependency/image closure or an SBOM. Test helpers and the fresh-runtime plan are separately hashed in the aggregate evidence.
- All final browser processes closed and fresh profiles were removed. Four ephemeral ports per two-account run, six per existing strict run and four per BFF-model run were independently refused. All strict components report CLOSED.
- The dedicated Colima profile is NOT_RUNNING and all12 known fixed test ports refuse connections. No Docker or historical runtime was started. Retained configuration, private keys, stores and archives were not accessed.

Trust changes are restricted to two generated public synthetic certificates in each fresh Chrome profile. No global/keychain trust, system hosts/DNS, personal browser profile or certificate-error exemption was used. Chrome149's internal certificate database is QA support, not an official production provisioning API. Process routing restrictions are not an OS network sandbox.

No public surface was modified or freshly inspected. No external messages, submissions, Git commits/pushes/PR, remote CI, dependency download, image build/scan, live WordPress change, retention operation, spending or deployment occurred. PR#27 remains not GO authority.

## Next steps, in order

1. **Review and reproduce this local checkpoint.** The [browser guide](./browser-engine/README.md) has the exact opt-in command and limits. Nothing is left running for manual testing; public URLs are not this local proof.
2. **Implement the fresh actual-runtime boundary.** Follow the [source-reviewed plan](./LOCAL-C-FRESH-RUNTIME-PLAN-2026-09-13.md): a task-owned lifecycle/configuration adapter, verified pristine WordPress source input, fresh independent databases and keys, exact local-only images/network, fresh Pol.is conversation and observed seed identifiers. Do not reuse `.env.staging`, retained archives, old stores or legacy launch commands unchanged. This shared local engineering does not imply a production-provider choice.
3. **Run the integrated native browser/actual WordPress/Pol.is journey while closed to the public.** Use invented registrations, real local signed outbox/ACK and gateway enforcement, then test forwarded invitations, terminal and selective revocation, restart/recovery and exact owned-resource cleanup. Keep real operator login, mailbox delivery and heritage decisions outside synthetic claims. Do not label this done until executed and verified.
4. **Resolve production-specific choices with the existing owner pack.** Dean/Barayamal owns C1/C2/C3 hosting/operations and eventual costs. C direction is selected; a provider variant and all-inclusive price are not. The decision pack (retained local evidence, `C-PRODUCTION-DECISIONS.md`; outside this repository) provides the recommended option, trade-offs and exact replies. Spending remains unapproved.
5. **Complete production controls and release evidence before a separate launch decision.** Real participant/operator identity, persistence/key custody, delivery controls, deployment-bound activation, restore assurance and complete release evidence remain outstanding. No external sending, submission, provisioning, spending, live installation, deployment or participant test proceeds without exact approval.

Pol.is provides the [official source and Docker self-hosting instructions](https://github.com/compdemocracy/polis/blob/stable/README.md) and [configuration guidance](https://github.com/compdemocracy/polis/blob/stable/docs/configuration.md). These were reviewed as the upstream foundation; they do not certify Barayamal's custom approval, invitation-binding or activation controls. The quick-start's global certificate-installation step was not executed.

[Previous strict native HTTPS milestone](./LOCAL-C-STRICT-NATIVE-HTTPS-2026-09-13.md).
