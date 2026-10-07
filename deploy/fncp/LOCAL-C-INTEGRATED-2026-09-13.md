# Option C — integrated identity, approval and voting increment

> Portability note — 7 October 2026: workstation paths were removed, and artifacts outside this source snapshot are labelled retained local evidence. Dated results below remain historical; this edit adds no runtime or release claim.

**13 September 2026 · Local synthetic only · Production and launch HOLD**

## Outcome

Signed synthetic OIDC is now wired through the browser-cookie/CSRF boundary to
strict account mapping, signed WordPress-contract approval, account-bound
invitation, signed activation and actual local Pol.is voting/revocation. The
strict path has no fixture-password fallback, HTTP identity injection or
automatic participation grant. The original fixture-only proof remains separate.

Final actual-origin run: **2026-09-13T14:19:21.395+10:00**, Australia/Sydney.
28 stage checks plus final preservation/cleanup assertions passed (retained local evidence, `evidence/integrated-origin-2026-09-13T04-19-21-395Z.json`; not included in this source snapshot).
An earlier successful run at 14:17:16 preceded final test-helper concurrency and
cleanup hardening. Each run added one invented vote and two terminal removal
records; this increment therefore retained **two invented votes and four new
terminal records**, not genuine participant data. Every newly allocated allowlist
entry was independently verified absent at operation version 2.

## Changes and validation

- Strict access mode: live same-instance signed principal; opaque stable
  account/round mapping; maximum 20 identities; exact identity-map integrity;
  current applied WordPress approval; principal and activation checks before and
  after asynchronous provider operations. New strict databases cannot silently
  adopt legacy mode, or vice versa. **19 new adapter tests**.
- Private synthetic browser driver: explicit injection, callback binding,
  cancellation, expiry, bounded state, one-use processing and race protection.
  **16 new driver tests**, alongside the **48 existing identity protocol tests**.
- Browser: optional strict composition, cookie/CSRF rotation, pending-login
  cancellation, no password fallback, private principal retention and rechecks,
  auth-only logout. Fixed a late-response/browser-deadline bug with **four new
  regression tests**. Browser suite now **21 tests**.
- Integrated journey: **13 tests** with real synthetic signatures and loopback
  BFF/API/signed-event HTTP, using a model response engine. Includes wrong-browser
  callback, forwarded invitation, forged event, unverified claim, callback replay,
  identity/activation expiry, stable re-login, terminal revocation, cookie/CSRF
  rotation, request injection, concurrent driver captures and independent cleanup.
- Combined local command: **335/335 passing** across deployment, access, identity,
  activation, browser, WordPress-runtime, recovery and integrated test files.
  Counts overlap the component lists above; do not add them as unique coverage.
- Local CI definition now includes integrated tests in the locked identity job
  and the existing dependency/image contract tests. **No GitHub CI run, commit,
  source submission, push, PR or deployment was performed.**

## Actual-origin evidence and preservation

The final runner verified exact five-image IDs, environment digest, source seed
digest and independent database membership of all fifteen distinct seed TIDs.
The image/config/source-seed bindings were unchanged at final observation.

Only fresh temporary strict access/authority databases and invented identities
were used. The preserved access SQLite file was byte-hashed before/after and
unchanged. Every preserved synthetic WordPress/MySQL table's row count and the
exact administrator-journal hash were unchanged. This is **not full MySQL
byte-for-byte or every-row equivalence**. The original PHP/access/browser
applications were not started or reapproved. The runner confirmed exactly one
new vote row and one latest-vote row per run and restored scoped whitelist count
to its pre-run baseline.

Proof-only authority was closed; all owned ephemeral listeners stopped; the
successful proof's new temporary stores were removed. Original stores, image
artifacts, prior encrypted recovery evidence and invented vote/tombstone history
remain. Final task-stack shutdown is recorded in the owner guide.

Final independent database readback: **0 provider whitelist rows, 15 fixed seeds,
30 retained invented vote rows**. Both task Compose stacks and the isolated Colima
profile were then stopped. At **2026-09-13T14:25:50+10:00**, all nine checked local
ports were closed (3000, 5500, 5501, 8088, 8099, 8100, 8101, 8102, 33079).

Local WIP source/runtime capture (retained local evidence, `evidence/local-wip-2026-09-13T04-23-49-480Z/runtime.json`; not included in this source snapshot):
14:23:49 Australia/Sydney, source aggregate
`f40efc5888cff2a1bb0943b9a797ab36071168167fa7df519dfd11b02c469e98`.
It includes uncommitted integration code and precedes this final status update;
it is not a release attestation or a claim that the containers remain running.

## Limits — do not promote these claims

This is a short-lived **synthetic integrated protocol proof**, not a running
production service. The issuer is intercepted in memory; there is no real IdP,
mailbox ownership check, participant, email/SMS or verified Indigenous heritage.
The scope remains self-attestation plus Barayamal round approval, not ancestry
verification. No live registration/retention records were read or changed.

The callback uses same-origin JSON on loopback. No new rendered-browser, TLS or
cross-site provider-redirect evidence was produced. Signed WordPress events were
generated by the private proof driver and traversed the real local receiver and
fresh access journal; **the PHP WordPress UI/outbox was not part of this new
identity journey**. The previous actual WordPress/browser proof is separately dated.

Production issuer/account recovery, secure public cookies/TLS, authenticated
WordPress account registration/approval, real delivery, distributed consistency,
trusted deployment measurement/signer custody, provider-wide closure and full
identity/activation recovery remain outstanding. The earlier three-store backup
does not include the new strict identity mapping/authority state or later votes.
Host-side integration is not in the five previously scanned images; their prior
0 Critical / 0 High / 15 Medium result is not a fresh whole-system scan or release
clearance. Separate QA-infrastructure findings remain unresolved.

Public Pulse/results/WordPress notice/fallback/alpha QA were not modified or
reopened, and were not freshly audited during this coding increment. PR #27 is
not GO authority. Dates remain provisional; no price, hosting target or purchase
has been approved by this work.

See [repeatable instructions and next engineering increments](./integrated-journey/README.md)
and the owner C self-hosting guide (retained local evidence, `C-SELF-HOSTING-GUIDE.md`; outside this repository).
