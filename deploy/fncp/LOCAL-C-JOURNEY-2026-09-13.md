# C continuation — actual local WordPress and voter journey

> Portability note — 7 October 2026: workstation paths were removed, and artifacts outside this source snapshot are labelled retained local evidence. Dated results below remain historical; this edit adds no runtime or release claim.

**13 September 2026, Australia/Sydney · Local synthetic engineering proof · Production HOLD**

This supersedes the earlier API-only progress description, not its historical test evidence. No external messages, public edits, Git submissions/pushes, paid resources, live WordPress changes or genuine participant tests occurred. The old registration-retention workflow is not involved.

## Implemented

- A disposable **WordPress 7.1** installation, using existing host **PHP 8.5.10** and dedicated **MySQL 8.4.11** container/data volume. It is separate from every Barayamal live site and Jetpack form. WP mail is suppressed; WordPress HTTP is denied except the exact local event receiver; registration, cron, updates and file editing are disabled.
- Administrator approval/revocation plugin: capability and operation-specific nonce checks, strict synthetic inputs, atomic WordPress option compare-and-swap journal, immutable outbox bodies, HMAC-SHA256 signatures with a five-minute transport freshness window, exact acknowledgements, explicit retries and terminal revocation. No heritage evidence fields or email delivery.
- A receiver on loopback **8101**, integrated in-process with the existing **8099** API's serialisation queue and SQLite store. It verifies the exact raw-body signature, event identity, round and monotonic subject version. Pending events deny access across process restart. Conflicting events fail; stale events do not restore access. Provider removal is still independently read back.
- A browser-facing service on loopback **8100**: synthetic account login, account-bound invitation redemption, fixed-statement response screen, Agree/Disagree/Pass, next statement and logout. It keeps backend credentials on the server, rotates HttpOnly/SameSite=Strict session cookies, requires separate CSRF tokens and exact-origin mutation checks, and exposes no administrative proxy route.
- Local capture-only invitation files and CLI round controls. These are not a real mail transport and do not prove real mailbox ownership.
- Reviewed CSV parser and local watcher upgrades; rebuilt the Pol.is server image. The server and alpha production/full npm audits report zero findings at this checkpoint. Package audit-zero is not source or whole-image security approval.
- Rebuilt all five application artifacts after pinning patched Node/OpenSSL/libuuid versions. Exact local ARM64 scans improved from 16 Critical / 66 High matches to **0 Critical / 0 High**, with **15 Medium** matches retained without suppression. The separate QA database/identity images remain unresolved and are not proposed production services. See [post-patch evidence](VERIFY-IMAGE-REMEDIATION-2026-09-13.md) and [preserved before snapshot](VERIFY-EXACT-IMAGE-SCAN-2026-09-13.md).
- Local CI definitions now include the new JavaScript suites and watcher regression. These edits remain local; GitHub CI has **not** been triggered.

## Actual browser and integration results

The root agent used the **Codex in-app browser** with the real local WordPress, gateway and Pol.is database—not a mock backend—for the following checks:

| Check | Observed result |
| --- | --- |
| Synthetic WordPress admin sign-in and Tools screen | PASS |
| Browser approve → immutable event → receiver → actual Pol.is allowlist | PASS, acknowledged |
| Another approved account attempts the intended account's invitation | PASS, access denied; token still redeemable by intended account |
| Intended synthetic account signs in and redeems invitation | PASS |
| Fixed statement rendered in browser, no submission/upload controls | PASS; desktop layout inspected |
| Agree saved and next fixed statement displayed | PASS |
| WordPress revokes the account while voting page remains open | PASS, acknowledged |
| Already-open browser attempts another vote after revocation | PASS, denied and returned to sign-in |
| Final browser assets restarted and compared against disk | PASS, both HTML and JS hashes match |
| Second account redeems its own invitation in final UI | PASS |
| Pass saved and next statement displayed in final UI | PASS |
| Local round closed while second voting page remains open | PASS, subsequent vote denied and returned to sign-in |
| Remaining WordPress approval revoked | PASS, acknowledged |

The final UI-only changes were focus/ARIA/heading-spacing refinements. The complete first journey preceded that final asset reload; invitation, rendering, response and closure were repeated afterwards. No mobile/assistive-technology/full-browser-matrix assurance is claimed. A screenshot showed the desktop layout without credentials or invitation tokens. Task-owned tabs were closed.

These rendered-browser journeys preceded the final Node/OS image patch. The actual-origin access and invitation/warm-revocation smokes were rerun successfully against the final patched images; a new rendered-browser journey was not claimed for that image revision. Browser source remained unchanged.

### Automated checks

- **189/189** combined local static/model/protocol tests passed, including 17 browser-server tests, 12 WordPress event/receiver tests, 8 copied-source WordPress configuration checks, 5 private-CLI diagnostic checks and the subprocess partial-start cleanup regression. These counts overlap earlier proof coverage.
- **107/107** focused server tests passed again in a clean pinned **Node 22.23.2** container, including 12 CSV migration/advisory regressions. TypeScript build passed.
- **2/2** actual Nodemon compatibility/start/reload/shutdown checks; **6/6** dependency-boundary checks.
- **36/36** WordPress contract/journal/adapter model checks.
- Real WordPress/receiver: initial **12** checks passed; later subscriber/form regressions passed in a **9-check** authorization/form rerun. These are overlapping runs, not 21 independent integration scenarios. See [WordPress evidence](wordpress-local/VERIFICATION.md).
- Actual Pol.is direct-route, XID, invalid-TID, suggestion-denial and warm-revocation smoke passed again after the final security image rebuild.
- Actual API invitation forwarding/expiry/replay/approval/revocation smoke passed again after the final security image rebuild.
- A fresh isolated PostgreSQL restore passed before the final image smokes: source/restored schema aggregates, one synthetic conversation, 15 fixed statements and 25 synthetic vote rows matched at that backup checkpoint. Later smokes add their own synthetic vote rows. Vote rows are **not** participant counts. No source database was overwritten; only the new restore container/network were removed.

## Problems found and fixed

1. The default WordPress `submit_button` added a `submit` field that the strict handler correctly rejected. Both forms now omit the submit-button name; actual rendered-form regression tests were added and browser submissions rechecked.
2. Ordinary event-journal capacity could prevent a terminal revocation. There is now reserved terminal capacity for all 20 subjects; repeated terminal versions cannot grow it indefinitely. Regression: 200 ordinary rows plus all 20 terminal revocations, all accounts denied, at most 220 rows.
3. An unavailable receiver port could leave the API alive after startup failed. Partial startup now closes acquired listeners/database and exits nonzero; a copied-source subprocess regression uses only ephemeral ports and confirms no leaked credentials.
4. Generated WordPress configuration or its database secret files could drift. Preparation now compares the exact expected configuration and database secret-file contents, preserving mismatches rather than declaring success. Malformed private input produces fixed diagnostics without printing parser excerpts; copied-source regressions use invented sentinels only.
5. This Docker daemon suppressed published ports on an internal network. The new WordPress database uses its own bridge, with inter-container communication disabled and only `127.0.0.1:33079` published. This is host isolation, **not an egress firewall**. Pol.is's existing internal network was not weakened. WordPress's exact-target HTTP/mail controls remain enforced.

## Final local access checkpoint

- Gateway round closed.
- Three persistent synthetic fixtures; three local approvals revoked.
- Three WordPress subjects, each latest decision revoked and acknowledged.
- Independent provider aggregate: **0 active allowlist operations / 0 remaining whitelist rows**; check selected and revoked zero additional identities and left vote/statement aggregates unchanged.
- All invitations invalidated by closure; browser services hold no usable participation authority for these fixtures.
- Evidence and synthetic database volumes retained. Do not delete/recreate the database or reuse these terminally revoked fixtures to make another demo pass. Use a new invented fixture.

This is not whole-provider conversation lifecycle closure: the dedicated synthetic conversation record is preserved. It is not production, historical registration or participant-deletion evidence.

## Remaining production work

1. Real account authentication/mailbox ownership, approved sending service and account recovery; no emails-as-XIDs. The local fixture secret is not a substitute.
2. Adapt WordPress registration/consent and eligibility decisions to the chosen real account system. Scope is self-attestation plus round approval—not verified Indigenous heritage. No ancestry documents.
3. Production HTTPS and secure cookies, secret storage, durable distributed sessions/events, constrained service networking, closed-by-default deployment activation and provider-wide closure/reconciliation.
4. Complete the release/architecture-specific review and required CI, then review a supported upstream base. The five rebuilt local ARM64 application artifacts now have zero Critical/High matches, with 15 Medium matches retained. Separate QA infrastructure findings and its OIDC root-user assertion remain unresolved. Local uncommitted code and this bounded image result are not a release attestation.
5. Coordinated recovery across **WordPress/MySQL, access SQLite and Pol.is/PostgreSQL**, restricted reporting, scoped deletion and operator incident procedures. The restore executed here covers PostgreSQL only.
6. Dean approves exact hosting region/provider, costs, operator and release scope before any provisioning; then separate deployment and participant-test approvals. No amount is currently approved for spending.

## Local entry points and instructions

- [WordPress runtime setup](local-wordpress-runtime/README.md)
- [WordPress plugin and outbox](wordpress-local/README.md)
- [Browser service and boundary tests](local-browser/README.md)
- [API harness](local-access/README.md)
- [Dependency migration review](DEPENDENCY-REVIEW-2026-09-13.md)
- [Final exact-image patch and scan report](VERIFY-IMAGE-REMEDIATION-2026-09-13.md)
- Owner-friendly guide: `C-SELF-HOSTING-GUIDE.md` (retained local evidence; outside this repository).

Official guidance used: [Pol.is Quick Start/source](https://github.com/compdemocracy/polis#quick-start), [XIDs](https://compdemocracy.org/xid/), [WordPress nonces](https://developer.wordpress.org/apis/security/nonces/), [WordPress releases](https://wordpress.org/download/releases/) and [official MySQL image](https://hub.docker.com/_/mysql). The custom approval and browser code is Barayamal proof work, not an official Pol.is-provided WordPress integration.
