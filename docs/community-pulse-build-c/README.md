# Build C — current direction and progress

Updated 8 October 2026, Australia/Sydney · Owner: Dean / Barayamal

First Nations Community Pulse gathers First Nations people's views, priorities
and experiences on community issues, policies and decisions affecting them.
Dean selected **Remove WordPress**. The target is a Community Pulse application
with native registration, consent and staff approval, using self-hosted Pol.is
for voting and analysis.

**Migration execution is not approved or implemented.** The source snapshot in this review branch remains WordPress-dependent; the
native target is a prepared design. Historical owner/release records are kept
as baseline evidence.
This directory records current decisions and prepared work; it is not a deployed
native registration service.

| Item | Current state | Review material |
| --- | --- | --- |
| Purpose | Community and policy listening; founder-only purpose superseded | [Scope revision](SCOPE-REVISION-2026-10-07.md) |
| Architecture | WordPress removal selected | [Migration plan](NATIVE-MIGRATION-PLAN-2026-10-07.md) |
| Audience | Decision pending; Australia-wide adult community cohort recommended, international cohort is an alternative | [Audience choice](SCOPE-REVISION-2026-10-07.md#questions-awaiting-deans-choice) |
| Native registration and staff authority | Designed; execution not approved or implemented | [Contracts and sequence](NATIVE-MIGRATION-PLAN-2026-10-07.md#execution-sequence-after-approval) |
| Staff interface | Disconnected design with invented records and disabled controls | [HTML preview](NATIVE-STAFF-PREVIEW-2026-10-07.html) |
| Earlier source assurance | 2,949 source tests passed; 808 are an included production subset; 32 separate PHP model checks passed | [Aggregate verification](PRIOR-SOURCE-VERIFICATION-2026-10-07.json) |
| Release qualification | Pending: installed native journey, current images/scans and joined recovery | [Acceptance criteria](NATIVE-MIGRATION-PLAN-2026-10-07.md#required-verification-and-acceptance) |
| Closed staging and launch | Pending concrete hosting, identity, delivery, backup, cost and test specification, followed by separate decisions | [Ordered work](NATIVE-MIGRATION-PLAN-2026-10-07.md#execution-sequence-after-approval) |

The preview is a static local design, with no scripts, authentication, database
or network requests. Static checks passed in the preparation run; browser policy
blocked local-file rendering, so its rendered layout has not been verified.
GitHub's source view is not a working staff application.

The GitHub review snapshot was independently rechecked in a fresh checkout:
**2,949/2,949** source tests passed on Node 24.19.0, with spawned tools using
the same runtime. PHP model/syntax checks, proof closure and credential review
passed. See [repository snapshot verification](REPOSITORY-SNAPSHOT-VERIFICATION-2026-10-07.json).
These are source/protocol checks, not a native authority or installed release.

The [current engineering review PR](https://github.com/Barayamal/polis/pull/44)
also carries the hosted-CI portability repairs. Its updated source passed
**2,953/2,953** FNCP tests on Node 24.19.0, server lint/build and focused startup,
production and installation checks. Exact Alpine package pins were verified for
both supported architectures. See [CI repair verification](CI-REPAIR-VERIFICATION-2026-10-08.json).
The fresh GitHub run and full release image/scan/recovery qualification remain
separate gates. The older 2,949-test receipt describes the imported snapshot
before these repairs, not the current source tree.

The companion private repository has [current scope documentation in PR 40](https://github.com/Barayamal/first-nations-community-pulse/pull/40)
and [a separate audit repair in PR 41](https://github.com/Barayamal/first-nations-community-pulse/pull/41).
That repair's exact-head quality CI passed; its production-only dependency audit
reported zero vulnerabilities. It does not clear development-only findings,
update either default branch or qualify a deployed native application.

The earlier verification snapshot records source fingerprint
`4730e2988791cafdeab55003f3cc13e38a783a8bc1d09650cf1020af9e8023d3`
and 1,995 files over local base commit
`9fccfec82797573dd5c873f1dee761378dff3706`. It includes local changes and is not
the digest of that commit's tree. The historical receipt remains unchanged;
fresh review checks are recorded separately. Neither set proves native approval implementation or
installed voter journey, image qualification, real identity-provider access or
hosted CI.

The current technical pilot limits are 20 lifetime registrations and 15 fixed
statements. They are pilot choices, not Pol.is limits. The revised audience,
statements, notice, round window and retention record must be reviewed together;
the historical founder-round dates and content are not automatically reused.

After the recorded local migration execution choice is resolved, follow the
plan in order: preserve the source baseline; implement native consent/decision
authority and staff login; connect access and invitations; replace deployment,
installation, activation, renewal and recovery; then qualify one candidate with
invented data. Prepare concrete staging details before any deployment decision.
Native development does not import or delete historical registrations.

This documentation update does not authorise sending, publication, deployment,
spending, live-record changes, invitations or opening.
