# Option C — fresh Linux container integration

> Portability note — 7 October 2026: workstation paths were removed, and artifacts outside this source snapshot are labelled retained local evidence. Dated results below remain historical; this edit adds no runtime or release claim.

**Historical bootstrap checkpoint. The [later participant integration milestone](./LOCAL-C-PARTICIPANT-INTEGRATION-2026-09-14.md) supersedes its unfinished-integration status.**

Status at **2026-09-14T02:18:43+10:00 (Australia/Sydney): REAL LOCAL BOOTSTRAP PASS / ALL TEST CONTAINERS AND VM STOPPED / KEEP_CLOSED.** This continues the [parent/child milestone](./LOCAL-C-BOOTSTRAP-PARENT-2026-09-14.md). The actual Pol.is application and PostgreSQL engine completed the fixed 19-request bootstrap, verified 15 seed statements and a closed/gated conversation, and passed an independent SQL baseline check. This is not the complete WordPress-to-voter journey, a persistent running stack, production readiness or approval to deploy. See aggregate evidence (retained local evidence, `evidence/container-integration-continuation-2026-09-14.json`; not included in this source snapshot) and public source inventories (retained local evidence, `evidence/container-integration-source-inventory-2026-09-14.json`; not included in this source snapshot).

## Completed source and build work

- Added an allowlisted, credential-free container-package generator and an explicit fresh-bootstrap image target. It packages the real Pol.is server, the fixed parent/child runtime, original issuer, JWKS service and database worker; it does not copy retained environment files, keys, databases, archives or dependency trees.
- Added a separate fixed-loopback JWKS role on port 8444. The original issuer remains the sole token authority; cancellation and expiry cannot silently create replacement authority.
- Added a fresh PostgreSQL material factory and non-root initialization script: independent synthetic credentials, pinned TLS certificate, all 20 public migrations, nonsuperuser application role, TLS/SCRAM-only application TCP access, exclusive no-resume marker and post-migration readiness marker.
- Added a bounded, one-attempt actual-application bootstrap CLI. It checks schema before HTTP work, journals each request before dispatch, creates the 15 fixed seed statements, closes/gates the conversation and checks an independent SQL baseline. Its output distinguishes child/listener shutdown from database/container ownership.
- Fixed eager moderation prompt loading in the fresh bootstrap profile. External moderation/geolocation are disabled explicitly in that profile; ordinary behavior is preserved. Added nine server regressions.
- Fixed migration-file ownership, material-directory permissions, the database worker's exact dependency path and cancellation between key writes and new listener creation.
- Fixed PostgreSQL pool authentication: `pg-pool` makes its password property non-enumerable, so the guarded client's object spread lost it. The guarded client now explicitly preserves the validated password. Two negative-before-fix regressions reproduced the defect; all 35 focused TLS tests and the subsequent actual PostgreSQL/SCRAM bootstrap pass. Accessor rejection is preserved.
- Fixed the local archive filename validator to accept the exact `pg_hba.conf` name. Replaced Docker archive copy into the running read-only API container with a fixed, non-root, exclusive stdin-to-tmpfs writer. No credential is passed in command arguments or environment variables, and the read-only root filesystem stays enabled.
- Built Linux/ARM64 API and PostgreSQL images in a newly created isolated local VM. No image was pushed. The final API build disables npm audit/funding calls.

## Verified scope

| Check | Node 22.23.2 | Node 24.21.0 | Node 26.8.2 |
| --- | --- | --- | --- |
| Foundation/model/transport tests | 1,936 PASS | 1,936 PASS | 1,936 PASS |
| Fresh server tests | 568 PASS / 27 suites | 568 PASS / 27 suites | 568 PASS / 27 suites |
| Separate fresh CSV compatibility | 12 PASS | 12 PASS | 12 PASS |
| Fresh TypeScript compilation | PASS | PASS | PASS |

PHP adds 59 passing checks. There were zero failures, cancellations or skipped tests in these final suites. The foundation increase of 64 comprises 13 fixed-port JWKS, 21 PostgreSQL material, 12 package and 18 container-run checks; the 12 server additions comprise nine moderation and three pool-password checks. These 76 additions are included in the totals, not extra tests. Repeated runs across runtimes are not additional unique coverage. The 19-request HTTPS regression uses synthetic response fixtures; the separate successful container attempt below used the actual application and database.

The fresh server snapshot is 150 public files / 1,744,761 bytes, SHA-256 `9d790f69af0fe3f00b283f0d7e27ec99b1ab88c93dace8e80601233c7689d177`; all still match after tests, with zero owned fixture leftovers. The final container source package is 165 files / 1,758,055 bytes, inventory SHA-256 `c1fbf42716c3dcc07d2969d2a6280a1480c7977f9de7b29b05dbf39a89f80e98`. All three final foundation runs reproduce this package inventory. This is a source inventory, not a complete dependency SBOM or vulnerability scan. The separate historical 27-file proof closure remains unchanged and explicitly non-deployable.

## Runtime outcomes

The fresh VM has separate Colima/Lima/cache/Docker configuration, no activated global Docker context, no SSH agent forwarding, no inherited host credential configuration and only one new task-owned writable mount. It is not the retained `fncp-c-20260913` profile. Application test containers have no published ports; the API owns a `none` network namespace and PostgreSQL shares its loopback namespace. Configuration alone is not an independently executed egress-denial test.

Each attempt used new credentials and exact new resources. No failed database, credentials or request sequence was resumed.

| Actual attempt | Result and correction |
| --- | --- |
| 1 | Stopped at the host archive filename validator, before Docker copy or PostgreSQL initialization. The validator rejected the underscore in `pg_hba.conf`; a public-only transfer probe isolated the cause. |
| 2 | PostgreSQL started and applied all 20 migrations. Docker rejected copying launch material into the running API container because its root filesystem was read-only. A separate public-only probe verified the fixed non-root stdin writer without weakening the filesystem control. |
| 3 | Schema admission and actual API child startup succeeded. The first conversation request failed because the guarded PostgreSQL client lost the pool's non-enumerable password. Zero HTTP responses were accepted. All application/issuer/workers and both containers were stopped. |
| 4 | **PASS, 02:17:27.930–02:17:32.274+10:00 Sydney.** All 20 migrations; schema admission; actual issuer/JWKS/Pol.is/PostgreSQL; **19 attempted / 19 accepted HTTP requests; 15 seed statements; closed/gated round; independent raw/latest-unique SQL baseline**. Two JWKS requests, zero rejections/TLS errors. |

The 19 requests comprise one conversation creation, 15 seed writes, seed readback, closure and closed readback—not 19 voters. The independent baseline includes one invented seed owner and 15 Pass rows, not zero votes. The conversation was initially active only inside this isolated bootstrap and closed at the end; public surfaces were not opened.

The successful actual API image is `sha256:d80f6fbeccd072fdb0dac097738292ec24a7bfac0ea4243dbe11dc8eafc5872d`; PostgreSQL is `sha256:0e6f9e3f09bf0a2ef15d0b95d06339efab6ea412d87f1bfcc710ab84f6272803`. The first API image was built but never executed; an intermediate corrected image served attempts 1–3 before the final pool-password correction.

The successful inner runner independently observed API child exit, IPC disconnection, listener refusal and issuer/JWKS/database-worker closure. It deliberately does **not** claim container ownership or database-process shutdown. The separate host owner stopped and inspected the exact PostgreSQL/API containers; both exited 0. At **02:18:22.388+10:00**, engine inspection found all **10 task-created containers stopped, zero running processes, zero published ports and zero host bind mounts**, with read-only roots. This total includes four attempt pairs and two public-only probes.

The fresh `fncp-fresh-20260914` VM was then stopped successfully; at **02:18:43+10:00**, profile status explicitly reported not running. No global profile/context was changed. Images, stopped containers, five private material volumes and task-owned evidence were preserved; the fresh VM directory occupies **4,794,976 KiB** of disk blocks (about 4.57 GiB). Database data and API launch/key material used private tmpfs and did not survive container shutdown. No participant or historical retention data was deleted. There is **no running preview or new public URL** and no reusable live conversation from this disposable run.

Independent namespace inspection found only loopback and zero IPv4 routes. An attempted outbound-connection denial test was **not** performed; isolation configuration and namespace inspection are not full production egress assurance. No launch activation was granted.

## Network and authority accounting

Public VM/image/source/package downloads occurred for the local build. The first image's default `npm ci` and `npm prune` performed dependency audits against npm; this was an unintended metadata transmission, not correspondence or deployment. The build context had no participant data or credentials. The final Dockerfile now specifies `--no-audit --no-fund` for all three installation/pruning commands, with regression assertions. This does not claim that arbitrary dependency lifecycle scripts are a complete no-egress sandbox.

No external messages, source upload, commit, push, PR, publication, production deployment, purchase, real invitation or retention operation was performed. No retained application environment, keys, store contents or archives were adopted. Public [Pulse](https://pulse.barayamal.com.au/), [results](https://pulse.barayamal.com.au/results), [WordPress close notice](https://barayamal.com.au/first-nations-community-pulse-register/) and [technical fallback](https://first-nations-community-pulse.deanosupremo.chatgpt.site/) were untouched, not freshly inspected.

## Next steps, in order

1. **Next local implementation:** join fresh WordPress registration and the strict access service to a new disposable actual Pol.is instance, using invented identities only. Reuse the verified source components, not the stopped database or previous credentials. The original bootstrap is complete; this is the next integration milestone.
2. Exercise registration → pending review → separate Barayamal approval → account-bound invitation → approved access → vote. Keep an email/message delivery adapter unsent; a local capture can test its draft. An email account or software approval does not verify Indigenous heritage. Barayamal's approval decision remains separate from authentication.
3. Verify the negative cases against actual services: an unapproved account, forwarded invitation, another approved account's token, a revoked warm session and a closed round must be denied. Then verify closed restart, backup/restore and selective revocation without enabling another account.
4. Finish full image/dependency inventory and scanning, native/generated-artifact checks, tested egress controls and operational recovery evidence. The source inventories and pinned build are not substitutes. No local test result or PR #27 grants GO authority.
5. Only when implementation evidence is ready, use the owner decision pack (retained local evidence, `C-PRODUCTION-DECISIONS.md`; outside this repository) to approve an exact hosting/authentication/operator arrangement and costed action. C is already selected; C1/C2/C3 and production spending remain undecided, with A$0 approved. Safe local implementation can continue without another choice of C. Messages, submissions, publication, deployment, purchases and real invitations remain paused pending exact approval.

## Official technical references

Final documentation review at 02:29:15+10:00 checked eight current documents, 179 local links (zero missing), all four new JSON evidence files and the selected Git whitespace diff. Two pre-existing whitespace-only lines in `moderation.ts` match HEAD and were preserved. A separate reviewer confirmed that the actual bootstrap claim is supported and that it does not establish the still-unjoined WordPress/participant journey.

The [Pol.is stable self-hosting README](https://github.com/compdemocracy/polis/blob/stable/README.md), [configuration reference](https://github.com/compdemocracy/polis/blob/stable/docs/configuration.md) and [server Dockerfile](https://github.com/compdemocracy/polis/blob/stable/server/Dockerfile) provide the upstream source and Docker/manual baseline. Barayamal-specific eligibility administration, invitation binding, revocation and launch controls are additional work, not guarantees supplied by upstream instructions.
