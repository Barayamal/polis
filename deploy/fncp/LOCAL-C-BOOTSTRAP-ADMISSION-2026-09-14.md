# Option C — fresh dependencies and bootstrap admission

> Portability note — 7 October 2026: workstation paths were removed, and artifacts outside this source snapshot are labelled retained local evidence. Dated results below remain historical; this edit adds no runtime or release claim.

Checkpoint: **2026-09-14T00:24:22+10:00 (Australia/Sydney). LOCAL_ONLY / KEEP_CLOSED.**

**This increment is complete; the fresh self-hosted stack is not complete or running.** It resolves the CSV mismatch in a separate lockfile-aligned dependency tree and adds application readiness, a strict bootstrap request/response boundary, and a public-only local JWKS service. It does not supply the remaining owned HTTPS application entrypoint or container lifecycle.

## Completed

1. **Verified a fresh dependency installation.** Copied only the public package manifests into a new private temporary directory, checked all 957 resolved dependency entries against the public npm registry and their SHA512 integrity metadata, then installed with lifecycle scripts, audit and funding requests disabled. All **933 installed package manifests** match the lock's version/resolved/integrity metadata; 24 missing entries are optional. No existing dependency directory, manifest or lockfile was overwritten.
2. **Resolved CSV compatibility in that fresh tree.** The actual `csv-parse 7.0.2` implementation passes all 12 unchanged tests on Node24 and Node26. The old working tree still contains 5.6.0; it was deliberately preserved and must not be mistaken for the verified fresh installation.
3. **Added [explicit application readiness](../../server/src/auth/fncp-bootstrap-readiness.ts).** [appReady](../../server/app.ts) resolves only after helper initialization, all route registration and the final error handler. Fresh-profile failures use a constant error without leaking the original. Ordinary error reporting is preserved. Readiness is not database health and cannot cancel a held application initializer.
4. **Implemented the [application admission boundary](../../server/src/auth/fncp-bootstrap-admission.ts).** Before the application is reached, it requires loopback TLS, the exact verified invented RS256 bootstrap actor, canonical headers/path/query and a bounded body. It permits only create-conversation → fifteen exact seeds → seed readback → closed/whitelist update → closed readback. It binds the first token, real response conversation/statement IDs and owner PID; rejects out-of-order, repeated, concurrent and cross-conversation requests; validates bounded canonical responses before allowing them to leave; and denies further work after uncertainty, close or deadline.
5. **Corrected the compression incompatibility.** Upstream compression flushes headers before complete-response validation, even without compression negotiation. The fresh profile alone skips compression. Ordinary behavior is unchanged. Accepted bootstrap responses force connection-close/no-store and omit the response ETag. Tests exercise real installed Express JSON and URL-encoded parsers; no request stream is fabricated or replayed.
6. **Added a [public-only JWKS service](./fresh-runtime/bootstrap-jwks-service.mjs).** A new one-shot branded handoff obtains only public key bytes from the original issuer's verified HTTPS endpoint. The service generates its own temporary DNS-SAN TLS credentials, owns one new loopback listener, exports no TLS/RSA private key or bearer, and closes with the original issuer. Its intended container hostname/8444 URI is explicitly distinct from the actual ephemeral loopback endpoint. Container DNS/reachability is **not** established.

The request-scoped logging boundary follows accepted requests and descendant asynchronous work. It does not certify every process-global startup log. The admission factory accepts explicitly trusted public issuer/key/source inputs; it does not itself prove ownership or acquire those inputs from the original branded issuer.

## Verification

| Check | Node26.8.2 | Node24.21.0 |
| --- | --- | --- |
| Foundation/model/transport suite | **1,820 PASS**, 22,818.893791ms | **1,820 PASS**, 25,002.511042ms |
| Server unit suite using fresh dependencies | **417 PASS**, 20 suites, 11.015s | **417 PASS**, 20 suites, 10.772s |
| Separate fresh CSV compatibility | **12 PASS**, 0.253s | **12 PASS**, 0.204s |
| Fresh TypeScript `--noEmit` | **PASS**, 1,235.928ms | **PASS**, 1,131.619ms |

No final suite has failures or skips. The 417 server tests include 70 new admission checks and 12 readiness checks; the 1,820 foundation tests include 23 new JWKS-service checks. The issuer/JWKS focused 49 checks are included in the foundation suite, not additional coverage. Repetition across Node versions is not twice as many unique tests. Separate PHP checks pass **23 identity +23 journal +13 WordPress-stub =59**.

Fresh source verification covers **136 copied public files /1,586,382 bytes**, with exact post-test equality to the source subset. A separate selected inventory covers **14 changed/relevant source, test and manifest files /649,982 bytes**. The older limited proof graph remains **27 files /230,564 bytes**, unchanged; none of these inventories is a complete release/SBOM or security certification.

- Current aggregate evidence (retained local evidence, `evidence/bootstrap-admission-continuation-2026-09-14.json`; not included in this source snapshot)
- Selected source inventory (retained local evidence, `evidence/bootstrap-admission-source-inventory-2026-09-14.json`; not included in this source snapshot)
- Fresh install audit (retained local evidence, `evidence/bootstrap-admission-dependency-audit-2026-09-14.json`; not included in this source snapshot)
- Fresh build audit (retained local evidence, `evidence/bootstrap-admission-fresh-build-2026-09-14.json`; not included in this source snapshot)
- Fresh source-copy inventory (retained local evidence, `evidence/bootstrap-admission-fresh-source-inventory-2026-09-14.json`; not included in this source snapshot)

## Problems and limits that still matter

- **Node22/image assurance remains outstanding.** The server declares Node >=22 <23; these tests used Node24/26 and the fresh install reported an engine warning. This is not approval to run production on either tested version. Ten dependency deprecation warnings were reported; no vulnerability audit, native-library assurance or image build/scan ran. Six packages have install-script metadata; scripts remained disabled and selected published artifacts were inspected, not proven fully operational.
- **One tooling boundary limitation was recorded.** An early clean-environment `npm --version` probe lacked explicit user/global configuration overrides. npm can load ambient configuration before returning its version. No configuration values were printed; the subsequent install used explicit empty configurations and a new cache. Do not claim zero ambient configuration reads. No retained application configuration, keys, certificates, stores or database contents were read.
- **The application launcher is still missing.** The new boundary is tested with actual loopback TLS and actual Express parsers, but invented route handlers. It is not automatically installed around the real application and is not a container-ready listener. Ordinary HTTP startup continues to refuse the fresh profile.
- **Timeout is not rollback.** Closing the boundary prevents new requests and closes active responses. It does not undo dispatched SQL or prove delayed application work has drained. Seed handlers schedule later DB updates; actual resource shutdown and independent database readback remain mandatory.
- **Closing JWKS is not cached-token revocation.** The API boundary and helper resources must be closed independently. The public-only service follows original issuer lifetime; it does not extend or reissue it.
- No real PostgreSQL engine, SQL/SCRAM execution, fresh Pol.is app, WordPress runtime or native browser integration ran in this increment. No Docker/VM command, global trust change, live record action, external correspondence, repository submission, deployment or spending occurred. Public package downloads and official-source reads occurred; no project source or participant data was uploaded.

## Next steps — in order

1. **Finish the owned HTTPS application entrypoint.** Validate the fresh profile before importing the app; obtain public trust from the same original issuer; bind the admission middleware before all app middleware; await `appReady` with a bounded failure path; create only fresh owned TLS/listener resources. Reject upgrade, CONNECT, parser-level faults and stalled handshakes before application dispatch. Do not reuse a production or retained staging configuration.
2. **Wire the actual isolated resource owner.** Join the public-only JWKS role, native PostgreSQL TLS, a reviewed ordinary bootstrap image and exact fresh database/network/volume/helper ownership. Verify the real isolated topology and negative egress. Host-loopback fixture evidence is not container evidence. Do not silently start the VM, switch context, pull images, change trust or fall back to host/default networking.
3. **Build and verify the real target runtime.** Reproduce dependencies for the pinned Linux/ARM64 Node22 image; review required native/generated artifacts, full dependency/image closure and operational warnings. Preserve the existing mismatched installation as historical evidence; do not use it for acceptance.
4. **Run one fresh invented-data bootstrap after its execution scope is established.** Journal before the first authenticated application request; create exactly one conversation and fifteen source-pinned seeds; capture actual IDs/PID; close it and enforce the whitelist; independently verify schema, raw and latest vote baselines. Require exact helper/client/issuer and resource closure evidence, not merely a successful HTTP response.
5. **Join fresh WordPress and native-browser assurance.** Exercise registration → separate Barayamal approval → account-bound invitation → approved voting → forwarded-link denial → already-open-session revocation; then recovery and closed restart. Use invented identities only. Round approval is not proof of Indigenous heritage; no real eligibility documents or participant testing are authorized by these tests.
6. **Keep production decisions separate.** C remains the chosen direction. C1/C2/C3 hosting/authentication selection, actual costs and deployment remain unapproved; the owner pack (retained local evidence, `C-PRODUCTION-DECISIONS.md`; outside this repository) already supplies the practical choices. No additional decision is needed merely to continue local source/test work. Any exact VM/runtime operation, external send, spend, submission, publication or real-participant step must satisfy its own recorded approval boundary.

## Official guidance used

The [official Pol.is stable README](https://github.com/compdemocracy/polis/blob/stable/README.md) supplies Docker/manual self-hosting guidance, and [official configuration documentation](https://github.com/compdemocracy/polis/blob/stable/docs/configuration.md) explains configuration. These are a baseline, not evidence that Barayamal's extra identity/access controls work.

The upstream convenience steps for global certificate trust, environment copies and general startup were not executed. This work uses the source with fresh-only configuration and scoped synthetic verification. Preserve the [Pulse page](https://pulse.barayamal.com.au/), [results](https://pulse.barayamal.com.au/results), [WordPress close notice](https://barayamal.com.au/first-nations-community-pulse-register/) and [technical fallback](https://first-nations-community-pulse.deanosupremo.chatgpt.site/). They were untouched, not freshly inspected.
