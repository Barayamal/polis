# Option C — HTTPS child entrypoint and transaction correction

> Portability note — 7 October 2026: workstation paths were removed, and artifacts outside this source snapshot are labelled retained local evidence. Dated results below remain historical; this edit adds no runtime or release claim.

Checkpoint: **2026-09-14T00:56:36+10:00 (Australia/Sydney). LOCAL_ONLY / KEEP_CLOSED.**

**This implementation increment is complete; the fresh self-hosted stack is not complete or running.** The fixed application entrypoint now exists and its listener/process boundaries are tested with synthetic app fixtures. The concrete parent/container owner and actual Pol.is/PostgreSQL run remain outstanding. There is no new user-facing preview URL.

## What changed

1. **[Fixed child entrypoint](../../server/src/bootstrap/https-entrypoint.ts).** It requires a dedicated Node child, private IPC, discarded standard input/output/error and a valid fresh-only profile. The only application import is the fixed compiled Pol.is app path, after public trust validation. It awaits explicit app readiness, reports its ephemeral HTTPS certificate/origin only over private IPC, handles stop/disconnect/failure, and exits its own process. Ordinary HTTP startup still refuses this profile. No retained environment or caller-selected app module is loaded.
2. **[Owned loopback HTTPS runtime](../../server/src/bootstrap/https-runtime.ts).** It generates fresh TLS material in a private temporary directory, installs the existing fixed 19-request admission boundary before the application, and listens only on an ephemeral 127.0.0.1 port. It rejects malformed TLS/HTTP, CONNECT, upgrades, Expect requests, wrong routes and stalled sockets. Readiness and cleanup are bounded. Closure destroys owned sockets and independently checks connection refusal. It is a host-loopback component, not proof of a container route.
3. **[Public API trust handoff](./fresh-runtime/bootstrap-api-trust.mjs).** A one-shot branded capability receives the public key and pinned synthetic seed bytes from the original issuer. Its API and JWKS-service roles share one verified public-key fetch; a failed fetch is cached, not retried under another role. It preserves the original lifetime, activity check and cancellation signal. It creates no token or listener and releases no private key. A parent launcher must continue observing the original signal after it sends public data to a child; IPC serialization alone does not carry that authority.
4. **[OIDC transaction correction](../../server/src/auth/create-user.ts).** Main account/mapping creation and the recovery mutation now use [one primary PostgreSQL client for the whole transaction](../../server/src/db/pg-query.ts). BEGIN, COMMIT and ROLLBACK require their exact acknowledgement tags. A statement failure remains latched even if a callback catches it. Retry requires a confirmed rollback and successful release; uncertain COMMIT, connection failure, failed rollback or failed release do not authorize another mutation attempt. Fresh-profile failures are sanitized. Ordinary mapping policy is preserved; this is not identity or Indigenous-heritage verification.
5. **Process/logging separation.** The fresh child owns its failure handlers; the fresh profile skips the conflicting legacy global handlers. Ordinary behavior remains. OS-level discarded output covers startup diagnostics that request-scoped logging controls cannot cover.

## Verification

| Check | Node 26.8.2 | Node 24.21.0 |
| --- | --- | --- |
| Foundation/model/transport suite | 1,843 PASS; 24,248.619333 ms | 1,843 PASS; 23,249.165 ms |
| Server unit suite, fresh dependencies | 514 PASS /23 suites; 22.631 s | 514 PASS /23 suites; 22.713 s |
| Separate CSV compatibility | 12 PASS; 0.101 s | 12 PASS; 0.104 s |
| Fresh TypeScript no-emit compilation | PASS | PASS |

Final whole suites have no failures or skips. PHP adds **23 identity +23 local-journal +13 WordPress-stub =59 PASS**. There are **120 new unique checks** in this increment: 42 HTTPS, 20 child-process, 35 transaction and 23 public-trust tests. These are already included above; repeated runtime and focused runs are not additional unique coverage.

The HTTPS tests use real fresh TLS and Express. The child tests run an actual fresh Node process and private IPC, but compile a **synthetic fixture application instead of importing the real Pol.is app**. Transaction tests mock the pool/client: actual SQL execution, PostgreSQL command semantics and rollback are not runtime-verified here. No actual database engine, WordPress or native-browser integration was run.

A new source-only snapshot preserves the preceding snapshot and both dependency installations. Its **141 public files /1,648,629 bytes** match their originals after tests. The selected current-source inventory is **13 files /245,284 bytes**. The reused fresh dependency tree still has **933 matching installed metadata records, 24 optional omissions and zero metadata mismatches**. No new package installation ran. The separate older proof graph remains **27 files /230,564 bytes**, unchanged; none is full release closure or security certification.

The eight updated guide/report files have **177 checked local links, zero missing targets**, and the scoped diff check passes. External references were not refetched by this link check.

- Aggregate evidence (retained local evidence, `evidence/bootstrap-entrypoint-continuation-2026-09-14.json`; not included in this source snapshot)
- Selected source inventory (retained local evidence, `evidence/bootstrap-entrypoint-source-inventory-2026-09-14.json`; not included in this source snapshot)
- Fresh public-source snapshot inventory (retained local evidence, `evidence/bootstrap-entrypoint-fresh-source-inventory-2026-09-14.json`; not included in this source snapshot)
- Previous dependency audit and limitation (retained local evidence, `evidence/bootstrap-admission-dependency-audit-2026-09-14.json`; not included in this source snapshot)
- [Previous admission/dependency milestone](./LOCAL-C-BOOTSTRAP-ADMISSION-2026-09-14.md)

The earlier npm version probe's possible ambient npm configuration read remains recorded. Do not reinterpret this increment as establishing zero ambient configuration reads across earlier work. No retained application configuration, keys, stores or participant content was accessed in this increment.

## Problems found and resolved

- Invalid/proxied cancellation signals could reach cleanup or initialization; validation now occurs before signal ownership is assigned.
- Immediate cancellation could still dispatch the queued initializer. A regression first demonstrated one unwanted call; the initializer now rechecks activity inside that queued callback and the final tests require zero calls.
- Transaction callbacks could swallow a failed statement, and an apparently resolved COMMIT could carry a ROLLBACK tag. Failure latching and exact tag checks now prevent false success.
- Three initial child-disconnect tests waited on Node's inconsistent close-event observation after parent IPC disconnection. Tests now observe exact child exit and IPC disconnection, and await process closure before removing fixtures. Three abandoned test directories containing 18 reproducible compiled fixture files were removed after checking for matching children. No user source or data was deleted.
- One old source-contract test expected the previous email-extraction syntax. It was corrected and strengthened with the new transaction/retry checks; both full foundation suites were rerun successfully.

## What still prevents a complete self-hosted run

At **00:32:55 AEST on 14 September**, the configured NVM directory exposed Node 25.9.0 and 26.8.2, not Node22. This is not a machine-wide absence claim. The separate test runtime is Node24.21.0. Pol.is declares Node >=22 <23, so these tests do not establish supported production runtime compatibility.

The dedicated Docker socket was absent at that same read-only checkpoint. No Docker CLI, VM start, context switch, image pull/build or retained resource inspection followed. Engine health was not inferred.

The kernel's fixed OpenSSL executable is tested on this Mac; Linux image packaging is not established. The loopback-only listener, fixed IPC child and public-trust capability are not yet joined into a concrete resource-owning parent/container launcher. Existing older lifecycle/image/topology assumptions cannot simply be reused. Child exit is not SQL rollback, database-container shutdown or closure of cached-token consumers.

## Next steps — in order

1. **Finish the concrete local parent/resource owner.** Consume the branded API trust once, preserve the original issuer deadline and abort signal, generate/attest the fresh profile, launch only the fixed compiled child with a minimal environment and discarded output, and observe its exact exit. Do not accept an arbitrary executable, environment, image or existing resource. Keep safe source/model tests local; no new owner decision is required for that work.
2. **Complete the Node22/container package.** Pin the ordinary bootstrap image and Linux/ARM64 dependencies; verify native/generated artifacts and OpenSSL packaging. Join native PostgreSQL TLS and the public JWKS/API services on the exact isolated topology, then prove internal reachability and denied external egress. Loopback fixture success is not evidence of that topology. Build/download/VM operations must stay within their separately recorded execution authority.
3. **Confirm the exact local execution scope when the launcher is ready.** Dean/Barayamal owns approval for any previously unapproved VM/resource operation. Present the exact profile, image/source hashes, fresh resources, cleanup policy and download/spend effects before that action. Do not silently start the absent runtime or switch to another engine. Source work can continue while that operation is paused.
4. **Run one fresh invented-data bootstrap.** Create a private attempt journal first. Verify schema, then create exactly one conversation and the 15 pinned statements through the actual app. Capture actual IDs/PID, close the conversation, enforce the whitelist, independently verify raw/latest vote baselines, and prove helper/client/issuer/database resource closure. A timeout or successful HTTP response cannot substitute for database evidence.
5. **Join WordPress and the voter journey.** With invented identities only, verify registration → separate Barayamal approval → account-bound invitation → voting → forwarded-link denial → already-open-session revocation → recovery and closed restart. WordPress administration is separate from Pol.is voting. Neither an email address nor a software approval flag proves Indigenous heritage. No real participant testing or messages are authorized by synthetic results.
6. **Keep production decisions separate.** C remains the selected direction. Use the owner decision pack (retained local evidence, `C-PRODUCTION-DECISIONS.md`; outside this repository) for C1/C2/C3 hosting/authentication, current quotes, operator responsibility and ongoing cost. These remain unselected/NOT COSTED; A$0 spending is approved. No provider contact, contract, submission, deployment, publication or invitation may be sent without exact approval. PR #27 is not GO authority.

The next useful action is **local owner/packaging implementation**, not deployment or participant testing. There is no provider message that needs sending to complete this code increment.

## Official Pol.is guidance

Use the [official stable self-hosting README](https://github.com/compdemocracy/polis/blob/stable/README.md) and [configuration reference](https://github.com/compdemocracy/polis/blob/stable/docs/configuration.md). They provide the Docker/manual baseline; Barayamal's additional approval, invitation and revocation controls require their own proof.

Upstream convenience steps that copy retained environment files, install global certificate trust or start a general stack were not executed. The [Pulse page](https://pulse.barayamal.com.au/), [results](https://pulse.barayamal.com.au/results), [WordPress close notice](https://barayamal.com.au/first-nations-community-pulse-register/) and [technical fallback](https://first-nations-community-pulse.deanosupremo.chatgpt.site/) were untouched, not freshly inspected. No new external correspondence, source upload, repository commit/push/PR, live-data action, public deployment or spending occurred.
