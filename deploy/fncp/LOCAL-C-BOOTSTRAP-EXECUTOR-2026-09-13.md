# Option C — bounded database executor and owned-session composition

> Portability note — 7 October 2026: workstation paths were removed, and artifacts outside this source snapshot are labelled retained local evidence. Dated results below remain historical; this edit adds no runtime or release claim.

Checkpoint: **2026-09-13T23:16:08+10:00. LOCAL_ONLY / KEEP_CLOSED.**

The read-only PostgreSQL executor and one-use bootstrap-session composition are
implemented and tested. **This is not a running self-hosted service or deployment
approval.** The new database tests use the installed pg client over actual
loopback TLS to a synthetic wire server; no PostgreSQL engine parses or executes
SQL. Session tests inject lifecycle, API and database models and create a fresh
local issuer. The complete real-transports/session/runtime combination is not run.

## Completed in this increment

- [Database executor](./fresh-runtime/bootstrap-database-executor.mjs) and
  [fixed worker](./fresh-runtime/bootstrap-database-worker.mjs): one original
  factory-branded schema check, then one baseline check. Each uses a separate
  process and connection; no arbitrary SQL, host, executable, environment,
  retained credentials, connection string, pool or retry is accepted.
- TLS validates the normal loopback IP SAN, explicit trust and the exact leaf
  **before PostgreSQL startup identifiers or authentication are sent**. A server
  refusing TLS cannot trigger plaintext fallback.
- The worker requests READ ONLY / REPEATABLE READ, fixed pg_catalog search path,
  statement/lock/idle-transaction limits and row-security denial. It checks exact
  field names/order/types, canonical boolean/integer values and one total
  aggregate row. It rolls back and closes before successful output is accepted.
- The parent bounds the entire query at six seconds and exact-child cleanup at
  a further 1.3 seconds. It can terminate a stuck parser process independently;
  no auxiliary database-cancellation connection is opened. These are scheduling
  bounds, not hard real-time guarantees if the parent/OS itself is stalled.
- [Owned-session composition](./fresh-runtime/bootstrap-owned-session.mjs):
  generated private names/credentials, immutable attempt journal, exact resource
  identities and one-shot creation. Catalog validation precedes API work. The
  actual-response creator PID and statement IDs feed the closed raw/latest-vote
  baseline **before helper shutdown**. Failed baseline still attempts exact
  helper stop; uncertain create IDs are not rediscovered or adopted.
- Cancellation is checked again after awaited integrity checks and before
  transport/database factory dispatch. The owned protocol is denied during
  final cleanup. Independent transport/database/issuer closure acknowledgements
  are required; uncertain closes are not replayed or promoted to success.
- The query handoff now exposes immutable kind/parameters/typed columns only for
  original branded descriptors. Copied descriptors do not acquire authority.

No schema result is promoted to migration completion, database readiness or GO.
A read-only SELECT is not a sandbox against malicious database functions,
operators or catalog/schema provenance. Actual authentication/SCRAM, PostgreSQL
acceptance and full migration bodies remain unverified.

## What the tests actually prove

| Evidence | Verified here | Not established |
| --- | --- | --- |
| Database transport | Two real TLS connections and two separately closed workers; eight fixed extended-protocol statements per operation; four trusted ownership callbacks | PostgreSQL engine execution, database freshness/authentication or actual catalog/vote counts |
| Negative database cases | Wrong CA and valid-CA alternate leaf rejected before startup; row/type/count errors, excess bytes, malformed-parser deadline, sanitized errors, cancellation, no ambient PG/Node configuration | General malicious-server sandbox or production security certification |
| Session composition | 22 grouped model tests: schema before API, stable IDs/PID, closed baseline before stop, failure/cancellation/unknown-resource handling | Real Docker/helper ownership, a running Pol.is API, real database or full concrete transport composition |
| Existing layers | Full source/model/TLS suites rerun | Earlier native browser, Docker/Colima, WordPress acquisition and actual-service observations were not rerun |

**1,788/1,788 tests PASS on each of Node 26.8.2 and Node 24.21.0**, respectively
24,507.898208ms and 24,756.815875ms. Zero failures, cancellations or skips.
**53 additions are included**, not extra unique coverage: 30 database-worker,
22 session and 1 query-handoff test. Fresh-runtime subset: 270 overlapping tests.
Separate PHP checks: **59 PASS** (23 identity, 23 journal, 13 WordPress stubs).

Independent source review found no material executor/session defect. A genuine
AbortSignal can override its instance methods; the executor now uses captured
EventTarget methods and intrinsic aborted checks, avoiding those getters.
An earlier malicious listener can suppress the immediate abort event, but intrinsic
post-await checks still deny continuation and the parent deadline bounds waiting.
The session manager's lifecycle/factory callbacks remain trusted code: they must
enforce their own timeouts. Cancellation cannot terminate a callback that never
returns; no successful cleanup is claimed in that case.

Aggregate evidence (retained local evidence, `evidence/bootstrap-executor-continuation-2026-09-13.json`; not included in this source snapshot) and
source inventory (retained local evidence, `evidence/bootstrap-executor-source-closure-2026-09-13.json`; not included in this source snapshot)
cover 13 current source/test files (252,645 bytes), plus 9 selected installed pg/
pg-protocol files (57,540 bytes). The separate limited 27-file/230,564-byte proof
graph still matches. Neither is a complete dependency/release closure or image
approval. Earlier source inventories remain dated snapshots, not current pins.

Independent artifact audit matched all 13 source and 9 selected dependency
hashes, confirmed the unchanged 27-file limited graph, and resolved all 161 local
file links across eight current documents. Test arithmetic is consistent;
`git diff --check` and scoped trailing-whitespace checks pass.

## Next steps — in order

1. **Implement the concrete ordinary-helper lifecycle.** Connect the new session
   to exact new resource IDs with bounded create/inspect/stop callbacks. The
   existing general Docker lifecycle is not this ordinary-helper adapter.
   Do not infer ownership from callback booleans or reuse retained staging.
2. **Finish image and startup review.** Pin a separately reviewed ordinary image;
   the dedicated gated image is not a substitute. Resolve fresh PostgreSQL 17
   migrations, database TLS, the Auth0 management-client constructor inputs,
   scoped issuer/JWKS certificate trust and container reachability. Disable mail,
   translation and other external integrations. No image pull/build or VM start
   was undertaken or authorized by these source checks.
3. **Verify the exact private topology before application mutation.** Revisit the
   internal-bridge/Colima publishing incompatibility with controlled local canaries.
   Require host/container reachability and negative-egress evidence; no unrestricted
   bridge or weakened TLS/access-gate fallback.
4. **Run an actual fresh synthetic bootstrap only once prerequisites are met.**
   Verify real schema, API/JWT-user mapping, actual returned IDs and both 15-row
   seed-owner Pass baselines; read back closed flags and stop the exact helper.
   Then implement/test a separate guarded active transition for synthetic QA.
   A binding file or this result does not activate a round.
5. **Join fresh actual WordPress, strict access and Pol.is.** Exercise rightful
   invitation redemption, valid forwarded-link denial, selective then terminal
   warm-session revocation, recovery and cleanup in the native browser.
6. **Keep production selection and communication separate.** C is the selected
   local direction. C1/C2/C3 remain unselected; costs are NOT COSTED and approved
   spending is A$0. Real identity, delivery, hosting, publication and participant
   testing need separate evidence and exact approval.

No PostgreSQL binary was available at the exact checked Homebrew16/17/18 paths;
this is not an exhaustive machine inventory. Nothing was installed as a fallback,
and Docker/Colima were not queried or started. No retained configuration, keys,
archives or databases were opened. Fresh synthetic test certificates/directories
were removed and test-owned listeners/workers closed; retained artifacts were
preserved. No fixed staging-port recheck is claimed.

No external message, public change, Git commit/push/PR, remote CI, deployment,
retention action, participant test or spending occurred. The public
[Pulse](https://pulse.barayamal.com.au/),
[results](https://pulse.barayamal.com.au/results),
[WordPress close notice](https://barayamal.com.au/first-nations-community-pulse-register/)
and [fallback](https://first-nations-community-pulse.deanosupremo.chatgpt.site/)
were left unchanged and were not freshly inspected.

Owner guide (retained local evidence, `C-SELF-HOSTING-GUIDE.md`; outside this repository)
· [Fresh integration plan](./LOCAL-C-FRESH-RUNTIME-PLAN-2026-09-13.md)
· [Prior transport checkpoint](./LOCAL-C-BOOTSTRAP-TRANSPORT-2026-09-13.md).

Technical basis: [official Pol.is self-hosting/source](https://github.com/compdemocracy/polis/blob/stable/README.md),
[configuration guidance](https://github.com/compdemocracy/polis/blob/stable/docs/configuration.md)
and [fresh-database image source](https://github.com/compdemocracy/polis/blob/stable/server/Dockerfile-db).
The explicit transaction follows [PostgreSQL 17 transaction controls](https://www.postgresql.org/docs/17/sql-set-transaction.html);
the TLS adapter follows [node-postgres SSL configuration](https://node-postgres.com/features/ssl)
and the installed pg 8.16.3 / pg-protocol 1.10.3 source. Current web examples can differ
from installed versions; no new driver features or insecure example settings were
silently adopted. Upstream instructions do not certify Barayamal's custom controls.
