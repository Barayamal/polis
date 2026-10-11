# Dedicated self-host math contract

The `fncp-production` Docker target enforces authenticated PostgreSQL TLS for the dedicated release. It inherits the reviewed minimal Java runtime and fixed dependency basis. The ordinary `runtime` target and default `upstream-production` stage preserve the previous upstream URI behavior.

## Configuration

| Variable | Dedicated value |
| --- | --- |
| `FNCP_OPTION_C_RELEASE_MODE` | Exactly `production`; baked into the dedicated target. Empty, false and malformed overrides fail. |
| `DATABASE_URL` | `postgres://user:password@postgres:5432/database` or `postgresql://...`; percent-encode reserved user/password characters. No query or fragment. Hostname must match the server certificate SAN. IPv6 hosts are supported. |
| `DATABASE_SSL` | Exactly `true`. |
| `DATABASE_SSL_CA_FILE` | Absolute path to the explicitly mounted readable PEM CA bundle, at most 1 MiB. The bundle must contain CA certificates. |
| `DATABASE_POOL_SIZE` | Existing pool setting; use a small positive count for the local rehearsal. |
| `DATABASE_IGNORE_SSL` | Must be absent or false in the dedicated profile. |
| `MATH_ENV` | Must match the API's math environment, normally `prod`; this keys database math rows. |
| `MATH_ZID_ALLOWLIST` | Optional comma-separated numeric conversation IDs; scope the isolated rehearsal to its known conversation. |

The dedicated JDBC connection uses `sslmode=verify-full`, the explicit `sslrootcert`, the standard validating factory and hostname verifier, and `gssEncMode=disable`. Empty client certificate/key properties prevent implicit `~/.postgresql` key discovery. The CA bundle is checked before creating the pool. Invalid dedicated inputs produce only `MATH_DATABASE_TLS_CONFIGURATION_INVALID`, without a credential-bearing URI or nested parser cause.

[pgJDBC documents](https://jdbc.postgresql.org/documentation/use/) that URL properties override a supplied Properties object and that its default `prefer` mode does not validate server identity. Dedicated URLs therefore reject query parameters, including attempts to supply another CA, factory, hostname verifier, user or SSL mode. [Its SSL guidance](https://jdbc.postgresql.org/documentation/ssl/) specifies certificate-chain and hostname verification for `verify-full`. The original math pooling implementation ignored its SSL argument; ordinary upstream configurations remain compatible when no dedicated release-mode key is present.

## Exact build boundary

Build from `math/` with `--target fncp-production --build-arg SOURCE_REVISION=<actual 40-character baseline revision>`. A local candidate must also carry the actual copied-source fingerprint and an explicit uncommitted-work label; the baseline revision alone is not a release attestation.

The reviewed Dockerfile pins these input indexes:

| Stage | Image index |
| --- | --- |
| BusyBox compiler | `node:24.18.1-alpine@sha256:f70403e87646dc51b45295f4b8b70cdad0b63d2297c4c9899119b03f7af7a6b3` |
| Clojure dependency resolution | `clojure:temurin-17-tools-deps@sha256:8250a7e6b20954680c2e3bf2e84ad4caab1c5ea68c56c28bca41fb9ac5a2e96e` |
| Bounded Java runtime | `amazoncorretto:17-alpine@sha256:e1138bf0cca62e04692de650ffe8923f35c39fcb554458c7acd98efc2d135144` |
| Runtime userland | `alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b` |

`deps.edn` is unchanged by this TLS fix; it includes Clojure 1.12.5 and pgJDBC 42.7.13. The build resolves `-M:run`, copies its exact JAR files into `/app/lib`, checks basename collisions, and writes `/app/classpath`. Only `src`, `resources`, `bin`, `system.properties` and the runtime JAR closure cross into the final worker. Test fixtures and tests remain excluded. The final process uses Java 17 and UID/GID 65532. Build probes prove class loading and core.matrix initialization, not database TLS or completed analysis.

## Closed conversation and database privileges

A closed conversation (`is_active=false`) can be processed normally. `postgres/poll` and `mod-poll` select votes/comments by timestamp without filtering conversation state. The default polling window is the preceding ten days. Seed recent fixture votes before starting the worker; do not open the conversation to make math run.

The normal `./bin/run` starts the `full` subcommand, which currently constructs only the vote/moderation poller system. In dedicated production mode the launcher directly replaces itself with one JVM using `-Xmx1024m`, leaving native-memory headroom under the dedicated 1536 MiB container limit. A failure exits observably under `restart: no`; there is no four-hour kill or unconditional restart loop. Present empty/invalid mode values fail before Java. Ordinary upstream mode with the release variable absent retains its existing 4 GiB restart-loop behavior. Direct foreground invocation for the dedicated owned runtime is:

```sh
/opt/java/openjdk/bin/java -Xmx1024m -cp "$(cat /app/classpath)" clojure.main -m polismath.runner poller
```

The legacy `update -z` CLI is not a reliable first-computation test: its new-conversation path has no loaded votes and its handler passes the whole system to an operation expecting the conversation manager. Use the normal poller and independently observe persisted output. Lowercase `-z` means numeric zid; uppercase `-Z` means an invitation code.

The core poller requires database CONNECT, public schema USAGE, SELECT on `votes` and `comments`, SELECT/INSERT/UPDATE on `math_ticks`, `math_main`, `math_profile`, `math_ptptstats`, `math_bidtopid`, and EXECUTE on `now_as_millis()`. These tables use conversation IDs and no sequences. Those grants derive from `src/polismath/components/postgres.clj` and the initial schema. The core worker needs no writes to participant, vote, comment, conversation, user or identity tables, and no task/export grants. Fixture insertion belongs to the separate owner role. A grants smoke test should observe a successful TLS query and denied writes to source tables.

## Deterministic synthetic engine fixture

`test/fixtures/dedicated-analysis.json` defines **18 participants, 15 approved non-meta statements, 270 unique votes**, within the 20-identity cap. Three cohorts of six use fixed agree/disagree patterns over three five-statement blocks. Every statement has 18 votes; agreement counts are 6, 12 and 6 across the blocks. These inputs span two dimensions. The engine includes a participant after `min(7, number-of-statements)` votes and supplements the top contributors until 15 are included where available. Neither rule is a hard minimum for computation. All 18 fixture participants vote on all 15 statements.

`test/dedicated-analysis-fixture.mjs` is a pure, owner-run SQL renderer. Pass JSON on stdin with exactly `database`, `zid`, `participantIds` (18 distinct existing pids), and `statementIds` (15 distinct existing tids). It never connects to a database or creates identities. The generated transaction checks the exact database, closed conversation, participant cap/distinct users, exact approved/active/non-meta statements, and absence of pre-existing votes/math output before inserting votes. It does not delete, replace or clean existing data. This is explicitly **engine fixture evidence**, not proof of identity approval, browser voting, consent, real users or production activation.

```sh
node math/test/dedicated-analysis-fixture.mjs < owned-fixture-identifiers.json > generated-engine-fixture.sql
node --test math/test/dedicated-analysis-fixture.test.mjs
```

The renderer uses an `INSERT ... SELECT ... FROM (VALUES ...)` statement. A top-level `WITH` failed against the real Pol.is `ON INSERT DO ALSO` vote rule because PostgreSQL expands that insert into multiple queries. `now_as_millis()` uses transaction-stable `now()`, preserving one timestamp origin and ordinals 0–269. Before committing, the renderer checks actual totals of 270 votes, 18 participants, 15 statements, 270 unique participant/statement pairs, a 269 ms timestamp span and 270 `votes_latest_unique` rows; a mismatch raises an exception. The self-host fixture composes creation and vote insertion within one transaction so a failed insert cannot leave partial fixture data.

After executing the reviewed SQL against the newly owned database, require persisted `math_main`, `math_bidtopid` and `math_ptptstats` rows with a common nonnegative tick matching `math_ticks` for the same zid/math environment; the initial tick can legitimately be zero. Require a positive `math_main.caching_tick`. Verify `n=18`, `n-cmts=15`, exact tids, complete participant coverage, finite two-component PCA, at least two nonempty groups, and the exact vote totals above. Compare every output's `lastVoteTimestamp` and the main row's `last_vote_timestamp` to the inserted maximum timestamp. Require complete `mod-in`, empty `mod-out`/`meta-tids`, and `lastModTimestamp` equal to the latest comment modification. Fail if results are absent, fallback/empty, inconsistent, or stale; a worker log line or API HTTP 200 is insufficient. The API integration math test that accepts empty fallback data cannot establish this result.

## Worker initialization and persistence corrections

These corrections affect this fork's math manager in ordinary and dedicated modes. The analysis formulas, participant inclusion thresholds and PCA are unchanged. Actor initialization, persistence ordering, retries and moderation-watermark preservation are corrected. Clustering retains Euclidean distance and Lloyd iteration, with the finite-distance computation correction described below.

The September 2026 `core-e` local rehearsal computed 18 voters, 15 statements, 270 votes, three base clusters, two groups, 15 consensus values and 18 private participant statistics. Its persisted moderation fields remained absent across independent read-only snapshots. The strict proof refused to pass despite the other computed results and valid TLS sessions.

- Concurrent first vote and moderation batches could each construct an actor after observing an empty conversation map. Publishing the second actor could strand the first actor's state. Actor construction and publication now occur under the manager's conversation-map monitor; putting messages into the actor queue occurs outside that monitor. A deterministic two-thread regression holds the first constructor while the second poller arrives, proves only one actor is constructed, and checks that both batches reach it.
- Each update previously spawned an independent persistence thread. Older vote snapshots could overwrite later moderation snapshots, and write errors escaped the actor's error handler. The actor now finishes its main, bucket-map and participant-stat writes before advancing. A regression checks ordering and propagation of a deliberately failing write. These three SQL writes are ordered, not one database transaction; readers must still reject mismatched ticks and wait for the complete set.
- The retry channel contains a message map, but the old splice concatenated that map as key/value entries. The retry is now wrapped as one message before combining it with the next incoming batch. A write-failure/replay regression checks that the failed vote and subsequent vote both reach the persisted state.
- A vote update preserved moderation sets but discarded their `last-mod-timestamp`. The base update graph now carries that scalar forward. The computation fixture asserts that an existing moderation watermark remains in `prep-main` after votes are processed.

The seeded fixture also required a separate test-harness correction: the parallel graph returns deferred computations. The test now forces its checked output while the fixed random-seed scope remains active. This changes test execution only, without replacing or bypassing native math calculations.

## Native distance cancellation correction

Forcing the complete seeded fixture exposed another runtime defect at PCA seed 1410. All three base centers were distinct and finite. After one weighted clustering step, a singleton center differed from its input row by approximately 9e-16. The installed Vectorz native-row distance returned `NaN`, while the same coordinates as plain vectors returned their finite Euclidean distance. `min-key` then assigned that point to the other group, leaving one group and causing silhouette to fail because no neighboring group existed.

Clustering now computes the Euclidean norm of explicit coordinate differences. Nearest-center assignment, convergence, distal-point selection and distance matrices all use that function. This avoids the cancellation in the optimized squared-norm/dot-product distance without changing weights, initialization, requested groups, iteration limits or silhouette semantics. A regression uses the exact native matrix rows and recalculated center, checks finite near-zero distance, retains both expected weighted groups, verifies input coordinates were not mutated and requires a finite silhouette. The full seeded fixture retains its original 18 participants, 15 statements, both seeds and strict group/moderation assertions.

The [Vectorz distance implementation](https://github.com/mikera/vectorz/blob/vectorz-0.66.0/src/main/java/mikera/vectorz/AVector.java) uses the squared-norm/dot-product identity, and [vectorz-clj delegates native vector distance there](https://github.com/mikera/vectorz-clj/blob/vectorz-clj-0.48.0/src/main/clojure/mikera/vectorz/matrix_api.clj). These public sources explain the mechanism; the recorded trace from the actual local image establishes the installed behavior. General one-cluster silhouette handling and cluster-count convergence remain separate upstream limitations; this fix does not conceal invalid groupings by substituting a score.

## Tests and execution evidence

`postgres-tls-test` exercises real Hikari/pgJDBC effective properties and the actual CA-loading factory without opening database sockets. It covers environment parsing, valid explicit CA and percent-encoded credentials, IPv6, malformed settings/URIs, missing/empty/invalid/non-CA/oversized certificate material, SSL/query override attempts, fixed error output and ordinary upstream behavior. Both PEM fixtures are synthetic public certificates; their private keys were discarded during generation.

`dedicated-analysis-test` runs the actual conversation computation on the shared 18×15 fixture with two fixed PCA random seeds and asserts output invariants rather than sign- or label-sensitive vectors. Both namespaces are included in `clojure -M:test`. In the `build` stage, `clojure -M:test` selects `test-runner` and runs the complete pure suite. For a bounded runtime container with current tests copied or mounted at `/app/test`, append that directory to `/app/classpath` and invoke `clojure.main` with `clojure.test/run-tests` for `postgres-tls-test` and `dedicated-analysis-test`, followed by `shutdown-agents` and a failing process exit for any error/failure. No Java or Clojure runtime is available on the current host; JVM and actual owned-database TLS results must be recorded after the parent builds the test container. Successful local SQL-renderer tests do not imply JVM or database TLS tests passed.

An actual TLS integration probe must succeed with the owned CA and matching hostname, observe `pg_stat_ssl.ssl=true` on its own connection, and fail with an unrelated CA and with a resolvable hostname missing from the certificate SAN. This probe must use only the parent's exact newly owned database and network; no default Docker context or existing database is part of this contract.
