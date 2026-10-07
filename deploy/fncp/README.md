# First Nations Community Pulse — Option C staging

Status: **synthetic-data staging only**

This directory packages a pinned, loopback-only Pol.is origin for testing the
Barayamal First Nations Community Pulse access boundary. It is not a production
deployment and it must never receive a genuine registration, eligibility
record, invitation, vote or statement.

Latest recorded evidence:

- [14 September fresh WordPress-to-participant integration — latest](./LOCAL-C-PARTICIPANT-INTEGRATION-2026-09-14.md) — real WordPress/strict access/Pol.is, three native53 and independent protocol26 PASS; vote attribution, selective revocation, closed restart and logical recovery PASS. Final exact images scanned; vulnerable QA image excluded from deployment. Clock guard preserved, VM settings restored, all48 task containers and VM stopped. Production remains unfinished and KEEP_CLOSED.
- [14 September actual fresh Linux container integration — historical bootstrap milestone](./LOCAL-C-CONTAINER-INTEGRATION-2026-09-14.md) — real Pol.is/PostgreSQL: 19/19 bootstrap requests, 15 synthetic seeds, final closed/gated state and independent SQL baseline PASS. All ten task containers and VM stopped. Each Node22/24/26: 1,936 foundation, 568 fresh server, 12 CSV; PHP59/TypeScript PASS. Fresh WordPress/participant integration and production assurance remain unfinished. KEEP_CLOSED.
- [14 September fixed parent, issuer-bound bridge and Node22 assurance — historical 01:27 checkpoint](./LOCAL-C-BOOTSTRAP-PARENT-2026-09-14.md) — each Node22/24/26 passes 1,872 foundation, 556 fresh server and 12 CSV tests; PHP59 and TypeScript pass. Real issuer/parent/child/TLS composition with synthetic app; actual database/container ownership, Linux image/topology and fresh WordPress/Pol.is integration remain unfinished. KEEP_CLOSED.
- [14 September HTTPS child entrypoint and transaction correction — historical 00:56 checkpoint](./LOCAL-C-BOOTSTRAP-ENTRYPOINT-2026-09-14.md) — each Node24/26 passes 1,843 foundation, 514 fresh server and 12 CSV tests; PHP59 and TypeScript pass. Owned host-loopback listener, fixed IPC child, public API trust and single-client OIDC transactions implemented. Concrete parent/container ownership, Node22/image and actual joined integration remain unfinished. KEEP_CLOSED.
- [14 September fresh dependencies and admission — historical 00:24 checkpoint](./LOCAL-C-BOOTSTRAP-ADMISSION-2026-09-14.md) — 1,820 foundation, 417 fresh server and 12 CSV tests per Node runtime; PHP59. Separate lockfile-aligned dependencies, appReady, 19-request admission and public-only JWKS added here; older dependencies preserved.
- [13 September preparatory startup and application TLS — historical 23:54 checkpoint](./LOCAL-C-BOOTSTRAP-STARTUP-2026-09-13.md) — 1,797 foundation and 335 server unit tests passed per Node runtime; PHP 59 passed. CSV was 9/12 with installed 5.6.0 versus locked 7.0.2; the later fresh install resolves that mismatch without overwriting the old tree. Startup/effect guards, strict app PG/JWKS TLS and cleanup/error fixes were implemented here.
- [13 September database executor and owned-session composition — historical 23:16 checkpoint](./LOCAL-C-BOOTSTRAP-EXECUTOR-2026-09-13.md) — 1,788 tests on each Node 24/26 and 59 PHP checks PASS. Concrete pg/TLS transport and injected session composition implemented then; actual PostgreSQL/Pol.is runtime was NOT RUN. See the later startup/TLS report for current work and outstanding checks.
- [13 September bootstrap HTTPS transport and database contract — historical 22:50 checkpoint](./LOCAL-C-BOOTSTRAP-TRANSPORT-2026-09-13.md) — 1,735 tests on each Node 24/26 and 59 PHP checks PASS. Real certificate-pinned HTTPS runs19 modeled API requests with verified synthetic JWTs; database SELECT/result contracts are source-tested only. Exact owned runtime integration, SQL execution, ordinary image, container TLS/topology and actual WordPress/Pol.is browser journey remain unfinished. KEEP_CLOSED.
- [13 September fresh bootstrap protocol and local HTTPS issuer — earlier](./LOCAL-C-BOOTSTRAP-PROTOCOL-2026-09-13.md) — 1,670 tests on each Node24/26 and59 PHP checks. One-shot protocol/HTTP mapper is model-tested; host-loopback RS256/JWKS uses actual TLS and installed JWT-library tests. Cached-token revocation is not provided by issuer closure. No Docker/Pol.is/database request, VM start or native-browser integration; owned helper/image/schema/container TLS/topology remain unfinished. KEEP_CLOSED.
- [13 September concrete Docker transport/preflight/lifecycle source — earlier](./LOCAL-C-DOCKER-ADAPTER-2026-09-13.md) — 1,620 tests on each Node24/26 and59 PHP checks. Fixed socket/empty client configuration, active callback authority, exact-ID ownership and cancellation/uncertain-result handling. That increment's real read-only preflight was BLOCKED; separate status found Colima stopped. Neither was repeated in the latest increment. No Docker mutation or VM start.
- [13 September fresh-only self-hosting foundation — earlier](./LOCAL-C-FRESH-FOUNDATION-2026-09-13.md) — 1,549 tests on each Node24/26 and59 PHP checks. Fresh private ownership/configuration, guarded injected lifecycle, exact bootstrap-result validation and separate pristine WordPress source/preparation API. Official7.1 bytes passed memory-only verification in that earlier increment, not reacquired in the latest one. Concrete Docker adapters were then unimplemented; see the later report for current source progress.
- [13 September two approved native browser accounts — earlier, not rerun in latest increment](./LOCAL-C-CROSS-ACCOUNT-2026-09-13.md) — 1,500 tests on each Node24/26 and59 PHP checks. Two-profile HTTPS proof passes30 checks plus27 nested strict assertions per runtime: valid forwarded invitations denied, unchanged rightful tokens accepted, both open sessions denied after both signed revocations. All14 final native journeys pass and all16 fresh profiles are removed. Actual strict service with modeled WordPress/Pol.is/invented issuer; no runtime access-rule change or production authority.
- [Fresh actual WordPress/Pol.is runtime plan — partial source implementation](./LOCAL-C-FRESH-RUNTIME-PLAN-2026-09-13.md) — fresh ownership/source foundations implemented; actual integration NOT_RUN. Follow the new boundary rather than rerunning retained-state launch scripts unchanged.
- [13 September native HTTPS through the strict service — earlier](./LOCAL-C-STRICT-NATIVE-HTTPS-2026-09-13.md) — 1,490 tests on each Node24/26 and59 PHP checks. Strict complete-vote and warm-revocation journeys each pass31 immediate/35 committed checks on each runtime; BFF-model27/31 regressions also pass. Actual strict access/activation and signed receipt/event boundaries, model WordPress/Pol.is/invented issuer. All strict runs end revoked with six ephemeral ports refused. No runtime access-rule change or production authority.
- [13 September native HTTPS and shutdown assurance — earlier](./LOCAL-C-NATIVE-HTTPS-2026-09-13.md) — 1,483 tests on each Node24/26, 59 PHP checks; actual Chrome149 HTTPS journeys pass 27 immediate-redirect and31 committed-issuer-page checks on each runtime. Disposable profile-only trust, cancellation/replay denial, 28 native HTTP UI regressions, and two shutdown fixes. Invented issuer/models only; no actual WordPress/Pol.is retest, real identity or production authority.
- [13 September native HTTP browser UI continuation — earlier](./LOCAL-C-NATIVE-BROWSER-2026-09-13.md) — 1,391 tests on each Node24/26, 59 PHP checks, and28 actual Chromium UI checks on each Node runtime. Historical failed HTTPS interception remains failed evidence; the later native HTTPS runner is separate.
- [13 September HTTPS protocol redirect — earlier](./LOCAL-C-HTTPS-REDIRECT-2026-09-13.md) — 1,349 tests on each Node 24/26, 59 PHP checks; certificate-verified loopback TLS and invented issuer with modelled browser cookies/navigation. No real IdP or production authority.
- [13 September dedicated strict local service — earlier](./LOCAL-C-STRICT-SERVICE-2026-09-13.md) — 1,154 tests on each of Node 24/26, 59 PHP checks; private operator authority, no HTTP test administration, all-service rollback/drain and 26-file pinned graph. Programmatic/local-only, not a production CLI or real login. No Docker, retained-store access, send or deployment.
- [13 September receiver, lifecycle and source-package review — earlier](./LOCAL-C-SOURCE-CLOSURE-2026-09-13.md) — 1,012 tests on each of Node 24/26, 59 PHP checks; 24-file pinned first-party source graph, not a full release or deployable strict service. No Docker, retained-store access, send or deployment.
- [13 September identity deadlines, actual local TLS and gateway admission — earlier](./LOCAL-C-NETWORK-HARDENING-2026-09-13.md) — 918 tests on each of Node 24/26, 59 PHP checks; invented issuer, no real browser redirect, Docker, retained-store change or deployment.
- [13 September review ZIP, pre-start admission and browser process crash proof — earlier](./LOCAL-C-REVIEW-BUNDLE-2026-09-13.md) — 864 tests on each of Node 24/26, 59 PHP checks, independently checked local archive; no Docker, real identity or production deployment.
- [13 September restored access cold start and whole-system review scope — earlier](./LOCAL-C-COLD-RESTART-REVIEW-2026-09-13.md) — 736 tests on each of Node 24/26, 59 PHP checks, actual closed restart and bounded offline inventory; not production or full restored-application assurance.
- [13 September seamless registration and actual four-store recovery — earlier local increment](./LOCAL-C-SEAMLESS-RECOVERY-2026-09-13.md) — 611 Node / 59 PHP checks, 26 actual journey stages and closed data restore PASS; real login, production recovery and deployment remain unproved/unapproved.
- [Expanded actual recovery procedure and exclusions](./expanded-recovery/README.md)
- [13 September fresh WordPress registration bound to strict identity and actual Pol.is](./LOCAL-C-WORDPRESS-IDENTITY-2026-09-13.md)
- [New registration/outbox protocol, local runner and limits](./wordpress-identity/README.md)
- [Strict identity/activation recovery validator — model only, KEEP_CLOSED](./strict-recovery/README.md)
- [13 September integrated signed identity, browser, approval and actual Pol.is journey](./LOCAL-C-INTEGRATED-2026-09-13.md)
- [Strict integrated proof: run instructions and exact limitations](./integrated-journey/README.md)
- [13 September identity, signed activation and three-store recovery increment](./LOCAL-C-FOUNDATIONS-2026-09-13.md)
- [OIDC protocol foundation — synthetic only](./identity-foundation/README.md)
- [Signed activation foundation — synthetic only](./activation-foundation/README.md)
- [Coordinated three-store recovery procedure](./local-recovery/README-C-COORDINATED-RECOVERY.md)
- [13 September actual local WordPress/browser journey](./LOCAL-C-JOURNEY-2026-09-13.md)
- [WordPress/browser restart walkthrough](./local-wordpress-runtime/README.md)
- [13 September local C implementation and test results](./LOCAL-C-IMPLEMENTATION-2026-09-13.md)
- [13 September dependency review](./DEPENDENCY-REVIEW-2026-09-13.md)
- [Local synthetic approval/invitation bridge](./local-access/README.md)
- [Synthetic backup/isolated restore proof](./local-recovery/README.md)
- [Disposable staging results observed through 28 July 2026](./STAGING-EVIDENCE-2026-07-26.md)
- [D1 dependency reduction](./D1-DEPENDENCY-EVIDENCE-2026-07-28.md)
- [D3 request-client migration](./D3-REQUEST-MIGRATION-EVIDENCE-2026-07-28.md)
- [D4 middleware cleanup](./D4-MIDDLEWARE-CLEANUP-EVIDENCE-2026-07-28.md)
- [D5 supported Express migration](./D5-EXPRESS-4-MIGRATION-EVIDENCE-2026-07-28.md)
- [D6 historical six-image/SBOM result](./D6-IMAGE-SBOM-EVIDENCE-2026-07-28.md)
- [D7 bounded image remediation result](./D7-BOUNDED-IMAGE-REMEDIATION-EVIDENCE-2026-07-28.md)
- [D8 Nginx slim-image evidence](./D8-NGINX-SLIM-IMAGE-EVIDENCE-2026-07-28.json)
- [D9 alpha runtime-split evidence](./D9-ALPHA-RUNTIME-SPLIT-EVIDENCE-2026-07-28.json)
- [D10 offline dependency-remediation evidence](./D10-OFFLINE-DEPENDENCY-REMEDIATION-EVIDENCE-2026-07-28.md)
- [D11 server production-tree remediation evidence](./D11-SERVER-PRODUCTION-TREE-REMEDIATION-EVIDENCE-2026-07-28.md)
- [D12 local PostgreSQL query-builder evidence](./D12-LOCAL-QUERY-BUILDER-EVIDENCE-2026-07-28.md)
- [D13 six-route XID revalidation evidence](./D13-XID-ROUTE-REVALIDATION-EVIDENCE-2026-07-29.md)

The dedicated production server also has a mandatory
[startup admission contract](../../server/docs/FNCP_PRODUCTION_ADMISSION.md).
It requires exact dual enforcement, one matching conversation and two
independent credentials before the process opens its listening socket. Release
evidence and CI build the `fncp-production` Docker target, which defaults the
dedicated mode inside the image. Disposable staging now builds that same
guarded target. Its initial generated configuration uses two independent
credentials, exact dual enforcement and one matching high-entropy bootstrap
conversation ID that is not yet present in the disposable database. This lets
the dedicated process start while every participant request for that binding
fails closed. An ordinary upstream Pol.is deployment remains unchanged while
the dedicated release mode is absent.

Refresh the production package evidence without applying automatic fixes:

```sh
node --test deploy/fncp/audit-production-dependencies.test.mjs
node deploy/fncp/audit-production-dependencies.mjs
node deploy/fncp/audit-production-dependencies.mjs --component=alpha
```

The audit command contacts the configured npm registry and runs
`npm audit --omit=dev --json` against the selected lockfile. The default
component is `server`; reviewed values are `server`, `alpha`, `file-server`,
`admin`, `legacy-participant` and `report`. The last four remain useful for
auditing the upstream full file-server path, but that path is deliberately not
built or shipped by the minimal FNCP staging Compose model.

The command prints only the selected component, dependency package
names/ranges, expected numeric dependency counts, direct/transitive severity
counts and fix shapes; advisory text, registry responses and unknown metadata
are not reflected. Do not run it with a registry configuration that should not
receive the dependency manifest.

Exit `0` means the production gate passed, exit `1` means critical/high or
unreviewed no-fix production package findings remain, and exit `2` means the
audit could not be completed or its npm v2 report was malformed or internally
inconsistent. The command never changes the lockfile; remediation belongs in
separately reviewed upgrade branches.

## Production-shaped migration artifact

`server/Dockerfile-migrate` defines the fifth fork-owned release artifact: a
short-lived, non-root libpq client that runs the 19 reviewed top-level Pol.is
migrations and exits. It uses the same digest-pinned PostgreSQL 17 Alpine base
as disposable QA, but removes the PostgreSQL server and lifecycle utilities.
The image requires an exact 40-character `SOURCE_REVISION` build argument and
records OCI source, revision, base-name and base-digest labels.

The entrypoint accepts no arguments. At action time its task environment must
provide:

- `FNCP_DATABASE_HOST` as one exact DNS hostname;
- `FNCP_DATABASE_PORT` as an integer from 1 through 65535;
- `FNCP_DATABASE_PASSWORD` as a 32–128 character base64url secret;
- `PGSSLMODE=verify-full`;
- `PGSSLROOTCERT` as an absolute, readable CA-bundle path;
- `FNCP_EXPECTED_DATABASE`;
- `FNCP_EXPECTED_MIGRATION_ROLE`; and
- `FNCP_RUNTIME_DB_ROLE`.

The runner writes the validated secret to a mode-0600 `PGPASSFILE` on its
read-only task's `/tmp` tmpfs, removes the secret from the `psql` child
environment, never places it in process arguments, and deletes the file on
exit.

The runner keeps the connection secret out of argv and logs, disables psql
startup files, sets `ON_ERROR_STOP`, acquires one session advisory lock and
applies only sorted, regular top-level migration files. Each filename and
SHA-256 is recorded in the migration-role-owned
`fncp_deploy.schema_migrations` table. An already-recorded filename with a
different SHA fails closed. It also verifies from `pg_stat_ssl` that the live
session uses TLS and refuses a recovery/read-only target.

The runtime database role must already exist and be distinct from the
migration role. Before any migration is applied, the runner rejects a runtime
role that is elevated, a member of another role, an object/schema/database
owner or already able to create persistent objects. After migration it grants
only public-schema table DML, sequence use and function execution (including
matching default privileges), while verifying the database-owner bootstrap
left no database/schema creation, temporary-object creation, table DDL-like
privileges or access to `fncp_deploy`.

The migration role is also a pre-provisioned, dedicated role—not the RDS
master or database owner. It must be `LOGIN NOINHERIT NOSUPERUSER NOCREATEDB
NOCREATEROLE NOREPLICATION NOBYPASSRLS`, have no role memberships, and remain
distinct from the runtime role. Its effective database privileges must be
exactly those required for migration: `CONNECT` and `CREATE`, but not
`TEMPORARY`; it must also have `USAGE` and `CREATE` on the existing `public`
schema. A separate database-owner/bootstrap process must first revoke
`CONNECT`, `CREATE` and `TEMPORARY` from database `PUBLIC`, revoke `USAGE` and
`CREATE` on schema `public` from `PUBLIC`, grant `CONNECT` and database
`CREATE` plus schema `USAGE` and `CREATE` directly to the migration role, and
grant only database `CONNECT` plus public-schema `USAGE` directly to the
runtime role. The runner verifies those effective and catalog ACLs; it does
not need database- or public-schema-owner authority. The migration role then
owns the application objects it creates, while never owning the database
itself. These conditions are checked before the tracking schema or any
application migration is changed.

The `polis-migration` Compose entry is deliberately build-only: it has no
network, credentials or ports and is behind the
`release-assurance-build-only` profile. Disposable QA continues to initialize
the separate `postgres` service; neither that database image nor the OIDC
simulator is a release artifact. The real migration task belongs on the
private no-ingress production migration path and must complete successfully
before any long-running runtime task starts.

The exact migration image has a disposable TLS lifecycle harness:

```sh
sh deploy/fncp/boot-migration-image-smoke.sh <40-character-source-revision>
```

It requires the matching local-only `polis-migration` image tag. It creates
only synthetic roles and data on an internal Docker network, proves missing
bootstrap denial, concurrent first-run locking, all 19 checksum receipts,
checksum-drift denial, idempotent replay and runtime tracking denial, then
removes its containers, network, certificate volume and temporary files.

## Exact-image evidence

The local-only image evidence collector defaults to the five fork-owned Pol.is
ARM64 release artifacts: API server, math worker, participant alpha, nginx
proxy and the short-lived migration task. That earlier five-image scope assumed
managed RDS, but C1/C2/C3 remain unselected: it is not an owner-approved topology.
PostgreSQL is classified as infrastructure in that particular scan scope, not
excluded from the complete system's assurance obligations. New host-side access,
identity, activation and WordPress components are also outside those five images.
The disposable PostgreSQL and OIDC simulator images remain
available only through the explicit `staging-seven` QA scope. The collector
builds the math dependencies in the pinned Clojure image, but copies only the
reviewed runtime closure into the separately pinned Temurin 17 JRE image; the
Clojure CLI and JDK build image do not cross into production. The collector
records a whole non-ignored source
manifest, exact scope, build log and image IDs, asserts that generated
participant keys and reviewed direct-development package sentinels are absent,
then creates CycloneDX SBOMs and Grype JSON scans with digest-pinned scanner
containers. Its ARM64 candidate gate is calculated only from the five release
artifacts:

```sh
node --test deploy/fncp/image-security-evidence.test.mjs

./deploy/fncp/collect-image-security-evidence.sh \
  /absolute/new/no-overwrite/evidence-directory
```

Base and scanner image digests are reviewed in
[`image-security.lock.json`](./image-security.lock.json). The collector refuses
to overwrite evidence or label a dirty source tree as an exact candidate
unless a WIP run explicitly opts in. Default candidate evidence forces
`linux/arm64`, rejects architecture mismatches, performs a pull/no-cache build,
cannot skip the build, disables scanner update checks after one recorded Grype
database update, and retains a checksummed database cache snapshot. Use
`FNCP_SCAN_SCOPE=staging-seven` only when the two disposable QA-infrastructure
images also need inspection. The generated summary explicitly records that
this local evidence is not a release attestation: deployment architecture,
immutable registry digests and multi-architecture verification remain
unbound. The collector does not log in to a registry, push an image or invoke a
cloud CLI.

The Node production build stages deliberately perform cold `npm ci`
installations without persistent BuildKit npm-cache mounts. Their final images
cross only the pruned production closure. Every Alpine package added by the
server Dockerfile is pinned to its reviewed exact package release, and the CI
runtime check verifies the three final-stage packages by version. Development
may still use a local npm cache mount; that target is not a release artifact.

Pull requests into `edge` also run a synthetic-only runtime-image matrix. Each
matrix entry builds exactly one of the five fork-owned release artifacts on an
ephemeral GitHub runner and checks its configured and effective non-root user,
reviewed runtime files and—on the migration artifact—its immutable source/base
labels and exact entrypoint. That workflow has read-only repository
permission, does not log in to a registry, does not push an image and does not
deploy. It is a regression gate for the Dockerfiles, not an SBOM scan or
release attestation.

The 28 July WIP scan generated all six SBOMs and scans. Its historical aggregate
included the QA simulator and failed the then-combined policy with 57 Critical
and 296 High match observations. See the [D6
evidence](./D6-IMAGE-SBOM-EVIDENCE-2026-07-28.md) for exact local image IDs,
scanner/database evidence, interpretation limits and remediation order.
The subsequent bounded D7 pass rebuilt nginx, participant alpha and server,
reducing those three images from 35 Critical/209 High to 2 Critical/38 High;
the [D7 evidence](./D7-BOUNDED-IMAGE-REMEDIATION-EVIDENCE-2026-07-28.md)
preserves the exact before/after boundary and residual blockers.

## Safety boundaries

- The deployed source baseline is upstream commit
  `424dcae02f0147723a19103dd2d971f6ec1b6db5`.
- All published modifications remain in the public
  [Barayamal Pol.is fork](https://github.com/Barayamal/polis).
- PostgreSQL and all application containers use an internal Docker network.
- The disposable origin, API and OIDC simulator bind only to `127.0.0.1`.
- Analytics, translation, LLM/report processors and outbound email are empty or
  disabled.
- The configured FNCP conversation also has a server-side processing policy
  that skips optional external language detection, Pro moderation enrichment
  and statement-notification delivery. This prevents a future shared-server
  feature toggle from sending an FNCP statement, topic, IP-derived location or
  notification outside the reviewed participant path.
- Production mode does not initialize telemetry unless
  `ENABLE_TELEMETRY=true`; this disposable profile pins it to `false`.
- The local OIDC simulator and its fixture users are for disposable QA only.
- No hosted conversation or hosted conversation data is imported.
- WordPress registration and First Nations eligibility evidence remain outside
  Pol.is.

## Prepare and validate

From the repository root:

```sh
./deploy/fncp/prepare-staging.sh
./deploy/fncp/verify-staging.sh
```

The first command creates git-ignored local secrets, seven-day test
certificates and participant JWT keys. It also creates distinct gateway and
provider credentials plus one random, valid but absent bootstrap conversation
binding with both enforcement switches set to `true`. It refuses to overwrite
an existing staging environment and does not create a conversation.

The second command proves the Compose model is valid, sensitive integrations
are disabled, the live hosted conversation is absent and every published port
is loopback-only. Its static deployment contract also proves the selected path
contains only the alpha participant assets and five exact URL locations with
method guards covering the six permitted method-and-route capabilities. It
also locks all six server route chains to explicit, conversation-scoped XID
allowlist revalidation before their handlers:

```sh
node --test deploy/fncp/deployment-boundary.test.mjs
```

The full Pol.is file-server image is not part of this path, so its admin,
legacy-participant and report bundles are neither built nor copied into the
FNCP proxy. The alpha SSR service owns its own participant assets. This is a
staging attack-surface reduction, not a claim that the remaining images are
production-ready.

This loopback proxy is **not a functional public participant gateway**. It does
not redeem a Barayamal grant and does not supply an authority-backed,
per-request gateway assertion to Pol.is. It must not be exposed to the
internet. Its URL and method filters are defence-in-depth for disposable
synthetic QA only; the production gateway and authorization/recovery service
remain separate, mandatory work.

## Build and start

These are build/recreate instructions, **not routine resume for the preserved
13 September proof**. Use the current owner guide's no-build resume path for that
stack. Do not rebuild or replace retained proof containers merely to view status.

```sh
docker --context colima-fncp-c-20260913 compose \
  --env-file deploy/fncp/.env.staging \
  -f deploy/fncp/docker-compose.staging.yml \
  build

docker --context colima-fncp-c-20260913 compose \
  --env-file deploy/fncp/.env.staging \
  -f deploy/fncp/docker-compose.staging.yml \
  up -d
```

When the repository is cloned below macOS `/tmp`, Colima cannot bind-mount
the generated certificates from that path. Use the bounded local-only helper:

```sh
DOCKER_CONTEXT=colima-fncp-c-20260913 ./deploy/fncp/start-colima-staging.sh
```

The helper removes only this Compose project's disposable containers, resets
the two certificate bind mounts, rebuilds the exact local source with refreshed
pinned bases, checks that required certificate/key files are present and nonempty,
and creates stopped containers. It checks all four source-revision labels and the
server's dedicated release-mode **before copying any keys/certificates or starting
any service**. A mismatched label or failed inspection permits neither operation,
even if a failed inspection printed a plausible value. Labels are assertions, not
complete dirty-source or cryptographic image attestation. The keys are not added to a
built image. The helper does not touch Docker objects outside the
`fncp-polis-staging` project. It writes an ignored, non-secret
`.colima-staging` marker so the bootstrap and activation helpers reuse the same
override. Those helpers create each affected server container in a stopped
state, copy only the disposable CA/signing keys, and start it afterwards; they
never fall back to the unusable `/tmp` bind mounts.

Disposable endpoints:

- Pol.is origin: <http://localhost:8088/>
- API diagnostic binding: <http://localhost:5500/api/v3/>
- Local OIDC simulator: <https://localhost:3000/>

Run the disposable API access matrix after the stack is healthy:

```sh
./deploy/fncp/bootstrap-synthetic-conversation.sh
./deploy/fncp/activate-synthetic-binding.sh
./deploy/fncp/smoke-test.sh
```

The first helper is one-shot and bounded. It starts only the profile-gated
`server-bootstrap` on `127.0.0.1:5501`, authenticates only as the documented
local OIDC fixture administrator, creates exactly one synthetic conversation,
adds exactly one synthetic seed statement and enables its XID whitelist. It
then atomically replaces both conversation IDs in `.env.staging` with the
exact created ID without printing an ID or credential. The ordinary bootstrap
container is removed on exit. It does not restart a service, contact a public
origin, deploy or run the participant trace. The protected restart marker is
installed before the first mutating request, so an interrupted or uncertain
transition stays fail-closed and cannot create a second conversation on
retry. Do not remove that marker and replay bootstrap; inspect or purge the
entire disposable stack and prepare a fresh one.

When `.colima-staging` is present, the same helper verifies the marker, applies
`docker-compose.colima.yml`, creates the bootstrap container stopped, copies
the ignored disposable CA/signing keys and starts it. The activation helper
uses the identical create-copy-start boundary for the dedicated server. An
invalid marker fails closed.

The generated environment has changed at that point but the running dedicated
server and participant alpha still hold the absent bootstrap binding. The
protected restart marker therefore blocks the trace. The second helper:

- removes any leftover ordinary bootstrap container;
- force-recreates the dedicated server, participant alpha and proxy locally;
- proves the server and alpha container IDs changed;
- reads back the exact provider binding from the guarded server;
- verifies a direct participant request is denied with the exact hardened
  gateway-required `403` through the recreated proxy; and
- removes the restart marker only after all checks pass.

If activation fails, the marker remains and `smoke-test.sh` refuses to run.
`docker compose restart` is insufficient because it does not reload the
changed environment; use the activation helper.

The smoke script then uses the already-created configured conversation. It
adds and removes generated QA XIDs only through the private provider adapter,
verifies exact readbacks, and exercises allowed, missing, invalid,
OIDC-bypass, removed-XID and removed-established-identity paths. It verifies the
fifteen fixed synthetic statement IDs and negative suggestion, unknown-ID and
invalid-vote requests. It prints statuses
only and deletes its temporary token and response files on exit. Its Pol.is
API requests supply `X-Forwarded-Proto: https` because this loopback check
stands in for the reviewed TLS reverse-proxy boundary. A request without that
secure-proxy signal is rejected. It revokes only its own generated synthetic
identity and leaves the shared synthetic conversation lifecycle unchanged so
other local checks can still run. This trace does not test whole-round closure
or genuine browser-session assurance. Stop the local services and purge the
disposable database volume after all evidence is recorded.

The clean cold-start matrix observed on 28 July 2026 passed: the allowlisted
XID returned `200`; missing, invalid, OIDC-bypass, removed and warm-session
requests after removal each returned `403`; and the synthetic conversation was
closed. This is synthetic local QA only, not production authorization.

The 29 July source hardening makes that allowlist check explicit on each of the
six retained capabilities, including the previously implicit
`GET /api/v3/comments` and `GET /api/v3/math/pca2` reads. The guard selects an
authenticated XID JWT claim over a conflicting request parameter, rejects
missing and removed XIDs with a non-cacheable `403`, and leaves the participant
middleware check in place as a fallback. Focused unit and static route-contract
tests pass. The expanded disposable PostgreSQL integration matrix is authored
but still requires an exact retained-stack run before this change can support a
release decision; see D13.

Release review subsequently corrected the Express error-handler ordering so
the global error middleware follows every asynchronously installed route. The
corrected source passed build, lint and focused Express-stack regressions. Its
server image was then rebuilt and the cold-start matrix passed again. The
recorded D7 SBOM/scan still predates that correction, so regenerate and review
the exact-image evidence before merge.

The OIDC certificate is intentionally short-lived and privately generated. Do
not install its CA as a system-wide trust anchor. Use an isolated browser
profile for manual QA or pass
`--cacert deploy/fncp/certs/rootCA.pem` to command-line checks.

## Stop and preserve the current proof

From this prepared clone, stop only the dedicated local stack. Preserve its
containers, database volumes, source, private configuration and recovery evidence:

```sh
docker --context colima-fncp-c-20260913 compose \
  -f deploy/fncp/local-wordpress-runtime/compose.yml stop
docker --context colima-fncp-c-20260913 compose \
  --env-file deploy/fncp/.env.staging \
  -f deploy/fncp/docker-compose.staging.yml \
  stop
colima stop --profile fncp-c-20260913
```

Stop any separately started host-side proof processes using their own controlled
shutdown before stopping the VM. Do not assume container shutdown stops a host
Node process. Verify the relevant listeners are closed afterward.

There is **no routine purge step**. Reducing results to aggregate evidence does
not authorize deleting source stores, archives, keys, configuration or logs.
Any future cleanup needs a separate exact-target inventory and Dean's explicit
approval, including the effect on recovery. Historical registration retention is
a different workflow and supplies no deletion authority here. Never use a broad
volume-removal or repository-cleanup command to stop or repair this proof.

## Production is a separate decision

Do not expose this Compose stack to the internet. A production deployment
requires, at minimum:

1. an Australian-region private application network and encrypted PostgreSQL;
2. a managed TLS/WAF/load-balancer boundary with the Pol.is origin otherwise
   unreachable;
3. staff-only production OIDC;
4. the Barayamal gateway validating approval, consent, conversation, expiry and
   revocation on every protected request;
5. direct/native participant, report, export and admin-route denial at the
   public participant gateway;
6. the five-route fixed-statement participant manifest passing its exact
   DB-backed and browser trace suites: core reads and fixed-statement votes
   succeed, while participant statement suggestions/writes are denied;
   missing/removed identity, HEAD aliases and every unused route fail closed;
   staff routes retain normal authentication;
7. a reviewed, component-aware dependency remediation and image/SBOM scan,
   including the OS, nginx, PostgreSQL and JVM/Clojure surfaces;
8. backup/PITR, restore, deletion, load, monitoring and incident tests;
9. a reviewed participant notice matching the actual processors and retention;
10. a visible no-charge link to the exact Corresponding Source.

The local stack proves buildability and supports the negative access matrix. It
does not by itself prove those production controls.
