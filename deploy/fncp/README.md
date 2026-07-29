# First Nations Community Pulse — Option C staging

Status: **synthetic-data staging only**

This directory packages a pinned, loopback-only Pol.is origin for testing the
Barayamal First Nations Community Pulse access boundary. It is not a production
deployment and it must never receive a genuine registration, eligibility
record, invitation, vote or statement.

Latest recorded evidence:

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
dedicated mode inside the image. Disposable staging explicitly builds `prod`,
and an ordinary upstream Pol.is deployment remains unchanged while the
dedicated release mode is absent.

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
proxy and the short-lived migration task. The planned production topology uses
managed RDS, so PostgreSQL is infrastructure rather than an application
release image. The disposable PostgreSQL and OIDC simulator images remain
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
- The current hosted conversation `4bumwmv4zf` and its data are not imported.
- WordPress registration and First Nations eligibility evidence remain outside
  Pol.is.

## Prepare and validate

From the repository root:

```sh
./deploy/fncp/prepare-staging.sh
./deploy/fncp/verify-staging.sh
```

The first command creates git-ignored local secrets, seven-day test
certificates and participant JWT keys. It refuses to overwrite an existing
staging environment.

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

```sh
docker compose \
  --env-file deploy/fncp/.env.staging \
  -f deploy/fncp/docker-compose.staging.yml \
  build

docker compose \
  --env-file deploy/fncp/.env.staging \
  -f deploy/fncp/docker-compose.staging.yml \
  up -d
```

When the repository is cloned below macOS `/tmp`, Colima cannot bind-mount
the generated certificates from that path. Use the bounded local-only helper:

```sh
./deploy/fncp/start-colima-staging.sh
```

The helper removes only this Compose project's disposable containers, resets
the two certificate bind mounts, validates the generated participant
`jwt-private.pem` and `jwt-public.pem`, and copies the disposable certificates
and keys into the newly created containers before starting the same
loopback-only stack. The keys are not added to a built image. The helper does
not touch Docker objects outside the `fncp-polis-staging` project.

Disposable endpoints:

- Pol.is origin: <http://localhost:8088/>
- API diagnostic binding: <http://localhost:5500/api/v3/>
- Local OIDC simulator: <https://localhost:3000/>

Run the disposable API access matrix after the stack is healthy:

```sh
./deploy/fncp/smoke-test.sh
```

It waits for API readiness for at most 45 seconds, creates and closes one
synthetic local conversation, exercises allowed, missing, invalid, OIDC-bypass,
removed-XID and removed-warm-session paths, prints statuses only and deletes
its temporary token and response files on exit. Its Pol.is API requests supply
`X-Forwarded-Proto: https` because this loopback check stands in for the
reviewed TLS reverse-proxy boundary. A request without that secure-proxy signal
is rejected. Purge the disposable database volume after evidence is recorded.

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

## Stop and purge

Stop without deleting the disposable database:

```sh
docker compose \
  --env-file deploy/fncp/.env.staging \
  -f deploy/fncp/docker-compose.staging.yml \
  down
```

After evidence has been reduced to non-identifying aggregate results, remove
the disposable database volume:

```sh
docker compose \
  --env-file deploy/fncp/.env.staging \
  -f deploy/fncp/docker-compose.staging.yml \
  down --volumes
```

Then delete the ignored `.env.staging`, `certs/` and any raw QA logs.

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
6. the six-route FNCP participant manifest passing its exact DB-backed and
   browser trace suites: core reads, vote and statement writes succeed;
   missing/removed identity, HEAD aliases and every unused route fail closed;
   staff routes retain normal authentication;
7. a reviewed, component-aware dependency remediation and image/SBOM scan,
   including the OS, nginx, PostgreSQL and JVM/Clojure surfaces;
8. backup/PITR, restore, deletion, load, monitoring and incident tests;
9. a reviewed participant notice matching the actual processors and retention;
10. a visible no-charge link to the exact Corresponding Source.

The local stack proves buildability and supports the negative access matrix. It
does not by itself prove those production controls.
