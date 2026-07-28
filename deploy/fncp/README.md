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
- [D6 exact-image/SBOM production-gate result](./D6-IMAGE-SBOM-EVIDENCE-2026-07-28.md)
- [D7 bounded image remediation result](./D7-BOUNDED-IMAGE-REMEDIATION-EVIDENCE-2026-07-28.md)
- [D8 Nginx slim-image evidence](./D8-NGINX-SLIM-IMAGE-EVIDENCE-2026-07-28.json)
- [D9 alpha runtime-split evidence](./D9-ALPHA-RUNTIME-SPLIT-EVIDENCE-2026-07-28.json)
- [D10 offline dependency-remediation evidence](./D10-OFFLINE-DEPENDENCY-REMEDIATION-EVIDENCE-2026-07-28.md)
- [D11 server production-tree remediation evidence](./D11-SERVER-PRODUCTION-TREE-REMEDIATION-EVIDENCE-2026-07-28.md)

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

## Exact-image evidence

The local-only image evidence collector builds the six-image minimal staging
model, records a whole non-ignored source manifest and image IDs, asserts that
generated participant keys and reviewed direct-development package sentinels
are absent, then creates CycloneDX SBOMs and Grype JSON scans with
digest-pinned scanner containers:

```sh
node --test deploy/fncp/image-security-evidence.test.mjs

./deploy/fncp/collect-image-security-evidence.sh \
  /absolute/new/no-overwrite/evidence-directory
```

Base and scanner image digests are reviewed in
[`image-security.lock.json`](./image-security.lock.json). The collector refuses
to overwrite evidence or label a dirty source tree as an exact candidate
unless a WIP run explicitly opts in. It does not log in to a registry, push an
image or invoke a cloud CLI.

The 28 July WIP scan generated all six SBOMs and scans but failed the
production policy with 57 Critical and 296 High match observations. See the
[D6 evidence](./D6-IMAGE-SBOM-EVIDENCE-2026-07-28.md) for exact local image
IDs, scanner/database evidence, interpretation limits and remediation order.
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
method guards covering the six permitted method-and-route capabilities:

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
