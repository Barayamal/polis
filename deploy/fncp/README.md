# First Nations Community Pulse — Option C staging

Status: **synthetic-data staging only**

This directory packages a pinned, loopback-only Pol.is origin for testing the
Barayamal First Nations Community Pulse access boundary. It is not a production
deployment and it must never receive a genuine registration, eligibility
record, invitation, vote or statement.

Latest recorded evidence:
[26 July 2026 disposable staging results](./STAGING-EVIDENCE-2026-07-26.md).

Refresh the production package evidence without applying automatic fixes:

```sh
node --test deploy/fncp/audit-production-dependencies.test.mjs
node deploy/fncp/audit-production-dependencies.mjs
node deploy/fncp/audit-production-dependencies.mjs --component=alpha
```

The audit command contacts the configured npm registry and runs
`npm audit --omit=dev --json` against the selected lockfile. The default
component is `server`; reviewed values are `server`, `alpha`, `file-server`,
`admin`, `legacy-participant` and `report`. Run each component separately
because the current file-server image builds multiple independently locked
clients and their counts cannot be safely deduplicated by adding them.

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

## Safety boundaries

- The deployed source baseline is upstream commit
  `424dcae02f0147723a19103dd2d971f6ec1b6db5`.
- All published modifications remain in the public
  [Barayamal Pol.is fork](https://github.com/Barayamal/polis).
- PostgreSQL and all application containers use an internal Docker network.
- The disposable origin, API and OIDC simulator bind only to `127.0.0.1`.
- Analytics, translation, LLM/report processors and outbound email are empty or
  disabled.
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
is loopback-only.

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
the two certificate bind mounts, copies the generated test certificates into
the newly created containers and starts the same loopback-only stack. It does
not touch Docker objects outside the `fncp-polis-staging` project.

Disposable endpoints:

- Pol.is origin: <http://localhost:8088/>
- API diagnostic binding: <http://localhost:5500/api/v3/>
- Local OIDC simulator: <https://localhost:3000/>

Run the disposable API access matrix after the stack is healthy:

```sh
./deploy/fncp/smoke-test.sh
```

It creates and closes one synthetic local conversation, exercises allowed,
missing, invalid, OIDC-bypass and removed-XID paths, prints statuses only and
deletes its temporary token and response files on exit. Purge the disposable
database volume after evidence is recorded.

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
