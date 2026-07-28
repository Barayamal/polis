# FNCP Option C D12 local PostgreSQL query builder — 28 July 2026

## Decision

This change is a **qualified GO for synthetic Option C staging**. It is not a
production release approval, an exact image attestation, a registry artifact
or a live participant deployment. The Option C production decision remains
**HOLD / NO-GO**.

The work removes the last High finding from the previously scanned server
production dependency path by replacing `sql@0.78.0` with a narrow,
PostgreSQL-only query builder owned in this repository. A fresh exact-image
SBOM and Grype scan is still required before the dependency finding can be
treated as closed at release level.

No genuine registration, identity, eligibility record, statement or vote was
used. All database, identity, conversation, XID and vote records were synthetic
and disposable.

## Source boundary

The local builder implements only the non-experimental FNCP server surface
observed in this source tree:

- table definitions, declared-column lookup and star selection;
- select, update and single-row insert;
- repeated where, and and or expressions;
- equality, inequality, greater-than and not-null expressions;
- IN and NOT IN, including empty lists, null values and subqueries;
- returning, column ordering, descending ordering, limit and offset; and
- parameterised `toQuery()` plus legacy-compatible inline `toString()`.

Unsupported `node-sql` behaviour must not be assumed to work. The separate
experimental report/client-report trees remain outside the minimal FNCP build.

Defense-in-depth restrictions added with the replacement:

- raw `ORDER BY` strings are limited to the two existing constants,
  `random()` and `is_seed desc, random()`;
- limit and offset require finite, safe, non-negative integers;
- write keys must match declared table columns; and
- empty `IN` and `NOT IN` expressions retain explicit fail-closed/succeed-empty
  semantics.

## Verification

The staging source passed:

- TypeScript production build;
- ESLint;
- 38 focused compatibility, dependency and rejection tests;
- 141 non-database unit tests across 18 suites;
- three isolated PostgreSQL 16 integration tests;
- production-tree checks proving `sql`, monolithic `lodash` and `sliced` are
  absent; and
- `git diff --check`.

The frozen compatibility fixtures cover 15 legacy query shapes and compare
both inline SQL and parameterised SQL/value output. The rejection fixtures
cover unapproved raw ordering, injection-shaped ordering text, negative,
fractional, non-finite, unsafe and non-numeric pagination values.

## Migrated-schema route matrix

A separately generated PostgreSQL 17 database loaded all **61** public Pol.is
tables from the pinned migration scripts. The built server then ran against
that database and a loopback-only synthetic JWKS issuer.

| Route action | Result |
|---|---:|
| Create synthetic conversation | 200 |
| Add synthetic seed statement | 200 |
| Create synthetic XID allowlist | 200 |
| Enable XID gate | 200 |
| Allowlisted participant init | 200 |
| Synthetic vote | 200 |
| Warm participant session | 200 |
| Missing XID | 403 |
| Invalid XID | 403 |
| OIDC participant bypass | 403 |
| Removed XID | 403 |
| Removed warm XID session | 403 |
| Close synthetic conversation | 200 |

The server, JWKS issuer and database were stopped afterwards. The disposable
database container, generated staging environment, certificates and signing
keys were deleted.

## Evidence limits

- Production routes still use legacy-compatible inline `toString()` in several
  places. Reviewed live write values are primitives, dates, nulls or ordinary
  arrays; the legacy array-of-object JSON representation is not currently
  reachable. Production should nevertheless migrate write paths to
  parameterised `toQuery()` or explicitly reject that value class.
- The route matrix is local synthetic evidence, not a browser, load,
  backup/restore, deletion, monitoring, multi-architecture or recovery result.
- A network-disabled server image build stopped at `apk add libpq-dev` because
  the pinned Alpine package indexes were not locally cached. No registry was
  contacted. A clean authorised build is still required.
- No fresh server image, CycloneDX SBOM or Grype report was produced, so the
  prior 11-observation server scan remains the latest exact scan.

## Planning delta only

Removing the sole High dependency path would change the mixed planning model
from 644 observations to **643**:

| Severity | Planning projection |
|---|---:|
| Critical | 2 |
| High | 29 |
| Medium | 463 |
| Low | 143 |
| Negligible | 6 |
| **Total** | **643** |

This is arithmetic across different source states and evidence types. It is
not a unified image scan, release attestation or exception approval.

## Remaining production gates

1. Perform an authorised clean pinned server build and fresh exact-image
   CycloneDX/Grype scan; confirm the server has zero Critical/High findings.
2. Migrate or constrain remaining inline query rendering, then repeat the
   migrated-schema route matrix.
3. Clear the alpha and math Critical/High findings from exact corrected images.
4. Complete the production gateway/authorisation adapter, native-route denial
   and immediate revocation tests.
5. Complete backup/restore, deletion, monitoring, load, rollback,
   multi-architecture, real-browser and independent acceptance gates.
6. Obtain the named Australian cloud, DNS, OIDC, billing, incident and recovery
   decisions before creating any internet-reachable infrastructure.
