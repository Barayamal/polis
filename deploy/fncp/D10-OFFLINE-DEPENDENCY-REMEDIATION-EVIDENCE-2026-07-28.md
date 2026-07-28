# FNCP Option C D10 offline dependency remediation — 28 July 2026

## Decision

The participant-alpha dependency cleanup and math-worker runtime hardening are
published synthetic-staging source improvements. They are **not** a same-source
image attestation and do not change the Option C production decision:
**HOLD / NO-GO**.

No registry image, cloud resource, internet-reachable service, conversation or
participant data was created or changed.

## Participant alpha

Source commit
`ccb1e4e746c85dfb93a35f71a00a90c65af325fd` removes six unused Visx
dependencies and the dead Lodash override. Repository-wide import review found
that only `@visx/group` and `@visx/scale` are used.

Offline verification passed:

- lint;
- 124 Jest tests;
- 4 source-boundary tests;
- production build;
- 3 built-output boundary tests;
- runtime boot and package-boundary checks; and
- 22 deployment and image-evidence contracts at that source stage.

The isolated runtime SBOM fell from 921 to 869 components and contained no
Lodash package. Applying that exact package removal to the D9 match set gives a
**modelled**, not rescanned, alpha result of:

- 0 Critical;
- 2 High;
- 9 Medium;
- 4 Low; and
- 15 observations total.

The two remaining High observations are in Astro 5.18.2. The minimum reviewed
upgrade candidate is Astro 6.4.6 with `@astrojs/node` 10.0.5, but those
artifacts were not present in the offline cache. No package-registry request
was made and no unreviewed framework upgrade was accepted.

## Math worker

Source commit
`e25b453b56b52457be7f98493ad990474d36c17d`:

- copies only the resolved runtime JAR closure into a multi-stage final image;
- preserves the exact `clojure -Spath` order in `/app/classpath`;
- fails the build unless the duplicated
  `clojure.core.matrix.random.RandomSeq` class resolves from the reviewed
  `core.matrix-0.63.0.jar`;
- runs directly on Java as numeric non-root user `65532:65532`;
- removes the Clojure CLI and Maven cache from the final runtime;
- keeps the four-hour timeout and restart boundary;
- moves unused Ring/Jetty tooling to the development alias;
- removes dead Korma/c3p0, Semantic CSV, Tentacles and Commons Collections
  production paths;
- restores Tentacles to the development alias only; and
- replaces the sole used Semantic CSV vectorisation operation with a focused,
  tested local helper.

Verification passed:

- 23 Node deployment/image-boundary checks;
- 56 selected repository math tests with 158 assertions and no failures or
  errors;
- the new vectorisation regression tests;
- shell syntax and diff checks; and
- independent source review after the deterministic-classpath and development
  alias corrections.

The reviewed offline feasibility image reported 1 Critical, 9 High, 424
Medium, 133 Low and 6 Negligible observations (573 total), compared with the
exact baseline math image at 4 Critical, 23 High and 599 total observations.
That feasibility image predates the final deterministic-classpath Dockerfile
correction and is therefore **not an attestation of the published source**.

An exact rebuild of the corrected Dockerfile was attempted once with networking
disabled and stopped before producing an image because the clean builder did
not contain the cached Cognitect AWS descriptor. It was not retried with
network access.

Before any deployment, the committed Dockerfile must be rebuilt and rescanned
from a clean source tree, and the worker must pass a disposable
PostgreSQL-connected start, poll, write and stop lifecycle test.

## Planning projection only

Substituting the exact Nginx component result, the modelled alpha result and
the reviewed math feasibility result into the historical five-image baseline
produces:

| Severity | Planning projection |
|---|---:|
| Critical | 3 |
| High | 41 |
| Medium | 481 |
| Low | 146 |
| Negligible | 6 |
| **Total** | **677** |

This combines different source and evidence states. It is useful only for
remediation planning. It is not a unified build, current image scan, registry
record, release attestation or exception approval.

## Remaining release gates

1. Run a reviewed network-enabled Astro 6 / Node adapter 10 compatibility
   spike, then repeat every alpha application, proxy, runtime and image check.
2. Upgrade the math PostgreSQL JDBC driver to at least 42.7.11 and address
   Commons IO, Jackson, Logback, LZ4 and the Cognitect/Jetty HTTP path.
3. Build and scan all five production-relevant fork images from one clean
   source state.
4. Combine those five images with the separately reviewed gateway and access
   authority, producing one seven-image source/SBOM/digest attestation.
5. Complete the disposable database lifecycle, browser, recovery, deletion,
   monitoring, load, multi-architecture and independent acceptance gates.
