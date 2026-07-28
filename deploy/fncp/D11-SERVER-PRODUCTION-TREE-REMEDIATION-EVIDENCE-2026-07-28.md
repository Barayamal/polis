# FNCP Option C D11 server production-tree remediation — 28 July 2026

## Decision

Source commit `4931c67690b263926e43466553d304da3f0b91d0` is a reviewed
**FNCP-only synthetic-staging improvement**. It is not an exact container-image
attestation, registry artifact, release approval or production deployment.
The Option C production decision remains **HOLD / NO-GO**.

No network, cloud resource, internet-reachable service, conversation or
participant data was used or changed.

## Scope

The five-image FNCP runtime does not build or ship the upstream
`client-report` or `report_bundle` applications. Within that deliberately
reduced boundary, the commit:

- removes the unused experimental `/api/v3/reportNarrative` server route;
- excludes its experimental narrative, report and prompt source trees from the
  FNCP server TypeScript build;
- removes the report-only `@tevko/sensemaking-tools` and `xmlbuilder2`
  production dependency roots; and
- scopes `sql@0.78.0` to reviewed Lodash `4.17.23`.

This intentionally breaks the separate report client's
`/api/v3/reportNarrative` integration if that excluded client is later added.
Restoring full upstream report-client compatibility requires a separate
dependency, build, test and security review. It is not silently covered by this
FNCP staging result.

## Verification

The reviewed candidate passed:

- a strict-offline clean dependency install;
- TypeScript build and lint;
- 19 focused server regressions;
- 42 broader FNCP gateway, participant-policy, comment-egress and middleware
  regressions;
- a clean compiled-output boundary;
- production dependency pruning;
- a parameterised PostgreSQL query-builder smoke check;
- diff and exact-file hash checks; and
- independent source review of the FNCP/report-client boundary.

The final source adds only a non-executable boundary comment after those checks.
The dependency-relevant manifest and lockfile are unchanged from the scanned
candidate.

## Production-tree scan

Using Syft 1.49.0, Grype 0.116.0 and Grype DB schema `v6.1.9` built
`2026-07-27T07:24:06Z`, the pruned **production dependency tree** reported:

| Severity | Observations |
|---|---:|
| Critical | 0 |
| High | 1 |
| Medium | 6 |
| Low | 4 |
| **Total** | **11** |

The sole High is `lodash@4.17.23`, `GHSA-r5fr-rjxr-66jc`.
`sql@0.78.0` does not call the affected `_.template` API, but that reachability
observation does not clear the zero-High release gate. Grype identifies Lodash
4.18.0 as the fix while npm labels that release a bad release, so it was
deliberately rejected.

The local evidence bundle checksum-manifest SHA-256 is
`b40cd12b35d61f753f55687a35f092bfbf7f1f5d252215255d29626a20f333a2`.
The bundle is local evidence, not a release artifact.

## Planning projection only

Substituting this server production-tree result, the exact Nginx component
result, the modelled alpha result and the reviewed math feasibility result into
the historical five-image baseline gives:

| Severity | Planning projection |
|---|---:|
| Critical | 1 |
| High | 30 |
| Medium | 463 |
| Low | 143 |
| Negligible | 6 |
| **Total** | **643** |

This combines different source states and evidence types. It is not a unified
build, current image scan, registry record, release attestation or exception
approval.

## Remaining release gates

1. Replace or locally fork `sql` so the server has zero Critical/High findings,
   or obtain a separately reviewed exception.
2. Perform one authorised, clean, network-enabled rebuild of every pinned
   production-relevant image and generate fresh exact-image SBOMs and scans.
3. Clear the remaining alpha and math Critical/High findings without accepting
   unreviewed or bad package releases.
4. Re-run functional, browser, recovery, deletion, monitoring, load,
   multi-architecture and independent acceptance gates from the same source
   state.
