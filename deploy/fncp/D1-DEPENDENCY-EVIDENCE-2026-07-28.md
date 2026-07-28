# FNCP Option C D1 dependency evidence — 28 July 2026

## Scope

This bounded pass starts from public fork commit `9677036` and changes only
packages that are unused, test/development-only, or have a compatible
non-major fix. It does not attempt the Express/body-parser/compression/timeout
migration and does not use `npm audit fix` or `npm audit fix --force`.

Both audit snapshots were produced by the repository's reviewed
`audit-production-dependencies.mjs` wrapper against the public npm registry
using `npm audit --omit=dev --json`.

## Production audit change

| Server audit field | Before | After | Change |
|---|---:|---:|---:|
| Production packages | 1,172 | 1,115 | -57 |
| Total package findings | 103 | 94 | -9 |
| Critical | 11 | 9 | -2 |
| High | 32 | 27 | -5 |
| Moderate | 50 | 48 | -2 |
| Low | 10 | 10 | 0 |
| Direct critical | 4 | 2 | -2 |
| Direct high | 7 | 3 | -4 |

The production gate still fails. Remaining direct critical/high packages are
`express`, `request`, `body-parser`, `compression` and `connect-timeout`.

## Reachability and treatment

| Package | Minimal FNCP runtime finding | Treatment |
|---|---|---|
| `axios` | Used only by the OIDC integration-test helper | Moved to exact dev dependency `1.18.1` |
| `dd-trace` | Production entry point can load it only after the explicit telemetry opt-in; FNCP staging pins telemetry off | Compatible exact upgrade `5.65.0` → `5.118.0` |
| `underscore` | Used throughout participation, votes, comments, XID and next-comment paths | Compatible exact upgrade `1.13.7` → `1.13.8` |
| `nodemailer` | No production source import; current email sender uses AWS SES v2 directly | Removed with unused Mailgun transport and their unused type packages |
| `optimist` | No source import | Removed |
| `morgan` | Development logger only, but the static import previously loaded it in production | Moved to exact dev dependency `1.11.0` and required only inside the development branch |
| `request` / `request-promise` | Still imported by the legacy static-file fetcher and optional moderation module | Retained; removal requires a separately reviewed runtime migration |

For the configured FNCP conversation, the server-side participant policy added
in the preceding hardening change prevents the optional moderation, IP
enrichment, language detection and notification/email paths from running.
That control does not make the deprecated request packages acceptable for
production; the static-file and moderation callers still need replacement.

## Lockfile

- Server lockfile SHA-256 after this pass:
  `9f6fc258472d98de313d23ef20a9e04ca5f9da817ab23949c9fe6519e767a8a4`
- No automatic audit fix was applied.
- No major-version HTTP-stack migration was attempted.

## Decision

This is a measurable reduction, not a production acceptance. Option C remains
synthetic-only until the remaining direct critical/high packages, reachable
transitive findings, exact images, SBOM/container scans and the wider
production-readiness gates are cleared.
