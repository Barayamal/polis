# FNCP Option C D4 middleware cleanup evidence — 28 July 2026

Historical checkpoint: superseded for current-candidate status by
[D5 supported Express migration](./D5-EXPRESS-4-MIGRATION-EVIDENCE-2026-07-28.md).

## Scope

This bounded pass starts from public fork commit `cfd923d` and removes three
unused direct middleware packages from the minimal Pol.is API-server tree:
`body-parser`, `compression` and `connect-timeout`. It does not upgrade the
legacy Express/Connect stack or change the production no-go decision.

The application was already using the body parser and compression middleware
bundled by its pinned Express/Connect runtime. The direct `body-parser` and
`compression` packages had no source imports. The one direct
`connect-timeout` call on `GET /api/v3/nextComment` is replaced by a focused
native timer that preserves the established 15-second timeout, request
`timedout`/`clearTimeout` behavior and `408` JSON response through the existing
global error handler.

## Production audit change

| Server audit field | Before | After | Change |
|---|---:|---:|---:|
| Production packages | 1,075 | 1,054 | -21 |
| Total package findings | 89 | 89 | 0 |
| Critical | 8 | 8 | 0 |
| High | 27 | 27 | 0 |
| Moderate | 44 | 44 | 0 |
| Low | 10 | 10 | 0 |
| Direct critical | 1 | 1 | 0 |
| Direct high | 3 | 0 | -3 |

The only remaining direct critical/high server finding is the pinned legacy
`express` package. Its bundled Connect dependency still carries vulnerable
transitive middleware versions, so removing duplicate direct declarations does
not change the total finding count. Express/Connect replacement remains a
separate, high-risk compatibility migration.

## Verification

- TypeScript build: pass;
- lint: pass;
- native timeout and middleware dependency-contract tests: 11/11 pass;
- native timeout behavior tests: 6/6 pass;
- production audit inventory: 89 findings with zero direct high findings; and
- no direct `body-parser`, `compression`, `connect-timeout` or
  `@types/connect-timeout` declaration remains.

The wider unit command was also attempted without the exact-stack database and
synthetic JWT fixtures. It produced the known environment-only application/JWT
failures while 89 tests passed. This is not recorded as a whole-suite pass;
the exact candidate-image run remains mandatory.

Server lockfile SHA-256:
`757e6c2b5915eaaef7eabf36490b40862eabf688027d7efa9823d2d8da0e1598`.

## Decision

The change removes three unnecessary direct risk owners and preserves the
reviewed timeout behavior, but it does not make the server production-ready.
The Express/Connect migration, transitive reachability review, exact-image
SBOM/scans and all runtime/operational gates remain open.
