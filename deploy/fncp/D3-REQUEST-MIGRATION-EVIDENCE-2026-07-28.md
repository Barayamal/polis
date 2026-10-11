# FNCP Option C D3 request-client migration evidence — 28 July 2026

## Scope

This bounded pass starts from public fork commit `984e4c4` and removes the
deprecated `request`, `request-promise` and `simple-oauth2` packages from the
minimal Pol.is API-server tree. It does not change participant routes, access
semantics or the production no-go decision.

## Runtime migration

- The static-file fetcher now uses the Node-native Fetch API and preserves
  redirects, streaming, preload replacement, social metadata replacement and
  the existing non-success response-body behaviour.
- The optional moderation region lookup now uses the Node-native Fetch API,
  URL-encodes its input, validates the HTTP response and applies a five-second
  timeout with the existing fail-soft fallback.
- `request`, `request-promise`, `simple-oauth2` and
  `@types/request-promise` are absent from the API-server dependency tree.
- The separate `client-report` lockfile still has its own upstream request
  dependency. That bundle is excluded from the minimal FNCP path and remains in
  the six-tree inventory until separately remediated.

## Production audit change

| Server audit field | Before | After | Change |
|---|---:|---:|---:|
| Production packages | 1,115 | 1,075 | -40 |
| Total package findings | 94 | 89 | -5 |
| Critical | 9 | 8 | -1 |
| High | 27 | 27 | 0 |
| Moderate | 48 | 44 | -4 |
| Low | 10 | 10 | 0 |
| Direct critical | 2 | 1 | -1 |
| Direct high | 3 | 3 | 0 |

At this checkpoint the remaining direct critical/high packages were
`express`, `body-parser`, `compression` and `connect-timeout`. The subsequent
[D4 middleware cleanup](./D4-MIDDLEWARE-CLEANUP-EVIDENCE-2026-07-28.md)
removed the three unused direct middleware declarations; the production gate
still fails on Express and its transitive tree.

## Verification

- deterministic clean `npm ci`: pass;
- TypeScript build: pass;
- lint: pass;
- server unit tests: 94/94 pass;
- focused new and updated tests: 8/8 pass;
- audit-wrapper tests: 6/6 pass; and
- `npm ls request request-promise request-promise-native simple-oauth2 --all`:
  empty.

Server lockfile SHA-256:
`fac5554697db1868f78fe3f584294cb248a013c3af497c86ea0a8ca649d2527e`.

The verification used synthetic data only. The disposable PostgreSQL
container, database and synthetic JWT keys were removed after the suite. Local
validation used Node `25.9.0`; the manifest targets Node 22, so an exact Node 22
candidate-image run remains mandatory.

## Decision

This removes one deprecated critical direct dependency family and reduces the
minimal API-server inventory, but does not clear Option C for deployment. The
remaining HTTP/middleware migration, whole-image SBOM/scans, authority-to-
gateway integration and all operating gates remain required.
