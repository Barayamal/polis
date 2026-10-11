# Option C dependency review — 13 September 2026

Initial security pass recorded at 2026-09-13T11:57:21+10:00; earlier bounded maintenance pass at 2026-09-13T12:09:08+10:00; **CSV/Nodemon follow-up completed at 2026-09-13T12:27:10+10:00** (Australia/Sydney). Local implementation based on fork commit `2898471efe889976670b09977ca6c08946dc04d9`, with uncommitted security and integration changes. **Local synthetic QA only; no release approval or claim that all dependencies are safe.**

## Latest outcome — CSV and development notifier findings repaired

The separately reviewed major-line migrations are now implemented and tested: **server and alpha production/full-tree npm audits all report zero package findings**. The earlier CSV moderate and three propagated development high package findings below are historical, not the current status. No `npm audit fix --force`, blanket semver override or relaxed audit threshold was used.

| Dependency | Previous → current | Final lock path / reason |
|---|---|---|
| csv-parse | 5.6.0 → **7.0.2**, direct exact pin | `server/node_modules/csv-parse`; fixes the column/prototype advisory |
| nodemon | 2.0.22 → **3.1.14**, direct exact dev pin | `server/node_modules/nodemon`; keeps the existing developer watcher |
| simple-update-notifier | 1.1.0 → **2.0.0**, parent-selected | `server/node_modules/simple-update-notifier`; now declares semver `^7.5.3` |
| notifier's semver | 7.0.0 → **7.8.5**, within new parent range | `server/node_modules/simple-update-notifier/node_modules/semver` |
| Nodemon's minimatch | 3.1.4 line → **10.2.6**, parent-selected | `server/node_modules/nodemon/node_modules/minimatch`; Node 22 is supported |

Nodemon's own semver resolves to 7.8.5. Its minimatch 10 parent selects brace-expansion 5.0.9 and balanced-match 4.0.4. These are deliberate parent-selected transitive major-line migrations, not claims that their old ranges were compatible. Eight unrelated optional OXC `libc` fields removed by npm 10 lock regeneration were restored unchanged.

### Source and migration review

- Reviewed all five CSV consumers: bulk comments, vote-import worker, narrative report conversion, experimental Sonnet conversion and experimental topic extraction. They now call the small pure `server/src/utils/csv-records.ts` helper, so tests exercise the same options used by those callers rather than a separate mock parser.
- Sync consumers retain `columns: true` and `skip_empty_lines: true`; records remain string-valued, including leading-zero IDs. The worker retains strict column count plus trimming; topics retains its existing relaxed column count. No numeric/date casting, automatic delimiter discovery or grouped columns was enabled.
- The official [CSV changelog](https://github.com/adaltas/node-csv/blob/csv-parse%407.0.2/packages/csv-parse/CHANGELOG.md) describes stricter TypeScript types and stream close behavior across the intervening releases, and notes that 7.0.0 was accidentally published as a major. Version 7.0.2 specifically fixes [prototype replacement through columns](https://github.com/advisories/GHSA-8cw4-87c7-c6xx). The helper uses the new typed sync overload; no broad `any` workaround was introduced.
- The library's newer trimming follows ECMAScript whitespace. The worker now trims unquoted non-breaking spaces as well as ordinary spaces; quoted whitespace stays intact. This is an explicitly tested normalization change, not byte-for-byte compatibility for every possible CSV input. Sync comment/report text does not enable trimming.
- [Nodemon 3.0 migration notes](https://github.com/remy/nodemon/releases/tag/v3.0.0) identify Node 8 support removal and the semver fix. Our exact Node 22 runtime is unaffected by the support-floor change. [Nodemon 3.1.14](https://github.com/remy/nodemon/releases/tag/v3.1.14) and its installed source preserve the existing CLI usage. The debug/build-watch scripts remain unchanged. Their debugger arguments were parsed without opening a debugger; the runtime watcher smoke uses no inspector or external listener and disables update notifications.

### Follow-up verification actually completed

Clean Linux ARM64 verification used pinned Node 22.23.1 / npm 10.9.8 with anonymous `node_modules` and `dist` volumes. No real CSV, database, email, AI service, public route or participant identity was used.

| Check | Result |
|---|---|
| `npm ci --ignore-scripts --no-audit --fund=false`, then `npm run build` in server | **Clean install and TypeScript compilation passed** |
| Jest with `jest.fncp.config.ts`: `csv-records-compat`, `http-middleware`, `fncp-gateway`, `postgres-query-builder-compat` | **107/107 passed across 4 suites**; 12 CSV-specific cases, 95 existing cases |
| CSV shared helper tests | Quoting, CRLF record endings and embedded newlines, UTF-8 chunk boundary, leading-zero strings, report/group column names, empty input, duplicate headers, strict/relaxed widths, malformed records, 1001-row pause/resume, end/close sequence and sync/stream prototype regression passed |
| `node --test deploy/fncp/nodemon-migration-smoke.mjs` after server build, from server working directory | **2/2 passed**: CLI debugger argument preservation and actual synthetic watcher start/reload/environment/shutdown |
| ESLint on new CSV helper and CSV test | Passed |
| `node --test deploy/fncp/dependency-patch-boundary.test.mjs` | **6/6 passed** |
| Server `npm audit --json` and existing production audit summary | **Both zero findings; production gate passed** |
| Fresh read-only alpha full-tree audit and existing production audit summary | **Both zero findings; production gate passed**; no alpha install, lock regeneration or rebuild in this follow-up |
| `git diff --check` | Passed |

The first watcher smoke attempts exposed test-harness assumptions (missing compiled file, then the wrong parsed-argument property); those assertions were corrected from Nodemon's actual source and the full clean sequence was repeated. Both actual watcher start/reload attempts already passed. No application failure was hidden or skipped.

These tests cover parser compatibility and the local watcher, not the full CSV-to-database import workflow, external storage/notification side effects, generated report correctness, AI functionality, all platforms, all package vulnerabilities or image/OS scanning. Experimental report files remain outside the ordinary TypeScript build, as before; their shared parser is tested but their external pipelines were not executed. Existing development-tool deprecation warnings remain. Audit-zero is a time-bound package-advisory result, not production acceptance.

### Current server freeze fingerprints

The main task must rebuild server images from this freeze before citing runtime results; an older image does not contain these repairs.

```text
78e48bc7834e90b1f36f8638e6a409b9a7ac2fe516e14cd9fbebc47aefafe9e0  server/package.json
48938b64010dc895ac5999b4bb0b44af9d9e2c592edf982cee3505a4148b27be  server/package-lock.json
d377538d7cabb3d567432129a938f1a0403a0413c3b8aafa05b57df9ef8aaec2  server/src/utils/csv-records.ts
9366914ad79f9f92bdbedaaff88e7fd97a053cfa6d2e68a4c30cdf42f79a6ad2  server/__tests__/unit/csv-records-compat.test.ts
74e6c26993629d218b29944ad2c2a386369cb931d6980732ff3b37948f18421e  deploy/fncp/nodemon-migration-smoke.mjs
```

Alpha manifests were not changed during this follow-up. The history below is retained to make the previous unresolved findings and earlier tests inspectable; its “final” labels refer to that previous pass only.

## Historical outcome and audit scope — 12:09 pass

Both existing production-package gates pass. Server production now has **one moderate finding (CSV parser)** and no critical/high findings. Server full-tree has three high package findings from one development-only notifier/semver advisory, plus the CSV moderate. Alpha production and full-tree audits both report **zero findings**.

Counts below are npm audit **package findings**, not unique CVEs, exploitation findings, affected people, or image-level findings. A package may have several advisories or installed copies. Do not subtract production counts from full-tree counts to calculate development counts: package grouping can overlap.

| Component / scope | Before: critical / high / moderate / low | After initial pass | After final pass | Final total |
|---|---|---|---|---:|
| Server, production (`--omit=dev`) | 0 / 2 / 4 / 0 | 0 / 0 / 4 / 0 | 0 / 0 / 1 / 0 | 1 |
| Server, full tree | 0 / 9 / 6 / 2 | 0 / 9 / 6 / 2 | 0 / 3 / 1 / 0 | 4 |
| Alpha, production (`--omit=dev`) | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 | 0 |
| Alpha, full tree | 2 / 14 / 2 / 2 | 1 / 5 / 2 / 2 | 0 / 0 / 0 / 0 | 0 |

All information-severity counts were zero. Final production audits reported no no-automatic-fix findings. The existing gate requires no high/critical production findings and no unreviewed no-fix findings; **a gate pass is not a clean vulnerability audit**. The initial server full-tree high count stayed nine because vulnerable development copies still caused package names to appear after their production copies were repaired; the final pass fixed those copies.

## Initial security pass — completed, not the final status

- Server: scoped override `brace-expansion@^5.0.2` → `5.0.9`; scoped override `js-yaml@4.3.0` → `4.3.2`. The former selector matches the parent's declared range; an initial installed-version-only selector did not change the lock entry and was corrected before verification.
- Server production paths now resolve `node_modules/@google-cloud/translate/node_modules/brace-expansion` to `5.0.9` and `node_modules/@datadog/wasm-js-rewriter/node_modules/js-yaml` to `4.3.2`. Two development YAML 4.x siblings also moved to `4.3.2`.
- Alpha: Astro `7.1.4` → `7.3.2`, `@astrojs/node` `11.0.2` → `11.1.5`, `@astrojs/react` `6.0.1` → `6.0.5`, YAML override `4.3.0` → `4.3.2`. npm regenerated their transitive closure, including compiler/markdown packages and Sharp `0.35.4` in the build tree.
- Initial verification: server 92/92 targeted tests; alpha source 6/6, build succeeded and generated-output 3/3; dependency regression checks 3/3. These are superseded by the repeated final-pass results below, not retrospectively changed.

Upstream sources: [brace-expansion patched versions](https://github.com/advisories/GHSA-rgw5-rvv9-x895), [YAML patched versions](https://github.com/advisories/GHSA-2883-xcg3-v3hh), [Astro AVIF advisory](https://github.com/advisories/GHSA-26w7-cxv4-gfx2).

## Final bounded maintenance pass — applied and frozen

No forced Express, CSV, Nodemon, Astro or package-manager major upgrade was applied. Exact overrides are scoped to the reviewed major line; existing production controls and audit thresholds remain unchanged. npm regeneration can relocate transitive copies; the paths below are the **final** lockfile locations.

### Server changes

Paths are relative to `server/`. All rows except qs are development-only in the lockfile.

| Package | Before → final version | Shape | Final path(s) |
|---|---|---|---|
| qs | 6.15.3 → 6.16.0 | Minor | `node_modules/qs` |
| Babel core | 7.27.1 → 7.29.6 | Minor | `node_modules/@babel/core` |
| Babel SystemJS transform | 7.27.1 → 7.29.4 | Minor | `node_modules/@babel/plugin-transform-modules-systemjs` |
| ajv | 6.12.6 → 6.14.0 | Minor | `node_modules/ajv` |
| brace-expansion 1.x | 1.1.11 → 1.1.18 | Patch | `node_modules/minimatch/node_modules/brace-expansion` |
| brace-expansion 2.x | 2.0.1 → 2.1.4 | Minor | `node_modules/brace-expansion` |
| browserslist | 4.24.4 → 4.28.7 | Minor | `node_modules/browserslist` |
| diff 4.x | 4.0.2 → 4.0.4 | Patch | `node_modules/ts-node/node_modules/diff` |
| flatted | 3.3.3 → 3.4.2 | Minor | `node_modules/flatted` |
| js-yaml 3.x | 3.14.1 → 3.15.2 | Minor | `node_modules/js-yaml` |
| minimatch 5.x | 5.1.6 → 5.1.8 | Patch | `node_modules/filelist/node_modules/minimatch` |
| morgan (direct dev dependency) | 1.11.0 → 1.12.1 | Minor | `node_modules/morgan` |

The explicitly approved `qs@^6: 6.16.0` override is outside Express/body-parser's declared `~6.15.1` tilde range; same-major is **not** a claim of range compatibility. Clean HTTP/gateway regression tests were therefore repeated. Express remains `4.22.2` and body-parser `1.20.6`; both propagated findings cleared with qs. Added tests cover duplicate fields, ordinary arrays, a sparse high index, prototype-shaped keys and isBuffer-shaped nested input. These bounded tests do not prove all parser inputs safe.

Relevant fixes: [qs array-limit issue](https://github.com/advisories/GHSA-x5fp-wj9c-mxmx), [qs isBuffer issue](https://github.com/advisories/GHSA-4mjr-xmp4-gh2g), [SystemJS code generation](https://github.com/advisories/GHSA-fv7c-fp4j-7gwp), [Babel source maps](https://github.com/advisories/GHSA-4x5r-pxfx-6jf8), [flatted prototype pollution](https://github.com/advisories/GHSA-rf6f-7fwh-wjgh), [morgan log forging](https://github.com/advisories/GHSA-jxfw-x594-9x9m).

### Alpha changes

Paths are relative to `client-participation-alpha/`. All affected nodes below are development-only in the lockfile.

| Package | Before → final version | Shape | Final path(s) |
|---|---|---|---|
| handlebars | 4.7.8 → 4.7.9 | Patch | `node_modules/handlebars` |
| brace-expansion 1.x | 1.1.12 → 1.1.18 | Patch | `node_modules/brace-expansion` |
| minimatch 3.x | 3.1.2 → 3.1.4 | Patch | `node_modules/minimatch` |
| minimatch 9.x | 9.0.5 → 9.0.7 | Patch | `node_modules/@typescript-eslint/typescript-estree/node_modules/minimatch`; `node_modules/glob/node_modules/minimatch` |
| brace-expansion under minimatch 9.x | 2.0.2 → 5.0.9 | Parent-selected transitive line change | `node_modules/@typescript-eslint/typescript-estree/node_modules/brace-expansion`; `node_modules/glob/node_modules/brace-expansion` |
| flatted | 3.3.3 → 3.4.2 | Minor | `node_modules/flatted` |
| nanoid 3.x | 3.3.16 → 3.3.18 | Patch | `node_modules/nanoid` |
| ws 8.x | 8.18.3 → 8.21.1 | Minor | `node_modules/ws` |
| @humanfs/node | 0.16.7 → 0.16.8 | Patch | `node_modules/@humanfs/node` |
| ajv 6.x | 6.12.6 → 6.14.0 | Minor | `node_modules/ajv` |
| diff 4.x | 4.0.2 → 4.0.4 | Patch | `node_modules/ts-node/node_modules/diff` |
| postcss-selector-parser 7.x | 7.1.1 → 7.1.3 | Patch | `node_modules/postcss-selector-parser` |

The minimatch **9.0.7 parent** now declares `brace-expansion ^5.0.2`; npm follows that updated upstream dependency and the separate 5.x override pins its patched 5.0.9. No 2.x override was forced onto 5.x. The retained `brace-expansion@^2: 2.1.4` override is not currently needed by the resolved alpha tree. This is an explicitly documented transitive major-line change introduced by the parent patch, not a blanket cross-major override. Alpha's distinct picomatch 2.3.2 and 4.0.5 lines remain intact.

Relevant fixes: [Handlebars critical advisory](https://github.com/advisories/GHSA-2w6w-674q-4c4q), [minimatch extglob ReDoS](https://github.com/advisories/GHSA-23c5-xmqv-rm74), [nanoid loop](https://github.com/advisories/GHSA-2v37-7h3g-55p8), [ws memory disclosure](https://github.com/advisories/GHSA-58qx-3vcg-4xpx), [@humanfs symlink copy](https://github.com/advisories/GHSA-p498-v437-472g), [ajv ReDoS](https://github.com/advisories/GHSA-2g4f-4pwh-qvx6), [diff parsing](https://github.com/advisories/GHSA-73rr-hh4g-fpgx), [PostCSS selector recursion](https://github.com/advisories/GHSA-w9m9-85wc-3x92).

## Previously remaining findings — resolved by the follow-up above

All paths are relative to `server/`; there are no remaining alpha package findings in this audit snapshot.

| Scope / severity | Package and exact path | Next action / reason deferred |
|---|---|---|
| Production, moderate | `csv-parse 5.6.0` — `node_modules/csv-parse` | [Prototype replacement](https://github.com/advisories/GHSA-8cw4-87c7-c6xx). npm proposes `7.0.2`: **major upgrade**. Review streaming/sync CSV imports, column handling and regression fixtures separately. |
| Development, high | `nodemon 2.0.22` — `node_modules/nodemon` | Propagated notifier/semver finding. npm proposes `nodemon 3.1.14`: **major upgrade**, intentionally not performed. |
| Development, high | `simple-update-notifier 1.1.0` — `node_modules/simple-update-notifier` | Propagated semver finding. Registry checked: no newer 1.x notifier release beyond 1.1.0 was available. |
| Development, high | `semver 7.0.0` — `node_modules/simple-update-notifier/node_modules/semver` | [Range-parser ReDoS](https://github.com/advisories/GHSA-c2qf-rxjj-qqgw). First patched 7.x is 7.5.2, outside notifier's `~7.0.0` requirement. No straightforward **range-compatible** patch; do not silently override it or force the Nodemon major. |

The three high rows represent **one underlying development advisory propagated along a dependency chain**, not three independent production vulnerabilities. The local-only boundary is temporary restriction, not risk acceptance for production. Do not supply untrusted CSV, run the development watcher on untrusted projects, or interpret these audits as authorization to reopen public services. A future separate maintenance pass can evaluate CSV 7.0.2 and Nodemon 3.1.14 with their API/startup/reload regressions.

## Compatibility and final verification actually completed

- Locks regenerated with `npm install --package-lock-only --ignore-scripts --no-audit --fund=false`: pinned Node **22.23.1 / npm 10.9.8** for server; pinned Node **24.18.0 / npm 11.16.0** for alpha. Eight unrelated optional OXC-package `libc` fields stripped by npm10 were restored.
- Astro 7.3.2 satisfies the node adapter's `astro: ^7.2.1` peer. React adapter 6.0.5 accepts React/React DOM19 and requires Node>=22.12.0.
- Optional Rolldown WASM dependencies still warn about `@napi-rs/wasm-runtime 1.2.0` expecting `@emnapi/core`/`@emnapi/runtime ^2.0.0-alpha.3`, while 1.11.1 is present. No forced peer override. Native Linux ARM64 installation/build succeeds; WASM fallback compatibility is **not verified**.
- Fresh clean tests used anonymous Docker volumes for `node_modules` and alpha `dist`/`.astro`, avoiding existing installs and generated-output races. Astro telemetry was disabled; no real participant input was used.

| Verification | Exact command (from indicated component/root) | Final result |
|---|---|---|
| Server targeted tests, Node22 | In `server/`: `npm ci --ignore-scripts --no-audit --fund=false`, then `npm exec -- jest --runInBand __tests__/unit/http-middleware.test.ts __tests__/unit/fncp-gateway.test.ts __tests__/unit/postgres-query-builder-compat.test.ts` | **95/95 passed**, including3 new parser regressions |
| Alpha source checks, Node24 | In `client-participation-alpha/`: `npm ci --ignore-scripts --no-audit --fund=false`, then `npm run test:fncp-boundaries` | **6/6 passed** |
| Alpha compilation and generated-output checks | Same isolated alpha container, `ASTRO_TELEMETRY_DISABLED=1`: `npm run build`, then `npm run test:fncp-built-boundaries` | **Build succeeded; 3/3 passed** |
| Dependency regression checks | Root: `node --test deploy/fncp/dependency-patch-boundary.test.mjs` | **5/5 passed** |
| Production audit summaries | Root: `node deploy/fncp/audit-production-dependencies.mjs --component=server` and `--component=alpha` | **Both gates passed**, with final counts above |
| Full-tree audit | In each component: `npm audit --json` | Server exit1: four findings; alpha exit0: zero findings |
| Whitespace check | Root: `git diff --check` | Passed |

The isolated server tests emitted a global application/database setup warning because no database was configured; selected unit suites passed. This does **not** establish database integration behaviour. npm also emitted deprecation warnings for older tooling; audit-zero is not a maintenance/support guarantee. Full lint, the full application test suite, alternate-platform builds and WASM fallback were not run in this dependency subtask.

The alpha build retains `passthroughImageService()`, no Sharp import in compiled SSR, no private gateway values in browser assets, and the existing denied image-route configuration. **Development classification alone never establishes absence from generated SSR.** Exact-image scanning and main-task rebuilt runtime checks are separate evidence, not replaced by package audits. After this final lock freeze the main task must use the rebuilt images, not earlier image IDs.

## Previous freeze fingerprints — server values superseded above

SHA-256 binds final counts to the reviewed files, not merely to the base Git commit.

```text
1988edf86c6a4e6124abbe52ecbd42f085874302f49f99d34ef9d40b81ed5437  server/package.json
93d8934c027c0c3fb1df934247c9d26cb8a27c89c99b8c2534e5a42d8b0dda06  server/package-lock.json
dd7d0da4dd6f183c72bdcf1ff1d68c15a88ce27351a26e33c9197f6824155e52  client-participation-alpha/package.json
8fcb474074735ac67d26ac5ef7fb0511440562af7f9d9035cb9870c05b19bad8  client-participation-alpha/package-lock.json
```

Audit outputs were inspected in this task; this document is a reviewed summary, not a signed scan attestation or immutable raw-audit archive. npm advisory information changes over time. No external messages, deployments, commits or pushes were made in this subtask. All package edits are frozen for final cached image rebuilding/runtime assurance; no audit threshold was weakened.
