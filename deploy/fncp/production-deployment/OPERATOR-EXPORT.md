# Private production aggregate export

`operator-export.mjs` is an offline, operator-only query and projection helper for the eight-role production composition. It performs no filesystem, engine, database, HTTP, activation or account actions. It does not offer a participant route or prove staff authorization.

Call `operatorSnapshotSql(publicProductionConfiguration)` for the fixed SQL. Run only those bytes through the owned maintenance image from the exact eight-role image lock, with the established private configuration/material custody checks, expected database and migration role, `PGSSLMODE=verify-full`, and the configured CA. Use `psql -X -q -A -t --no-password -v ON_ERROR_STOP=1`; do not allow caller SQL, interpolation, a startup file or unverified database TLS. Check successful process completion and the final read-only transaction rollback before accepting its one JSON result. SQL uses `REPEATABLE READ READ ONLY`, fixed timeouts, and `search_path=pg_catalog`; it returns aggregates and private validation flags rather than identity mappings or individual votes.

Then call:

```js
const result = aggregateOperatorSnapshot(
  publicProductionConfiguration,
  exactEightRoleImageLock,
  JSON.parse(privateDatabaseResult),
  { statements: orderedReviewedTexts, seedSha256 }
);
```

The fifteen texts must be the exact ordered strings used for participant activation, without normalization. `seedSha256` is SHA-256 of `JSON.stringify(orderedReviewedTexts)`. The configured fifteen statement IDs must be strictly increasing. The result is constructed from an explicit allowlist and deeply frozen. Supplied extra private fields never appear in it; malformed data, executable properties, sparse arrays and excessive input are rejected. A caller-supplied snapshot is not a signed database receipt: the helper cannot replace verified execution or private operator authorization.

The query and projector require one configured closed, private, XID-gated conversation, no public data export, strict moderation, no statement suggestions, the exact twenty migration hashes, PostgreSQL 17 on the primary, the expected nonprivileged migration login, and observed TLS 1.2/1.3 with at least 128-bit encryption. All fifteen active approved seeds must match the configured IDs and reviewed text, with no metadata statements. Native history/latest vote agreement, valid vote values, unambiguous timestamps, exact persisted vote and moderation watermarks, common main/auxiliary math ticks, voter membership, group totals and native group-aware consensus are checked before projection. The fixed math environment remains `dev`, matching the deployed worker contract.

The twenty-person cohort cap excludes exactly one verified nonvoting seed owner. The owner is resolved from the bound conversation's `owner` UID and its actual participant UID/PID, not from a hardcoded PID. That identity must have authored all fifteen seeds, have no historical votes and have no participant XID mapping. Twenty cohort voters plus this owner can therefore produce twenty-one native participant identities; twenty-one cohort registrations or voters still fail.

Every other native participant must have exactly one conversation/owner/UID/PID XID mapping joined to the dedicated provider operation ledger. Native users and XID mappings outside that binding are rejected. Version-2 revocation tombstones remain part of provider registration counts and historical analysis: revocation removes future admission rather than erasing prior votes. Current provider allowlist rows must agree with version-1 presence/version-2 removal, with no owner-wide fallback or unknown row. Provider registrations that have not visited need not have a native participant or math vote. These aggregate counts are the native provider footprint; they do not count pending WordPress accounts or independently establish total registration authorization.

Output contains runtime source revision/fingerprint and all eight image IDs, seed/binding hashes, snapshot/TLS/math watermarks, aggregate native/provider/voter counts, group sizes, and fifteen statements with agree/disagree/pass totals and native group-aware consensus. Consensus is the product across groups of `(agree + 1) / (seen + 2)`, not a percentage. Group-vote and consensus fields are also projected numerically inside PostgreSQL; member maps and raw persisted objects are not selected. The runtime source fields describe the locked images; record this offline helper's own source/hash separately if it was added after that image checkpoint.

The operator must first close participant admission, drain in-flight work, close the native round using the separately reviewed maintenance operation, and wait for persistent math to catch up. This export closes nothing and grants no activation. Treat stale or incomplete math as a retryable observation only after the runtime catches up; do not weaken assertions. Store the accepted full export in a newly created private file outside the source checkout and keep its evidence hash. Release only separately approved aggregate content; a synthetic QA summary does not authorize release of real participant data.

Run host contract tests with:

```sh
node --test deploy/fncp/production-deployment/operator-export.test.mjs
```

The tests cover 18 and 20 voters plus one owner, unvisited provider registrations, owner-vote/identity/tombstone failures, seed and schema binding, privacy/TLS/role checks, strict persistence and consensus failures, output privacy and malformed inputs. They are synthetic pure-function checks. Actual PostgreSQL execution and an observed persisted native result require the separate owned-runtime proof.
