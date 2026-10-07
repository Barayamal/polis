import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  bootstrapSchemaQuery, validateBootstrapSchemaResult,
  bootstrapBaselineQuery, validateBootstrapBaselineResult, bootstrapDatabaseQueryContract,
} from './bootstrap-database-contract.mjs';

const MESSAGE = 'Fresh bootstrap database contract rejected; no database action or authority granted.';
const deny = fn => assert.throws(fn, error => error.message === MESSAGE && error.cause === undefined);
const ids = [8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987, 1597, 2584, 4181, 2147483647];
const input = () => ({ conversationId: '7freshDatabaseQA', statementIds: [...ids], seedOwnerPid: 23 });
const schema = () => ({ server_major_17: true, transaction_read_only: true, origin_replication_role: true,
  tables_match: true, columns_match: true, unique_keys_match: true, foreign_keys_match: true,
  id_triggers_match: true, vote_rule_present: true, function_signatures_match: true });
const baseline = () => ({ transaction_read_only: true, target_rows: 1, conversation_alias_rows: 1,
  owner_rows: 1, owner_mapping_rows: 1, participant_rows: 1, owner_participant_rows: 1,
  statement_rows: 15, valid_seed_rows: 15, distinct_expected_statement_ids: 15,
  raw_vote_rows: 15, raw_seed_owner_pass_rows: 15, raw_distinct_seed_ids: 15,
  latest_unique_vote_rows: 15, latest_seed_owner_pass_rows: 15, latest_distinct_seed_ids: 15,
  applicable_whitelist_rows: 0, applicable_xid_rows: 0, provider_operation_rows: 0, closed_flags_match: true });
const publicSource = path => readFile(new URL('../../../server/' + path, import.meta.url), 'utf8');

test('worker handoff requires the original factory brand and returns only immutable kind, values and typed columns', () => {
  const q = bootstrapBaselineQuery(input()); const handoff = bootstrapDatabaseQueryContract(q);
  assert.deepEqual(Object.keys(handoff), ['kind', 'values', 'columns']);
  assert.equal(handoff.kind, 'baseline'); assert.equal(handoff.values, q.values);
  assert.deepEqual(handoff.columns, Object.entries(baseline()).map(([name, value]) => ({ name, dataTypeID: typeof value === 'boolean' ? 16 : 23 })));
  assert.deepEqual(bootstrapDatabaseQueryContract(bootstrapSchemaQuery()).columns, Object.keys(schema()).map(name => ({ name, dataTypeID: 16 })));
  assert.ok(Object.isFrozen(handoff) && Object.isFrozen(handoff.values) && Object.isFrozen(handoff.values[1]) &&
    Object.isFrozen(handoff.columns) && handoff.columns.every(Object.isFrozen));
  for (const invalid of [undefined, null, {}, { ...q }, structuredClone(q), new Proxy(q, {})]) deny(() => bootstrapDatabaseQueryContract(invalid));
  deny(() => bootstrapDatabaseQueryContract(q, true));
});

test('schema descriptor is fixed, immutable and contains no configurable database or executor', () => {
  const a = bootstrapSchemaQuery(), b = bootstrapSchemaQuery();
  assert.deepEqual(Object.keys(a), ['name', 'text', 'values']); assert.equal(a.name, 'fncp-bootstrap-schema-v1');
  assert.notEqual(a, b); assert.equal(a.text, b.text); assert.deepEqual(a.values, []);
  assert.ok(Object.isFrozen(a) && Object.isFrozen(a.values));
  assert.throws(() => { a.text = 'DELETE'; }, TypeError); assert.throws(() => a.values.push('retained'), TypeError);
  for (const value of [undefined, null, {}, 'dsn', () => {}]) deny(() => bootstrapSchemaQuery(value));
});

test('fixed SQL has one SELECT result and no mutable statements, caller SQL or wildcard content projection', () => {
  for (const q of [bootstrapSchemaQuery(), bootstrapBaselineQuery(input())]) {
    assert.match(q.text, /^WITH /u); assert.match(q.text, /\bSELECT\b/u); assert.ok(q.text.length < 12000);
    assert.doesNotMatch(q.text, /;|--|\/\*|\b(?:INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|COPY|CALL|DO|GRANT|TRUNCATE|LOCK)\b/iu);
    assert.doesNotMatch(q.text, /\bSELECT\s+(?:\w+\.)?\*/iu);
    assert.doesNotMatch(q.text, /FOR\s+(?:UPDATE|SHARE)|pg_advisory|pg_sleep|dblink|lo_export/iu);
  }
});

test('schema validator admits only the exact limited catalog projection and never marks a database ready', () => {
  const result = validateBootstrapSchemaResult(bootstrapSchemaQuery(), [schema()]);
  assert.equal(result.catalogAdmission, 'LIMITED_REQUIRED_OBJECTS_MATCHED');
  assert.equal(result.requiredTables, 11); assert.equal(result.requiredColumns, 58);
  assert.equal(result.requiredUniqueKeys, 14); assert.equal(result.requiredForeignKeys, 9); assert.equal(result.requiredIdTriggers, 4);
  for (const field of ['databaseReady', 'actualDatabaseRead', 'actualBootstrapExecuted', 'databaseOwnershipVerified', 'fullSchemaVerified', 'functionAndRuleBodiesVerified', 'activationGranted', 'roundOpen']) assert.equal(result[field], false);
  assert.equal(result.classification, 'DATABASE_CONTRACT_ONLY'); assert.ok(Object.isFrozen(result));
});

test('every missing or nonboolean catalog condition denies schema admission', () => {
  const query = bootstrapSchemaQuery();
  for (const key of Object.keys(schema())) for (const bad of [false, null, undefined, 'true', 1, {}, []]) {
    deny(() => validateBootstrapSchemaResult(query, [{ ...schema(), [key]: bad }]));
  }
  const missing = schema(); delete missing.vote_rule_present;
  deny(() => validateBootstrapSchemaResult(query, [missing]));
});

test('schema checks are qualified catalog metadata, exact version/read-only/session mode and non-RLS tables', () => {
  const sql = bootstrapSchemaQuery().text;
  for (const catalog of ['pg_class', 'pg_namespace', 'pg_attribute', 'pg_constraint', 'pg_index', 'pg_trigger', 'pg_proc', 'pg_rewrite']) assert.ok(sql.includes('pg_catalog.' + catalog));
  assert.match(sql, /BETWEEN 170000 AND 179999/u); assert.match(sql, /current_setting\('transaction_read_only'\)='on'/u);
  assert.match(sql, /current_setting\('session_replication_role'\)='origin'/u);
  assert.match(sql, /r\.relkind='r' AND r\.relpersistence='p' AND NOT r\.relrowsecurity/u);
  assert.match(sql, /n\.nspname='public'/u); assert.doesNotMatch(sql, /FROM public\./u);
  assert.match(sql, /format_type\(a\.atttypid,a\.atttypmod\)=e\.type_name AND a\.attnotnull=e\.not_null/u);
});

test('schema requires ordered unique/FK keys and usable origin triggers without pretending to attest bodies', () => {
  const sql = bootstrapSchemaQuery().text;
  assert.match(sql, /array_agg\(a\.attname::text ORDER BY k\.ord\)/u);
  assert.match(sql, /c\.convalidated AND NOT c\.condeferrable/u); assert.match(sql, /i\.indisvalid AND i\.indisready/u);
  assert.match(sql, /t\.tgtype=e\.type_mask AND t\.tgenabled IN \('O','A'\)/u);
  assert.match(sql, /NOT t\.tgisinternal AND t\.tgqual IS NULL AND t\.tgnargs=0/u);
  assert.match(sql, /w\.ev_type='3' AND w\.ev_enabled IN \('O','A'\) AND NOT w\.is_instead/u);
  assert.match(sql, /p\.prokind='f' AND NOT p\.prosecdef/u);
  assert.doesNotMatch(sql, /pg_get_functiondef|prosrc|ev_action/u);
});

test('baseline descriptor binds actual sparse statement IDs, exact conversation and creator PID through parameters', () => {
  const provided = input(); const q = bootstrapBaselineQuery(provided);
  assert.equal(q.name, 'fncp-bootstrap-baseline-v1'); assert.deepEqual(q.values, ['7freshDatabaseQA', ids, 23]);
  assert.ok(Object.isFrozen(q) && Object.isFrozen(q.values) && Object.isFrozen(q.values[1]));
  provided.statementIds[0] = 0; provided.seedOwnerPid = 0; assert.equal(q.values[1][0], 8); assert.equal(q.values[2], 23);
  assert.doesNotMatch(q.text, /7freshDatabaseQA|2147483647/u);
  assert.match(q.text, /WHERE z\.zinvite=\$1::text/u); assert.match(q.text, /ANY\(\$2::integer\[\]\)/u); assert.match(q.text, /pid=\$3::integer/u);
  const other = bootstrapBaselineQuery({ ...input(), conversationId: '8otherFreshQA' }); assert.equal(other.text, q.text);
});

test('baseline IDs reject injection, absent bootstrap placeholders and every invalid numeric boundary', () => {
  for (const conversationId of [null, 5, '', "7abcdef';SELECT", '7abcde/secret', 'abcdef', '9fncpBootstrap' + 'a'.repeat(48), '7' + 'a'.repeat(100)]) deny(() => bootstrapBaselineQuery({ ...input(), conversationId }));
  for (const seedOwnerPid of [-1, -0, 2147483648, 1.5, Infinity, NaN, '23', 23n, null, undefined]) deny(() => bootstrapBaselineQuery({ ...input(), seedOwnerPid }));
  for (const bad of [-1, -0, 2147483648, 1.5, Infinity, NaN, '8', null]) { const statementIds = [...ids]; statementIds[0] = bad; deny(() => bootstrapBaselineQuery({ ...input(), statementIds })); }
  for (const statementIds of [ids.slice(1), [...ids, 7], Array(15).fill(2), [], null]) deny(() => bootstrapBaselineQuery({ ...input(), statementIds }));
  const q = bootstrapBaselineQuery({ ...input(), seedOwnerPid: 0 }); assert.equal(q.values[2], 0);
});

test('input arrays/records reject sparse entries, symbols, extra keys, proxies and accessors without execution', () => {
  let reads = 0; const trap = () => { reads++; throw new Error('private'); };
  const getter = { ...input() }; Object.defineProperty(getter, 'seedOwnerPid', { get: trap });
  const slots = [...ids]; Object.defineProperty(slots, '0', { get: trap });
  const sparse = [...ids]; delete sparse[3]; const extraArray = [...ids]; extraArray.extra = 1;
  const proxy = new Proxy(input(), { get: trap, ownKeys: trap, getPrototypeOf: trap });
  for (const value of [getter, proxy, { ...input(), extra: true }, { ...input(), [Symbol('hidden')]: 1 }, Object.create(input()), { ...input(), statementIds: slots }, { ...input(), statementIds: sparse }, { ...input(), statementIds: extraArray }, { ...input(), statementIds: new Proxy(ids, { get: trap }) }]) deny(() => bootstrapBaselineQuery(value));
  assert.equal(reads, 0);
});

test('only issued exact-kind query objects can validate a result; copying never grants provenance', () => {
  const s = bootstrapSchemaQuery(), b = bootstrapBaselineQuery(input());
  for (const q of [undefined, null, {}, { ...s }, JSON.parse(JSON.stringify(s)), b, Object.create(s), new Proxy(s, {})]) deny(() => validateBootstrapSchemaResult(q, [schema()]));
  for (const q of [undefined, null, {}, { ...b }, JSON.parse(JSON.stringify(b)), s, Object.create(b), new Proxy(b, {})]) deny(() => validateBootstrapBaselineResult(q, [baseline()]));
  assert.equal(validateBootstrapBaselineResult(b, [baseline()]).rawVoteHistoryRows, 15);
});

test('validators reject additional/missing arguments and extra result fields without reading them', () => {
  const s = bootstrapSchemaQuery(), b = bootstrapBaselineQuery(input()); let reads = 0;
  const poison = new Proxy({}, { get() { reads++; throw new Error('private'); } });
  deny(() => bootstrapBaselineQuery()); deny(() => bootstrapBaselineQuery(input(), poison));
  for (const [fn, q, r] of [[validateBootstrapSchemaResult, s, schema()], [validateBootstrapBaselineResult, b, baseline()]]) {
    deny(() => fn()); deny(() => fn(q)); deny(() => fn(q, [r], poison));
    deny(() => fn(q, [{ ...r, private: 'must never echo' }])); deny(() => fn(q, [{ ...r, [Symbol('hidden')]: true }]));
  }
  assert.equal(reads, 0);
});

test('exact one-row projection rejects driver wrappers, array tricks, proxies and accessors without reads', () => {
  let reads = 0; const trap = () => { reads++; throw new Error('private'); };
  for (const [fn, q, good] of [[validateBootstrapSchemaResult, bootstrapSchemaQuery(), schema()], [validateBootstrapBaselineResult, bootstrapBaselineQuery(input()), baseline()]]) {
    const arrayGetter = [good]; Object.defineProperty(arrayGetter, '0', { get: trap });
    const rowGetter = { ...good }; Object.defineProperty(rowGetter, Object.keys(good)[0], { get: trap });
    const extra = [good]; extra.extra = true;
    for (const rows of [null, {}, { rows: [good] }, [], [good, good], Array(1), extra, arrayGetter, [rowGetter], [Object.create(good)], new Proxy([good], { get: trap }), [new Proxy(good, { get: trap })]]) deny(() => fn(q, rows));
  }
  assert.equal(reads, 0);
});

test('complete aggregate baseline is accepted but is never upgraded to actual database/runtime evidence', () => {
  const r = validateBootstrapBaselineResult(bootstrapBaselineQuery(input()), [baseline()]);
  assert.equal(r.baselineAdmission, 'CLOSED_SEED_BASELINE_MATCHED'); assert.equal(r.rawVoteHistoryRows, 15);
  assert.equal(r.latestUniqueVoteRows, 15); assert.equal(r.rawSeedOwnerPassVotes, 15); assert.equal(r.latestUniqueSeedOwnerPassVotes, 15);
  for (const k of ['actualDatabaseRead', 'actualBootstrapExecuted', 'databaseOwnershipVerified', 'databaseReady', 'functionAndRuleBodiesVerified', 'fullSchemaVerified', 'activationGranted', 'roundOpen', 'statementTextsVerified', 'otherConversationsInspected', 'actorOidcSubjectVerified']) assert.equal(r[k], false);
  assert.ok(Object.isFrozen(r)); assert.match(r.snapshotScope, /NOT_PERSISTENT_READINESS_OR_RUNTIME_EVIDENCE/u);
});

test('every aggregate baseline field fails independently on missing/wrong/coerced values', () => {
  const q = bootstrapBaselineQuery(input());
  for (const [key, expected] of Object.entries(baseline())) {
    for (const value of [null, undefined, String(expected), {}, [], -0, NaN, Infinity, typeof expected === 'number' ? expected + 1 : false]) deny(() => validateBootstrapBaselineResult(q, [{ ...baseline(), [key]: value }]));
    const omitted = baseline(); delete omitted[key]; deny(() => validateBootstrapBaselineResult(q, [omitted]));
  }
});

test('extra raw history is rejected even when latest-unique still shows exactly fifteen seed Pass votes', () => {
  const q = bootstrapBaselineQuery(input());
  for (const raw_vote_rows of [16, 30, 2147483647]) deny(() => validateBootstrapBaselineResult(q, [{ ...baseline(), raw_vote_rows }]));
  deny(() => validateBootstrapBaselineResult(q, [{ ...baseline(), raw_vote_rows: 30, raw_seed_owner_pass_rows: 30 }]));
  assert.equal(validateBootstrapBaselineResult(q, [baseline()]).latestUniqueVoteRows, 15);
});

test('both history and latest-unique require fifteen distinct expected IDs rather than fifteen copies of one vote', () => {
  const q = bootstrapBaselineQuery(input());
  for (const field of ['raw_distinct_seed_ids', 'latest_distinct_seed_ids', 'distinct_expected_statement_ids']) for (const n of [0, 1, 14, 16]) deny(() => validateBootstrapBaselineResult(q, [{ ...baseline(), [field]: n }]));
  const sql = q.text; assert.equal((sql.match(/count\(DISTINCT tid\)::integer/gu) ?? []).length, 3);
  assert.match(sql, /FROM raw_votes WHERE pid=\$3::integer AND tid=ANY\(\$2::integer\[\]\) AND vote=0/u);
  assert.match(sql, /FROM latest_votes WHERE pid=\$3::integer AND tid=ANY\(\$2::integer\[\]\) AND vote=0/u);
});

test('unknown conversation, alternate aliases, other participants and wrong owner do not pass the exact baseline', () => {
  const q = bootstrapBaselineQuery(input());
  for (const k of ['target_rows', 'conversation_alias_rows', 'owner_rows', 'owner_mapping_rows', 'participant_rows', 'owner_participant_rows']) for (const n of [0, 2]) deny(() => validateBootstrapBaselineResult(q, [{ ...baseline(), [k]: n }]));
  assert.match(q.text, /p\.pid=\$3::integer AND p\.uid=t\.owner/u); assert.match(q.text, /c\.uid=t\.owner AND c\.is_seed IS TRUE/u);
});

test('legacy owner-level whitelist/XID routes and conversation operation tombstones are counted, never silently filtered away', () => {
  const q = bootstrapBaselineQuery(input());
  assert.match(q.text, /w\.zid=t\.zid OR \(w\.zid IS NULL AND w\.owner=t\.owner\)/u);
  assert.match(q.text, /x\.zid=t\.zid OR \(x\.zid IS NULL AND x\.owner=t\.owner\)/u);
  assert.match(q.text, /public\.fncp_provider_allowlist_operations o JOIN target t ON o\.zid=t\.zid/u);
  for (const k of ['applicable_whitelist_rows', 'applicable_xid_rows', 'provider_operation_rows']) deny(() => validateBootstrapBaselineResult(q, [{ ...baseline(), [k]: 1 }]));
});

test('the single aggregate statement stays conversation scoped and never returns contact, statement, XID or owner identifiers', () => {
  const q = bootstrapBaselineQuery(input());
  for (const table of ['conversations', 'zinvites', 'users', 'oidc_user_mappings', 'participants', 'comments', 'votes', 'votes_latest_unique', 'xid_whitelist', 'xids', 'fncp_provider_allowlist_operations']) assert.ok(q.text.includes('public.' + table));
  assert.doesNotMatch(q.text, /\b(?:email|hname|username|oidc_sub|txt|xid|site_id)\b/u);
  assert.doesNotMatch(q.text, /LIMIT|OFFSET|ORDER BY|UNION/iu);
  const result = JSON.stringify(validateBootstrapBaselineResult(q, [baseline()]));
  for (const privateValue of [q.values[0], JSON.stringify(ids), 'seedOwnerPid', 'statementIds', 'conversationId', 'text', 'values']) assert.ok(!result.includes(privateValue));
});

test('closed flags are explicit and data-open false is not misrepresented as private native Pol.is routing', () => {
  const sql = bootstrapBaselineQuery(input()).text;
  for (const flag of ['is_active', 'is_data_open', 'is_draft', 'treevite_enabled', 'topics_enabled', 'profanity_filter', 'spam_filter']) assert.ok(sql.includes(flag + ' IS FALSE'));
  for (const flag of ['use_xid_whitelist', 'xid_required', 'is_anon', 'strict_moderation']) assert.ok(sql.includes(flag + ' IS TRUE'));
  assert.match(sql, /COALESCE\(\(SELECT bool_and/u);
  assert.doesNotMatch(sql, /is_public IS FALSE/u);
  deny(() => validateBootstrapBaselineResult(bootstrapBaselineQuery(input()), [{ ...baseline(), closed_flags_match: false }]));
});

test('catalog assumptions match fixed local migration source, including types, changed keys and enabled seed/vote machinery', async () => {
  const initial = await publicSource('postgres/migrations/000000_initial.sql');
  const xid = await publicSource('postgres/migrations/000002_add_xid_constraint.sql');
  const rule = await publicSource('postgres/migrations/000006_update_votes_rule.sql');
  const oidc = await publicSource('postgres/migrations/000010_create_oidc_user_mappings.sql');
  const gates = await publicSource('postgres/migrations/000015_add_xid_requirements.sql');
  const operations = await publicSource('postgres/migrations/000019_add_fncp_provider_allowlist_operations.sql');
  for (const table of ['users', 'conversations', 'zinvites', 'participants', 'comments', 'votes', 'votes_latest_unique', 'xids', 'xid_whitelist']) assert.match(initial, new RegExp(`CREATE TABLE ${table}\\s*\\(`, 'u'));
  assert.match(initial, /tid INTEGER NOT NULL/u); assert.match(initial, /txt VARCHAR\(1000\) NOT NULL/u);
  assert.match(initial, /CREATE TRIGGER tid_auto\s+BEFORE INSERT ON comments/u); assert.match(initial, /CREATE TRIGGER pid_auto_unlock\s+AFTER INSERT ON participants/u);
  assert.match(xid, /UNIQUE \(owner, xid\)/u); assert.match(oidc, /oidc_sub VARCHAR\(255\) PRIMARY KEY/u);
  assert.match(gates, /ADD COLUMN xid_required BOOLEAN NOT NULL DEFAULT false/u);
  assert.match(rule, /ON INSERT TO votes[\s\S]+INSERT INTO votes_latest_unique[\s\S]+ON CONFLICT \(zid, pid, tid\) DO UPDATE/u);
  assert.match(operations, /PRIMARY KEY \(zid, xid\)/u);
});

test('raw vote semantics and latest-unique aggregation are grounded in comments/votes source, not export signs', async () => {
  const comments = await publicSource('src/routes/comments.ts'); const comment = await publicSource('src/comment.ts');
  const initial = await publicSource('postgres/migrations/000000_initial.sql');
  assert.match(comments, /shouldDefaultVote = req\.p\.is_seed && _.isUndefined\(vote\)/u);
  assert.match(comments, /finalVote = shouldDefaultVote \? 0 : vote/u);
  assert.match(comment, /from votes_latest_unique where zid = \(\$1\) group by tid, vote/u);
  assert.match(initial, /-1 = Agree, 1 = Disagree, 0 = Pass\/Unsure/u);
  const sql = bootstrapBaselineQuery(input()).text;
  assert.match(sql, /FROM public\.votes v JOIN target/u); assert.match(sql, /FROM public\.votes_latest_unique v JOIN target/u);
});

test('module has no connection/execution/runtime/secret/SQL-selector surface and explicitly preserves readiness gaps', async () => {
  const source = await readFile(new URL('./bootstrap-database-contract.mjs', import.meta.url), 'utf8');
  const imports = [...source.matchAll(/^import .* from '([^']+)'/gmu)].map(m => m[1]);
  assert.deepEqual(imports, ['node:util/types', '../fresh-bootstrap-result.mjs']);
  assert.doesNotMatch(source, /process\.env|fetch\(|readFile\(|writeFile\(|spawn\(|exec\(|runDocker\(|new Client\(|new Pool\(/u);
  assert.equal((source.match(/^export function /gmu) ?? []).length, 5);
  assert.match(source, /Catalog presence does not attest function\/rule bodies/u);
  assert.match(source, /SELECT is not a/u); assert.match(source, /retained\/live participant state/u);
});
