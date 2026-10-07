/** Pure fresh-bootstrap SQL contract. No connection, SQL execution or I/O.
 * Descriptors are private handoffs, not database/ownership capabilities. A future
 * driver must admit an exact new database, use a bounded read-only transaction
 * with a fixed search_path and trusted catalog/schema provenance, and never
 * execute this against retained/live participant state. A SELECT is not a
 * sandbox against a malicious database's functions, operators, RLS or views.
 * Catalog presence does not attest function/rule bodies, defaults, permissions,
 * migration completion, app startup or actual readiness. No activation follows.
 *
 * Source: server/Dockerfile-db; migrations/000000_initial.sql, 000002, 000006,
 * 000009, 000010, 000013, 000015, 000018 and fork-specific 000019; comments.ts
 * seed handling; comment.ts latest-unique aggregation; auth/create-user.ts.
 */
import { isProxy } from 'node:util/types';
import { validateFreshBootstrapResult } from '../fresh-bootstrap-result.mjs';

const issued = new WeakMap();
const failure = () => new Error('Fresh bootstrap database contract rejected; no database action or authority granted.');
const freeze = value => { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; };
function exact(value, names) {
  if (!value || typeof value !== 'object' || isProxy(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw failure();
  const fields = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(fields).length !== names.length || names.some(n => !fields[n] || !Object.hasOwn(fields[n], 'value'))) throw failure();
  return Object.fromEntries(names.map(n => [n, fields[n].value]));
}
function oneRow(rows, keys) {
  if (!Array.isArray(rows) || isProxy(rows) || Object.getPrototypeOf(rows) !== Array.prototype) throw failure();
  const slots = Object.getOwnPropertyDescriptors(rows);
  if (Reflect.ownKeys(slots).length !== 2 || slots.length?.value !== 1 || !slots[0] || !Object.hasOwn(slots[0], 'value')) throw failure();
  return exact(slots[0].value, keys);
}
function descriptor(kind, text, values) {
  const result = freeze({ name: `fncp-bootstrap-${kind}-v1`, text, values }); issued.set(result, kind); return result;
}
function admitted(query, kind) { if (!query || typeof query !== 'object' || isProxy(query) || issued.get(query) !== kind) throw failure(); }

// Only fixed module constants are interpolated into SQL. Caller IDs are values.
// These are REQUIRED columns, not an assertion that tables have no other fields.
const columns = {
  users: [['uid', 'integer', true], ['email', 'character varying(256)', false], ['site_id', 'character varying(256)', true], ['is_owner', 'boolean', false]],
  oidc_user_mappings: [['oidc_sub', 'character varying(255)', true], ['uid', 'integer', true]],
  conversations: [['zid', 'integer', true], ['owner', 'integer', false], ...['is_active', 'is_anon', 'is_draft', 'is_public', 'is_data_open', 'strict_moderation', 'profanity_filter', 'spam_filter', 'treevite_enabled', 'use_xid_whitelist'].map(n => [n, 'boolean', false]), ['xid_required', 'boolean', true], ['topics_enabled', 'boolean', true]],
  zinvites: [['zid', 'integer', true], ['zinvite', 'character varying(300)', true], ['uuid', 'uuid', false]],
  participants: [['zid', 'integer', true], ['pid', 'integer', true], ['uid', 'integer', true]],
  comments: [['zid', 'integer', true], ['tid', 'integer', true], ['pid', 'integer', true], ['uid', 'integer', true], ['txt', 'character varying(1000)', true], ['is_seed', 'boolean', true], ['mod', 'integer', true], ['active', 'boolean', true]],
  votes: [['zid', 'integer', true], ['pid', 'integer', true], ['tid', 'integer', true], ['vote', 'smallint', false], ['created', 'bigint', false], ['weight_x_32767', 'smallint', false]],
  votes_latest_unique: [['zid', 'integer', true], ['pid', 'integer', true], ['tid', 'integer', true], ['vote', 'smallint', false], ['modified', 'bigint', false], ['weight_x_32767', 'smallint', false]],
  xid_whitelist: [['zid', 'integer', false], ['owner', 'integer', true], ['xid', 'text', true]],
  xids: [['zid', 'integer', false], ['pid', 'integer', false], ['uid', 'integer', true], ['owner', 'integer', true], ['xid', 'text', true]],
  fncp_provider_allowlist_operations: [['zid', 'integer', true], ['xid', 'text', true], ['operation_version', 'smallint', true], ['desired_present', 'boolean', true]],
};
const uniqueKeys = [
  ['users', ['uid']], ['users', ['email']], ['oidc_user_mappings', ['oidc_sub']], ['oidc_user_mappings', ['uid']],
  ['conversations', ['zid']], ['zinvites', ['zinvite']], ['participants', ['zid', 'pid']], ['participants', ['zid', 'uid']],
  ['comments', ['zid', 'tid']], ['comments', ['zid', 'txt']], ['votes_latest_unique', ['zid', 'pid', 'tid']],
  ['xid_whitelist', ['owner', 'xid']], ['xids', ['owner', 'xid']], ['fncp_provider_allowlist_operations', ['zid', 'xid']],
];
const foreignKeys = [
  ['oidc_user_mappings', ['uid'], 'users', ['uid']], ['conversations', ['owner'], 'users', ['uid']],
  ['zinvites', ['zid'], 'conversations', ['zid']], ['participants', ['uid'], 'users', ['uid']],
  ['participants', ['zid'], 'conversations', ['zid']], ['comments', ['zid', 'pid'], 'participants', ['zid', 'pid']],
  ['xid_whitelist', ['zid'], 'conversations', ['zid']], ['xids', ['zid', 'pid'], 'participants', ['zid', 'pid']],
  ['fncp_provider_allowlist_operations', ['zid'], 'conversations', ['zid']],
];
const literal = v => typeof v === 'boolean' ? String(v) : `'${v}'`;
const arraySql = a => `ARRAY[${a.map(literal).join(',')}]::text[]`;
const tuples = a => a.map(row => '(' + row.join(',') + ')').join(',\n');
const keyNames = (relation, key) => `(SELECT array_agg(a.attname::text ORDER BY k.ord) FROM pg_catalog.unnest(${key}) WITH ORDINALITY AS k(num,ord) JOIN pg_catalog.pg_attribute a ON a.attrelid=${relation} AND a.attnum=k.num)`;
const schemaFields = ['server_major_17', 'transaction_read_only', 'origin_replication_role', 'tables_match', 'columns_match', 'unique_keys_match', 'foreign_keys_match', 'id_triggers_match', 'vote_rule_present', 'function_signatures_match'];

const SCHEMA_SQL = `WITH required_columns(table_name,column_name,type_name,not_null) AS (VALUES
${tuples(Object.entries(columns).flatMap(([table, cols]) => cols.map(([n, t, nullable]) => [literal(table), literal(n), literal(t), literal(nullable)])))}),
required_unique(table_name,key_names) AS (VALUES
${tuples(uniqueKeys.map(([t, keys]) => [literal(t), arraySql(keys)]))}),
required_foreign(table_name,key_names,target_table,target_keys) AS (VALUES
${tuples(foreignKeys.map(([t, keys, target, targetKeys]) => [literal(t), arraySql(keys), literal(target), arraySql(targetKeys)]))}),
required_triggers(table_name,trigger_name,type_mask) AS (VALUES
('comments','tid_auto',7),('comments','tid_auto_unlock',5),('participants','pid_auto',7),('participants','pid_auto_unlock',5)),
required_functions(schema_name,function_name,args,result_type) AS (VALUES
('public','now_as_millis','','bigint'),('public','random_polis_site_id','','text'),
('public','random_string','integer','text'),('public','tid_auto','','trigger'),('public','tid_auto_unlock','','trigger'),
('public','pid_auto','','trigger'),('public','pid_auto_unlock','','trigger'),('pg_catalog','gen_random_uuid','','uuid')),
relations AS (SELECT c.oid,c.relname,c.relkind,c.relpersistence,c.relrowsecurity FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public')
SELECT pg_catalog.current_setting('server_version_num')::integer BETWEEN 170000 AND 179999 AS server_major_17,
pg_catalog.current_setting('transaction_read_only')='on' AS transaction_read_only,
pg_catalog.current_setting('session_replication_role')='origin' AS origin_replication_role,
NOT EXISTS (SELECT 1 FROM (SELECT DISTINCT table_name FROM required_columns) e WHERE NOT EXISTS
 (SELECT 1 FROM relations r WHERE r.relname=e.table_name AND r.relkind='r' AND r.relpersistence='p' AND NOT r.relrowsecurity)) AS tables_match,
NOT EXISTS (SELECT 1 FROM required_columns e WHERE NOT EXISTS
 (SELECT 1 FROM relations r JOIN pg_catalog.pg_attribute a ON a.attrelid=r.oid
 WHERE r.relname=e.table_name AND a.attname=e.column_name AND a.attnum>0 AND NOT a.attisdropped
 AND pg_catalog.format_type(a.atttypid,a.atttypmod)=e.type_name AND a.attnotnull=e.not_null)) AS columns_match,
NOT EXISTS (SELECT 1 FROM required_unique e WHERE NOT EXISTS
 (SELECT 1 FROM relations r JOIN pg_catalog.pg_constraint c ON c.conrelid=r.oid JOIN pg_catalog.pg_index i ON i.indexrelid=c.conindid
 WHERE r.relname=e.table_name AND c.contype IN ('u','p') AND c.convalidated AND NOT c.condeferrable
 AND i.indisvalid AND i.indisready AND ${keyNames('r.oid', 'c.conkey')}=e.key_names)) AS unique_keys_match,
NOT EXISTS (SELECT 1 FROM required_foreign e WHERE NOT EXISTS
 (SELECT 1 FROM relations r JOIN pg_catalog.pg_constraint c ON c.conrelid=r.oid JOIN relations target ON target.oid=c.confrelid
 WHERE r.relname=e.table_name AND target.relname=e.target_table AND c.contype='f' AND c.convalidated AND NOT c.condeferrable
 AND ${keyNames('r.oid', 'c.conkey')}=e.key_names AND ${keyNames('target.oid', 'c.confkey')}=e.target_keys)) AS foreign_keys_match,
NOT EXISTS (SELECT 1 FROM required_triggers e WHERE NOT EXISTS
 (SELECT 1 FROM relations r JOIN pg_catalog.pg_trigger t ON t.tgrelid=r.oid JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid
 JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE r.relname=e.table_name AND t.tgname=e.trigger_name
 AND p.proname=e.trigger_name AND n.nspname='public' AND t.tgtype=e.type_mask AND t.tgenabled IN ('O','A')
 AND NOT t.tgisinternal AND t.tgqual IS NULL AND t.tgnargs=0)) AS id_triggers_match,
EXISTS (SELECT 1 FROM relations r JOIN pg_catalog.pg_rewrite w ON w.ev_class=r.oid WHERE r.relname='votes'
 AND w.rulename='on_vote_insert_update_unique_table' AND w.ev_type='3' AND w.ev_enabled IN ('O','A') AND NOT w.is_instead) AS vote_rule_present,
NOT EXISTS (SELECT 1 FROM required_functions e WHERE NOT EXISTS
 (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname=e.schema_name AND p.proname=e.function_name AND p.prokind='f' AND NOT p.prosecdef
 AND pg_catalog.oidvectortypes(p.proargtypes)=e.args AND pg_catalog.format_type(p.prorettype,NULL)=e.result_type)) AS function_signatures_match`;

// One SELECT snapshot; every application-table read is limited to the exact
// zinvite-derived conversation (or its owner). No statement/contact/XID content
// is selected. Pass is RAW vote=0; export sign reversal is irrelevant here.
const BASELINE_SQL = `WITH target AS (
 SELECT c.zid,c.owner,c.is_active,c.use_xid_whitelist,c.xid_required,c.is_data_open,c.is_anon,c.is_draft,
 c.strict_moderation,c.treevite_enabled,c.topics_enabled,c.profanity_filter,c.spam_filter
 FROM public.conversations c JOIN public.zinvites z ON z.zid=c.zid WHERE z.zinvite=$1::text
), selected_comments AS (SELECT c.zid,c.tid,c.pid,c.uid,c.is_seed,c.active,c.mod FROM public.comments c JOIN target t ON t.zid=c.zid),
raw_votes AS (SELECT v.pid,v.tid,v.vote FROM public.votes v JOIN target t ON t.zid=v.zid),
latest_votes AS (SELECT v.pid,v.tid,v.vote FROM public.votes_latest_unique v JOIN target t ON t.zid=v.zid)
SELECT
pg_catalog.current_setting('transaction_read_only')='on' AS transaction_read_only,
(SELECT count(*)::integer FROM target) AS target_rows,
(SELECT count(*)::integer FROM public.zinvites z JOIN target t ON z.zid=t.zid) AS conversation_alias_rows,
(SELECT count(*)::integer FROM public.users u JOIN target t ON u.uid=t.owner) AS owner_rows,
(SELECT count(*)::integer FROM public.oidc_user_mappings m JOIN target t ON m.uid=t.owner) AS owner_mapping_rows,
(SELECT count(*)::integer FROM public.participants p JOIN target t ON p.zid=t.zid) AS participant_rows,
(SELECT count(*)::integer FROM public.participants p JOIN target t ON p.zid=t.zid WHERE p.pid=$3::integer AND p.uid=t.owner) AS owner_participant_rows,
(SELECT count(*)::integer FROM selected_comments) AS statement_rows,
(SELECT count(*)::integer FROM selected_comments c JOIN target t ON c.zid=t.zid WHERE c.tid=ANY($2::integer[])
 AND c.pid=$3::integer AND c.uid=t.owner AND c.is_seed IS TRUE AND c.active IS TRUE AND c.mod=1) AS valid_seed_rows,
(SELECT count(DISTINCT tid)::integer FROM selected_comments WHERE tid=ANY($2::integer[])) AS distinct_expected_statement_ids,
(SELECT count(*)::integer FROM raw_votes) AS raw_vote_rows,
(SELECT count(*)::integer FROM raw_votes WHERE pid=$3::integer AND tid=ANY($2::integer[]) AND vote=0) AS raw_seed_owner_pass_rows,
(SELECT count(DISTINCT tid)::integer FROM raw_votes WHERE pid=$3::integer AND tid=ANY($2::integer[]) AND vote=0) AS raw_distinct_seed_ids,
(SELECT count(*)::integer FROM latest_votes) AS latest_unique_vote_rows,
(SELECT count(*)::integer FROM latest_votes WHERE pid=$3::integer AND tid=ANY($2::integer[]) AND vote=0) AS latest_seed_owner_pass_rows,
(SELECT count(DISTINCT tid)::integer FROM latest_votes WHERE pid=$3::integer AND tid=ANY($2::integer[]) AND vote=0) AS latest_distinct_seed_ids,
(SELECT count(*)::integer FROM public.xid_whitelist w JOIN target t ON w.zid=t.zid OR (w.zid IS NULL AND w.owner=t.owner)) AS applicable_whitelist_rows,
(SELECT count(*)::integer FROM public.xids x JOIN target t ON x.zid=t.zid OR (x.zid IS NULL AND x.owner=t.owner)) AS applicable_xid_rows,
(SELECT count(*)::integer FROM public.fncp_provider_allowlist_operations o JOIN target t ON o.zid=t.zid) AS provider_operation_rows,
COALESCE((SELECT bool_and(is_active IS FALSE AND use_xid_whitelist IS TRUE AND xid_required IS TRUE
 AND is_data_open IS FALSE AND is_anon IS TRUE AND is_draft IS FALSE AND strict_moderation IS TRUE
 AND treevite_enabled IS FALSE AND topics_enabled IS FALSE AND profanity_filter IS FALSE AND spam_filter IS FALSE) FROM target),false) AS closed_flags_match`;
const baselineExpected = {
  transaction_read_only: true, target_rows: 1, conversation_alias_rows: 1, owner_rows: 1, owner_mapping_rows: 1,
  participant_rows: 1, owner_participant_rows: 1, statement_rows: 15, valid_seed_rows: 15, distinct_expected_statement_ids: 15,
  raw_vote_rows: 15, raw_seed_owner_pass_rows: 15, raw_distinct_seed_ids: 15,
  latest_unique_vote_rows: 15, latest_seed_owner_pass_rows: 15, latest_distinct_seed_ids: 15,
  applicable_whitelist_rows: 0, applicable_xid_rows: 0, provider_operation_rows: 0, closed_flags_match: true,
};
const scope = () => ({ classification: 'DATABASE_CONTRACT_ONLY', actualDatabaseRead: false, actualBootstrapExecuted: false,
  databaseOwnershipVerified: false, fullSchemaVerified: false, functionAndRuleBodiesVerified: false,
  databaseReady: false, activationGranted: false, roundOpen: false });

export function bootstrapSchemaQuery() {
  if (arguments.length) throw failure(); return descriptor('schema', SCHEMA_SQL, []);
}
// Private worker handoff: a copied/lookalike descriptor never gains authority.
// No caller-supplied SQL is returned or accepted by the concrete executor.
export function bootstrapDatabaseQueryContract(query) {
  if (arguments.length !== 1 || !query || typeof query !== 'object' || isProxy(query)) throw failure();
  const kind = issued.get(query);
  if (!['schema', 'baseline'].includes(kind)) throw failure();
  const fields = kind === 'schema' ? schemaFields.map(name => ({ name, dataTypeID: 16 })) :
    Object.entries(baselineExpected).map(([name, value]) => ({ name, dataTypeID: typeof value === 'boolean' ? 16 : 23 }));
  return freeze({ kind, values: query.values, columns: fields });
}
export function validateBootstrapSchemaResult(query, rows) {
  try {
    if (arguments.length !== 2) throw failure(); admitted(query, 'schema');
    const row = oneRow(rows, schemaFields); if (schemaFields.some(k => row[k] !== true)) throw failure();
    return freeze({ ...scope(), catalogAdmission: 'LIMITED_REQUIRED_OBJECTS_MATCHED', requiredTables: Object.keys(columns).length,
      requiredColumns: Object.values(columns).reduce((n, c) => n + c.length, 0), requiredUniqueKeys: uniqueKeys.length, requiredForeignKeys: foreignKeys.length,
      requiredIdTriggers: 4, voteUpsertRulePresence: true });
  } catch { throw failure(); }
}
export function bootstrapBaselineQuery(input) {
  try {
    if (arguments.length !== 1) throw failure();
    const data = exact(input, ['conversationId', 'statementIds', 'seedOwnerPid']);
    const binding = validateFreshBootstrapResult({ conversationId: data.conversationId, statementIds: data.statementIds });
    if (!Number.isSafeInteger(data.seedOwnerPid) || data.seedOwnerPid < 0 || data.seedOwnerPid > 2147483647 || Object.is(data.seedOwnerPid, -0)) throw failure();
    return descriptor('baseline', BASELINE_SQL, [binding.conversationId, binding.statementIds, data.seedOwnerPid]);
  } catch { throw failure(); }
}
export function validateBootstrapBaselineResult(query, rows) {
  try {
    if (arguments.length !== 2) throw failure(); admitted(query, 'baseline');
    const row = oneRow(rows, Object.keys(baselineExpected));
    if (Object.entries(baselineExpected).some(([k, expected]) => row[k] !== expected || Object.is(row[k], -0))) throw failure();
    return freeze({ ...scope(), baselineAdmission: 'CLOSED_SEED_BASELINE_MATCHED', statements: 15, seedOwnerParticipants: 1,
      rawVoteHistoryRows: 15, latestUniqueVoteRows: 15, rawSeedOwnerPassVotes: 15, latestUniqueSeedOwnerPassVotes: 15,
      applicableWhitelistRows: 0, applicableXidRows: 0, providerOperationRows: 0,
      statementTextsVerified: false, otherConversationsInspected: false, actorOidcSubjectVerified: false,
      snapshotScope: 'ONE_INJECTED_RESULT_NOT_PERSISTENT_READINESS_OR_RUNTIME_EVIDENCE' });
  } catch { throw failure(); }
}
