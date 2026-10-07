import { createHash } from 'node:crypto';
import { validateProductionConfiguration, validateProductionImageLock } from './compose.mjs';
const sha256=value=>createHash('sha256').update(value).digest('hex');
const freeze=value=>{if(value&&typeof value==='object'){for(const child of Object.values(value))freeze(child);Object.freeze(value);}return value;};

// This module creates fixed read-only SQL and projects a supplied private
// snapshot. It performs no filesystem, process, database or network operations.

const MIGRATIONS = Object.freeze({
  "000000_initial.sql": "2652134140cd8796ee3ab64995d509206bab3ebe8a03bba0cf48038a32dc6cea",
  "000001_update_pwreset_table.sql": "cb21278194c4b7db510c12bf1a7761b3a905410a7b3769edeb0d1865b6ec047b",
  "000002_add_xid_constraint.sql": "a27a8e63c79cd055198fa201b1745c85e0cd0e0b75f228b7153571631e529c07",
  "000003_add_origin_permanent_cookie_columns.sql": "0d7f27facfecff1327573d3e1a5f65a3277ea94a30bcd8692606f00a7e496d3d",
  "000004_drop_waitinglist_table.sql": "f2fc4184a965ffad01913d0e71a806c6f7e2aecc5f59279c11b0cd3ed3a77528",
  "000005_drop_slack_stripe_canvas.sql": "392e5b8aadb7a85767820ec97fcfb0853821d35089be3e8c3dfe70df24782839",
  "000006_update_votes_rule.sql": "8fb05b7b1b6a8b123cea6b2680054d8da2fe48585c51a2f9f108b8b174d85c60",
  "000007_drop_geolocation_fields.sql": "f68b69b86112ad52e2cb79a9b631ea77a0285b24201b41c15d9c13257f7cd9cc",
  "000008_add_comment_priority.sql": "c867b53be3cca6bce059b19ea9eb3950120fb5840a1476af409924ca55905261",
  "000009_add_uuid_to_zinvites.sql": "43f36fe0b8578bc4b32761a2b9d7a5181a8159ff8b0c7bb0a1a73f802ec5f670",
  "000010_create_oidc_user_mappings.sql": "450a3f69883aa56c3bc85994ab1baf5e208634d88435a156fe2a22738b1d9f9a",
  "000011_alter_suzinvites_xid_to_text.sql": "00a1eb2d9604804a56705eaac92bb6d37b6c696abdfd9bb079d4a1c494ff0ab6",
  "000012_create_topic_agenda_selections.sql": "cc513693124f031ce1d55e7e73b14b4e3c40a4070e65465adbc621e63b1008cf",
  "000013_create_treevite.sql": "4b8334f73246c69bc9ecadd4a2dc00c8cfb642351ba70ed4a9a58b882a4ac53f",
  "000014_alter_reports_modlevel.sql": "c2af6d57af2866f1f259bb41b94dbf730eca499a4b18f092c4aeeebce5a95025",
  "000015_add_xid_requirements.sql": "186c904addd0c8a42c10057e6ae362fe2799cc076e877bef3ffa14e9852184e7",
  "000016_add_orig_id.sql": "6cdc0588c000fbbe89d578bc2f0aa60422b92b5320aba737d6d83f89d8d990db",
  "000017_create_byod_job_table.sql": "f27c03a1229f296fab21cee059b743c7137bf502e4178854e596a8efa4808b55",
  "000018_add_topics_enabled.sql": "a1e1c0572064d88877d87142bc4e40132b84672bbe84392e99f9f6f4c2ea107e",
  "000019_add_fncp_provider_allowlist_operations.sql": "bb0b8e035d41563fdf73cda33956030eb9209a47b503cd5a1216ed6886a6dcbd"
});

const fail = () => new Error('Production operator export rejected.');
const integer = value => Number.isSafeInteger(value) && value >= 0;
const object = value => value && Object.getPrototypeOf(value) === Object.prototype;
const sameSet = (actual, expected) => Array.isArray(actual) && actual.length === expected.length
  && new Set(actual).size === expected.length && expected.every(value => actual.includes(value));
const sqlLiteral = value => "'" + value.replaceAll("'", "''") + "'";
const equalNumber = (a, b) => typeof a === 'number' && Number.isFinite(a) && Math.abs(a - b) <= 1e-10;
const CLASSIFICATION = 'PRODUCTION_OPERATOR_AGGREGATE_EXPORT';
/** Fixed query: no caller SQL, identity columns, member maps or individual votes
 * are returned. Identifier comparisons are evaluated privately in the database.
 */
export function operatorSnapshotSql(configuration) {
  const c = validateProductionConfiguration(configuration);
  return [
    'BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;',
    "SET LOCAL search_path=pg_catalog;",
    "SET LOCAL statement_timeout='15000ms';",
    "SET LOCAL idle_in_transaction_session_timeout='15000ms';",
    "SET LOCAL lock_timeout='2000ms';",
    'WITH bound AS (SELECT c.* FROM public.conversations c JOIN public.zinvites z USING(zid)',
    ' WHERE z.zinvite=' + sqlLiteral(c.binding.conversationId) + '),',
    'seed_owner AS (SELECT p.pid,p.uid FROM bound b JOIN public.participants p ON p.zid=b.zid AND p.uid=b.owner JOIN public.users u ON u.uid=p.uid WHERE u.is_owner IS TRUE),',
    'operations AS (SELECT o.* FROM public.fncp_provider_allowlist_operations o WHERE o.zid=(SELECT zid FROM bound)),',
    'latest_history AS (SELECT DISTINCT ON (pid,tid) pid,tid,vote,created FROM public.votes',
    ' WHERE zid=(SELECT zid FROM bound) ORDER BY pid,tid,created DESC),',
    "main AS (SELECT * FROM public.math_main WHERE zid=(SELECT zid FROM bound) AND math_env='dev')",
    'SELECT jsonb_build_object(',
    "'database',current_database(),'role',current_user,",
    "'readOnly',current_setting('transaction_read_only'),'isolation',current_setting('transaction_isolation'),",
    "'snapshotAt',transaction_timestamp(),",
    "'serverMajor',current_setting('server_version_num')::integer/10000,'primary',NOT pg_is_in_recovery(),",
    "'roleSafe',EXISTS(SELECT 1 FROM pg_roles r WHERE r.rolname=current_user AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolinherit AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolreplication AND NOT r.rolbypassrls AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=r.oid) AND NOT EXISTS(SELECT 1 FROM pg_database WHERE datname=current_database() AND datdba=r.oid)) AND session_user=current_user,",
    "'schemaMatches',(SELECT jsonb_object_agg(filename,sha256::text) FROM fncp_deploy.schema_migrations)="+sqlLiteral(JSON.stringify(MIGRATIONS))+"::jsonb,",
    "'conversationRows',(SELECT count(*) FROM public.conversations),'inviteRows',(SELECT count(*) FROM public.zinvites WHERE zid=(SELECT zid FROM bound)),",
    "'tls',(SELECT jsonb_build_object('ssl',ssl,'version',version,'bits',bits) FROM pg_stat_ssl WHERE pid=pg_backend_pid()),",
    "'boundCount',(SELECT count(*) FROM bound),",
    "'conversation',(SELECT jsonb_build_object('code'," + sqlLiteral(c.binding.conversationId) + ",'closed',NOT is_active,'gated',use_xid_whitelist,'dataOpen',is_data_open,'private',NOT is_public,'xidRequired',xid_required,'strictModeration',strict_moderation,'suggestionsDisabled',write_type=0 AND topics_enabled=false AND treevite_enabled=false) FROM bound),",
    "'participantRows',(SELECT count(*) FROM public.participants WHERE zid=(SELECT zid FROM bound)),",
    "'identities',(SELECT count(DISTINCT uid) FROM public.participants WHERE zid=(SELECT zid FROM bound)),",
    "'identifiedRows',(SELECT count(uid) FROM public.participants WHERE zid=(SELECT zid FROM bound)),",
    "'cohort',jsonb_build_object(",
    "'registrations',(SELECT count(*) FROM operations),'present',(SELECT count(*) FROM operations WHERE operation_version=1 AND desired_present IS TRUE),'revoked',(SELECT count(*) FROM operations WHERE operation_version=2 AND desired_present IS FALSE),",
    "'seedOwnerRows',(SELECT count(*) FROM seed_owner),'seedOwnerVoteEvents',(SELECT count(*) FROM public.votes WHERE zid=(SELECT zid FROM bound) AND pid IN(SELECT pid FROM seed_owner)),",
    "'seedOwnerAuthoredAll',NOT EXISTS(SELECT 1 FROM public.comments cm WHERE cm.zid=(SELECT zid FROM bound) AND NOT EXISTS(SELECT 1 FROM seed_owner s WHERE s.uid=cm.uid AND s.pid=cm.pid)),",
    "'seedOwnerMappingRows',(SELECT count(*) FROM public.xids WHERE uid=(SELECT owner FROM bound)),",
    "'nativeUserRows',(SELECT count(*) FROM public.users),",
    "'unknownUserRows',(SELECT count(*) FROM public.users u WHERE u.uid<>(SELECT owner FROM bound) AND NOT EXISTS(SELECT 1 FROM public.xids x JOIN operations o USING(zid,xid) WHERE x.uid=u.uid AND x.owner=(SELECT owner FROM bound))),",
    "'unknownParticipantRows',(SELECT count(*) FROM public.participants p WHERE p.zid=(SELECT zid FROM bound) AND p.uid<>(SELECT owner FROM bound) AND 1<>(SELECT count(*) FROM public.xids x JOIN operations o USING(zid,xid) WHERE x.zid=p.zid AND x.pid=p.pid AND x.uid=p.uid AND x.owner=(SELECT owner FROM bound))),",
    "'invalidMappingRows',(SELECT count(*) FROM public.xids x WHERE (x.zid IS DISTINCT FROM (SELECT zid FROM bound) OR x.owner IS DISTINCT FROM (SELECT owner FROM bound) OR x.uid=(SELECT owner FROM bound) OR x.xid!~'^fncp_[A-Za-z0-9_-]{16,251}$' OR NOT EXISTS(SELECT 1 FROM operations o WHERE o.zid=x.zid AND o.xid=x.xid) OR (x.pid IS NOT NULL AND NOT EXISTS(SELECT 1 FROM public.participants p WHERE p.zid=x.zid AND p.pid=x.pid AND p.uid=x.uid)))),",
    "'providerStateMatches',NOT EXISTS(SELECT 1 FROM operations o WHERE o.xid!~'^fncp_[A-Za-z0-9_-]{16,251}$' OR (o.operation_version=1 AND o.desired_present IS TRUE AND 1<>(SELECT count(*) FROM public.xid_whitelist w WHERE w.zid=o.zid AND w.xid=o.xid AND w.owner=(SELECT owner FROM bound))) OR (o.operation_version=2 AND o.desired_present IS FALSE AND EXISTS(SELECT 1 FROM public.xid_whitelist w WHERE w.xid=o.xid AND (w.zid=o.zid OR w.owner=(SELECT owner FROM bound)))) OR NOT((o.operation_version=1 AND o.desired_present IS TRUE) OR (o.operation_version=2 AND o.desired_present IS FALSE))) AND NOT EXISTS(SELECT 1 FROM public.xid_whitelist w WHERE (w.zid IS DISTINCT FROM (SELECT zid FROM bound) OR w.owner IS DISTINCT FROM (SELECT owner FROM bound) OR NOT EXISTS(SELECT 1 FROM operations o WHERE o.zid=w.zid AND o.xid=w.xid AND o.operation_version=1 AND o.desired_present IS TRUE)))",
    "),",
    "'voterCount',(SELECT count(DISTINCT pid) FROM public.votes_latest_unique WHERE zid=(SELECT zid FROM bound)),",
    "'latestVoteCount',(SELECT count(*) FROM public.votes_latest_unique WHERE zid=(SELECT zid FROM bound)),",
    "'voteWatermark',(SELECT max(created) FROM public.votes WHERE zid=(SELECT zid FROM bound)),",
    "'moderationWatermark',(SELECT max(modified) FROM public.comments WHERE zid=(SELECT zid FROM bound)),",
    "'invalidVoteEvents',(SELECT count(*) FROM public.votes WHERE zid=(SELECT zid FROM bound) AND (vote IS NULL OR vote NOT IN(-1,0,1) OR created IS NULL)),",
    "'unknownLatestVotes',(SELECT count(*) FROM public.votes_latest_unique v",
    ' LEFT JOIN public.participants p USING(zid,pid) LEFT JOIN public.comments cm ON cm.zid=v.zid AND cm.tid=v.tid',
    ' WHERE v.zid=(SELECT zid FROM bound) AND (p.pid IS NULL OR cm.tid IS NULL OR v.vote IS NULL OR v.vote NOT IN(-1,0,1))),',
    "'ambiguousVoteTimes',EXISTS(SELECT 1 FROM public.votes WHERE zid=(SELECT zid FROM bound)",
    ' GROUP BY pid,tid,created HAVING count(DISTINCT vote)>1),',
    "'latestMatchesHistory',NOT EXISTS(SELECT 1 FROM latest_history h FULL JOIN",
    ' (SELECT pid,tid,vote,modified FROM public.votes_latest_unique WHERE zid=(SELECT zid FROM bound)) v USING(pid,tid)',
    ' WHERE h.pid IS NULL OR v.pid IS NULL OR h.vote IS DISTINCT FROM v.vote OR h.created IS DISTINCT FROM v.modified),',
    "'statements',COALESCE((SELECT jsonb_agg(jsonb_build_object('id',cm.tid,'text',cm.txt,'approved',cm.mod=1,",
    "'active',cm.active,'seed',cm.is_seed,'meta',cm.is_meta,",
    "'agree',(SELECT count(*) FROM public.votes_latest_unique v WHERE v.zid=cm.zid AND v.tid=cm.tid AND v.vote=-1),",
    "'disagree',(SELECT count(*) FROM public.votes_latest_unique v WHERE v.zid=cm.zid AND v.tid=cm.tid AND v.vote=1),",
    "'pass',(SELECT count(*) FROM public.votes_latest_unique v WHERE v.zid=cm.zid AND v.tid=cm.tid AND v.vote=0)",
    ') ORDER BY cm.tid) FROM public.comments cm WHERE cm.zid=(SELECT zid FROM bound)),\'[]\'::jsonb),',
    "'math',(SELECT jsonb_build_object('environment',math_env,'tick',math_tick,'cachingTick',caching_tick,",
    "'rowVoteWatermark',last_vote_timestamp,'dataVoteWatermark',data->'lastVoteTimestamp','dataModWatermark',data->'lastModTimestamp',",
    "'bindingMatches',(data->>'zid')::integer=zid,",
    "'voterMembershipMatches',(SELECT jsonb_agg(pid ORDER BY pid) FROM (SELECT DISTINCT pid FROM public.votes_latest_unique WHERE zid=main.zid) p)=",
    " (SELECT jsonb_agg(value::integer ORDER BY value::integer) FROM jsonb_array_elements_text(data->'in-conv')),",
    "'participants',data->'n','statementCount',data->'n-cmts','statementIds',data->'tids',",
    "'modIn',data->'mod-in','modOut',data->'mod-out','metaIds',data->'meta-tids',",
    "'groupIds',(SELECT jsonb_agg((g->>'id')::integer) FROM jsonb_array_elements(data->'group-clusters') g),",
    "'groupVotes',(SELECT jsonb_object_agg(g.key,jsonb_build_object('n-members',(g.value->>'n-members')::integer,'votes',(SELECT jsonb_object_agg(v.key,jsonb_build_object('A',(v.value->>'A')::integer,'D',(v.value->>'D')::integer,'S',(v.value->>'S')::integer)) FROM jsonb_each(g.value->'votes') v))) FROM jsonb_each(data->'group-votes') g),",
    "'consensus',(SELECT jsonb_object_agg(v.key,(v.value#>>'{}')::double precision) FROM jsonb_each(data->'group-aware-consensus') v)) FROM main),",
    "'mathTick',(SELECT math_tick FROM public.math_ticks WHERE zid=(SELECT zid FROM bound) AND math_env='dev'),",
    "'auxiliary',jsonb_build_array(",
    "(SELECT jsonb_build_object('tick',math_tick,'voteWatermark',data->'lastVoteTimestamp','bindingMatches',(data->>'zid')::integer=zid)",
    " FROM public.math_bidtopid WHERE zid=(SELECT zid FROM bound) AND math_env='dev'),",
    "(SELECT jsonb_build_object('tick',math_tick,'voteWatermark',data->'lastVoteTimestamp','bindingMatches',(data->>'zid')::integer=zid)",
    " FROM public.math_ptptstats WHERE zid=(SELECT zid FROM bound) AND math_env='dev'))",
    ');',
    'ROLLBACK;',
    '',
  ].join('\n');
}

/** Pure fail-closed projection. Extra private properties can never be serialized
 * accidentally: every output property is constructed explicitly here.
 */
function projectSnapshot(configuration, lock, s, seed) {
  const c = validateProductionConfiguration(configuration); lock=validateProductionImageLock(lock);
  const seeds=validateSeeds(c,seed);assertJsonData(s);
  if (lock.sourceRevision !== c.sourceRevision || !object(s)
    || s.database !== c.database.name || s.role !== c.database.migrationRole
    || s.serverMajor !== 17 || s.primary !== true || s.roleSafe !== true || s.schemaMatches !== true
    || s.conversationRows !== 1 || s.inviteRows !== 1
    || s.readOnly !== 'on' || s.isolation !== 'repeatable read'
    || !object(s.tls) || s.tls.ssl !== true || !['TLSv1.2','TLSv1.3'].includes(s.tls.version) || !integer(s.tls.bits) || s.tls.bits < 128
    || s.boundCount !== 1 || s.conversation?.code !== c.binding.conversationId
    || s.conversation?.private !== true || s.conversation?.xidRequired !== true
    || s.conversation?.strictModeration !== true || s.conversation?.suggestionsDisabled !== true
    || s.conversation?.closed !== true || s.conversation?.gated !== true || s.conversation?.dataOpen !== false
    || !integer(s.participantRows) || s.participantRows > 21 || s.participantRows < 2
    || s.identities !== s.participantRows || s.identifiedRows !== s.participantRows
    || !integer(s.voterCount) || s.voterCount < 2 || s.voterCount > 20 || s.voterCount > s.identities-1
    || !integer(s.latestVoteCount) || s.latestVoteCount < 1 || s.latestVoteCount > 300
    || !integer(s.voteWatermark) || s.voteWatermark < 1 || !integer(s.moderationWatermark) || s.moderationWatermark < 1
    || s.invalidVoteEvents !== 0 || s.unknownLatestVotes !== 0 || s.ambiguousVoteTimes !== false || s.latestMatchesHistory !== true
    || typeof s.snapshotAt !== 'string' || !Number.isFinite(Date.parse(s.snapshotAt))
    || !Array.isArray(s.statements) || !sameSet(s.statements.map(x => x.id), c.binding.statementIds)) throw fail();
  const cohort=s.cohort;
  if(!object(cohort)||!integer(cohort.registrations)||cohort.registrations<2||cohort.registrations>20
    ||!integer(cohort.present)||!integer(cohort.revoked)||cohort.present+cohort.revoked!==cohort.registrations
    ||cohort.seedOwnerRows!==1||cohort.seedOwnerVoteEvents!==0||cohort.seedOwnerAuthoredAll!==true||cohort.seedOwnerMappingRows!==0
    ||!integer(cohort.nativeUserRows)||cohort.nativeUserRows<s.participantRows||cohort.nativeUserRows>cohort.registrations+1
    ||cohort.unknownUserRows!==0||cohort.unknownParticipantRows!==0||cohort.invalidMappingRows!==0||cohort.providerStateMatches!==true
    ||s.identities-1>cohort.registrations)throw fail();
  const m = s.math;
  if (!object(m) || m.environment !== 'dev' || !integer(m.tick) || m.tick !== s.mathTick
    || !integer(m.cachingTick) || m.cachingTick < 1 || m.bindingMatches !== true || m.voterMembershipMatches !== true
    || m.rowVoteWatermark !== s.voteWatermark || m.dataVoteWatermark !== s.voteWatermark || m.dataModWatermark !== s.moderationWatermark
    || m.participants !== s.voterCount || m.statementCount !== 15
    || !sameSet(m.statementIds, c.binding.statementIds) || !sameSet(m.modIn, c.binding.statementIds)
    || !sameSet(m.modOut, []) || !sameSet(m.metaIds, [])
    || !Array.isArray(s.auxiliary) || s.auxiliary.length !== 2 || s.auxiliary.some(x => !object(x)
      || x.tick !== m.tick || x.voteWatermark !== s.voteWatermark || x.bindingMatches !== true)
    || !Array.isArray(m.groupIds) || m.groupIds.length < 2 || m.groupIds.length > 5
    || !m.groupIds.every(integer) || new Set(m.groupIds).size !== m.groupIds.length
    || !object(m.groupVotes) || !sameSet(Object.keys(m.groupVotes), m.groupIds.map(String))
    || !object(m.consensus) || !sameSet(Object.keys(m.consensus), c.binding.statementIds.map(String))) throw fail();
  const groups = m.groupIds.map(id => m.groupVotes[id]);
  if (groups.some(g => !object(g) || !integer(g['n-members']) || g['n-members'] < 1 || g['n-members'] > 20
      || !object(g.votes) || !sameSet(Object.keys(g.votes), c.binding.statementIds.map(String)))
    || groups.reduce((sum, g) => sum + g['n-members'], 0) !== s.voterCount) throw fail();
  let total = 0;
  const statements = [...s.statements].sort((a,b) => a.id-b.id).map(statement => {
    if (statement.text!==seeds[c.binding.statementIds.indexOf(statement.id)] || statement.approved !== true || statement.active !== true || statement.seed !== true || statement.meta !== false
      || typeof statement.text !== 'string' || !statement.text.trim() || Buffer.byteLength(statement.text) > 10_000
      || !['agree','disagree','pass'].every(k => integer(statement[k])) || statement.agree + statement.disagree + statement.pass > s.voterCount) throw fail();
    let agree = 0; let disagree = 0; let seen = 0; let consensus = 1;
    for (const group of groups) {
      const v = group.votes[statement.id];
      if (!object(v) || !['A','D','S'].every(k => integer(v[k])) || v.S > group['n-members'] || v.A + v.D > v.S) throw fail();
      agree += v.A; disagree += v.D; seen += v.S; consensus *= (v.A + 1) / (v.S + 2);
    }
    if (agree !== statement.agree || disagree !== statement.disagree || seen-agree-disagree !== statement.pass
      || !equalNumber(m.consensus[statement.id], consensus)) throw fail();
    total += seen;
    return { statementId: statement.id, text: statement.text, agree, disagree, pass: seen-agree-disagree,
      nativeGroupAwareConsensus: m.consensus[statement.id] };
  });
  if (total !== s.latestVoteCount) throw fail();
  return {
    version: 1, classification: CLASSIFICATION, authorization: 'EXTERNAL_PRIVATE_OPERATOR_CUSTODY_REQUIRED',
    scope: 'CLOSED_PRODUCTION_ROUND', oidcStaffAuthorizationImplemented: false,
    source: { revision: c.sourceRevision, fingerprint: lock.sourceFingerprint, images: { ...lock.images },
      bindingSha256: sha256(JSON.stringify(c.binding)), seedSha256: seed.seedSha256 },
    snapshot: { at: new Date(s.snapshotAt).toISOString(), isolation: 'repeatable read', readOnly: true,
      postgresTls: true, mathEnvironment: 'dev', voteCreatedWatermark: s.voteWatermark,
      moderationModifiedWatermark: s.moderationWatermark, mathTick: m.tick, cachingTick: m.cachingTick },
    aggregate: { nativeIdentities: s.identities, seedOwnersWithoutVotes: 1, nativeParticipantIdentities: s.identities-1,
      providerRegistrations: cohort.registrations, providerPresent: cohort.present, providerRevoked: cohort.revoked, voters: s.voterCount, statements: 15, latestVotes: s.latestVoteCount,
      groupSizes: groups.map(g => g['n-members']).sort((a,b) => a-b) },
    consensusDefinition: 'Native Pol.is product across groups of (agree + 1) / (seen + 2); not a percentage.',
    statements,
  };
}

function assertJsonData(value){
  let nodes=0,bytes=0;
  function walk(v,depth){
    if(++nodes>10000||depth>16)throw fail();
    if(v===null||typeof v==='boolean')return;
    if(typeof v==='string'){bytes+=Buffer.byteLength(v);if(bytes>262144)throw fail();return;}
    if(typeof v==='number'){if(!Number.isFinite(v)||Object.is(v,-0))throw fail();return;}
    if(typeof v!=='object'||![Object.prototype,Array.prototype].includes(Object.getPrototypeOf(v)))throw fail();
    const ds=Object.getOwnPropertyDescriptors(v),keys=Reflect.ownKeys(ds);
    if(keys.some(k=>typeof k!=='string')||Object.values(ds).some(d=>!Object.hasOwn(d,'value')))throw fail();
    if(Array.isArray(v)&&(Object.keys(v).length!==v.length||keys.length!==v.length+1
      ||keys.some(k=>k!=='length'&&(!/^(0|[1-9][0-9]*)$/u.test(k)||Number(k)>=v.length))
      ||Array.from({length:v.length},(_,i)=>String(i)).some(k=>!Object.hasOwn(v,k))))throw fail();
    for(const key of keys)if(key!=='length'||!Array.isArray(v))walk(ds[key].value,depth+1);
  }
  walk(value,0);
}
function validateSeeds(c,seed){
  assertJsonData(seed);
  if(!object(seed)||Reflect.ownKeys(seed).length!==2||!Object.hasOwn(seed,'statements')||!Object.hasOwn(seed,'seedSha256')
    ||!Array.isArray(seed.statements)||seed.statements.length!==15||new Set(seed.statements).size!==15
    ||seed.statements.some(s=>typeof s!=='string'||!s.trim()||[...s].length>1000||Buffer.byteLength(s)>4000||/[\u0000\uD800-\uDFFF]/u.test(s))
    ||typeof seed.seedSha256!=='string'||!/^[a-f0-9]{64}$/u.test(seed.seedSha256)||sha256(JSON.stringify(seed.statements))!==seed.seedSha256
    ||c.binding.statementIds.some((id,i)=>i>0&&id<=c.binding.statementIds[i-1]))throw fail();
  return seed.statements;
}

/** Call only with the single result from the exact fixed query after a successful
 * read-only transaction/exit0 through a custody-checked verify-full runner.
 * The supplied snapshot is evidence data, not a signed or branded DB receipt.
 */
export function aggregateOperatorSnapshot(configuration,lock,snapshot,seed){
  try{return freeze(projectSnapshot(configuration,lock,snapshot,seed));}catch{throw fail();}
}
