import { createHash } from 'node:crypto';
import { validateProductionConfiguration } from './compose.mjs';

const denied = () => new Error('Native round maintenance rejected.');
const plans = new WeakSet();
const hash = value => createHash('sha256').update(value).digest('hex');
const freeze = value => { if (value && typeof value === 'object') { for (const child of Object.values(value)) freeze(child); Object.freeze(value); } return value; };
function exact(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || ![Object.prototype,null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value,key))
    || Object.values(Object.getOwnPropertyDescriptors(value)).some(descriptor => !Object.hasOwn(descriptor,'value'))) throw denied();
}
function strings(value) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length !== 15
    || Reflect.ownKeys(value).length !== 16 || Object.keys(value).length !== 15
    || Array.from({length:15},(_,index)=>String(index)).some(key=>!Object.hasOwn(value,key))
    || Object.values(Object.getOwnPropertyDescriptors(value)).some(descriptor => !Object.hasOwn(descriptor,'value'))
    || value.some(text => typeof text !== 'string' || !text.trim() || [...text].length > 1000
      || Buffer.byteLength(text) > 4000 || /[\u0000\uD800-\uDFFF]/u.test(text)) || new Set(value).size !== 15) throw denied();
  return [...value];
}

// Review/update this source constant when an immutable top-level migration
// changes. Tests compare all twenty filenames and bytes against source.
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
const BEGIN = "BEGIN ISOLATION LEVEL SERIALIZABLE;\nSET LOCAL search_path=pg_catalog;\nSET LOCAL statement_timeout='15s';\nSET LOCAL lock_timeout='2s';\nSET LOCAL idle_in_transaction_session_timeout='15s';";
const BIND = "SELECT pg_catalog.length(pg_catalog.set_config('fncp.native_round_input', $1, true)) AS fncp_input_length;";
const MUTATE = `DO $fncp_native_round$
DECLARE
  input jsonb := pg_catalog.current_setting('fncp.native_round_input', true)::jsonb;
  round public.conversations%ROWTYPE;
  expected_active boolean;
  changed_rows integer;
  actual_ids jsonb;
  actual_texts jsonb;
BEGIN
  IF input IS NULL OR input->>'operation' NOT IN ('open','close')
    OR pg_catalog.current_database() IS DISTINCT FROM input->>'database'
    OR current_user::text IS DISTINCT FROM input->>'migrationRole'
    OR session_user::text IS DISTINCT FROM current_user::text
    OR pg_catalog.current_setting('transaction_isolation') <> 'serializable'
    OR pg_catalog.current_setting('transaction_read_only') <> 'off'
    OR pg_catalog.pg_is_in_recovery()
    OR pg_catalog.current_setting('server_version_num')::integer NOT BETWEEN 170000 AND 179999
    OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_stat_ssl
      WHERE pid=pg_catalog.pg_backend_pid() AND ssl IS TRUE AND version IN ('TLSv1.2','TLSv1.3') AND bits>=128)
    OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname=current_user
      AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolinherit AND NOT r.rolcreatedb
      AND NOT r.rolcreaterole AND NOT r.rolreplication AND NOT r.rolbypassrls
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=r.oid)
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_database WHERE datname=current_database() AND datdba=r.oid))
  THEN RAISE EXCEPTION 'FNCP_NATIVE_ROUND_SESSION_REJECTED'; END IF;

  -- Serialize against the existing immutable migration runner before touching
  -- its tracking table. All locks and input data expire with this transaction.
  PERFORM pg_catalog.pg_advisory_xact_lock(1179537232, 1);
  LOCK TABLE fncp_deploy.schema_migrations IN SHARE MODE;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      JOIN pg_catalog.pg_roles r ON r.oid=c.relowner
      WHERE n.nspname='fncp_deploy' AND c.relname='schema_migrations' AND c.relkind='r' AND r.rolname=current_user)
    OR (SELECT pg_catalog.jsonb_object_agg(filename, sha256::text) FROM fncp_deploy.schema_migrations)
       IS DISTINCT FROM input->'migrations'
  THEN RAISE EXCEPTION 'FNCP_NATIVE_ROUND_SCHEMA_REJECTED'; END IF;

  -- Prevent concurrent invite remapping or comment insertion/moderation during
  -- the checks. These bounded locks change no other conversation's records.
  LOCK TABLE public.conversations, public.zinvites, public.comments IN SHARE ROW EXCLUSIVE MODE;
  IF (SELECT count(*) FROM public.conversations) <> 1
    OR (SELECT count(*) FROM public.zinvites WHERE zinvite=input->>'conversationId') <> 1
  THEN RAISE EXCEPTION 'FNCP_NATIVE_ROUND_BINDING_REJECTED'; END IF;
  SELECT c.* INTO STRICT round FROM public.conversations c JOIN public.zinvites z USING(zid)
    WHERE z.zinvite=input->>'conversationId' FOR UPDATE OF c,z;
  IF (SELECT count(*) FROM public.zinvites WHERE zid=round.zid) <> 1
  THEN RAISE EXCEPTION 'FNCP_NATIVE_ROUND_BINDING_REJECTED'; END IF;
  SELECT pg_catalog.jsonb_agg(tid ORDER BY tid), pg_catalog.jsonb_agg(txt ORDER BY tid)
    INTO actual_ids,actual_texts FROM public.comments WHERE zid=round.zid;
  IF actual_ids IS DISTINCT FROM input->'statementIds' OR actual_texts IS DISTINCT FROM input->'statements'
  THEN RAISE EXCEPTION 'FNCP_NATIVE_ROUND_SEEDS_REJECTED'; END IF;

  expected_active := input->>'operation'='open';
  IF expected_active AND (
      round.is_active IS DISTINCT FROM false OR round.is_public IS DISTINCT FROM false
      OR round.is_data_open IS DISTINCT FROM false OR round.use_xid_whitelist IS DISTINCT FROM true
      OR round.xid_required IS DISTINCT FROM true OR round.is_anon IS DISTINCT FROM true
      OR round.is_draft IS DISTINCT FROM false OR round.strict_moderation IS DISTINCT FROM true
      OR round.profanity_filter IS DISTINCT FROM false OR round.spam_filter IS DISTINCT FROM false
      OR round.topics_enabled IS DISTINCT FROM false OR round.treevite_enabled IS DISTINCT FROM false
      OR round.write_type IS DISTINCT FROM 0 OR round.vis_type IS DISTINCT FROM 0
      OR round.owner IS NULL OR round.org_id IS NULL
      OR EXISTS (SELECT 1 FROM public.comments WHERE zid=round.zid
        AND (active IS DISTINCT FROM true OR is_seed IS DISTINCT FROM true
          OR mod IS DISTINCT FROM 1 OR is_meta IS DISTINCT FROM false)))
  THEN RAISE EXCEPTION 'FNCP_NATIVE_ROUND_OPENING_REJECTED'; END IF;

  -- Close still works after a privacy/moderation flag drifts. It retains the
  -- exact database, schema, conversation, statement IDs and text binding.
  UPDATE public.conversations SET is_active=expected_active
    WHERE zid=round.zid AND is_active IS DISTINCT FROM expected_active;
  GET DIAGNOSTICS changed_rows=ROW_COUNT;
  IF changed_rows NOT BETWEEN 0 AND 1 OR (expected_active AND changed_rows<>1)
    OR (SELECT is_active FROM public.conversations WHERE zid=round.zid) IS DISTINCT FROM expected_active
  THEN RAISE EXCEPTION 'FNCP_NATIVE_ROUND_POSTCONDITION_REJECTED'; END IF;
  PERFORM pg_catalog.set_config('fncp.native_round_result',pg_catalog.jsonb_build_object(
    'profile','FNCP_NATIVE_ROUND_V1','operation',input->>'operation',
    'deployment',input->>'deployment','conversationId',input->>'conversationId',
    'seedSha256',input->>'seedSha256','statementCount',15,'isActive',expected_active,
    'changed',changed_rows=1,'participantAdmissionActivated',false)::text,true);
END
$fncp_native_round$;`;
const RESULT = "SELECT pg_catalog.current_setting('fncp.native_round_result')::jsonb AS native_round_result;";

/** Pure fixed-operation plan. The only parameter is public JSON data. No
 * database client, credential, filesystem, process or arbitrary SQL is accepted.
 * statements is the same ordered string array used by participant activation.
 */
export function nativeRoundMaintenance(configuration, request) {
  try {
    const c=validateProductionConfiguration(configuration);
    exact(request,['operation','statements','seedSha256']);
    if (!['open','close'].includes(request.operation) || typeof request.seedSha256 !== 'string'
      || !/^[a-f0-9]{64}$/u.test(request.seedSha256)
      || c.binding.statementIds.some((id,index)=>index>0 && id<=c.binding.statementIds[index-1])) throw denied();
    const statements=strings(request.statements);
    // Canonical JSON of an array of strings is exactly JSON.stringify(array),
    // matching production-service's sha(canonical(c.statements)).
    if (hash(JSON.stringify(statements)) !== request.seedSha256) throw denied();
    const binding={deployment:c.deployment,conversationId:c.binding.conversationId,
      statementIds:[...c.binding.statementIds],seedSha256:request.seedSha256};
    const payload=JSON.stringify({...binding,operation:request.operation,database:c.database.name,
      migrationRole:c.database.migrationRole,statements,migrations:MIGRATIONS});
    const queries=[{text:BEGIN,values:[]},{text:BIND,values:[payload]},{text:MUTATE,values:[]},
      {text:RESULT,values:[]},{text:'COMMIT;',values:[]}];
    const encoded=Buffer.from(payload,'utf8').toString('base64');
    const psqlBind=BIND.replace('$1',"pg_catalog.convert_from(pg_catalog.decode(:'fncp_round_payload','base64'),'UTF8')").replace(/;$/u,'')+'\n\\gset';
    const psqlInput=["\\set ON_ERROR_STOP on","\\set QUIET on","\\set fncp_round_payload '"+encoded+"'",
      BEGIN,psqlBind,MUTATE,RESULT,'COMMIT;',''].join('\n');
    const plan=freeze({profile:'FNCP_NATIVE_ROUND_V1',operation:request.operation,binding,
      requiresVerifiedTlsMaintenanceRunner:true,participantAdmissionActivated:false,
      queries,psql:{arguments:['-X','--no-psqlrc','--quiet','--no-align','--tuples-only','--no-password','--set=ON_ERROR_STOP=1'],stdin:psqlInput}});
    plans.add(plan);return plan;
  } catch { throw denied(); }
}

/** Accept a receipt only after the caller observes successful COMMIT / psql
 * exit0. This validates its shape and operation binding, not who executed SQL.
 */
export function validateNativeRoundReceipt(plan, receipt) {
  try {
    if(!plans.has(plan))throw denied();
    exact(receipt,['profile','operation','deployment','conversationId','seedSha256','statementCount','isActive','changed','participantAdmissionActivated']);
    if (plan?.profile!=='FNCP_NATIVE_ROUND_V1' || receipt.profile!==plan.profile || receipt.operation!==plan.operation
      || receipt.deployment!==plan.binding.deployment || receipt.conversationId!==plan.binding.conversationId
      || receipt.seedSha256!==plan.binding.seedSha256 || receipt.statementCount!==15
      || receipt.isActive!==(plan.operation==='open') || typeof receipt.changed!=='boolean'
      || plan.operation==='open' && receipt.changed!==true || receipt.participantAdmissionActivated!==false) throw denied();
    return freeze(structuredClone(receipt));
  } catch { throw denied(); }
}
