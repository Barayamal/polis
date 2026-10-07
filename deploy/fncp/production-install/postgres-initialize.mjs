/** Fresh PostgreSQL maintenance candidate. Pure plans only: importing or calling
 * this module does not run SQL, start an engine, inspect material or publish ports.
 * Reuses the reviewed role initializer, migration image and normal configuration.
 * The caller owns exclusive resource creation, custody, execution and evidence. */
import { isProxy } from 'node:util/types';
import { renderProductionCompose, validateProductionConfiguration } from '../production-deployment/compose.mjs';
import { nativeRoundMaintenance } from '../production-deployment/native-round.mjs';

export const PROFILE = 'FNCP_FRESH_POSTGRES_INITIALIZE_V1';
const denied = () => new Error('Fresh PostgreSQL initialization rejected.');
const plans = new WeakSet();
const freeze = value => { if (value && typeof value === 'object') { for (const child of Object.values(value)) freeze(child); Object.freeze(value); } return value; };
function exact(value, keys) {
  if (!value || typeof value !== 'object' || isProxy(value) || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value)) || Reflect.ownKeys(value).length !== keys.length
    || keys.some(key => !Object.hasOwn(value, key))
    || Object.values(Object.getOwnPropertyDescriptors(value)).some(d => !Object.hasOwn(d, 'value'))) throw denied();
}
function data(value, seen=new Set(), depth=0) {
  if (depth>32 || isProxy(value)) throw denied();
  if (!value || typeof value!=='object') return;
  if (seen.has(value) || ![Object.prototype,null,Array.prototype].includes(Object.getPrototypeOf(value))) throw denied();
  seen.add(value);
  for (const [key,descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
    if (!Object.hasOwn(descriptor,'value')) throw denied();
    if (Array.isArray(value) && key!=='length' && !/^(0|[1-9][0-9]*)$/u.test(key)) throw denied();
    data(descriptor.value,seen,depth+1);
  }
  seen.delete(value);
}
function text(value, limit) {
  if (typeof value !== 'string' || !value.trim() || [...value].length > limit
    || Buffer.byteLength(value) > 4 * limit || /[\u0000\uD800-\uDFFF]/u.test(value)) throw denied();
  return value;
}

// The original role initializer creates PGDATA only after this stronger empty
// parent check. It never adopts a PG_VERSION/partial cluster on a repeat attempt.
// No shell arguments or caller-supplied path are interpolated into this wrapper.
export const FRESH_VOLUME_GUARD = `set -eu
umask 077
fail() { printf '%s\\n' 'FNCP_FRESH_POSTGRES_VOLUME_REJECTED' >&2; exit 1; }
[ "$#" -eq 0 ] || fail
[ "$(id -u):$(id -g)" = '70:70' ] || fail
root=/var/lib/postgresql/data
[ -d "$root" ] && [ ! -L "$root" ] || fail
[ "$(stat -c '%u:%g:%a' "$root")" = '70:70:700' ] || fail
[ -z "$(find "$root" -mindepth 1 -maxdepth 1 -print -quit)" ] || fail
exec /usr/local/bin/fncp-initialize-database initialize
`;

const BEGIN = "BEGIN ISOLATION LEVEL SERIALIZABLE;\nSET LOCAL search_path=pg_catalog,public;\nSET LOCAL statement_timeout='15s';\nSET LOCAL lock_timeout='2s';\nSET LOCAL idle_in_transaction_session_timeout='15s';";
const BIND = "SELECT pg_catalog.length(pg_catalog.set_config('fncp.fresh_postgres_input',$1,true)) AS fncp_input_length;";
const SEED = `DO $fncp_fresh_postgres$
DECLARE
  input jsonb := pg_catalog.current_setting('fncp.fresh_postgres_input',true)::jsonb;
  relation record;
  has_rows boolean;
  owner_uid integer;
  round_zid integer;
  owner_pid integer;
  item record;
  actual_ids jsonb;
  actual_texts jsonb;
BEGIN
  IF input IS NULL OR input->>'profile' <> 'FNCP_FRESH_POSTGRES_INITIALIZE_V1'
    OR pg_catalog.current_database() IS DISTINCT FROM input->>'database'
    OR current_user::text IS DISTINCT FROM input->>'migrationRole'
    OR session_user::text IS DISTINCT FROM current_user::text
    OR pg_catalog.current_setting('transaction_isolation') <> 'serializable'
    OR pg_catalog.current_setting('transaction_read_only') <> 'off'
    OR pg_catalog.pg_is_in_recovery()
    OR pg_catalog.current_setting('server_version_num')::integer NOT BETWEEN 170000 AND 179999
    OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_stat_ssl WHERE pid=pg_catalog.pg_backend_pid()
      AND ssl IS TRUE AND version IN ('TLSv1.2','TLSv1.3') AND bits>=128)
    OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname=current_user
      AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolinherit AND NOT r.rolcreatedb
      AND NOT r.rolcreaterole AND NOT r.rolreplication AND NOT r.rolbypassrls
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=r.oid)
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_database WHERE datname=current_database() AND datdba=r.oid))
    OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname=input->>'mathRole'
      AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolinherit AND NOT r.rolcreatedb
      AND NOT r.rolcreaterole AND NOT r.rolreplication AND NOT r.rolbypassrls
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=r.oid)
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_database WHERE datname=current_database() AND datdba=r.oid)
      AND NOT pg_catalog.has_database_privilege(r.oid,current_database(),'CREATE')
      AND NOT pg_catalog.has_database_privilege(r.oid,current_database(),'TEMPORARY')
      AND NOT pg_catalog.has_schema_privilege(r.oid,'public','CREATE'))
  THEN RAISE EXCEPTION 'FNCP_FRESH_POSTGRES_SESSION_REJECTED'; END IF;

  PERFORM pg_catalog.pg_advisory_xact_lock(1179537232,1);
  LOCK TABLE fncp_deploy.schema_migrations IN SHARE MODE;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      JOIN pg_catalog.pg_roles r ON r.oid=c.relowner WHERE n.nspname='fncp_deploy'
      AND c.relname='schema_migrations' AND c.relkind='r' AND r.rolname=current_user)
    OR (SELECT pg_catalog.jsonb_object_agg(filename,sha256::text) FROM fncp_deploy.schema_migrations)
      IS DISTINCT FROM input->'migrations'
    OR EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' AND (c.relkind NOT IN ('r','i','S') OR c.relowner<>(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)))
    OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
      WHERE n.nspname='public' AND (p.prosecdef OR p.proowner<>(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)))
  THEN RAISE EXCEPTION 'FNCP_FRESH_POSTGRES_SCHEMA_REJECTED'; END IF;

  -- Every public base table must be empty, not merely the expected round tables.
  -- Catalog names are identifier-quoted, never executable input from the plan.
  -- All table locks remain held until COMMIT; a retry after seeding rejects.
  FOR relation IN SELECT c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' AND c.relkind='r' ORDER BY c.relname
  LOOP
    EXECUTE pg_catalog.format('LOCK TABLE public.%I IN ACCESS EXCLUSIVE MODE',relation.relname);
    EXECUTE pg_catalog.format('SELECT EXISTS(SELECT 1 FROM public.%I)',relation.relname) INTO has_rows;
    IF has_rows THEN RAISE EXCEPTION 'FNCP_FRESH_POSTGRES_NOT_EMPTY'; END IF;
  END LOOP;

  -- Fresh math starts with schema USAGE only. Grants below must not preserve
  -- accidental pre-existing DML/sequence/function privileges or PUBLIC access.
  IF EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      CROSS JOIN (VALUES('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),('REFERENCES'),('TRIGGER')) AS p(privilege)
      WHERE n.nspname='public' AND c.relkind='r' AND pg_catalog.has_table_privilege(input->>'mathRole',c.oid,p.privilege))
    OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      CROSS JOIN (VALUES('USAGE'),('SELECT'),('UPDATE')) AS p(privilege)
      WHERE n.nspname='public' AND c.relkind='S' AND pg_catalog.has_sequence_privilege(input->>'mathRole',c.oid,p.privilege))
    OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
      WHERE n.nspname='public' AND pg_catalog.has_function_privilege(input->>'mathRole',p.oid,'EXECUTE'))
    OR pg_catalog.has_schema_privilege(input->>'mathRole','fncp_deploy','USAGE')
  THEN RAISE EXCEPTION 'FNCP_FRESH_POSTGRES_MATH_ACL_REJECTED'; END IF;

  -- An internal seed author only: no email, password, OIDC mapping or XID.
  INSERT INTO public.users(hname,username,email,is_owner)
    VALUES('FNCP seed author','fncp-seed-author',NULL,true) RETURNING uid INTO owner_uid;
  INSERT INTO public.conversations(owner,org_id,topic,description,is_active,is_public,is_data_open,
    use_xid_whitelist,xid_required,is_anon,is_draft,strict_moderation,profanity_filter,spam_filter,
    topics_enabled,treevite_enabled,write_type,vis_type)
    VALUES(owner_uid,owner_uid,input->>'topic',input->>'description',false,false,false,true,true,
      true,false,true,false,false,false,false,0,0) RETURNING zid INTO round_zid;
  INSERT INTO public.zinvites(zid,zinvite) VALUES(round_zid,input->>'conversationId');
  INSERT INTO public.participants(uid,zid) VALUES(owner_uid,round_zid) RETURNING pid INTO owner_pid;
  IF owner_pid<>0 THEN RAISE EXCEPTION 'FNCP_FRESH_POSTGRES_SEED_AUTHOR_REJECTED'; END IF;
  FOR item IN SELECT value,ordinality FROM pg_catalog.jsonb_array_elements_text(input->'statements') WITH ORDINALITY ORDER BY ordinality
  LOOP
    INSERT INTO public.comments(zid,pid,uid,txt,is_seed,mod,is_meta,active)
      VALUES(round_zid,owner_pid,owner_uid,item.value,true,1,false,true);
  END LOOP;

  -- Same narrowly scoped math grants as the reviewed selfhost initializer.
  EXECUTE pg_catalog.format('GRANT USAGE ON SCHEMA public TO %I',input->>'mathRole');
  EXECUTE pg_catalog.format('GRANT SELECT ON public.votes,public.comments TO %I',input->>'mathRole');
  EXECUTE pg_catalog.format('GRANT SELECT,INSERT,UPDATE ON public.math_ticks,public.math_main,public.math_profile,public.math_ptptstats,public.math_bidtopid TO %I',input->>'mathRole');
  EXECUTE pg_catalog.format('GRANT EXECUTE ON FUNCTION public.now_as_millis() TO %I',input->>'mathRole');

  IF EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      CROSS JOIN (VALUES('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),('REFERENCES'),('TRIGGER')) AS p(privilege)
      WHERE n.nspname='public' AND c.relkind='r'
      AND pg_catalog.has_table_privilege(input->>'mathRole',c.oid,p.privilege) IS DISTINCT FROM
        ((c.relname IN ('votes','comments') AND p.privilege='SELECT')
          OR (c.relname IN ('math_ticks','math_main','math_profile','math_ptptstats','math_bidtopid') AND p.privilege IN ('SELECT','INSERT','UPDATE'))))
    OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
      WHERE n.nspname='public' AND pg_catalog.has_function_privilege(input->>'mathRole',p.oid,'EXECUTE')
        IS DISTINCT FROM (p.oid='public.now_as_millis()'::regprocedure))
  THEN RAISE EXCEPTION 'FNCP_FRESH_POSTGRES_MATH_ACL_POSTCONDITION_REJECTED'; END IF;

  SELECT pg_catalog.jsonb_agg(tid ORDER BY tid),pg_catalog.jsonb_agg(txt ORDER BY tid)
    INTO actual_ids,actual_texts FROM public.comments WHERE zid=round_zid;
  IF actual_ids IS DISTINCT FROM input->'statementIds' OR actual_texts IS DISTINCT FROM input->'statements'
    OR (SELECT count(*) FROM public.conversations)<>1 OR (SELECT count(*) FROM public.users)<>1
    OR (SELECT count(*) FROM public.zinvites)<>1 OR (SELECT count(*) FROM public.participants)<>1
    OR (SELECT count(*) FROM public.comments)<>15
    OR EXISTS(SELECT 1 FROM public.votes) OR EXISTS(SELECT 1 FROM public.xids)
    OR EXISTS(SELECT 1 FROM public.xid_whitelist) OR EXISTS(SELECT 1 FROM public.oidc_user_mappings)
    OR EXISTS(SELECT 1 FROM public.suzinvites) OR EXISTS(SELECT 1 FROM public.treevite_invites)
    OR EXISTS(SELECT 1 FROM public.fncp_provider_allowlist_operations)
    OR EXISTS(SELECT 1 FROM public.comments WHERE active IS DISTINCT FROM true OR is_seed IS DISTINCT FROM true
      OR mod IS DISTINCT FROM 1 OR is_meta IS DISTINCT FROM false OR uid<>owner_uid OR pid<>owner_pid)
    OR NOT EXISTS(SELECT 1 FROM public.conversations WHERE zid=round_zid AND owner=owner_uid AND org_id=owner_uid
      AND is_active IS FALSE AND is_public IS FALSE AND is_data_open IS FALSE AND use_xid_whitelist IS TRUE
      AND xid_required IS TRUE AND is_anon IS TRUE AND is_draft IS FALSE AND strict_moderation IS TRUE
      AND profanity_filter IS FALSE AND spam_filter IS FALSE AND topics_enabled IS FALSE AND treevite_enabled IS FALSE
      AND write_type=0 AND vis_type=0)
  THEN RAISE EXCEPTION 'FNCP_FRESH_POSTGRES_POSTCONDITION_REJECTED'; END IF;
  PERFORM pg_catalog.set_config('fncp.fresh_postgres_result',pg_catalog.jsonb_build_object(
    'profile','FNCP_FRESH_POSTGRES_INITIALIZE_V1','deployment',input->>'deployment',
    'conversationId',input->>'conversationId','seedSha256',input->>'seedSha256',
    'statementCount',15,'seedAuthors',1,'participantAccounts',0,'votes',0,
    'nativeRoundOpen',false,'participantAdmissionActivated',false)::text,true);
END
$fncp_fresh_postgres$;`;
const RESULT = "SELECT pg_catalog.current_setting('fncp.fresh_postgres_result')::jsonb AS fresh_postgres_result;";

/** Read/validate only: returns separate maintenance descriptors and data-only SQL.
 * Never merge these initializer commands into the normal startup composition. */
export function postgresInitializationPlan(configuration, imageLock, ownerToken, request) {
  try {
    if (arguments.length !== 4) throw denied();
    data(configuration);data(imageLock);data(request);
    exact(request,['statements','seedSha256','topic','description']);
    const c=validateProductionConfiguration(configuration);
    if (c.binding.statementIds.some((id,index)=>id!==index)) throw denied();
    // Reuse the same text/hash/migration binding as later native open/close.
    const bound=nativeRoundMaintenance(c,{operation:'close',statements:request.statements,seedSha256:request.seedSha256});
    const original=JSON.parse(bound.queries[1].values[0]);
    const normal=renderProductionCompose(c,imageLock,ownerToken);
    const initialize=structuredClone(normal.services.postgres);
    delete initialize.networks;delete initialize.healthcheck;
    initialize.network_mode='none';initialize.profiles=['maintenance'];
    initialize.entrypoint=['/bin/sh'];initialize.command=['-c',FRESH_VOLUME_GUARD];
    const seed=structuredClone(normal.services.migration);
    seed.entrypoint=['/bin/sh'];
    // Password is scoped to libpq's process, never interpolated in argv or SQL.
    seed.command=['-c','set -eu; [ "$PGSSLMODE" = verify-full ] && [ "$FNCP_DATABASE_HOST" = postgres ] && [ "$FNCP_DATABASE_PORT" = 5432 ] && [ "$PGSSLROOTCERT" = /run/fncp/database-ca.pem ] && [ -s "$PGSSLROOTCERT" ] || { printf "%s\\n" FNCP_FRESH_POSTGRES_CLIENT_REJECTED >&2; exit 1; }; export PGHOST="$FNCP_DATABASE_HOST" PGPORT="$FNCP_DATABASE_PORT" PGUSER="$FNCP_EXPECTED_MIGRATION_ROLE" PGDATABASE="$FNCP_EXPECTED_DATABASE" PGPASSWORD="$FNCP_DATABASE_PASSWORD" PGCONNECT_TIMEOUT=10 PGTARGETSESSIONATTRS=read-write; unset FNCP_DATABASE_PASSWORD DATABASE_URL PGOPTIONS PGSERVICE PGSERVICEFILE; exec psql -X --no-psqlrc --quiet --no-align --tuples-only --no-password --set=ON_ERROR_STOP=1'];
    const payload=JSON.stringify({...original,profile:PROFILE,mathRole:c.database.mathRole,
      topic:text(request.topic,1000),description:text(request.description,50000)});
    const psqlBind=BIND.replace('$1',"pg_catalog.convert_from(pg_catalog.decode(:'fncp_fresh_payload','base64'),'UTF8')").replace(/;$/u,'')+'\n\\gset';
    const stdin=["\\set ON_ERROR_STOP on","\\set QUIET on","\\set fncp_fresh_payload '"+Buffer.from(payload).toString('base64')+"'",BEGIN,psqlBind,SEED,RESULT,'COMMIT;',''].join('\n');
    const plan=freeze({profile:PROFILE,binding:bound.binding,
      publishedPorts:0,requiresNewOwnedEmptyVolume:true,requiresStoppedApplicationServices:true,
      nativeRoundOpen:false,participantAdmissionActivated:false,
      maintenance:{initialize,start:normal.services.postgres,migration:normal.services.migration,seed},
      queries:[{text:BEGIN,values:[]},{text:BIND,values:[payload]},{text:SEED,values:[]},{text:RESULT,values:[]},{text:'COMMIT;',values:[]}],
      psql:{arguments:['-X','--no-psqlrc','--quiet','--no-align','--tuples-only','--no-password','--set=ON_ERROR_STOP=1'],stdin}});
    plans.add(plan);return plan;
  } catch { throw denied(); }
}

/** Shape/binding validation only, not an attestation. Caller must independently
 * observe execution exit0/COMMIT and actual persisted state through a new session. */
export function validatePostgresInitializationReceipt(plan,receipt) {
  try {
    if (arguments.length!==2 || !plans.has(plan)) throw denied();
    exact(receipt,['profile','deployment','conversationId','seedSha256','statementCount','seedAuthors',
      'participantAccounts','votes','nativeRoundOpen','participantAdmissionActivated']);
    if (receipt.profile!==PROFILE || receipt.deployment!==plan.binding.deployment
      || receipt.conversationId!==plan.binding.conversationId || receipt.seedSha256!==plan.binding.seedSha256
      || receipt.statementCount!==15 || receipt.seedAuthors!==1 || receipt.participantAccounts!==0 || receipt.votes!==0
      || receipt.nativeRoundOpen!==false || receipt.participantAdmissionActivated!==false) throw denied();
    return freeze(structuredClone(receipt));
  } catch { throw denied(); }
}
