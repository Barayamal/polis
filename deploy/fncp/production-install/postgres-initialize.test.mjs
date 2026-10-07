import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync,readdirSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {postgresInitializationPlan,validatePostgresInitializationReceipt,FRESH_VOLUME_GUARD} from './postgres-initialize.mjs';
import {renderProductionCompose} from '../production-deployment/compose.mjs';

const sha=v=>createHash('sha256').update(v).digest('hex');
const denied={message:'Fresh PostgreSQL initialization rejected.'};
const configuration=()=>({version:1,profile:'FNCP_PRODUCTION_COMPOSE_V1',deployment:'fncp-fresh-postgres-test',platform:'linux/arm64',stateDirectory:'/private/fncp-test/core',sourceRevision:'a'.repeat(40),
  database:{name:'polis',owner:'polis_owner',migrationRole:'polis_migration',runtimeRole:'polis_runtime',mathRole:'polis_math',host:'postgres',port:5432},
  binding:{conversationId:'9freshClosedRound',statementIds:Array.from({length:15},(_,i)=>i)},
  identity:{issuer:'https://issuer.example.invalid/',audience:'configured-client',jwksUri:'https://issuer.example.invalid/jwks'}});
const lock=()=>({version:1,sourceRevision:'a'.repeat(40),sourceFingerprint:'c'.repeat(64),images:Object.fromEntries(['api','math','postgres','migration','participant','wordpress','mariadb','proxy'].map((r,i)=>[r,'sha256:'+String(i+1).repeat(64)]))});
const request=()=>{const statements=Array.from({length:15},(_,i)=>'Reviewed synthetic statement '+i);return {statements,seedSha256:sha(JSON.stringify(statements)),topic:'Closed synthetic round',description:'Local initialization only.'};};
const plan=()=>postgresInitializationPlan(configuration(),lock(),'d'.repeat(48),request());
const receipt=p=>({profile:p.profile,deployment:p.binding.deployment,conversationId:p.binding.conversationId,
  seedSha256:p.binding.seedSha256,statementCount:15,seedAuthors:1,participantAccounts:0,votes:0,nativeRoundOpen:false,participantAdmissionActivated:false});

test('maintenance plan reuses exact normal image/material/volume contract, without normal startup mutation',()=>{
  const c=configuration(),l=lock(),owner='d'.repeat(48),normal=renderProductionCompose(c,l,owner);
  const p=postgresInitializationPlan(c,l,owner,request());
  assert.deepEqual(p.maintenance.start,normal.services.postgres);assert.deepEqual(p.maintenance.migration,normal.services.migration);
  assert.deepEqual(p.maintenance.initialize.volumes,normal.services.postgres.volumes);
  assert.deepEqual(p.maintenance.initialize.environment,normal.services.postgres.environment);
  assert.equal(p.maintenance.initialize.image,l.images.postgres);assert.equal(p.maintenance.seed.image,l.images.migration);
  assert.deepEqual(p.maintenance.initialize.entrypoint,['/bin/sh']);assert.deepEqual(p.maintenance.initialize.command,['-c',FRESH_VOLUME_GUARD]);
  assert.equal(p.maintenance.initialize.network_mode,'none');assert.equal(p.maintenance.initialize.networks,undefined);
  assert.equal(p.maintenance.initialize.healthcheck,undefined);assert.equal(p.maintenance.initialize.user,'70:70');
  assert.deepEqual(p.maintenance.seed.volumes,normal.services.migration.volumes);
  assert.equal(p.publishedPorts,0);assert.equal(p.nativeRoundOpen,false);assert.equal(p.participantAdmissionActivated,false);
  assert.equal(p.requiresNewOwnedEmptyVolume,true);assert.equal(p.requiresStoppedApplicationServices,true);
  assert.deepEqual(renderProductionCompose(c,l,owner),normal);
});

test('fresh guard accepts no path/force input and checks entire parent emptiness and UID/GID/mode',()=>{
  for(const snippet of ['"$#" -eq 0','id -u','id -g','70:70','70:70:700','[ ! -L "$root" ]',
    'find "$root" -mindepth 1 -maxdepth 1 -print -quit','exec /usr/local/bin/fncp-initialize-database initialize']) assert.ok(FRESH_VOLUME_GUARD.includes(snippet),snippet);
  assert.doesNotMatch(FRESH_VOLUME_GUARD,/\b(?:rm|chown|chmod|eval|source|curl|wget)\b/u);
});

test('all request values remain one data parameter including SQL, shell and psql metacharacters',()=>{
  const r=request();r.statements[0]="'; COMMIT; DROP TABLE public.comments; -- \\quit\n$fncp_fresh_postgres$";
  r.statements[1]='Māori 🐬 e\u0301';r.topic='test $(touch /tmp/should-not-run)';r.description="'\\gexec\n;COMMIT";
  r.seedSha256=sha(JSON.stringify(r.statements));const p=postgresInitializationPlan(configuration(),lock(),'d'.repeat(48),r),base=plan();
  assert.deepEqual(p.queries.map(q=>q.text),base.queries.map(q=>q.text));assert.deepEqual(p.maintenance,base.maintenance);
  assert.equal(p.queries.flatMap(q=>q.values).length,1);const payload=JSON.parse(p.queries[1].values[0]);
  assert.deepEqual(payload.statements,r.statements);assert.equal(payload.topic,r.topic);assert.equal(payload.description,r.description);
  assert.equal(p.psql.stdin.includes('DROP TABLE'),false);assert.equal(p.psql.stdin.includes(r.topic),false);
  const encoded=p.psql.stdin.match(/^\\set fncp_fresh_payload '([A-Za-z0-9+/=]+)'$/mu)?.[1];assert.ok(encoded);
  assert.equal(Buffer.from(encoded,'base64').toString(),p.queries[1].values[0]);assert.equal(p.psql.stdin.trim().split('\n').at(-1),'COMMIT;');
});

test('pins current top-level migrations through the reviewed native-round validator',()=>{
  const directory=new URL('../../../server/postgres/migrations/',import.meta.url);
  const expected=Object.fromEntries(readdirSync(directory).filter(n=>n.endsWith('.sql')).sort().map(name=>[name,sha(readFileSync(new URL(name,directory)))]));
  assert.equal(Object.keys(expected).length,20);assert.deepEqual(JSON.parse(plan().queries[1].values[0]).migrations,expected);
});

test('fresh SQL is serializable, TLS/session/role bound and checks all tables before writes',()=>{
  const sql=plan().queries.map(q=>q.text).join('\n');
  for(const snippet of ['SERIALIZABLE',"statement_timeout='15s'","lock_timeout='2s'",'pg_stat_ssl','pg_is_in_recovery',
    'server_version_num','current_user','session_user','rolinherit','rolsuper','rolbypassrls','pg_auth_members',
    'pg_advisory_xact_lock(1179537232,1)','LOCK TABLE fncp_deploy.schema_migrations IN SHARE MODE',
    'ACCESS EXCLUSIVE MODE','FNCP_FRESH_POSTGRES_NOT_EMPTY','FNCP_FRESH_POSTGRES_POSTCONDITION_REJECTED']) assert.ok(sql.includes(snippet),snippet);
  assert.ok(sql.indexOf('FNCP_FRESH_POSTGRES_NOT_EMPTY')<sql.indexOf('INSERT INTO public.users'));
  assert.match(sql,/WHERE n\.nspname='public' AND c\.relkind='r' ORDER BY c\.relname/u);
  assert.match(sql,/pg_catalog\.format\('SELECT EXISTS\(SELECT 1 FROM public\.%I\)'/u);
});

test('creates only credentialless seed author, closed conversation and 15 seed rows, never voter data',()=>{
  const sql=plan().queries[2].text;
  assert.match(sql,/VALUES\('FNCP seed author','fncp-seed-author',NULL,true\)/u);
  assert.deepEqual([...sql.matchAll(/INSERT INTO public\.([a-z_]+)/gu)].map(m=>m[1]),['users','conversations','zinvites','participants','comments']);
  assert.match(sql,/RETURNING uid INTO owner_uid/u);assert.match(sql,/RETURNING zid INTO round_zid/u);
  assert.match(sql,/RETURNING pid INTO owner_pid/u);assert.match(sql,/owner_pid<>0/u);
  for(const field of ['is_active IS FALSE','is_public IS FALSE','is_data_open IS FALSE','use_xid_whitelist IS TRUE',
    'xid_required IS TRUE','strict_moderation IS TRUE','topics_enabled IS FALSE','treevite_enabled IS FALSE','write_type=0 AND vis_type=0'])assert.ok(sql.includes(field),field);
  assert.doesNotMatch(sql,/^\s*(?:UPDATE|DELETE FROM|TRUNCATE|ALTER TABLE)\s/imu);
  assert.match(sql,/'seedAuthors',1,'participantAccounts',0,'votes',0/u);
});

test('math grants are exact limited table/function operations and never role membership or DDL',()=>{
  const sql=plan().queries[2].text;
  assert.deepEqual([...sql.matchAll(/format\('(GRANT [^']+)'/gu)].map(m=>m[1]),[
    'GRANT USAGE ON SCHEMA public TO %I','GRANT SELECT ON public.votes,public.comments TO %I',
    'GRANT SELECT,INSERT,UPDATE ON public.math_ticks,public.math_main,public.math_profile,public.math_ptptstats,public.math_bidtopid TO %I',
    'GRANT EXECUTE ON FUNCTION public.now_as_millis() TO %I']);
  assert.doesNotMatch(sql,/GRANT (?:ALL|CREATE|DELETE|TRUNCATE)/u);
  assert.ok(sql.indexOf('FNCP_FRESH_POSTGRES_MATH_ACL_REJECTED')<sql.indexOf('INSERT INTO public.users'));
  for(const check of ['has_table_privilege','has_sequence_privilege','has_function_privilege','FNCP_FRESH_POSTGRES_MATH_ACL_POSTCONDITION_REJECTED'])assert.ok(sql.includes(check));
});

test('seed maintenance client requires verify-full fixed internal host, preserves CA and avoids password argv',()=>{
  const command=plan().maintenance.seed.command;
  assert.equal(command.length,2);assert.equal(command[0],'-c');
  for(const fragment of ['"$PGSSLMODE" = verify-full','"$FNCP_DATABASE_HOST" = postgres','"$FNCP_DATABASE_PORT" = 5432',
    '"$PGSSLROOTCERT" = /run/fncp/database-ca.pem','--no-password','--set=ON_ERROR_STOP=1','PGCONNECT_TIMEOUT=10',
    'PGTARGETSESSIONATTRS=read-write','unset FNCP_DATABASE_PASSWORD DATABASE_URL PGOPTIONS PGSERVICE PGSERVICEFILE']) assert.ok(command[1].includes(fragment),fragment);
  assert.doesNotMatch(command[1],/psql[^;]*\$FNCP_DATABASE_PASSWORD/u);
});

test('actual shell rejects invalid client configuration before psql without relying on set -e AND-list behavior',()=>{
  for(const override of [{PGSSLMODE:'require'},{FNCP_DATABASE_HOST:'elsewhere'},{FNCP_DATABASE_PORT:'5433'},{PGSSLROOTCERT:'/tmp/other-ca.pem'}]){
    const r=spawnSync('/bin/sh',plan().maintenance.seed.command,{encoding:'utf8',env:{PATH:'/not-an-executable-directory',
      PGSSLMODE:'verify-full',FNCP_DATABASE_HOST:'postgres',FNCP_DATABASE_PORT:'5432',PGSSLROOTCERT:'/run/fncp/database-ca.pem',...override}});
    assert.equal(r.status,1);assert.equal(r.stdout,'');assert.equal(r.stderr,'FNCP_FRESH_POSTGRES_CLIENT_REJECTED\n');
  }
});

test('rejects invalid/changed texts, unsafe topic/description and unexpected activation or credential fields',()=>{
  for(const mutate of [r=>r.statements.pop(),r=>r.statements[14]=r.statements[0],r=>r.statements[0]='x'.repeat(1001),
    r=>r.seedSha256='0'.repeat(64),r=>r.statements[0]='\ud800',r=>r.topic='',r=>r.topic='x'.repeat(1001),
    r=>r.description='',r=>r.description='x'.repeat(50001),r=>r.topic='a\0b',r=>r.password='secret',r=>r.activate=true]){
    const r=request();mutate(r);assert.throws(()=>postgresInitializationPlan(configuration(),lock(),'d'.repeat(48),r),denied);
  }
});

test('rejects nonfresh statement IDs and ambiguous normal database/image contracts',()=>{
  for(const mutate of [c=>c.binding.statementIds=c.binding.statementIds.map(x=>x+1),c=>c.database.host='remote',
    c=>c.database.mathRole=c.database.runtimeRole,c=>c.binding.conversationId="9sql';--",c=>c.password='secret']){
    const c=configuration();mutate(c);assert.throws(()=>postgresInitializationPlan(c,lock(),'d'.repeat(48),request()),denied);
  }
  const l=lock();l.images.postgres=l.images.migration;assert.throws(()=>postgresInitializationPlan(configuration(),l,'d'.repeat(48),request()),denied);
});

test('rejects accessor and Proxy hooks without running them',()=>{
  let hooks=0;const r=request();Object.defineProperty(r,'topic',{get(){hooks++;return 'no';}});
  assert.throws(()=>postgresInitializationPlan(configuration(),lock(),'d'.repeat(48),r),denied);
  const c=configuration();c.database=new Proxy(c.database,{get(){hooks++;throw new Error('trap');}});
  assert.throws(()=>postgresInitializationPlan(c,lock(),'d'.repeat(48),request()),denied);
  const b=request();b.statements=new Proxy(b.statements,{get(){hooks++;throw new Error('trap');}});
  assert.throws(()=>postgresInitializationPlan(configuration(),lock(),'d'.repeat(48),b),denied);assert.equal(hooks,0);
});

test('snapshot immutable plans and receipts reject copies and changed counts/bindings',()=>{
  const c=configuration(),r=request(),p=postgresInitializationPlan(c,lock(),'d'.repeat(48),r);
  c.binding.conversationId='9changedRound';r.statements[0]='changed';
  assert.equal(p.binding.conversationId,'9freshClosedRound');assert.equal(JSON.parse(p.queries[1].values[0]).statements[0],'Reviewed synthetic statement 0');
  assert.throws(()=>p.maintenance.initialize.command.push('force'));
  assert.deepEqual(validatePostgresInitializationReceipt(p,receipt(p)),receipt(p));
  assert.throws(()=>validatePostgresInitializationReceipt(structuredClone(p),receipt(p)),denied);
  for(const mutate of [r=>r.nativeRoundOpen=true,r=>r.participantAdmissionActivated=true,r=>r.participantAccounts=1,r=>r.seedAuthors=0,
    r=>r.votes=1,r=>r.statementCount=14,r=>r.seedSha256='0'.repeat(64),r=>r.force=true]){
    const value=receipt(p);mutate(value);assert.throws(()=>validatePostgresInitializationReceipt(p,value),denied);
  }
});
