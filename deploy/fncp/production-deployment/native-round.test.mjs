import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync,readdirSync} from 'node:fs';
import {nativeRoundMaintenance,validateNativeRoundReceipt} from './native-round.mjs';
const sha=v=>createHash('sha256').update(v).digest('hex');
const denied={message:'Native round maintenance rejected.'};
const configuration=()=>({version:1,profile:'FNCP_PRODUCTION_COMPOSE_V1',deployment:'fncp-native-round-contract',platform:'linux/arm64',stateDirectory:'/private/fncp-test/core-state',sourceRevision:'a'.repeat(40),
  database:{name:'polis',owner:'polis_owner',migrationRole:'polis_migration',runtimeRole:'polis_runtime',mathRole:'polis_math',host:'postgres',port:5432},
  binding:{conversationId:'9fixedConversation',statementIds:Array.from({length:15},(_,i)=>i)},
  identity:{issuer:'https://issuer.example.invalid/',audience:'configured-client',jwksUri:'https://issuer.example.invalid/jwks'}});
const request=(operation='open')=>{const statements=Array.from({length:15},(_,i)=>'Reviewed seed '+i);return {operation,statements,seedSha256:sha(JSON.stringify(statements))};};
const plan=(operation='open')=>nativeRoundMaintenance(configuration(),request(operation));
const receipt=p=>({profile:'FNCP_NATIVE_ROUND_V1',operation:p.operation,deployment:p.binding.deployment,conversationId:p.binding.conversationId,
  seedSha256:p.binding.seedSha256,statementCount:15,isActive:p.operation==='open',changed:true,participantAdmissionActivated:false});

test('pure plan snapshots exact binding, uses fixed SQL with one parameter and grants no participant admission',()=>{
  const c=configuration(),r=request(),p=nativeRoundMaintenance(c,r);c.binding.statementIds[0]=99;r.statements[0]='changed';
  assert.equal(p.binding.statementIds[0],0);assert.equal(JSON.parse(p.queries[1].values[0]).statements[0],'Reviewed seed 0');
  assert.equal(p.participantAdmissionActivated,false);assert.equal(p.requiresVerifiedTlsMaintenanceRunner,true);
  assert.equal(p.queries.flatMap(q=>q.values).length,1);assert.equal(p.queries[1].text.match(/\$1/gu).length,1);
  assert.ok(Object.isFrozen(p.queries[1].values));assert.throws(()=>p.binding.statementIds.push(21));
  assert.deepEqual(p.psql.arguments,['-X','--no-psqlrc','--quiet','--no-align','--tuples-only','--no-password','--set=ON_ERROR_STOP=1']);
});

test('untrusted text remains data for SQL quotes, dollar quoting, psql commands and Unicode',()=>{
  const r=request();r.statements[0]="'; COMMIT; DROP TABLE public.comments; -- \\quit\n$fncp_native_round$";
  r.statements[1]='Unicode Māori 🐬 with a tab\t and newline\nend';r.seedSha256=sha(JSON.stringify(r.statements));
  const p=nativeRoundMaintenance(configuration(),r),safe=plan();
  assert.deepEqual(p.queries.map(q=>q.text),safe.queries.map(q=>q.text));
  assert.deepEqual(JSON.parse(p.queries[1].values[0]).statements,r.statements);
  const encoded=p.psql.stdin.match(/^\\set fncp_round_payload '([A-Za-z0-9+/=]+)'$/mu)?.[1];assert.ok(encoded);
  assert.equal(Buffer.from(encoded,'base64').toString(),p.queries[1].values[0]);
  assert.equal(p.psql.stdin.includes(r.statements[0]),false);assert.equal(p.psql.stdin.includes('DROP TABLE'),false);
  assert.match(p.psql.stdin,/decode\(:'fncp_round_payload','base64'\)/u);
  assert.equal(p.psql.stdin.trim().split('\n').at(-1),'COMMIT;');
});

test('open and close use identical fixed SQL and independently bound operation data',()=>{
  const a=plan('open'),b=plan('close');assert.deepEqual(a.queries.map(q=>q.text),b.queries.map(q=>q.text));
  assert.equal(JSON.parse(a.queries[1].values[0]).operation,'open');assert.equal(JSON.parse(b.queries[1].values[0]).operation,'close');
  assert.match(a.queries[2].text,/IF expected_active AND \(/u);
  assert.match(a.queries[2].text,/UPDATE public\.conversations SET is_active=expected_active\s+WHERE zid=round\.zid/u);
  assert.doesNotMatch(a.queries.map(q=>q.text).join('\n'),/\b(?:INSERT|DELETE|CREATE|ALTER|TRUNCATE|GRANT)\s/iu);
});

test('maintenance retains TLS/role/primary/schema/locking/row-postcondition requirements',()=>{
  const sql=plan().queries.map(q=>q.text).join('\n');
  for(const fragment of ['SERIALIZABLE','statement_timeout','lock_timeout','idle_in_transaction_session_timeout','pg_stat_ssl','bits>=128',
    'pg_is_in_recovery','session_user','rolsuper','rolinherit','rolcreatedb','rolcreaterole','rolreplication','rolbypassrls',
    'pg_advisory_xact_lock(1179537232, 1)','LOCK TABLE fncp_deploy.schema_migrations IN SHARE MODE',
    'LOCK TABLE public.conversations, public.zinvites, public.comments IN SHARE ROW EXCLUSIVE MODE',
    'FOR UPDATE OF c,z','INTO actual_ids,actual_texts','changed_rows=ROW_COUNT','FNCP_NATIVE_ROUND_POSTCONDITION_REJECTED'])assert.ok(sql.includes(fragment),fragment);
  for(const flag of ['is_active','is_public','is_data_open','use_xid_whitelist','xid_required','is_anon','is_draft','strict_moderation',
    'profanity_filter','spam_filter','topics_enabled','treevite_enabled','write_type','vis_type'])assert.ok(sql.includes('round.'+flag+' IS DISTINCT FROM'),flag);
  for(const flag of ['active','is_seed','mod','is_meta'])assert.ok(sql.includes(flag+' IS DISTINCT FROM'),flag);
});

test('exact migration filename/hash contract matches all current top-level source migrations',()=>{
  const directory=new URL('../../../server/postgres/migrations/',import.meta.url);
  const expected=Object.fromEntries(readdirSync(directory).filter(n=>n.endsWith('.sql')).sort().map(name=>[name,sha(readFileSync(new URL(name,directory)))]));
  assert.equal(Object.keys(expected).length,20);assert.deepEqual(JSON.parse(plan().queries[1].values[0]).migrations,expected);
});

test('reject missing/duplicate/unbound/oversized seed text, wrong digest and noncanonical IDs',()=>{
  const changes=[r=>r.statements.pop(),r=>r.statements[14]=r.statements[0],r=>r.statements[0]=' ',r=>r.statements[0]='x'.repeat(1001),
    r=>r.statements[0]='bad\u0000text',r=>r.statements[0]='bad\uD800text',r=>r.seedSha256='0'.repeat(64),r=>r.seedSha256=r.seedSha256.toUpperCase(),
    r=>r.operation='reopen',r=>r.operation=true,r=>r.sql='SELECT 1',r=>r.credentials='forbidden'];
  for(const change of changes){const r=request();change(r);assert.throws(()=>nativeRoundMaintenance(configuration(),r),denied);}
  const c=configuration();[c.binding.statementIds[0],c.binding.statementIds[1]]=[1,0];assert.throws(()=>nativeRoundMaintenance(c,request()),denied);
});

test('descriptor hooks, sparse arrays and hidden properties never execute caller code',()=>{
  let invoked=0;const r=request();Object.defineProperty(r,'operation',{get(){invoked++;return 'open';}});
  assert.throws(()=>nativeRoundMaintenance(configuration(),r),denied);
  const sparse=request();delete sparse.statements[0];sparse.statements.some=()=>{invoked++;return false;};
  assert.throws(()=>nativeRoundMaintenance(configuration(),sparse),denied);
  const a=request();Object.defineProperty(a.statements,'0',{get(){invoked++;return 'surprise';},enumerable:true});
  assert.throws(()=>nativeRoundMaintenance(configuration(),a),denied);
  const hidden=request();Object.defineProperty(hidden,'sql',{value:'COMMIT'});assert.throws(()=>nativeRoundMaintenance(configuration(),hidden),denied);
  assert.equal(invoked,0);
});

test('strict public Compose configuration rejects hidden role, network and credential overrides',()=>{
  for(const alter of [c=>c.password='secret',c=>c.database.host='elsewhere',c=>c.database.runtimeRole=c.database.migrationRole,
    c=>c.binding.conversationId="9bad';--",c=>c.binding.statementIds[0]=-0,c=>c.platform='linux/amd64',c=>c.networks={host:{}}]){
    const c=configuration();alter(c);assert.throws(()=>nativeRoundMaintenance(c,request()),denied);
  }
});

test('seed digest matches participant ordered string JSON and SQL carries exact text without normalization',()=>{
  const r=request();r.statements[0]='  Māori e\u0301  ';r.seedSha256=sha(JSON.stringify(r.statements));
  const p=nativeRoundMaintenance(configuration(),r);assert.equal(p.binding.seedSha256,r.seedSha256);
  assert.equal(JSON.parse(p.queries[1].values[0]).statements[0],r.statements[0]);
  const changed=structuredClone(r);changed.statements[0]=changed.statements[0].normalize('NFC');
  assert.throws(()=>nativeRoundMaintenance(configuration(),changed),denied);
});

test('receipt validation binds exact original plan and permits idempotent close only',()=>{
  const p=plan(),value=receipt(p);assert.deepEqual(validateNativeRoundReceipt(p,value),value);
  const closed=plan('close'),r={...receipt(closed),changed:false};assert.deepEqual(validateNativeRoundReceipt(closed,r),r);
  assert.throws(()=>validateNativeRoundReceipt(structuredClone(p),value),denied);
  for(const alter of [r=>r.changed=false,r=>r.isActive=false,r=>r.conversationId='9differentRound',r=>r.seedSha256='0'.repeat(64),
    r=>r.statementCount=14,r=>r.participantAdmissionActivated=true,r=>r.sql='unexpected']){
    const bad=receipt(p);alter(bad);assert.throws(()=>validateNativeRoundReceipt(p,bad),denied);
  }
});
