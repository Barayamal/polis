import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { chmodSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { MODE, STORES, binding, canonical, eventDigest, seal, sha256, signManifest, unseal, validateConsistency, verifyManifest } from './coordinated-contract.mjs';
import { accessSnapshot, assertAdversarialCopy, denyOldAuthority, restoreArguments, runCoordinated, validateRestoreTarget, validateRuntimeMounts, validateWordPressSource } from './coordinated-proof.mjs';
import { createLocalAccess } from '../local-access/access-server.mjs';

function model() {
  const journal={schema_version:1,subjects:{},events:{}};
  const access={rounds:[{id:'123abcde',open:0}],fixtures:[],approvals:[],invitations:[],sessions:[],events:[]};
  const operations=[];
  for(const name of ['synthetic_one','synthetic_two','synthetic_three']) {
    access.fixtures.push({id:name,credential_hash:'a'.repeat(64)});
    const xid='fncp_'+randomBytes(32).toString('base64url');access.approvals.push({fixture:name,round:'123abcde',state:'revoked',xid});operations.push({xid,operation_version:2,desired_present:false});
    for(const version of [1,2]) {
      const event={schema_version:1,event_id:randomUUID(),subject:name,round_id:'synthetic_round_local',version,state:version===1?'approved':'revoked',occurred_at:'2026-09-13T00:00:00Z'};
      journal.events[event.event_id]={event,body:canonical(event),delivered:true,last_result:'ACKNOWLEDGED'};
      journal.subjects['synthetic_round_local:'+name]={event_id:event.event_id,version,state:event.state};
      access.events.push({event_id:event.event_id,subject:name,version,state:event.state,digest:eventDigest(event),applied:1});
    }
  }
  return {journal,access,operations};
}
function bundle() {
  const key=randomBytes(32),run=randomBytes(12).toString('hex'),scopeHash=sha256('isolated-test-scope');
  const components=Object.fromEntries(STORES.map(store=>[store,seal(Buffer.from('synthetic fixture only'),key,binding(run,store,scopeHash))]));
  const manifest={version:1,mode:MODE,run,scopeHash,components:Object.fromEntries(STORES.map(store=>[store,{filename:store+'.aesgcm',mode:'600',bytes:components[store].length,sha256:sha256(components[store])}]))};
  return {key,run,scopeHash,components,signed:signManifest(manifest,key)};
}

test('AES-GCM round trip requires exact run/store/scope and never plaintext envelope',()=>{
  const b=bundle();for(const store of STORES){assert.equal(unseal(b.components[store],b.key,binding(b.run,store,b.scopeHash)).toString(),'synthetic fixture only');assert.ok(!b.components[store].includes('synthetic fixture only'));}
});
test('ciphertext, tag, key, AAD scope, store and run tampering all fail authentication',()=>{
  const b=bundle();const original=b.components[STORES[0]];
  for(const field of ['tag','nonce','ciphertext']) {const e=JSON.parse(original);e[field]=(e[field][0]==='a'?'b':'a')+e[field].slice(1);assert.throws(()=>unseal(Buffer.from(canonical(e)),b.key,binding(b.run,STORES[0],b.scopeHash)));}
  assert.throws(()=>unseal(original,randomBytes(32),binding(b.run,STORES[0],b.scopeHash)));
  assert.throws(()=>unseal(original,b.key,binding('f'.repeat(24),STORES[0],b.scopeHash)));
  assert.throws(()=>unseal(original,b.key,binding(b.run,STORES[1],b.scopeHash)));
  assert.throws(()=>unseal(original,b.key,binding(b.run,STORES[0],sha256('other'))));
});
test('manifest rejects missing, extra, mismatched, swapped or stale components and changed metadata',()=>{
  const b=bundle();assert.equal(verifyManifest(b.signed,b.key,b.run,b.scopeHash,b.components).run,b.run);
  const missing={...b.components};delete missing[STORES[0]];assert.throws(()=>verifyManifest(b.signed,b.key,b.run,b.scopeHash,missing));
  assert.throws(()=>verifyManifest(b.signed,b.key,b.run,b.scopeHash,{...b.components,extra:Buffer.from('x')}));
  assert.throws(()=>verifyManifest(b.signed,b.key,b.run,b.scopeHash,{...b.components,[STORES[0]]:b.components[STORES[1]]}));
  assert.throws(()=>verifyManifest(b.signed,b.key,'a'.repeat(24),b.scopeHash,b.components));
  const changed=structuredClone(b.signed);changed.manifest.components[STORES[0]].filename='../another.aesgcm';assert.throws(()=>verifyManifest(changed,b.key,b.run,b.scopeHash,b.components));
});
test('three-store event versions, digests and terminal provider tombstones agree',()=>{
  const m=model();assert.equal(validateConsistency(m.journal,m.access,m.operations).revoked,3);
});
test('stale approval, pending event, missing tombstone and extra fixture fail closed',()=>{
  for(const mutate of [m=>{m.access.approvals[0].state='approved';},m=>{m.access.events[0].applied=0;},m=>{m.access.events[0].digest='f'.repeat(64);},m=>{m.operations[0].desired_present=true;},m=>{m.operations.shift();},m=>{m.access.fixtures.push({id:'synthetic_extra'});},m=>{m.access.rounds[0].open=1;},m=>{m.access.sessions.push({});},m=>{Object.values(m.journal.subjects)[0].version=1;}]){const m=model();mutate(m);assert.throws(()=>validateConsistency(m.journal,m.access,m.operations));}
});
test('restore targets are exact pinned images, fresh tmpfs, internal-ID-only and never existing source mounts',()=>{
  const run='a'.repeat(24),network='b'.repeat(64),image='sha256:85b9bf2e29cf836ecb8c2a15a935d4ba0c606631dff1dd79531a11983c638f2a';
  const args=restoreArguments('mysql',run,network,image);assert.ok(args.includes('--pull=never'));assert.ok(args.includes('/var/lib/mysql:rw,nosuid,nodev,size=768m'));assert.ok(args.includes('/docker-entrypoint-initdb.d:ro,nosuid,nodev,size=1m'));assert.ok(!args.some(arg=>['-v','--volume','--mount','-p','--publish','--network=host'].includes(arg)));
  for(const bad of ['default','host','fncp-existing'])assert.throws(()=>restoreArguments('mysql',run,bad,image));assert.throws(()=>restoreArguments('mysql',run,network,'mysql:latest'));
});
test('source WordPress guard rejects an arbitrary or broad live target',()=>{assert.throws(()=>validateWordPressSource({Id:'a'.repeat(64),Running:true,Image:'mysql:latest',Ports:{}}));});
test('actual restore mount table requires protected tmpfs data and read-only init directory',()=>{
  const text='tmpfs /var/lib/mysql tmpfs rw,nosuid,nodev,size=786432k 0 0\ntmpfs /docker-entrypoint-initdb.d tmpfs ro,nosuid,nodev,size=1024k 0 0\n';validateRuntimeMounts(text,'mysql');
  assert.throws(()=>validateRuntimeMounts(text.replace(' ro,',' rw,'),'mysql'));assert.throws(()=>validateRuntimeMounts(text.replace(' tmpfs rw,',' ext4 rw,'),'mysql'));assert.throws(()=>validateRuntimeMounts(text.replaceAll('nodev,',''),'mysql'));
});
test('no explicit coordinated mode performs no Docker or backup work and claims no key/authenticated archives',async()=>{const result=await runCoordinated('wrong-mode');assert.equal(result.outcome,'FAIL');assert.equal(result.phase,'explicit-mode');assert.equal(result.retainedBackupsAuthenticatedEncrypted,false);assert.equal(result.privateKeySeparateDirectory,false);assert.equal(result.retainedComponentCount,0);});
test('inspected restore target rejects wrong source identity, image, network, published port, label or mount',()=>{
  const run='a'.repeat(24),net='b'.repeat(64),source='d'.repeat(64);
  const info={Id:'c'.repeat(64),Image:'sha256:85b9bf2e29cf836ecb8c2a15a935d4ba0c606631dff1dd79531a11983c638f2a',Labels:{'org.barayamal.fncp.coordinated-recovery-run':run},Ports:{},Networks:{test:{NetworkID:net}},Mounts:[{Type:'tmpfs',Destination:'/var/lib/mysql'},{Type:'tmpfs',Destination:'/docker-entrypoint-initdb.d'}]};
  validateRestoreTarget(info,'mysql',run,net,[source]);
  const pending={...structuredClone(info),Running:false,Networks:{['fncp-coordinated-'+run]:{NetworkID:''}},Mounts:[],Tmpfs:{'/var/lib/mysql':'rw,nosuid,nodev,size=768m','/docker-entrypoint-initdb.d':'ro,nosuid,nodev,size=1m'}};
  validateRestoreTarget(pending,'mysql',run,net,[source],true);assert.throws(()=>validateRestoreTarget(pending,'mysql',run,net,[source]));
  pending.Tmpfs['/var/lib/mysql']='rw';assert.throws(()=>validateRestoreTarget(pending,'mysql',run,net,[source],true));
  for(const mutate of [i=>{i.Id=source;},i=>{i.Image='mysql:latest';},i=>{i.Networks.test.NetworkID=source;},i=>{i.Ports={'3306/tcp':[]};},i=>{i.Mounts[0].Type='volume';},i=>{i.Labels={};}]){const changed=structuredClone(info);mutate(changed);assert.throws(()=>validateRestoreTarget(changed,'mysql',run,net,[source]));}
});
test('restored code denies valid stale warm sessions/invitations/reapproval and stale WordPress replay',async()=>{
  const run=randomBytes(12).toString('hex');const dir=fileURLToPath(new URL('./.runtime/coordinated-work-'+run+'/',import.meta.url));mkdirSync(dir,{recursive:true,mode:0o700});const path=join(dir,'adversarial.sqlite');const m=model();
  const app=createLocalAccess({mode:'fixture-only',dbPath:path,conversationId:'123abcde',adminSecret:randomBytes(32).toString('base64url'),provider:{}});await app.close();
  try{chmodSync(path,0o600);const db=new DatabaseSync(path);for(const f of m.access.fixtures)db.prepare('INSERT INTO fixtures VALUES(?,?)').run(f.id,f.credential_hash);for(const a of m.access.approvals)db.prepare('INSERT INTO approvals VALUES(?,?,?,?)').run(a.fixture,a.round,a.xid,a.state);for(const e of m.access.events)db.prepare('INSERT INTO wordpress_events VALUES(?,?,?,?,?,?)').run(e.event_id,e.subject,e.version,e.state,e.digest,e.applied);const before=accessSnapshot(db,'123abcde');assert.equal(before.aggregates.closedRounds,1);db.close();const result=await denyOldAuthority(path,'123abcde',m.journal,run);assert.equal(result.providerCalls,0);assert.equal(result.staleApprovalReplaysDenied,3);}finally{rmSync(dir,{recursive:true});}
});
test('adversarial-write helper rejects original SQLite, arbitrary paths and missing run before opening',()=>{
  assert.throws(()=>assertAdversarialCopy(fileURLToPath(new URL('../local-access/.runtime/synthetic.sqlite',import.meta.url)),'a'.repeat(24)));
  assert.throws(()=>assertAdversarialCopy('/tmp/arbitrary.sqlite','a'.repeat(24)));
  assert.throws(()=>assertAdversarialCopy('/tmp/arbitrary.sqlite'));
});
test('runner enforces quiescence, exact read-only source tools, private retention, guarded cleanup, no source import',()=>{
  const source=readFileSync(new URL('./coordinated-proof.mjs',import.meta.url),'utf8');
  for(const text of ["quiescent(sourcePg,sourceWp)","{readOnly:true}","--single-transaction","--skip-lock-tables","--skip-add-drop-table","await backup(sourceDb,sqliteCopy)","verifyManifest(","unseal(","MYSQL_PWD=", "info.Labels?.[LABEL]===run", "!\u005bsourcePg,sourceWp\u005d.includes(id)","--internal", "privateFile(resolve(RUNTIME,'coordinated-keys'", "same(before.aggregate,restored)","same(sourceHash,sha256(readFileSync(SQLITE)))"])assert.ok(source.includes(text),text);
  assert.doesNotMatch(source,/docker\(\['(?:system|volume)','prune'|down.*-v|DROP DATABASE|TRUNCATE|pg_restore[^\n]*sourcePg|mysql[^\n]*input:plain[^\n]*sourceWp/);
  assert.match(source,/count\(DISTINCT txt\)/);assert.match(source,/count\(DISTINCT tid\)/);assert.match(source,/distinctFixedSeedTexts:15,distinctFixedSeedTids:15/);
});
