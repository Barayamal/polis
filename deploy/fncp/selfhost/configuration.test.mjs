import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp,writeFile,chmod,symlink,rm,realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { validateConfiguration,loadConfiguration,composeConfiguration,validateImageLock } from './configuration.mjs';

const configuration=()=>({version:1,classification:'closed-local-core',deployment:'fncp-contract-test',platform:'linux/arm64',engine:{host:'unix:///tmp/task-owned/docker.sock',configDirectory:'/tmp/task-owned/docker'},stateDirectory:'/tmp/task-owned/state',sourceRevision:'a'.repeat(40),database:{name:'polis',owner:'polis_owner',migrationRole:'polis_migration',runtimeRole:'polis_runtime',mathRole:'polis_math',host:'postgres',port:5432},binding:{conversationId:'9selfhosttest',statementIds:Array.from({length:15},(_,i)=>i)},identity:{issuer:'https://identity.invalid/',audience:'polis-local',jwksUri:'https://identity.invalid/jwks'}});
const imageLock=()=>({version:1,sourceRevision:'a'.repeat(40),sourceFingerprint:'b'.repeat(64),images:Object.fromEntries(['api','math','migration','postgres'].map((n,i)=>[n,'sha256:'+String(i+1).repeat(64)]))});
test('valid closed core configuration is snapshotted without caller aliasing',()=>{const c=configuration();const v=validateConfiguration(c);c.binding.statementIds[0]=100;assert.equal(v.binding.statementIds[0],0);});
test('unknown fields, public/remote engine, unsupported modes and malformed paths reject',()=>{
 for(const alter of [c=>c.unexpected=true,c=>c.classification='production',c=>c.engine.host='tcp://127.0.0.1:2375',c=>c.engine.extra=true,c=>c.platform='linux/amd64',c=>c.deployment='user-project',c=>c.stateDirectory='/tmp/../home']){const c=configuration();alter(c);assert.throws(()=>validateConfiguration(c),/FNCP_SELFHOST_/);}
});
test('database roles stay distinct and statement binding remains exactly15 canonical IDs',()=>{
 for(const alter of [c=>c.database.runtimeRole=c.database.owner,c=>c.database.name='polis;drop database x',c=>c.database.host='unrelated.host',c=>c.binding.statementIds.pop(),c=>c.binding.statementIds[14]=0,c=>c.binding.statementIds[0]=-0,c=>c.binding.statementIds[0]='0',c=>c.binding.conversationId='']){const c=configuration();alter(c);assert.throws(()=>validateConfiguration(c),/FNCP_SELFHOST_/);}
});
test('identity URLs cannot smuggle credentials, fragments, query overrides or HTTP',()=>{
 for(const value of ['http://identity.invalid/','https://user:password@identity.invalid/','https://identity.invalid/#fragment','https://identity.invalid/?insecure=true']){const c=configuration();c.identity.issuer=value;assert.throws(()=>validateConfiguration(c),/FNCP_SELFHOST_IDENTITY/);}
});
test('mutable image tags and source mismatches reject',()=>{const l=imageLock();l.images.api='polis:latest';assert.throws(()=>validateImageLock(l));const c=configuration();c.sourceRevision='b'.repeat(40);assert.throws(()=>composeConfiguration(c,imageLock(),'c'.repeat(48)));});
test('core topology has no host ports and all persistent resources carry ownership',()=>{
 const p=composeConfiguration(configuration(),imageLock(),'c'.repeat(48));
 assert.equal(p.networks.private.internal,true);assert.equal(p['x-fncp-boundary'].participantIngress,false);
 for(const [name,s] of Object.entries(p.services)){
  assert.equal(s.ports,undefined,name);assert.equal(s.network_mode,undefined,name);assert.equal(s.read_only,true,name);assert.deepEqual(s.cap_drop,['ALL']);assert.equal(s.labels['org.barayamal.fncp.owner'],'c'.repeat(48));
  for(const v of s.volumes??[])if(v.type==='bind'){assert.equal(v.read_only,true);assert.equal(v.bind.create_host_path,false);}
 }
 assert.deepEqual(p.services.postgres.command,['start']);assert.deepEqual(p.services.migration.profiles,['maintenance']);
 assert.equal(p.volumes.postgres.labels['org.barayamal.fncp.owner'],'c'.repeat(48));
 assert.deepEqual(p.services.math.depends_on,{api:{condition:'service_healthy'}});
});
test('configuration reader rejects world-readable files and symlinks',async()=>{
 const d=await mkdtemp(join(await realpath(tmpdir()),'fncp-config-test-'));
 try{const p=join(d,'config.json');await writeFile(p,JSON.stringify(configuration()),{mode:0o600});assert.equal((await loadConfiguration(p)).version,1);await chmod(p,0o644);await assert.rejects(loadConfiguration(p),/PRIVATE_FILE/);await chmod(p,0o600);const l=join(d,'link.json');await symlink(p,l);await assert.rejects(loadConfiguration(l),/PRIVATE_FILE/);}finally{await rm(d,{recursive:true,force:true});}
});
