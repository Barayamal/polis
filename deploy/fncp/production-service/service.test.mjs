import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, chmodSync, existsSync, readdirSync, symlinkSync, statSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createConnection, createServer } from 'node:net';
import { join } from 'node:path';
import { createProductionService, isProductionService } from './service.mjs';
import { startProductionOperator, requestProductionOperator } from './operator.mjs';
import { serviceFixture, refused } from './test-support/service-fixture.mjs';
const denied={message:'Production service unavailable.'};
const declarations=x=>({consentVersion:x.manifest.content.consentVersion,adultSelfAttested:true,eligibilitySelfAttested:true,registrationConsent:true});
function childService(configurationPath){const script=`import {readFileSync} from 'node:fs';import {createProductionService} from ${JSON.stringify(new URL('./service.mjs',import.meta.url).href)};try{const s=await createProductionService({configurationPath:JSON.parse(readFileSync(0,'utf8'))});await s.close();process.stdout.write('CREATED');}catch(e){if(e.message!=='Production service unavailable.')process.exit(2);process.stdout.write('DENIED');}`;const r=spawnSync(process.execPath,['--input-type=module','-e',script],{input:JSON.stringify(configurationPath),encoding:'utf8',timeout:5000,maxBuffer:8192,env:{PATH:process.env.PATH,NODE_NO_WARNINGS:'1'}});assert.equal(r.error,undefined);assert.equal(r.status,0);assert.equal(r.stderr,'');return r.stdout;}
function noLocks(x){for(const name of ['service.lock','activation.sqlite.lock','access.sqlite.writer.lock'])assert.equal(existsSync(join(x.stateDirectory,name)),false,name+' released');}
async function operatorRaw(path,raw){return new Promise((resolve,reject)=>{let text='';const s=createConnection({path,allowHalfOpen:true});s.setTimeout(2000,()=>s.destroy(Error('test operator deadline')));s.once('connect',()=>s.end(raw));s.on('data',b=>text+=b);s.once('error',reject);s.once('end',()=>{s.destroy();resolve(text);});});}

test('actual file-backed composition starts closed and authenticates/registers over native HTTPS peers',async t=>{
  const x=await serviceFixture(t),s=await x.create();assert.ok(Object.isFrozen(s));assert.equal(isProductionService(s),true);assert.equal(isProductionService({...s}),false);
  assert.equal(s.operator.status().roundOpen,false);assert.throws(()=>s.operator.admit());
  const start=await s.start();assert.equal(start.participantOrigin,x.manifest.participant.origin);assert.equal(start.eventOrigin,x.manifest.receiver.origin);assert.equal(start.roundOpen,false);
  const client=x.client();await client.login();const registration=await client.call('/registration',declarations(x));assert.equal(registration.status,200);assert.equal(registration.body.registrationState,'pending');assert.equal(registration.body.participantAccessGranted,false);
  assert.equal(x.h.records.size,1);assert.ok(x.h.issuer.calls.some(c=>c.endpoint==='token'));assert.ok(x.h.issuer.calls.some(c=>c.endpoint==='jwks'));assert.ok(x.h.calls.some(c=>c.peer==='wordpress'&&c.action==='register'));
  assert.equal(s.operator.status().roundOpen,false);assert.equal(s.operator.status().registrations,1);assert.equal(x.h.votes.length,0);
  assert.deepEqual(await s.close(),{closed:true,drained:true});await refused(x.participantPort);await refused(x.receiverPort);noLocks(x);
});

test('duplicate composition in another process cannot rewrite the active boot, replay floor or either ledger',async t=>{
  const x=await serviceFixture(t),s=await x.create();await s.start();s.operator.activate(x.envelope(s));assert.deepEqual(s.operator.admit(),{roundOpen:true});
  const challenge=s.operator.challenge(),files=['activation.sqlite','access.sqlite','service.lock','activation.sqlite.lock','access.sqlite.writer.lock'];const before=files.map(name=>readFileSync(join(x.stateDirectory,name)));
  assert.equal(childService(x.configurationPath),'DENIED');for(let i=0;i<files.length;i++)assert.deepEqual(readFileSync(join(x.stateDirectory,files[i])),before[i],files[i]+' unchanged');
  assert.deepEqual(s.operator.challenge(),challenge);assert.equal(s.operator.status().roundOpen,true);await s.close();noLocks(x);
});

test('ordinary restart retains registration and replay floor but closes old activation, round and browser session',async t=>{
  const x=await serviceFixture(t),first=await x.create();await first.start();const client=x.client();await client.login();assert.equal((await client.call('/registration',declarations(x))).status,200);
  const envelope=x.envelope(first);first.operator.activate(envelope);first.operator.admit();const before=first.operator.challenge();await first.close();noLocks(x);
  const second=await x.create();assert.equal(second.operator.status().registrations,1);assert.equal(second.operator.status().roundOpen,false);assert.equal(second.operator.challenge().nextSequence,before.nextSequence);assert.notEqual(second.operator.challenge().binding.bootId,before.binding.bootId);assert.throws(()=>second.operator.activate(envelope));assert.throws(()=>second.operator.admit());
  await second.start();const status=await client.call('/session');assert.equal(status.status,200);assert.equal(status.body.authenticated,false);assert.equal(status.body.participationSession,false);await second.close();
});

test('same-size captured material change closes admission and both listeners permanently for this instance',async t=>{
  const x=await serviceFixture(t),s=await x.create();await s.start();s.operator.activate(x.envelope(s));s.operator.admit();
  const path=x.manifest.secrets.gatewayKeyFile,before=readFileSync(path);writeFileSync(path,Buffer.from('Z'.repeat(before.length)));assert.throws(()=>s.operator.status(),denied);
  await s.close();writeFileSync(path,before);assert.throws(()=>s.operator.challenge(),denied);await assert.rejects(()=>s.start(),denied);await refused(x.participantPort);await refused(x.receiverPort);noLocks(x);
});

test('background custody check closes changed material without any operator or participant call',async t=>{
  const x=await serviceFixture(t),s=await x.create();await s.start();s.operator.activate(x.envelope(s));s.operator.admit();const path=x.manifest.secrets.gatewayKeyFile,before=readFileSync(path);writeFileSync(path,'Z'.repeat(before.length));
  const deadline=performance.now()+3500;while(existsSync(join(x.stateDirectory,'service.lock'))&&performance.now()<deadline)await new Promise(resolve=>setTimeout(resolve,25));
  assert.equal(existsSync(join(x.stateDirectory,'service.lock')),false);await s.close();await refused(x.participantPort);await refused(x.receiverPort);writeFileSync(path,before);assert.throws(()=>s.operator.challenge(),denied);noLocks(x);
});

test('reviewed activation cannot admit before both listeners start or after service closure',async t=>{
  const x=await serviceFixture(t),s=await x.create();s.operator.activate(x.envelope(s));assert.throws(()=>s.operator.admit(),denied);assert.equal(s.operator.status().roundOpen,false);
  await s.start();assert.equal(s.operator.status().roundOpen,false);s.operator.activate(x.envelope(s));assert.deepEqual(s.operator.admit(),{roundOpen:true});await s.close();assert.throws(()=>s.operator.admit(),denied);
});

test('actual receiver listen failure drains construction and prevents reviewed admission',async t=>{
  const x=await serviceFixture(t),blocker=createServer(socket=>socket.destroy());await new Promise((resolve,reject)=>{blocker.once('error',reject);blocker.listen(x.receiverPort,'127.0.0.1',resolve);});
  try{const s=await x.create();s.operator.activate(x.envelope(s));await assert.rejects(()=>s.start(),denied);assert.throws(()=>s.operator.admit(),denied);await s.close();noLocks(x);await refused(x.participantPort);}
  finally{await new Promise(resolve=>blocker.close(resolve));}await refused(x.receiverPort);
});

test('offline private signing key, certificate and bundled public keys are rejected before ledger creation',async t=>{
  const x=await serviceFixture(t),path=x.manifest.activation.publicKeyFile,publicPem=readFileSync(path);
  for(const bad of [x.signingKeys.privateKey.export({type:'pkcs8',format:'pem'}),x.participantTls.cert,Buffer.concat([publicPem,publicPem])]){writeFileSync(path,bad);await assert.rejects(()=>x.create(),denied);assert.deepEqual(readdirSync(x.stateDirectory),[]);}
  writeFileSync(path,publicPem);const s=await x.create();assert.equal(s.operator.status().roundOpen,false);await s.close();noLocks(x);
});

test('early constructor rejection releases the compositor lock and never creates ledger state',async t=>{
  const x=await serviceFixture(t);x.manifest.participant.arbitraryTransport=true;x.save();await assert.rejects(()=>x.create(),denied);assert.deepEqual(readdirSync(x.stateDirectory),[]);
  delete x.manifest.participant.arbitraryTransport;x.save();const s=await x.create();await s.close();noLocks(x);
});

test('composition refuses permissive or symlinked configuration before acquiring writer ownership',async t=>{
  const x=await serviceFixture(t);chmodSync(x.configurationPath,0o644);await assert.rejects(()=>x.create(),denied);assert.deepEqual(readdirSync(x.stateDirectory),[]);chmodSync(x.configurationPath,0o600);
  const link=join(x.materialDirectory,'alias.json');symlinkSync(x.configurationPath,link);await assert.rejects(()=>createProductionService({configurationPath:link}),denied);assert.deepEqual(readdirSync(x.stateDirectory),[]);
});

test('private native operator socket accepts only real service and reviewed activation commands',async t=>{
  const x=await serviceFixture(t),s=await x.create();await s.start();await assert.rejects(()=>startProductionOperator({...s}));const operator=await startProductionOperator(s);
  try{assert.equal(statSync(operator.path).mode&0o7777,0o600);const call=(command,payload)=>requestProductionOperator({stateDirectory:x.stateDirectory,command,...(payload===undefined?{}:{payload})});
    assert.equal((await call('status')).roundOpen,false);await assert.rejects(()=>call('admit'));assert.deepEqual(await call('challenge'),s.operator.challenge());
    assert.equal((await call('activate',x.envelope(s))).active,true);assert.deepEqual(await call('admit'),{roundOpen:true});assert.equal((await call('status')).roundOpen,true);
    for(const payload of [undefined,{}, {accountId:'acct_'+'a'.repeat(43)}, {registrationId:'not-a-reference'},
      {registrationId:'00000000-0000-4000-8000-000000000000',accountId:'acct_'+'a'.repeat(43)},
      {registrationId:'00000000-0000-4000-8000-000000000000'}]) await assert.rejects(()=>call('invitation-for-registration',payload));
    assert.deepEqual(await call('close-admission'),{roundOpen:false});await assert.rejects(()=>call('admit'));await assert.rejects(()=>call('unknown-command'));
    const response=await operatorRaw(operator.path,'{ "command": "admit" }\n');assert.deepEqual(JSON.parse(response),{error:'operator_unavailable',ok:false});assert.equal(s.operator.status().roundOpen,false);
  }finally{await operator.close();await s.close();}assert.equal(existsSync(operator.path),false);noLocks(x);
});

test('duplicate operator listener refuses startup without replacing or revoking the owned active service',async t=>{
  const x=await serviceFixture(t),s=await x.create();await s.start();s.operator.activate(x.envelope(s));s.operator.admit();const operator=await startProductionOperator(s);
  try{const before=statSync(operator.path);await assert.rejects(()=>startProductionOperator(s));assert.equal(statSync(operator.path).ino,before.ino);assert.equal(s.operator.status().roundOpen,true);
    assert.deepEqual(JSON.parse(await operatorRaw(operator.path,'{"command":"status","command":"admit"}\n')),{error:'operator_unavailable',ok:false});
  }finally{await operator.close();await s.close();}
});

test('ninth image requires an edge-material digest and activation hashes it with the complete manifest',async t=>{
  const x=await serviceFixture(t);x.manifest.activation.images.edge='sha256:'+'9'.repeat(64);x.save();await assert.rejects(()=>x.create(),denied);assert.deepEqual(readdirSync(x.stateDirectory),[]);
  x.manifest.activation.edgeMaterialSha256='malformed';x.save();await assert.rejects(()=>x.create(),denied);assert.deepEqual(readdirSync(x.stateDirectory),[]);
  x.manifest.activation.edgeMaterialSha256='d'.repeat(64);x.save();const s=await x.create();const challenge=s.operator.challenge();assert.equal(challenge.purpose,'FNCP_PRODUCTION_ACTIVATION_V2');assert.equal(challenge.binding.images.edge,x.manifest.activation.images.edge);
  const {sha,canonical}=await import('./contracts.mjs');const fingerprints=Object.fromEntries(readdirSync(x.materialDirectory).map(name=>[join(x.materialDirectory,name),sha(readFileSync(join(x.materialDirectory,name)))]));
  assert.equal(challenge.binding.configSha256,sha(canonical({manifest:x.manifest,material:fingerprints})));assert.equal(s.operator.activate(x.envelope(s)).active,true);
  x.manifest.activation.edgeMaterialSha256='e'.repeat(64);x.save();assert.throws(()=>s.operator.status(),denied);await s.close();noLocks(x);
});

test('operator-access digest selects V3 service activation and material drift closes it',async t=>{
  const x=await serviceFixture(t);x.manifest.activation.images.edge='sha256:'+'9'.repeat(64);
  x.manifest.activation.images.operator='sha256:'+'a'.repeat(64);x.manifest.activation.edgeMaterialSha256='d'.repeat(64);x.manifest.activation.operatorAccessSha256='e'.repeat(64);x.save();
  const s=await x.create(),challenge=s.operator.challenge();assert.equal(challenge.purpose,'FNCP_PRODUCTION_ACTIVATION_V3');
  assert.equal(challenge.binding.operatorAccessSha256,x.manifest.activation.operatorAccessSha256);
  assert.equal(challenge.binding.images.operator,x.manifest.activation.images.operator);
  assert.equal(s.operator.activate(x.envelope(s)).active,true);
  x.manifest.activation.operatorAccessSha256='f'.repeat(64);x.save();assert.throws(()=>s.operator.status(),denied);
  await s.close();noLocks(x);
});
