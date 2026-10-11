import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,realpathSync,chmodSync,rmSync,readFileSync,writeFileSync,existsSync} from 'node:fs';
import {join} from 'node:path';
import {createSyntheticInstallation} from './synthetic-input.mjs';
import {stageProductionMaterial} from './stage-material.mjs';
import {canonical,sha} from '../production-service/contracts.mjs';

async function fixture(t,version=2) {
  const root=realpathSync(mkdtempSync('/tmp/fncp-stage-v'+version+'-'));chmodSync(root,0o700);
  t.after(()=>rmSync(root,{recursive:true,force:true}));
  const imageLock={version,sourceRevision:'a'.repeat(40),sourceFingerprint:'b'.repeat(64),images:Object.fromEntries(
    ['api','math','postgres','migration','participant','wordpress','mariadb','proxy','edge',...(version===3?['operator']:[])].map((role,i)=>[role,'sha256:'+(i+1).toString(16).padStart(64,'0')]))};
  const f=await createSyntheticInstallation({directory:join(root,'fixture'),targetDirectory:join(root,'stage'),imageLock});
  return {...f,run:()=>stageProductionMaterial({inputDirectory:f.inputDirectory,targetDirectory:f.targetDirectory}),
    edit:(file,change)=>{const path=join(f.inputDirectory,file),value=JSON.parse(readFileSync(path));change(value);writeFileSync(path,canonical(value)+'\n');}};
}
test('V2 joins independent edge custody and preserves exact normal descriptor on verified rerun',async t=>{
  const f=await fixture(t), first=await f.run();assert.equal(first.result,'MATERIAL_STAGED');assert.equal(first.filesVerified,42);
  const c=JSON.parse(readFileSync(join(f.targetDirectory,'compose.json')));assert.equal(c.services.edge.image,'sha256:'+'9'.padStart(64,'0'));
  assert.equal(c.services.edge.ports,undefined);assert.equal(c.volumes.edge_material.labels['org.barayamal.fncp.resource'],'volume:edge_material');
  assert.equal((await f.run()).changed,false);
});
test('V3 stages the activation-bound access digest and only the two exact loopback bindings',async t=>{
  const f=await fixture(t,3),first=await f.run();assert.equal(first.result,'MATERIAL_STAGED');
  const c=JSON.parse(readFileSync(join(f.targetDirectory,'compose.json'))),receipt=JSON.parse(readFileSync(join(f.targetDirectory,'stage.receipt.json')));
  assert.equal(c.services.edge.ports,undefined);assert.equal(c.services.wordpress.ports,undefined);
  assert.deepEqual(c.services.operator.ports,[{host_ip:'127.0.0.1',mode:'host',protocol:'tcp',published:8443,target:8443},{host_ip:'127.0.0.1',mode:'host',protocol:'tcp',published:9443,target:9443}]);
  assert.equal(c.services.operator.image,'sha256:'+'a'.padStart(64,'0'));assert.equal(c.networks.operator_access.internal,false);
  assert.equal(receipt.publishedPorts,2);
  const service=JSON.parse(readFileSync(join(f.targetDirectory,'participant_material/service.json')));
  assert.equal(service.activation.operatorAccessSha256,sha(canonical(f.configuration.operatorAccess)));
  assert.equal((await f.run()).changed,false);
});
test('V3 refuses an externally bound participant listener before staging',async t=>{
  const f=await fixture(t,3);f.edit('installation.json',v=>{v.configuration.operatorAccess.participant.hostIp='0.0.0.0';});
  await assert.rejects(f.run());assert.equal(existsSync(f.targetDirectory),false);
});
for (const [name,edit] of [
  ['edge origin drift',f=>f.edit('edge_material/config.json',v=>{v.publicOrigin='https://wrong.invalid';})],
  ['hidden edge cookie exception',f=>f.edit('edge_material/config.json',v=>{v.discardCookies=['arbitrary'];})],
  ['edge reuses participant private key',f=>{
    for(const [from,to] of [['participant-cert.pem','server.pem'],['participant-key.pem','server-key.pem']])writeFileSync(join(f.inputDirectory,'edge_material',to),readFileSync(join(f.inputDirectory,'participant_material',from)));
  }],
  ['edge upstream trusts wrong CA',f=>writeFileSync(join(f.inputDirectory,'edge_material/upstream-ca.pem'),readFileSync(join(f.inputDirectory,'core/material/database-ca.pem')))],
  ['downgrade loses ninth image binding',f=>f.edit('installation.json',v=>{v.version=1;v.profile='FNCP_FRESH_MATERIAL_STAGE_V1';})],
]) test('V2 refuses '+name+' before staging',async t=>{
  const f=await fixture(t);edit(f);await assert.rejects(f.run());assert.equal(existsSync(f.targetDirectory),false);
});
