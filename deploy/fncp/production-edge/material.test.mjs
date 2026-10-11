import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, realpathSync, chmodSync, writeFileSync, rmSync, unlinkSync, symlinkSync, linkSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonical } from '../production-service/contracts.mjs';
import { CONTAINER_PROFILE, createContainerParticipantTransport, createParticipantEdge } from './edge.mjs';
import { createContainerParticipantEdge } from './material.mjs';
import { freshLeaf } from './tls-fixture.mjs';
const denied={message:'Participant edge material rejected.'};
function fixture(t) {
  const directory=realpathSync(mkdtempSync(join(tmpdir(),'fncp-edge-material-')));chmodSync(directory,0o700);t.after(()=>rmSync(directory,{recursive:true,force:true}));
  const tls=freshLeaf(),config={version:1,profile:CONTAINER_PROFILE,publicOrigin:'https://127.0.0.1',discardCookies:[]};
  const save=(name,bytes)=>writeFileSync(join(directory,name),bytes,{mode:0o600});save('config.json',canonical(config)+'\n');save('server.pem',tls.tls.cert);save('server-key.pem',tls.tls.key);save('upstream-ca.pem',tls.ca);
  return {directory,config,tls,save,path:join(directory,'config.json')};
}
test('private edge material constructs fixed container profile and captures all four file fingerprints',async t=>{
  const f=fixture(t),edge=createContainerParticipantEdge({configurationPath:f.path});assert.equal(edge.snapshot().profile,CONTAINER_PROFILE);assert.equal(edge.snapshot().listenerOpen,false);assert.equal(edge.verify(),true);assert.equal(Object.keys(edge.fingerprints()).length,4);assert.equal((await edge.close()).listenerClosed,true);assert.throws(()=>edge.verify());
});
test('container transport endpoints are fixed and loopback profile still rejects cross-container options',async t=>{
  const f=fixture(t),options={publicOrigin:'https://127.0.0.1',listen:{host:'0.0.0.0',port:8443},upstream:{address:'participant-edge-upstream',port:8443,ca:f.tls.ca},tls:f.tls.tls,discardCookies:[]};
  assert.throws(()=>createParticipantEdge(options),{message:'Participant edge configuration rejected.'});
  for(const edit of [x=>x.listen.host='127.0.0.1',x=>x.listen.port=443,x=>x.upstream.address='wordpress',x=>x.upstream.port=8444]){const x=structuredClone(options);edit(x);assert.throws(()=>createContainerParticipantTransport(x),{message:'Participant edge configuration rejected.'});}
  const edge=createContainerParticipantTransport(options);assert.equal((await edge.close()).listenerClosed,true);
});
for(const [name,edit] of [
  ['unexpected file',f=>f.save('operator.key','unrelated')],['unknown config key',f=>{f.config.upstream='attacker';f.save('config.json',canonical(f.config)+'\n');}],
  ['noncanonical config',f=>f.save('config.json',JSON.stringify(f.config)+'\n')],['public directory',f=>chmodSync(f.directory,0o755)],
  ['world-readable key',f=>chmodSync(join(f.directory,'server-key.pem'),0o644)],
  ['symlink key',f=>{unlinkSync(join(f.directory,'server-key.pem'));symlinkSync('server.pem',join(f.directory,'server-key.pem'));}],
  ['hardlinked key',f=>{unlinkSync(join(f.directory,'server-key.pem'));linkSync(join(f.directory,'server.pem'),join(f.directory,'server-key.pem'));}],
  ['wrong key',f=>f.save('server-key.pem',freshLeaf().tls.key)],['wrong server certificate purpose',f=>{const x=freshLeaf({purpose:'clientAuth'});f.save('server.pem',x.tls.cert);f.save('server-key.pem',x.tls.key);}],
])test('edge material refuses '+name,t=>{const f=fixture(t);edit(f);assert.throws(()=>createContainerParticipantEdge({configurationPath:f.path}),denied);});
test('post-construction material replacement or mutation closes custody before start',async t=>{
  const f=fixture(t),edge=createContainerParticipantEdge({configurationPath:f.path});f.save('upstream-ca.pem',freshLeaf().ca);assert.throws(()=>edge.verify());await assert.rejects(edge.start());assert.equal((await edge.close()).listenerClosed,true);
});
test('image contains only fixed edge and material dependencies and no installation or signing tools',()=>{
  const docker=readFileSync(new URL('./Dockerfile',import.meta.url),'utf8');assert.match(docker,/USER 1000:1000/u);assert.match(docker,/org\.barayamal\.fncp\.profile="FNCP_PARTICIPANT_EDGE_CONTAINER_V1"/u);assert.doesNotMatch(docker,/offline-sign|production-install|operator\.mjs|npm ci|EXPOSE/u);
});
