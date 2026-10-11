import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseParticipantCommand, validateParticipantLaunch, validateParticipantBootstrapReceipt } from './participant-container-run.mjs';
import { participantRouteAllowed } from './participant-child.mjs';

for (const action of ['open','close','snapshot','stop']) test('explicit participant command '+action, () => {
  assert.equal(parseParticipantCommand(JSON.stringify({action})),action);
});
for (const input of ['', '{}', '{"action":"open","round":"other"}', '{"action":"open","action":"close"}',
  '{ "action":"open"}', '{"action":"delete"}', 'null', '[]', '{"action":false}']) test('invalid participant command '+input, () => {
  assert.throws(()=>parseParticipantCommand(input));
});
for (const [method,path] of [['GET','/api/v3/participationInit?conversation_id=3abcde&lang=en&agid=1'],
  ['GET','/api/v3/nextComment?conversation_id=3abcde'],['POST','/api/v3/votes'],
  ...['upsert','readback','remove'].map(name=>['POST','/fncp/private/xid-allowlist/'+name])]) {
  test('private participant route '+method+' '+path,()=>assert.equal(participantRouteAllowed(method,path),true));
}
for (const [method,path] of [['GET','/'],['HEAD','/api/v3/participationInit'],['POST','/api/v3/comments'],
  ['GET','/api/v3/math/pca2'],['GET','/api/v3/participationInit/'],['GET','/api/v3/%70articipationInit'],
  ['GET','/api/v3/participationInit\n'],['POST','/fncp/private/xid-allowlist/upsert/'],['GET','https://outside.invalid/api/v3/nextComment']]) {
  test('excluded participant route '+method+' '+JSON.stringify(path),()=>assert.equal(participantRouteAllowed(method,path),false));
}
test('empty/forged launch cannot select any previous configuration',()=>{
  for(const value of [undefined,null,{},[],{namespaceId:'a'.repeat(24)},new Proxy({}, {})])assert.throws(()=>validateParticipantLaunch(value));
});
const finalReceipt={version:1,bootstrapPassed:true,apiChildExitVerified:true,apiIpcDisconnected:true,apiListenerRefused:true,
  issuerClosed:true,jwksClosed:true,databaseWorkersClosed:true};
test('only complete final bootstrap exit/IPC/listener receipt is admitted',()=>{
  assert.deepEqual(validateParticipantBootstrapReceipt(finalReceipt),finalReceipt);
});
for(const key of Object.keys(finalReceipt))test('missing or unconfirmed bootstrap final receipt fact '+key,()=>{
  const missing={...finalReceipt};delete missing[key];
  assert.throws(()=>validateParticipantBootstrapReceipt(missing));
  for(const value of [false,null,'true',undefined])assert.throws(()=>validateParticipantBootstrapReceipt({...finalReceipt,[key]:value}));
});
test('receipt cannot substitute a close-call journal summary or add arbitrary facts',()=>{
  assert.throws(()=>validateParticipantBootstrapReceipt({knownCloseCallsFulfilled:true,factoriesWithoutReturnedCleanupEvidence:0}));
  assert.throws(()=>validateParticipantBootstrapReceipt({...finalReceipt,other:true}));
  assert.throws(()=>validateParticipantBootstrapReceipt({...finalReceipt,version:2}));
});
test('separate participant entrypoint has no retained configuration or ordinary index fallback',()=>{
  const owner=readFileSync(new URL('./participant-container-run.mjs',import.meta.url),'utf8');
  const child=readFileSync(new URL('./participant-child.mjs',import.meta.url),'utf8');
  assert.doesNotMatch(owner,/\.env\.staging|readStagingProvider|colima-fncp-c|bootstrap-container-run\.mjs/);
  assert.match(owner,/O_EXCL/);assert.match(owner,/EXACT_CLOSED_BASELINE_MATCHED/);
  assert.match(child,/assertFncpProductionAdmission/);assert.match(child,/host: '127\.0\.0\.1', port: 5500/);
  assert.doesNotMatch(child,/require\([^\n]*index\.js/);
});
