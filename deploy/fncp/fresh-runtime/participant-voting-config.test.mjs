/** Join the real participant environment builder to the real gateway policy.
 * No app/runtime/database is launched. A new certificate is an inert fixture.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { participantEnvironment } from './participant-container-run.mjs';

const require = createRequire(new URL('../../../server/package.json', import.meta.url));
const ts = require('typescript');
function policy(name) {
  const source = readFileSync(new URL('../../../server/src/auth/'+name+'.ts', import.meta.url),'utf8');
  const compiled = ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,
    module:ts.ModuleKind.CommonJS,esModuleInterop:true}}).outputText;
  const module={exports:{}};
  const imports=name==='fncp-gateway' ? {'./fncp-log-boundary':policy('fncp-log-boundary')} : {};
  new Function('require','module','exports',compiled)(name=>imports[name]??require(name),module,module.exports);
  return module.exports;
}
const {loadFncpGatewayConfig,evaluateFncpGatewayRequest}=policy('fncp-gateway');
function fixture(t) {
  const directory=mkdtempSync(join(tmpdir(),'participant-voting-config-'));
  t.after(()=>rmSync(directory,{recursive:true,force:false}));
  const namespaceId='a'.repeat(24),host='fncp-fresh-pg-'+namespaceId;
  execFileSync(process.platform==='darwin'?'/opt/homebrew/bin/openssl':'/usr/bin/openssl',
    ['req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-noenc','-days','1',
      '-subj','/CN=synthetic.invalid','-addext',`subjectAltName=DNS:${host},IP:127.0.0.1`,
      '-keyout',join(directory,'key.pem'),'-out',join(directory,'cert.pem')],
    {timeout:10000,stdio:'ignore',env:{PATH:'/usr/bin:/bin',OPENSSL_CONF:'/dev/null'}});
  const databaseCertificatePem=readFileSync(join(directory,'cert.pem'),'utf8');
  const launch={namespaceId,database:'fncp_fresh_'+'b'.repeat(24),user:'fncp_fresh_'+'c'.repeat(24),password:'d'.repeat(64),
    databaseCertificatePem,databaseCertificateSha256:createHash('sha256').update(new X509Certificate(databaseCertificatePem).raw).digest('hex')};
  const provider={conversationId:'3syntheticVotingConfig',gatewaySecret:'g'.repeat(43),providerSecret:'p'.repeat(43)};
  // Deliberately nonsequential: silently substituting 0..14 must fail this test.
  const binding={conversationId:provider.conversationId,statementIds:Array.from({length:15},(_,n)=>101+n*3),seedOwnerPid:0};
  const request=tid=>({method:'POST',path:'/api/v3/votes',query:{},
    headers:{'x-fncp-gateway-key':provider.gatewaySecret,'x-fncp-conversation-id':provider.conversationId,
      'x-fncp-participant-xid':'fncp_'+'x'.repeat(43)},body:{conversation_id:provider.conversationId,tid,vote:0}});
  return {launch,provider,binding,request};
}
test('actual bootstrap TIDs reach real gateway and admit every exact manifest vote',t=>{
  const {launch,provider,binding,request}=fixture(t);
  const env=participantEnvironment(launch,provider,binding),config=loadFncpGatewayConfig(env);
  assert.deepEqual([...config.fixedStatementIds],binding.statementIds);
  for(const tid of binding.statementIds)assert.equal(evaluateFncpGatewayRequest(request(tid),config).status,undefined);
  assert.equal(evaluateFncpGatewayRequest(request(0),config).status,400);
});
test('omitting the environment manifest reproduces read-ready but vote-denied failure',t=>{
  const {launch,provider,binding,request}=fixture(t);
  const env={...participantEnvironment(launch,provider,binding)};delete env.FNCP_FIXED_STATEMENT_IDS;
  const config=loadFncpGatewayConfig(env);
  assert.equal(evaluateFncpGatewayRequest(request(binding.statementIds[0]),config).status,503);
  const read={...request(binding.statementIds[0]),method:'GET',path:'/api/v3/participationInit',body:{}};
  assert.equal(evaluateFncpGatewayRequest(read,config).status,undefined);
});
test('missing, duplicate or differently scoped binding cannot build participant environment',t=>{
  const {launch,provider,binding}=fixture(t);
  assert.throws(()=>participantEnvironment(launch,provider));
  assert.throws(()=>participantEnvironment(launch,provider,{...binding,conversationId:'4otherSyntheticRound'}));
  assert.throws(()=>participantEnvironment(launch,provider,{...binding,statementIds:Array(15).fill(1)}));
});
