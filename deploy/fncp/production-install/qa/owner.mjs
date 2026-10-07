// Separate QA process. Private input/control is only newline JSON on stdin.
import assert from 'node:assert/strict';
import {createInterface} from 'node:readline';
import {lstatSync} from 'node:fs';
import {createStandaloneQaIssuer} from './issuer.mjs';
import {createMainQaActor} from './actor.mjs';
import {requestProductionOperator} from '/app/deploy/fncp/production-service/operator.mjs';
const emit=x=>process.stdout.write(JSON.stringify(x)+'\n');
const lines=createInterface({input:process.stdin,crlfDelay:Infinity});let issuer,actor,config,stopped=false,failed=false;
const exact=(v,keys)=>{assert.ok(v&&Object.getPrototypeOf(v)===Object.prototype);assert.deepEqual(Object.keys(v).sort(),[...keys].sort());};
async function stop(){if(stopped)return;stopped=true;await issuer?.close();emit({event:'CLOSED',closed:true,issuerClosed:issuer?.snapshot().closed===true,normalServiceOwnedByParent:true});lines.close();}
try{for await(const line of lines){assert.ok(Buffer.byteLength(line)<=131072);const value=JSON.parse(line);
  if(!config){exact(value,['profile','issuer','issuerCa','edgeCa','wordpressCa','operatorPassword','activationPrivateKey','expectedBinding']);assert.match(value.profile,/^FNCP_JOINED_INSTALL_QA_OWNER_V[23]$/u);assert.equal(process.getuid(),1000);const s=lstatSync('/run/qa');assert.ok(s.isDirectory()&&!s.isSymbolicLink()&&s.uid===1000&&(s.mode&0o777)===0o700);
    assert.equal(value.issuer.origin,'https://qa-issuer:8443');assert.equal(value.issuer.callbackUri,'https://pulse.synthetic.invalid/oidc/callback');assert.equal(value.issuer.clientId,'fncp-main-qa');assert.match(value.operatorPassword,/^[A-Za-z0-9_-]{43}$/u);
    exact(value.expectedBinding,['deploymentId','conversationId','sourceRevision','images',...(value.profile.endsWith('V3')?['operatorAccessSha256']:[])]);assert.match(value.expectedBinding.deploymentId,/^fncp-[a-z0-9][a-z0-9-]{4,40}$/u);assert.match(value.expectedBinding.conversationId,/^[0-9][A-Za-z0-9]{5,99}$/u);const roles=['api','math','postgres','migration','participant','wordpress','mariadb','proxy','edge',...(value.profile.endsWith('V3')?['operator']:[])];exact(value.expectedBinding.images,roles);for(const image of Object.values(value.expectedBinding.images))assert.match(image,/^sha256:[a-f0-9]{64}$/u);assert.equal(new Set(Object.values(value.expectedBinding.images)).size,roles.length);assert.match(value.expectedBinding.sourceRevision,/^[a-f0-9]{40}$/u);if(value.profile.endsWith('V3'))assert.match(value.expectedBinding.operatorAccessSha256,/^[a-f0-9]{64}$/u);
    config=value;issuer=await createStandaloneQaIssuer(value.issuer);actor=createMainQaActor(value,requestProductionOperator,value=>emit({event:'PROGRESS',...value}));emit({event:'READY',profile:value.profile,issuerReady:true,productionServicesStartedByActor:false});continue;
  }
  exact(value,['action']);if(value.action==='prove')emit({event:'PROOF',...await actor.prove()});else if(value.action==='close-admission')emit({event:'CONTROL',action:value.action,ok:true,...await actor.closeAdmission()});else if(value.action==='snapshot')emit({event:'SNAPSHOT',...actor.snapshot(),issuer:issuer.snapshot()});else if(value.action==='stop'){await stop();break;}else throw Error();
}await stop();}catch{failed=true;emit({event:'FAILED',error:'Joined-install QA failed.',...actor?.snapshot(),issuer:issuer?.snapshot()});try{await stop();}catch{}process.exitCode=1;}finally{if(failed)process.exitCode=1;}
