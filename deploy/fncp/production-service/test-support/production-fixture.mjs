// TEST SUPPORT ONLY. Invented registrations and protocol peers, never production imports.
import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { randomBytes,randomUUID,generateKeyPairSync,createHmac } from 'node:crypto';
import { mkdtempSync,realpathSync,chmodSync,rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createTestIssuer,freshCertificate } from '../../production-identity/test-support/https-issuer.mjs';
import { createProductionPolisProvider } from '../../production-provider/provider.mjs';
import { createProductionActivation } from '../../production-activation/authority.mjs';
import { signProductionActivation } from '../../production-activation/offline-sign.mjs';
import { IMAGE_ROLES } from '../../production-activation/protocol.mjs';
import { createProductionWordPressBridge } from '../wordpress-bridge.mjs';
import { createProductionAccess } from '../access.mjs';
import { canonical,sha } from '../contracts.mjs';
const token=()=>randomBytes(32).toString('base64url');
const hmac=(key,value)=>createHmac('sha256',Buffer.from(key,'base64url')).update(value).digest('hex');
async function peer(handler){const tls=freshCertificate();const sockets=new Set();const server=createServer(tls,async(req,res)=>{req.on('error',()=>{});res.on('error',()=>{});try{await handler(req,res);}catch{if(!res.headersSent)res.writeHead(503,{'content-type':'application/json'});res.end('{"error":"fixture_unavailable"}');}});server.on('connection',s=>{sockets.add(s);s.on('close',()=>sockets.delete(s));});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));return{origin:'https://127.0.0.1:'+server.address().port,tls,async close(){await new Promise(resolve=>{server.close(resolve);for(const s of sockets)s.destroy();});}};}
const read=async req=>{let s='';for await(const b of req){s+=b;if(s.length>16384)throw Error('fixture body');}return s;};
const json=(res,value,status=200)=>{res.writeHead(status,{'content-type':'application/json','cache-control':'no-store, private'});res.end(JSON.stringify(value));};
export async function createProductionFixture(t,options={}){
  const directory=realpathSync(mkdtempSync(join(tmpdir(),'fncp-production-service-test-')));chmodSync(directory,0o700);let instant=Date.now();const now=()=>instant;
  const issuer=await createTestIssuer({now,...(options.callbackUri?{callbackUri:options.callbackUri}:{})});let identity=issuer.identity;
  const records=new Map(),receipts=new Map(),allowlist=new Map(),votes=[];const calls=[];const behavior={};
  const requestKey=token(),responseKey=token(),eventKey=token(),gatewaySecret=token(),providerSecret=token();
  const notice={adultDeclaration:'Synthetic test: I self-attest that I am at least 18.',eligibilityDeclaration:'Synthetic test: I self-attest to this round eligibility.',registrationDeclaration:'Synthetic test: I consent to registration under this notice.'};
  const c={deploymentId:'fncp-production-fixture',conversationId:'9productionFixture',consentVersion:'synthetic-notice-v1',noticeSha256:sha(canonical(notice)),statementIds:Array.from({length:15},(_,i)=>i),statements:Array.from({length:15},(_,i)=>`Invented test statement ${i+1}.`),identityBindingSha256:'d'.repeat(64),credentialBindingSha256:sha(canonical({gatewaySecretSha256:sha(gatewaySecret),providerSecretSha256:sha(providerSecret),eventKeySha256:sha(eventKey)})),notice};
  const wp=await peer(async(req,res)=>{const action=req.url?.split('/').at(-1);const raw=await read(req);if(behavior.wpGate)await behavior.wpGate(action);if(behavior.wpDown)return json(res,{error:'unavailable'},503);
    assert.equal(req.method,'POST');assert.equal(req.url,'/wp-json/fncp/v1/'+action);assert.ok(['register','status'].includes(action));assert.equal(req.headers.origin,undefined);assert.equal(req.headers.cookie,undefined);assert.equal(req.headers['x-fncp-signature'],'sha256='+hmac(requestKey,'FNCP_WP_REQUEST_V1\n'+action+'\n'+req.headers['x-fncp-timestamp']+'.'+raw));const p=JSON.parse(raw);assert.equal(canonical(p),raw);assert.equal(p.deploymentId,c.deploymentId);assert.equal(p.conversationId,c.conversationId);calls.push({peer:'wordpress',action});
    let value;
    if(action==='register'){
      const old=receipts.get(p.receiptId);if(old&&old.raw!==raw)return json(res,{error:'conflict'},409);
      if(!old){if(p.expiresAt<=Math.floor(now()/1000))return json(res,{error:'expired'},403);if(records.has(p.accountId)||records.size>=20)return json(res,{error:'conflict'},409);assert.equal(p.noticeSha256,c.noticeSha256);assert.equal(p.adultSelfAttested&&p.eligibilitySelfAttested&&p.registrationConsent,true);
        const row={registrationId:randomUUID(),state:'pending',version:0,decisionEventId:null,deliveryPending:false};records.set(p.accountId,row);receipts.set(p.receiptId,{raw,id:row.registrationId});}
      value={schemaVersion:1,deploymentId:c.deploymentId,conversationId:c.conversationId,receiptId:p.receiptId,registrationId:receipts.get(p.receiptId).id,status:'SUBMITTED_NOT_APPROVED'};
      if(behavior.registrationResponseLost)return json(res,{error:'lost'},503);
    }else{const r=records.get(p.accountId);value={schemaVersion:1,deploymentId:c.deploymentId,conversationId:c.conversationId,accountId:p.accountId,nonce:behavior.wrongNonce?token():p.nonce,...(r??{registrationId:null,state:'unregistered',version:0,decisionEventId:null,deliveryPending:false}),observedAt:Math.floor(now()/1000)};}
    const payload=Buffer.from(canonical(value)).toString('base64url');json(res,{payload,signature:behavior.badSignature?'0'.repeat(64):hmac(responseKey,'FNCP_WP_RESPONSE_V1\n'+action+'\n'+payload)});
  });
  const polis=await peer(async(req,res)=>{const u=new URL(req.url,'https://fixture.invalid');const raw=await read(req);const body=raw?JSON.parse(raw):null;const operation=u.pathname.split('/').at(-1);calls.push({peer:'polis',operation});if(behavior.providerGate)await behavior.providerGate(operation,body);if(behavior.providerDown)return json(res,{error:'unavailable'},503);
    if(u.pathname.startsWith('/fncp/private/xid-allowlist/')){
      assert.equal(req.headers.authorization,'Bearer '+providerSecret);assert.equal(body.conversationId,c.conversationId);const old=allowlist.get(body.participantXid);
      if(operation==='readback')return json(res,{conversationId:c.conversationId,participantXid:body.participantXid,operationVersion:old??null,present:old===1});
      if(operation==='upsert'&&old===2)return json(res,{error:'terminal'},409);assert.equal(body.operationVersion,operation==='upsert'?1:2);allowlist.set(body.participantXid,body.operationVersion);res.writeHead(204);return res.end();
    }
    assert.equal(req.headers['x-fncp-gateway-key'],gatewaySecret);assert.equal(req.headers['x-fncp-conversation-id'],c.conversationId);const xid=req.headers['x-fncp-participant-xid'];if(allowlist.get(xid)!==1)return json(res,{error:'denied'},403);
    const nextComment={tid:0,txt:behavior.badStatement?'Unreviewed text':c.statements[0],remaining:15,total:15};
    if(operation==='votes'){votes.push({xid,tid:body.tid,vote:body.vote});return json(res,{nextComment,auth:'SENSITIVE_FIXTURE_ONLY',currentPid:999});}
    if(operation==='nextComment')return json(res,nextComment);
    return json(res,{nextComment,votes:[],conversation:{conversation_id:c.conversationId},auth:'SENSITIVE_FIXTURE_ONLY'});
  });
  const keys=generateKeyPairSync('ed25519');let access,activation,provider,wordpress;let closed=false;
  const start=()=>{
    provider=createProductionPolisProvider({origin:polis.origin,conversationId:c.conversationId,statementIds:c.statementIds,gatewaySecret,providerSecret,ca:polis.tls.cert});
    wordpress=createProductionWordPressBridge({origin:wp.origin,deploymentId:c.deploymentId,conversationId:c.conversationId,consentVersion:c.consentVersion,noticeSha256:c.noticeSha256,serviceRequestKey:requestKey,serviceResponseKey:responseKey,ca:wp.tls.cert,now});
    activation=createProductionActivation({binding:{deploymentId:c.deploymentId,conversationId:c.conversationId,sourceRevision:'1'.repeat(40),configSha256:sha(canonical(c)),seedSha256:sha(canonical(c.statements)),providerSha256:sha(canonical(provider.binding())),images:Object.fromEntries(IMAGE_ROLES.map(k=>[k,'sha256:'+'2'.repeat(64)])),recoveryEpoch:options.recoveryEpoch??'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',scope:{maxParticipants:20,statementCount:15,suggestions:false}},publicKey:keys.publicKey,keyId:'fixture-offline-key',ledgerPath:join(directory,'activation.sqlite'),now});
    access=createProductionAccess({identity,provider,activation,wordpress,storePath:join(directory,'access.sqlite'),configuration:c,now});
  };
  try{start();}catch(e){try{activation?.dispose();provider?.close();wordpress?.close();}catch{}await wp.close();await polis.close();await issuer.close();rmSync(directory,{recursive:true,force:true});throw e;}
  const result={directory,configuration:c,get identity(){return identity;},issuer,behavior,records,allowlist,votes,calls,wpOrigin:wp.origin,wpCa:wp.tls.cert,eventKey,now,setTime:v=>{instant=v;},advance:ms=>{instant+=ms;},get access(){return access;},get activation(){return activation;},get wordpress(){return wordpress;},
    // TEST SUPPORT ONLY: copied construction material for a second real service
    // with its own state directory; never imported or exposed by runtime code.
    get testConstructionMaterial(){return{identity:{...issuer.options,identityKey:Buffer.from(issuer.options.identityKey),ca:Buffer.from(issuer.options.ca)},
      wordpress:{origin:wp.origin,ca:Buffer.from(wp.tls.cert),requestKey,responseKey,eventKey},
      provider:{origin:polis.origin,ca:Buffer.from(polis.tls.cert),gatewaySecret,providerSecret}};},
    async principal(subject='invented-subject'){const r=await issuer.authenticate({claims:{sub:subject}},identity);assert.equal(r.ok,true);await access.authenticate(r.principal);return r.principal;},
    activate(){const at=Math.floor(now()/1000);activation.accept(signProductionActivation({challenge:activation.challenge(),privateKey:keys.privateKey,activationId:randomUUID(),issuedAt:at,notBefore:at,expiresAt:at+600}));access.operator.setRoundOpen(true);},
    async register(p){return access.register(p,{consentVersion:c.consentVersion,adultSelfAttested:true,eligibilitySelfAttested:true,registrationConsent:true});},
    event(p,state){const r=records.get(p.accountId);assert.ok(r);if(r.state==='revoked'&&state==='approved')throw Error('terminal fixture');const version=state==='approved'?1:2,eventId=r.state===state?r.decisionEventId:randomUUID();Object.assign(r,{state,version,decisionEventId:eventId,deliveryPending:true});return{schemaVersion:1,eventId,deploymentId:c.deploymentId,conversationId:c.conversationId,registrationId:r.registrationId,accountId:p.accountId,version,state,occurredAt:Math.floor(now()/1000)};},
    async approve(p){const e=result.event(p,'approved');const ack=await access.ingestWordPressEvent(e);records.get(p.accountId).deliveryPending=false;return {event:e,ack};},
    async revoke(p){const e=result.event(p,'revoked');const ack=await access.ingestWordPressEvent(e);records.get(p.accountId).deliveryPending=false;return {event:e,ack};},
    invite:p=>access.operator.issueInvitation(p.accountId),
    async restart(){await access.close();identity=issuer.createAdapter();start();},
    async close(){if(closed)return;closed=true;try{await access.close();}catch{}await wp.close();await polis.close();await issuer.close();rmSync(directory,{recursive:true,force:true});}
  };t.after(()=>result.close());return result;
}
