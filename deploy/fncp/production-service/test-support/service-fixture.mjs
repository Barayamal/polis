// TEST SUPPORT ONLY. File-backed composition with fresh native HTTPS peers.
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { mkdirSync, mkdtempSync, realpathSync, chmodSync, writeFileSync, rmSync } from 'node:fs';
import { createServer, connect } from 'node:net';
import { request } from 'node:https';
import { join } from 'node:path';
import { createProductionFixture } from './production-fixture.mjs';
import { freshCertificate } from '../../production-identity/test-support/https-issuer.mjs';
import { IMAGE_ROLES } from '../../production-activation/protocol.mjs';
import { signProductionActivation } from '../../production-activation/offline-sign.mjs';
import { createProductionService } from '../service.mjs';

async function availablePort(){const server=createServer();await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});const port=server.address().port;await new Promise(resolve=>server.close(resolve));return port;}
export async function refused(port){await new Promise((resolve,reject)=>{const socket=connect({host:'127.0.0.1',port});socket.setTimeout(500);socket.once('connect',()=>{socket.destroy();reject(Error('owned listener still open'));});socket.once('timeout',()=>{socket.destroy();reject(Error('refusal deadline'));});socket.once('error',e=>{socket.destroy();e.code==='ECONNREFUSED'?resolve():reject(Error('unexpected refusal result'));});});}
export async function serviceFixture(t){
  const participantPort=await availablePort();let receiverPort=await availablePort();while(receiverPort===participantPort)receiverPort=await availablePort();
  const participantOrigin='https://127.0.0.1:'+participantPort,receiverOrigin='https://127.0.0.1:'+receiverPort;
  const peerCleanup=[],h=await createProductionFixture({after:fn=>peerCleanup.push(fn)},{callbackUri:participantOrigin+'/oidc/callback'});
  const directory=realpathSync(mkdtempSync('/tmp/fncp-service-test-')),materialDirectory=join(directory,'material'),stateDirectory=join(directory,'state');chmodSync(directory,0o700);
  for(const path of [materialDirectory,stateDirectory])mkdirSync(path,{mode:0o700});
  const material=h.testConstructionMaterial,signingKeys=generateKeyPairSync('ed25519'),participantTls=freshCertificate(),receiverTls=freshCertificate();
  const file=(name,body)=>{const path=join(materialDirectory,name);writeFileSync(path,body,{mode:0o600});return path;};
  const {now,identityKey,ca,clientSecret,...identityPublic}=material.identity;
  const manifest={profile:'FNCP_PRODUCTION_SERVICE_V1',deploymentId:h.configuration.deploymentId,conversationId:h.configuration.conversationId,stateDirectory,
    participant:{origin:participantOrigin,host:'127.0.0.1',port:participantPort},receiver:{origin:receiverOrigin,host:'127.0.0.1',port:receiverPort},
    identity:{...identityPublic,clientSecretFile:file('oidc-secret.txt',clientSecret),identityKeyFile:file('identity-key.txt',identityKey.toString('base64url')),caFile:file('identity-ca.pem',ca)},
    provider:{origin:material.provider.origin},wordpress:{origin:material.wordpress.origin},
    activation:{sourceRevision:'1'.repeat(40),images:Object.fromEntries(IMAGE_ROLES.map(role=>[role,'sha256:'+'2'.repeat(64)])),recoveryEpoch:randomUUID(),keyId:'service-fixture-review-key',publicKeyFile:file('activation-public.pem',signingKeys.publicKey.export({format:'pem',type:'spki'}))},
    content:{consentVersion:h.configuration.consentVersion,notice:h.configuration.notice,statementIds:h.configuration.statementIds,statements:h.configuration.statements},
    secrets:{gatewayKeyFile:file('gateway-key.txt',material.provider.gatewaySecret),providerKeyFile:file('provider-key.txt',material.provider.providerSecret),wordpressRequestKeyFile:file('wordpress-request-key.txt',material.wordpress.requestKey),wordpressResponseKeyFile:file('wordpress-response-key.txt',material.wordpress.responseKey),wordpressEventKeyFile:file('wordpress-event-key.txt',material.wordpress.eventKey)},
    tls:{participantKeyFile:file('participant-key.pem',participantTls.key),participantCertFile:file('participant-cert.pem',participantTls.cert),receiverKeyFile:file('receiver-key.pem',receiverTls.key),receiverCertFile:file('receiver-cert.pem',receiverTls.cert)},
    trust:{providerCaFile:file('provider-ca.pem',material.provider.ca),wordpressCaFile:file('wordpress-ca.pem',material.wordpress.ca)}};
  const configurationPath=join(materialDirectory,'service.json'),instances=[];
  const save=()=>writeFileSync(configurationPath,JSON.stringify(manifest,null,2)+'\n',{mode:0o600});save();
  t.after(async()=>{for(const s of instances)try{await s.close();}catch{}for(const cleanup of peerCleanup)await cleanup();rmSync(directory,{recursive:true,force:true});});
  async function create(){const service=await createProductionService({configurationPath});instances.push(service);return service;}
  function envelope(service){const at=Math.floor(Date.now()/1000);return signProductionActivation({challenge:service.operator.challenge(),privateKey:signingKeys.privateKey,activationId:randomUUID(),issuedAt:at,notBefore:at,expiresAt:at+600});}
  function client(){const jar=new Map();let csrf='';
    async function call(path,values,overrides={}){const method=values===undefined?'GET':'POST',raw=values===undefined?undefined:JSON.stringify(values);return new Promise((resolve,reject)=>{
      const req=request({hostname:'127.0.0.1',port:participantPort,ca:participantTls.cert,rejectUnauthorized:true,agent:false,method,path,
        headers:{host:new URL(participantOrigin).host,connection:'close','sec-fetch-site':'same-origin','sec-fetch-mode':'cors','sec-fetch-dest':'empty',...(jar.size?{cookie:[...jar].map(([k,v])=>k+'='+v).join('; ')}:{}),...(csrf?{'x-csrf-token':csrf}:{}),...(raw===undefined?{}:{origin:participantOrigin,'content-type':'application/json','content-length':Buffer.byteLength(raw)}),...overrides}},res=>{
        const chunks=[];res.on('data',b=>chunks.push(b));res.once('error',reject);res.once('end',()=>{try{const text=Buffer.concat(chunks).toString('utf8'),body=/application\/json/u.test(res.headers['content-type']??'')?JSON.parse(text):text;for(const cookie of res.headers['set-cookie']??[]){const[k,v]=cookie.split(';')[0].split('=');if(!v||/Max-Age=0(?:;|$)/u.test(cookie))jar.delete(k);else jar.set(k,v);}if(body?.csrf)csrf=body.csrf;resolve({status:res.statusCode,headers:res.headers,body});}catch{reject(Error('invalid fixture reply'));}});
      });req.setTimeout(3000,()=>req.destroy(Error('fixture request deadline')));req.once('error',reject);req.end(raw);
    });}
    async function login(){assert.equal((await call('/session')).status,200);const begun=await call('/oidc/login',{});assert.equal(begun.status,200);const callback=new URL(h.issuer.authorizationResponse(begun.body.authorizationUrl));const response=await call(callback.pathname+callback.search,undefined,{'sec-fetch-site':'cross-site','sec-fetch-mode':'navigate','sec-fetch-dest':'document','sec-fetch-user':'?1'});assert.equal(response.status,303);const status=await call('/session');assert.equal(status.body.authenticated,true);return status;}
    return{call,login,jar};
  }
  return{h,manifest,configurationPath,materialDirectory,stateDirectory,participantPort,receiverPort,participantTls,receiverTls,signingKeys,save,create,envelope,client};
}
