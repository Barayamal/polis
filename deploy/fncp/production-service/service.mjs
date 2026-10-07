import {createPublicKey,createPrivateKey} from 'node:crypto';
import {join} from 'node:path';
import {createProductionIdentity} from '../production-identity/identity.mjs';
import {createProductionPolisProvider} from '../production-provider/provider.mjs';
import {createProductionActivation} from '../production-activation/authority.mjs';
import {createProductionWordPressBridge} from './wordpress-bridge.mjs';
import {createProductionAccess} from './access.mjs';
import {createProductionBrowser} from './browser.mjs';
import {createProductionWordPressReceiver} from './event-receiver.mjs';
import {createMaterialCustody,acquireServiceLock} from './custody.mjs';
import {exact,canonical,sha,secretBytes,SHA} from './contracts.mjs';
const failure=()=>new Error('Production service unavailable.');
const instances=new WeakSet();
export const isProductionService=value=>instances.has(value);
/** Strict file-backed composition. No request or serialized principal can
 * provide adapters, clocks, authority or endpoint configuration. */
export async function createProductionService({configurationPath}){
 const custody=createMaterialCustody();let lock,identity,provider,wordpress,activation,access,browser,receiver,manifest,configurationSha256,closed=false,closing=false,started=false,running=false,timer,last=-1,closePromise;const buffers=[];
 const bytes=(path,max)=>{const b=custody.read(path,max);buffers.push(b);return b;};
 const text=(path,max=8192)=>{const b=bytes(path,max),s=b.toString('utf8');if(!Buffer.from(s).equals(b)||s.trim()!==s)throw failure();return s;};
 try{
  const raw=bytes(configurationPath,131072);manifest=JSON.parse(raw.toString('utf8'));
  exact(manifest,['profile','deploymentId','conversationId','stateDirectory','participant','receiver','identity','provider','wordpress','activation','content','secrets','tls','trust']);
  if(manifest.profile!=='FNCP_PRODUCTION_SERVICE_V1')throw failure();
  lock=acquireServiceLock(manifest.stateDirectory);
  exact(manifest.participant,['origin','host','port']);exact(manifest.receiver,['origin','host','port']);
  for(const listener of [manifest.participant,manifest.receiver])if(!['127.0.0.1','0.0.0.0','::1','::'].includes(listener.host)||!Number.isInteger(listener.port)||listener.port<1||listener.port>65535)throw failure();
  if(manifest.participant.origin===manifest.receiver.origin||manifest.participant.port===manifest.receiver.port)throw failure();
  exact(manifest.identity,['issuer','authorizationEndpoint','tokenEndpoint','jwksUri','callbackUri','clientId','tokenEndpointAuthMethod','signingAlgorithm','clientSecretFile','identityKeyFile'],['caFile']);
  exact(manifest.provider,['origin']);exact(manifest.wordpress,['origin']);
  const edgeBinding=Object.hasOwn(manifest.activation.images??{},'edge');
  const operatorImage=Object.hasOwn(manifest.activation.images??{},'operator');
  const operatorBinding=Object.hasOwn(manifest.activation??{},'operatorAccessSha256');
  exact(manifest.activation,['sourceRevision','images','recoveryEpoch','keyId','publicKeyFile',...(edgeBinding?['edgeMaterialSha256']:[]),...(operatorBinding?['operatorAccessSha256']:[])]);
  if(edgeBinding&&(typeof manifest.activation.edgeMaterialSha256!=='string'||!SHA.test(manifest.activation.edgeMaterialSha256))
    ||operatorBinding!==operatorImage||operatorBinding&&(!edgeBinding||typeof manifest.activation.operatorAccessSha256!=='string'||!SHA.test(manifest.activation.operatorAccessSha256)))throw failure();
  exact(manifest.content,['consentVersion','notice','statementIds','statements']);
  exact(manifest.secrets,['gatewayKeyFile','providerKeyFile','wordpressRequestKeyFile','wordpressResponseKeyFile','wordpressEventKeyFile']);
  exact(manifest.tls,['participantKeyFile','participantCertFile','receiverKeyFile','receiverCertFile']);
  exact(manifest.trust,[],['providerCaFile','wordpressCaFile']);
  if(manifest.identity.callbackUri!==manifest.participant.origin+'/oidc/callback'||new Set([manifest.participant.origin,manifest.receiver.origin,manifest.provider.origin,manifest.wordpress.origin]).size!==4)throw failure();
  const {clientSecretFile,identityKeyFile,caFile,...idPublic}=manifest.identity;
  const identityKey=secretBytes(text(identityKeyFile));buffers.push(identityKey);const clientSecret=text(clientSecretFile,2048);
  const secrets=Object.fromEntries(Object.entries(manifest.secrets).map(([role,path])=>[role,text(path,43)]));
  const keyHashes=[sha(identityKey),...Object.values(secrets).map(s=>{const b=secretBytes(s);try{return sha(b);}finally{b.fill(0);}})];if(new Set(keyHashes).size!==keyHashes.length||Object.values(secrets).includes(clientSecret)||clientSecret===identityKey.toString('base64url'))throw failure();
  const idCa=caFile?bytes(caFile):undefined,providerCa=manifest.trust.providerCaFile?bytes(manifest.trust.providerCaFile):undefined,wpCa=manifest.trust.wordpressCaFile?bytes(manifest.trust.wordpressCaFile):undefined;
  const participantTls={key:bytes(manifest.tls.participantKeyFile,32768),cert:bytes(manifest.tls.participantCertFile)},receiverTls={key:bytes(manifest.tls.receiverKeyFile,32768),cert:bytes(manifest.tls.receiverCertFile)};
  if(sha(createPublicKey(createPrivateKey(participantTls.key)).export({format:'der',type:'spki'}))===sha(createPublicKey(createPrivateKey(receiverTls.key)).export({format:'der',type:'spki'})))throw failure();
  const activationPublicPem=bytes(manifest.activation.publicKeyFile,8192);
  if(!/^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\r?\n?$/u.test(activationPublicPem.toString('ascii'))||activationPublicPem.some(b=>b>127))throw failure();
  const publicKey=createPublicKey(activationPublicPem);
  configurationSha256=sha(canonical({manifest,material:custody.fingerprints()}));
  identity=createProductionIdentity({...idPublic,clientSecret,identityKey,...(idCa?{ca:idCa}:{})});
  provider=createProductionPolisProvider({...manifest.provider,conversationId:manifest.conversationId,statementIds:manifest.content.statementIds,gatewaySecret:secrets.gatewayKeyFile,providerSecret:secrets.providerKeyFile,...(providerCa?{ca:providerCa}:{})});
  const c={deploymentId:manifest.deploymentId,conversationId:manifest.conversationId,...manifest.content,noticeSha256:sha(canonical(manifest.content.notice)),credentialBindingSha256:sha(canonical({
   listeners:{participant:manifest.participant,receiver:manifest.receiver},
   secrets:Object.fromEntries(Object.entries(secrets).map(([role,value])=>[role,sha(value)])),
   activationAuthority:{keyId:manifest.activation.keyId,publicKeySha256:sha(publicKey.export({format:'der',type:'spki'}))},
   tls:{participantKeySha256:sha(participantTls.key),participantCertSha256:sha(participantTls.cert),receiverKeySha256:sha(receiverTls.key),receiverCertSha256:sha(receiverTls.cert)},
  })),identityBindingSha256:sha(canonical({configuration:idPublic,identityKeySha256:sha(identityKey),clientSecretSha256:sha(clientSecret),trustSha256:idCa?sha(idCa):null}))};
  wordpress=createProductionWordPressBridge({...manifest.wordpress,deploymentId:c.deploymentId,conversationId:c.conversationId,consentVersion:c.consentVersion,noticeSha256:c.noticeSha256,serviceRequestKey:secrets.wordpressRequestKeyFile,serviceResponseKey:secrets.wordpressResponseKeyFile,...(wpCa?{ca:wpCa}:{})});
  activation=createProductionActivation({binding:{deploymentId:c.deploymentId,conversationId:c.conversationId,sourceRevision:manifest.activation.sourceRevision,configSha256:configurationSha256,seedSha256:sha(canonical(c.statements)),providerSha256:sha(canonical(provider.binding())),images:manifest.activation.images,recoveryEpoch:manifest.activation.recoveryEpoch,
    ...(operatorBinding?{operatorAccessSha256:manifest.activation.operatorAccessSha256}:{}),scope:{maxParticipants:20,statementCount:15,suggestions:false}},publicKey,keyId:manifest.activation.keyId,ledgerPath:join(manifest.stateDirectory,'activation.sqlite')});
  access=createProductionAccess({identity,provider,wordpress,activation,storePath:join(manifest.stateDirectory,'access.sqlite'),configuration:c});
  receiver=createProductionWordPressReceiver({...manifest.receiver,tls:receiverTls,access,eventKey:secrets.wordpressEventKeyFile});
  browser=createProductionBrowser({...manifest.participant,tls:participantTls,identity,access});
 }catch{
  try{await receiver?.close();}catch{}try{if(browser)await browser.close();else if(access)await access.close();else{identity?.close();provider?.close();wordpress?.close();activation?.dispose();}}catch{}
  try{lock?.release();}catch{}custody.close();for(const b of buffers)b.fill(0);throw failure();
 }
 // Browser currently retains TLS input bytes for its owned server. Keep these
 // captured buffers private until the complete service drains.
 function verify(){try{if(closing||closed)throw failure();const at=Date.now();if(!Number.isSafeInteger(at)||at<last)throw failure();last=at;lock.verify();custody.verify();if(running){const b=browser.snapshot(),r=receiver.snapshot();if(b.phase!=='RUNNING'||b.admissionClosed||!b.listenerOpen||r.closing||r.faulted||!r.listenerOpen)throw failure();}return true;}catch{try{access.closeAdmission();}catch{}if(!closing)queueMicrotask(()=>void close().catch(()=>{}));throw failure();}}
 async function close(){if(closePromise)return closePromise;closing=true;running=false;clearInterval(timer);try{access.closeAdmission();}catch{}
  closePromise=(async()=>{let failed=false;try{await receiver.close();}catch{failed=true;}try{await browser.close();}catch{failed=true;}try{lock.release();}catch{failed=true;}custody.close();for(const b of buffers)b.fill(0);closed=true;if(failed)throw failure();return Object.freeze({closed:true,drained:true});})();return closePromise;
 }
 function ready(){verify();const b=browser.snapshot(),r=receiver.snapshot();if(!running||b.phase!=='RUNNING'||b.admissionClosed||!b.listenerOpen||r.closing||r.faulted||!r.listenerOpen){access.closeAdmission();throw failure();}}
 const operator=Object.freeze({
  status(){verify();return Object.freeze({profile:manifest.profile,configurationSha256,...access.operator.status(),browser:browser.snapshot(),receiver:receiver.snapshot()});},
  challenge(){verify();return activation.challenge();},
  recoveryDescriptor(){verify();return access.operator.recoveryDescriptor();},
  activate(envelope){verify();return activation.accept(envelope);},
  admit(){ready();return access.operator.setRoundOpen(true);},
  closeAdmission(){verify();access.closeAdmission();return Object.freeze({roundOpen:false});},
  issueInvitation(accountId){ready();return access.operator.issueInvitation(accountId);},
  issueInvitationForRegistration(registrationId){ready();return access.operator.issueInvitationForRegistration(registrationId);},
 });
 const result=Object.freeze({operator,stateDirectory:manifest.stateDirectory,
  async start(){if(started||closing||closed)throw failure();started=true;verify();try{const eventListener=await receiver.start();verify();const participantListener=await browser.start();verify();running=true;timer=setInterval(()=>{try{verify();}catch{}},1000);timer.unref();return Object.freeze({profile:manifest.profile,participantOrigin:participantListener.origin,eventOrigin:eventListener.origin,roundOpen:false});}catch{await close().catch(()=>{});throw failure();}},
  close,
 });instances.add(result);return result;
}
