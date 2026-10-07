import { request } from 'node:https';
import { checkServerIdentity } from 'node:tls';
import { performance } from 'node:perf_hooks';
import { createHmac, randomBytes, X509Certificate } from 'node:crypto';
import { ACCOUNT,UUID,SHA,NAME,CONVERSATION,exact,canonical,sha,same,secretBytes,validDeclarations } from './contracts.mjs';
const registry=new WeakSet();
const failure=()=>new Error('WordPress registration unavailable.');
const REQUEST='FNCP_WP_REQUEST_V1\n',RESPONSE='FNCP_WP_RESPONSE_V1\n';
export const isProductionWordPressBridge=value=>registry.has(value);
export function createProductionWordPressBridge(options){
  let settings,requestKey,responseKey,ca;
  try{
    exact(options,['origin','deploymentId','conversationId','consentVersion','noticeSha256','serviceRequestKey','serviceResponseKey'],['ca','now']);
    const u=new URL(options.origin);
    if(!/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(u.hostname)||u.protocol!=='https:'||u.origin!==options.origin||u.username||u.password||u.search||u.hash||!NAME.test(options.deploymentId)||!CONVERSATION.test(options.conversationId)
      ||typeof options.consentVersion!=='string'||! /^[A-Za-z0-9_-]{1,128}$/u.test(options.consentVersion)||!SHA.test(options.noticeSha256))throw failure();
    requestKey=secretBytes(options.serviceRequestKey);responseKey=secretBytes(options.serviceResponseKey);if(same(options.serviceRequestKey,options.serviceResponseKey))throw failure();
    if(options.ca!==undefined){if(!(options.ca instanceof Uint8Array)||options.ca.length<1||options.ca.length>65536)throw failure();ca=Buffer.from(options.ca);const pem=ca.toString('utf8');const certs=pem.match(/-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----/gu);if(!certs?.length||pem.replace(/-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----/gu,'').trim())throw failure();for(const cert of certs)new X509Certificate(cert);}
    const now=options.now??Date.now;if(typeof now!=='function')throw failure();settings=Object.freeze({origin:options.origin,deploymentId:options.deploymentId,conversationId:options.conversationId,consentVersion:options.consentVersion,noticeSha256:options.noticeSha256,now});
  }catch{requestKey?.fill(0);responseKey?.fill(0);throw failure();}
  let closed=false,last=-1;const active=new Set();
  const close=()=>{closed=true;for(const abort of [...active])abort();requestKey.fill(0);responseKey.fill(0);};
  const instant=()=>{try{const t=settings.now();if(closed||!Number.isSafeInteger(t)||t<0||t<last)throw failure();last=t;return t;}catch{close();throw failure();}};
  instant();
  const context=()=>({schemaVersion:1,deploymentId:settings.deploymentId,conversationId:settings.conversationId});
  const verifyEnvelope=(action,raw)=>{
    const e=JSON.parse(raw);exact(e,['payload','signature']);
    if(typeof e.payload!=='string'||!/^[A-Za-z0-9_-]{1,16000}$/u.test(e.payload)||typeof e.signature!=='string'||!SHA.test(e.signature)
      ||!same(e.signature,createHmac('sha256',responseKey).update(RESPONSE+action+'\n'+e.payload).digest('hex')))throw failure();
    const bytes=Buffer.from(e.payload,'base64url');if(bytes.toString('base64url')!==e.payload)throw failure();const p=JSON.parse(bytes.toString('utf8'));
    if(canonical(p)!==bytes.toString('utf8')||p.schemaVersion!==1||p.deploymentId!==settings.deploymentId||p.conversationId!==settings.conversationId)throw failure();return p;
  };
  const rpc=(action,payload)=>{
    const started=instant();if(active.size>=32)throw failure();const body=canonical(payload);if(Buffer.byteLength(body)>16384)throw failure();const timestamp=String(Math.floor(started/1000));
    const signature=createHmac('sha256',requestKey).update(REQUEST+action+'\n'+timestamp+'.'+body).digest('hex');
    return new Promise((resolve,reject)=>{
      let settled=false,req,res;const deadline=performance.now()+5000;
      const finish=(error,value)=>{if(settled)return;settled=true;clearTimeout(timer);active.delete(abort);if(error){res?.destroy();req?.destroy();reject(failure());}else resolve(value);};
      const abort=()=>finish(failure());const timer=setTimeout(abort,5000);active.add(abort);
      try{
        req=request(settings.origin+'/wp-json/fncp/v1/'+action,{method:'POST',ca,rejectUnauthorized:true,checkServerIdentity,minVersion:'TLSv1.2',agent:false,maxHeaderSize:16384,
          headers:{'content-type':'application/json','content-length':Buffer.byteLength(body),'x-fncp-timestamp':timestamp,'x-fncp-signature':'sha256='+signature,connection:'close'}},response=>{
          res=response;if(closed||req.socket.authorized!==true||res.statusCode!==200||res.headers['set-cookie']!==undefined||!/(?:^|,)\s*no-store\s*(?:,|$)/iu.test(res.headers['cache-control']??'')||res.headers['content-encoding']!==undefined||!/^application\/json(?:\s*;|$)/iu.test(res.headers['content-type']??'')){abort();return;}
          const chunks=[];let size=0;res.on('data',chunk=>{size+=chunk.length;if(closed||size>32768||performance.now()>=deadline){abort();return;}chunks.push(Buffer.from(chunk));});res.on('aborted',abort);res.on('error',abort);
          res.on('end',()=>{try{if(closed||!res.complete||performance.now()>=deadline)throw failure();const observed=instant();const p=verifyEnvelope(action,Buffer.concat(chunks).toString('utf8'));finish(null,{payload:p,started,finished:observed});}catch{abort();}});
        });req.on('error',abort);req.end(body);
      }catch{abort();}
    });
  };
  const bridge=Object.freeze({profile:'FNCP_PRODUCTION_WORDPRESS_V1',binding:()=>Object.freeze({...context(),origin:settings.origin,consentVersion:settings.consentVersion,noticeSha256:settings.noticeSha256,trustSha256:ca?sha(ca):'NODE_DEFAULT_TRUST',requestKeySha256:sha(requestKey),responseKeySha256:sha(responseKey)}),
    async register(input){try{exact(input,['receiptId','accountId','consentVersion','adultSelfAttested','eligibilitySelfAttested','registrationConsent','issuedAt','expiresAt']);validDeclarations({consentVersion:input.consentVersion,adultSelfAttested:input.adultSelfAttested,eligibilitySelfAttested:input.eligibilitySelfAttested,registrationConsent:input.registrationConsent},settings.consentVersion);
      if(!UUID.test(input.receiptId)||!ACCOUNT.test(input.accountId)||!Number.isSafeInteger(input.issuedAt)||!Number.isSafeInteger(input.expiresAt)||input.issuedAt<0||input.expiresAt<=input.issuedAt||input.expiresAt-input.issuedAt>60)throw failure();
      const {payload:p}=await rpc('register',{...context(),...input,noticeSha256:settings.noticeSha256});exact(p,['schemaVersion','deploymentId','conversationId','receiptId','registrationId','status']);if(p.receiptId!==input.receiptId||!UUID.test(p.registrationId)||p.status!=='SUBMITTED_NOT_APPROVED')throw failure();return Object.freeze(p);
    }catch{throw failure();}},
    async status(accountId){try{if(!ACCOUNT.test(accountId))throw failure();const nonce=randomBytes(32).toString('base64url');const {payload:p,started,finished}=await rpc('status',{...context(),accountId,nonce});
      exact(p,['schemaVersion','deploymentId','conversationId','accountId','nonce','registrationId','state','version','decisionEventId','deliveryPending','observedAt']);
      if(p.accountId!==accountId||p.nonce!==nonce||!['unregistered','pending','approved','revoked'].includes(p.state)||!Number.isSafeInteger(p.observedAt)||p.observedAt<Math.floor(started/1000)-30||p.observedAt>Math.floor(finished/1000)+30||typeof p.deliveryPending!=='boolean')throw failure();
      if(p.state==='unregistered'){if(p.registrationId!==null||p.version!==0||p.decisionEventId!==null||p.deliveryPending)throw failure();}
      else{if(!UUID.test(p.registrationId)||p.version!==({pending:0,approved:1,revoked:2}[p.state])||(p.version===0?p.decisionEventId!==null:!UUID.test(p.decisionEventId))||(p.version===0&&p.deliveryPending))throw failure();}
      return Object.freeze(p);
    }catch{throw failure();}},close});
  registry.add(bridge);return bridge;
}
