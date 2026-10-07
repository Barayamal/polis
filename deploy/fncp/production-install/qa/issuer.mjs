// Invented QA identity provider only. No production image imports this module.
// Native TLS, one-use authorization codes, PKCE and real ES256 signatures allow
// the unchanged production adapter to enforce its complete protocol contract.
import assert from 'node:assert/strict';
import {createServer} from 'node:https';
import {createPrivateKey,createPublicKey,createHash,randomBytes,sign,timingSafeEqual,X509Certificate} from 'node:crypto';
const PROFILE='FNCP_NORMAL_MAIN_QA_IDP_V1';
const subjects=new Set(['invented-normal-alice','invented-normal-bob',...Array.from({length:16},(_,i)=>'invented-normal-extra-'+String(i+2).padStart(2,'0'))]);
const b64=x=>Buffer.from(x).toString('base64url');
const secret=v=>typeof v==='string'&&/^[A-Za-z0-9_-]{43}$/u.test(v);
const equal=(a,b)=>typeof a==='string'&&typeof b==='string'&&a.length===b.length&&timingSafeEqual(Buffer.from(a),Buffer.from(b));
const exact=(v,keys)=>{assert.ok(v&&Object.getPrototypeOf(v)===Object.prototype);assert.deepEqual(Object.keys(v).sort(),[...keys].sort());};
export async function createStandaloneQaIssuer(c){
  exact(c,['profile','origin','host','port','tls','signingKey','clientId','clientSecret','callbackUri','ownerKey']);assert.equal(c.profile,PROFILE);
  const origin=new URL(c.origin);assert.equal(origin.origin,c.origin);assert.equal(origin.protocol,'https:');assert.ok(!origin.username&&!origin.password);
  const callback=new URL(c.callbackUri);assert.equal(callback.protocol,'https:');assert.equal(callback.pathname,'/oidc/callback');assert.ok(!callback.search&&!callback.hash&&!callback.username&&!callback.password);
  assert.ok(['127.0.0.1','0.0.0.0'].includes(c.host));assert.ok(Number.isInteger(c.port)&&c.port>=0&&c.port<=65535);assert.equal(Number(origin.port||443),c.port);
  exact(c.tls,['key','cert']);const leaf=new X509Certificate(c.tls.cert),tlsKey=createPrivateKey(c.tls.key);assert.equal(leaf.ca,false);assert.ok(leaf.publicKey.equals(createPublicKey(tlsKey)));
  assert.ok(leaf.checkHost(origin.hostname,{subject:'never'})||leaf.checkIP(origin.hostname));
  assert.match(c.clientId,/^[A-Za-z0-9_-]{3,128}$/u);assert.ok(secret(c.clientSecret)&&secret(c.ownerKey)&&c.clientSecret!==c.ownerKey);
  const signing=createPrivateKey(c.signingKey);assert.equal(signing.asymmetricKeyType,'ec');assert.equal(signing.asymmetricKeyDetails.namedCurve,'prime256v1');
  const jwk={...createPublicKey(signing).export({format:'jwk'}),kid:'normal-main-qa-idp-key',alg:'ES256',use:'sig'};
  const codes=new Map(),sockets=new Set();let issuer,closed=false,closePromise,last=0;const counts={authorizations:0,tokenExchanges:0,jwksReads:0,denied:0};
  const clock=()=>{const at=Date.now();if(closed||!Number.isSafeInteger(at)||at<last)throw Error();last=at;return at;};
  const prune=at=>{for(const[code,x]of codes)if(x.expiresAt<=at)codes.delete(code);};
  const jwt=claims=>{const data=b64(JSON.stringify({alg:'ES256',kid:jwk.kid,typ:'JWT'}))+'.'+b64(JSON.stringify(claims));return data+'.'+sign('sha256',Buffer.from(data),{key:signing,dsaEncoding:'ieee-p1363'}).toString('base64url');};
  const server=createServer({...c.tls,minVersion:'TLSv1.2',maxHeaderSize:8192,handshakeTimeout:5000},async(req,res)=>{
    req.on('error',()=>{});res.on('error',()=>{});let timeout,stage='request-metadata';
    const json=(code,v)=>{if(!res.destroyed&&!res.writableEnded){res.writeHead(code,{'content-type':'application/json','cache-control':'no-store',connection:'close'});res.end(JSON.stringify(v));}};
    try{
      const at=clock();prune(at);assert.equal(req.headers.host,new URL(issuer).host);assert.equal(req.socket.encrypted,true);assert.ok(!req.headers.cookie&&!req.headers['x-forwarded-proto']);
      const url=new URL(req.url,issuer);assert.equal(url.origin,new URL(issuer).origin);
      if(req.method==='GET'&&url.pathname==='/jwks'&&!url.search){counts.jwksReads++;json(200,{keys:[jwk]});return;}
      if(req.method==='GET'&&url.pathname==='/authorize'){
        stage='qa-authorization';
        assert.ok(equal(req.headers['x-fncp-qa-owner'],c.ownerKey));const sub=req.headers['x-fncp-qa-subject'];assert.ok(subjects.has(sub));
        const p=url.searchParams,keys=['client_id','redirect_uri','response_type','response_mode','scope','code_challenge','code_challenge_method','state','nonce'];assert.deepEqual([...p.keys()].sort(),keys.sort());
        assert.equal(p.get('client_id'),c.clientId);assert.equal(p.get('redirect_uri'),c.callbackUri);assert.equal(p.get('response_type'),'code');assert.equal(p.get('response_mode'),'query');assert.equal(p.get('scope'),'openid email');assert.equal(p.get('code_challenge_method'),'S256');
        for(const key of ['state','nonce','code_challenge'])assert.match(p.get(key),/^[A-Za-z0-9_-]{43,128}$/u);assert.ok(codes.size<64);
        const code=randomBytes(32).toString('base64url');codes.set(code,{sub,nonce:p.get('nonce'),challenge:p.get('code_challenge'),expiresAt:at+60000});counts.authorizations++;
        const target=new URL(c.callbackUri);target.search=new URLSearchParams({code,state:p.get('state'),iss:issuer});res.writeHead(303,{location:target.href,'cache-control':'no-store',connection:'close'});res.end();return;
      }
      stage='token-route';assert.equal(req.method,'POST');assert.equal(url.pathname,'/token');assert.equal(url.search,'');assert.ok(['application/x-www-form-urlencoded','application/x-www-form-urlencoded;charset=utf-8'].includes(req.headers['content-type']?.replaceAll(' ','').toLowerCase()));
      timeout=setTimeout(()=>req.destroy(),5000);const chunks=[];let size=0;for await(const chunk of req){size+=chunk.length;assert.ok(size<=8192);chunks.push(chunk);}clearTimeout(timeout);assert.equal(req.complete,true);
      stage='token-body-fields';const body=new URLSearchParams(Buffer.concat(chunks).toString('utf8'));assert.deepEqual([...body.keys()].sort(),['code','code_verifier','grant_type','redirect_uri'].sort());
      stage='token-code';
      const entry=codes.get(body.get('code'));codes.delete(body.get('code'));assert.ok(entry&&entry.expiresAt>clock());
      stage='token-client';const header=req.headers.authorization;assert.ok(typeof header==='string'&&/^Basic [A-Za-z0-9+/]+={0,2}$/u.test(header));const parts=Buffer.from(header.slice(6),'base64').toString('utf8').split(':');assert.equal(parts.length,2);const decode=x=>decodeURIComponent(x.replaceAll('+',' '));assert.ok(equal(decode(parts[0]),c.clientId)&&equal(decode(parts[1]),c.clientSecret));
      stage='token-pkce';
      assert.equal(body.get('grant_type'),'authorization_code');assert.equal(body.get('redirect_uri'),c.callbackUri);assert.match(body.get('code_verifier'),/^[A-Za-z0-9._~-]{43,128}$/u);
      assert.equal(createHash('sha256').update(body.get('code_verifier')).digest('base64url'),entry.challenge);
      stage='token-sign';const now=Math.floor(clock()/1000);const token=jwt({iss:issuer,aud:c.clientId,sub:entry.sub,iat:now,exp:now+300,nonce:entry.nonce,email:entry.sub+'@example.invalid',email_verified:true});counts.tokenExchanges++;
      json(200,{token_type:'Bearer',access_token:randomBytes(32).toString('base64url'),id_token:token,expires_in:300});
    }catch{counts.denied++;counts.lastDeniedStage=stage;json(400,{error:'qa_authorization_unavailable'});}finally{clearTimeout(timeout);}
  });
  server.on('connection',s=>{sockets.add(s);s.once('close',()=>sockets.delete(s));if(closed)s.destroy();});server.on('tlsClientError',()=>{});server.on('clientError',(_,s)=>s.destroy());server.on('error',()=>{void close();});
  server.maxConnections=128;server.dropMaxConnection=true;server.requestTimeout=6000;server.headersTimeout=5000;server.keepAliveTimeout=1;server.maxRequestsPerSocket=1;
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(c.port,c.host,()=>{server.removeListener('error',reject);resolve();});});origin.port=String(server.address().port);issuer=origin.origin+'/';
  function close(){if(closePromise)return closePromise;closed=true;codes.clear();closePromise=new Promise(resolve=>{server.close(()=>resolve(Object.freeze({closed:true})));for(const s of sockets)s.destroy();});return closePromise;}
  return Object.freeze({binding(){return Object.freeze({profile:PROFILE,issuer,authorizationEndpoint:issuer+'authorize',tokenEndpoint:issuer+'token',jwksUri:issuer+'jwks',callbackUri:c.callbackUri,clientId:c.clientId,signingAlgorithm:'ES256',tokenEndpointAuthMethod:'client_secret_basic'});},snapshot(){return Object.freeze({...counts,pendingCodes:codes.size,listenerOpen:server.listening,closed});},close});
}
