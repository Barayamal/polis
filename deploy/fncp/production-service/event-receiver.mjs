import { createServer } from 'node:https';
import { X509Certificate,createPrivateKey,createPublicKey,createHmac } from 'node:crypto';
import { isIP } from 'node:net';
import { isProductionAccess } from './access.mjs';
import { exact,canonical,secretBytes,same,UUID } from './contracts.mjs';
const fail=()=>new Error('WordPress event receiver unavailable.');
const MAX_CONNECTIONS=128,HANDSHAKE_TIMEOUT_MS=5000;
/** Private direct-TLS listener. It authenticates the exact bounded raw event;
 * the single access writer owns persistence and commits terminal denial first. */
export function createProductionWordPressReceiver(options){
  let origin,tls,access,host,port,now,key;
  try{exact(options,['origin','tls','access','eventKey'],['host','port','now']);({origin,tls,access}=options);exact(tls,['key','cert']);host=options.host??'127.0.0.1';port=options.port??Number(new URL(origin).port||443);now=options.now??Date.now;
    const u=new URL(origin);if(u.protocol!=='https:'||u.origin!==origin||u.username||u.password||!isProductionAccess(access)||typeof now!=='function'||!['127.0.0.1','0.0.0.0','::1','::'].includes(host)||!Number.isInteger(port)||port<0||port>65535)throw fail();
    if(!(tls.key instanceof Uint8Array)||!(tls.cert instanceof Uint8Array)||tls.key.length>65536||tls.cert.length>65536)throw fail();const certificate=new X509Certificate(tls.cert),privateKey=createPrivateKey(Buffer.from(tls.key));if(!certificate.publicKey.export({format:'der',type:'spki'}).equals(createPublicKey(privateKey).export({format:'der',type:'spki'})))throw fail();const hostname=u.hostname.replace(/^\[|\]$/gu,'');if(!(isIP(hostname)?certificate.checkIP(hostname):certificate.checkHost(hostname,{subject:'never'})))throw fail();
    tls={key:Buffer.from(tls.key),cert:Buffer.from(tls.cert),minVersion:'TLSv1.2'};key=secretBytes(options.eventKey);
  }catch{key?.fill(0);throw fail();}
  const expectedHost=new URL(origin).host,sockets=new Map(),inflight=new Set();
  let closing=false,faulted=false,last=-1,startPromise,listenPromise,closePromise,readers=0,closureFailed=false;
  const deny=()=>{try{access.closeAdmission();}catch{closureFailed=true;}};
  const clock=()=>{
    if(closing||faulted)throw fail();
    try{const t=now();if(!Number.isSafeInteger(t)||t<0||t<last)throw fail();last=t;return t;}
    catch{faulted=true;deny();throw fail();}
  };
  try{clock();}catch{key.fill(0);tls.key.fill(0);throw fail();}
  const server=createServer({...tls,maxHeaderSize:8192,handshakeTimeout:HANDSHAKE_TIMEOUT_MS},(req,res)=>{
    req.on('error',()=>{});res.on('error',()=>{});let timer;const work=(async()=>{
      const reply=(status,body)=>{if(res.destroyed||res.writableEnded)return;res.writeHead(status,{'content-type':'application/json','cache-control':'no-store, private','x-content-type-options':'nosniff',connection:'close'});res.end(JSON.stringify(body));};
      if(readers>=32){reply(503,{error:'event_unavailable'});req.resume();return;}readers++;
      try{
        clock();if(req.method!=='POST'||req.url!=='/internal/wordpress/events'||req.headers.host!==expectedHost||req.socket.encrypted!==true||req.headers['content-type']!=='application/json'||req.headers.cookie!==undefined||req.headers.origin!==undefined||Object.keys(req.headers).some(k=>k.startsWith('sec-fetch-')||k.startsWith('x-forwarded-'))||req.headers['content-encoding']!==undefined)throw fail();
        const names=req.rawHeaders.filter((_,i)=>i%2===0).map(x=>x.toLowerCase());if(new Set(names).size!==names.length)throw fail();
        const timestamp=req.headers['x-fncp-timestamp'],signature=req.headers['x-fncp-signature'],eventId=req.headers['x-fncp-event-id'];if(typeof timestamp!=='string'||!/^\d{10}$/u.test(timestamp)||typeof signature!=='string'||!/^sha256=[a-f0-9]{64}$/u.test(signature)||typeof eventId!=='string'||!UUID.test(eventId))throw fail();
        timer=setTimeout(()=>{reply(408,{error:'event_unavailable'});req.destroy();},5000);const chunks=[];let bytes=0;for await(const chunk of req){bytes+=chunk.length;if(bytes>8192)throw fail();chunks.push(Buffer.from(chunk));}
        clearTimeout(timer);if(!req.complete||closing||faulted)throw fail();const raw=Buffer.concat(chunks),text=raw.toString('utf8');if(!Buffer.from(text).equals(raw)||!same(signature,'sha256='+createHmac('sha256',key).update('FNCP_WP_EVENT_V1\n'+timestamp+'.'+text).digest('hex')))throw fail();
        if(Math.abs(Math.floor(clock()/1000)-Number(timestamp))>30)throw fail();const event=JSON.parse(text);if(canonical(event)!==text||event.eventId!==eventId)throw fail();
        const ack=await access.ingestWordPressEvent(event);clock();exact(ack,['ok','eventId','version']);if(ack.ok!==true||ack.eventId!==eventId||ack.version!==event.version)throw fail();reply(200,ack);
      }catch{reply(503,{error:'event_unavailable'});if(!req.complete)req.destroy();}finally{clearTimeout(timer);readers--;}
    })();inflight.add(work);work.finally(()=>inflight.delete(work)).catch(()=>{});
  });
  server.requestTimeout=6000;server.headersTimeout=5000;server.keepAliveTimeout=1;server.maxRequestsPerSocket=1;
  // Bound connections before TLS or HTTP headers can consume a reader slot.
  server.maxConnections=MAX_CONNECTIONS;server.dropMaxConnection=true;
  server.on('connection',socket=>{
    let settled;const drained=new Promise(resolve=>{settled=resolve;});sockets.set(socket,drained);
    socket.once('close',()=>{sockets.delete(socket);settled();});
    if(closing)socket.destroy();
  });
  server.on('clientError',(_,socket)=>socket.destroy());
  server.on('tlsClientError',(_,socket)=>socket.destroy());
  server.on('error',()=>{
    faulted=true;deny();
    queueMicrotask(()=>{void close().catch(()=>{});});
  });

  function close(){
    if(closePromise)return closePromise;
    closing=true;deny();
    closePromise=(async()=>{
      // A listen attempt may not yet have produced its native listener. Await
      // that attempt, not the public start promise whose failure also closes.
      if(listenPromise)await listenPromise.catch(()=>{});
      const stopped=server.listening?new Promise(resolve=>{
        try{server.close(error=>{if(error)closureFailed=true;resolve();});}
        catch{closureFailed=true;resolve();}
      }):Promise.resolve();
      for(const socket of sockets.keys())socket.destroy();
      // Closing a socket does not cancel an authenticated ingest already in
      // access. Drain those operations before the compositor closes its DB.
      await Promise.allSettled([...inflight]);
      await stopped;
      await Promise.allSettled([...sockets.values()]);
      key.fill(0);tls.key.fill(0);
      if(server.listening||sockets.size||inflight.size||closureFailed)throw fail();
      return Object.freeze({closed:true,drained:true});
    })();
    return closePromise;
  }
  function start(){
    if(closing||faulted)return Promise.reject(fail());
    if(startPromise)return startPromise;
    listenPromise=new Promise((resolve,reject)=>{
      const cleanup=()=>{server.removeListener('error',failed);server.removeListener('listening',listening);};
      const failed=()=>{cleanup();reject(fail());};
      const listening=()=>{cleanup();resolve();};
      server.once('error',failed);server.once('listening',listening);
      try{server.listen(port,host);}catch{failed();}
    });
    startPromise=(async()=>{
      try{await listenPromise;clock();return Object.freeze({origin,port:server.address().port});}
      catch{faulted=true;deny();await close().catch(()=>{});throw fail();}
    })();
    return startPromise;
  }
  return Object.freeze({start,close,
    snapshot(){return Object.freeze({profile:'FNCP_PRODUCTION_WORDPRESS_RECEIVER_V1',closing,faulted,readers,inflight:inflight.size,connections:sockets.size,listenerOpen:server.listening});},
  });
}
