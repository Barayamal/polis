import test from 'node:test';
import assert from 'node:assert/strict';
import {request,Server} from 'node:https';
import {createConnection} from 'node:net';
import {once} from 'node:events';
import {setTimeout as delay} from 'node:timers/promises';
import {createHmac,randomUUID} from 'node:crypto';
import {createProductionFixture} from './test-support/production-fixture.mjs';
import {freshCertificate} from '../production-identity/test-support/https-issuer.mjs';
import {createProductionWordPressReceiver} from './event-receiver.mjs';
import {canonical} from './contracts.mjs';
async function setup(t){const h=await createProductionFixture(t),tls=freshCertificate();const receiver=createProductionWordPressReceiver({origin:'https://127.0.0.1',tls,access:h.access,eventKey:h.eventKey,host:'127.0.0.1',port:0,now:h.now});const started=await receiver.start();t.after(()=>receiver.close().catch(()=>{}));const p=await h.principal();await h.register(p);h.activate();return{h,p,receiver,tls,port:started.port};}
function send(f,event,options={}){const raw=options.raw??canonical(event),timestamp=String(options.timestamp??Math.floor(f.h.now()/1000));const signature='sha256='+createHmac('sha256',Buffer.from(f.h.eventKey,'base64url')).update('FNCP_WP_EVENT_V1\n'+timestamp+'.'+raw).digest('hex');return new Promise((resolve,reject)=>{const req=request({hostname:'127.0.0.1',port:f.port,path:options.path??'/internal/wordpress/events',method:options.method??'POST',ca:f.tls.cert,rejectUnauthorized:true,agent:false,headers:{host:'127.0.0.1','content-type':'application/json','x-fncp-timestamp':timestamp,'x-fncp-event-id':event.eventId,'x-fncp-signature':signature,...options.headers}},res=>{let body='';res.on('data',b=>body+=b);res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,body}));});req.on('error',reject);req.end(raw);});}
test('native HTTPS receiver authenticates immutable events, acknowledges once and applies terminal denial',async t=>{const f=await setup(t);const e=f.h.event(f.p,'approved');const first=await send(f,e);assert.equal(first.status,200);assert.deepEqual(JSON.parse(first.body),{ok:true,eventId:e.eventId,version:1});assert.equal((await send(f,e)).status,200);const inv=await f.h.invite(f.p),cap=await f.h.access.redeem(f.p,inv.invitationToken);await f.h.access.participate(f.p,cap,'vote',{tid:0,vote:1});const rev=f.h.event(f.p,'revoked');assert.equal((await send(f,rev)).status,200);await assert.rejects(f.h.access.participate(f.p,cap,'vote',{tid:0,vote:1}));assert.equal(f.h.votes.length,1);assert.equal((await send(f,{...rev,eventId:randomUUID()})).status,503);assert.equal((await send(f,e)).status,200);});
for(const [name,opts]of Object.entries({signature:{headers:{'x-fncp-signature':'sha256:'+'0'.repeat(64)}},cookie:{headers:{cookie:'wp_auth=synthetic'}},origin:{headers:{origin:'https://127.0.0.1'}},fetch:{headers:{'sec-fetch-site':'same-origin'}},forwarded:{headers:{'x-forwarded-proto':'https'}},wrongHost:{headers:{host:'other.invalid'}},query:{path:'/internal/wordpress/events?debug=1'},verb:{method:'PUT'},type:{headers:{'content-type':'text/plain'}},encoding:{headers:{'content-encoding':'gzip'}},duplicate:{headers:{'x-fncp-timestamp':['1900000000','1900000000']}}}))test(`receiver rejects ${name} without applying event`,async t=>{const f=await setup(t),e=f.h.event(f.p,'approved');const r=await send(f,e,opts).catch(()=>({status:503}));assert.equal(r.status,503);assert.equal(f.h.allowlist.size,0);assert.doesNotMatch(r.body??'',/acct_|registrationId|signature|eventId/);});
test('stale authenticated timestamp, changed event ID and noncanonical JSON deny',async t=>{const f=await setup(t),e=f.h.event(f.p,'approved');for(const options of [{timestamp:Math.floor(f.h.now()/1000)-31},{headers:{'x-fncp-event-id':randomUUID()}},{raw:JSON.stringify(e)},{raw:canonical({...e,extra:'unexpected'})}])assert.equal((await send(f,e,options)).status,503);assert.equal(f.h.allowlist.size,0);});
test('oversized body is bounded before any access side effect',async t=>{const f=await setup(t),e=f.h.event(f.p,'approved');const r=await send(f,e,{raw:' '.repeat(8193)}).catch(()=>({status:503}));assert.equal(r.status,503);assert.equal(f.receiver.snapshot().readers,0);assert.equal(f.h.allowlist.size,0);});
test('WordPress delivery failure persists revocation and exact retry completes removal',async t=>{const f=await setup(t);await send(f,f.h.event(f.p,'approved'));f.h.behavior.providerDown=true;const e=f.h.event(f.p,'revoked');assert.equal((await send(f,e)).status,503);await assert.rejects(f.h.invite(f.p));f.h.behavior.providerDown=false;assert.equal((await send(f,e)).status,200);assert.equal([...f.h.allowlist.values()][0],2);});
test('clock rollback closes admission permanently even after clock correction',async t=>{const f=await setup(t),e=f.h.event(f.p,'approved');const saved=f.h.now();f.h.setTime(saved-1);assert.equal((await send(f,e)).status,503);f.h.setTime(saved);assert.equal((await send(f,e)).status,503);assert.equal(f.receiver.snapshot().faulted,true);assert.equal(f.h.access.operator.status().roundOpen,false);});
test('close during provider wait denies first, drains and leaves no listener',async t=>{const f=await setup(t),e=f.h.event(f.p,'approved');let enter,release;const entered=new Promise(r=>enter=r),blocked=new Promise(r=>release=r);f.h.behavior.providerGate=async op=>{if(op==='upsert'){enter();await blocked;}};const delivery=send(f,e).catch(()=>({status:503}));await entered;const closing=f.receiver.close();assert.equal(f.h.access.operator.status().roundOpen,false);release();await closing;assert.equal((await delivery).status,503);assert.equal(f.receiver.snapshot().inflight,0);await assert.rejects(send(f,e));await assert.rejects(f.receiver.start());});
test('close before start is idempotent and prevents late listening',async t=>{const h=await createProductionFixture(t),tls=freshCertificate();const receiver=createProductionWordPressReceiver({origin:'https://127.0.0.1',tls,access:h.access,eventKey:h.eventKey,port:0});const a=receiver.close();assert.equal(a,receiver.close());await a;await assert.rejects(receiver.start());});

async function capturedReceiver(t) {
  const h=await createProductionFixture(t),tls=freshCertificate();let server;
  const listen=Server.prototype.listen;
  const spy=t.mock.method(Server.prototype,'listen',function(...args){server=this;return listen.apply(this,args);});
  const receiver=createProductionWordPressReceiver({origin:'https://127.0.0.1',tls,access:h.access,eventKey:h.eventKey,port:0,now:h.now});
  t.after(()=>receiver.close().catch(()=>{}));
  return {h,tls,receiver,spy,get server(){return server;}};
}
async function rawConnection(t,port) {
  const socket=createConnection({host:'127.0.0.1',port});socket.on('error',()=>{});
  t.after(()=>socket.destroy());await once(socket,'connect');return socket;
}
function socketClosed(socket,timeout=1000) {
  return new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{socket.removeListener('close',finish);reject(new Error('socket did not close'));},timeout);
    function finish(){clearTimeout(timer);resolve();}socket.once('close',finish);
  });
}
async function until(predicate) {
  for(let i=0;i<200;i++){if(predicate())return;await delay(5);}
  assert.ok(predicate(),'bounded condition did not settle');
}
test('a post-start native server error closes admission, drains, and cannot restart',async t=>{
  const f=await capturedReceiver(t),started=await f.receiver.start();f.spy.mock.restore();f.h.activate();
  const socket=await rawConnection(t,started.port),ended=socketClosed(socket);
  assert.doesNotThrow(()=>f.server.emit('error',new Error('synthetic listener failure')));
  assert.equal(f.h.access.operator.status().roundOpen,false);
  await f.receiver.close();await ended;
  assert.equal(f.receiver.snapshot().faulted,true);assert.equal(f.server.listening,false);
  assert.equal(f.receiver.snapshot().inflight,0);await assert.rejects(f.receiver.start());
});
test('close during first listen awaits the actual native close callback',async t=>{
  const f=await capturedReceiver(t);const starting=f.receiver.start();const server=f.server;f.spy.mock.restore();
  const nativeClose=server.close;let finishNativeClose,closeObserved=false;
  t.mock.method(server,'close',function(callback){return nativeClose.call(this,error=>{
    closeObserved=true;finishNativeClose=()=>callback(error);
  });});
  let settled=false;const closing=f.receiver.close().then(value=>{settled=true;return value;});
  // Attach the rejection handler before allowing the listen turn to settle.
  const rejected=assert.rejects(starting);
  await until(()=>closeObserved);await delay(5);
  assert.equal(settled,false,'drained must await the real listener-close callback');
  finishNativeClose();await closing;await rejected;
  assert.equal(server.listening,false);assert.equal(f.receiver.snapshot().inflight,0);
});
test('128 native pre-TLS connections are bounded before HTTP readers exist',async t=>{
  const f=await capturedReceiver(t),started=await f.receiver.start();f.spy.mock.restore();
  const sockets=await Promise.all(Array.from({length:128},()=>rawConnection(t,started.port)));
  await until(()=>f.receiver.snapshot().connections===128);
  assert.equal(f.receiver.snapshot().readers,0);
  const excess=await rawConnection(t,started.port);await socketClosed(excess);
  assert.equal(f.receiver.snapshot().connections,128);
  const ended=sockets.map(socket=>socketClosed(socket));
  await f.receiver.close();await Promise.all(ended);
  assert.equal(f.receiver.snapshot().connections,0);assert.equal(f.h.allowlist.size,0);
});
test('an incomplete native TLS handshake is closed at the five-second deadline',async t=>{
  const f=await capturedReceiver(t),started=await f.receiver.start();f.spy.mock.restore();
  const began=performance.now(),socket=await rawConnection(t,started.port);
  // Explicit timeout prevents a missing handshake bound from hanging the suite.
  await socketClosed(socket,8000);
  const elapsed=performance.now()-began;
  assert.ok(elapsed>=4500&&elapsed<8000,`unexpected handshake lifetime ${elapsed}`);
  assert.equal(f.receiver.snapshot().readers,0);assert.equal(f.h.allowlist.size,0);
});
test('receiver close waits for ingests while leaving the access DB available for its owner',async t=>{
  const f=await setup(t),e=f.h.event(f.p,'approved');let enter,release;
  const entered=new Promise(r=>enter=r),blocked=new Promise(r=>release=r);
  f.h.behavior.providerGate=async op=>{if(op==='upsert'){enter();await blocked;}};
  const delivery=send(f,e).catch(()=>({status:503}));await entered;
  let settled=false;const closing=f.receiver.close().then(value=>{settled=true;return value;});
  await delay(10);assert.equal(settled,false);assert.equal(f.receiver.snapshot().inflight,1);
  assert.equal(f.h.access.operator.status().roundOpen,false);
  release();await closing;await delivery;
  assert.equal(f.receiver.snapshot().inflight,0);
  // The compositor, not this listener, owns access disposal after both listeners drain.
  assert.equal(f.h.access.operator.status().roundOpen,false);
});
