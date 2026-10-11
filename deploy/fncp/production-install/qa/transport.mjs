// Native HTTPS protocol actor only. Does not claim browser-engine behaviour.
import assert from 'node:assert/strict';
import {request} from 'node:https';
import {checkServerIdentity} from 'node:tls';

export function createQaHttpsClient(origin,ca,{participant=false}={}){
  const base=new URL(origin);assert.equal(base.origin,origin);assert.equal(base.protocol,'https:');
  if(participant)assert.equal(origin,'https://pulse.synthetic.invalid');
  const jar=new Map();let csrf='';const observations=[];
  async function call(path,{method='GET',json,form,headers={},saveCookies=true}={}){
    assert.ok(path.startsWith('/')&&!path.startsWith('//'));const target=new URL(path,origin);assert.equal(target.origin,origin);
    const raw=json===undefined?(form===undefined?undefined:new URLSearchParams(form).toString()):JSON.stringify(json);
    const cookie=[...jar].map(([name,value])=>`${name}=${value}`).join('; '),at=performance.now();
    return new Promise((resolve,reject)=>{
      let settled=false,timer;
      const failed=()=>{if(settled)return;settled=true;clearTimeout(timer);observations.push({method,route:target.pathname,status:null,durationMs:Math.ceil(performance.now()-at),tlsVerified:false});reject(new Error('QA HTTPS request unavailable.'));};
      const completed=value=>{if(settled)return;settled=true;clearTimeout(timer);resolve(value);};
      const req=request(target,{...(participant?{hostname:'edge',port:8443,servername:base.hostname,checkServerIdentity:(_hostname,certificate)=>checkServerIdentity(base.hostname,certificate)}:{}),method,ca,rejectUnauthorized:true,minVersion:'TLSv1.2',agent:false,headers:{connection:'close',host:base.host,
        ...(cookie?{cookie}:{}),...(participant?{'sec-fetch-site':'same-origin','sec-fetch-mode':'cors','sec-fetch-dest':'empty',...(csrf?{'x-csrf-token':csrf}:{})}:{}),
        ...(method==='POST'?{origin}:{}),...(raw===undefined?{}:{'content-type':json===undefined?'application/x-www-form-urlencoded':'application/json','content-length':Buffer.byteLength(raw)}),...headers}},res=>{
        let size=0;const chunks=[];res.on('data',chunk=>{size+=chunk.length;if(size>1048576){failed();res.destroy(new Error('QA response limit'));return;}chunks.push(chunk);});
        res.once('error',failed);res.once('aborted',failed);res.once('close',()=>{if(!res.complete)failed();});res.once('end',()=>{try{
          if(settled)return;assert.ok(performance.now()-at<15000);assert.equal(req.socket.authorized,true);assert.equal(res.complete,true);const text=Buffer.concat(chunks).toString('utf8');let body;
          if(/application\/json/iu.test(res.headers['content-type']??''))body=JSON.parse(text);
          if(saveCookies)for(const value of res.headers['set-cookie']??[]){const first=value.split(';')[0],i=first.indexOf('='),name=first.slice(0,i),v=first.slice(i+1);assert.ok(i>0);if(!v||/Max-Age=0(?:;|$)/iu.test(value))jar.delete(name);else jar.set(name,v);}
          if(participant&&typeof body?.csrf==='string')csrf=body.csrf;
          // Deliberately omit query strings, Location, cookies and bodies.
          observations.push({method,route:target.pathname,status:res.statusCode,durationMs:Math.ceil(performance.now()-at),tlsVerified:true});
          completed({status:res.statusCode,headers:res.headers,text,body,tlsVerified:true});
        }catch{failed();}});
      });timer=setTimeout(()=>{failed();req.destroy(new Error('QA absolute deadline'));},15000);req.once('error',failed);req.end(raw);
    });
  }
  return Object.freeze({call,privateSession:()=>({cookies:Object.fromEntries(jar),csrf}),observations:()=>observations.map(x=>({...x}))});
}
