import {createServer,createConnection} from 'node:net';
import {lstatSync,chmodSync,existsSync} from 'node:fs';
import {join} from 'node:path';
import {privateDirectory} from './custody.mjs';
import {isProductionService} from './service.mjs';
import {exact,canonical} from './contracts.mjs';
const fail=()=>new Error('Private operator operation unavailable.');
const LIMIT=65536;
/** This socket is only for the host/container service owner. It is never an
 * HTTP route or a participant endpoint. Tokens return solely to that operator. */
export async function startProductionOperator(service){
 if(!isProductionService(service))throw fail();const directory=service.stateDirectory;privateDirectory(directory);const path=join(directory,'operator.sock');if(existsSync(path)||path.length>100)throw fail();
 const sockets=new Set(),operations=new Set();let closing=false,closed=false,identity,closePromise;
 const server=createServer({allowHalfOpen:true},socket=>{
  sockets.add(socket);socket.on('close',()=>sockets.delete(socket));socket.on('error',()=>{});let chunks=[],size=0;
  const timer=setTimeout(()=>socket.destroy(),5000);socket.on('close',()=>clearTimeout(timer));
  socket.on('data',chunk=>{size+=chunk.length;if(size>LIMIT){socket.destroy();return;}chunks.push(chunk);});
  socket.on('end',()=>{clearTimeout(timer);const operation=(async()=>{try{
    if(closing||operations.size>=32)throw fail();privateDirectory(directory);const s=lstatSync(path);if(!s.isSocket()||s.ino!==identity.ino||s.dev!==identity.dev||s.uid!==process.getuid()||(s.mode&0o777)!==0o600)throw fail();
    const raw=Buffer.concat(chunks),value=raw.toString('utf8');chunks=[];if(!Buffer.from(value).equals(raw)||!value.endsWith('\n')||value.indexOf('\n')!==value.length-1)throw fail();const message=JSON.parse(value.slice(0,-1));if(canonical(message)+'\n'!==value)throw fail();exact(message,['command'],['payload']);let result;
    if(['status','challenge','admit','close-admission','recovery-descriptor'].includes(message.command)){exact(message,['command']);result=message.command==='close-admission'?service.operator.closeAdmission():message.command==='recovery-descriptor'?service.operator.recoveryDescriptor():service.operator[message.command]();}
    else if(message.command==='activate'){exact(message,['command','payload']);result=service.operator.activate(message.payload);}
    else if(message.command==='invitation'){exact(message,['command','payload']);exact(message.payload,['accountId']);result=await service.operator.issueInvitation(message.payload.accountId);}
    else if(message.command==='invitation-for-registration'){exact(message,['command','payload']);exact(message.payload,['registrationId']);result=await service.operator.issueInvitationForRegistration(message.payload.registrationId);}
    else throw fail();
    if(closing)throw fail();socket.end(canonical({ok:true,result:result??null})+'\n');
   }catch{socket.end('{"error":"operator_unavailable","ok":false}\n');}})();operations.add(operation);operation.finally(()=>operations.delete(operation)).catch(()=>{});
  });
 });server.maxConnections=32;
 let permanentFailure=false;
 server.on('error',()=>{permanentFailure=true;try{service.operator.closeAdmission();}catch{}if(!closing)queueMicrotask(()=>void close().catch(()=>{}));});
 try{await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(path,()=>{server.removeListener('error',reject);resolve();});});chmodSync(path,0o600);identity=lstatSync(path);if(!identity.isSocket()||identity.uid!==process.getuid()||(identity.mode&0o777)!==0o600)throw fail();}catch{await close().catch(()=>{});throw fail();}
 function close(){if(closePromise)return closePromise;closing=true;closePromise=(async()=>{const stopped=new Promise(resolve=>{if(!server.listening)return resolve();server.close(()=>resolve());});for(const socket of sockets)socket.destroy();await Promise.allSettled([...operations]);await stopped;closed=true;if(permanentFailure)throw fail();return Object.freeze({closed:true,drained:true});})();return closePromise;}
 return Object.freeze({path,close,snapshot:()=>Object.freeze({closed,closing,pending:operations.size})});
}
export async function requestProductionOperator({stateDirectory,command,payload}){
 privateDirectory(stateDirectory);const path=join(stateDirectory,'operator.sock'),s=lstatSync(path);if(!s.isSocket()||s.uid!==process.getuid()||(s.mode&0o777)!==0o600)throw fail();
 const body=canonical({command,...(payload===undefined?{}:{payload})})+'\n';if(Buffer.byteLength(body)>LIMIT)throw fail();
 return new Promise((resolve,reject)=>{let received=0,chunks=[];const socket=createConnection({path,allowHalfOpen:true});const timer=setTimeout(()=>socket.destroy(fail()),30000);socket.on('error',()=>{clearTimeout(timer);reject(fail());});socket.on('connect',()=>socket.end(body));socket.on('data',b=>{received+=b.length;if(received>LIMIT)socket.destroy(fail());else chunks.push(b);});socket.on('end',()=>{clearTimeout(timer);try{const raw=Buffer.concat(chunks),text=raw.toString('utf8'),message=JSON.parse(text);if(!Buffer.from(text).equals(raw)||canonical(message)+'\n'!==text||message.ok!==true)throw fail();exact(message,['ok','result']);resolve(message.result);}catch{reject(fail());}finally{socket.destroy();}});});
}
