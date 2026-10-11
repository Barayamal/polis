import {openSync,closeSync,readFileSync,writeFileSync,fstatSync,lstatSync,realpathSync,unlinkSync,constants} from 'node:fs';
import {dirname,isAbsolute,resolve} from 'node:path';
import {randomBytes} from 'node:crypto';
import {sha} from './contracts.mjs';
const fail=()=>new Error('Private service material rejected.');
const sameFile=(a,b)=>a.dev===b.dev&&a.ino===b.ino&&a.uid===b.uid&&a.nlink===b.nlink&&a.mode===b.mode&&a.size===b.size;
export function privateDirectory(path){if(typeof path!=='string'||!isAbsolute(path)||resolve(path)!==path||realpathSync(path)!==path)throw fail();const s=lstatSync(path);if(!s.isDirectory()||s.uid!==process.getuid()||(s.mode&0o7777)!==0o700)throw fail();return s;}
/** Read a canonical single-link owned file through a non-following descriptor.
 * Every role is captured once; later custody checks compare identity and bytes. */
export function createMaterialCustody(){const held=new Map();let closed=false;
 const read=(path,maxBytes=65536)=>{let fd;try{if(closed||!Number.isSafeInteger(maxBytes)||maxBytes<1||maxBytes>262144||typeof path!=='string'||resolve(path)!==path||!isAbsolute(path))throw fail();const parent=privateDirectory(dirname(path));fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW);const before=fstatSync(fd),named=lstatSync(path);if(!sameFile(before,named)||!before.isFile()||before.nlink!==1||before.uid!==process.getuid()||![0o400,0o600].includes(before.mode&0o7777)||before.size<1||before.size>maxBytes)throw fail();const bytes=readFileSync(fd);const after=fstatSync(fd);if(bytes.length!==before.size||!sameFile(before,after)||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs||!sameFile(after,lstatSync(path)))throw fail();const checkedParent=privateDirectory(dirname(path));if(checkedParent.ino!==parent.ino||checkedParent.dev!==parent.dev)throw fail();const previous=held.get(path),fingerprint=sha(bytes);if(previous&&(previous.fingerprint!==fingerprint||!sameFile(previous.file,after)||previous.parent.ino!==parent.ino||previous.parent.dev!==parent.dev))throw fail();held.set(path,{file:after,parent,fingerprint,maxBytes});return bytes;}catch{throw fail();}finally{if(fd!==undefined)closeSync(fd);}};
 return Object.freeze({read,
  verify(){if(closed)throw fail();for(const [path,record]of [...held]){const parent=privateDirectory(dirname(path));if(parent.ino!==record.parent.ino||parent.dev!==record.parent.dev)throw fail();const bytes=read(path,record.maxBytes);bytes.fill(0);}return true;},
  fingerprints(){return Object.freeze(Object.fromEntries([...held].map(([p,v])=>[p,v.fingerprint])));},
  close(){closed=true;held.clear();}
 });
}
/** Exclusive process ownership precedes all SQLite/activation construction.
 * A crash leaves an explicit custody problem; no PID, timeout or stale-lock
 * heuristic is allowed to take over or unlink another owner's lock. */
export function acquireServiceLock(directory){const parent=privateDirectory(directory),path=directory+'/service.lock';let fd,stat;try{fd=openSync(path,'wx',0o600);writeFileSync(fd,randomBytes(32).toString('hex'));stat=fstatSync(fd);if(!sameFile(stat,lstatSync(path)))throw fail();}catch{if(fd!==undefined){closeSync(fd);if(stat){const s=lstatSync(path);if(s.dev===stat.dev&&s.ino===stat.ino)unlinkSync(path);}}throw fail();}let released=false;
 const verify=()=>{if(released)throw fail();const p=privateDirectory(directory),s=lstatSync(path),f=fstatSync(fd);if(p.ino!==parent.ino||p.dev!==parent.dev||!sameFile(s,stat)||!sameFile(f,stat)||s.nlink!==1||(s.mode&0o7777)!==0o600)throw fail();return true;};
 return Object.freeze({verify,release(){if(released)return;let valid=false;try{verify();valid=true;}finally{released=true;closeSync(fd);}if(valid)unlinkSync(path);}});
}
