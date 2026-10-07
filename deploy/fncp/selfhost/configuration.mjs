import { lstat, readFile, realpath } from 'node:fs/promises';
import { isAbsolute, resolve } from 'node:path';
import { createHash } from 'node:crypto';

export const fail = (code) => new Error(`FNCP_SELFHOST_${code}`);
export const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
export function exact(value, names) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype ||
      Object.keys(value).length !== names.length || names.some(k => !Object.hasOwn(value,k))) throw fail('CONFIG_FIELDS');
}
const digest = v => typeof v === 'string' && /^sha256:[0-9a-f]{64}$/.test(v);
export function validateConfiguration(c) {
  exact(c,['version','classification','deployment','platform','engine','stateDirectory','sourceRevision','database','binding','identity']);
  if(c.version!==1 || c.classification!=='closed-local-core' || !/^fncp-[a-z0-9][a-z0-9-]{4,40}$/.test(c.deployment) || c.platform!=='linux/arm64') throw fail('CONFIG_SCOPE');
  exact(c.engine,['host','configDirectory']);
  if(typeof c.engine.host!=='string' || !c.engine.host.startsWith('unix:///') || /[\r\n\0]/.test(c.engine.host)) throw fail('ENGINE');
  for(const p of [c.engine.configDirectory,c.stateDirectory]) if(typeof p!=='string'||!isAbsolute(p)||resolve(p)!==p||/[\r\n\0]/.test(p))throw fail('PATH');
  if(!/^[0-9a-f]{40}$/.test(c.sourceRevision))throw fail('SOURCE_REVISION');
  exact(c.database,['name','owner','migrationRole','runtimeRole','mathRole','host','port']);
  if(!['name','owner','migrationRole','runtimeRole','mathRole'].every(k=>typeof c.database[k]==='string'&&/^[a-z_][a-z0-9_]{0,62}$/.test(c.database[k]))||new Set([c.database.owner,c.database.migrationRole,c.database.runtimeRole,c.database.mathRole]).size!==4||c.database.host!=='postgres'||c.database.port!==5432)throw fail('DATABASE');
  exact(c.binding,['conversationId','statementIds']);
  if(typeof c.binding.conversationId!=='string'||!/^[0-9][a-zA-Z0-9]{5,99}$/.test(c.binding.conversationId)||!Array.isArray(c.binding.statementIds)||c.binding.statementIds.length!==15||new Set(c.binding.statementIds).size!==15||!c.binding.statementIds.every(n=>Number.isSafeInteger(n)&&n>=0&&n<=2147483647&&!Object.is(n,-0)))throw fail('BINDING');
  exact(c.identity,['issuer','audience','jwksUri']);
  for(const key of ['issuer','jwksUri']){
    let u;try{u=new URL(c.identity[key]);}catch{throw fail('IDENTITY');}
    if(u.protocol!=='https:'||u.username||u.password||u.hash||u.search)throw fail('IDENTITY');
  }
  if(typeof c.identity.audience!=='string'||!c.identity.audience||c.identity.audience.length>256||/[\r\n\0]/.test(c.identity.audience))throw fail('IDENTITY');
  return structuredClone(c);
}
export async function privateRead(path, max=65536) {
  const s=await lstat(path);
  if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o077)!==0||s.size<1||s.size>max||await realpath(path)!==resolve(path))throw fail('PRIVATE_FILE');
  const bytes=await readFile(path);const t=await lstat(path);
  if(['ino','dev','size','mtimeMs','ctimeMs'].some(k=>s[k]!==t[k]))throw fail('CHANGED_FILE');
  return bytes;
}
export async function loadConfiguration(path) {
  let parsed;try{parsed=JSON.parse(await privateRead(resolve(path)));}catch(e){if(e.message?.startsWith('FNCP_SELFHOST_'))throw e;throw fail('CONFIG_PARSE');}
  return validateConfiguration(parsed);
}
export function validateImageLock(lock) {
  exact(lock,['version','sourceRevision','sourceFingerprint','images']);
  exact(lock.images,['api','math','migration','postgres']);
  if(lock.version!==1||!/^[0-9a-f]{40}$/.test(lock.sourceRevision)||!/^[0-9a-f]{64}$/.test(lock.sourceFingerprint)||!Object.values(lock.images).every(digest))throw fail('IMAGE_LOCK');
  return lock;
}
export function composeConfiguration(c, lock, token) {
  validateConfiguration(c);validateImageLock(lock);
  if(!/^[a-f0-9]{48}$/.test(token)||lock.sourceRevision!==c.sourceRevision)throw fail('OWNER');
  const labels={'org.barayamal.fncp.owner':token,'org.barayamal.fncp.classification':'closed-local-core'};
  const security={read_only:true,cap_drop:['ALL'],security_opt:['no-new-privileges:true'],restart:'no',pids_limit:256,labels,networks:['private'],tmpfs:['/tmp:rw,nosuid,nodev,size=128m,mode=1777']};
  const secret=(name,target)=>({type:'bind',source:resolve(c.stateDirectory,'material',name),target,read_only:true,bind:{create_host_path:false}});
  const common=[secret('database-ca.pem','/run/fncp/database-ca.pem')];
  return {name:c.deployment,'x-fncp-boundary':{classification:'closed-local-core',participantIngress:false,productionIdentityWiring:false},services:{
    postgres:{...security,image:lock.images.postgres,user:'70:70',mem_limit:'1536m',command:['start'],environment:{PGDATA:'/var/lib/postgresql/data/pgdata',FNCP_DATABASE_NAME:c.database.name,FNCP_OWNER_ROLE:c.database.owner,FNCP_MIGRATION_ROLE:c.database.migrationRole,FNCP_RUNTIME_ROLE:c.database.runtimeRole,FNCP_MATH_ROLE:c.database.mathRole},volumes:[{type:'volume',source:'postgres',target:'/var/lib/postgresql/data'},secret('database-owner-password','/run/fncp/database-owner-password'),secret('database-migration-password','/run/fncp/database-migration-password'),secret('database-runtime-password','/run/fncp/database-runtime-password'),secret('database-math-password','/run/fncp/database-math-password'),secret('database-server.pem','/run/fncp/database-server.pem'),secret('database-server.key','/run/fncp/database-server.key')],healthcheck:{test:['CMD','pg_isready','-h','/var/lib/postgresql/data/pgdata/socket','-U','postgres','-d','postgres','-p','5432'],interval:'3s',timeout:'2s',retries:20}},
    migration:{...security,tmpfs:[...security.tmpfs,'/var/lib/postgresql/data:ro,nosuid,nodev,size=1m,mode=0700'],image:lock.images.migration,user:'70:70',profiles:['maintenance'],mem_limit:'256m',env_file:[resolve(c.stateDirectory,'material','migration.env')],volumes:common,depends_on:{postgres:{condition:'service_healthy'}}},
    api:{...security,image:lock.images.api,user:'1000:1000',mem_limit:'1536m',env_file:[resolve(c.stateDirectory,'material','api.env')],volumes:[...common,secret('jwt-private.pem','/run/fncp/jwt-private.pem'),secret('jwt-public.pem','/run/fncp/jwt-public.pem')],depends_on:{postgres:{condition:'service_healthy'}},healthcheck:{test:['CMD','node','-e',"const net=require('net');const s=net.connect(5000,'127.0.0.1',()=>{s.end();process.exit(0)});s.setTimeout(1500,()=>process.exit(1));s.on('error',()=>process.exit(1))"],interval:'3s',timeout:'2s',retries:20}},
    math:{...security,image:lock.images.math,user:'65532:65532',mem_limit:'1536m',env_file:[resolve(c.stateDirectory,'material','math.env')],volumes:common,depends_on:{api:{condition:'service_healthy'}}}
  },networks:{private:{internal:true,labels}},volumes:{postgres:{labels}}};
}
