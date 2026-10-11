import { isAbsolute, resolve } from 'node:path';

export const PROFILE = 'FNCP_PRODUCTION_COMPOSE_V1';
export const PROFILE_V2 = 'FNCP_PRODUCTION_COMPOSE_V2';
export const PROFILE_V3 = 'FNCP_PRODUCTION_COMPOSE_V3';
export const OPERATOR_ACCESS_PROFILE = 'FNCP_OPERATOR_LOOPBACK_V1';
export const ROLES = Object.freeze(['api','math','postgres','migration','participant','wordpress','mariadb','proxy']);
export const ROLES_V2 = Object.freeze([...ROLES, 'edge']);
export const ROLES_V3 = Object.freeze([...ROLES_V2, 'operator']);
export function imageRoles(version = 1) { if (version === 1) return ROLES; if (version === 2) return ROLES_V2; if (version === 3) return ROLES_V3; throw failure(); }
const failure = () => new Error('Production composition rejected.');
const digest = v => typeof v === 'string' && /^sha256:[a-f0-9]{64}$/u.test(v);
const hex = (v,n) => typeof v === 'string' && new RegExp('^[a-f0-9]{'+n+'}$','u').test(v);
const plain = v => v !== null && typeof v === 'object' && !Array.isArray(v) && [Object.prototype,null].includes(Object.getPrototypeOf(v));
function exact(v,required,optional=[]){
  if(!plain(v)||required.some(k=>!Object.hasOwn(v,k))||Reflect.ownKeys(v).some(k=>typeof k!=='string'||![...required,...optional].includes(k))
    ||Object.values(Object.getOwnPropertyDescriptors(v)).some(d=>!Object.hasOwn(d,'value')))throw failure();
}
function canonical(v,depth=0){
  if(depth>32)throw failure();
  if(Array.isArray(v)){if(Object.getPrototypeOf(v)!==Array.prototype||Reflect.ownKeys(v).some(k=>k!=='length'&&!/^(0|[1-9][0-9]*)$/u.test(String(k)))||Object.keys(v).length!==v.length
    ||Object.values(Object.getOwnPropertyDescriptors(v)).some(d=>!Object.hasOwn(d,'value')))throw failure();return '['+v.map(x=>canonical(x,depth+1)).join(',')+']';}
  if(plain(v)){exact(v,Object.keys(v));return '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k],depth+1)).join(',')+'}';}
  if(v===null||typeof v==='boolean'||typeof v==='string'||Number.isSafeInteger(v)&&!Object.is(v,-0))return JSON.stringify(v);
  throw failure();
}
function https(v){if(typeof v!=='string'||v.length>2048||/[\u0000-\u0020\u007f$\\]/u.test(v))throw failure();const u=new URL(v);if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash||u.href!==v)throw failure();}
function freeze(value){if(value&&typeof value==='object'){for(const v of Object.values(value))freeze(v);Object.freeze(value);}return value;}

/** Public descriptor validation only. This function reads no files or engine. */
export function validateProductionConfiguration(input){try{
  exact(input,['version','profile','deployment','platform','stateDirectory','sourceRevision','database','binding','identity'],['oidcEgress','edge','operatorAccess']);
  canonical(input);
  const profiles={1:PROFILE,2:PROFILE_V2,3:PROFILE_V3};
  if(![1,2,3].includes(input.version)||input.profile!==profiles[input.version]||input.platform!=='linux/arm64'||typeof input.deployment!=='string'||!/^fncp-[a-z0-9][a-z0-9-]{4,40}$/u.test(input.deployment)
    ||!hex(input.sourceRevision,40)||input.oidcEgress!==undefined&&input.oidcEgress!==false)throw failure();
  if(input.version===1&&(input.edge!==undefined||input.operatorAccess!==undefined)||input.version===2&&input.operatorAccess!==undefined)throw failure();
  if(input.version>=2){exact(input.edge,['publicOrigin','discardCookies']);const u=new URL(input.edge.publicOrigin);https(u.href);
    if(u.origin!==input.edge.publicOrigin||!Array.isArray(input.edge.discardCookies)||input.edge.discardCookies.length>1||input.edge.discardCookies.some(x=>x!=='__cf_bm'))throw failure();}
  if(input.version===3){
    exact(input.operatorAccess,['profile','tunnelRequired','participant','wordpress']);
    if(input.operatorAccess.profile!==OPERATOR_ACCESS_PROFILE||input.operatorAccess.tunnelRequired!==true)throw failure();
    for(const [role,published] of [['participant',8443],['wordpress',9443]]){
      const listener=input.operatorAccess[role];exact(listener,['hostIp','published','target','protocol']);
      if(listener.hostIp!=='127.0.0.1'||listener.published!==published||listener.target!==8443||listener.protocol!=='tcp')throw failure();
    }
  }
  const path=input.stateDirectory;if(typeof path!=='string'||!isAbsolute(path)||resolve(path)!==path||path==='/'||path.length>4096||/[\u0000-\u001f\u007f$\\]/u.test(path))throw failure();
  exact(input.database,['name','owner','migrationRole','runtimeRole','mathRole','host','port']);
  const db=input.database;if(['name','owner','migrationRole','runtimeRole','mathRole'].some(k=>typeof db[k]!=='string'||!/^[a-z_][a-z0-9_]{0,62}$/u.test(db[k])||['postgres','template0','template1'].includes(db[k]))
    ||new Set([db.owner,db.migrationRole,db.runtimeRole,db.mathRole]).size!==4||db.host!=='postgres'||db.port!==5432)throw failure();
  exact(input.binding,['conversationId','statementIds']);const ids=input.binding.statementIds;
  if(typeof input.binding.conversationId!=='string'||!/^[0-9][A-Za-z0-9]{5,99}$/u.test(input.binding.conversationId)||!Array.isArray(ids)||ids.length!==15||new Set(ids).size!==15
    ||ids.some(v=>!Number.isSafeInteger(v)||v<0||v>2147483647||Object.is(v,-0)))throw failure();
  exact(input.identity,['issuer','audience','jwksUri']);https(input.identity.issuer);https(input.identity.jwksUri);
  if(typeof input.identity.audience!=='string'||!input.identity.audience||input.identity.audience.length>256||/[\u0000-\u0020\u007f$\\]/u.test(input.identity.audience))throw failure();
  canonical(input);return freeze({...structuredClone(input),oidcEgress:input.oidcEgress??false});
}catch{throw failure();}}

export function validateProductionImageLock(input){try{
  exact(input,['version','sourceRevision','sourceFingerprint','images']);exact(input.images,imageRoles(input.version));
  canonical(input);
  if(![1,2,3].includes(input.version)||!hex(input.sourceRevision,40)||!hex(input.sourceFingerprint,64)||!Object.values(input.images).every(digest)||new Set(Object.values(input.images)).size!==imageRoles(input.version).length)throw failure();
  return freeze(structuredClone(input));
}catch{throw failure();}}

/** Normal start from separately provisioned state; no build, init or installer. */
export function renderProductionCompose(configuration,imageLock,ownerToken){try{
  const c=validateProductionConfiguration(configuration),lock=validateProductionImageLock(imageLock);
  if(!hex(ownerToken,48)||c.sourceRevision!==lock.sourceRevision||c.version!==lock.version)throw failure();
  const commonLabels={'org.barayamal.fncp.owner':ownerToken,'org.barayamal.fncp.classification':'production-private-normal-start',
    'org.opencontainers.image.revision':lock.sourceRevision,'org.barayamal.fncp.source-fingerprint':lock.sourceFingerprint};
  const labels=resource=>({...commonLabels,'org.barayamal.fncp.resource':resource});
  const coreTmp='/tmp:rw,nosuid,nodev,size=128m,mode=1777';
  const base=(role,user,memory,cpus,pids=256)=>({image:lock.images[role],platform:'linux/arm64',pull_policy:'never',user,read_only:true,cap_drop:['ALL'],
    security_opt:['no-new-privileges:true'],restart:'no',stop_signal:'SIGTERM',stop_grace_period:'30s',pids_limit:pids,mem_limit:memory,cpus,labels:labels(role),networks:{core:{}},tmpfs:[coreTmp]});
  const bind=(name,target)=>({type:'bind',source:resolve(c.stateDirectory,'material',name),target,read_only:true,bind:{create_host_path:false}});
  const volume=(source,target,read_only=false)=>({type:'volume',source,target,read_only,volume:{nocopy:true}});
  const ca=()=>bind('database-ca.pem','/run/fncp/database-ca.pem');
  const tcpHealth=(binary,code)=>({test:['CMD',binary,'-e',code],interval:'5s',timeout:'2s',retries:20,start_period:'5s'});
  const nodeTcp=ports=>`const net=require('node:net');let n=${ports.length};for(const p of ${JSON.stringify(ports)}){const s=net.connect(p,'127.0.0.1',()=>{s.end();if(--n===0)process.exit(0)});s.setTimeout(1500,()=>process.exit(1));s.on('error',()=>process.exit(1))}`;
  const services={
    postgres:{...base('postgres','70:70','1536m','1.0'),command:['start'],environment:{PGDATA:'/var/lib/postgresql/data/pgdata',FNCP_DATABASE_NAME:c.database.name,FNCP_OWNER_ROLE:c.database.owner,FNCP_MIGRATION_ROLE:c.database.migrationRole,FNCP_RUNTIME_ROLE:c.database.runtimeRole,FNCP_MATH_ROLE:c.database.mathRole},
      volumes:[volume('postgres','/var/lib/postgresql/data'),...['owner','migration','runtime','math'].map(role=>bind('database-'+role+'-password','/run/fncp/database-'+role+'-password')),bind('database-server.pem','/run/fncp/database-server.pem'),bind('database-server.key','/run/fncp/database-server.key')],
      healthcheck:{test:['CMD','pg_isready','-h','/var/lib/postgresql/data/pgdata/socket','-U','postgres','-d','postgres','-p','5432'],interval:'3s',timeout:'2s',retries:20}},
    migration:{...base('migration','70:70','256m','0.5'),profiles:['maintenance'],tmpfs:[coreTmp,'/var/lib/postgresql/data:ro,nosuid,nodev,size=1m,mode=0700'],env_file:[resolve(c.stateDirectory,'material','migration.env')],volumes:[ca()],depends_on:{postgres:{condition:'service_healthy'}}},
    api:{...base('api','1000:1000','1536m','1.0'),env_file:[resolve(c.stateDirectory,'material','api.env')],volumes:[ca(),bind('jwt-private.pem','/run/fncp/jwt-private.pem'),bind('jwt-public.pem','/run/fncp/jwt-public.pem')],depends_on:{postgres:{condition:'service_healthy'}},healthcheck:tcpHealth('node',nodeTcp([5000]))},
    math:{...base('math','65532:65532','1536m','2.0'),env_file:[resolve(c.stateDirectory,'material','math.env')],volumes:[ca()],depends_on:{api:{condition:'service_healthy'}}},
    mariadb:{...base('mariadb','999:999','768m','1.0'),network_mode:'none',entrypoint:['mariadbd'],command:['--datadir=/var/lib/mysql','--socket=/run/mysqld/mysqld.sock','--pid-file=/run/mysqld/mysqld.pid','--skip-networking','--skip-log-bin','--skip-name-resolve','--local-infile=0','--innodb-buffer-pool-size=128M','--max-connections=32','--general-log=0','--slow-query-log=0','--log-error=/dev/stderr'],
      tmpfs:['/tmp:rw,noexec,nosuid,nodev,size=64m,mode=0700,uid=999,gid=999'],volumes:[volume('mariadb','/var/lib/mysql'),volume('mariadb_socket','/run/mysqld')],
      healthcheck:{test:['CMD','mariadb-admin','--protocol=socket','--socket=/run/mysqld/mysqld.sock','ping','--silent'],interval:'3s',timeout:'2s',retries:20}},
    wordpress:{...base('wordpress','33:33','512m','1.0',128),entrypoint:['/usr/local/bin/fncp-wordpress-start'],command:[],working_dir:'/usr/src/wordpress',
      tmpfs:['/tmp:rw,noexec,nosuid,nodev,size=64m,mode=0700,uid=33,gid=33',...['/var/run/apache2','/var/lock/apache2','/var/log/apache2'].map(path=>path+':rw,noexec,nosuid,nodev,size=8m,mode=0700,uid=33,gid=33'),'/var/www/html:ro,noexec,nosuid,nodev,size=1m,mode=0555'],
      volumes:[volume('wordpress_material','/run/fncp/wordpress',true),volume('mariadb_socket','/run/mysqld',true)],depends_on:{mariadb:{condition:'service_healthy'}},
      healthcheck:{test:['CMD','php','-r',"$$s=@fsockopen('127.0.0.1',8443,$$e,$$m,1);if(!$$s)exit(1);fclose($$s);"],interval:'5s',timeout:'2s',retries:20,start_period:'10s'}},
    proxy:{...base('proxy','101:101','128m','0.5',64),networks:{core:{aliases:['polis-proxy']}},entrypoint:['nginx'],command:['-g','daemon off;'],tmpfs:['/tmp:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=101,gid=101'],volumes:[volume('proxy_material','/run/fncp',true)],depends_on:{api:{condition:'service_healthy'}}},
    participant:{...base('participant','1000:1000','512m','1.0',128),networks:{core:{aliases:['participant-events']}},
      entrypoint:['node'],command:['--max-old-space-size=384','deploy/fncp/production-service/main.mjs','/run/fncp/service.json'],working_dir:'/app',environment:{NODE_ENV:'production'},
      tmpfs:['/tmp:rw,noexec,nosuid,nodev,size=64m,mode=0700,uid=1000,gid=1000'],volumes:[volume('participant_material','/run/fncp',true),volume('participant_state','/var/lib/fncp')],
      depends_on:{proxy:{condition:'service_started'},wordpress:{condition:'service_healthy'}},healthcheck:tcpHealth('node',nodeTcp([8443,8444]))},
  };
  delete services.mariadb.networks;
  if(c.version>=2){
    services.participant.networks.participant_ingress={aliases:['participant-edge-upstream']};
    services.edge={...base('edge','1000:1000','128m','0.5',64),networks:{participant_ingress:{}},
      entrypoint:['node'],command:['--max-old-space-size=96','deploy/fncp/production-edge/main.mjs','/run/fncp/edge/config.json'],working_dir:'/app',environment:{NODE_ENV:'production'},
      tmpfs:['/tmp:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=1000,gid=1000'],volumes:[volume('edge_material','/run/fncp/edge',true)],
      depends_on:{participant:{condition:'service_healthy'}},healthcheck:tcpHealth('node',nodeTcp([8443]))};
  }
  if(c.version===3){
    const port=(listener,target=listener.target)=>[{target,published:listener.published,host_ip:listener.hostIp,protocol:listener.protocol,mode:'host'}];
    services.operator={...base('operator','1000:1000','128m','0.5',64),
      networks:{core:{},participant_ingress:{},operator_access:{}},entrypoint:['node'],
      command:['--max-old-space-size=64','deploy/fncp/production-operator/main.mjs'],working_dir:'/app',environment:{NODE_ENV:'production'},
      ports:[...port(c.operatorAccess.participant),...port(c.operatorAccess.wordpress,9443)],
      tmpfs:['/tmp:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=1000,gid=1000'],
      depends_on:{edge:{condition:'service_healthy'},wordpress:{condition:'service_healthy'}},healthcheck:tcpHealth('node',nodeTcp([8443,9443]))};
  }
  const volumeNames=['postgres','mariadb','mariadb_socket','wordpress_material','participant_material','participant_state','proxy_material',...(c.version>=2?['edge_material']:[])];
  const volumes=Object.fromEntries(volumeNames.map(name=>[name,{name:c.deployment+'_'+name,driver:'local',labels:labels('volume:'+name)}]));
  volumes.mariadb_socket.driver_opts={type:'tmpfs',device:'tmpfs',o:'size=16m,uid=999,gid=33,mode=0750,noexec,nosuid,nodev'};
  return freeze({name:c.deployment,'x-fncp-boundary':{profile:c.profile,normalStartOnly:true,requiresProvisionedState:true,publishedPorts:c.version===3?2:0,publicListeners:0,defaultAdmission:'closed',statementCount:15,maxParticipants:20,
    sourceRevision:lock.sourceRevision,sourceFingerprint:lock.sourceFingerprint,conversationId:c.binding.conversationId,statementIds:[...c.binding.statementIds],identity:{...c.identity},oidcEgress:c.oidcEgress,
    ...(c.version>=2?{edge:{...c.edge},participantIngress:'internal-isolated',durableVolumes:7}:{}),
    ...(c.version===3?{operatorAccess:structuredClone(c.operatorAccess),operatorTunnelRequired:true,operatorGateway:'opaque-tcp-no-material'}:{}),
    egressDestinationEnforcement:c.version===3?'operator-gateway-only-no-application-egress':'no-external-egress'},services,
    networks:{core:{name:c.deployment+'_core',internal:true,labels:labels('network:core')},...(c.version>=2?{participant_ingress:{name:c.deployment+'_participant_ingress',internal:true,labels:labels('network:participant_ingress')}}:{}),...(c.version===3?{operator_access:{name:c.deployment+'_operator_access',internal:false,labels:labels('network:operator_access')}}:{})},volumes});
}catch{throw failure();}}

/** Verify the saved raw descriptor before execution; reject every override. */
export function validateProductionCompose(document,configuration,imageLock,ownerToken){try{
  const actual=canonical(document);if(Buffer.byteLength(actual)>131072||actual!==canonical(renderProductionCompose(configuration,imageLock,ownerToken)))throw failure();return true;
}catch{throw failure();}}
