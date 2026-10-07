#!/usr/bin/env node
// Disposable synthetic native test, never a host installer. No port publishing,
// host mounts, real accounts, external network, retained credentials or repair.
import { spawnSync } from 'node:child_process';
import { randomBytes, createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, chmodSync, rmSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonical } from '../production-service/contracts.mjs';

const [socket, wordpress, mariadb, output] = process.argv.slice(2);
if (process.argv.length !== 6 || !/^unix:\/\/\/Users\/[A-Za-z0-9._/-]+\/docker\.sock$/u.test(socket ?? '')
  || ![wordpress,mariadb].every(v=>/^sha256:[a-f0-9]{64}$/u.test(v ?? ''))
  || !output?.startsWith('/') || resolve(output)!==output) throw Error('Expected explicit task-local Docker socket, two exact image IDs and new evidence path.');
process.umask(0o077);
mkdirSync(output,{mode:0o700});
const scratch=mkdtempSync(join(tmpdir(),'fncp-fresh-wp-')); chmodSync(scratch,0o700);
const owner=randomBytes(24).toString('hex'), prefix='fncp-wp-init-'+randomBytes(8).toString('hex');
const label='org.barayamal.fncp.synthetic-install-owner';
const resources={containers:[],volumes:[]}, checks=[], startedAt=new Date().toISOString();
const sourceDir=fileURLToPath(new URL('.',import.meta.url));
const sourceBytes=Object.fromEntries(['rehearse-wordpress.mjs','wordpress-native-probe.php','wordpress-initialize.php','wordpress-initialize-lib.php'].map(name=>[name,readFileSync(join(sourceDir,name))]));
const evidence=(name,value)=>writeFileSync(join(output,name),typeof value==='string'?value:JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o600});
const sha=raw=>createHash('sha256').update(raw).digest('hex');
const docker=(args,input,allowFailure=false)=>{
  const r=spawnSync('docker',['--host',socket,...args],{input,encoding:'utf8',timeout:120000,maxBuffer:8*1024*1024});
  if(!allowFailure&&(r.status!==0||r.error)) throw Error('Native rehearsal Docker operation rejected: '+args[0]);
  return r;
};
const inspect=(kind,name)=>JSON.parse(docker([kind,'inspect',name]).stdout)[0];
const record=(name,pass,extra={})=>{checks.push({name,pass,...extra});if(!pass)throw Error('Native rehearsal check failed: '+name);};
const common=['--pull=never','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','128','--memory','768m','--cpus','1','--label',label+'='+owner];
const volume=(name,target,ro=false)=>['--mount',`type=volume,src=${name},dst=${target}${ro?',readonly':''},volume-nocopy`];
const names={data:prefix+'-db',socket:prefix+'-socket',material:prefix+'-material',db:prefix+'-mariadb',wp:prefix+'-wordpress'};
const engineId=docker(['info','--format','{{.ID}}']).stdout.trim();
if(!engineId)throw Error('Engine identity unavailable.');
const sameEngine=()=>{if(docker(['info','--format','{{.ID}}']).stdout.trim()!==engineId)throw Error('Engine changed.');};
const absent=(kind,name)=>{sameEngine();const r=docker([kind,'inspect',name],undefined,true);if(r.status===0||!/no such/iu.test(r.stderr))throw Error('New resource name not verified absent.');};
const ownedRun=(args,input,allowFailure=false)=>{
  const name=prefix+'-helper-'+resources.containers.length;absent('container',name);resources.containers.push(name);
  return docker(['run','--name',name,...args],input,allowFailure);
};
let status='FAIL';
try {
  for(const [role,id,uid] of [['wordpress',wordpress,'33:33'],['mariadb',mariadb,'999:999']]){
    const i=inspect('image',id);record(role+' exact immutable arm64 image',i.Id===id&&i.Architecture==='arm64'&&i.Config.User===uid);
  }
  const bundle=join(scratch,'bundle');mkdirSync(bundle,{mode:0o700});
  for(const dir of ['wordpress','wordpress-initialize','maintenance'])mkdirSync(join(bundle,dir),{mode:0o700});
  const secret=()=>randomBytes(32).toString('base64url');
  const config={profile:'FNCP_WORDPRESS_RUNTIME_V1',wordpressOrigin:'https://wordpress:8443',databaseName:'fncp_wordpress',databaseUser:'fncp_wp',databasePassword:secret(),tablePrefix:'fncp_',salts:Array.from({length:8},secret)};
  const plugin={profile:'FNCP_PRODUCTION_WORDPRESS_V1',deploymentId:'fncp-synthetic-install',conversationId:'3syntheticRound',wordpressOrigin:config.wordpressOrigin,eventEndpoint:'https://participant-events:8444/internal/wordpress/events',consentVersion:'synthetic-v1',noticeSha256:'a'.repeat(64),serviceRequestKey:secret(),serviceResponseKey:secret(),eventKey:secret(),caFile:'/run/fncp/wordpress/receiver-ca.pem'};
  const operator={profile:'FNCP_WORDPRESS_INITIALIZE_V1',siteTitle:'Closed synthetic installation',operatorLogin:'synthetic_operator',operatorEmail:'operator@example.invalid',operatorPassword:secret()};
  const write=(path,value)=>writeFileSync(path,value,{flag:'wx',mode:0o600});
  write(join(bundle,'wordpress/config.json'),canonical(config)+'\n');
  write(join(bundle,'wordpress/plugin-config.json'),canonical(plugin)+'\n');
  write(join(bundle,'wordpress-initialize/owner.json'),canonical(operator)+'\n');
  const ssl=(args,input)=>{const r=spawnSync('openssl',args,{cwd:scratch,input,encoding:'utf8',timeout:10000});if(r.status!==0)throw Error('Synthetic TLS preparation failed.');};
  ssl(['req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-noenc','-days','1','-subj','/CN=Invented installation CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout','ca-key.pem','-out','ca.pem']);
  ssl(['req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-noenc','-subj','/CN=wordpress','-keyout','leaf-key.pem','-out','leaf.csr']);
  ssl(['x509','-req','-in','leaf.csr','-CA','ca.pem','-CAkey','ca-key.pem','-CAcreateserial','-days','1','-extfile','/dev/stdin','-out','leaf.pem'],'subjectAltName=DNS:wordpress\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n');
  for(const [source,target]of[['ca.pem','receiver-ca.pem'],['leaf.pem','server.pem'],['leaf-key.pem','server-key.pem']])write(join(bundle,'wordpress',target),readFileSync(join(scratch,source)));
  const files=['wordpress-initialize.php','wordpress-initialize-lib.php'];
  evidence('initializer-source.json',Object.entries(sourceBytes).map(([name,raw])=>({name,sha256:sha(raw)})));
  for(const name of files)write(join(bundle,'maintenance',name),sourceBytes[name]);
  for(const name of [names.data,names.socket,names.material]){absent('volume',name);resources.volumes.push(name);docker(['volume','create','--label',label+'='+owner,name]);const v=inspect('volume',name);if(v.Labels?.[label]!==owner||v.Driver!=='local'||Object.keys(v.Options??{}).length)throw Error('New volume ownership rejected.');}
  const tar=spawnSync('tar',['-cf','-','-C',bundle,'.'],{maxBuffer:2*1024*1024});if(tar.status!==0)throw Error('Synthetic archive failed.');
  ownedRun(['--rm','-i',...common,'--user','0:0','--cap-add','CHOWN','--cap-add','FOWNER','--cap-add','DAC_OVERRIDE',...volume(names.material,'/run/fncp'),...volume(names.data,'/var/lib/mysql'),...volume(names.socket,'/run/mysqld'),'--entrypoint','sh',wordpress,'-euc',
    'tar -xf - -C /run/fncp; chown 0:0 /run/fncp; chmod 0755 /run/fncp; chown -R 33:33 /run/fncp/wordpress /run/fncp/wordpress-initialize; chmod 0700 /run/fncp/wordpress /run/fncp/wordpress-initialize; chmod 0600 /run/fncp/wordpress/* /run/fncp/wordpress-initialize/*; chmod 0755 /run/fncp/maintenance; chmod 0644 /run/fncp/maintenance/*; chown 999:999 /var/lib/mysql; chmod 0700 /var/lib/mysql; chown 999:33 /run/mysqld; chmod 0750 /run/mysqld'],tar.stdout);
  const dbmounts=[...volume(names.data,'/var/lib/mysql'),...volume(names.socket,'/run/mysqld')];
  ownedRun(['--rm',...common,'--user','999:999','--tmpfs','/tmp:rw,nosuid,nodev,noexec,mode=0700,uid=999,gid=999',...dbmounts,'--entrypoint','sh',mariadb,'-euc','test -z "$(ls -A /var/lib/mysql)"; mariadb-install-db --no-defaults --datadir=/var/lib/mysql --auth-root-authentication-method=socket --auth-root-socket-user=root --skip-test-db >/tmp/init.log 2>&1']);
  absent('container',names.db);resources.containers.push(names.db);
  docker(['create','--name',names.db,...common,'--user','999:999','--tmpfs','/tmp:rw,nosuid,nodev,noexec,mode=0700,uid=999,gid=999',...dbmounts,'--entrypoint','mariadbd',mariadb,'--no-defaults','--datadir=/var/lib/mysql','--socket=/run/mysqld/mysqld.sock','--pid-file=/run/mysqld/mysqld.pid','--skip-networking','--skip-log-bin','--skip-name-resolve','--local-infile=0','--general-log=0','--slow-query-log=0','--log-error=/dev/stderr']);docker(['start',names.db]);
  docker(['exec','--user','999:999',names.db,'sh','-euc','for n in $(seq 1 80); do mariadb-admin --no-defaults --socket=/run/mysqld/mysqld.sock ping >/dev/null 2>&1 && exit 0; sleep 0.1; done; exit 1']);
  const wpMounts=[...volume(names.material,'/run/fncp',true),...volume(names.socket,'/run/mysqld',true)];
  const phase=(which,uid,expect=0)=>{const r=ownedRun(['--rm',...common,'--user',uid,...(uid==='0:0'?['--cap-add','DAC_OVERRIDE']:[]),'--tmpfs','/tmp:rw,nosuid,nodev,noexec,mode=1777',...wpMounts,'--entrypoint','php',wordpress,'/run/fncp/maintenance/wordpress-initialize.php',which],undefined,true);evidence('phase-'+checks.length+'.json',{phase:which,status:r.status,stdout:r.stdout,stderr:r.stderr});record(which+' phase expected '+expect,r.status===expect);return r;};
  phase('site','33:33',1);phase('database','0:0');phase('database','0:0',1);phase('site','33:33');phase('site','33:33',1);phase('finalize','0:0');
  const tmpfs=['/tmp','/var/run/apache2','/var/lock/apache2','/var/log/apache2'].flatMap(p=>['--tmpfs',p+':rw,nosuid,nodev,noexec,mode=0700,uid=33,gid=33']);
  absent('container',names.wp);resources.containers.push(names.wp);
  docker(['create','--name',names.wp,...common,'--user','33:33',...tmpfs,'--tmpfs','/var/www/html:ro,nosuid,nodev,noexec,mode=0555',...wpMounts,wordpress]);docker(['start',names.wp]);
  docker(['exec',names.wp,'php','-r',`for($n=0;$n<80;$n++){ $s=@fsockopen('127.0.0.1',8443,$e,$m,1);if($s){fclose($s);exit(0);}usleep(100000);}exit(1);`]);
  const probe=sourceBytes['wordpress-native-probe.php'];
  let r=docker(['exec','-i',names.wp,'php'],probe,true);evidence('probe-before-result.json',{status:r.status,stdout:r.stdout,stderr:r.stderr});record('native probe completed',r.status===0);const before=JSON.parse(r.stdout);record('normal runtime initialized, closed, synthetic login passed',before.pass===true,before);evidence('native-before-restart.json',before);
  docker(['stop',names.wp]);docker(['stop',names.db]);docker(['start',names.db]);
  docker(['exec','--user','999:999',names.db,'sh','-euc','for n in $(seq 1 80); do mariadb-admin --no-defaults --socket=/run/mysqld/mysqld.sock ping >/dev/null 2>&1 && exit 0; sleep 0.1; done; exit 1']);docker(['start',names.wp]);
  docker(['exec',names.wp,'php','-r',`for($n=0;$n<80;$n++){ $s=@fsockopen('127.0.0.1',8443,$e,$m,1);if($s){fclose($s);exit(0);}usleep(100000);}exit(1);`]);
  r=docker(['exec','-i',names.wp,'php'],probe,true);evidence('probe-after-result.json',{status:r.status,stdout:r.stdout,stderr:r.stderr});record('restarted native probe completed',r.status===0);const after=JSON.parse(r.stdout);record('database and normal runtime restart preserved closed empty state',after.pass===true&&JSON.stringify(after)===JSON.stringify(before));evidence('native-after-restart.json',after);
  for(const name of [names.db,names.wp]){const i=inspect('container',name);record('runtime confinement '+(name===names.db?'database':'wordpress'),i.HostConfig.NetworkMode==='none'&&Object.keys(i.HostConfig.PortBindings??{}).length===0&&i.HostConfig.ReadonlyRootfs&&i.HostConfig.CapDrop.includes('ALL'));}
  record('rehearsal and initializer source unchanged',Object.entries(sourceBytes).every(([name,raw])=>raw.equals(readFileSync(join(sourceDir,name)))));
  status='PASS';
} catch(error){evidence('failure.json',{message:error.message});process.exitCode=1;}
finally{
  const cleanup=[];
  for(const name of [...resources.containers].reverse()){
    try{if(docker(['info','--format','{{.ID}}']).stdout.trim()!==engineId)throw Error('engine');const r=docker(['container','inspect',name],undefined,true);if(r.status!==0&&/no such/iu.test(r.stderr)){cleanup.push({type:'synthetic-container',removed:true});continue;}const i=JSON.parse(r.stdout)[0];if(i.Config.Labels?.[label]!==owner)throw Error('ownership');docker(['rm','-f',i.Id]);cleanup.push({type:'synthetic-container',removed:true});}catch{cleanup.push({type:'synthetic-container',removed:false});process.exitCode=1;}
  }
  for(const name of [...resources.volumes].reverse()){
    try{if(docker(['info','--format','{{.ID}}']).stdout.trim()!==engineId)throw Error('engine');const i=inspect('volume',name);if(i.Labels?.[label]!==owner)throw Error('ownership');docker(['volume','rm',name]);cleanup.push({type:'synthetic-volume',removed:true});}catch{cleanup.push({type:'synthetic-volume',removed:false});process.exitCode=1;}
  }
  rmSync(scratch,{recursive:true,force:true});
  const finalStatus=cleanup.every(x=>x.removed)?status:'CLEANUP_INCOMPLETE';
  evidence('summary.json',{status:finalStatus,startedAt,finishedAt:new Date().toISOString(),profile:'FNCP_SYNTHETIC_FRESH_WORDPRESS_REHEARSAL_V1',wordpressImage:wordpress,mariadbImage:mariadb,checks,cleanup,syntheticOnly:true,publishedPorts:0,externalNetwork:false,fullStackIntegration:false,joinedRecovery:false,launchAuthorized:false});
  evidence('checksums.sha256',readdirSync(output).sort().map(name=>sha(readFileSync(join(output,name)))+'  '+name).join('\n')+'\n');
  process.stdout.write('Native synthetic WordPress rehearsal '+finalStatus+'; inspect summary.json.\n');
}
