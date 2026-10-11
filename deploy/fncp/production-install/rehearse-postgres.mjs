#!/usr/bin/env node
// Disposable local synthetic database rehearsal, not a host installer. No host
// mounts, published ports, real accounts, external network or retained secrets.
import {spawnSync} from 'node:child_process';
import {randomBytes,createHash} from 'node:crypto';
import {mkdtempSync,mkdirSync,readFileSync,writeFileSync,chmodSync,rmSync,readdirSync,realpathSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {prepareLocalMaterial} from '../selfhost/prepare-local-material.mjs';
import {snapshotMaterial,assertMaterial} from '../selfhost/material.mjs';
import {postgresInitializationPlan,validatePostgresInitializationReceipt} from './postgres-initialize.mjs';

const [socket,postgres,migration,output]=process.argv.slice(2);
if(process.argv.length!==6 || !/^unix:\/\/\/Users\/[A-Za-z0-9._/-]+\/docker\.sock$/u.test(socket??'')
  || ![postgres,migration].every(v=>/^sha256:[a-f0-9]{64}$/u.test(v??'')) || postgres===migration
  || !output?.startsWith('/') || resolve(output)!==output || output==='/')throw Error('Expected explicit task-local Docker socket, two exact image IDs and new evidence path.');
process.umask(0o077);mkdirSync(output,{mode:0o700});
const scratch=mkdtempSync(join(realpathSync(tmpdir()),'fncp-fresh-pg-'));chmodSync(scratch,0o700);
const owner=randomBytes(24).toString('hex'),prefix='fncp-pg-init-'+randomBytes(8).toString('hex');
const label='org.barayamal.fncp.synthetic-install-owner',checks=[],resources={containers:[],volumes:[],networks:[]};
const startedAt=new Date().toISOString(),sourceRoot=fileURLToPath(new URL('../../../',import.meta.url));
const names={data:prefix+'-data',material:prefix+'-material',network:prefix+'-network',postgres:prefix+'-postgres'};
const sha=v=>createHash('sha256').update(v).digest('hex');
const write=(path,value)=>writeFileSync(path,value,{flag:'wx',mode:0o600});
const evidence=(name,value)=>write(join(output,name),typeof value==='string'?value:JSON.stringify(value,null,2)+'\n');
const record=(name,pass,detail={})=>{checks.push({name,pass,...detail});if(!pass)throw Error('Native PostgreSQL check failed: '+name);};
const docker=(args,input,allowFailure=false)=>{const r=spawnSync('docker',['--host',socket,...args],{input,encoding:'utf8',timeout:180000,maxBuffer:8*1024*1024});if(!allowFailure&&(r.status!==0||r.error))throw Error('Native PostgreSQL Docker operation rejected: '+args[0]);return r;};
const inspect=(kind,name)=>JSON.parse(docker([kind,'inspect',name]).stdout)[0];
let engineId,status='FAIL',sourceBefore,materialManifest,selfhost;
const sameEngine=()=>{if(!engineId||docker(['info','--format','{{.ID}}']).stdout.trim()!==engineId)throw Error('Engine identity changed.');};
const missing=(kind,name,result)=>result.status!==0&&!result.error&&(/no such/iu.test(result.stderr)
  ||kind==='network'&&result.stderr.includes('network '+name+' not found'));
const absent=(kind,name)=>{sameEngine();const r=docker([kind,'inspect',name],undefined,true);if(!missing(kind,name,r))throw Error('New resource name not verified absent.');};
const ownedVolume=name=>{sameEngine();if(!resources.volumes.includes(name))throw Error('Untracked volume.');const i=inspect('volume',name);if(i.Labels?.[label]!==owner||i.Driver!=='local'||Object.keys(i.Options??{}).length)throw Error('Volume ownership rejected.');};
const mount=(name,target,ro=false)=>{ownedVolume(name);return ['--mount',`type=volume,src=${name},dst=${target}${ro?',readonly':''},volume-nocopy`];};
const network=()=>{sameEngine();const n=inspect('network',names.network);if(!resources.networks.includes(names.network)||n.Labels?.[label]!==owner||n.Internal!==true||n.Driver!=='bridge')throw Error('Network confinement rejected.');return ['--network',names.network];};
const base=['--pull=never','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','256','--memory','1536m','--cpus','1','--label',label+'='+owner,'--tmpfs','/tmp:rw,nosuid,nodev,size=128m,mode=1777'];
const helper=(args,input,allowFailure=false)=>{const name=prefix+'-helper-'+resources.containers.length;absent('container',name);resources.containers.push(name);return docker(['run','--name',name,'--rm',...base,...args],input,allowFailure);};
const files=[
  'deploy/fncp/production-install/rehearse-postgres.mjs','deploy/fncp/production-install/postgres-initialize.mjs',
  'deploy/fncp/production-deployment/compose.mjs','deploy/fncp/production-deployment/native-round.mjs',
  'deploy/fncp/selfhost/prepare-local-material.mjs','deploy/fncp/selfhost/material.mjs','deploy/fncp/selfhost/configuration.mjs',
  'deploy/fncp/selfhost/fncpctl.mjs','server/bin/fncp-initialize-database.sh','server/bin/fncp-run-migrations.sh',
  ...readdirSync(join(sourceRoot,'server/postgres/migrations')).filter(n=>n.endsWith('.sql')).sort().map(n=>'server/postgres/migrations/'+n),
];
const sourceSnapshot=()=>files.map(path=>({path,sha256:sha(readFileSync(join(sourceRoot,path)))}));
try{
  engineId=docker(['info','--format','{{.ID}}']).stdout.trim();if(!engineId)throw Error('Engine identity unavailable.');
  sourceBefore=sourceSnapshot();evidence('source-manifest.json',sourceBefore);
  const revision=spawnSync('git',['-C',sourceRoot,'rev-parse','HEAD'],{encoding:'utf8'}).stdout.trim();
  if(!/^[a-f0-9]{40}$/u.test(revision))throw Error('Source revision unavailable.');
  for(const [role,id] of [['postgres',postgres],['migration',migration]]){
    const i=inspect('image',id);record(role+' exact immutable arm64 image',i.Id===id&&i.Architecture==='arm64'&&i.Os==='linux'&&['70:70','postgres'].includes(i.Config.User));
    evidence(role+'-image.json',{id:i.Id,architecture:i.Architecture,os:i.Os,user:i.Config.User,sourceRevision:i.Config.Labels?.['org.opencontainers.image.revision'],rootFs:i.RootFS});
  }
  const state=join(scratch,'state');mkdirSync(state,{mode:0o700});
  selfhost={version:1,classification:'closed-local-core',deployment:prefix,platform:'linux/arm64',engine:{host:socket,configDirectory:join(scratch,'docker-config')},stateDirectory:state,sourceRevision:revision,
    database:{name:'fncp_synthetic',owner:'fncp_owner',migrationRole:'fncp_migration',runtimeRole:'fncp_runtime',mathRole:'fncp_math',host:'postgres',port:5432},
    binding:{conversationId:'9syntheticFresh'+randomBytes(8).toString('hex'),statementIds:Array.from({length:15},(_,i)=>i)},
    identity:{issuer:'https://synthetic-identity.invalid/',audience:'synthetic-rehearsal',jwksUri:'https://synthetic-identity.invalid/jwks'}};
  const configPath=join(scratch,'synthetic-config.json');write(configPath,JSON.stringify(selfhost));await prepareLocalMaterial(configPath);materialManifest=await snapshotMaterial(selfhost);
  const {classification,engine,...publicConfiguration}=selfhost;publicConfiguration.profile='FNCP_PRODUCTION_COMPOSE_V1';
  // Unexecuted roles are explicit placeholders solely for the pure plan's full
  // normal shape. They are not inspected, loaded, started or release evidence.
  const imageLock={version:1,sourceRevision:revision,sourceFingerprint:sha(JSON.stringify(sourceBefore)),images:Object.fromEntries(['api','math','postgres','migration','participant','wordpress','mariadb','proxy'].map(role=>[role,role==='postgres'?postgres:role==='migration'?migration:'sha256:'+sha('UNEXECUTED_REHEARSAL_ROLE:'+role)]))};
  const statements=Array.from({length:15},(_,i)=>'Invented closed-installation statement '+(i+1));
  const plan=postgresInitializationPlan(publicConfiguration,imageLock,owner,{statements,seedSha256:sha(JSON.stringify(statements)),topic:'Closed synthetic database rehearsal',description:'Invented local test only; not a participant round.'});
  const material=join(state,'material'),bundle=join(scratch,'pg-material');mkdirSync(bundle,{mode:0o700});
  for(const filename of ['database-owner-password','database-migration-password','database-runtime-password','database-math-password','database-ca.pem','database-server.pem','database-server.key'])write(join(bundle,filename),readFileSync(join(material,filename)));
  for(const name of [names.data,names.material]){absent('volume',name);resources.volumes.push(name);docker(['volume','create','--label',label+'='+owner,name]);ownedVolume(name);}
  absent('network',names.network);resources.networks.push(names.network);docker(['network','create','--internal','--driver','bridge','--label',label+'='+owner,names.network]);network();
  const tar=spawnSync('tar',['-cf','-','-C',bundle,'.'],{maxBuffer:2*1024*1024});if(tar.status!==0)throw Error('Synthetic archive failed.');
  helper(['-i','--network','none','--user','0:0','--cap-add','CHOWN','--cap-add','FOWNER','--cap-add','DAC_OVERRIDE',...mount(names.data,'/var/lib/postgresql/data'),...mount(names.material,'/run/fncp'),'--entrypoint','sh',postgres,'-euc',
    'test -z "$(ls -A /var/lib/postgresql/data)"; test -z "$(ls -A /run/fncp)"; tar -xf - -C /run/fncp; chown -R 70:70 /run/fncp; chmod 0700 /run/fncp; chmod 0644 /run/fncp/*; chown 70:70 /var/lib/postgresql/data; chmod 0700 /var/lib/postgresql/data'],tar.stdout);
  const checkImageSources=(id,paths)=>{const r=helper(['--network','none','--user','70:70','--entrypoint','sha256sum',id,...paths.map(x=>x[0])]);const observed=r.stdout.trim().split('\n').map(l=>l.split(/\s+/u)[0]);record('image source hashes '+(id===postgres?'postgres':'migration'),observed.length===paths.length&&paths.every(([,host],n)=>observed[n]===sha(readFileSync(join(sourceRoot,host)))));};
  checkImageSources(postgres,[['/usr/local/bin/fncp-initialize-database','server/bin/fncp-initialize-database.sh']]);
  checkImageSources(migration,[['/usr/local/bin/fncp-run-migrations','server/bin/fncp-run-migrations.sh'],...files.filter(p=>p.startsWith('server/postgres/migrations/')).map(p=>['/opt/fncp/migrations/'+p.split('/').at(-1),p])]);
  const pgEnv=join(scratch,'postgres.env');write(pgEnv,Object.entries(plan.maintenance.start.environment).map(([k,v])=>k+'='+v).join('\n')+'\n');
  const pgMounts=()=>[...mount(names.data,'/var/lib/postgresql/data'),...mount(names.material,'/run/fncp',true)];
  const initialize=()=>helper(['--network','none','--user','70:70','--env-file',pgEnv,...pgMounts(),'--entrypoint','/bin/sh',postgres,...plan.maintenance.initialize.command],undefined,true);
  await assertMaterial(selfhost,materialManifest);let r=initialize();record('fresh database four-role initialization',r.status===0);evidence('fresh-initialize.json',{exitStatus:r.status,receipt:r.stdout.trim()});
  r=initialize();record('existing initialized volume refused without reset',r.status!==0&&r.stderr.includes('FNCP_FRESH_POSTGRES_VOLUME_REJECTED'));evidence('initialize-repeat.json',{exitStatus:r.status,rejected:r.status!==0});
  absent('container',names.postgres);resources.containers.push(names.postgres);docker(['create','--name',names.postgres,...base,...network(),'--network-alias','postgres','--user','70:70','--env-file',pgEnv,...pgMounts(),postgres,'start']);docker(['start',names.postgres]);
  const ready=()=>{sameEngine();const i=inspect('container',names.postgres);if(i.Config.Labels?.[label]!==owner)throw Error('Runtime ownership changed.');docker(['exec',names.postgres,'sh','-euc','for n in $(seq 1 100); do pg_isready -h /var/lib/postgresql/data/pgdata/socket -U postgres -d postgres >/dev/null 2>&1 && exit 0; sleep 0.1; done; exit 1']);};ready();
  const migrationEnv=join(material,'migration.env');
  const pgClient=(input,{role='migration',override={},expected=0,marker,name='maintenance SQL'}={})=>{
    const parsed=Object.fromEntries(readFileSync(migrationEnv,'utf8').trim().split('\n').map(line=>{const i=line.indexOf('=');return[line.slice(0,i),line.slice(i+1)];}));
    if(role!=='migration'){parsed.FNCP_EXPECTED_MIGRATION_ROLE=selfhost.database[role==='runtime'?'runtimeRole':'mathRole'];parsed.FNCP_DATABASE_PASSWORD=readFileSync(join(material,'database-'+role+'-password'),'utf8');}
    Object.assign(parsed,override);const envfile=join(scratch,'client-'+resources.containers.length+'.env');write(envfile,Object.entries(parsed).map(([k,v])=>k+'='+v).join('\n')+'\n');
    const result=helper(['-i',...network(),'--user','70:70','--env-file',envfile,...mount(names.material,'/run/fncp',true),'--entrypoint','/bin/sh',migration,...plan.maintenance.seed.command],input,true);
    const matched=typeof marker==='string'?result.stderr.includes(marker):marker instanceof RegExp?marker.test(result.stderr):false;
    const pass=expected===0?result.status===0:result.status!==0&&!result.error&&matched;
    if(!pass)evidence('failed-sql-'+checks.length+'.json',{name,status:result.status,stderr:result.stderr});
    record(name,pass,{exitStatus:result.status,...(expected===0?{}:{expectedRejectionObserved:matched})});
    return result;
  };
  r=helper([...network(),'--user','70:70','--env-file',migrationEnv,...mount(names.material,'/run/fncp',true),migration],undefined,true);record('twenty immutable migrations applied',r.status===0);evidence('migration.json',{exitStatus:r.status,stdout:r.stdout,stderr:r.stderr});
  const originalPayload=JSON.parse(plan.queries[1].values[0]);
  const changedPayload=changes=>plan.psql.stdin.replace(Buffer.from(plan.queries[1].values[0]).toString('base64'),Buffer.from(JSON.stringify({...originalPayload,...changes})).toString('base64'));
  pgClient(plan.psql.stdin,{role:'runtime',expected:1,marker:'FNCP_FRESH_POSTGRES_SESSION_REJECTED',name:'runtime role cannot initialize'});
  pgClient(plan.psql.stdin,{override:{FNCP_EXPECTED_DATABASE:'postgres'},expected:1,marker:/FNCP_FRESH_POSTGRES_SESSION_REJECTED|pg_hba\.conf (?:rejects|entry)/iu,name:'wrong database refused'});
  pgClient(plan.psql.stdin,{override:{PGSSLMODE:'require'},expected:1,marker:'FNCP_FRESH_POSTGRES_CLIENT_REJECTED',name:'unverified TLS client refused'});
  pgClient(changedPayload({statementIds:[...selfhost.binding.statementIds.slice(0,14),99]}),{expected:1,marker:'FNCP_FRESH_POSTGRES_POSTCONDITION_REJECTED',name:'wrong native seed binding rolls back'});
  pgClient(plan.psql.stdin.replace(plan.queries[0].text,plan.queries[0].text+"\nUPDATE fncp_deploy.schema_migrations SET sha256=repeat('0',64) WHERE filename='000019_add_fncp_provider_allowlist_operations.sql';"),{expected:1,marker:'FNCP_FRESH_POSTGRES_SCHEMA_REJECTED',name:'changed migration ledger refused and rolled back'});
  pgClient(plan.psql.stdin.replace(plan.queries[0].text,plan.queries[0].text+"\nINSERT INTO public.beta(name) VALUES('synthetic contaminated attempt');"),{expected:1,marker:'FNCP_FRESH_POSTGRES_NOT_EMPTY',name:'pre-existing non-round data refused and rolled back'});
  pgClient(plan.psql.stdin.replace(plan.queries[0].text,plan.queries[0].text+"\nGRANT UPDATE ON public.votes TO fncp_math;"),{expected:1,marker:'FNCP_FRESH_POSTGRES_MATH_ACL_REJECTED',name:'excess math privileges refused and rolled back'});
  r=pgClient(plan.psql.stdin,{name:'fresh closed native round seeded'});const receipt=validatePostgresInitializationReceipt(plan,JSON.parse(r.stdout.trim()));evidence('seed-receipt.json',receipt);
  const bind=plan.psql.stdin.slice(0,plan.psql.stdin.indexOf(plan.queries[2].text));
  const probe=bind+`SELECT json_build_object(
    'migrations',(SELECT count(*) FROM fncp_deploy.schema_migrations),
    'migrationHashesMatch',(SELECT jsonb_object_agg(filename,sha256::text) FROM fncp_deploy.schema_migrations)=(current_setting('fncp.fresh_postgres_input')::jsonb->'migrations'),
    'conversations',(SELECT count(*) FROM public.conversations),'seedAuthors',(SELECT count(*) FROM public.users),
    'nativeParticipants',(SELECT count(*) FROM public.participants),'statements',(SELECT count(*) FROM public.comments),
    'seedIdsMatch',(SELECT jsonb_agg(tid ORDER BY tid) FROM public.comments)=(current_setting('fncp.fresh_postgres_input')::jsonb->'statementIds'),
    'seedTextsMatch',(SELECT jsonb_agg(txt ORDER BY tid) FROM public.comments)=(current_setting('fncp.fresh_postgres_input')::jsonb->'statements'),
    'closed',(SELECT bool_and(is_active IS FALSE AND is_public IS FALSE AND is_data_open IS FALSE AND use_xid_whitelist IS TRUE AND xid_required IS TRUE AND strict_moderation IS TRUE AND topics_enabled IS FALSE AND treevite_enabled IS FALSE AND write_type=0 AND vis_type=0) FROM public.conversations),
    'votes',(SELECT count(*) FROM public.votes),'xids',(SELECT count(*) FROM public.xids),
    'allowlist',(SELECT count(*) FROM public.xid_whitelist),'oidcMappings',(SELECT count(*) FROM public.oidc_user_mappings),
    'invitations',(SELECT count(*) FROM public.suzinvites)+(SELECT count(*) FROM public.treevite_invites),
    'unrelatedRows',(SELECT count(*) FROM public.beta),
    'fourRestrictedRoles',(SELECT count(*)=4 AND bool_and(rolcanlogin AND NOT rolsuper AND NOT rolinherit AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls) FROM pg_roles WHERE rolname IN ('fncp_owner','fncp_migration','fncp_runtime','fncp_math')),
    'exactMathTablePrivileges',NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      CROSS JOIN (VALUES('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),('REFERENCES'),('TRIGGER')) AS p(privilege)
      WHERE n.nspname='public' AND c.relkind='r' AND has_table_privilege('fncp_math',c.oid,p.privilege)
        IS DISTINCT FROM ((c.relname IN ('votes','comments') AND p.privilege='SELECT')
          OR (c.relname IN ('math_ticks','math_main','math_profile','math_ptptstats','math_bidtopid') AND p.privilege IN ('SELECT','INSERT','UPDATE')))),
    'exactMathFunctionPrivileges',NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
      WHERE n.nspname='public' AND has_function_privilege('fncp_math',p.oid,'EXECUTE') IS DISTINCT FROM (p.oid='public.now_as_millis()'::regprocedure)));
ROLLBACK;
`;
  const expected={migrations:20,migrationHashesMatch:true,conversations:1,seedAuthors:1,nativeParticipants:1,statements:15,seedIdsMatch:true,seedTextsMatch:true,closed:true,votes:0,xids:0,allowlist:0,oidcMappings:0,invitations:0,unrelatedRows:0,fourRestrictedRoles:true,exactMathTablePrivileges:true,exactMathFunctionPrivileges:true};
  const before=JSON.parse(pgClient(probe,{name:'independent persisted state verified'}).stdout.trim());record('exact closed seed and role aggregates',JSON.stringify(before)===JSON.stringify(expected));evidence('before-restart.json',before);
  pgClient(plan.psql.stdin,{expected:1,marker:'FNCP_FRESH_POSTGRES_NOT_EMPTY',name:'repeat seed refuses existing public data'});
  for(const role of ['runtime','math']){
    pgClient("BEGIN; CREATE TABLE public.fncp_forbidden_synthetic(n integer); ROLLBACK;",{role,expected:1,marker:/permission denied/iu,name:role+' role cannot create tables'});
    pgClient('SELECT count(*) FROM fncp_deploy.schema_migrations;',{role,expected:1,marker:/permission denied/iu,name:role+' role cannot read migration ledger'});
  }
  pgClient("BEGIN; INSERT INTO public.notification_tasks(zid) SELECT zid FROM public.conversations; UPDATE public.notification_tasks SET modified=modified+1; DELETE FROM public.notification_tasks; ROLLBACK;",{role:'runtime',name:'runtime DML allowed in rolled-back transaction'});
  pgClient("BEGIN; INSERT INTO public.math_ticks(zid,math_env) SELECT zid,'synthetic_rehearsal' FROM public.comments LIMIT 1; UPDATE public.math_ticks SET math_tick=math_tick+1; ROLLBACK;",{role:'math',name:'math DML allowed only on analysis tables'});
  pgClient('UPDATE public.comments SET txt=txt;',{role:'math',expected:1,marker:/permission denied/iu,name:'math role cannot change seed statements'});
  sameEngine();if(inspect('container',names.postgres).Config.Labels?.[label]!==owner)throw Error('Runtime ownership changed.');docker(['stop',names.postgres]);docker(['start',names.postgres]);ready();
  const after=JSON.parse(pgClient(probe,{name:'normal startup restart independently verified'}).stdout.trim());record('restart and negative attempts preserve closed state',JSON.stringify(after)===JSON.stringify(before));evidence('after-restart.json',after);
  const running=inspect('container',names.postgres);record('runtime confinement',running.Config.Labels?.[label]===owner&&running.Image===postgres&&running.Config.User==='70:70'&&running.HostConfig.ReadonlyRootfs&&running.HostConfig.CapDrop.includes('ALL')&&Object.keys(running.HostConfig.PortBindings??{}).length===0&&Object.keys(running.NetworkSettings.Networks).join('')===names.network&&running.Mounts.every(m=>m.Type==='volume'||m.Type==='tmpfs'));network();
  await assertMaterial(selfhost,materialManifest);record('private generated material unchanged',true);
  record('bound source unchanged',JSON.stringify(sourceSnapshot())===JSON.stringify(sourceBefore));status='PASS';
}catch(error){evidence('failure.json',{message:error.message});process.exitCode=1;}
finally{
  const cleanup=[];
  for(const name of [...resources.containers].reverse()){
    try{sameEngine();const r=docker(['container','inspect',name],undefined,true);if(missing('container',name,r)){cleanup.push({type:'synthetic-container',removed:true});continue;}const i=JSON.parse(r.stdout)[0];if(i.Config.Labels?.[label]!==owner||!/^\/?[a-f0-9]{64}$/u.test(i.Id))throw Error('ownership');docker(['rm','-f',i.Id]);cleanup.push({type:'synthetic-container',removed:true});}catch{cleanup.push({type:'synthetic-container',removed:false});process.exitCode=1;}
  }
  for(const name of [...resources.volumes].reverse()){
    try{sameEngine();const r=docker(['volume','inspect',name],undefined,true);if(missing('volume',name,r)){cleanup.push({type:'synthetic-volume',removed:true});continue;}ownedVolume(name);docker(['volume','rm',name]);cleanup.push({type:'synthetic-volume',removed:true});}catch{cleanup.push({type:'synthetic-volume',removed:false});process.exitCode=1;}
  }
  for(const name of [...resources.networks].reverse()){
    try{sameEngine();const r=docker(['network','inspect',name],undefined,true);if(missing('network',name,r)){cleanup.push({type:'synthetic-network',removed:true});continue;}network();const i=JSON.parse(r.stdout)[0];docker(['network','rm',i.Id]);cleanup.push({type:'synthetic-network',removed:true});}catch{cleanup.push({type:'synthetic-network',removed:false});process.exitCode=1;}
  }
  rmSync(scratch,{recursive:true,force:true});
  const finalStatus=cleanup.every(x=>x.removed)?status:'CLEANUP_INCOMPLETE';
  evidence('summary.json',{status:finalStatus,startedAt,finishedAt:new Date().toISOString(),profile:'FNCP_SYNTHETIC_FRESH_POSTGRES_REHEARSAL_V1',postgresImage:postgres,migrationImage:migration,sourceSha256:sourceBefore?sha(JSON.stringify(sourceBefore)):null,checks,cleanup,syntheticOnly:true,publishedPorts:0,externalNetwork:false,fullStackIntegration:false,joinedRecovery:false,launchAuthorized:false,unexecutedNormalRoleImagesArePlaceholders:true});
  evidence('checksums.sha256',readdirSync(output).sort().map(name=>sha(readFileSync(join(output,name)))+'  '+name).join('\n')+'\n');
  process.stdout.write('Native synthetic PostgreSQL rehearsal '+finalStatus+'; inspect summary.json.\n');
}
