#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { lstat, mkdir, readFile, writeFile, realpath, open, unlink } from 'node:fs/promises';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { randomBytes, X509Certificate } from 'node:crypto';
import { fail, sha256, loadConfiguration, privateRead, validateImageLock, composeConfiguration } from './configuration.mjs';
import { snapshotMaterial, assertMaterial } from './material.mjs';
import { assertContainerProfile } from './container-profile.mjs';

const ROOT=fileURLToPath(new URL('../../../',import.meta.url));
const CLEAN_ENV={PATH:process.env.PATH,HOME:process.env.HOME,LANG:'C',LC_ALL:'C',DOCKER_CLI_HINTS:'false',DOCKER_BUILDKIT:'1'};
export async function execute(binary,args,{input,log,timeout=30000}={}) {
  return new Promise((done,reject)=>{
    const p=spawn(binary,args,{env:CLEAN_ENV,stdio:['pipe','pipe','pipe'],shell:false});
    let size=0;const chunks=[];let overflow=false;let pending=Promise.resolve();
    const timer=setTimeout(()=>{overflow=true;p.kill('SIGKILL');},timeout);
    const consume=b=>{size+=b.length;if(log&&size<=64*1024*1024)pending=pending.then(()=>log.write(b));else if(!log&&size<=8*1024*1024)chunks.push(b);else{overflow=true;p.kill('SIGKILL');}};
    p.stdout.on('data',consume);p.stderr.on('data',log?consume:()=>{});
    p.on('error',()=>{clearTimeout(timer);reject(fail('PROCESS'));});
    p.on('close',async(code,signal)=>{clearTimeout(timer);try{await pending;}catch{overflow=true;}if(code||signal||overflow)reject(fail('PROCESS_FAILED'));else done(Buffer.concat(chunks).toString().trim());});
    p.stdin.on('error',()=>{});p.stdin.end(input);
  });
}
export async function sourceSnapshot(root=ROOT) {
  const names=(await execute('git',['-C',root,'ls-files','-z','--cached','--others','--exclude-standard'])).split('\0').filter(Boolean).sort();
  const files=[];
  for(const name of names){
    if(name==='deploy/fncp/selfhost/source-lock.json')continue;
    const path=join(root,name);const stat=await lstat(path);
    if(!stat.isFile()||stat.isSymbolicLink())throw fail('SOURCE_FILE');
    const publicCertificateFixtures=['math/test/fixtures/dedicated-test-ca.pem','math/test/fixtures/dedicated-test-leaf.pem'];
    if(publicCertificateFixtures.includes(name)){
      const pem=await readFile(path,'utf8');if(!/^-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+\n-----END CERTIFICATE-----\n?$/.test(pem))throw fail('PRIVATE_SOURCE');new X509Certificate(pem);
    }else if(/(^|\/)(node_modules|\.git|keys|certs|private|\.runtime)(\/|$)/.test(name)||/\.(key|pem|sqlite|sqlite3|dump)$/.test(name))throw fail('PRIVATE_SOURCE');
    files.push({path:name,sha256:sha256(await readFile(path)),executable:!!(stat.mode&0o111)});
  }
  return {version:1,sourceRevision:await execute('git',['-C',root,'rev-parse','HEAD']),sourceFingerprint:sha256(JSON.stringify(files)),files};
}
async function secureDirectory(path,{create=false}={}) {
  if(create)await mkdir(path,{mode:0o700});
  const s=await lstat(path);if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077)!==0||await realpath(path)!==path)throw fail('PRIVATE_DIRECTORY');
}
const writePrivate=(path,value)=>writeFile(path,typeof value==='string'?value:JSON.stringify(value,null,2)+'\n',{mode:0o600,flag:'wx'});
export async function createController(c) {
  await secureDirectory(c.engine.configDirectory);
  const socket=await lstat(c.engine.host.slice(7));if(!socket.isSocket()||socket.isSymbolicLink()||socket.uid!==process.getuid())throw fail('ENGINE_SOCKET');
  const docker=(args,opts)=>execute('docker',['--host',c.engine.host,'--config',c.engine.configDirectory,...args],opts);
  const info=JSON.parse(await docker(['info','--format','{{json .}}']));
  if(!info.ID||info.OSType!=='linux'||!['aarch64','arm64'].includes(info.Architecture))throw fail('ENGINE_PLATFORM');
  const compose=(args,opts)=>docker(['compose','--project-name',c.deployment,'--project-directory',c.stateDirectory,'--env-file',join(c.stateDirectory,'empty.env'),'--file',join(c.stateDirectory,'compose.yml'),...args],opts);
  const ids=async()=>{const raw=await docker(['ps','-aq','--filter',`label=com.docker.compose.project=${c.deployment}`]);return raw?raw.split('\n'):[];};
  const inspect=async id=>JSON.parse(await docker(['inspect',id]))[0];
  async function ownership({imagesRequired=true,materialRequired=true}={}){
    await secureDirectory(c.stateDirectory);
    const owner=JSON.parse(await privateRead(join(c.stateDirectory,'owner.json')));
    if(owner.version!==1||owner.engineId!==info.ID||owner.configurationSha256!==sha256(JSON.stringify(c))||!/^[a-f0-9]{48}$/.test(owner.token))throw fail('OWNERSHIP');
    if(materialRequired){
      const material=JSON.parse(await privateRead(join(c.stateDirectory,'material-manifest.json')));
      if(sha256(JSON.stringify(material))!==owner.materialSha256)throw fail('MATERIAL_CHANGED');
      await assertMaterial(c,material);
    }
    const lock=validateImageLock(JSON.parse(await privateRead(join(c.stateDirectory,'images.json'))));
    if(lock.sourceRevision!==c.sourceRevision)throw fail('SOURCE_REVISION');
    const expected=composeConfiguration(c,lock,owner.token);
    if(sha256(await readFile(join(c.stateDirectory,'compose.yml')))!==sha256(JSON.stringify(expected,null,2)+'\n'))throw fail('COMPOSE_CHANGED');
    for(const kind of ['volume','network']){
      const expectedName=`${c.deployment}_${kind==='volume'?'postgres':'private'}`;
      const exactRows=JSON.parse(await docker([kind,'inspect',expectedName]));
      if(exactRows.length!==1||exactRows[0].Name!==expectedName||exactRows[0].Labels?.['com.docker.compose.project']!==c.deployment||exactRows[0].Labels?.['org.barayamal.fncp.owner']!==owner.token||(kind==='network'&&!exactRows[0].Internal))throw fail('RESOURCE_OWNERSHIP');
      const raw=await docker([kind,'ls','-q','--filter',`label=com.docker.compose.project=${c.deployment}`]);
      for(const id of raw?raw.split('\n'):[]){
        const row=JSON.parse(await docker([kind,'inspect',id]))[0];
        if(row.Labels?.['org.barayamal.fncp.owner']!==owner.token ||
           (kind==='network' && (!row.Internal || row.Name!==`${c.deployment}_private`)) ||
           (kind==='volume' && row.Name!==`${c.deployment}_postgres`))throw fail('RESOURCE_OWNERSHIP');
      }
    }
    const containers=[];
    for(const id of await ids()){
      const row=await inspect(id);const service=row.Config?.Labels?.['com.docker.compose.service'];
      if(!expected.services[service]||row.Config.Labels['org.barayamal.fncp.owner']!==owner.token||row.Image!==lock.images[service]||!row.HostConfig.ReadonlyRootfs||row.HostConfig.Privileged||Object.keys(row.HostConfig.PortBindings??{}).length||row.HostConfig.NetworkMode!==`${c.deployment}_private`||!row.HostConfig.CapDrop?.includes('ALL'))throw fail('CONTAINER_OWNERSHIP');
      assertContainerProfile(row,expected.services[service],c);
      containers.push(row);
    }
    if(imagesRequired)for(const id of Object.values(lock.images)){const row=JSON.parse(await docker(['image','inspect',id]))[0];if(row.Id!==id)throw fail('IMAGE_ID');}
    return {owner,lock,containers};
  }
  async function locked(fn){
    await secureDirectory(c.stateDirectory);
    const lock=join(c.stateDirectory,'operation.lock');await writePrivate(lock,{pid:process.pid,operationStartedAt:new Date().toISOString()});
    try{return await fn();}finally{await unlink(lock);}
  }
  return {
    async build(){
      await docker(['buildx','version']);
      const before=await sourceSnapshot();if(before.sourceRevision!==c.sourceRevision)throw fail('SOURCE_REVISION');
      await secureDirectory(c.stateDirectory,{create:true});
      await writePrivate(join(c.stateDirectory,'empty.env'),'# No ambient Compose environment\n');
      const images={};const definitions=[['api','server','Dockerfile','fncp-production'],['math','math','Dockerfile','fncp-production'],['migration','server','Dockerfile-migrate',null],['postgres','server','Dockerfile-selfhost-db',null]];
      for(const [name,context,file,target] of definitions){
        const output=await open(join(c.stateDirectory,`build-${name}.log`),'wx',0o600);
        const iid=join(c.stateDirectory,`${name}.iid`);
        try{await docker(['build','--platform',c.platform,'--build-arg',`SOURCE_REVISION=${c.sourceRevision}`,'--iidfile',iid,'-f',join(ROOT,context,file),...(target?['--target',target]:[]),join(ROOT,context)],{log:output,timeout:30*60*1000});}
        finally{await output.close();}
        images[name]=(await readFile(iid,'utf8')).trim();
        process.stdout.write(JSON.stringify({stage:'BUILD',service:name,result:'PASS',image:images[name]})+'\n');
      }
      const after=await sourceSnapshot();if(after.sourceFingerprint!==before.sourceFingerprint)throw fail('SOURCE_CHANGED_DURING_BUILD');
      await writePrivate(join(c.stateDirectory,'source.json'),before);
      await writePrivate(join(c.stateDirectory,'images.json'),validateImageLock({version:1,sourceRevision:before.sourceRevision,sourceFingerprint:before.sourceFingerprint,images}));
      return {result:'PASS',images};
    },
    async initialize(){
      await secureDirectory(c.stateDirectory);
      return locked(async()=>{
        if((await ids()).length)throw fail('EXISTING_PROJECT');
        const volumes=await docker(['volume','ls','-q','--filter',`label=com.docker.compose.project=${c.deployment}`]);
        const networks=await docker(['network','ls','-q','--filter',`label=com.docker.compose.project=${c.deployment}`]);
        const allVolumeNames=(await docker(['volume','ls','--format','{{.Name}}'])).split('\n');
        const allNetworkNames=(await docker(['network','ls','--format','{{.Name}}'])).split('\n');
        const allContainerNames=(await docker(['ps','-a','--format','{{.Names}}'])).split('\n');
        if(volumes||networks||allVolumeNames.includes(`${c.deployment}_postgres`)||allNetworkNames.includes(`${c.deployment}_private`)||allContainerNames.some(n=>n.startsWith(c.deployment+'-')||n.startsWith(c.deployment+'_')))throw fail('EXISTING_PROJECT');
        const lock=validateImageLock(JSON.parse(await privateRead(join(c.stateDirectory,'images.json'))));
        if((await sourceSnapshot()).sourceFingerprint!==lock.sourceFingerprint)throw fail('SOURCE_CHANGED');
        const material=await snapshotMaterial(c);
        const owner={version:1,engineId:info.ID,configurationSha256:sha256(JSON.stringify(c)),materialSha256:sha256(JSON.stringify(material)),token:randomBytes(24).toString('hex'),createdAt:new Date().toISOString()};
        const rendered=composeConfiguration(c,lock,owner.token);
        await writePrivate(join(c.stateDirectory,'material-manifest.json'),material);
        await writePrivate(join(c.stateDirectory,'owner.json'),owner);
        await writePrivate(join(c.stateDirectory,'compose.yml'),rendered);
        await compose(['config','--quiet']);
        await assertMaterial(c,material);
        await compose(['run','--rm','--no-deps','postgres','initialize'],{timeout:120000});
        await compose(['up','--detach','--wait','--wait-timeout','90','postgres'],{timeout:120000});
        await ownership();
        await compose(['--profile','maintenance','run','--rm','--no-deps','migration'],{timeout:180000});
        const mathGrants=`GRANT USAGE ON SCHEMA public TO :"math_role";
GRANT SELECT ON public.votes, public.comments TO :"math_role";
GRANT SELECT, INSERT, UPDATE ON public.math_ticks, public.math_main, public.math_profile, public.math_ptptstats, public.math_bidtopid TO :"math_role";
GRANT EXECUTE ON FUNCTION public.now_as_millis() TO :"math_role";`;
        const client='export PGHOST="$FNCP_DATABASE_HOST" PGPORT="$FNCP_DATABASE_PORT" PGUSER="$FNCP_EXPECTED_MIGRATION_ROLE" PGDATABASE="$FNCP_EXPECTED_DATABASE" PGPASSWORD="$FNCP_DATABASE_PASSWORD"; exec psql -X -q -v ON_ERROR_STOP=1 -v math_role="'+c.database.mathRole+'"';
        await compose(['--profile','maintenance','run','--rm','--no-deps','-T','--entrypoint','/bin/sh','migration','-c',client],{input:mathGrants,timeout:30000});
        await writePrivate(join(c.stateDirectory,'initialized.json'),{version:1,engineId:info.ID,configurationSha256:owner.configurationSha256,initializedAt:new Date().toISOString()});
        return {result:'PASS',initialized:true,participation:'CLOSED',apiStarted:false};
      });
    },
    async fixture(){return locked(async()=>{
      const {containers}=await ownership();
      if(containers.some(r=>r.State.Running&&r.Config.Labels['com.docker.compose.service']!=='postgres'))throw fail('FIXTURE_SERVICES_RUNNING');
      const {localFixture}=await import('./local-fixture.mjs');
      const client='export PGHOST="$FNCP_DATABASE_HOST" PGPORT="$FNCP_DATABASE_PORT" PGUSER="$FNCP_EXPECTED_MIGRATION_ROLE" PGDATABASE="$FNCP_EXPECTED_DATABASE" PGPASSWORD="$FNCP_DATABASE_PASSWORD"; exec psql -X -q -v ON_ERROR_STOP=1';
      await compose(['--profile','maintenance','run','--rm','--no-deps','-T','--entrypoint','/bin/sh','migration','-c',client],{input:localFixture(c),timeout:30000});
      return {result:'PASS',classification:'SQL_ENGINE_AND_STARTUP_FIXTURE',participantsWithVotes:18,seedOwnerWithoutVotes:1,statements:15,votes:270,participantAdmissionProven:false};
    });},
    async start(){return locked(async()=>{const {owner}=await ownership();const initialized=JSON.parse(await privateRead(join(c.stateDirectory,'initialized.json')));if(initialized.engineId!==info.ID||initialized.configurationSha256!==owner.configurationSha256)throw fail('NOT_INITIALIZED');await compose(['up','--detach','--no-build','--wait','--wait-timeout','90','api','math'],{timeout:120000});await ownership();return {result:'PASS',participation:'CLOSED',publishedPorts:0};});},
    async stop(){return locked(async()=>{
      const {containers}=await ownership({imagesRequired:false,materialRequired:false});
      const order=['api','math','migration','postgres'];const stopped=[];
      // Close request intake, then stop writers while PostgreSQL is available.
      for(const service of order)for(const row of containers.filter(r=>r.Config.Labels['com.docker.compose.service']===service&&r.State.Running)){
        await docker(['stop','--time','20',row.Id],{timeout:30000});stopped.push(service);
      }
      return {result:'PASS',stopped:stopped.length,shutdownOrder:stopped,volumesPreserved:true};
    });},
    async status(){const {containers}=await ownership({imagesRequired:false});return {result:'PASS',classification:c.classification,services:containers.map(r=>({service:r.Config.Labels['com.docker.compose.service'],status:r.State.Status,health:r.State.Health?.Status??null})),publishedPorts:0};}
  };
}
export async function main(argv=process.argv.slice(2)){
  if(argv.length!==2||!['validate','source-lock','build','init','fixture','start','status','stop'].includes(argv[0]))throw fail('USAGE');
  const [operation,path]=argv;const c=await loadConfiguration(path);
  if(operation==='validate')return {result:'PASS',classification:c.classification,requiresSeededClosedConversation:true,participantServiceImplemented:false};
  if(operation==='source-lock'){const snapshot=await sourceSnapshot();await writeFile(join(ROOT,'deploy/fncp/selfhost/source-lock.json'),JSON.stringify(snapshot,null,2)+'\n',{mode:0o644,flag:'wx'});return {result:'PASS',sourceFingerprint:snapshot.sourceFingerprint,files:snapshot.files.length};}
  const controller=await createController(c);return controller[operation==='init'?'initialize':operation]();
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  main().then(result=>console.log(JSON.stringify(result))).catch(e=>{console.error(e?.message?.startsWith('FNCP_SELFHOST_')?e.message:'FNCP_SELFHOST_REJECTED');process.exitCode=1;});
}
