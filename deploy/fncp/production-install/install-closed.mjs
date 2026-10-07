#!/usr/bin/env node
// Explicit fresh installation. Normal Compose remains immutable and never runs
// maintenance commands. An unsuccessful attempt retains its owned state closed.
import { spawn } from 'node:child_process';
import { constants, lstatSync, realpathSync, readFileSync, mkdirSync, writeFileSync,
  openSync, closeSync, fstatSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { canonical, sha } from '../production-service/contracts.mjs';
import { acquireInstallationLock, createInstallationScratch } from './installation-custody.mjs';
import { materialArchiveArguments } from './material-archive.mjs';
import { stageProductionMaterial } from './stage-material.mjs';
import { postgresInitializationPlan, validatePostgresInitializationReceipt } from './postgres-initialize.mjs';
import { validateProductionCompose } from '../production-deployment/compose.mjs';
import { validateRunningProductionSnapshot } from '../production-deployment/recovery-ownership.mjs';
import { dockerPluginDirectories } from '../release-readiness/collect-candidate-release.mjs';
import { createCandidateSourceLock, validateCandidateSourceLock } from '../release-readiness/candidate-source-lock.mjs';
import { dockerAbsenceVerdict, dockerFailureDiagnostic } from './docker-result.mjs';
import { composeRawShellCommand, MARIADB_FRESH_INITIALIZE } from './maintenance-shell.mjs';

const ROOT = resolve(fileURLToPath(new URL('../../../', import.meta.url)));
const LABEL = 'org.barayamal.fncp.owner';
const denied = stage => new Error('FNCP_CLOSED_INSTALL_REJECTED:' + stage);
const json = value => canonical(value) + '\n';
export function dockerNetworkInternalArguments(network) {
  if (network?.internal === true) return ['--internal'];
  if (network?.internal === false) return [];
  throw denied('NETWORK_DESCRIPTOR');
}
function privateDirectory(path) {
  if (typeof path !== 'string' || resolve(path) !== path || path === '/' || realpathSync(path) !== path) throw denied('DIRECTORY');
  const s = lstatSync(path);
  if (!s.isDirectory() || s.uid !== process.getuid() || (s.mode & 0o7777) !== 0o700) throw denied('DIRECTORY');
}
function privateFile(path) {
  privateDirectory(dirname(path)); const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const s = fstatSync(fd), n = lstatSync(path);
    if (!s.isFile() || s.nlink !== 1 || s.uid !== process.getuid() || (s.mode & 0o7777) !== 0o600
      || s.size < 1 || s.size > 1048576 || s.ino !== n.ino || s.dev !== n.dev) throw denied('FILE');
    const bytes = readFileSync(fd), after = fstatSync(fd);
    if (bytes.length !== s.size || s.mtimeMs !== after.mtimeMs || s.ctimeMs !== after.ctimeMs) throw denied('FILE_CHANGED');
    return bytes;
  } finally { closeSync(fd); }
}
function processRun(binary, args, input, timeout = 120000) {
  return new Promise(done => {
    const child = spawn(binary, args, { shell: false, env: { PATH: process.env.PATH, HOME: process.env.HOME,
      LANG: 'C', LC_ALL: 'C', DOCKER_CLI_HINTS: 'false' }, stdio: ['pipe','pipe','pipe'] });
    const out = [], err = []; let bytes = 0, overflow = false, termination = 'exit';
    const timer = setTimeout(() => { overflow = true; termination = 'timeout'; child.kill('SIGKILL'); }, timeout);
    const collect = parts => chunk => { bytes += chunk.length; if (bytes > 8*1024*1024) { overflow = true; if (termination === 'exit') termination = 'output-limit'; child.kill('SIGKILL'); } else parts.push(chunk); };
    child.stdout.on('data', collect(out)); child.stderr.on('data', collect(err)); child.stdin.on('error', () => {});
    child.on('error', () => { clearTimeout(timer); done({ code: null, stdout: Buffer.concat(out), stderr: Buffer.concat(err), overflow, termination: 'spawn-error' }); });
    child.on('close', (code, signal) => { clearTimeout(timer); done({ code, stdout: Buffer.concat(out), stderr: Buffer.concat(err), overflow,
      termination: termination === 'exit' && signal ? 'signal' : termination }); });
    child.stdin.end(input);
  });
}

/** Only explicit new resources. No pull, signing, invitations, public listeners,
 * force/adoption, host discovery, deletion or automatic repair. */
export async function installClosed(options) {
  const lock = acquireInstallationLock(options?.targetDirectory); let success = false;
  try { const result = await installClosedLocked(options, lock); success = true; return result; }
  finally { lock.finish(success); }
}
async function installClosedLocked(options, installLock) {
  const keys = ['socket','inputDirectory','targetDirectory','operatorFile','evidenceDirectory'];
  if (!options || canonical(Object.keys(options).sort()) !== canonical(keys.sort())
    || !/^unix:\/\/\/[^\s]+\/docker\.sock$/u.test(options.socket)) throw denied('OPTIONS');
  const { socket, inputDirectory, targetDirectory, operatorFile, evidenceDirectory } = options;
  const socketStat = lstatSync(socket.slice(7));
  if (!socketStat.isSocket() || socketStat.isSymbolicLink() || socketStat.uid !== process.getuid()) throw denied('SOCKET');
  privateDirectory(dirname(evidenceDirectory));
  if (resolve(evidenceDirectory) !== evidenceDirectory || evidenceDirectory === targetDirectory
    || evidenceDirectory.startsWith(targetDirectory + '/') || targetDirectory.startsWith(evidenceDirectory + '/')) throw denied('PATH');
  const operatorBytes = privateFile(operatorFile);
  const operator = JSON.parse(operatorBytes);
  if (!Buffer.from(json(operator)).equals(operatorBytes) || operator.profile !== 'FNCP_WORDPRESS_INITIALIZE_V1') throw denied('OPERATOR');
  await stageProductionMaterial({ inputDirectory, targetDirectory });
  const plan = JSON.parse(privateFile(join(targetDirectory,'installation.json')));
  const c = plan.configuration, lock = plan.imageLock, owner = plan.ownerToken;
  if (c.oidcEgress) throw denied('EXTERNAL_EGRESS');
  const normal = JSON.parse(privateFile(join(targetDirectory,'compose.json')));
  validateProductionCompose(normal,c,lock,owner);
  const source = await createCandidateSourceLock(ROOT);
  if (source.sourceRevision !== lock.sourceRevision || source.sourceFingerprint !== lock.sourceFingerprint) throw denied('SOURCE_LOCK');
  mkdirSync(evidenceDirectory,{mode:0o700});
  const save = (name,value) => writeFileSync(join(evidenceDirectory,name), typeof value === 'string' ? value : json(value), {mode:0o600,flag:'wx'});
  const dockerConfig = join(evidenceDirectory,'docker-config'); mkdirSync(dockerConfig,{mode:0o700});
  writeFileSync(join(dockerConfig,'config.json'),json({cliPluginsExtraDirs:await dockerPluginDirectories(['compose'])}),{mode:0o600,flag:'wx'});
  let dockerPhase = 'engine-preflight', failureCount = 0;
  const operation = args => args[1] === 'inspect' ? 'inspect'
    : args[0] === 'compose' ? 'compose' + (args.find(v => ['run','up','ps'].includes(v)) ? '-' + args.find(v => ['run','up','ps'].includes(v)) : '')
    : ['volume','network'].includes(args[0]) ? args[0] + '-' + args[1] : args[0];
  const recordFailure = (args,result,absence) => {
    const diagnostic = dockerFailureDiagnostic({operation:operation(args),phase:dockerPhase,result,absence});
    save('docker-failure-' + (++failureCount) + '.json',diagnostic);
    return diagnostic;
  };
  const docker = async (args,input,allow=false) => {
    const r = await processRun('docker',['--host',socket,'--config',dockerConfig,...args],input);
    if (!allow && (r.code !== 0 || r.overflow || r.termination !== 'exit')) {
      const diagnostic = recordFailure(args,r);
      throw denied('DOCKER_' + args[0] + ':' + diagnostic.category);
    }
    return r;
  };
  const inspect = async (kind,name) => JSON.parse((await docker([kind,'inspect',name])).stdout)[0];
  const info = JSON.parse((await docker(['info','--format','{{json .}}'])).stdout);
  if (!info.ID || info.OSType !== 'linux' || !['aarch64','arm64'].includes(info.Architecture)) throw denied('ENGINE');
  const resources = {containers:[],volumes:[],networks:[]}, checks = [], began = new Date().toISOString();
  save('source-lock.json',source); save('image-lock.json',lock); save('configuration.json',c);
  save('attempt.json',{profile:'FNCP_CLOSED_INSTALL_V'+c.version,engineId:info.ID,deployment:c.deployment,ownerToken:owner,began});
  const sameEngine = async () => { if ((await docker(['info','--format','{{.ID}}'])).stdout.toString().trim() !== info.ID) throw denied('ENGINE_CHANGED'); };
  const absent = async (kind,name) => {
    await sameEngine(); const r = await docker([kind,'inspect',name],undefined,true);
    const verdict = dockerAbsenceVerdict(kind,name,r);
    if (verdict !== 'absent') {
      recordFailure([kind,'inspect',name],r,verdict);
      throw denied(verdict === 'present' ? 'RESOURCE_EXISTS' : 'RESOURCE_ABSENCE_UNCONFIRMED');
    }
  };
  const labels = (resource) => ({[LABEL]:owner,'org.barayamal.fncp.source-fingerprint':lock.sourceFingerprint,
    'org.opencontainers.image.revision':lock.sourceRevision,'org.barayamal.fncp.resource':resource});
  const labelArgs = value => Object.entries(value).flatMap(([k,v])=>['--label',k+'='+v]);
  const owned = async (kind,name,expected) => {
    await sameEngine(); const i = await inspect(kind,name), got = kind === 'container' ? i.Config.Labels : i.Labels;
    if (Object.entries(expected).some(([k,v])=>got?.[k]!==v)) throw denied('OWNERSHIP');
    return i;
  };
  const helper = async (args,input) => {
    const name = c.deployment + '-installation-' + resources.containers.length;
    await absent('container',name); resources.containers.push(name);
    const r = await docker(['run','--rm','--name',name,'--pull=never','--network','none','--read-only',
      '--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','128','--memory','512m',
      ...labelArgs(labels('installation-helper')),...args],input);
    return r.stdout;
  };
  const volume = (name,target,ro=false) => ['--mount',`type=volume,src=${name},dst=${target}${ro?',readonly':''},volume-nocopy`];
  const emptyEnv = join(evidenceDirectory,'empty.env'); save('empty.env','');
  const compose = async (file,args,input) => docker(['compose','--project-name',c.deployment,'--project-directory',targetDirectory,
    '--env-file',emptyEnv,'--file',file,...args],input);
  const normalFile = join(targetDirectory,'compose.json');
  const checkpoint = async name => {
    installLock.verify();
    await validateCandidateSourceLock(ROOT,source);
    await stageProductionMaterial({inputDirectory,targetDirectory});
    if (!privateFile(operatorFile).equals(operatorBytes)) throw denied('OPERATOR_CHANGED');
    checks.push(name); save('progress-'+checks.length+'.json',{name,pass:true});
  };
  let status = 'FAIL', maintenanceVolume;
  const scratch = createInstallationScratch(); let scratchRemoved = false;
  try {
    dockerPhase = 'image-and-namespace-preflight';
    for (const [role,id] of Object.entries(lock.images)) {
      const i = await inspect('image',id);
      if (i.Id!==id || i.Architecture!=='arm64' || i.Os!=='linux'
        || i.Config.Labels?.['org.opencontainers.image.revision']!==lock.sourceRevision
        || i.Config.Labels?.['org.barayamal.fncp.source-fingerprint']!==lock.sourceFingerprint) throw denied('IMAGE_PROVENANCE_'+role);
    }
    if ((await docker(['ps','-aq','--filter','label=com.docker.compose.project='+c.deployment])).stdout.toString().trim()) throw denied('PROJECT_EXISTS');
    for (const v of Object.values(normal.volumes)) await absent('volume',v.name);
    for (const n of Object.values(normal.networks)) await absent('network',n.name);
    maintenanceVolume = c.deployment + '_installation_material'; await absent('volume',maintenanceVolume);
    await checkpoint('source-images-material-and-new-namespace');
    dockerPhase = 'create-owned-volumes';
    for (const [role,v] of Object.entries(normal.volumes)) {
      resources.volumes.push(v.name);
      await docker(['volume','create','--driver','local',...labelArgs({...v.labels,'com.docker.compose.project':c.deployment,'com.docker.compose.volume':role}),
        ...Object.entries(v.driver_opts??{}).flatMap(([k,val])=>['--opt',k+'='+val]),v.name]);
      await owned('volume',v.name,v.labels);
    }
    dockerPhase = 'create-owned-networks';
    for (const [role,n] of Object.entries(normal.networks)) {
      resources.networks.push(n.name);
      await docker(['network','create','--driver','bridge',...dockerNetworkInternalArguments(n),
        ...labelArgs({...n.labels,'com.docker.compose.project':c.deployment,'com.docker.compose.network':role}),n.name]);
      const observed = await owned('network',n.name,n.labels); if (observed.Internal !== n.internal) throw denied('NETWORK');
    }
    const materialRoles = { participant_material:1000,wordpress_material:33,proxy_material:101,...(c.version>=2?{edge_material:1000}:{}) };
    for (const [role,uid] of Object.entries(materialRoles)) {
      dockerPhase = 'stage-' + role.replaceAll('_','-');
      const directory = join(targetDirectory,role), names = readdirSync(directory).sort();
      const tar = await processRun('tar',materialArchiveArguments(directory,names)); if (tar.code!==0 || tar.overflow) throw denied('ARCHIVE');
      const expected = names.map(name=>sha(readFileSync(join(directory,name)))+'  '+name).join('\n')+'\n';
      await helper(['-i','--user','0:0','--cap-add','CHOWN','--cap-add','FOWNER','--cap-add','DAC_OVERRIDE',
        ...volume(normal.volumes[role].name,'/material'),'--entrypoint','sh',lock.images.participant,'-euc',
        'test -z "$(ls -A /material)"; tar -xf - -C /material; chown -R '+uid+':'+uid+' /material; chmod 0700 /material; chmod 0600 /material/*'],tar.stdout);
      const observed = await helper(['--user',uid+':'+uid,...volume(normal.volumes[role].name,'/material',true),'--entrypoint','sh',lock.images.participant,'-euc',
        'cd /material; test "$(LC_ALL=C ls -A1)" = \''+names.join('\n')+'\'; test "$(stat -c %u:%g:%a .)" = '+uid+':'+uid+':700; for f in *; do test -f "$f" && test ! -L "$f" && test "$(stat -c %u:%g:%a:%h "$f")" = '+uid+':'+uid+':600:1; done; sha256sum '+names.join(' ')]);
      if (observed.toString()!==expected) throw denied('VOLUME_MATERIAL');
    }
    for (const [role,uid] of [['postgres',70],['mariadb',999],['participant_state',1000]]) {
      dockerPhase = 'initialize-' + role.replaceAll('_','-') + '-directory';
      await helper(['--user','0:0','--cap-add','CHOWN','--cap-add','FOWNER','--cap-add','DAC_OVERRIDE',...volume(normal.volumes[role].name,'/data'),
        '--entrypoint','sh',lock.images.participant,'-euc','test -z "$(ls -A /data)"; chown '+uid+':'+uid+' /data; chmod 0700 /data; test "$(stat -c %u:%g:%a /data)" = '+uid+':'+uid+':700']);
    }
    // The installer-only volume is never declared in normal Compose.
    dockerPhase = 'stage-maintenance-material';
    resources.volumes.push(maintenanceVolume); await docker(['volume','create',...labelArgs(labels('installation-material')),maintenanceVolume]);
    const scriptDir = targetDirectory + '.install-material'; scratch.directory(scriptDir);
    scratch.directory(join(scriptDir,'wordpress-initialize')); scratch.directory(join(scriptDir,'maintenance'));
    scratch.file(join(scriptDir,'wordpress-initialize/owner.json'),operatorBytes);
    for (const name of ['wordpress-initialize.php','wordpress-initialize-lib.php'])
      scratch.file(join(scriptDir,'maintenance',name),readFileSync(new URL(name,import.meta.url)));
    const tar = await processRun('tar',materialArchiveArguments(scriptDir,['.'])); if(tar.code!==0 || tar.overflow) throw denied('MAINTENANCE_ARCHIVE');
    await helper(['-i','--user','0:0','--cap-add','CHOWN','--cap-add','FOWNER','--cap-add','DAC_OVERRIDE',...volume(maintenanceVolume,'/material'),
      '--entrypoint','sh',lock.images.participant,'-euc','test -z "$(ls -A /material)"; tar -xf - -C /material; chown -R 33:33 /material; chmod 0755 /material /material/maintenance; chmod 0644 /material/maintenance/*; chmod 0700 /material/wordpress-initialize; chmod 0600 /material/wordpress-initialize/owner.json'],tar.stdout);
    const participant = JSON.parse(privateFile(join(targetDirectory,'participant_material/service.json')));
    const pg = postgresInitializationPlan(c,lock,owner,{statements:participant.content.statements,seedSha256:sha(JSON.stringify(participant.content.statements)),
      topic:'Closed Community Pulse installation',description:'Admission remains closed pending a separately approved activation.'});
    const clean = descriptor => { const s = structuredClone(descriptor); delete s.profiles; delete s.depends_on; delete s.healthcheck; return s; };
    const wpInit = phase => ({...clean(normal.services.wordpress),user:phase==='site'?'33:33':'0:0',network_mode:'none',
      networks:undefined,cap_add:phase==='site'?[]:['DAC_OVERRIDE'],entrypoint:['php'],command:['/installation/maintenance/wordpress-initialize.php',phase],
      volumes:[...normal.services.wordpress.volumes,{type:'volume',source:'installation_material',target:'/installation',read_only:true,volume:{nocopy:true}},
        {type:'volume',source:'installation_material',target:'/run/fncp/wordpress-initialize',read_only:true,volume:{nocopy:true,subpath:'wordpress-initialize'}}]});
    const maintenance = {name:c.deployment,services:{
      'pg-initialize':{...clean(pg.maintenance.initialize),command:composeRawShellCommand(pg.maintenance.initialize.command)},
      'pg-migrate':clean(pg.maintenance.migration),
      'pg-seed':{...clean(pg.maintenance.seed),command:composeRawShellCommand(pg.maintenance.seed.command)},
      'mariadb-initialize':{...clean(normal.services.mariadb),entrypoint:['sh'],command:composeRawShellCommand(['-euc',MARIADB_FRESH_INITIALIZE])},
      'wp-database':wpInit('database'),'wp-site':wpInit('site'),'wp-finalize':wpInit('finalize')},
      volumes:Object.fromEntries([...Object.entries(normal.volumes).map(([k,v])=>[k,{name:v.name,external:true}]),['installation_material',{name:maintenanceVolume,external:true}]]),
      networks:Object.fromEntries(Object.entries(normal.networks).map(([k,v])=>[k,{name:v.name,external:true}]))};
    for (const s of Object.values(maintenance.services)) if (s.network_mode) delete s.networks;
    save('maintenance-compose.json',JSON.stringify(maintenance,null,2)+'\n');
    const maintenanceFile = join(evidenceDirectory,'maintenance-compose.json');
    const phase = async (name,input) => {
      dockerPhase = name;
      await sameEngine(); const r = await compose(maintenanceFile,['run','--rm','--no-deps','-T',name],input);
      checks.push(name); save(name+'.json',{pass:true,outputSha256:sha(r.stdout)}); return r.stdout;
    };
    await checkpoint('all-owned-volumes-material-and-maintenance-separated');
    await phase('pg-initialize'); await phase('mariadb-initialize');
    dockerPhase = 'start-native-databases';
    await compose(normalFile,['up','--detach','--no-deps','--wait','--wait-timeout','90','postgres','mariadb']);
    await phase('pg-migrate');
    const pgReceipt = validatePostgresInitializationReceipt(pg,JSON.parse(await phase('pg-seed',pg.psql.stdin))); save('postgres-receipt.json',pgReceipt);
    for (const name of ['wp-database','wp-site','wp-finalize']) await phase(name);
    dockerPhase = 'detach-maintenance-material';
    await owned('volume',maintenanceVolume,labels('installation-material')); await docker(['volume','rm',maintenanceVolume]);
    await absent('volume',maintenanceVolume);
    scratch.cleanup(); scratchRemoved = true;
    await checkpoint('fresh-databases-seeded-closed-installer-detached');
    dockerPhase = 'start-normal-services';
    await compose(normalFile,['up','--detach','--wait','--wait-timeout','120']);
    dockerPhase = 'inspect-normal-services';
    const ids = (await compose(normalFile,['ps','-q'])).stdout.toString().trim().split('\n').filter(Boolean);
    if (ids.length!==Object.keys(lock.images).length-1) throw denied('NORMAL_ROLE_COUNT');
    const runtime = [];
    for (const id of ids) {
      const i = await owned('container',id,{[LABEL]:owner}), role = i.Config.Labels['com.docker.compose.service'], expected = normal.services[role];
      const expectedPorts = Object.fromEntries((expected?.ports ?? []).map(port => [port.target+'/'+port.protocol,[{HostIp:port.host_ip,HostPort:String(port.published)}]]));
      const actualPorts = Object.fromEntries(Object.entries(i.HostConfig.PortBindings??{}).filter(([,value])=>value!==null));
      if (!expected || role==='migration' || i.Image!==lock.images[role] || !i.State.Running || i.Config.User!==expected.user
        || !i.HostConfig.ReadonlyRootfs || i.HostConfig.Privileged || canonical(actualPorts)!==canonical(expectedPorts)
        || canonical(i.HostConfig.CapDrop)!=='["ALL"]' || i.HostConfig.CapAdd?.length
        || !i.HostConfig.SecurityOpt.includes('no-new-privileges:true') || i.HostConfig.RestartPolicy.Name!=='no') throw denied('RUNTIME_PROFILE');
      for (const m of expected.volumes??[]) {
        const observed = i.Mounts.find(v=>v.Destination===m.target);
        if (!observed || observed.Type!==m.type || observed.RW!==(m.read_only!==true)
          || (m.type==='volume'?observed.Name!==normal.volumes[m.source].name:observed.Source!==m.source)) throw denied('RUNTIME_MOUNT');
      }
      if (i.Mounts.some(m=>m.Name===maintenanceVolume)) throw denied('INSTALLER_ATTACHED');
      const networks = Object.keys(i.NetworkSettings.Networks).sort();
      const expectedNetworks = expected.network_mode==='none'?['none']:Object.keys(expected.networks).map(n=>normal.networks[n].name).sort();
      if (canonical(networks)!==canonical(expectedNetworks)) throw denied('RUNTIME_NETWORK');
      runtime.push({role,image:i.Image,user:i.Config.User,running:true,publishedPorts:(expected.ports??[]).length,installerMaterial:false});
    }
    const exactSnapshot = validateRunningProductionSnapshot({configuration:c,imageLock:lock,ownerToken:owner,
      rows:await Promise.all(ids.map(id=>inspect('container',id))),
      images:Object.fromEntries(await Promise.all(Object.entries(lock.images).map(async ([role,id])=>[role,await inspect('image',id)]))),
      volumes:await Promise.all(Object.values(normal.volumes).map(v=>inspect('volume',v.name))),
      networks:await Promise.all(Object.values(normal.networks).map(n=>inspect('network',n.name))),
      coreMaterial:Object.fromEntries(['api.env','math.env','migration.env'].map(name=>[name,{data:privateFile(join(c.stateDirectory,'material',name)).toString('base64')}]))});
    save('normal-runtime.json',{...exactSnapshot,roles:runtime});
    const participantId = (await compose(normalFile,['ps','-q','participant'])).stdout.toString().trim();
    const state = await docker(['exec',participantId,'node','deploy/fncp/production-service/operator-cli.mjs','/var/lib/fncp','status']);
    save('participant-status.json',state.stdout.toString());
    const observed = JSON.parse(state.stdout); if (observed.roundOpen!==false || observed.registrations!==0) throw denied('ADMISSION_OPEN');
    await checkpoint('normal-services-running-from-exact-descriptor'); status='PASS_CLOSED_INSTALL';
    return {status,deployment:c.deployment,engineId:info.ID,normalServices:runtime.length,publishedPorts:c.version===3?2:0,activationGranted:false};
  } finally {
    operatorBytes.fill(0);
    if (!scratchRemoved) { try { scratch.cleanup(); scratchRemoved = true; } catch { status = 'FAIL'; checks.push('maintenance-scratch-custody-requires-inspection'); } }
    if (status!=='PASS_CLOSED_INSTALL') {
      // Stop only independently owner-checked containers; preserve all volumes.
      try {
        dockerPhase = 'failure-stop-owned-containers';
        await sameEngine(); const rows = (await docker(['ps','-aq','--filter','label='+LABEL+'='+owner])).stdout.toString().trim().split('\n').filter(Boolean);
        for (const id of rows) { await owned('container',id,{[LABEL]:owner}); await docker(['stop','--time','20',id]); }
      } catch { checks.push('failure-stop-requires-operator-inspection'); }
    }
    save('summary.json',{status,began,finishedAt:new Date().toISOString(),checks,resources,sourceFingerprint:lock.sourceFingerprint,
      imageLockSha256:sha(canonical(lock)),dockerFailureReceipts:failureCount,publishedPorts:c?.version===3?2:0,activationGranted:false,retainedState:true,wholeJourneyProved:false,launchAuthorized:false});
    if (!scratchRemoved) throw denied('MAINTENANCE_SCRATCH_CLEANUP');
  }
}
if (process.argv[1] && import.meta.url===pathToFileURL(resolve(process.argv[1])).href) {
  const [socket,inputDirectory,targetDirectory,operatorFile,evidenceDirectory]=process.argv.slice(2);
  installClosed({socket,inputDirectory,targetDirectory,operatorFile,evidenceDirectory}).then(r=>console.log(JSON.stringify(r)))
    .catch(error=>{console.error(error.message.startsWith('FNCP_')?error.message:'FNCP_CLOSED_INSTALL_REJECTED');process.exitCode=1;});
}
