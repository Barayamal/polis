import test from 'node:test';
import assert from 'node:assert/strict';
import { PROFILE,ROLES,validateProductionConfiguration,validateProductionImageLock,renderProductionCompose,validateProductionCompose } from './compose.mjs';
const denied={message:'Production composition rejected.'},owner='e'.repeat(48);
const configuration=()=>({version:1,profile:PROFILE,deployment:'fncp-production-contract-20260914',platform:'linux/arm64',stateDirectory:'/private/fncp-test/core-state',sourceRevision:'a'.repeat(40),
  database:{name:'polis',owner:'polis_owner',migrationRole:'polis_migration',runtimeRole:'polis_runtime',mathRole:'polis_math',host:'postgres',port:5432},
  binding:{conversationId:'9fixedConversation',statementIds:Array.from({length:15},(_,i)=>i)},identity:{issuer:'https://issuer.example.invalid/',audience:'configured-client',jwksUri:'https://issuer.example.invalid/jwks'}});
const imageLock=()=>({version:1,sourceRevision:'a'.repeat(40),sourceFingerprint:'b'.repeat(64),images:Object.fromEntries(ROLES.map((role,i)=>[role,'sha256:'+String(i+1).repeat(64)]))});
const rendered=()=>renderProductionCompose(configuration(),imageLock(),owner);

test('pure normal-start descriptor snapshots input and defaults to internal networking without egress',()=>{
  const c=configuration(),v=validateProductionConfiguration(c),doc=renderProductionCompose(c,imageLock(),owner);assert.equal(v.oidcEgress,false);assert.deepEqual(Object.keys(doc.networks),['core']);assert.equal(doc.networks.core.internal,true);assert.equal(doc['x-fncp-boundary'].publishedPorts,0);assert.equal(doc['x-fncp-boundary'].defaultAdmission,'closed');
  c.binding.statementIds[0]=99;assert.equal(v.binding.statementIds[0],0);assert.equal(doc['x-fncp-boundary'].statementIds[0],0);assert.ok(Object.isFrozen(doc.services.participant.volumes));assert.throws(()=>doc.services.participant.volumes.push({}));
  assert.equal(validateProductionCompose(doc,configuration(),imageLock(),owner),true);
});
test('configuration rejects overrides, interpolation, path aliases, remote database and unsupported platform',()=>{
  for(const alter of [c=>c.ports=['443:8443'],c=>c.networks={host:{}},c=>c.environment={UNSAFE:'1'},c=>c.command=['sh'],c=>c.platform='linux/amd64',c=>c.deployment='shared',c=>c.stateDirectory='relative',c=>c.stateDirectory='/private/a/../b',c=>c.stateDirectory='/private/$HOME',c=>c.stateDirectory='/private/line\npath',c=>c.database.host='outside.example',c=>c.database.port=6543,c=>c.oidcEgress='true']){const c=configuration();alter(c);assert.throws(()=>validateProductionConfiguration(c),denied);}
});
test('identity is explicit HTTPS and default egress does not invent an external issuer fixture',()=>{
  for(const url of ['http://issuer.example.invalid/','https://user:password@issuer.example.invalid/','https://issuer.example.invalid/?override=1','https://issuer.example.invalid/#fragment','https://issuer.example.invalid:443/']){const c=configuration();c.identity.issuer=url;assert.throws(()=>validateProductionConfiguration(c),denied);}
  const doc=rendered();assert.deepEqual(doc['x-fncp-boundary'].identity,configuration().identity);assert.equal(doc['x-fncp-boundary'].egressDestinationEnforcement,'no-external-egress');assert.equal(doc.services.issuer,undefined);
});
test('exact fifteen canonical statement IDs and four distinct restricted DB roles remain mandatory',()=>{
  for(const alter of [c=>c.binding.statementIds.pop(),c=>c.binding.statementIds[14]=0,c=>c.binding.statementIds[0]=-0,c=>c.binding.statementIds[0]='0',c=>c.database.runtimeRole=c.database.owner,c=>c.database.name='polis;DROP',c=>c.database.owner='postgres']){const c=configuration();alter(c);assert.throws(()=>validateProductionConfiguration(c),denied);}
  const changed=configuration();changed.binding.conversationId='9differentConversation';assert.throws(()=>validateProductionCompose(rendered(),changed,imageLock(),owner),denied);
});
test('constructor descriptors reject getters and sparse or accessor-backed ID arrays without executing them',()=>{
  let calls=0;const c=configuration();Object.defineProperty(c.binding.statementIds,'0',{get(){calls++;return 0;},enumerable:true});assert.throws(()=>validateProductionConfiguration(c),denied);assert.equal(calls,0);
  const sparse=configuration();delete sparse.binding.statementIds[2];assert.throws(()=>validateProductionConfiguration(sparse),denied);
  const top=configuration();Object.defineProperty(top,'platform',{get(){calls++;return'linux/arm64';},enumerable:true});assert.throws(()=>validateProductionConfiguration(top),denied);assert.equal(calls,0);
});
test('eight independent full image IDs, matching source and owner token are required',()=>{
  for(const alter of [l=>l.images.api='polis:latest',l=>l.images.api='sha256:abcd',l=>l.images.api=l.images.math,l=>delete l.images.proxy,l=>l.images.qa='sha256:'+'c'.repeat(64),l=>l.sourceFingerprint='bad']){const l=imageLock();alter(l);assert.throws(()=>validateProductionImageLock(l),denied);}
  const mismatch=imageLock();mismatch.sourceRevision='c'.repeat(40);assert.throws(()=>renderProductionCompose(configuration(),mismatch,owner),denied);assert.throws(()=>renderProductionCompose(configuration(),imageLock(),'missing-owner'),denied);
});
test('all role isolation and resource limits are explicit, with no published or hidden exposed ports',()=>{
  const doc=rendered(),uids={api:'1000:1000',math:'65532:65532',postgres:'70:70',migration:'70:70',participant:'1000:1000',wordpress:'33:33',mariadb:'999:999',proxy:'101:101'};
  assert.deepEqual(Object.keys(doc.services).sort(),[...ROLES].sort());
  for(const[role,s]of Object.entries(doc.services)){assert.equal(s.image,imageLock().images[role]);assert.equal(s.platform,'linux/arm64');assert.equal(s.pull_policy,'never');assert.equal(s.user,uids[role]);assert.equal(s.read_only,true);assert.deepEqual(s.cap_drop,['ALL']);assert.deepEqual(s.security_opt,['no-new-privileges:true']);assert.equal(s.restart,'no');assert.equal(s.ports,undefined);assert.equal(s.expose,undefined);assert.ok(s.pids_limit>0&&s.pids_limit<=256);assert.match(s.mem_limit,/^[1-9][0-9]*m$/u);assert.ok(Number(s.cpus)>0&&Number(s.cpus)<=2);assert.equal(s.labels['org.barayamal.fncp.owner'],owner);assert.ok(s.tmpfs.every(x=>x.includes('nosuid')&&x.includes('nodev')&&x.includes('size=')));}
  for(const[n,r]of [...Object.entries(doc.volumes),...Object.entries(doc.networks)]){assert.equal(r.labels['org.barayamal.fncp.owner'],owner);assert.ok(r.name.startsWith(doc.name+'_'),n);}
});
test('core material mounts retain exact per-file paths and readonly/no-create contract',()=>{
  const doc=rendered();for(const role of ['api','math','migration'])assert.deepEqual(doc.services[role].env_file,[configuration().stateDirectory+'/material/'+role+'.env']);
  const binds=Object.values(doc.services).flatMap(s=>s.volumes).filter(v=>v.type==='bind');assert.equal(binds.length,11);
  for(const v of binds){assert.equal(v.read_only,true);assert.deepEqual(v.bind,{create_host_path:false});assert.equal(v.source,configuration().stateDirectory+'/material/'+v.target.split('/').at(-1));assert.ok(v.target.startsWith('/run/fncp/'));}
  assert.equal(doc.services.math.mem_limit,'1536m');assert.equal(doc.services.api.mem_limit,'1536m');assert.equal(doc.services.migration.mem_limit,'256m');assert.deepEqual(doc.services.math.depends_on,{api:{condition:'service_healthy'}});assert.deepEqual(doc.services.postgres.command,['start']);
});
test('MariaDB is socket-only, with its data exclusive and socket shared readonly only with WordPress',()=>{
  const doc=rendered(),m=doc.services.mariadb;assert.equal(m.network_mode,'none');assert.equal(m.networks,undefined);assert.deepEqual(m.entrypoint,['mariadbd']);assert.ok(m.command.includes('--skip-networking'));assert.ok(m.command.includes('--datadir=/var/lib/mysql'));assert.ok(m.command.includes('--local-infile=0'));
  const socketUsers=Object.entries(doc.services).filter(([,s])=>s.volumes.some(v=>v.source==='mariadb_socket'));assert.deepEqual(socketUsers.map(([n])=>n).sort(),['mariadb','wordpress']);assert.equal(doc.services.wordpress.volumes.find(v=>v.source==='mariadb_socket').read_only,true);
  assert.deepEqual(Object.entries(doc.services).filter(([,s])=>s.volumes.some(v=>v.source==='mariadb')).map(([n])=>n),['mariadb']);assert.equal(doc.volumes.mariadb_socket.driver_opts.o,'size=16m,uid=999,gid=33,mode=0750,noexec,nosuid,nodev');
});
test('participant and WordPress use distinct persistent readonly material with immutable image source',()=>{
  const doc=rendered();for(const[role,source,target]of [['participant','participant_material','/run/fncp'],['wordpress','wordpress_material','/run/fncp/wordpress'],['proxy','proxy_material','/run/fncp']]){const mount=doc.services[role].volumes.find(v=>v.source===source);assert.equal(mount.target,target);assert.equal(mount.read_only,true);assert.equal(mount.volume.nocopy,true);}
  assert.equal(doc.services.participant.volumes.find(v=>v.source==='participant_state').target,'/var/lib/fncp');assert.equal(doc.services.participant.volumes.find(v=>v.source==='participant_state').read_only,false);
  assert.ok(doc.services.wordpress.tmpfs.some(v=>v.startsWith('/var/www/html:ro,')));assert.equal(doc.services.wordpress.volumes.some(v=>v.target==='/usr/src/wordpress'),false);assert.deepEqual(doc.services.wordpress.entrypoint,['/usr/local/bin/fncp-wordpress-start']);assert.match(doc.services.wordpress.healthcheck.test[3],/\$\$s/u);
});
test('current profiles reject broad OIDC egress instead of delegating an unenforced allowlist',()=>{
  for(const version of [1,2,3]){
    const c=configuration();c.version=version;c.profile=version===1?'FNCP_PRODUCTION_COMPOSE_V1':version===2?'FNCP_PRODUCTION_COMPOSE_V2':'FNCP_PRODUCTION_COMPOSE_V3';
    if(version>=2)c.edge={publicOrigin:'https://participant.example.invalid',discardCookies:[]};
    if(version===3)c.operatorAccess={profile:'FNCP_OPERATOR_LOOPBACK_V1',tunnelRequired:true,participant:{hostIp:'127.0.0.1',published:8443,target:8443,protocol:'tcp'},wordpress:{hostIp:'127.0.0.1',published:9443,target:8443,protocol:'tcp'}};
    c.oidcEgress=true;assert.throws(()=>validateProductionConfiguration(c),denied);
  }
  const doc=rendered();assert.equal(doc.networks.oidc_egress,undefined);assert.deepEqual(Object.keys(doc.services.participant.networks),['core']);
});
test('normal start excludes initialization and keeps migrations in an explicit maintenance profile',()=>{
  const doc=rendered();assert.deepEqual(doc.services.migration.profiles,['maintenance']);for(const[r,s]of Object.entries(doc.services))if(r!=='migration')assert.equal(s.profiles,undefined);
  assert.doesNotMatch(JSON.stringify(doc),/\/qa\/|\/run\/qa|install\.php|inspect\.php|docker-entrypoint\.sh|--initialize|"build"|docker\.sock/u);assert.equal(doc['x-fncp-boundary'].requiresProvisionedState,true);assert.equal(doc['x-fncp-boundary'].normalStartOnly,true);
});
test('saved descriptor validator rejects hidden ports, extra mounts/networks and security or role changes',()=>{
  const alterations=[d=>d.services.api.ports=['5000:5000'],d=>d.services.wordpress.expose=['9999'],d=>d.services.participant.network_mode='host',d=>d.services.api.privileged=true,d=>d.services.math.read_only=false,d=>d.services.proxy.cap_add=['NET_ADMIN'],d=>d.services.api.security_opt=[],d=>d.services.postgres.restart='always',d=>d.services.mariadb.user='0:0',d=>d.services.mariadb.command.push('--port=3306'),d=>d.services.participant.command=['sh'],d=>d.services.wordpress.entrypoint=['docker-entrypoint.sh'],d=>d.services.api.env_file.push('/etc/unreviewed.env'),d=>d.services.api.volumes.push({type:'bind',source:'/var/run/docker.sock',target:'/var/run/docker.sock'}),d=>d.services.api.volumes[0].bind.create_host_path=true,d=>d.services.api.volumes[0].source='/other/ca.pem',d=>d.services.participant.volumes[0].read_only=false,d=>d.services.wordpress.volumes[1].read_only=false,d=>d.networks.core.internal=false,d=>d.networks.extra={external:true},d=>d.volumes.postgres.external=true,d=>d.volumes.mariadb_socket.driver_opts.o='device=/etc',d=>d.services.migration.profiles=[],d=>d.services.api.image=imageLock().images.participant];
  for(const alter of alterations){const doc=structuredClone(rendered());alter(doc);assert.throws(()=>validateProductionCompose(doc,configuration(),imageLock(),owner),denied);}
});

test('explicit V2 adds a ninth role, seventh durable volume and isolated participant edge network without ingress publication',async()=>{
  const {PROFILE_V2,ROLES_V2,imageRoles}=await import('./compose.mjs');const c={...configuration(),version:2,profile:PROFILE_V2,edge:{publicOrigin:'https://participants.example.invalid',discardCookies:['__cf_bm']}};
  const lock={...imageLock(),version:2,images:{...imageLock().images,edge:'sha256:'+'9'.repeat(64)}};
  const doc=renderProductionCompose(c,lock,owner);assert.deepEqual(imageRoles(2),ROLES_V2);assert.equal(doc['x-fncp-boundary'].profile,PROFILE_V2);assert.equal(doc['x-fncp-boundary'].durableVolumes,7);
  assert.equal(Object.keys(doc.services).length,9);assert.equal(Object.keys(doc.volumes).length,8);assert.deepEqual(Object.keys(doc.services.edge.networks),['participant_ingress']);
  assert.deepEqual(Object.entries(doc.services).filter(([,s])=>s.networks?.participant_ingress).map(([r])=>r),['participant','edge']);assert.equal(doc.networks.participant_ingress.internal,true);
  assert.deepEqual(doc.services.participant.networks.participant_ingress,{aliases:['participant-edge-upstream']});assert.equal(doc.services.edge.user,'1000:1000');assert.equal(doc.services.edge.ports,undefined);
  assert.deepEqual(doc.services.edge.volumes,[{type:'volume',source:'edge_material',target:'/run/fncp/edge',read_only:true,volume:{nocopy:true}}]);
  assert.deepEqual(doc.services.proxy.networks,{core:{aliases:['polis-proxy']}});assert.equal(validateProductionCompose(doc,c,lock,owner),true);
  for(const edit of [x=>x.edge.publicOrigin='http://participants.example.invalid',x=>x.edge.publicOrigin+='/',x=>x.edge.discardCookies=['cf_clearance'],x=>x.edge.listen='0.0.0.0',x=>x.version=1,x=>delete x.edge]){const changed=structuredClone(c);edit(changed);assert.throws(()=>renderProductionCompose(changed,lock,owner),denied);}
  assert.throws(()=>renderProductionCompose(c,imageLock(),owner),denied);assert.throws(()=>renderProductionCompose(configuration(),lock,owner),denied);
  for(const edit of [x=>x.services.edge.networks.core={},x=>x.services.edge.ports=['443:8443'],x=>x.services.edge.volumes[0].read_only=false,x=>x.networks.participant_ingress.internal=false,x=>x.services.proxy=structuredClone(x.services.edge)]){const changed=structuredClone(doc);edit(changed);assert.throws(()=>validateProductionCompose(changed,c,lock,owner),denied);}
});

test('V3 publishes only two fixed IPv4 loopback TLS listeners through an isolated opaque gateway',async()=>{
  const {PROFILE_V3,OPERATOR_ACCESS_PROFILE,ROLES_V3,imageRoles}=await import('./compose.mjs');
  const operatorAccess={profile:OPERATOR_ACCESS_PROFILE,tunnelRequired:true,participant:{hostIp:'127.0.0.1',published:8443,target:8443,protocol:'tcp'},wordpress:{hostIp:'127.0.0.1',published:9443,target:8443,protocol:'tcp'}};
  const c={...configuration(),version:3,profile:PROFILE_V3,edge:{publicOrigin:'https://participants.example.invalid',discardCookies:[]},operatorAccess};
  const lock={...imageLock(),version:3,images:{...imageLock().images,edge:'sha256:'+'9'.repeat(64),operator:'sha256:'+'a'.repeat(64)}};
  const doc=renderProductionCompose(c,lock,owner);
  assert.deepEqual(imageRoles(3),ROLES_V3);assert.equal(doc['x-fncp-boundary'].publishedPorts,2);assert.equal(doc['x-fncp-boundary'].publicListeners,0);
  assert.equal(doc['x-fncp-boundary'].operatorTunnelRequired,true);assert.deepEqual(doc['x-fncp-boundary'].operatorAccess,operatorAccess);
  assert.equal(doc.services.edge.ports,undefined);assert.equal(doc.services.wordpress.ports,undefined);
  assert.deepEqual(doc.services.operator.ports,[{target:8443,published:8443,host_ip:'127.0.0.1',protocol:'tcp',mode:'host'},{target:9443,published:9443,host_ip:'127.0.0.1',protocol:'tcp',mode:'host'}]);
  assert.deepEqual(Object.entries(doc.services).filter(([,service])=>service.ports).map(([role])=>role),['operator']);
  assert.deepEqual(Object.keys(doc.services.operator.networks),['core','participant_ingress','operator_access']);
  assert.equal(doc.networks.operator_access.internal,false);assert.equal(doc.networks.core.internal,true);assert.equal(doc.networks.participant_ingress.internal,true);
  assert.equal(doc['x-fncp-boundary'].egressDestinationEnforcement,'operator-gateway-only-no-application-egress');
  assert.equal(validateProductionCompose(doc,c,lock,owner),true);
  const edits=[x=>x.operatorAccess.participant.hostIp='0.0.0.0',x=>x.operatorAccess.participant.hostIp='::1',x=>x.operatorAccess.participant.published=0,
    x=>x.operatorAccess.participant.published=443,x=>x.operatorAccess.participant.target=5000,x=>x.operatorAccess.participant.protocol='udp',
    x=>x.operatorAccess.wordpress.hostIp='192.0.2.1',x=>x.operatorAccess.wordpress.published=8443,x=>x.operatorAccess.tunnelRequired=false,
    x=>x.operatorAccess.profile='UNREVIEWED',x=>x.operatorAccess.database={hostIp:'127.0.0.1',published:5432,target:5432,protocol:'tcp'},x=>delete x.operatorAccess];
  for(const edit of edits){const changed=structuredClone(c);edit(changed);assert.throws(()=>renderProductionCompose(changed,lock,owner),denied);}
  for(const edit of [x=>x.services.operator.ports[0].host_ip='0.0.0.0',x=>x.services.operator.ports[1].published=8443,x=>x.services.edge.ports=[{target:8443,published:8443,host_ip:'127.0.0.1',protocol:'tcp',mode:'host'}],x=>x.services.operator.networks.core=undefined,x=>x.networks.operator_access.internal=true,x=>x.services.api.ports=[{target:5000,published:5000,host_ip:'127.0.0.1',protocol:'tcp',mode:'host'}]]){
    const changed=structuredClone(doc);edit(changed);assert.throws(()=>validateProductionCompose(changed,c,lock,owner),denied);
  }
});
