import test from 'node:test';
import assert from 'node:assert/strict';
import { assertContainerProfile } from './container-profile.mjs';
const c={deployment:'fncp-test-core'};
const service={user:'70:70',restart:'no',security_opt:['no-new-privileges:true'],volumes:[{type:'volume',source:'postgres',target:'/var/lib/postgresql/data'},{type:'bind',source:'/private/runtime/database-server.key',target:'/run/fncp/database-server.key',read_only:true}],tmpfs:['/tmp:rw,nosuid,nodev,size=128m,mode=1777']};
function valid(){return {Config:{User:'70:70'},HostConfig:{ReadonlyRootfs:true,Privileged:false,PublishAllPorts:false,RestartPolicy:{Name:'no'},CapDrop:['ALL'],CapAdd:[],SecurityOpt:['no-new-privileges:true'],PortBindings:{},NetworkMode:'fncp-test-core_private',Tmpfs:{'/tmp':'rw,nosuid,nodev,size=128m,mode=1777'}},NetworkSettings:{Ports:{'5432/tcp':null},Networks:{'fncp-test-core_private':{}}},Mounts:[{Type:'volume',Name:'fncp-test-core_postgres',Destination:'/var/lib/postgresql/data',RW:true},{Type:'bind',Source:'/private/runtime/database-server.key',Destination:'/run/fncp/database-server.key',RW:false}]};}
test('exact owned database storage and private isolation pass',()=>assert.equal(assertContainerProfile(valid(),service,c),true));
for(const [name,change] of [
 ['replacement database volume',r=>r.Mounts[0].Name='some-other-database'],
 ['changed certificate source',r=>r.Mounts[1].Source='/private/other.key'],
 ['writable certificate',r=>r.Mounts[1].RW=true],
 ['missing data mount',r=>r.Mounts.shift()],
 ['additional anonymous volume',r=>r.Mounts.push({Type:'volume',Name:'anonymous',Destination:'/extra',RW:true})],
 ['root process',r=>r.Config.User='0:0'],
 ['additional public network',r=>r.NetworkSettings.Networks.bridge={}],
 ['publish all exposed ports',r=>r.HostConfig.PublishAllPorts=true],
 ['published runtime port',r=>r.NetworkSettings.Ports['5432/tcp']=[{HostIp:'0.0.0.0',HostPort:'5432'}]],
 ['automatic restart',r=>r.HostConfig.RestartPolicy.Name='always'],
 ['privilege escalation allowed',r=>r.HostConfig.SecurityOpt=[]],
 ['disabled seccomp profile',r=>r.HostConfig.SecurityOpt.push('seccomp=unconfined')],
 ['added capability',r=>r.HostConfig.CapAdd=['NET_ADMIN']],
 ['unreviewed writable tmpfs',r=>r.HostConfig.Tmpfs['/secret']='rw'],
 ['changed temporary filesystem policy',r=>r.HostConfig.Tmpfs['/tmp']='rw,exec'],
])test(name+' rejects even with unchanged identity labels',()=>{const r=valid();change(r);assert.throws(()=>assertContainerProfile(r,service,c),/FNCP_SELFHOST_CONTAINER_PROFILE/);});
