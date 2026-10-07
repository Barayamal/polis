/** Disposable actual integration. Fixed Linux container paths, no live data or
 * external identity/mail. Aggregate output only; private material stays tmpfs. */
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {mkdir,readFile,writeFile,copyFile,lstat} from 'node:fs/promises';
import {createHash,randomBytes} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {connect} from 'node:net';
import {createFreshContainerWordPress} from './wordpress-container-runtime.mjs';
import {createStrictLocalService} from '../strict-service/service.mjs';
import {LocalPolisProvider} from '../local-access/access-server.mjs';
import {createSyntheticIdentityHarness} from '../identity-foundation/synthetic-harness.mjs';
import {createSyntheticBrowserDriver} from '../identity-foundation/synthetic-browser-driver.mjs';
import {syntheticBinding,syntheticClaims,syntheticSigningFixture} from '../activation-foundation/synthetic-fixtures.mjs';
import {createBrowserClient} from '../local-browser/integration-client.mjs';
import {createWordPressIdentityClient} from '../wordpress-identity/wordpress-client.mjs';
import {exerciseWordPressIdentityJourney} from '../wordpress-identity/journey.mjs';
import {exerciseNativeWordPressJourney} from './journey-native-browser.mjs';
import {observeFreshJourneyVote} from './journey-vote-observation.mjs';
const ROOT='/run/fncp/journey', BOOT='/run/fncp/bootstrap';
const ENV={PATH:'/usr/bin:/bin',LANG:'C',LC_ALL:'C',FNCP_LOCAL_SYNTHETIC_MODE:'fixture-only'};
const hash=b=>createHash('sha256').update(b).digest('hex');
const random=()=>randomBytes(32).toString('base64url');
const assert=(value,label='CHECK')=>{if(!value)throw Error(label);};
const pause=ms=>new Promise(r=>setTimeout(r,ms));
async function command(bin,args,input,timeout=30000){
  return new Promise((resolve,reject)=>{
    const c=spawn(bin,args,{env:ENV,stdio:['pipe','pipe','ignore']});let size=0;const chunks=[];
    const timer=setTimeout(()=>c.kill('SIGKILL'),timeout);
    c.stdout.on('data',b=>{size+=b.length;if(size>16*1024*1024)c.kill('SIGKILL');else chunks.push(b);});
    c.on('error',()=>reject(Error('PROCESS')));c.on('close',code=>{clearTimeout(timer);code===0?resolve(Buffer.concat(chunks)):reject(Error('PROCESS'));});
    c.stdin.on('error',()=>{});c.stdin.end(input);
  });
}
async function stopped(child){
  if(!child||child.exitCode!==null||child.signalCode!==null)return;
  await new Promise(resolve=>{const timer=setTimeout(()=>child.kill('SIGKILL'),5000);child.once('close',()=>{clearTimeout(timer);resolve();});child.kill('SIGTERM');});
}
async function refusal(port){return new Promise(resolve=>{const s=connect({host:'127.0.0.1',port});s.setTimeout(1000);s.once('connect',()=>{s.destroy();resolve(false);});s.once('error',e=>resolve(e.code==='ECONNREFUSED'));s.once('timeout',()=>{s.destroy();resolve(false);});});}
async function egress(){
  const results=[];
  for(const host of ['1.1.1.1','8.8.8.8','2606:4700:4700::1111'])results.push(await new Promise(resolve=>{
    const s=connect({host,port:443});s.setTimeout(1200);s.once('connect',()=>{s.destroy();resolve({family:host.includes(':')?'IPv6':'IPv4',denied:false});});
    s.once('error',e=>resolve({family:host.includes(':')?'IPv6':'IPv4',denied:['ENETUNREACH','EHOSTUNREACH','EACCES','EPERM'].includes(e.code),code:e.code}));
    s.once('timeout',()=>{s.destroy();resolve({denied:false,code:'TIMEOUT_UNCERTAIN'});});
  }));assert(results.every(r=>r.denied),'EGRESS');return results;
}
async function participant(){
  const child=spawn('/usr/local/bin/node',['/opt/fncp/deploy/fncp/fresh-runtime/participant-container-run.mjs'],{env:ENV,stdio:['pipe','pipe','ignore']});
  const exited=new Promise(resolve=>child.once('close',(code,signal)=>resolve({code,signal})));
  const lines=createInterface({input:child.stdout});const queue=[];let pending;
  lines.on('line',line=>{let data;try{assert(line.length<65536);data=JSON.parse(line);}catch{child.kill('SIGTERM');return;}
    if(pending){const {resolve,timer}=pending;pending=undefined;clearTimeout(timer);resolve(data);}else if(queue.length<40)queue.push(data);else child.kill('SIGTERM');});
  const failed=()=>{if(pending){clearTimeout(pending.timer);pending.reject(Error('PARTICIPANT_EXIT'));pending=undefined;}};
  child.on('error',failed);child.on('close',failed);
  const next=()=>queue.length?Promise.resolve(queue.shift()):new Promise((resolve,reject)=>{const timer=setTimeout(()=>{pending=undefined;reject(Error('PARTICIPANT_TIMEOUT'));},30000);pending={resolve,reject,timer};});
  let ready;try{ready=await next();assert(ready.event==='READY','PARTICIPANT_READY');}catch(e){await stopped(child);throw e;}
  return {child,ready,async control(action){child.stdin.write(JSON.stringify({action})+'\n');const value=await next();assert(value.event==='CONTROL'&&value.action===action&&value.ok===true,'PARTICIPANT_CONTROL');return value;},async close(){try{child.stdin.write('{"action":"stop"}\n');const final=await next();assert(final.event==='CLOSED'&&final.ok===true&&final.outcome==='PASS'&&['roundClosed','childExitVerified','listenerRefused','databaseClientClosed'].every(k=>final[k]===true),'PARTICIPANT_FINAL');let timer;const exit=await Promise.race([exited,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('PARTICIPANT_EXIT_TIMEOUT')),10000);})]).finally(()=>clearTimeout(timer));assert(exit.code===0&&!exit.signal&&await refusal(5500),'PARTICIPANT_CLOSURE');}catch(e){await stopped(child);throw e;}}};
}
async function main(){
  process.umask(0o077);
  const report={classification:'FRESH_ACTUAL_WORDPRESS_STRICT_POLIS_JOURNEY',outcome:'FAIL',checks:[],productionReady:false,realIdentity:false,nativeBrowser:false,authenticationTransport:'SYNTHETIC_INJECTED_CALLBACK',externalMail:false,activationFixtureOnly:true};
  let phase='PLATFORM',sqlProcess,polis,wp,service,restored;let closed=false;
  const sqlRoot=ROOT+'/mysql',socket=ROOT+'/mysql.sock';
  const sql=(query)=>command('/usr/bin/mariadb',['--no-defaults','--socket='+socket,'-uroot','--batch','--raw','--skip-column-names'],query);
  try{
    assert(process.platform==='linux'&&process.getuid()===1000&&process.argv.length===2,'PLATFORM');
    const stamp=await lstat(ROOT);assert(stamp.isDirectory()&&stamp.uid===1000,'ROOT');
    await writeFile(ROOT+'/journey-claimed','ONE_FRESH_ATTEMPT\n',{flag:'wx',mode:0o600});
    phase='EGRESS';report.egress=await egress();
    phase='MARIA_INIT';await mkdir(sqlRoot,{mode:0o700});
    await command('/usr/bin/mariadb-install-db',['--no-defaults','--datadir='+sqlRoot,'--auth-root-authentication-method=normal','--skip-test-db','--tmpdir=/tmp'],undefined,60000);
    sqlProcess=spawn('/usr/bin/mariadbd',['--no-defaults','--tmpdir=/tmp','--datadir='+sqlRoot,'--socket='+socket,'--pid-file='+ROOT+'/mysql.pid','--port=3306','--bind-address=127.0.0.1','--skip-name-resolve','--innodb-buffer-pool-size=64M','--log-error='+ROOT+'/mysql-error.log'],{env:ENV,stdio:'ignore'});
    let ready=false;for(let n=0;n<60;n++){try{await sql('SELECT 1;');ready=true;break;}catch{await pause(500);}}assert(ready,'MARIA_READY');
    const database='synthetic_'+randomBytes(10).toString('hex'),user='synthetic_'+randomBytes(8).toString('hex'),password=random();
    await sql(`CREATE DATABASE \`${database}\`; CREATE USER '${user}'@'127.0.0.1' IDENTIFIED BY '${password}'; GRANT ALL ON \`${database}\`.* TO '${user}'@'127.0.0.1';`);
    report.databaseEngine=(await sql('SELECT VERSION();')).toString().trim();
    phase='PARTICIPANT_START';polis=await participant();
    const providerValues=JSON.parse(await readFile(BOOT+'/participant-provider.json','utf8'));
    const provider=new LocalPolisProvider(providerValues);
    report.providerRequests=[];const providerRequest=provider.request.bind(provider);
    provider.request=async(path,options)=>{const started=Date.now();const route=path.split('?')[0];assert(['/api/v3/participationInit','/api/v3/nextComment','/api/v3/votes','/fncp/private/xid-allowlist/upsert','/fncp/private/xid-allowlist/readback','/fncp/private/xid-allowlist/remove'].includes(route),'TRACE_ROUTE');try{const response=await providerRequest(path,options);report.providerRequests.push({route,status:response.status,milliseconds:Date.now()-started});return response;}catch(e){report.providerRequests.push({route,status:null,milliseconds:Date.now()-started,transportFailure:true});throw e;}};
    const binding={...syntheticBinding(),conversationId:provider.conversationId,configSha256:hash(JSON.stringify(providerValues)),seedSha256:hash(await readFile('/opt/fncp/deploy/fncp/seed-statements.json'))};
    const identityKey=randomBytes(32), identity=await createSyntheticIdentityHarness({identityKey});
    const driver=createSyntheticBrowserDriver({mode:'SYNTHETIC_ONLY',identity:identity.identity,syntheticAuthorizationResponse:identity.authorizationResponse});
    let browserBinding,lastPrincipal,currentSubject;const principals=new Map();
    const wrappedDriver={mode:'SYNTHETIC_ONLY',begin(input){browserBinding=input.browserSessionId;return driver.begin(input);},async complete(input){const result=await driver.complete(input);lastPrincipal=result.principal;if(result.ok&&currentSubject)principals.set(currentSubject,result.principal);return result;},discard:input=>driver.discard(input)};
    const signer=syntheticSigningFixture(),secrets={eventSecret:random(),challengeSecret:random(),registrationSecret:random()};
    const storage={access:ROOT+'/access.sqlite',activation:ROOT+'/activation.sqlite'};
    report.clockObservation={backwardSteps:0,maxBackwardMilliseconds:0};let previousClock=Date.now();
    const observedClock=()=>{const stamp=Date.now();if(stamp<previousClock){report.clockObservation.backwardSteps++;report.clockObservation.maxBackwardMilliseconds=Math.max(report.clockObservation.maxBackwardMilliseconds,previousClock-stamp);}previousClock=stamp;return stamp;};
    const settings={now:observedClock,mode:'STRICT_LOCAL_ONLY',identity:identity.identity,oidcDriver:wrappedDriver,provider,activation:{binding,publicKey:signer.publicKey,keyId:signer.keyId},storage,eventSecret:secrets.eventSecret,ports:{access:8104,receiver:8101,browser:8100},registration:{challengeSecret:secrets.challengeSecret,registrationSecret:secrets.registrationSecret,fetch}};
    phase='STRICT_START';service=await createStrictLocalService(settings);const {origins}=await service.start();
    phase='WORDPRESS_START';wp=await createFreshContainerWordPress({database,user,password,...secrets});
    report.wordPressBefore=await wp.aggregate();
    const operator=createWordPressIdentityClient(undefined,await wp.operatorSession());
    let priorEnvelope;
    const h={client:()=>createBrowserClient(origins.browser),activate(){priorEnvelope=signer.signClaims(syntheticClaims(service.operator.activationBinding(),Math.floor(Date.now()/1000),{sequence:service.operator.nextActivationSequence(),expiresAt:Math.floor(Date.now()/1000)+1200}));return service.operator.activate(priorEnvelope);},
      async admin(action,body){try{let result;if(action==='round'){result=await service.operator.setRoundOpen(body.open);await polis.control(body.open?'open':'close');}else if(action==='invitations')result=await service.operator.issueInvitation(body.fixture);else return{status:404,body:{}};return{status:action==='invitations'?201:200,body:result};}catch(e){return{status:e.status??503,body:{}};}},
      async login(client,subject){currentSubject=subject;await client.session();assert((await client.oidcStart()).status===200,'LOGIN_START');const response=await driver.injectTestResponse({browserSessionId:browserBinding,syntheticSubject:subject,emailVerifiedByIssuer:true});assert(response.ok,'LOGIN_ISSUE');lastPrincipal=undefined;const result=await client.oidcCallback(response.callback.callbackUrl);assert(lastPrincipal&&result.status===200,'LOGIN_COMPLETE');return {result,fixture:'synthetic_i'+hash(lastPrincipal.accountId).slice(0,39)};}};
    phase='WORDPRESS_JOURNEY';
    if(process.env.FNCP_JOURNEY_NATIVE==='true'){
      h.activate();
      report.journey=await exerciseNativeWordPressJourney({origin:origins.browser,operator,
        async injectLogin(subject){assert(['synthetic_native_alice','synthetic_native_bob'].includes(subject),'NATIVE_SUBJECT');currentSubject=subject;const response=await driver.injectTestResponse({browserSessionId:browserBinding,syntheticSubject:subject,emailVerifiedByIssuer:true});assert(response.ok,'NATIVE_LOGIN');return response.callback.callbackUrl;},
        async setRoundOpen(value){const result=await h.admin('round',{open:value});assert(result.status===200,'NATIVE_ROUND');},
        async issueInvitation(registrationId,subject){assert(/^[a-f0-9-]{36}$/.test(registrationId),'NATIVE_REFERENCE');const principal=principals.get(subject);assert(principal&&identity.identity.isVerifiedPrincipal(principal),'NATIVE_PRINCIPAL');const fixture='synthetic_i'+hash(principal.accountId).slice(0,39);const registry=JSON.parse((await sql(`SELECT option_value FROM \`${database}\`.synthetic_options WHERE option_name='fncp_wp_identity_registry_v1';`)).toString().trim());assert(registry.registrations[registrationId]?.fixture===fixture,'NATIVE_ACCOUNT_BINDING');const result=await h.admin('invitations',{fixture});assert(result.status===201,'NATIVE_INVITATION');return result.body.invitationToken;}});
      report.nativeBrowser=report.journey.browserEngineTested;report.authenticationTransport=report.journey.authenticationTransport;report.checks=report.journey.checks;assert(report.journey.outcome==='PASS','NATIVE_JOURNEY');
    }else report.journey=await exerciseWordPressIdentityJourney({h,seamless:true,wordpress:()=>createWordPressIdentityClient(),operator,observer(label){report.checks.push(label);}});
    phase='INDEPENDENT_FINAL';report.wordPressAfter=await wp.aggregate();assert(report.wordPressAfter.registrations===2&&report.wordPressAfter.acknowledgedTerminalSubjects===2&&report.wordPressAfter.pendingEvents===0,'WORDPRESS_FINAL');
    report.polisSnapshot=await polis.control('snapshot');const final=report.polisSnapshot.snapshot;assert(final.open===false&&final.gated===true&&final.seedStatements===15&&final.allowlistRows===0&&final.terminalIdentities===2&&final.rawVotes===16&&final.latestVotes===16,'POLIS_FINAL');
    phase='INDEPENDENT_VOTE_ATTRIBUTION';
    const native=process.env.FNCP_JOURNEY_NATIVE==='true';
    const principal=principals.get(native?'synthetic_native_alice':'synthetic_wp_bound_alice');
    assert(principal&&identity.identity.isVerifiedPrincipal(principal),'VOTE_PRINCIPAL');
    const expected=identity.identity.participantXid(principal,provider.conversationId);assert(expected.ok,'VOTE_XID');
    const bootstrapBinding=JSON.parse(await readFile(BOOT+'/binding.json','utf8'));
    report.voteAttribution=await observeFreshJourneyVote({...bootstrapBinding,expectedXid:expected.xid,expectedVote:native?-1:0});
    phase='QUIESCE';await service.close();service=undefined;report.wordpressQuiescence=await wp.closeGuests();
    const access=new DatabaseSync(storage.access,{readOnly:true});const auth=new DatabaseSync(storage.activation,{readOnly:true});
    assert(access.prepare('SELECT count(*) n FROM sessions').get().n===0,'NO_SESSIONS');access.close();auth.close();
    phase='CLOSED_RESTART';
    await mkdir(ROOT+'/restored',{mode:0o700});for(const [role,path]of Object.entries(storage)){await copyFile(path,ROOT+'/restored/'+role+'.sqlite');const db=new DatabaseSync(ROOT+'/restored/'+role+'.sqlite',{readOnly:true});assert(db.prepare('PRAGMA integrity_check').get().integrity_check==='ok','RESTORED_INTEGRITY');db.close();}
    restored=await createStrictLocalService({...settings,storage:{access:ROOT+'/restored/access.sqlite',activation:ROOT+'/restored/activation.sqlite'}});
    const restarted=await restored.start();const denied=await fetch(restarted.origins.access+'/polis/participation-init',{redirect:'error'});assert([401,403].includes(denied.status),'RESTORED_DENIAL');
    const status=await restored.operator.status();assert(status.open===false,'RESTORED_CLOSED');let replayDenied=false;try{const replay=restored.operator.activate(priorEnvelope);replayDenied=replay?.ok===false;}catch{replayDenied=true;}assert(replayDenied,'ACTIVATION_REPLAY');report.closedRestart={passed:true,integrityChecked:true,priorActivationDenied:true,oldSessions:0,unauthenticatedStatus:denied.status};
    await restored.close();restored=undefined;
    phase='WORDPRESS_BACKUP_RESTORE';await wp.close();
    const dumpArgs=['--no-defaults','--socket='+socket,'-uroot','--single-transaction','--skip-comments','--skip-add-drop-table','--order-by-primary','--hex-blob'];
    const dump=await command('/usr/bin/mariadb-dump',[...dumpArgs,database],undefined,30000);
    const restoreDatabase='restored_'+randomBytes(10).toString('hex');await sql(`CREATE DATABASE \`${restoreDatabase}\`;`);
    await command('/usr/bin/mariadb',['--no-defaults','--socket='+socket,'-uroot',restoreDatabase],dump,30000);
    const counts=await sql(`SELECT (SELECT COUNT(*) FROM \`${database}\`.synthetic_options)=(SELECT COUNT(*) FROM \`${restoreDatabase}\`.synthetic_options), (SELECT COUNT(*) FROM \`${database}\`.synthetic_users)=(SELECT COUNT(*) FROM \`${restoreDatabase}\`.synthetic_users);`);
    assert(counts.toString().trim()==='1\t1','RESTORE_COUNTS');const restoredDump=await command('/usr/bin/mariadb-dump',[...dumpArgs,restoreDatabase],undefined,30000);assert(dump.equals(restoredDump),'RESTORE_CONTENT');report.wordpressBackupRestore={bytes:dump.length,sha256:hash(dump),tableCountsMatch:true,completeLogicalDumpMatch:true};
    phase='COMPLETE';report.outcome='PASS';
  }catch(e){report.failurePhase=phase;if(/^(WP journey: )[A-Za-z0-9 :,-]{1,180}$/.test(e.message??''))report.failedCheck=e.message;}
  finally{
    const results=await Promise.allSettled([Promise.resolve().then(()=>restored?.close()),Promise.resolve().then(()=>service?.close()),Promise.resolve().then(()=>wp?.close()),Promise.resolve().then(()=>polis?.close())]);
    await stopped(sqlProcess);report.mariaExitVerified=!!sqlProcess&&sqlProcess.exitCode===0&&sqlProcess.signalCode===null;closed=results.every(r=>r.status==='fulfilled')&&report.mariaExitVerified;
    report.localProcessesClosed=closed;report.portsRefused={};for(const port of [3306,5500,8100,8101,8103,8104])report.portsRefused[port]=await refusal(port);
    if(!closed||!Object.values(report.portsRefused).every(Boolean))report.outcome='FAIL';
    report.finishedAt=new Date().toISOString();await writeFile(ROOT+'/aggregate.json',JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});
  }
  process.stdout.write(JSON.stringify(report)+'\n');process.exitCode=report.outcome==='PASS'?0:1;
}
main().catch(()=>{process.stdout.write(JSON.stringify({outcome:'FAIL',failurePhase:'FINALIZATION'})+'\n');process.exitCode=1;});
