// Privileged, invented-cohort QA operator. Calls the normal BFF/native WP and
// normal private IPC only; it never constructs a service/access capability.
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {lstatSync,readFileSync,writeFileSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import {createQaHttpsClient} from './transport.mjs';
import {signProductionActivation} from './offline-sign.mjs';

const PARTICIPANT='https://pulse.synthetic.invalid',WP='https://wordpress:8443',STATE='/var/lib/fncp';
const privatePattern=/acct_[A-Za-z0-9_-]+|fncp_[A-Za-z0-9_-]{43}|invented-normal-(?:alice|bob)|@example\.invalid|access_token|refresh_token|id_token|"(?:xid|pid|uid)"/u;
export function createMainQaActor(c,operator,progress=()=>{}){
  const fixture=JSON.parse(readFileSync(new URL('./dedicated-analysis.json',import.meta.url),'utf8'));assert.equal(fixture.participantCount,18);assert.equal(fixture.statementCount,15);assert.equal(fixture.cohortSize,6);assert.equal(fixture.profiles.length,3);assert.ok(fixture.profiles.every(p=>p.length===15&&p.every(v=>[-1,1].includes(v))));const expectedVotes=[];
  const clients=[],checks=[];let stage='waiting',proved=false,closedAdmission=false,alice,bob,aliceRow,bobRow,held,oldEnvelope;
  const check=(name,value)=>{assert.equal(value,true,name);checks.push(name);};
  const ipc=(command,payload)=>operator({stateDirectory:STATE,command,...(payload===undefined?{}:{payload})});
  const privateFile=(name,value)=>{assert.match(name,/^[a-z-]+\.json$/u);writeFileSync('/run/qa/'+name,JSON.stringify(value),{mode:0o600,flag:'wx'});};
  const rows=()=>{const s=lstatSync(STATE+'/access.sqlite');assert.ok(s.isFile()&&!s.isSymbolicLink()&&s.uid===1000&&(s.mode&0o777)===0o600);const db=new DatabaseSync(STATE+'/access.sqlite',{readOnly:true});try{db.exec('PRAGMA query_only=ON; PRAGMA busy_timeout=2000; BEGIN');const value=db.prepare('SELECT account_id,xid,registration_id,state,provider_state,event_version FROM accounts ORDER BY account_id LIMIT 21').all();assert.ok(value.length<=20);db.exec('ROLLBACK');return value;}finally{db.close();}};
  const client=(origin,ca,participant=false)=>{const x=createQaHttpsClient(origin,ca,{participant});clients.push(x);return x;};
  const safe=response=>{assert.doesNotMatch(response.text,privatePattern);return response;};
  async function login(subject){
    const x=client(PARTICIPANT,c.edgeCa,true);check('BFF initial session uses verified native TLS '+subject,safe(await x.call('/session')).status===200);
    const anonymous=x.privateSession().cookies['__Host-fncp-session'];const begun=await x.call('/oidc/login',{method:'POST',json:{}});assert.equal(begun.status,200);
    check('transaction cookie is secure HttpOnly Lax '+subject,(begun.headers['set-cookie']??[]).some(v=>/^__Host-fncp-transaction=/u.test(v)&&/; Path=\/; Secure; HttpOnly; SameSite=Lax;/u.test(v)&&!v.includes('Domain=')));
    const url=new URL(begun.body.authorizationUrl);assert.equal(url.origin,c.issuer.origin);const idp=client(c.issuer.origin,c.issuerCa);
    const auth=await idp.call(url.pathname+url.search,{headers:{'x-fncp-qa-owner':c.issuer.ownerKey,'x-fncp-qa-subject':'invented-normal-'+subject}});assert.equal(auth.status,303);
    const callback=new URL(auth.headers.location);assert.equal(callback.origin,PARTICIPANT);assert.equal(callback.pathname,'/oidc/callback');
    const done=await x.call(callback.pathname+callback.search,{headers:{'sec-fetch-site':'cross-site','sec-fetch-mode':'navigate','sec-fetch-dest':'document','sec-fetch-user':'?1'}});assert.equal(done.status,303);assert.equal(done.headers.location,'/');
    check('callback rotates secure strict session and clears transaction '+subject,(done.headers['set-cookie']??[]).some(v=>/^__Host-fncp-session=/u.test(v)&&/; Path=\/; Secure; HttpOnly; SameSite=Strict;/u.test(v))&&x.privateSession().cookies['__Host-fncp-session']!==anonymous&&!x.privateSession().cookies['__Host-fncp-transaction']);
    const session=safe(await x.call('/session'));check('native BFF authenticated identity remains private '+subject,session.status===200&&session.body.authenticated===true&&session.body.participantAccessGranted===false);
    return {x,session};
  }
  async function register(subject){
    const before=rows(),{x,session}=await login(subject);assert.equal(session.body.registrationState,'unregistered');const notice=session.body.registrationNotice;
    for(const k of ['adultDeclaration','eligibilityDeclaration','registrationDeclaration'])assert.ok(typeof notice[k]==='string'&&notice[k].length>0);
    const r=safe(await x.call('/registration',{method:'POST',json:{consentVersion:notice.consentVersion,adultSelfAttested:true,eligibilitySelfAttested:true,registrationConsent:true}}));
    check('three declarations create actual WordPress pending registration '+subject,r.status===200&&r.body.registrationState==='pending'&&r.body.participantAccessGranted===false);
    const after=rows(),fresh=after.filter(row=>!before.some(old=>old.account_id===row.account_id));assert.equal(after.length,before.length+1);assert.equal(fresh.length,1);assert.ok(fresh[0].registration_id);return {x,row:fresh[0]};
  }
  function wpClient(){const x=client(WP,c.wordpressCa);return {...x,async login(user,password){
    const page=await x.call('/wp-login.php');check('normal WordPress executes PHP over verified HTTPS '+user,page.status===200&&/name="log"/u.test(page.text)&&!page.text.includes('<?php'));
    const r=await x.call('/wp-login.php',{method:'POST',form:{log:user,pwd:password,'wp-submit':'Log In',redirect_to:WP+'/wp-admin/tools.php?page=fncp-production-registration',testcookie:'1'}});
    check('normal native WordPress staff login '+user,[302,303].includes(r.status)&&(r.headers['set-cookie']??[]).some(v=>/wordpress_sec_/u.test(v)&&/secure/iu.test(v)&&/httponly/iu.test(v)));},
    async nonce(action){const r=await x.call('/wp-admin/tools.php?page=fncp-production-registration');assert.equal(r.status,200);const form=(r.text.match(/<form\b[^>]*>[\s\S]*?<\/form>/gu)??[]).find(f=>f.includes(`name="action" value="${action}"`));const value=form?.match(/name="_fncp_nonce" value="([A-Za-z0-9]+)"/u)?.[1];assert.ok(value);return value;},
    async decide(row,state,nonce){return x.call('/wp-admin/admin-post.php',{method:'POST',form:{action:'fncp_production_decide',_fncp_nonce:nonce??await this.nonce('fncp_production_decide'),registration_id:row.registration_id,state}});},
    async retry(){return x.call('/wp-admin/admin-post.php',{method:'POST',form:{action:'fncp_production_retry',_fncp_nonce:await this.nonce('fncp_production_retry')}});}};}
  async function prove(){
    assert.equal(proved,false);proved=true;stage='normal-startup';const before=await ipc('status');check('fresh joined main starts admission closed',before.roundOpen===false&&before.registrations===0&&before.browser.listenerOpen===true&&before.receiver.listenerOpen===true);assert.equal(rows().length,0);
    stage='anonymous-edge-controls';const outsider=client(PARTICIPANT,c.edgeCa,true);
    for(const route of ['/api/v3/participants','/wp-admin/','/events','/operator','/health'])check('edge refuses anonymous private route '+route,(await outsider.call(route)).status===404);
    for(const headers of [{host:'attacker.example.invalid'},{authorization:'Bearer invented'},{'x-fncp-principal':'invented'},{'x-forwarded-principal':'invented'},{cookie:'unknown_edge_cookie=invented'}])check('edge rejects anonymous authority or unknown cookie '+Object.keys(headers)[0],(await outsider.call('/session',{headers})).status===403);
    const metadata=safe(await outsider.call('/session',{headers:{forwarded:'for=203.0.113.1;host=attacker.example.invalid;proto=http','x-forwarded-host':'attacker.example.invalid','x-forwarded-proto':'http'}}));check('spoofed forwarding metadata grants no authentication',metadata.status===200&&metadata.body.authenticated===false&&metadata.body.participantAccessGranted===false);
    check('anonymous edge voting remains closed',(await outsider.call('/polis/participation-init')).status!==200);
    stage='native-registration';({x:alice,row:aliceRow}=await register('alice'));({x:bob,row:bobRow}=await register('bob'));
    stage='native-staff-controls';const admin=wpClient(),anonymousStaff=wpClient();await admin.login('qa_operator',c.operatorPassword);
    check('anonymous staff cannot view administration',(await anonymousStaff.call('/wp-admin/tools.php?page=fncp-production-registration')).status!==200);
    check('anonymous staff cannot decide',(await anonymousStaff.decide(aliceRow,'approved','invalid')).status!==200);
    check('native bad nonce cannot approve',(await admin.decide(aliceRow,'approved','invalid')).status===403);
    check('rejected staff writes leave both registrations pending',rows().every(r=>r.state==='pending'&&r.event_version===0));
    stage='durable-outbox';const pending=await admin.decide(aliceRow,'approved');check('closed normal activation leaves native delivery pending',pending.status===200&&pending.body?.outcome==='PENDING');
    check('pending receiver delivery cannot approve local account',rows().every(r=>r.state==='pending'));
    stage='actual-bound-activation';const challenge=await ipc('challenge');for(const key of Object.keys(c.expectedBinding))assert.deepEqual(challenge.binding[key],c.expectedBinding[key]);const activationVersion=Object.hasOwn(c.expectedBinding,'operatorAccessSha256')?3:2,expectedImages=activationVersion===3?10:9;check('operator challenge binds every actual runtime image and reviewed activation domain',Object.keys(challenge.binding.images).length===expectedImages&&Object.hasOwn(challenge.binding.images,'edge')&&(activationVersion!==3||Object.hasOwn(challenge.binding.images,'operator'))&&challenge.purpose==='FNCP_PRODUCTION_ACTIVATION_V'+activationVersion);
    const now=Math.floor(Date.now()/1000);oldEnvelope=signProductionActivation({challenge,privateKey:c.activationPrivateKey,activationId:randomUUID(),issuedAt:now,notBefore:now,expiresAt:now+1200});await ipc('activate',oldEnvelope);await ipc('admit');check('normal private operator opens only after valid envelope',(await ipc('status')).roundOpen===true);
    stage='native-approval-retry';const retried=await admin.retry();check('native nonce retry ACKs normal signed event receiver',retried.status===200&&retried.body?.outcome==='ACKNOWLEDGED');
    const approved=await admin.decide(bobRow,'approved');check('second native approval ACKs normal receiver',approved.status===200&&approved.body?.outcome==='ACKNOWLEDGED');
    for(const x of [alice,bob]){const s=safe(await x.call('/session'));check('approved status retains private account mapping',s.status===200&&s.body.registrationState==='approved'&&s.body.participantAccessGranted===false);}
    check('both native grants are durable and provider-confirmed',rows().every(r=>r.state==='approved'&&r.provider_state==='approved'));
    stage='account-bound-invitation';const invitation=await ipc('invitation',{accountId:aliceRow.account_id});
    check('forwarded invitation denied for other authenticated account',safe(await bob.call('/invitations/redeem',{method:'POST',json:{invitationToken:invitation.invitationToken}})).status!==200);
    const beforeCookie=alice.privateSession().cookies['__Host-fncp-session'];const redeemed=safe(await alice.call('/invitations/redeem',{method:'POST',json:{invitationToken:invitation.invitationToken}}));check('rightful browser redemption rotates private grant session',redeemed.status===200&&redeemed.body.participationSession===true&&alice.privateSession().cookies['__Host-fncp-session']!==beforeCookie);
    async function voteAll(x,row,index){
      stage='native-vote-batch-'+String(index).padStart(2,'0');let response=safe(await x.call('/polis/participation-init'));assert.equal(response.status,200);const seen=new Set(),profile=fixture.profiles[Math.floor(index/fixture.cohortSize)];
      for(let n=0;n<15;n++){
        const statement=response.body.statement;assert.ok(statement!==null&&Number.isSafeInteger(statement.tid)&&statement.tid>=0&&statement.tid<15&&!seen.has(statement.tid));assert.equal(statement.text,`Invented test statement ${statement.tid+1}.`);assert.equal(response.body.complete,false);
        // A failed or uncertain request ends the entire attempt. No vote retry.
        response=safe(await x.call('/polis/votes',{method:'POST',json:{tid:statement.tid,vote:profile[statement.tid]}}));assert.equal(response.status,200);assert.equal(typeof response.body.complete,'boolean');seen.add(statement.tid);
      }
      assert.equal(seen.size,15);check('participant completes all15 actual reviewed native votes '+String(index).padStart(2,'0'),response.body.complete===true&&response.body.statement===null);
      expectedVotes.push({participantXid:row.xid,expectedVotes:[...profile]});progress({completedParticipants:expectedVotes.length,confirmedVoteResponses:expectedVotes.length*15});
    }
    await voteAll(alice,aliceRow,0);
    const bobInvitation=await ipc('invitation',{accountId:bobRow.account_id});const bobRedeem=safe(await bob.call('/invitations/redeem',{method:'POST',json:{invitationToken:bobInvitation.invitationToken}}));assert.equal(bobRedeem.status,200);await voteAll(bob,bobRow,1);
    held={alice:alice.privateSession(),bob:bob.privateSession(),consumedInvitation:invitation.invitationToken,oldEnvelope,capturedAt:Date.now()};
    stage='terminal-revocation';const revoked=await admin.decide(aliceRow,'revoked');check('native terminal revocation ACKs normal receiver',revoked.status===200&&revoked.body?.outcome==='ACKNOWLEDGED');
    check('revoked browser grant cannot fetch another statement',safe(await alice.call('/polis/next-comment')).status!==200);
    check('terminal native registration cannot be reapproved',(await admin.decide(aliceRow,'approved')).status!==200);
    for(let i=2;i<18;i++){
      stage='native-additional-registration-'+String(i).padStart(2,'0');const {x,row}=await register('extra-'+String(i).padStart(2,'0'));
      const approval=await admin.decide(row,'approved');assert.equal(approval.status,200);assert.equal(approval.body?.outcome,'ACKNOWLEDGED');
      const status=safe(await x.call('/session'));assert.equal(status.status,200);assert.equal(status.body.registrationState,'approved');
      const invite=await ipc('invitation',{accountId:row.account_id});const redeem=safe(await x.call('/invitations/redeem',{method:'POST',json:{invitationToken:invite.invitationToken}}));assert.equal(redeem.status,200);await voteAll(x,row,i);
    }
    const final=rows();check('recovery cohort retains one revoked and17 approved accounts',final.length===18&&final.filter(r=>r.state==='revoked'&&r.provider_state==='removed').length===1&&final.filter(r=>r.state==='approved'&&r.provider_state==='approved').length===17);
    held.unusedInvitation=(await ipc('invitation',{accountId:bobRow.account_id})).invitationToken;
    privateFile('native-vote-expectation.json',{profile:'FNCP_NORMAL_MAIN_QA_VOTE_MATRIX_V1',conversationId:c.expectedBinding.conversationId,statementIds:Array.from({length:15},(_,i)=>i),participants:expectedVotes});
    privateFile('held-browser-state.json',held);stage='holding';return {pass:true,checks:checks.length,checkpoints:[...checks],actualNormalMain:true,actualNativeWordPress:true,actualNativePolis:true,actualPrivateOperator:true,
      ...(activationVersion===3?{actualTenImageActivationBinding:true}:{actualNineImageActivationBinding:true}),
      actualParticipantEdge:true,actualBffHttpsProtocol:true,browserEngineProof:false,identityPeer:'INVENTED_LOCAL_HTTPS_OIDC',registrations:18,revoked:1,approved:17,voteResponsesConfirmed:270,databaseVoteAttributionProven:false};
  }
  async function closeAdmission(){assert.equal(proved,true);if(closedAdmission)return {roundOpen:false};stage='close-admission';await ipc('close-admission');check('normal operator closure stops admission',(await ipc('status')).roundOpen===false);for(const x of [alice,bob])check('closed round rejects warm participant statement access',safe(await x.call('/polis/next-comment')).status!==200);const descriptor=await ipc('recovery-descriptor');privateFile('recovery-descriptor.json',descriptor);closedAdmission=true;stage='holding-closed';return {roundOpen:false,recoveryDescriptorCaptured:true};}
  return Object.freeze({prove,closeAdmission,snapshot:()=>({stage,proved,closedAdmission,checks:checks.length,requests:clients.flatMap(x=>x.observations())})});
}
