import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync } from 'node:fs';
import { join } from 'node:path';
import { createHmac,randomUUID } from 'node:crypto';
import { request } from 'node:https';
import { createProductionFixture } from './test-support/production-fixture.mjs';
import { serviceFixture } from './test-support/service-fixture.mjs';
import { isProductionAccess } from './access.mjs';
import { startProductionOperator,requestProductionOperator } from './operator.mjs';
import { canonical } from './contracts.mjs';
const fixture=createProductionFixture;
async function admitted(t){const h=await fixture(t),p=await h.principal();await h.register(p);h.activate();await h.approve(p);const invitation=await h.invite(p);const grant=await h.access.redeem(p,invitation.invitationToken);return{h,p,grant,invitation};}
function gate(){let enter,release;const entered=new Promise(r=>enter=r),blocked=new Promise(r=>release=r);return{entered,release,async wait(){enter();await blocked;}};}

async function deliverServiceEvent(x,event){
  const raw=canonical(event),timestamp=String(Math.floor(Date.now()/1000));
  const signature=createHmac('sha256',Buffer.from(x.h.eventKey,'base64url')).update('FNCP_WP_EVENT_V1\n'+timestamp+'.'+raw).digest('hex');
  return new Promise((resolve,reject)=>{
    const req=request({hostname:'127.0.0.1',port:x.receiverPort,path:'/internal/wordpress/events',method:'POST',agent:false,
      ca:x.receiverTls.cert,rejectUnauthorized:true,minVersion:'TLSv1.2',headers:{'content-type':'application/json','content-length':Buffer.byteLength(raw),
        'x-fncp-timestamp':timestamp,'x-fncp-event-id':event.eventId,'x-fncp-signature':'sha256='+signature}},res=>{
      let text='';res.on('data',chunk=>{text+=chunk;if(text.length>4096)req.destroy(Error('test ACK too large'));});res.once('error',reject);
      res.once('end',()=>{try{resolve({status:res.statusCode,body:JSON.parse(text)});}catch{reject(Error('invalid test ACK'));}});
    });req.setTimeout(3000,()=>req.destroy(Error('test receiver deadline')));req.once('error',reject);req.end(raw);
  });
}

test('actual production identity, private HTTPS contracts and SQLite approval compose into narrow voting capability',async t=>{const {h,p,grant}=await admitted(t);assert.equal(isProductionAccess(h.access),true);assert.equal(isProductionAccess({...h.access}),false);assert.equal(Object.isFrozen(grant),true);assert.deepEqual(JSON.stringify(grant),'{}');
  const s=await h.access.participate(p,grant,'init');assert.deepEqual(s,{statement:{tid:0,text:h.configuration.statements[0]},complete:false});const v=await h.access.participate(p,grant,'vote',{tid:0,vote:1});assert.deepEqual(v,s);assert.equal(h.votes.length,1);assert.doesNotMatch(JSON.stringify(v),/acct_|fncp_|SENSITIVE|currentPid|auth|xid/);});

test('login, declarations and operator approval remain separate; copying principals or grants cannot create access',async t=>{const h=await fixture(t),p=await h.principal();assert.deepEqual(await h.access.status(p),{authenticated:true,registrationState:'unregistered',registrationReference:null,participantAccessGranted:false,roundOpen:false});await assert.rejects(h.access.redeem(p,'A'.repeat(43)));await assert.rejects(h.access.register(p,{consentVersion:h.configuration.consentVersion,adultSelfAttested:true,eligibilitySelfAttested:false,registrationConsent:true}));assert.equal(h.records.size,0);await h.register(p);assert.equal((await h.access.status(p)).registrationState,'pending');await assert.rejects(h.invite(p));await assert.rejects(h.access.authenticate(Object.freeze({...p})));});

test('rightful registration status exposes only its immutable reference and private issuance waits for approval',async t=>{
  const h=await fixture(t),p=await h.principal();const registered=await h.register(p),reference=h.records.get(p.accountId).registrationId;
  assert.equal(registered.registrationReference,reference);
  assert.doesNotMatch(JSON.stringify(registered),/acct_|fncp_|invented-subject|invented@example|"xid"|token/u);
  const calls=h.calls.length;
  for(const invalid of [undefined,null,1,{},p.accountId,'not-a-uuid',reference.toUpperCase(),randomUUID()])await assert.rejects(h.access.operator.issueInvitationForRegistration(invalid));
  assert.equal(h.calls.length,calls);
  h.activate();await assert.rejects(h.access.operator.issueInvitationForRegistration(reference));
  await h.approve(p);const invitation=await h.access.operator.issueInvitationForRegistration(reference);
  assert.deepEqual(Object.keys(invitation).sort(),['delivery','expiresAt','invitationToken']);
  assert.equal(invitation.delivery,'PRIVATE_OPERATOR_RESPONSE_ONLY');
  assert.ok(invitation.expiresAt>h.now()&&invitation.expiresAt<=h.now()+600_000);
  assert.ok(invitation.expiresAt<=h.identity.principalDeadline(p));
  assert.doesNotMatch(JSON.stringify(invitation),/acct_|fncp_|registrationId|invented@example|"xid"/u);
  const grant=await h.access.redeem(p,invitation.invitationToken);await h.access.participate(p,grant,'vote',{tid:0,vote:-1});assert.equal(h.votes.length,1);
});

test('reference-bound reissue invalidates old codes and forwarded codes do not consume rightful redemption',async t=>{
  const h=await fixture(t),p=await h.principal(),other=await h.principal('invented-invitation-other');
  await h.register(p);await h.register(other);h.activate();await h.approve(p);await h.approve(other);
  const reference=h.records.get(p.accountId).registrationId;
  const old=await h.access.operator.issueInvitationForRegistration(reference),fresh=await h.access.operator.issueInvitationForRegistration(reference);
  assert.notEqual(old.invitationToken,fresh.invitationToken);await assert.rejects(h.access.redeem(p,old.invitationToken));
  await assert.rejects(h.access.redeem(other,fresh.invitationToken));
  const grant=await h.access.redeem(p,fresh.invitationToken);await assert.rejects(h.access.redeem(p,fresh.invitationToken));
  await h.access.participate(p,grant,'vote',{tid:0,vote:1});assert.equal(h.votes.length,1);
});

test('registration reference cannot replace current sign-in and new sign-in consumes an outstanding code',async t=>{
  const h=await fixture(t),p=await h.principal();await h.register(p);h.activate();await h.approve(p);
  const reference=h.records.get(p.accountId).registrationId,old=await h.access.operator.issueInvitationForRegistration(reference);
  await h.access.logout(p);await assert.rejects(h.access.operator.issueInvitationForRegistration(reference));
  const fresh=await h.principal();assert.equal(fresh.accountId,p.accountId);
  assert.equal((await h.access.status(fresh)).registrationReference,reference);
  await assert.rejects(h.access.redeem(fresh,old.invitationToken));
  const invitation=await h.access.operator.issueInvitationForRegistration(reference);await h.access.redeem(fresh,invitation.invitationToken);
  assert.equal(h.records.size,1);
});

test('reference issuance denies closed admission, expired identity and terminal revocation',async t=>{
  const h=await fixture(t),p=await h.principal();await h.register(p);h.activate();await h.approve(p);
  const reference=h.records.get(p.accountId).registrationId;
  h.access.closeAdmission();await assert.rejects(h.access.operator.issueInvitationForRegistration(reference));
  h.activate();const invitation=await h.access.operator.issueInvitationForRegistration(reference);
  h.advance(300_000);await assert.rejects(h.access.operator.issueInvitationForRegistration(reference));await assert.rejects(h.access.redeem(p,invitation.invitationToken));
  const fresh=await h.principal();h.activate();await h.revoke(fresh);await assert.rejects(h.access.operator.issueInvitationForRegistration(reference));
  assert.equal(h.votes.length,0);
});

for(const fault of ['wpDown','wrongNonce'])test(`reference issuance requires a fresh authenticated WordPress response (${fault})`,async t=>{
  const h=await fixture(t),p=await h.principal();await h.register(p);h.activate();await h.approve(p);
  const reference=h.records.get(p.accountId).registrationId;h.behavior[fault]=true;
  await assert.rejects(h.access.operator.issueInvitationForRegistration(reference));
  assert.equal(h.access.operator.status().roundOpen,false);h.behavior[fault]=false;
  await assert.rejects(h.access.operator.issueInvitationForRegistration(reference));assert.equal(h.votes.length,0);
});

test('revocation during reference issuance readback withholds any invitation',async t=>{
  const h=await fixture(t),p=await h.principal();await h.register(p);h.activate();await h.approve(p);
  const reference=h.records.get(p.accountId).registrationId,g=gate();t.after(g.release);
  h.behavior.wpGate=action=>action==='status'?g.wait():undefined;
  const issuing=h.access.operator.issueInvitationForRegistration(reference);await g.entered;h.event(p,'revoked');g.release();
  await assert.rejects(issuing);h.behavior.wpGate=undefined;
  await assert.rejects(h.access.operator.issueInvitationForRegistration(reference));assert.equal(h.votes.length,0);
});

test('private socket resolves the displayed registration reference through signed WordPress approval into BFF redemption',async t=>{
  const x=await serviceFixture(t),service=await x.create();await service.start();const operator=await startProductionOperator(service);
  try{
    const client=x.client();await client.login();
    const registered=await client.call('/registration',{consentVersion:x.manifest.content.consentVersion,adultSelfAttested:true,eligibilitySelfAttested:true,registrationConsent:true});
    assert.equal(registered.status,200);assert.equal(registered.body.registrationState,'pending');
    const reference=registered.body.registrationReference,accountId=[...x.h.records.keys()][0];assert.equal(x.h.records.size,1);
    assert.equal(reference,x.h.records.get(accountId).registrationId);
    service.operator.activate(x.envelope(service));service.operator.admit();
    const event=x.h.event({accountId},'approved'),ack=await deliverServiceEvent(x,event);
    assert.equal(ack.status,200);assert.deepEqual(ack.body,{ok:true,eventId:event.eventId,version:1});
    const status=await client.call('/session');assert.equal(status.body.registrationState,'approved');assert.equal(status.body.registrationReference,reference);
    const invitation=await requestProductionOperator({stateDirectory:x.stateDirectory,command:'invitation-for-registration',payload:{registrationId:reference}});
    assert.deepEqual(Object.keys(invitation).sort(),['delivery','expiresAt','invitationToken']);assert.equal(invitation.delivery,'PRIVATE_OPERATOR_RESPONSE_ONLY');
    assert.doesNotMatch(JSON.stringify(invitation),/acct_|fncp_|registration|email|"xid"/u);
    const redeemed=await client.call('/invitations/redeem',{invitationToken:invitation.invitationToken});assert.equal(redeemed.status,200);assert.equal(redeemed.body.participationSession,true);
    assert.ok(!JSON.stringify(redeemed.body).includes(invitation.invitationToken));
    assert.equal((await client.call('/polis/participation-init')).status,200);
    assert.equal((await client.call('/polis/votes',{tid:0,vote:-1})).status,200);assert.equal(x.h.votes.length,1);
  }finally{await operator.close();await service.close();}
});

test('forwarded invitation denies without consuming rightful use, and simultaneous redemption succeeds once',async t=>{const h=await fixture(t),p=await h.principal(),other=await h.principal('invented-second');await h.register(p);await h.register(other);h.activate();await h.approve(p);await h.approve(other);const i=await h.invite(p);await assert.rejects(h.access.redeem(other,i.invitationToken));const r=await Promise.allSettled([h.access.redeem(p,i.invitationToken),h.access.redeem(p,i.invitationToken)]);assert.equal(r.filter(x=>x.status==='fulfilled').length,1);const g=r.find(x=>x.status==='fulfilled').value;await assert.rejects(h.access.participate(p,Object.freeze({...g}),'vote',{tid:0,vote:1}));assert.equal(h.votes.length,0);});

test('twenty lifetime registrations including revoked identities; concurrent last-slot admission remains bounded',async t=>{const h=await fixture(t);const people=[];for(let i=0;i<21;i++)people.push(await h.principal('invented-person-'+i));for(const p of people.slice(0,19))await h.register(p);const results=await Promise.allSettled(people.slice(19).map(p=>h.register(p)));assert.equal(results.filter(x=>x.status==='fulfilled').length,1);assert.equal(h.records.size,20);await h.revoke(people[0]);await assert.rejects(h.register(people[20]));assert.equal(h.access.operator.status().registrations,20);});

test('revocation persists denial before queued removal and survives provider failure and restart',async t=>{const {h,p,grant,invitation}=await admitted(t);h.behavior.providerDown=true;const e=h.event(p,'revoked');await assert.rejects(h.access.ingestWordPressEvent(e));await assert.rejects(h.access.participate(p,grant,'vote',{tid:0,vote:1}));assert.equal(h.votes.length,0);h.behavior.providerDown=false;await h.restart();const reauth=await h.issuer.authenticate({claims:{sub:'invented-subject'}},h.identity);assert.equal(reauth.ok,true);assert.equal(reauth.principal.accountId,p.accountId);await assert.rejects(h.access.authenticate(reauth.principal));await assert.rejects(h.access.redeem(p,invitation.invitationToken));const ack=await h.access.ingestWordPressEvent(e);assert.equal(ack.eventId,e.eventId);assert.equal([...h.allowlist.values()][0],2);});

test('stale approved event cannot undo terminal tombstone and event identity conflicts are rejected',async t=>{const h=await fixture(t),p=await h.principal();await h.register(p);h.activate();const {event:approved}=await h.approve(p);const {event:revoked}=await h.revoke(p);const ack=await h.access.ingestWordPressEvent(approved);assert.equal(ack.eventId,approved.eventId);await assert.rejects(h.access.ingestWordPressEvent({...revoked,eventId:randomUUID()}));assert.equal([...h.allowlist.values()][0],2);});

test('fresh WordPress readback denies undelivered revocation before any vote',async t=>{const {h,p,grant}=await admitted(t);h.event(p,'revoked');await assert.rejects(h.access.participate(p,grant,'vote',{tid:0,vote:-1}));assert.equal(h.votes.length,0);});

test('WordPress outage closes admission and cannot use cached approval',async t=>{const {h,p,grant}=await admitted(t);h.behavior.wpDown=true;await assert.rejects(h.access.participate(p,grant,'vote',{tid:0,vote:1}));h.behavior.wpDown=false;await assert.rejects(h.access.participate(p,grant,'vote',{tid:0,vote:1}));assert.equal(h.votes.length,0);assert.equal(h.access.operator.status().roundOpen,false);});

test('expired identity during provider wait withholds result and never blindly retries a possible vote',async t=>{const {h,p,grant}=await admitted(t);const g=gate();h.behavior.providerGate=op=>op==='votes'?g.wait():undefined;const pending=h.access.participate(p,grant,'vote',{tid:0,vote:1});await g.entered;h.advance(16*60_000);g.release();await assert.rejects(pending);assert.equal(h.votes.length,1);});

test('terminal event arriving during provider wait invalidates result before removal waits in queue',async t=>{const {h,p,grant}=await admitted(t);const g=gate();h.behavior.providerGate=op=>op==='votes'?g.wait():undefined;const voting=h.access.participate(p,grant,'vote',{tid:0,vote:1});await g.entered;const revoking=h.access.ingestWordPressEvent(h.event(p,'revoked'));g.release();await assert.rejects(voting);await revoking;assert.equal(h.votes.length,1);await assert.rejects(h.access.participate(p,grant,'vote',{tid:1,vote:1}));assert.equal(h.votes.length,1);});

test('lost registration response retries original immutable receipt instead of enrolling twice',async t=>{const h=await fixture(t),p=await h.principal();h.behavior.registrationResponseLost=true;await assert.rejects(h.register(p));assert.equal(h.records.size,1);h.advance(65_000);h.behavior.registrationResponseLost=false;await h.register(p);assert.equal(h.records.size,1);assert.equal((await h.access.status(p)).registrationState,'pending');});

test('restart starts closed, consumes invitations, invalidates principal and capability continuity',async t=>{const {h,p,grant,invitation}=await admitted(t);await h.restart();assert.equal(h.access.operator.status().roundOpen,false);await assert.rejects(h.access.authenticate(p));const fresh=await h.principal();await assert.rejects(h.access.redeem(fresh,invitation.invitationToken));await assert.rejects(h.access.participate(fresh,grant,'vote',{tid:0,vote:1}));assert.equal(h.votes.length,0);});

for(const kind of ['clock','storage'])test(`${kind} fault remains closed after apparent repair`,async t=>{const {h,p,grant}=await admitted(t);const saved=h.now();if(kind==='clock')h.setTime(saved-1);else chmodSync(join(h.directory,'access.sqlite'),0o644);await assert.rejects(h.access.participate(p,grant,'next'));if(kind==='clock')h.setTime(saved);else chmodSync(join(h.directory,'access.sqlite'),0o600);await assert.rejects(h.access.participate(p,grant,'next'));await assert.rejects(h.access.authenticate(p));});

test('unreviewed statement text is withheld and bad TIDs never reach provider',async t=>{const {h,p,grant}=await admitted(t);await assert.rejects(h.access.participate(p,grant,'vote',{tid:15,vote:1}));assert.equal(h.votes.length,0);h.behavior.badStatement=true;await assert.rejects(h.access.participate(p,grant,'next'));assert.equal(h.access.operator.status().roundOpen,false);});


test('an expired never-committed registration recovers only after fresh WordPress absence',async t=>{const h=await fixture(t),p=await h.principal();h.behavior.wpDown=true;await assert.rejects(h.register(p));assert.equal(h.records.size,0);assert.equal(h.access.operator.status().registrations,1);h.advance(65_000);h.behavior.wpDown=false;await h.register(p);assert.equal(h.records.size,1);assert.equal(h.access.operator.status().registrations,1);assert.equal((await h.access.status(p)).registrationState,'pending');await h.restart();assert.equal(h.access.operator.status().registrations,1);});

test('expired uncertain registration reconciles signed current account without granting approval',async t=>{const h=await fixture(t),p=await h.principal();h.behavior.registrationResponseLost=true;await assert.rejects(h.register(p));h.advance(65_000);await h.register(p);assert.equal(h.records.size,1);assert.equal((await h.access.status(p)).registrationState,'pending');await assert.rejects(h.invite(p));});


test('status distinguishes a reserved unconfirmed attempt and reconciles a lost committed response without resubmission',async t=>{const h=await fixture(t),p=await h.principal();h.behavior.wpDown=true;await assert.rejects(h.register(p));h.behavior.wpDown=false;assert.equal((await h.access.status(p)).registrationState,'unconfirmed');h.behavior.registrationResponseLost=true;await assert.rejects(h.register(p));const before=h.calls.filter(c=>c.action==='register').length;assert.equal((await h.access.status(p)).registrationState,'pending');assert.equal(h.calls.filter(c=>c.action==='register').length,before);});
