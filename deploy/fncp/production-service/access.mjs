import { ACCESS_SCHEMA as schema,ACCESS_COLUMNS as columns } from './store-schema.mjs';
import { validateExistingProductionStore } from './store-validation.mjs';
import { DatabaseSync } from 'node:sqlite';
import { randomBytes,randomUUID } from 'node:crypto';
import { openSync,closeSync,lstatSync,fstatSync,realpathSync,unlinkSync } from 'node:fs';
import { dirname,isAbsolute } from 'node:path';
import { createParticipantIdentityBoundary } from './principal-boundary.mjs';
import { isProductionIdentityAdapter } from '../production-identity/identity.mjs';
import { isProductionPolisProvider } from '../production-provider/provider.mjs';
import { isProductionActivation } from '../production-activation/authority.mjs';
import { isProductionWordPressBridge } from './wordpress-bridge.mjs';
import { ACCOUNT,XID,UUID,SHA,NAME,CONVERSATION,OPAQUE,ProductionAccessError,exact,canonical,sha,validDeclarations } from './contracts.mjs';
const instances=new WeakSet();
export const isProductionAccess=value=>instances.has(value);
const deny=(status=403,code='participation_denied')=>new ProductionAccessError(status,code);


/** One process owns this separate production store. All positive effects are
 * serialized. A signed terminal denial is persisted synchronously on arrival,
 * before it waits behind any in-flight provider operation. */
export function createProductionAccess(options){
  let c,identity,provider,activation,wordpress,boundary,now,db,dbIdentity,lockIdentity,lockFd,storePath,boundFingerprint,bootId,parentIdentity,recoveryBinding;
  try{
    exact(options,['identity','provider','activation','wordpress','storePath','configuration'],['now']);
    ({identity,provider,activation,wordpress,storePath}=options);now=options.now??Date.now;
    if(!isProductionIdentityAdapter(identity)||!isProductionPolisProvider(provider)||!isProductionActivation(activation)||!isProductionWordPressBridge(wordpress)||typeof now!=='function')throw deny();
    exact(options.configuration,['deploymentId','conversationId','consentVersion','noticeSha256','statementIds','statements','identityBindingSha256','credentialBindingSha256','notice']);c=structuredClone(options.configuration);
    if(!NAME.test(c.deploymentId)||!CONVERSATION.test(c.conversationId)||!SHA.test(c.noticeSha256)||!SHA.test(c.identityBindingSha256)||!SHA.test(c.credentialBindingSha256)||! /^[A-Za-z0-9_-]{1,128}$/u.test(c.consentVersion)
      ||!Array.isArray(c.statementIds)||c.statementIds.length!==15||new Set(c.statementIds).size!==15||c.statementIds.some((x,i)=>!Number.isSafeInteger(x)||x<0||(i>0&&x<=c.statementIds[i-1]))
      ||!Array.isArray(c.statements)||c.statements.length!==15||new Set(c.statements).size!==15||c.statements.some(x=>typeof x!=='string'||!x.trim()||x.length>3000))throw deny();
    exact(c.notice,['adultDeclaration','eligibilityDeclaration','registrationDeclaration']);
    if(Object.values(c.notice).some(x=>typeof x!=='string'||!x.trim()||x.length>3000)||sha(canonical(c.notice))!==c.noticeSha256)throw deny();
    const pb=provider.binding(),wb=wordpress.binding(),ab=activation.challenge().binding;
    if(pb.conversationId!==c.conversationId||canonical(pb.statementIds)!==canonical(c.statementIds)||wb.deploymentId!==c.deploymentId||wb.conversationId!==c.conversationId||wb.consentVersion!==c.consentVersion||wb.noticeSha256!==c.noticeSha256
      ||ab.deploymentId!==c.deploymentId||ab.conversationId!==c.conversationId||ab.providerSha256!==sha(canonical(pb))||ab.seedSha256!==sha(canonical(c.statements)))throw deny();
    boundary=createParticipantIdentityBoundary({identity,conversationId:c.conversationId});
    if(typeof storePath!=='string'||(storePath!==':memory:'&&(!isAbsolute(storePath)||!storePath.endsWith('.sqlite'))))throw deny();
    if(storePath!==':memory:'){
      const parent=dirname(storePath),p=lstatSync(parent);if(realpathSync(parent)!==parent||!p.isDirectory()||p.uid!==process.getuid()||(p.mode&0o777)!==0o700)throw deny();
      lockFd=openSync(storePath+'.writer.lock','wx',0o600);lockIdentity=fstatSync(lockFd);parentIdentity=p;const lockPath=lstatSync(storePath+'.writer.lock');if(lockPath.ino!==lockIdentity.ino||lockPath.dev!==lockIdentity.dev||lockPath.nlink!==1||lockPath.uid!==process.getuid()||(lockPath.mode&0o777)!==0o600)throw deny();
      try{closeSync(openSync(storePath,'wx',0o600));}catch(e){if(e.code!=='EEXIST')throw e;}
      dbIdentity=lstatSync(storePath);if(!dbIdentity.isFile()||dbIdentity.isSymbolicLink()||dbIdentity.nlink!==1||dbIdentity.uid!==process.getuid()||(dbIdentity.mode&0o777)!==0o600)throw deny();
    }
    db=new DatabaseSync(storePath,{timeout:1000});db.exec('PRAGMA foreign_keys=ON;PRAGMA journal_mode=DELETE;PRAGMA synchronous=FULL;PRAGMA trusted_schema=OFF;');
    const tables=db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all().map(x=>x.name);
    if(!tables.length)db.exec(schema);else if(canonical(tables)!==canonical(Object.keys(columns).sort()))throw deny();
    for(const [table,names]of Object.entries(columns))if(canonical(db.prepare(`PRAGMA table_info(${table})`).all().map(x=>x.name))!==canonical(names))throw deny();
    if(db.prepare('PRAGMA quick_check').get().quick_check!=='ok'||db.prepare('PRAGMA foreign_key_check').all().length||db.prepare('SELECT count(*) AS n FROM accounts').get().n>20||db.prepare('SELECT count(*) AS n FROM events').get().n>40)throw deny();
    const {bootId:ignoredBoot,...staticActivation}=ab;
    recoveryBinding={configuration:c,provider:pb,wordpress:wb,activation:staticActivation};
    const binding=sha(canonical(recoveryBinding));boundFingerprint=binding;bootId=randomUUID();const at=now(),old=db.prepare('SELECT * FROM meta WHERE singleton=1').get();
    validateExistingProductionStore(db,{schema,configuration:c,bindingSha:binding});
    if(!Number.isSafeInteger(at)||at<0||old&&(old.binding_sha!==binding||old.schema_version!==1||old.faulted!==0||!Number.isSafeInteger(old.last_ms)||at<old.last_ms))throw deny();
    db.exec('BEGIN IMMEDIATE');try{db.prepare('INSERT INTO meta VALUES(1,1,?,?,0,?) ON CONFLICT(singleton) DO UPDATE SET last_ms=excluded.last_ms,boot_id=excluded.boot_id').run(binding,at,bootId);db.exec('UPDATE invitations SET used=1;COMMIT');}catch(e){db.exec('ROLLBACK');throw e;}
  }catch{
    try{db?.close();}catch{}try{if(lockFd!==undefined)closeSync(lockFd);if(lockIdentity){const s=lstatSync(storePath+'.writer.lock');if(s.ino===lockIdentity.ino&&s.dev===lockIdentity.dev)unlinkSync(storePath+'.writer.lock');}}catch{}
    throw deny(503,'access_configuration_rejected');
  }
  const seed=new Map(c.statementIds.map((id,i)=>[id,c.statements[i]]));
  const principals=new Map(),grants=new WeakMap(),accountEpochs=new Map();
  let epoch=0,generation,roundOpen=false,faulted=false,closing=false,disposed=false,chain=Promise.resolve(),pending=0,closePromise;
  const account=id=>db.prepare('SELECT * FROM accounts WHERE account_id=?').get(id);
  const invalidate=id=>{accountEpochs.set(id,(accountEpochs.get(id)??0)+1);db.prepare('UPDATE invitations SET used=1 WHERE account_id=?').run(id);};
  const clearAdmission=()=>{epoch++;roundOpen=false;generation=undefined;db.exec('UPDATE invitations SET used=1');};
  const fault=()=>{faulted=true;epoch++;roundOpen=false;generation=undefined;principals.clear();try{activation.close();}catch{}try{identity.close();}catch{}try{db.prepare('UPDATE meta SET faulted=1 WHERE singleton=1').run();db.exec('UPDATE invitations SET used=1');}catch{}};
  const storage=()=>{if(storePath===':memory:')return;const s=lstatSync(storePath),l=lstatSync(storePath+'.writer.lock'),p=lstatSync(dirname(storePath));if(s.ino!==dbIdentity.ino||s.dev!==dbIdentity.dev||s.nlink!==1||s.uid!==process.getuid()||(s.mode&0o777)!==0o600||!s.isFile()||l.ino!==lockIdentity.ino||l.dev!==lockIdentity.dev||l.nlink!==1||l.uid!==process.getuid()||(l.mode&0o777)!==0o600||realpathSync(dirname(storePath))!==dirname(storePath)||p.uid!==process.getuid()||p.ino!==parentIdentity.ino||p.dev!==parentIdentity.dev||(p.mode&0o777)!==0o700)throw deny();};
  const clock=()=>{try{if(faulted||closing||disposed)throw deny();storage();const t=now(),row=db.prepare('SELECT * FROM meta WHERE singleton=1').get();if(!Number.isSafeInteger(t)||t<0||!row||row.faulted||row.schema_version!==1||row.binding_sha!==boundFingerprint||row.boot_id!==bootId||t<row.last_ms)throw deny();db.prepare('UPDATE meta SET last_ms=? WHERE singleton=1').run(t);return t;}catch{fault();throw deny(503,'access_closed');}};
  const transact=fn=>{db.exec('BEGIN IMMEDIATE');try{const r=fn();db.exec('COMMIT');return r;}catch(e){try{db.exec('ROLLBACK');}catch{fault();}throw e;}};
  const current=(principal,remembered=true)=>{clock();let i;try{i=boundary.current(principal);}catch{throw deny(401,'authentication_required');}const row=account(i.accountId);if(row&&row.xid!==i.participantXid){fault();throw deny();}if(remembered&&principals.get(i.accountId)!==principal)throw deny(401,'authentication_required');return i;};
  const active=expected=>{clock();let g;try{g=activation.assertActive();}catch{clearAdmission();throw deny();}if(typeof g!=='string'||!g){fault();throw deny();}if(g!==generation){clearAdmission();generation=g;}if(expected!==undefined&&g!==expected)throw deny();return g;};
  const isOpen=()=>{try{active();return roundOpen;}catch{return false;}};
  const queue=(fn,critical=false)=>{if(closing||disposed||faulted)return Promise.reject(deny(503,'access_closed'));if(pending>=(critical?52:32))return Promise.reject(deny(503,'access_capacity'));pending++;const task=chain.then(()=>{clock();return fn();}).catch(e=>{if(e instanceof ProductionAccessError)throw e;fault();throw deny(503,'access_unavailable');});chain=task.catch(()=>{});return task.finally(()=>{pending--;});};
  const persistRevocation=(id,registrationId,eventId,inTransaction=false)=>{const row=account(id);if(!row)throw deny(409,'registration_required');if(row.registration_id&&row.registration_id!==registrationId){fault();throw deny();}const write=()=>{db.prepare("UPDATE accounts SET registration_id=?,state='revoked',provider_state=CASE WHEN provider_state='removed' THEN 'removed' ELSE 'pending_remove' END,event_version=2,event_id=? WHERE account_id=?").run(registrationId,eventId,id);invalidate(id);};if(inTransaction)write();else transact(write);principals.delete(id);};
  const readback=async(id,principal,expectedGeneration)=>{
    const before=account(id);if(!before)throw deny(409,'registration_required');
    let r;try{r=await wordpress.status(id);}catch{clearAdmission();try{activation.close();}catch{}throw deny(503,'approval_unavailable');}
    clock();if(r.state==='revoked'){persistRevocation(id,r.registrationId,r.decisionEventId);throw deny(403,'approval_revoked');}
    if(principal)current(principal);if(expectedGeneration!==undefined)active(expectedGeneration);
    const row=account(id);if(row.state==='revoked')throw deny(403,'approval_revoked');
    if(r.registrationId!==row.registration_id||r.state==='unregistered'){clearAdmission();throw deny(403,'registration_unconfirmed');}
    if(r.state==='pending'&&row.event_version>0){fault();throw deny(503,'approval_history_changed');}
    if(r.state==='approved'&&row.event_version===1&&r.decisionEventId!==row.event_id){fault();throw deny(503,'approval_history_changed');}
    if(r.state==='approved'&&(r.version!==1||r.decisionEventId!==row.event_id||row.event_version!==1))throw deny(403,'approval_pending');
    return r;
  };
  const applyEvent=async event=>{
    const row=account(event.accountId);if(!row)throw deny();
    if(event.state==='revoked'||row.state==='revoked'){
      if(event.state==='approved'){db.prepare('UPDATE events SET applied=1 WHERE event_id=?').run(event.eventId);return;}
      try{await provider.allowlist('remove',row.xid);clock();const r=await provider.allowlist('readback',row.xid);clock();if(r.present||r.operationVersion!==2)throw deny();db.prepare("UPDATE accounts SET provider_state='removed' WHERE account_id=? AND state='revoked'").run(event.accountId);db.prepare('UPDATE events SET applied=1 WHERE event_id=?').run(event.eventId);}catch{throw deny(503,'removal_pending');}return;
    }
    const principal=principals.get(event.accountId);current(principal);const g=active();
    let r=await readback(event.accountId,principal,g);if(r.state!=='approved')throw deny(403,'approval_pending');
    db.prepare("UPDATE accounts SET provider_state='pending_allow' WHERE account_id=? AND state!='revoked'").run(event.accountId);
    try{
      current(principal);active(g);if(account(event.accountId).state==='revoked')throw deny();await provider.allowlist('upsert',row.xid);
      current(principal);active(g);r=await readback(event.accountId,principal,g);if(r.state!=='approved')throw deny();
      const p=await provider.allowlist('readback',row.xid);current(principal);active(g);if(!p.present||p.operationVersion!==1)throw deny();
      r=await readback(event.accountId,principal,g);if(r.state!=='approved')throw deny();
      transact(()=>{if(account(event.accountId).state==='revoked')throw deny();db.prepare("UPDATE accounts SET state='approved',provider_state='approved' WHERE account_id=? AND event_version=1").run(event.accountId);db.prepare('UPDATE events SET applied=1 WHERE event_id=?').run(event.eventId);});
    }catch(e){if(!(e instanceof ProductionAccessError)){clearAdmission();try{activation.close();}catch{}}throw deny(503,'approval_pending');}
  };
  const publicState=(principal)=>{const i=current(principal),r=account(i.accountId);return Object.freeze({authenticated:true,registrationState:r?(r.registration_id?r.state:'unconfirmed'):'unregistered',registrationReference:r?.registration_id??null,participantAccessGranted:false,roundOpen:isOpen()});};
  const eventShape=event=>{exact(event,['schemaVersion','eventId','deploymentId','conversationId','registrationId','accountId','version','state','occurredAt']);if(event.schemaVersion!==1||event.deploymentId!==c.deploymentId||event.conversationId!==c.conversationId||!UUID.test(event.eventId)||!UUID.test(event.registrationId)||!ACCOUNT.test(event.accountId)||!['approved','revoked'].includes(event.state)||event.version!==(event.state==='approved'?1:2)||!Number.isSafeInteger(event.occurredAt)||event.occurredAt<0||event.occurredAt>Math.floor(clock()/1000)+30)throw deny(400,'invalid_event');};
  const assertApproved=(principal,g)=>{const i=current(principal);active(g);const r=account(i.accountId);if(!roundOpen||r?.state!=='approved'||r.provider_state!=='approved'||r.event_version!==1||!db.prepare('SELECT applied FROM events WHERE event_id=?').get(r.event_id)?.applied)throw deny();return {i,r};};
  const projection=(kind,result)=>{const candidate=kind==='next'?result:result?.nextComment;if(candidate===null||candidate===undefined||(typeof candidate==='object'&&!Array.isArray(candidate)&&!Object.hasOwn(candidate,'tid')))return Object.freeze({statement:null,complete:true});if(!seed.has(candidate.tid)||candidate.txt!==seed.get(candidate.tid))throw deny(503,'statement_unconfirmed');return Object.freeze({statement:Object.freeze({tid:candidate.tid,text:candidate.txt}),complete:false});};
  // Called only inside the access queue. A registration reference selects an
  // existing account for the private operator; it never supplies a principal
  // or replaces current WordPress approval, activation or session authority.
  const issueInvitation=async accountId=>{
    if(db.prepare('SELECT count(*) AS n FROM invitations').get().n>=1024)throw deny(409,'invitation_capacity');
    const p=principals.get(accountId),g=active();assertApproved(p,g);
    const r=await readback(accountId,p,g);assertApproved(p,g);if(r.state!=='approved')throw deny();
    const value=randomBytes(32).toString('base64url'),expiresAt=Math.min(clock()+600_000,boundary.current(p).expiresAt);
    invalidate(accountId);db.prepare('INSERT INTO invitations VALUES(?,?,?,0)').run(sha(value),accountId,expiresAt);
    return Object.freeze({invitationToken:value,expiresAt,delivery:'PRIVATE_OPERATOR_RESPONSE_ONLY'});
  };
  const api=Object.freeze({profile:'FNCP_PRODUCTION_ACCESS_V1',
    registrationNotice(){return Object.freeze({consentVersion:c.consentVersion,noticeSha256:c.noticeSha256,...c.notice});},
    authenticate(principal){return queue(async()=>{const i=current(principal,false);invalidate(i.accountId);principals.set(i.accountId,principal);const row=account(i.accountId);if(row?.state==='revoked')throw deny(403,'approval_revoked');return publicState(principal);});},
    register(principal,input){return queue(async()=>{validDeclarations(input,c.consentVersion);const i=current(principal);let row=account(i.accountId);if(row?.state==='revoked')throw deny(403,'approval_revoked');
      if(!row){if(db.prepare('SELECT count(*) AS n FROM accounts').get().n>=20)throw deny(409,'registration_capacity');const at=Math.floor(clock()/1000);const receipt={receiptId:randomUUID(),accountId:i.accountId,...input,issuedAt:at,expiresAt:Math.min(at+60,Math.floor(i.expiresAt/1000))};if(receipt.expiresAt<=at)throw deny(401,'authentication_required');db.prepare('INSERT INTO accounts(account_id,xid,receipt_id,receipt_json) VALUES(?,?,?,?)').run(i.accountId,i.participantXid,receipt.receiptId,canonical(receipt));row=account(i.accountId);}
      if(!row.registration_id){let receipt=JSON.parse(row.receipt_json),r;
        try{r=await wordpress.register(receipt);}catch{
          current(principal);if(receipt.expiresAt>Math.floor(clock()/1000))throw deny(503,'registration_pending');
          // First retry the exact receipt, including after expiry, because WP
          // may already have committed it. Only a fresh authenticated status
          // can reconcile that uncertain commit or justify a new attempt.
          let observed;try{observed=await wordpress.status(i.accountId);}catch{throw deny(503,'registration_pending');}current(principal);
          if(observed.state==='revoked'){persistRevocation(i.accountId,observed.registrationId,observed.decisionEventId);throw deny(403,'approval_revoked');}
          if(observed.state!=='unregistered')r={registrationId:observed.registrationId};
          else{row=account(i.accountId);if(row.registration_id)r={registrationId:row.registration_id};else{
            const at=Math.floor(clock()/1000);receipt={receiptId:randomUUID(),accountId:i.accountId,...input,issuedAt:at,expiresAt:Math.min(at+60,Math.floor(i.expiresAt/1000))};if(receipt.expiresAt<=at)throw deny(401,'authentication_required');
            // A new UUID names a new attempt; never rewrite the body of an
            // existing receipt or free the reserved lifetime cohort slot.
            db.prepare('UPDATE accounts SET receipt_id=?,receipt_json=? WHERE account_id=? AND registration_id IS NULL').run(receipt.receiptId,canonical(receipt),i.accountId);
            try{r=await wordpress.register(receipt);}catch{throw deny(503,'registration_pending');}
          }}
        }
        current(principal);row=account(i.accountId);if(row.registration_id&&row.registration_id!==r.registrationId){fault();throw deny();}db.prepare('UPDATE accounts SET registration_id=? WHERE account_id=?').run(r.registrationId,i.accountId);
      }
      return publicState(principal);});},
    status(principal){return queue(async()=>{const i=current(principal);let row=account(i.accountId);
      if(row&&!row.registration_id){let observed;try{observed=await wordpress.status(i.accountId);}catch{throw deny(503,'registration_pending');}current(principal);if(observed.state==='revoked')persistRevocation(i.accountId,observed.registrationId,observed.decisionEventId);else if(observed.state!=='unregistered')db.prepare('UPDATE accounts SET registration_id=? WHERE account_id=? AND registration_id IS NULL').run(observed.registrationId,i.accountId);row=account(i.accountId);}
      if(row?.state==='revoked')return Object.freeze({authenticated:true,registrationState:'revoked',registrationReference:row.registration_id,participantAccessGranted:false,roundOpen:false});if(row?.registration_id){await readback(i.accountId,principal);const pendingEvent=db.prepare('SELECT body FROM events WHERE account_id=? AND version=1 AND applied=0').get(i.accountId);if(pendingEvent&&isOpen())try{await applyEvent(JSON.parse(pendingEvent.body));}catch(e){if(account(i.accountId)?.state==='revoked')throw e;}}
      return publicState(principal);});},
    ingestWordPressEvent(event){
      try{eventShape(event);const raw=canonical(event),digest=sha(raw);const existing=db.prepare('SELECT * FROM events WHERE event_id=? OR(account_id=? AND version=?)').all(event.eventId,event.accountId,event.version);if(existing.some(x=>x.digest!==digest))throw deny(409,'event_conflict');const row=account(event.accountId);if(!row)throw deny(409,'registration_required');if(row.registration_id&&row.registration_id!==event.registrationId)throw deny(409,'registration_conflict');
        if(!existing.length){if(db.prepare('SELECT count(*) AS n FROM events').get().n>=40)throw deny(409,'event_capacity');transact(()=>{db.prepare('INSERT INTO events(event_id,account_id,version,state,digest,body) VALUES(?,?,?,?,?,?)').run(event.eventId,event.accountId,event.version,event.state,digest,raw);if(event.state==='revoked')persistRevocation(event.accountId,event.registrationId,event.eventId,true);if(event.state==='approved'&&row.state!=='revoked')db.prepare("UPDATE accounts SET registration_id=?,event_version=1,event_id=?,state='pending',provider_state='pending_allow' WHERE account_id=?").run(event.registrationId,event.eventId,event.accountId);});}
        if(event.state==='revoked'&&existing.length)persistRevocation(event.accountId,event.registrationId,event.eventId);
        return queue(async()=>{const saved=db.prepare('SELECT applied FROM events WHERE event_id=?').get(event.eventId);if(!saved.applied)await applyEvent(event);return Object.freeze({ok:true,eventId:event.eventId,version:event.version});},event.state==='revoked');
      }catch(e){return Promise.reject(e instanceof ProductionAccessError?e:deny(503,'event_unavailable'));}
    },
    redeem(principal,invitationToken){return queue(async()=>{if(!OPAQUE.test(invitationToken))throw deny();const g=active(),{i}=assertApproved(principal,g);const tokenHash=sha(invitationToken),inv=db.prepare('SELECT * FROM invitations WHERE token_hash=?').get(tokenHash);if(!inv||inv.account_id!==i.accountId||inv.used||inv.expires_ms<=clock())throw deny();const r=await readback(i.accountId,principal,g);assertApproved(principal,g);if(r.state!=='approved')throw deny();let cap;
      transact(()=>{if(db.prepare('UPDATE invitations SET used=1 WHERE token_hash=? AND used=0').run(tokenHash).changes!==1)throw deny();accountEpochs.set(i.accountId,(accountEpochs.get(i.accountId)??0)+1);cap=Object.freeze({});grants.set(cap,{principal,accountId:i.accountId,expiresAt:Math.min(i.expiresAt,clock()+15*60_000),epoch,accountEpoch:accountEpochs.get(i.accountId),generation:g});});return cap;});},
    participate(principal,grant,kind,values={}){return queue(async()=>{if(!['init','next','vote'].includes(kind))throw deny(400,'invalid_request');exact(values,kind==='vote'?['tid','vote']:[]);if(kind==='vote'&&(!seed.has(values.tid)||![-1,0,1].includes(values.vote)))throw deny(400,'invalid_vote');
      const check=()=>{const cap=grants.get(grant),g=active();const {i,r}=assertApproved(principal,g);if(!cap||cap.principal!==principal||cap.accountId!==i.accountId||cap.epoch!==epoch||cap.accountEpoch!==accountEpochs.get(i.accountId)||cap.generation!==g||cap.expiresAt<=clock())throw deny();return {i,r,g};};
      const before=check();const w=await readback(before.i.accountId,principal,before.g);check();if(w.state!=='approved')throw deny();let result;
      try{result=await provider.participate(kind,before.r.xid,values);}catch{clearAdmission();try{activation.close();}catch{}throw deny(503,kind==='vote'?'vote_outcome_unconfirmed':'provider_unavailable');}
      check();const after=await readback(before.i.accountId,principal,before.g);check();if(after.state!=='approved')throw deny();try{return projection(kind,result);}catch{clearAdmission();try{activation.close();}catch{}throw deny(503,'statement_unconfirmed');}});},
    logout(principal){try{const i=boundary.current(principal);invalidate(i.accountId);principals.delete(i.accountId);}catch{epoch++;}return Promise.resolve();},
    closeAdmission(){epoch++;roundOpen=false;generation=undefined;try{activation.close();db.exec('UPDATE invitations SET used=1');}catch{fault();throw deny(503,'closure_unconfirmed');}},
    operator:Object.freeze({
      recoveryDescriptor(){clock();return Object.freeze({binding:structuredClone(recoveryBinding),bindingSha256:boundFingerprint});},
      status(){clock();return Object.freeze({profile:'FNCP_PRODUCTION_ACCESS_V1',roundOpen:isOpen(),registrations:db.prepare('SELECT count(*) AS n FROM accounts').get().n,pendingEvents:db.prepare('SELECT count(*) AS n FROM events WHERE applied=0').get().n});},
      setRoundOpen(value){if(typeof value!=='boolean')throw deny(400,'invalid_request');if(value){active();roundOpen=true;}else api.closeAdmission();return Object.freeze({roundOpen});},
      issueInvitation(accountId){return queue(async()=>{if(!ACCOUNT.test(accountId))throw deny(400,'invalid_request');return issueInvitation(accountId);});},
      issueInvitationForRegistration(registrationId){return queue(async()=>{
        if(typeof registrationId!=='string'||!UUID.test(registrationId))throw deny(400,'invalid_request');
        const row=db.prepare('SELECT account_id FROM accounts WHERE registration_id=?').get(registrationId);
        if(!row)throw deny();return issueInvitation(row.account_id);
      });},
    }),
    close(){if(closePromise)return closePromise;let failure=false;try{api.closeAdmission();}catch{failure=true;}closing=true;principals.clear();boundary.close();identity.close();
      closePromise=(async()=>{await chain;try{provider.close();wordpress.close();activation.dispose();db.close();disposed=true;}catch{failure=true;}
        try{if(lockFd!==undefined)closeSync(lockFd);if(lockIdentity){const s=lstatSync(storePath+'.writer.lock');if(s.ino!==lockIdentity.ino||s.dev!==lockIdentity.dev)throw deny();unlinkSync(storePath+'.writer.lock');}}catch{failure=true;}
        if(failure)throw deny(503,'closure_unconfirmed');return Object.freeze({closed:true,drained:true});})();return closePromise;},
  });instances.add(api);return api;
}
