import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { JOURNEY_VOTE_OBSERVATION_SQL,validateFreshJourneyVoteAggregate,observeFreshJourneyVote } from './journey-vote-observation.mjs';

/** Execute the exact relational SELECT unchanged against synthetic SQLite
 * tables. PostgreSQL TLS/transaction execution is a separate actual-run check.
 */
function fixture(t,vote=0){
  const db=new DatabaseSync(':memory:');t.after(()=>db.close());
  db.exec(`ATTACH DATABASE ':memory:' AS public;
    CREATE TABLE public.conversations(zid INTEGER,owner INTEGER,is_active BOOLEAN,use_xid_whitelist BOOLEAN,xid_required BOOLEAN,is_data_open BOOLEAN,strict_moderation BOOLEAN,topics_enabled BOOLEAN,treevite_enabled BOOLEAN);
    CREATE TABLE public.zinvites(zid INTEGER,zinvite TEXT);
    CREATE TABLE public.participants(zid INTEGER,pid INTEGER,uid INTEGER);
    CREATE TABLE public.comments(zid INTEGER,tid INTEGER,pid INTEGER,uid INTEGER,is_seed BOOLEAN,active BOOLEAN,mod INTEGER);
    CREATE TABLE public.votes(zid INTEGER,pid INTEGER,tid INTEGER,vote INTEGER);
    CREATE TABLE public.votes_latest_unique(zid INTEGER,pid INTEGER,tid INTEGER,vote INTEGER);
    CREATE TABLE public.xids(owner INTEGER,uid INTEGER,xid TEXT,zid INTEGER,pid INTEGER);
    INSERT INTO public.conversations VALUES(1,100,FALSE,TRUE,TRUE,FALSE,TRUE,FALSE,FALSE);
    INSERT INTO public.zinvites VALUES(1,'3syntheticVoteScope');
    INSERT INTO public.participants VALUES(1,0,100),(1,1,201),(1,2,202);`);
  db.function('current_setting',name=>name==='transaction_read_only'?'on':'unknown');
  const alice='fncp_'+'a'.repeat(43),bob='fncp_'+'b'.repeat(43);
  db.prepare('INSERT INTO public.xids VALUES(100,201,?,1,1)').run(alice);
  db.prepare('INSERT INTO public.xids VALUES(100,202,?,1,2)').run(bob);
  const tids=Array.from({length:15},(_,n)=>101+n*3);
  const args={'1':'3syntheticVoteScope','2':0,'18':alice,'19':vote};
  for(let i=0;i<tids.length;i++){
    args[String(i+3)]=tids[i];
    db.prepare('INSERT INTO public.comments VALUES(1,?,0,100,TRUE,TRUE,1)').run(tids[i]);
    db.prepare('INSERT INTO public.votes VALUES(1,0,?,0)').run(tids[i]);
    db.prepare('INSERT INTO public.votes_latest_unique VALUES(1,0,?,0)').run(tids[i]);
  }
  db.prepare('INSERT INTO public.votes VALUES(1,1,?,?)').run(tids[0],vote);
  db.prepare('INSERT INTO public.votes_latest_unique VALUES(1,1,?,?)').run(tids[0],vote);
  return {db,args,alice,bob,tids,observe(){
    db.exec('PRAGMA query_only = ON');
    const raw=db.prepare(JOURNEY_VOTE_OBSERVATION_SQL).get(args);
    const row={...raw,transaction_read_only:raw.transaction_read_only===1,closed_gates:raw.closed_gates===1};
    return validateFreshJourneyVoteAggregate([row]);
  }};
}
for(const vote of [0,-1])test('sole real-account fixture vote attributed correctly in both tables: '+vote,t=>{
  const h=fixture(t,vote),result=h.observe();
  assert.deepEqual(result,{outcome:'PASS',rawParticipantVotes:1,latestParticipantVotes:1,expectedAccountMatched:true,
    statementManifestMatched:true,voteValueMatched:true,closedGatesVerified:true,rawLatestAgreement:true});
  assert.doesNotMatch(JSON.stringify(result),/fncp_|3synthetic|101|statementIds|expectedXid/);
});
test('another approved account cannot inherit the voting account attribution',t=>{
  const h=fixture(t);h.args['18']=h.bob;assert.throws(()=>h.observe());
});
for(const [name,sql] of [
  ['wrong raw account','UPDATE public.votes SET pid=2 WHERE pid=1'],
  ['wrong latest account','UPDATE public.votes_latest_unique SET pid=2 WHERE pid=1'],
  ['extra raw vote','INSERT INTO public.votes VALUES(1,2,101,0)'],
  ['missing latest vote','DELETE FROM public.votes_latest_unique WHERE pid=1'],
  ['foreign manifest TID','UPDATE public.votes SET tid=999 WHERE pid=1'],
  ['different raw/latest statement','UPDATE public.votes_latest_unique SET tid=104 WHERE pid=1'],
  ['wrong raw value','UPDATE public.votes SET vote=-1 WHERE pid=1'],
  ['wrong latest value','UPDATE public.votes_latest_unique SET vote=-1 WHERE pid=1'],
  ['XID belongs to another conversation','UPDATE public.xids SET zid=2 WHERE uid=201'],
  ['XID pid absent','UPDATE public.xids SET pid=NULL WHERE uid=201'],
  ['XID pid mismatched','UPDATE public.xids SET pid=2 WHERE uid=201'],
  ['XID uid mismatched','UPDATE public.xids SET uid=202 WHERE uid=201'],
  ['XID owner mismatched','UPDATE public.xids SET owner=999 WHERE uid=201'],
  ['round still open','UPDATE public.conversations SET is_active=TRUE'],
  ['allowlist gate absent','UPDATE public.conversations SET use_xid_whitelist=FALSE'],
  ['seed owner duplicated TID','UPDATE public.votes SET tid=104 WHERE pid=0 AND tid=101'],
  ['seed statement no longer seeded','UPDATE public.comments SET is_seed=FALSE WHERE tid=101'],
])test('query refuses '+name,t=>{const h=fixture(t);h.db.exec(sql);assert.throws(()=>h.observe());});
test('incorrect seed-owner reference cannot conceal another account vote',t=>{
  const h=fixture(t);h.args['2']=1;assert.throws(()=>h.observe());
});
test('observed manifest is checked against seeds as well as the voted TID',t=>{
  const h=fixture(t);h.args['17']=999;assert.throws(()=>h.observe());
});
test('read-only observation input errors remain static and redact caller values',async()=>{
  for(const expected of [null,{}, {conversationId:'sensitive-untrusted-marker'},[],new Proxy({}, {})]){
    await assert.rejects(observeFreshJourneyVote(expected),error=>error.message==='FRESH_JOURNEY_VOTE_OBSERVATION_FAILED');
  }
});
test('aggregate validator cannot turn missing or string-valued facts into success',()=>{
  for(const rows of [[],[{}],[{},{}],{rows:[]},[new Proxy({}, {})]])assert.throws(()=>validateFreshJourneyVoteAggregate(rows));
});
