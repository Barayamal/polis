/** Independent read-only attribution of the sole invented participant vote.
 * Caller supplies freshly observed bootstrap binding and the expected opaque
 * XID derived by the verified identity foundation. No identity content leaves
 * this helper. It neither creates authority nor certifies a person's heritage.
 */
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { checkServerIdentity } from 'node:tls';
import { isProxy } from 'node:util/types';
import { validateFreshBootstrapResult } from '../fresh-bootstrap-result.mjs';
import { validateParticipantLaunch } from './participant-container-run.mjs';

const ROOT='/run/fncp/bootstrap';
const fail=()=>new Error('FRESH_JOURNEY_VOTE_OBSERVATION_FAILED');
const exact=(value,names)=>{
  if(!value||typeof value!=='object'||isProxy(value)||Object.getPrototypeOf(value)!==Object.prototype||
    Reflect.ownKeys(value).length!==names.length||names.some(key=>!Object.hasOwn(value,key))||
    Object.values(Object.getOwnPropertyDescriptors(value)).some(field=>!Object.hasOwn(field,'value')))throw fail();
  return value;
};
function parameters(expected){
  exact(expected,['conversationId','seedOwnerPid','statementIds','expectedXid','expectedVote']);
  validateFreshBootstrapResult({conversationId:expected.conversationId,statementIds:expected.statementIds});
  if(!Number.isSafeInteger(expected.seedOwnerPid)||expected.seedOwnerPid<0||Object.is(expected.seedOwnerPid,-0)||
    typeof expected.expectedXid!=='string'||!/^fncp_[A-Za-z0-9_-]{43}$/u.test(expected.expectedXid)||
    ![0,-1].includes(expected.expectedVote)||Object.is(expected.expectedVote,-0))throw fail();
  return Object.freeze([expected.conversationId,expected.seedOwnerPid,...expected.statementIds,expected.expectedXid,expected.expectedVote]);
}

// Parameter positions are fixed: scope, seed owner, fifteen actual TIDs, account
// XID, raw vote value. CAST syntax deliberately also permits relational fixture
// tests in SQLite; the production query executes unchanged against PostgreSQL.
// xids.ts/createXidRecord binds owner+uid+xid and stores the new participant's
// zid+pid. All four links must agree; a same-owner or same-PID shortcut cannot
// substitute a different account or a different conversation.
export const JOURNEY_VOTE_OBSERVATION_SQL=`WITH
manifest(tid) AS (VALUES ${Array.from({length:15},(_,n)=>`(CAST($${n+3} AS INTEGER))`).join(',')}),
target AS (SELECT c.zid,c.owner,c.is_active,c.use_xid_whitelist,c.xid_required,c.is_data_open,c.strict_moderation,c.topics_enabled,c.treevite_enabled
 FROM public.conversations c JOIN public.zinvites z ON z.zid=c.zid WHERE z.zinvite=$1),
selected_comments AS (SELECT c.* FROM public.comments c JOIN target t ON t.zid=c.zid),
raw_votes AS (SELECT v.zid,v.pid,v.tid,v.vote FROM public.votes v JOIN target t ON t.zid=v.zid),
latest_votes AS (SELECT v.zid,v.pid,v.tid,v.vote FROM public.votes_latest_unique v JOIN target t ON t.zid=v.zid),
raw_participant AS (SELECT * FROM raw_votes WHERE pid<>$2),
latest_participant AS (SELECT * FROM latest_votes WHERE pid<>$2),
expected_identity AS (SELECT x.* FROM public.xids x JOIN target t ON x.owner=t.owner WHERE x.xid=$18),
expected_participant AS (SELECT p.zid,p.pid,p.uid FROM public.participants p JOIN target t ON p.zid=t.zid
 JOIN expected_identity x ON x.uid=p.uid AND x.owner=t.owner AND x.zid=p.zid AND x.pid=p.pid
 WHERE p.pid<>$2 AND p.uid<>t.owner)
SELECT
current_setting('transaction_read_only')='on' AS transaction_read_only,
(SELECT CAST(count(*) AS INTEGER) FROM target) AS target_rows,
(SELECT CAST(count(*) AS INTEGER) FROM public.participants p JOIN target t ON p.zid=t.zid WHERE p.pid=$2 AND p.uid=t.owner) AS seed_owner_rows,
(SELECT CAST(count(*) AS INTEGER) FROM selected_comments) AS statement_rows,
(SELECT CAST(count(*) AS INTEGER) FROM selected_comments c JOIN target t ON c.zid=t.zid JOIN manifest m ON m.tid=c.tid
 WHERE c.pid=$2 AND c.uid=t.owner AND c.is_seed IS TRUE AND c.active IS TRUE AND c.mod=1) AS valid_seed_rows,
(SELECT CAST(count(*) AS INTEGER) FROM raw_votes WHERE pid=$2 AND vote=0 AND tid IN (SELECT tid FROM manifest)) AS seed_owner_raw_pass_rows,
(SELECT CAST(count(*) AS INTEGER) FROM latest_votes WHERE pid=$2 AND vote=0 AND tid IN (SELECT tid FROM manifest)) AS seed_owner_latest_pass_rows,
(SELECT CAST(count(DISTINCT tid) AS INTEGER) FROM raw_votes WHERE pid=$2 AND vote=0 AND tid IN (SELECT tid FROM manifest)) AS seed_owner_raw_distinct_tids,
(SELECT CAST(count(DISTINCT tid) AS INTEGER) FROM latest_votes WHERE pid=$2 AND vote=0 AND tid IN (SELECT tid FROM manifest)) AS seed_owner_latest_distinct_tids,
(SELECT CAST(count(*) AS INTEGER) FROM raw_votes) AS raw_rows,
(SELECT CAST(count(*) AS INTEGER) FROM latest_votes) AS latest_rows,
(SELECT CAST(count(*) AS INTEGER) FROM raw_participant) AS raw_participant_votes,
(SELECT CAST(count(*) AS INTEGER) FROM latest_participant) AS latest_participant_votes,
(SELECT CAST(count(*) AS INTEGER) FROM expected_identity) AS expected_identity_rows,
(SELECT CAST(count(*) AS INTEGER) FROM expected_participant) AS expected_participant_rows,
(SELECT CAST(count(*) AS INTEGER) FROM raw_participant v JOIN expected_participant p ON v.zid=p.zid AND v.pid=p.pid) AS raw_expected_account_rows,
(SELECT CAST(count(*) AS INTEGER) FROM latest_participant v JOIN expected_participant p ON v.zid=p.zid AND v.pid=p.pid) AS latest_expected_account_rows,
(SELECT CAST(count(*) AS INTEGER) FROM raw_participant WHERE tid IN (SELECT tid FROM manifest)) AS raw_manifest_rows,
(SELECT CAST(count(*) AS INTEGER) FROM latest_participant WHERE tid IN (SELECT tid FROM manifest)) AS latest_manifest_rows,
(SELECT CAST(count(*) AS INTEGER) FROM raw_participant WHERE vote=$19) AS raw_expected_vote_rows,
(SELECT CAST(count(*) AS INTEGER) FROM latest_participant WHERE vote=$19) AS latest_expected_vote_rows,
(SELECT CAST(count(*) AS INTEGER) FROM raw_participant v JOIN latest_participant l ON v.zid=l.zid AND v.pid=l.pid AND v.tid=l.tid AND v.vote=l.vote) AS raw_latest_matched_rows,
EXISTS(SELECT 1 FROM target WHERE is_active IS FALSE AND use_xid_whitelist IS TRUE AND xid_required IS TRUE
 AND is_data_open IS FALSE AND strict_moderation IS TRUE AND topics_enabled IS FALSE AND treevite_enabled IS FALSE) AS closed_gates`;

const expectedCounts={target_rows:1,seed_owner_rows:1,statement_rows:15,valid_seed_rows:15,
  seed_owner_raw_pass_rows:15,seed_owner_latest_pass_rows:15,seed_owner_raw_distinct_tids:15,seed_owner_latest_distinct_tids:15,
  raw_rows:16,latest_rows:16,raw_participant_votes:1,latest_participant_votes:1,expected_identity_rows:1,expected_participant_rows:1,
  raw_expected_account_rows:1,latest_expected_account_rows:1,raw_manifest_rows:1,latest_manifest_rows:1,
  raw_expected_vote_rows:1,latest_expected_vote_rows:1,raw_latest_matched_rows:1};
/** Pure aggregate validation; emits no private query inputs or database rows. */
export function validateFreshJourneyVoteAggregate(rows){
  if(!Array.isArray(rows)||isProxy(rows)||Object.getPrototypeOf(rows)!==Array.prototype||rows.length!==1)throw fail();
  const row=exact(rows[0],[...Object.keys(expectedCounts),'transaction_read_only','closed_gates']);
  if(row.transaction_read_only!==true||row.closed_gates!==true||
    Object.entries(expectedCounts).some(([key,count])=>row[key]!==count))throw fail();
  return Object.freeze({outcome:'PASS',rawParticipantVotes:1,latestParticipantVotes:1,expectedAccountMatched:true,
    statementManifestMatched:true,voteValueMatched:true,closedGatesVerified:true,rawLatestAgreement:true});
}
async function fixedFile(name,limit){
  const path=ROOT+'/'+name,before=await lstat(path);
  const same=after=>['dev','ino','mode','uid','gid','nlink','size','mtimeMs','ctimeMs'].every(key=>after[key]===before[key]);
  if(!before.isFile()||before.isSymbolicLink()||before.nlink!==1||before.uid!==1000||(before.mode&0o777)!==0o600||before.size<1||before.size>limit)throw fail();
  const file=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{
    if(!same(await file.stat()))throw fail();
    const bytes=Buffer.alloc(limit+1);let size=0;
    while(size<bytes.length){const chunk=await file.read(bytes,size,bytes.length-size,size);if(!chunk.bytesRead)break;size+=chunk.bytesRead;}
    if(size!==before.size||!same(await file.stat())||!same(await lstat(path)))throw fail();
    return new TextDecoder('utf-8',{fatal:true}).decode(bytes.subarray(0,size));
  }finally{await file.close();}
}

/** Fixed Linux QA API only. Always closes this helper's own PostgreSQL client;
 * closure says nothing about the application's or container's process state.
 */
export async function observeFreshJourneyVote(expected){
  let client,result,failed=false;
  try{
    if(arguments.length!==1)throw fail();const values=parameters(expected);
    if(process.platform!=='linux'||process.getuid?.()!==1000)throw fail();
    const directory=await lstat(ROOT);
    if(!directory.isDirectory()||directory.isSymbolicLink()||directory.uid!==1000||(directory.mode&0o777)!==0o700||await realpath(ROOT)!==ROOT)throw fail();
    const launch=validateParticipantLaunch(JSON.parse(await fixedFile('launch.json',16384)));
    const cert=await fixedFile('postgres-cert.pem',8192);
    if(cert!==launch.databaseCertificatePem)throw fail();
    const host='fncp-fresh-pg-'+launch.namespaceId;
    const require=createRequire('/opt/fncp/server/node_modules/pg/package.json');
    const Client=require('/opt/fncp/server/node_modules/pg/lib/client.js');
    client=new Client({host,port:5432,database:launch.database,user:launch.user,password:launch.password,
      ssl:{ca:cert,rejectUnauthorized:true,minVersion:'TLSv1.2',servername:host,checkServerIdentity:(_name,peer)=>
        checkServerIdentity(host,peer)||(!peer.raw||createHash('sha256').update(peer.raw).digest('hex')!==launch.databaseCertificateSha256?fail():undefined)},
      connectionTimeoutMillis:2000,query_timeout:4000,application_name:'fncp-fresh-vote-observation',
      options:'-c default_transaction_read_only=on -c statement_timeout=3000 -c lock_timeout=1000 -c idle_in_transaction_session_timeout=5000'});
    client.on('error',()=>{failed=true;});
    await client.connect();
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    await client.query('SET LOCAL search_path = pg_catalog, public');
    result=validateFreshJourneyVoteAggregate((await client.query(JOURNEY_VOTE_OBSERVATION_SQL,values)).rows);
    await client.query('COMMIT');
  }catch{failed=true;}
  finally{
    if(client){
      let timer;
      try{
        // A timed-out end forcibly closes this client's socket and fails the
        // observation. Never report successful cleanup from a timeout alone.
        await Promise.race([client.end(),new Promise((_,reject)=>{timer=setTimeout(()=>{
          client.connection?.stream?.destroy();reject(fail());},2500);})]);
      }catch{failed=true;}finally{clearTimeout(timer);}
    }
  }
  if(failed||!result)throw fail();
  return Object.freeze({...result,databaseClientClosed:true});
}
