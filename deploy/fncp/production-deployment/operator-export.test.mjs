import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync,readdirSync} from 'node:fs';
import {aggregateOperatorSnapshot,operatorSnapshotSql} from './operator-export.mjs';
const sha=v=>createHash('sha256').update(v).digest('hex');
const rejected={message:'Production operator export rejected.'};
function fixture(n=18){
 const ids=Array.from({length:15},(_,i)=>i),texts=ids.map(i=>'Reviewed statement '+i);
 const c={version:1,profile:'FNCP_PRODUCTION_COMPOSE_V1',deployment:'fncp-export-contract',platform:'linux/arm64',stateDirectory:'/private/export-fixture',sourceRevision:'a'.repeat(40),
  database:{name:'polis',owner:'polis_owner',migrationRole:'polis_migration',runtimeRole:'polis_runtime',mathRole:'polis_math',host:'postgres',port:5432},
  binding:{conversationId:'9fixedExportRound',statementIds:ids},identity:{issuer:'https://issuer.invalid/',audience:'client',jwksUri:'https://issuer.invalid/jwks'}};
 const lock={version:1,sourceRevision:c.sourceRevision,sourceFingerprint:'b'.repeat(64),images:Object.fromEntries(['api','math','postgres','migration','participant','wordpress','mariadb','proxy'].map((r,i)=>[r,'sha256:'+String(i+1).repeat(64)]))};
 const groupIds=[2,7,11],sizes=n===20?[7,7,6]:[6,6,6],score=sizes.reduce((v,k)=>v*3/(k+2),1);
 const seed={statements:texts,seedSha256:sha(JSON.stringify(texts))};
 const s={database:c.database.name,role:c.database.migrationRole,readOnly:'on',isolation:'repeatable read',snapshotAt:'2026-09-14T12:00:00Z',
  serverMajor:17,primary:true,roleSafe:true,schemaMatches:true,conversationRows:1,inviteRows:1,tls:{ssl:true,version:'TLSv1.3',bits:256},
  boundCount:1,conversation:{code:c.binding.conversationId,closed:true,gated:true,dataOpen:false,private:true,xidRequired:true,strictModeration:true,suggestionsDisabled:true},
  participantRows:n+1,identities:n+1,identifiedRows:n+1,voterCount:n,latestVoteCount:15*n,
  cohort:{registrations:n,present:n-1,revoked:1,seedOwnerRows:1,seedOwnerVoteEvents:0,seedOwnerAuthoredAll:true,seedOwnerMappingRows:0,
   nativeUserRows:n+1,unknownUserRows:0,unknownParticipantRows:0,invalidMappingRows:0,providerStateMatches:true},
  voteWatermark:2000000,moderationWatermark:1000000,invalidVoteEvents:0,unknownLatestVotes:0,ambiguousVoteTimes:false,latestMatchesHistory:true,
  statements:ids.map(id=>({id,text:texts[id],approved:true,active:true,seed:true,meta:false,agree:6,disagree:9,pass:n-15})),
  math:{environment:'dev',tick:0,cachingTick:2,rowVoteWatermark:2000000,dataVoteWatermark:2000000,dataModWatermark:1000000,bindingMatches:true,voterMembershipMatches:true,
   participants:n,statementCount:15,statementIds:ids,modIn:ids,modOut:[],metaIds:[],groupIds,
   groupVotes:Object.fromEntries(groupIds.map((id,i)=>[id,{'n-members':sizes[i],votes:Object.fromEntries(ids.map(tid=>[tid,{A:2,D:3,S:sizes[i]}]))}])),
   consensus:Object.fromEntries(ids.map(id=>[id,score]))},mathTick:0,auxiliary:[1,2].map(()=>({tick:0,voteWatermark:2000000,bindingMatches:true}))};
 return{c,lock,s,seed};
}
const project=f=>aggregateOperatorSnapshot(f.c,f.lock,f.s,f.seed);

test('18 real-provider voters plus the nonvoting seed owner project to closed aggregates',()=>{
 const f=fixture(),v=project(f);assert.equal(v.aggregate.nativeIdentities,19);assert.equal(v.aggregate.voters,18);
 assert.equal(v.aggregate.seedOwnersWithoutVotes,1);assert.equal(v.aggregate.providerRegistrations,18);
 assert.equal(v.aggregate.providerPresent,17);assert.equal(v.aggregate.providerRevoked,1);
 assert.deepEqual(v.aggregate.groupSizes,[6,6,6]);assert.equal(v.aggregate.latestVotes,270);
 assert.equal(v.source.seedSha256,f.seed.seedSha256);assert.equal(Object.keys(v.source.images).length,8);
 assert.equal(v.snapshot.moderationModifiedWatermark,1000000);assert.equal(v.oidcStaffAuthorizationImplemented,false);
 assert.equal(v.statements[0].nativeGroupAwareConsensus,27/512);assert.ok(Object.isFrozen(v.statements[0]));
});
test('20 cohort voters and exactly one seed owner are accepted without raising the voter cap',()=>{
 const v=project(fixture(20));assert.equal(v.aggregate.nativeIdentities,21);assert.equal(v.aggregate.voters,20);
 assert.equal(v.aggregate.latestVotes,300);assert.deepEqual(v.aggregate.groupSizes,[6,7,7]);
});
test('provider registrations that have not visited do not become native identities or math voters',()=>{
 const f=fixture();f.s.cohort.registrations=20;f.s.cohort.present=19;
 const v=project(f);assert.equal(v.aggregate.providerRegistrations,20);assert.equal(v.aggregate.nativeParticipantIdentities,18);assert.equal(v.aggregate.voters,18);
});
test('aggregate projection never emits identity maps, raw votes, or injected private fields',()=>{
 const f=fixture(),secret='PRIVATE_SENTINEL_NEVER_EXPORTED';f.s.email=secret;f.s.uid=secret;f.s.xid=secret;
 f.s.math['in-conv']=[secret];f.s.math['base-clusters']={members:[secret]};f.s.math.voteVectors=[secret];
 f.s.math.groupVotes[2].members=[secret];f.s.statements[0].uid=secret;
 const v=project(f);assert.equal(JSON.stringify(v).includes(secret),false);
 assert.deepEqual(Object.keys(v.statements[0]).sort(),['statementId','text','agree','disagree','pass','nativeGroupAwareConsensus'].sort());
 f.lock.images.api='sha256:'+'f'.repeat(64);f.s.statements[0].text='mutated';assert.equal(v.statements[0].text,'Reviewed statement 0');assert.notEqual(v.source.images.api,f.lock.images.api);
});
const denials=[
 ['21 registered cohort identities',f=>{f.s.cohort.registrations=21;f.s.cohort.present=20;}],
 ['21 voters',f=>{f.s.voterCount=21;}],['22 native participant identities',f=>{f.s.participantRows=f.s.identities=f.s.identifiedRows=22;}],
 ['missing owner',f=>{f.s.cohort.seedOwnerRows=0;}],['duplicate owner',f=>{f.s.cohort.seedOwnerRows=2;}],
 ['owner cast a vote',f=>{f.s.cohort.seedOwnerVoteEvents=1;}],['another seed author',f=>{f.s.cohort.seedOwnerAuthoredAll=false;}],
 ['owner linked to cohort XID',f=>{f.s.cohort.seedOwnerMappingRows=1;}],['unknown native user',f=>{f.s.cohort.unknownUserRows=1;}],
 ['unknown native participant',f=>{f.s.cohort.unknownParticipantRows=1;}],['mismatched UID PID XID mapping',f=>{f.s.cohort.invalidMappingRows=1;}],
 ['revoked XID left whitelisted',f=>{f.s.cohort.providerStateMatches=false;}],['provider counts disagree',f=>{f.s.cohort.present++;}],
 ['native identities exceed registrations',f=>{f.s.cohort.registrations=17;f.s.cohort.present=16;}],
 ['unmapped extra native user',f=>{f.s.cohort.nativeUserRows=20;}],['anonymous participant',f=>{f.s.identifiedRows--;}],
 ['wrong binding',f=>{f.s.conversation.code='9OtherBinding';}],['multiple rounds',f=>{f.s.conversationRows=2;}],['alternate invite',f=>{f.s.inviteRows=2;}],
 ['open round',f=>{f.s.conversation.closed=false;}],['public round',f=>{f.s.conversation.private=false;}],['public data',f=>{f.s.conversation.dataOpen=true;}],
 ['ungated',f=>{f.s.conversation.gated=false;}],['XID not required',f=>{f.s.conversation.xidRequired=false;}],
 ['suggestions enabled',f=>{f.s.conversation.suggestionsDisabled=false;}],['strict moderation disabled',f=>{f.s.conversation.strictModeration=false;}],
 ['wrong database',f=>{f.s.database='another';}],['privileged role',f=>{f.s.roleSafe=false;}],['wrong role',f=>{f.s.role='postgres';}],
 ['wrong server major',f=>{f.s.serverMajor=16;}],['replica',f=>{f.s.primary=false;}],['schema mismatch',f=>{f.s.schemaMatches=false;}],
 ['writable transaction',f=>{f.s.readOnly='off';}],['weak isolation',f=>{f.s.isolation='read committed';}],['missing TLS',f=>{f.s.tls.ssl=false;}],
 ['weak TLS',f=>{f.s.tls.version='TLSv1.1';}],['weak TLS key',f=>{f.s.tls.bits=127;}],
 ['stale vote watermark',f=>{f.s.math.dataVoteWatermark--;}],['stale row watermark',f=>{f.s.math.rowVoteWatermark--;}],
 ['stale moderation watermark',f=>{f.s.math.dataModWatermark--;}],['different math tick',f=>{f.s.mathTick++;}],
 ['auxiliary incomplete',f=>{f.s.auxiliary[0]=null;}],['auxiliary stale',f=>{f.s.auxiliary[1].voteWatermark--;}],
 ['wrong math membership',f=>{f.s.math.voterMembershipMatches=false;}],['moderated out statement',f=>{f.s.math.modOut=[0];}],
 ['unknown statement',f=>{f.s.math.statementIds=[...f.s.math.statementIds.slice(1),44];}],['unapproved seed',f=>{f.s.statements[0].approved=false;}],
 ['nonseed statement',f=>{f.s.statements[0].seed=false;}],['changed seed text',f=>{f.s.statements[0].text+=' changed';}],
 ['invalid vote event',f=>{f.s.invalidVoteEvents=1;}],['unknown latest vote',f=>{f.s.unknownLatestVotes=1;}],
 ['ambiguous vote timestamp',f=>{f.s.ambiguousVoteTimes=true;}],['history mismatch',f=>{f.s.latestMatchesHistory=false;}],
 ['group member count corruption',f=>{f.s.math.groupVotes[2]['n-members']++;}],['group vote corruption',f=>{f.s.math.groupVotes[2].votes[0].A++;}],
 ['consensus corruption',f=>{f.s.math.consensus[0]=0.9;}],['total vote corruption',f=>{f.s.latestVoteCount--;}],
 ['wrong seed digest',f=>{f.seed.seedSha256='c'.repeat(64);}],['wrong image revision',f=>{f.lock.sourceRevision='c'.repeat(40);}],
 ['four-role lock',f=>{delete f.lock.images.participant;}],['extra image role',f=>{f.lock.images.qa='sha256:'+'f'.repeat(64);}],
];
for(const[name,change]of denials)test('rejects '+name,()=>{const f=fixture();change(f);assert.throws(()=>project(f),rejected);});

test('fixed SQL is read-only, privately checks the seed owner and XID/tombstone mapping, and emits no identity lists',()=>{
 const sql=operatorSnapshotSql(fixture().c);assert.match(sql,/^BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;/);
 assert.match(sql,/ROLLBACK;\n$/);assert.doesNotMatch(sql,/^\s*(INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|GRANT|REVOKE|TRUNCATE|COPY|DO|CALL)\b/im);
 for(const text of ['search_path=pg_catalog','idle_in_transaction_session_timeout','pg_stat_ssl','roleSafe','schemaMatches','seed_owner',
  'seedOwnerVoteEvents','seedOwnerAuthoredAll','unknownUserRows','unknownParticipantRows','invalidMappingRows','fncp_provider_allowlist_operations',
  'operation_version=2','x.pid=p.pid AND x.uid=p.uid','latestMatchesHistory','lastModTimestamp','voterMembershipMatches'])assert.ok(sql.includes(text),text);
 assert.doesNotMatch(sql,/'groupVotes',data->|'consensus',data->/);
 assert.match(sql,/FROM public\.xids x WHERE \(x\.zid IS DISTINCT FROM/u);
 assert.match(sql,/NOT EXISTS\(SELECT 1 FROM public\.xid_whitelist w WHERE \(w\.zid IS DISTINCT FROM/u);
 assert.doesNotMatch(sql,/'(?:uid|pid|xid|email|members|in-conv|base-clusters)'\s*,|jsonb_agg\(.*(?:uid|xid|email)/);
 assert.throws(()=>operatorSnapshotSql({...fixture().c,binding:{conversationId:"9bad'; DROP TABLE public.votes; --",statementIds:fixture().c.binding.statementIds}}));
});
test('fixed export schema hash set is exactly the 20 current source migrations',()=>{
 const sql=operatorSnapshotSql(fixture().c),raw=sql.match(/'schemaMatches',.*='([^']+)'::jsonb,/u)?.[1];assert.ok(raw);
 const dir=new URL('../../../server/postgres/migrations/',import.meta.url),expected=Object.fromEntries(readdirSync(dir).filter(n=>n.endsWith('.sql')).sort().map(n=>[n,sha(readFileSync(new URL(n,dir)))]));
 assert.equal(Object.keys(expected).length,20);assert.deepEqual(JSON.parse(raw),expected);
});
test('seed normalization is not implicit and bound Unicode is preserved exactly',()=>{
 const f=fixture();f.seed.statements[0]=' Māori e\u0301 🐬 ';f.seed.seedSha256=sha(JSON.stringify(f.seed.statements));f.s.statements[0].text=f.seed.statements[0];
 assert.equal(project(f).statements[0].text,f.seed.statements[0]);f.s.statements[0].text=f.s.statements[0].text.normalize('NFC');assert.throws(()=>project(f),rejected);
});
test('accessors, toJSON callbacks, sparse arrays, cycles, nonfinite numbers and oversized snapshots are rejected without invocation',()=>{
 let invoked=0;
 const changes=[f=>Object.defineProperty(f.s,'database',{get(){invoked++;return f.c.database.name;}}),
  f=>{f.s.toJSON=()=>{invoked++;return{};}},f=>{delete f.s.statements[0];},f=>{delete f.s.math.groupIds[0];f.s.math.groupIds.extra=2;},f=>{f.s.circular=f.s;},f=>{f.s.math.consensus[0]=NaN;},
  f=>{f.s.extra='x'.repeat(262145);},f=>Object.defineProperty(f.seed.statements,'0',{get(){invoked++;return'anything';},enumerable:true})];
 for(const change of changes){const f=fixture();change(f);assert.throws(()=>project(f),rejected);}assert.equal(invoked,0);
});
