/** Separate one-attempt participant owner AFTER successful disposable bootstrap.
 * Fixed Linux/container paths. Private credentials remain in the fresh tmpfs.
 * Only aggregate JSON is emitted. Exact stdin commands control only this round.
 * No Docker/container/network attestation is implied by application readiness.
 */
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { createHash, randomBytes, X509Certificate } from 'node:crypto';
import { createRequire } from 'node:module';
import { spawn } from 'node:child_process';
import { connect } from 'node:net';
import { checkServerIdentity } from 'node:tls';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { validateFreshBootstrapResult } from '../fresh-bootstrap-result.mjs';

const ROOT = '/run/fncp/bootstrap';
const fail = () => new Error('FRESH_PARTICIPANT_RUNTIME_FAILED');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const equal = (a, b) => ['dev','ino','uid','gid','mode','nlink','size','mtimeMs','ctimeMs'].every(k => a[k] === b[k]);
function exact(value, names) {
  if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype ||
      Reflect.ownKeys(value).length !== names.length || names.some(k => !Object.hasOwn(value, k)) ||
      Object.values(Object.getOwnPropertyDescriptors(value)).some(v => !Object.hasOwn(v, 'value'))) throw fail();
  return value;
}
export function parseParticipantCommand(text) {
  if (typeof text !== 'string' || text.length > 64) throw fail();
  const value = exact(JSON.parse(text), ['action']);
  if (JSON.stringify(value) !== text || !['open','close','snapshot','stop'].includes(value.action)) throw fail();
  return value.action;
}
export function validateParticipantBootstrapReceipt(value) {
  const facts=['bootstrapPassed','apiChildExitVerified','apiIpcDisconnected','apiListenerRefused',
    'issuerClosed','jwksClosed','databaseWorkersClosed'];
  exact(value,['version',...facts]);
  if(value.version!==1||facts.some(key=>value[key]!==true))throw fail();
  return Object.freeze({...value});
}
export function validateParticipantLaunch(value) {
  exact(value, ['namespaceId','database','user','password','databaseCertificatePem','databaseCertificateSha256']);
  if (typeof value.namespaceId !== 'string' || !/^[a-f0-9]{24}$/u.test(value.namespaceId) ||
      !['database','user'].every(k => typeof value[k] === 'string' && /^fncp_fresh_[a-f0-9]{24}$/u.test(value[k])) ||
      typeof value.password !== 'string' || !/^[a-f0-9]{64}$/u.test(value.password) ||
      typeof value.databaseCertificatePem !== 'string' || Buffer.byteLength(value.databaseCertificatePem) > 8192 ||
      typeof value.databaseCertificateSha256 !== 'string' || !/^[a-f0-9]{64}$/u.test(value.databaseCertificateSha256)) throw fail();
  const cert = new X509Certificate(value.databaseCertificatePem);
  const host = `fncp-fresh-pg-${value.namespaceId}`;
  if (hash(cert.raw) !== value.databaseCertificateSha256 || cert.checkIP('127.0.0.1') !== '127.0.0.1' ||
      cert.checkHost(host, { subject: 'never', wildcards: false }) !== host ||
      Date.parse(cert.validFrom) > Date.now() || Date.parse(cert.validTo) <= Date.now() || !cert.verify(cert.publicKey)) throw fail();
  return Object.freeze({ ...value });
}
export function participantEnvironment(launch, provider, bootstrapBinding) {
  if (arguments.length !== 3) throw fail();
  validateParticipantLaunch(launch); exact(provider, ['conversationId','gatewaySecret','providerSecret']);
  exact(bootstrapBinding, ['conversationId','statementIds','seedOwnerPid']);
  validateFreshBootstrapResult({ conversationId: bootstrapBinding.conversationId, statementIds: bootstrapBinding.statementIds });
  if (bootstrapBinding.conversationId !== provider.conversationId || !Number.isSafeInteger(bootstrapBinding.seedOwnerPid) ||
      bootstrapBinding.seedOwnerPid < 0) throw fail();
  if (![provider.gatewaySecret,provider.providerSecret].every(v => typeof v === 'string' && /^[A-Za-z0-9_-]{43}$/u.test(v)) ||
      provider.gatewaySecret === provider.providerSecret) throw fail();
  const hostname = `fncp-fresh-api-${launch.namespaceId}:5500`;
  const url = `postgres://${launch.user}:${launch.password}@fncp-fresh-pg-${launch.namespaceId}:5432/${launch.database}`;
  return Object.freeze({ PATH:'/usr/bin:/bin', LANG:'C', LC_ALL:'C', NODE_ENV:'production', DEV_MODE:'false', TESTING:'false',
    ENABLE_TELEMETRY:'false', USE_NETWORK_HOST:'false', SHOULD_USE_TRANSLATION_API:'false', BACKFILL_COMMENT_LANG_DETECTION:'false',
    RUN_PERIODIC_EXPORT_TESTS:'false', SERVER_LOG_TO_FILE:'false', SERVER_LOG_LEVEL:'error', EMAIL_TRANSPORT_TYPES:'disabled',
    ADMIN_EMAILS:'[]', ADMIN_UIDS:'[]', API_SERVER_PORT:'5500', DATABASE_SSL:'true',
    DATABASE_SSL_CA_FILE:ROOT+'/postgres-cert.pem', DATABASE_URL:url, READ_ONLY_DATABASE_URL:url,
    API_PROD_HOSTNAME:hostname, DOMAIN_OVERRIDE:hostname, POLIS_JWT_ISSUER:`https://${hostname}/`,
    POLIS_JWT_AUDIENCE:'fncp-fresh-synthetic-participants', JWT_PRIVATE_KEY_PATH:ROOT+'/participant-private.pem',
    JWT_PUBLIC_KEY_PATH:ROOT+'/participant-public.pem', LOGIN_CODE_PEPPER:randomBytes(32).toString('hex'),
    ENCRYPTION_PASSWORD_00001:randomBytes(32).toString('hex'), FNCP_OPTION_C_RELEASE_MODE:'production',
    FNCP_FIXED_STATEMENT_IDS:bootstrapBinding.statementIds.join(','),
    FNCP_GATEWAY_ENFORCEMENT:'true', FNCP_GATEWAY_CONVERSATION_ID:provider.conversationId,
    FNCP_GATEWAY_SHARED_SECRET:provider.gatewaySecret, FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT:'true',
    FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID:provider.conversationId, FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL:provider.providerSecret });
}
async function readFixed(name, limit) {
  const path = ROOT+'/'+name, before = await lstat(path);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.uid !== 1000 ||
      (before.mode & 0o777) !== 0o600 || before.size < 1 || before.size > limit) throw fail();
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    if (!equal(before,await file.stat())) throw fail();
    const bytes = await file.readFile();
    if (bytes.length !== before.size || !equal(before,await file.stat()) || !equal(before,await lstat(path))) throw fail();
    return bytes;
  } finally { await file.close(); }
}
async function writeExclusive(name, value) {
  const file = await open(ROOT+'/'+name, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await file.writeFile(value); await file.sync(); } finally { await file.close(); }
}
const SNAPSHOT = `WITH target AS (SELECT c.* FROM public.conversations c JOIN public.zinvites z USING(zid) WHERE z.zinvite=$1)
 SELECT (SELECT count(*)::integer FROM target) AS target_rows,
 (SELECT is_active FROM target) AS open,
 (SELECT use_xid_whitelist AND xid_required AND NOT is_data_open AND strict_moderation AND NOT topics_enabled AND NOT treevite_enabled FROM target) AS gated,
 (SELECT count(*)::integer FROM public.comments c JOIN target t USING(zid)) AS seed_statements,
 (SELECT count(*)::integer FROM public.votes v JOIN target t USING(zid)) AS raw_votes,
 (SELECT count(*)::integer FROM public.votes_latest_unique v JOIN target t USING(zid)) AS latest_votes,
 (SELECT count(*)::integer FROM public.xid_whitelist w JOIN target t ON w.zid=t.zid OR (w.zid IS NULL AND w.owner=t.owner)) AS allowlist_rows,
 (SELECT count(*)::integer FROM public.fncp_provider_allowlist_operations o JOIN target t USING(zid) WHERE o.operation_version=2 AND NOT o.desired_present) AS terminal_identities`;
async function refused() {
  return new Promise(resolveRefused => {
    const socket = connect({host:'127.0.0.1',port:5500}); socket.setTimeout(1000);
    socket.once('connect',()=>{socket.destroy();resolveRefused(false);});
    socket.once('timeout',()=>{socket.destroy();resolveRefused(false);});
    socket.once('error',e=>resolveRefused(e.code==='ECONNREFUSED'));
  });
}
async function run() {
  let phase='PLATFORM', db, child, childExit, childCode, childReady=false, stopped=false, failed=false, binding, lastSnapshot;
  let closePromise, timer, buffer='', commands=0, chain=Promise.resolve(), currentControl;
  let finishStartup;
  const startupSettled = new Promise(resolveStartup => { finishStartup = resolveStartup; });
  const active = () => { if (stopped) throw fail(); };
  const emit = value => process.stdout.write(JSON.stringify(value)+'\n');
  const snapshot = async () => {
    const result = await db.query(SNAPSHOT,[binding.conversationId]);
    if (result.rows.length!==1) throw fail();
    const row=result.rows[0];
    if(row.target_rows!==1 || row.gated!==true || row.seed_statements!==15 || typeof row.open!=='boolean' ||
      !['raw_votes','latest_votes','allowlist_rows','terminal_identities'].every(k=>Number.isSafeInteger(row[k])&&row[k]>=0)) throw fail();
    lastSnapshot={open:row.open,gated:row.gated,seedStatements:row.seed_statements,rawVotes:row.raw_votes,
      latestVotes:row.latest_votes,allowlistRows:row.allowlist_rows,terminalIdentities:row.terminal_identities};
    return lastSnapshot;
  };
  const setOpen = async value => {
    if (value) await snapshot();
    const result=await db.query(`UPDATE public.conversations c SET is_active=$2 FROM public.zinvites z
      WHERE z.zid=c.zid AND z.zinvite=$1 AND (NOT $2 OR (c.use_xid_whitelist AND c.xid_required AND NOT c.is_data_open)) RETURNING c.is_active`,[binding.conversationId,value]);
    if(result.rowCount!==1 || result.rows[0].is_active!==value) throw fail();
    const resultSnapshot=await snapshot(); if(resultSnapshot.open!==value) throw fail(); return resultSnapshot;
  };
  const close = (error=false) => {
    failed ||= error;
    if(closePromise) return closePromise;
    stopped=true; clearTimeout(timer); process.stdin.pause();
    closePromise=(async()=>{
      // Cancellation latches first; wait for construction to settle so cleanup
      // cannot report completion before a late child/database handle exists.
      await startupSettled;
      let roundClosed=false, listenerRefused=false, dbClosed=false;
      if(child) {
        try { if(child.connected) child.send({type:'stop'}); else child.kill('SIGTERM'); } catch {child.kill('SIGTERM');}
        const kill=setTimeout(()=>child.kill('SIGKILL'),3000);
        await childExit;clearTimeout(kill);if(childCode!==0) failed=true;
      }
      try { await currentControl; } catch { failed=true; }
      // The app has stopped admitting work before the database closure. Even
      // gate drift must not prevent an attempted close of this exact round.
      try { if(db&&binding){await setOpen(false);roundClosed=true;} } catch {failed=true;}
      try {listenerRefused=await refused();if(!listenerRefused)failed=true;}catch{failed=true;}
      try{if(db)await db.end();dbClosed=true;}catch{failed=true;}
      emit({event:'CLOSED',outcome:failed?'FAIL':'PASS',ok:!failed,phase,
        childExitVerified:!!child&&childCode===0,listenerRefused,databaseClientClosed:dbClosed,roundClosed,
        snapshot:lastSnapshot??null,containersStopped:false,productionReady:false});
      process.exitCode=failed?1:0;process.stdin.destroy();
    })(); return closePromise;
  };
  process.once('SIGTERM',()=>void close());process.once('SIGINT',()=>void close(true));
  process.stdin.once('end',()=>void chain.then(()=>close()));
  process.stdin.once('error',()=>void close(true));
  try {
    if(process.platform!=='linux'||process.getuid?.()!==1000||process.argv.length!==2||process.execArgv.length!==0)throw fail();
    const directory=await lstat(ROOT);
    active();
    if(!directory.isDirectory()||directory.isSymbolicLink()||directory.uid!==1000||(directory.mode&0o777)!==0o700||await realpath(ROOT)!==ROOT)throw fail();
    phase='FRESH_BOOTSTRAP_HANDOFF';
    const launch=validateParticipantLaunch(JSON.parse(await readFixed('launch.json',16384)));
    active();
    binding=JSON.parse(await readFixed('binding.json',4096));exact(binding,['statementIds','conversationId','seedOwnerPid']);
    validateFreshBootstrapResult({conversationId:binding.conversationId,statementIds:binding.statementIds});
    if(!Number.isSafeInteger(binding.seedOwnerPid)||binding.seedOwnerPid<0)throw fail();
    const journal=(await readFixed('attempt.jsonl',32768)).toString('utf8').trim().split('\n').map(line=>JSON.parse(line));
    const last=journal.at(-1);
    if(!journal.some(row=>row.event==='EXACT_CLOSED_BASELINE_MATCHED')||last?.event!=='LOCAL_COMPONENT_CLOSE_CALLS_SETTLED'||
      last.knownCloseCallsFulfilled!==true||last.factoriesWithoutReturnedCleanupEvidence!==0||!(await refused()))throw fail();
    active();
    // The journal's close-call settlement is not proof of independently observed
    // exit, IPC and listener shutdown. The external owner writes this exclusive
    // private receipt only after accepting the bootstrap's final aggregate.
    validateParticipantBootstrapReceipt(JSON.parse(await readFixed('bootstrap-finalized.json',2048)));
    active();
    const cert=(await readFixed('postgres-cert.pem',8192)).toString('utf8');
    if(cert!==launch.databaseCertificatePem)throw fail();
    active();
    // Exclusive marker prevents resumption or reuse after any uncertain attempt.
    await writeExclusive('participant-attempt.json',JSON.stringify({mode:'FRESH_SYNTHETIC_ONLY',attempt:1})+'\n');
    active();
    const provider={conversationId:binding.conversationId,gatewaySecret:randomBytes(32).toString('base64url'),providerSecret:randomBytes(32).toString('base64url')};
    const environment=participantEnvironment(launch,provider,binding);
    await writeExclusive('participant-provider.json',JSON.stringify(provider)+'\n');
    active();
    const require=createRequire('/opt/fncp/server/dist/app.js');
    const {Client}=require('/opt/fncp/server/node_modules/pg');
    const host=`fncp-fresh-pg-${launch.namespaceId}`;
    db=new Client({host,port:5432,database:launch.database,user:launch.user,password:launch.password,
      ssl:{ca:cert,rejectUnauthorized:true,minVersion:'TLSv1.2',servername:host,checkServerIdentity:(_name,peer)=>
        checkServerIdentity(host,peer)||(!peer.raw||hash(peer.raw)!==launch.databaseCertificateSha256?fail():undefined)},
      connectionTimeoutMillis:2000,query_timeout:4000,options:'-c statement_timeout=3000 -c lock_timeout=1000'});
    db.on('error',()=>void close(true));
    phase='BASELINE';await db.connect();const initial=await snapshot();
    active();
    if(initial.open||initial.rawVotes!==15||initial.latestVotes!==15||initial.allowlistRows!==0||initial.terminalIdentities!==0)throw fail();
    phase='APP_START';
    child=spawn('/usr/local/bin/node',['/opt/fncp/deploy/fncp/fresh-runtime/participant-child.mjs'],
      {cwd:'/app',env:environment,stdio:['ignore','ignore','ignore','ipc'],shell:false});
    childExit=new Promise(resolveExit=>{
      child.once('exit',code=>{childCode=code;resolveExit();if(!stopped)void close(true);});
      // Failed spawn need not emit exit. It supplies no successful exit evidence,
      // but still releases cleanup rather than leaving an unbounded owner wait.
      child.once('error',()=>{resolveExit();if(!stopped)void close(true);});
    });
    await new Promise((resolveReady,rejectReady)=>{
      const deadline=setTimeout(()=>rejectReady(fail()),15000);
      child.once('error',()=>{clearTimeout(deadline);rejectReady(fail());});
      child.once('exit',()=>{clearTimeout(deadline);rejectReady(fail());});
      child.once('message',message=>{
        clearTimeout(deadline);
        if(!message||Object.keys(message).sort().join()!=='actualPolis,loopbackPort,type'||message.type!=='PARTICIPANT_CHILD_READY'||
          message.loopbackPort!==5500||message.actualPolis!==true)rejectReady(fail());else{childReady=true;resolveReady();}
      });
    });
    if(stopped||!childReady)throw fail();
    phase='READY';timer=setTimeout(()=>void close(true),540000);
    emit({event:'READY',outcome:'PASS',ok:true,actualPolis:true,loopbackPort:5500,roundOpen:false,
      databaseTlsVerified:true,syntheticOnly:true,productionReady:false,snapshot:initial});
    process.stdin.setEncoding('utf8');
    process.stdin.on('data',chunk=>{
      if(stopped)return;buffer+=chunk;
      if(buffer.length>1024){void close(true);return;}
      while(buffer.includes('\n')){
        const at=buffer.indexOf('\n'),line=buffer.slice(0,at);buffer=buffer.slice(at+1);
        chain=chain.then(async()=>{
          if(stopped)return;if(++commands>32)throw fail();const action=parseParticipantCommand(line);
          if(action==='stop'){await close();return;}
          phase='CONTROL_'+action.toUpperCase();
          currentControl=action==='snapshot'?snapshot():setOpen(action==='open');
          let state;
          try {state=await currentControl;} finally {currentControl=undefined;}
          if(stopped)return;
          emit({event:'CONTROL',action,outcome:'PASS',ok:true,snapshot:state});phase='READY';
        }).catch(()=>close(true));
      }
    });
    process.stdin.resume();
    finishStartup();
  } catch {finishStartup();await close(true);}
}
if(process.argv[1]&&pathToFileURL(resolve(process.argv[1])).href===import.meta.url){
  run().catch(()=>{process.stdout.write('{"event":"CLOSED","outcome":"FAIL","ok":false,"phase":"FINALIZATION"}\n');process.exitCode=1;});
}
