/** Local synthetic data only. Closed, quiescent three-store encrypted recovery proof. */
import { execFileSync, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { DatabaseSync, backup } from 'node:sqlite';
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual, parseEnv } from 'node:util';
import { aggregateQuery, validateAggregate, validateConfiguration, validateSourceContainer, CONTEXT, classifyFailure } from './recovery-proof.mjs';
import { MODE, STORES, binding, canonical, eventDigest, seal, sha256, signManifest, unseal, validateConsistency, verifyManifest } from './coordinated-contract.mjs';
import { createLocalAccess } from '../local-access/access-server.mjs';

const ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const DEPLOY = resolve(ROOT, 'deploy/fncp');
const COMPOSE = resolve(DEPLOY, 'docker-compose.staging.yml');
const WP_COMPOSE = resolve(DEPLOY, 'local-wordpress-runtime/compose.yml');
const ENV = resolve(DEPLOY, '.env.staging');
const SQLITE = resolve(DEPLOY, 'local-access/.runtime/synthetic.sqlite');
const RUNTIME = resolve(DEPLOY, 'local-recovery/.runtime');
const LABEL = 'org.barayamal.fncp.coordinated-recovery-run';
const ID = /^[a-f0-9]{64}$/u;
const MYSQL_IMAGE = 'sha256:85b9bf2e29cf836ecb8c2a15a935d4ba0c606631dff1dd79531a11983c638f2a';
const PG_IMAGE = 'sha256:9d9684f7a95e94c9eb370212edea832e7b9916b7bd96b2821c5bc9cf63a0e8b3';
const WP_DB = 'fncp_wp_synthetic';
const PG_RESTORE_DB = 'fncp_coordinated_restore';
const WP_RESTORE_DB = 'fncp_wp_coordinated_restore';
const PG_RESTORE_ROLE = 'fncp_restore_owner';
const WP_TABLES = ['commentmeta','comments','links','options','postmeta','posts','term_relationships','term_taxonomy','termmeta','terms','usermeta','users'].map(name => 'synthetic_' + name);
const ACCESS_TABLES = ['approvals','fixtures','invitations','round','sessions','wordpress_events'];
const requireThat = (ok) => { if (!ok) throw new Error('Coordinated synthetic recovery boundary failed.'); };
const same = (left, right) => requireThat(isDeepStrictEqual(left, right));
const sqlString = value => "'" + value.replaceAll("'", "''") + "'";
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

function docker(args, options = {}) {
  return execFileSync('docker', ['--context', CONTEXT, ...args], { encoding: 'utf8',
    stdio: ['pipe','pipe','pipe'], timeout: 30000, maxBuffer: 64 * 1024 * 1024, ...options });
}
function inspect(id) {
  requireThat(ID.test(id));
  return JSON.parse(docker(['inspect', '--type', 'container', '--format',
    '{"Id":{{json .Id}},"Image":{{json .Image}},"Running":{{json .State.Running}},"Labels":{{json .Config.Labels}},"Tmpfs":{{json (index .HostConfig "Tmpfs")}},"Ports":{{json .HostConfig.PortBindings}},"Networks":{{json .NetworkSettings.Networks}},"Mounts":{{json .Mounts}}}', id]));
}
function network(id) { requireThat(ID.test(id)); return JSON.parse(docker(['network','inspect','--format','{{json .}}',id])); }
function pg(id, config, sql) {
  return docker(['exec','-i',id,'psql','-X','-A','-t','-v','ON_ERROR_STOP=1','-U',config.role,'-d',config.database], { input: sql }).trim();
}
function mysql(id, sql, restored = false) {
  const args = restored ? ['mysql','--batch','--raw','--skip-column-names','-u','root',WP_RESTORE_DB] :
    ['sh','-c','MYSQL_PWD="$(cat /run/secrets/db-password)" exec mysql --batch --raw --skip-column-names -u fncp_wp_synthetic fncp_wp_synthetic'];
  return docker(['exec','-i',id,...args], {input: sql}).trim();
}

export function validateWordPressSource(info) {
  const bindings = info.Ports?.['3306/tcp'];
  requireThat(ID.test(info.Id ?? '') && info.Running && info.Image === MYSQL_IMAGE &&
    info.Labels?.['com.docker.compose.project'] === 'fncp-wordpress-synthetic' &&
    info.Labels?.['com.docker.compose.service'] === 'db' &&
    info.Labels?.['org.barayamal.fncp.purpose'] === 'synthetic-wordpress-only' &&
    info.Labels?.['com.docker.compose.project.config_files'] === WP_COMPOSE &&
    Object.keys(info.Ports ?? {}).length === 1 && bindings?.length === 1 &&
    bindings[0].HostIp === '127.0.0.1' && bindings[0].HostPort === '33079' &&
    Object.keys(info.Networks ?? {}).length === 1 && info.Mounts?.length === 3);
  requireThat(info.Mounts.some(m => m.Type === 'volume' && m.Name === 'fncp-wordpress-synthetic_wp-synthetic-db' && m.Destination === '/var/lib/mysql'));
  for (const name of ['db-password','root-password']) requireThat(info.Mounts.some(m =>
    m.Type === 'bind' && !m.RW && m.Source === resolve(DEPLOY, 'local-wordpress-runtime/.runtime', name) && m.Destination === '/run/secrets/' + name));
}

function noOpenFile(path) {
  const result = spawnSync('lsof', ['-t', path], {encoding:'utf8',stdio:['ignore','pipe','pipe'],timeout:5000});
  requireThat(!result.error && result.status === 1 && !result.stdout.trim());
}
function quiescent(sourcePg, sourceWp, extras = [], ownSqlite = false) {
  same(docker(['ps','-q','--no-trunc']).trim().split('\n').filter(Boolean).sort(), [sourcePg,sourceWp,...extras].sort());
  for (const port of [8099,8100,8101,8102]) {
    const result = spawnSync('lsof', ['-nP', `-iTCP:${port}`, '-sTCP:LISTEN', '-t'], {encoding:'utf8',stdio:['ignore','pipe','pipe'],timeout:5000});
    requireThat(!result.error && result.status === 1 && !result.stdout.trim());
  }
  if (!ownSqlite) noOpenFile(SQLITE);
  for (const suffix of ['-wal','-shm','-journal']) requireThat(!existsSync(SQLITE + suffix));
}
function privateDirectory(path, fresh = false) {
  if (fresh) mkdirSync(path, {mode:0o700}); else if (!existsSync(path)) mkdirSync(path, {recursive:true,mode:0o700});
  requireThat(lstatSync(path).isDirectory() && !lstatSync(path).isSymbolicLink()); chmodSync(path,0o700);
}
function privateFile(path, value) { writeFileSync(path, value, {flag:'wx',mode:0o600}); }
function readPrivate(path) { const stat=lstatSync(path); requireThat(stat.isFile() && !stat.isSymbolicLink() && (stat.mode & 0o777) === 0o600); return readFileSync(path); }

export function accessSnapshot(db, conversation) {
  const schema = db.prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").all();
  same(schema.filter(row=>row.type==='table').map(row=>row.name).sort(),ACCESS_TABLES);
  requireThat(db.prepare('PRAGMA integrity_check').get().integrity_check === 'ok' && db.prepare('PRAGMA foreign_key_check').all().length === 0);
  const details = { rounds: db.prepare('SELECT * FROM round ORDER BY id').all(), fixtures: db.prepare('SELECT * FROM fixtures ORDER BY id').all(),
    approvals: db.prepare('SELECT * FROM approvals ORDER BY fixture').all(), invitations: db.prepare('SELECT * FROM invitations ORDER BY token_hash').all(),
    sessions: db.prepare('SELECT * FROM sessions ORDER BY token_hash').all(), events: db.prepare('SELECT * FROM wordpress_events ORDER BY event_id').all() };
  requireThat(details.rounds.length === 1 && details.rounds[0].id === conversation && details.rounds[0].open === 0);
  return { details, aggregates: { schemaObjects:schema.length,schemaHash:sha256(canonical(schema)),rowCounts:Object.fromEntries(Object.entries(details).map(([key,rows])=>[key,rows.length])),
    integrityCheck:'ok',foreignKeyViolations:0,closedRounds:1,contentHash:sha256(canonical(details)) } };
}

function pgSnapshot(id, config, seeds) {
  const aggregate = JSON.parse(pg(id,config,aggregateQuery(config.conversation,seeds))); validateAggregate(aggregate);
  const extra = JSON.parse(pg(id,config,`SELECT json_build_object(
    'whitelist',(SELECT count(*) FROM xid_whitelist),
    'unscopedOperations',(SELECT count(*) FROM fncp_provider_allowlist_operations o WHERE NOT EXISTS(SELECT 1 FROM zinvites z WHERE z.zid=o.zid AND z.zinvite=${sqlString(config.conversation)})),
    'whitelistEnforced',(SELECT count(*) FROM conversations WHERE use_xid_whitelist IS TRUE),
    'distinctFixedSeedTexts',(SELECT count(DISTINCT txt) FROM comments WHERE is_seed IS TRUE AND active IS TRUE),
    'distinctFixedSeedTids',(SELECT count(DISTINCT tid) FROM comments WHERE is_seed IS TRUE AND active IS TRUE),
    'otherConnections',(SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND backend_type='client backend'))`));
  same(extra,{whitelist:0,unscopedOperations:0,whitelistEnforced:1,distinctFixedSeedTexts:15,distinctFixedSeedTids:15,otherConnections:0});
  const operations=JSON.parse(pg(id,config,"SELECT COALESCE(json_agg(o ORDER BY xid),'[]'::json) FROM (SELECT xid,operation_version,desired_present FROM fncp_provider_allowlist_operations) o"));
  const tables=JSON.parse(pg(id,config,"SELECT json_agg(table_name ORDER BY table_name) FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE'"));
  requireThat(tables.length>0 && tables.every(name=>/^[a-z][a-z0-9_]*$/u.test(name)));
  // PostgreSQL functions accept at most 100 arguments: aggregate rows instead
  // of passing two arguments per table (this schema already has 62 tables).
  const rowCounts=JSON.parse(pg(id,config,'SELECT json_object_agg(name,n) FROM (' + tables.map(name=>`SELECT ${sqlString(name)} AS name,count(*) AS n FROM "${name}"`).join(' UNION ALL ') + ') counted'));
  const schema=pg(id,config,`SELECT json_build_object('columns',(SELECT json_agg(r ORDER BY table_name,ordinal_position) FROM (SELECT table_name,column_name,ordinal_position,data_type,udt_name,is_nullable,column_default FROM information_schema.columns WHERE table_schema='public') r),
    'indexes',(SELECT json_agg(r ORDER BY tablename,indexname) FROM (SELECT tablename,indexname,indexdef FROM pg_indexes WHERE schemaname='public') r))`);
  return { operations, aggregates:{...aggregate,...extra,rowCounts,schemaHash:sha256(schema),tombstoneHash:sha256(canonical(operations))} };
}

function wpSnapshot(id, restored=false) {
  const database=restored?WP_RESTORE_DB:WP_DB;
  if(!restored) requireThat(docker(['exec','-i',id,'sh','-c','MYSQL_PWD="$(cat /run/secrets/root-password)" exec mysql --batch --raw --skip-column-names -u root'],{input:"SELECT count(*) FROM information_schema.processlist WHERE ID<>CONNECTION_ID() AND USER IN ('fncp_wp_synthetic','root');"}).trim()==='0');
  const tables=JSON.parse(mysql(id,`SELECT JSON_ARRAYAGG(TABLE_NAME) FROM information_schema.tables WHERE table_schema='${database}'`,restored)).sort(); same(tables, [...WP_TABLES].sort());
  const values=JSON.parse(mysql(id,`SELECT JSON_OBJECT(
    'nonInnoDB',(SELECT count(*) FROM information_schema.tables WHERE table_schema='${database}' AND ENGINE<>'InnoDB'),
    'users',(SELECT count(*) FROM synthetic_users),'knownUsers',(SELECT count(*) FROM synthetic_users WHERE (user_login='synthetic_admin' AND user_email='synthetic_admin@example.test') OR (user_login='synthetic_wp_subscriber' AND user_email='')),
    'siteMatches',(SELECT count(*) FROM synthetic_options WHERE option_name IN ('siteurl','home') AND option_value='http://127.0.0.1:8102'),
    'registrationDisabled',(SELECT count(*) FROM synthetic_options WHERE option_name='users_can_register' AND option_value='0'),
    'publicDisabled',(SELECT count(*) FROM synthetic_options WHERE option_name='blog_public' AND option_value='0'),
    'pluginsDisabled',(SELECT count(*) FROM synthetic_options WHERE option_name='active_plugins' AND option_value='a:0:{}'),
    'attachments',(SELECT count(*) FROM synthetic_posts WHERE post_type='attachment'),
    'posts',(SELECT count(*) FROM synthetic_posts),
    'stockPostScope',(SELECT count(*) FROM synthetic_posts WHERE (post_type='post' AND post_name='hello-world' AND post_status='publish') OR (post_type='page' AND post_name='sample-page' AND post_status='publish') OR (post_type='page' AND post_name='privacy-policy' AND post_status='draft') OR (post_type='wp_navigation' AND post_name='navigation' AND post_status='publish') OR (post_type='post' AND post_name='' AND post_status='auto-draft' AND post_content='')),
    'comments',(SELECT count(*) FROM synthetic_comments),
    'stockComments',(SELECT count(*) FROM synthetic_comments WHERE comment_author='A WordPress Commenter' AND comment_author_email='wapuu@wordpress.example'),
    'journalRows',(SELECT count(*) FROM synthetic_options WHERE option_name='fncp_wp_local_journal_v1'))`,restored));
  same(values,{nonInnoDB:0,users:2,knownUsers:2,siteMatches:2,registrationDisabled:1,publicDisabled:1,pluginsDisabled:1,attachments:0,posts:5,stockPostScope:5,comments:1,stockComments:1,journalRows:1});
  const rowCounts=JSON.parse(mysql(id,'SELECT JSON_OBJECT(' + tables.map(name=>`'${name}',(SELECT count(*) FROM ${name})`).join(',') + ')',restored));
  const schema=mysql(id,`SELECT TABLE_NAME,COLUMN_NAME,ORDINAL_POSITION,COLUMN_TYPE,IS_NULLABLE,COALESCE(COLUMN_DEFAULT,'<NULL>'),EXTRA FROM information_schema.columns WHERE table_schema='${database}' ORDER BY TABLE_NAME,ORDINAL_POSITION`,restored);
  const indexes=mysql(id,`SELECT TABLE_NAME,INDEX_NAME,NON_UNIQUE,SEQ_IN_INDEX,COLUMN_NAME,COALESCE(SUB_PART,0) FROM information_schema.statistics WHERE table_schema='${database}' ORDER BY TABLE_NAME,INDEX_NAME,SEQ_IN_INDEX`,restored);
  const journal=JSON.parse(mysql(id,"SELECT option_value FROM synthetic_options WHERE option_name='fncp_wp_local_journal_v1'",restored));
  return { journal,aggregates:{...values,rowCounts,schemaHash:sha256(schema+'\n'+indexes),journalHash:sha256(canonical(journal))} };
}

export function restoreArguments(store, run, networkId, image) {
  requireThat(['postgres','mysql'].includes(store) && /^[a-f0-9]{24}$/u.test(run) && ID.test(networkId) && image === (store==='postgres'?PG_IMAGE:MYSQL_IMAGE));
  const data=store==='postgres'?'/var/lib/postgresql/data':'/var/lib/mysql';
  const args=['create','--pull=never','--name',`fncp-coordinated-${store}-${run}`,'--label',`${LABEL}=${run}`,'--network',networkId,
    '--restart=no','--memory=1200m','--pids-limit=256','--tmpfs',`${data}:rw,nosuid,nodev,size=768m`,'--tmpfs','/docker-entrypoint-initdb.d:ro,nosuid,nodev,size=1m'];
  if(store==='postgres')args.push('--env','POSTGRES_HOST_AUTH_METHOD=trust','--env',`POSTGRES_DB=${PG_RESTORE_DB}`,'--env',`POSTGRES_USER=${PG_RESTORE_ROLE}`);
  else args.push('--env','MYSQL_ALLOW_EMPTY_PASSWORD=yes','--env',`MYSQL_DATABASE=${WP_RESTORE_DB}`);
  return [...args,image];
}

export function validateRestoreTarget(info, store, run, networkId, sources, beforeStart=false) {
  const data=store==='postgres'?'/var/lib/postgresql/data':'/var/lib/mysql';
  const attached=Object.values(info.Networks??{});
  const networkMatches=attached.length===1 && (attached[0].NetworkID===networkId ||
    (beforeStart && !info.Running && attached[0].NetworkID==='' && Object.keys(info.Networks)[0]==='fncp-coordinated-'+run));
  // This Docker daemon omits HostConfig.Tmpfs mounts from .Mounts even after
  // start. Require the exact configuration here AND actual /proc mounts below.
  const configuredTmpfs=info.Mounts?.length===0&&isDeepStrictEqual(info.Tmpfs,
    {[data]:'rw,nosuid,nodev,size=768m','/docker-entrypoint-initdb.d':'ro,nosuid,nodev,size=1m'});
  const mounted=info.Mounts?.length===2&&info.Mounts.every(m=>m.Type==='tmpfs')&&info.Mounts.some(m=>m.Destination===data)&&info.Mounts.some(m=>m.Destination==='/docker-entrypoint-initdb.d');
  requireThat(['postgres','mysql'].includes(store) && ID.test(info.Id ?? '') && !sources.includes(info.Id) &&
    info.Image===(store==='postgres'?PG_IMAGE:MYSQL_IMAGE) && info.Labels?.[LABEL]===run &&
    Object.keys(info.Ports??{}).length===0 && networkMatches && (configuredTmpfs||mounted));
}

export function validateRuntimeMounts(text, store) {
  requireThat(['postgres','mysql'].includes(store));
  const data=store==='postgres'?'/var/lib/postgresql/data':'/var/lib/mysql';
  const rows=text.trim().split('\n').map(line=>line.split(' '));
  for(const [path,access] of [[data,'rw'],['/docker-entrypoint-initdb.d','ro']]) {
    const matching=rows.filter(row=>row[1]===path);
    requireThat(matching.length===1&&matching[0][2]==='tmpfs');
    for(const flag of [access,'nosuid','nodev'])requireThat(matching[0][3].split(',').includes(flag));
  }
}

async function ready(id, kind) {
  for(let attempt=0;attempt<90;attempt++) {
    try { if(kind==='postgres') docker(['exec',id,'pg_isready','-h','127.0.0.1','-U',PG_RESTORE_ROLE,'-d',PG_RESTORE_DB]);
      else requireThat(docker(['exec',id,'mysql','--protocol=TCP','-h','127.0.0.1','-u','root','--batch','--skip-column-names','-e','SELECT 1']).trim()==='1');
      return;
    } catch { await delay(500); }
  }
  throw new Error('Isolated restore database unavailable.');
}

/** Restored data first remains unchanged. A SECOND fresh SQLite copy receives
 * stale-authority test rows to prove revocation wins even over valid warm tokens. */
export function assertAdversarialCopy(path, run) {
  requireThat(/^[a-f0-9]{24}$/u.test(run ?? '') && path===resolve(RUNTIME,'coordinated-work-'+run,'adversarial.sqlite'));
  const directory=resolve(RUNTIME,'coordinated-work-'+run);
  requireThat(lstatSync(directory).isDirectory() && !lstatSync(directory).isSymbolicLink());
  const target=lstatSync(path);requireThat(target.isFile()&&!target.isSymbolicLink()&&(target.mode&0o777)===0o600);
  if(existsSync(SQLITE)){const source=lstatSync(SQLITE);requireThat(realpathSync(path)!==realpathSync(SQLITE) && !(target.dev===source.dev&&target.ino===source.ino));}
}
export async function denyOldAuthority(path, conversation, journal, run) {
  assertAdversarialCopy(path,run);
  let calls=0; const provider={allowlist:async()=>{calls++;throw new Error('No provider access allowed.');},participate:async()=>{calls++;throw new Error('No provider access allowed.');}};
  const db=new DatabaseSync(path); const fixtures=db.prepare('SELECT id FROM fixtures ORDER BY id').all();
  const oldToken=randomBytes(32).toString('base64url'); const authToken=randomBytes(32).toString('base64url'); const invitation=randomBytes(32).toString('base64url');
  // Adversarial stale rows exist ONLY in the second fresh restore-test copy.
  db.prepare('INSERT INTO sessions VALUES(?,?,?,?,?)').run(sha256(oldToken),fixtures[0].id,conversation,'participation',Date.now()+60000);
  db.prepare('INSERT INTO sessions VALUES(?,?,?,?,?)').run(sha256(authToken),fixtures[0].id,conversation,'fixture-auth',Date.now()+60000);
  db.prepare('INSERT INTO invitations VALUES(?,?,?,?,0)').run(sha256(invitation),fixtures[0].id,conversation,Date.now()+60000);
  db.close();
  const adminSecret=randomBytes(32).toString('base64url');
  const app=createLocalAccess({mode:'fixture-only',dbPath:path,conversationId:conversation,adminSecret,provider});
  try {
    const origin=await app.listen(0);
    const request=async(path,token,body)=>{const response=await fetch(origin+path,{method:body===undefined?'GET':'POST',redirect:'error',signal:AbortSignal.timeout(5000),
      headers:{Authorization:`Bearer ${token}`,...(body===undefined?{}:{'Content-Type':'application/json'})},...(body===undefined?{}:{body:canonical(body)})}); await response.arrayBuffer();return response.status;};
    requireThat(await request('/polis/participation-init',oldToken)===403);
    requireThat(await request('/invitations/redeem',authToken,{invitationToken:invitation})===403);
    requireThat(await request('/test-admin/approve',adminSecret,{fixture:fixtures[0].id})===409);
    for(const record of Object.values(journal.events).filter(record=>record.event.state==='approved')) {
      requireThat((await app.ingestWordPressEvent(record.event)).outcome==='STALE_NO_OP');
    }
    requireThat(calls===0);
    return {validOldWarmSessionDenied:true,validUnusedOldInvitationDenied:true,terminalReapprovalDenied:true,staleApprovalReplaysDenied:3,providerCalls:0,adversarialRowsOnlyInSecondRestoreCopy:true};
  } finally { await app.close(); }
}

export async function runCoordinated(mode=process.env.FNCP_COORDINATED_RECOVERY_MODE) {
  process.umask(0o077); let phase='explicit-mode'; const run=randomBytes(12).toString('hex');
  let dir,work,key,sourceDb,sourcePg,sourceWp,createdNetwork; const created=[]; let before,after,restored,denial; let cleanup=true; let passed=false; let failureCode=null;
  let retainedComponentCount=0; let backupsAuthenticated=false; let keyRetained=false;
  try {
    requireThat(mode===MODE);
    const config=validateConfiguration(parseEnv(readFileSync(ENV,'utf8')),'synthetic-local-restore-proof',existsSync(resolve(DEPLOY,'.synthetic-bootstrap-restart')));
    const seeds=JSON.parse(readFileSync(resolve(DEPLOY,'seed-statements.json'),'utf8'));
    sourcePg=docker(['compose','--project-name',config.project,'--env-file',ENV,'-f',COMPOSE,'ps','-q','postgres']).trim();
    sourceWp=docker(['compose','-f',WP_COMPOSE,'ps','-q','db']).trim();
    phase='exact-source-and-quiescence';
    const pgInfo=inspect(sourcePg);validateSourceContainer(pgInfo,config,COMPOSE); requireThat(pgInfo.Image===PG_IMAGE);
    requireThat(pgInfo.Mounts.length===1 && pgInfo.Mounts[0].Type==='volume' && pgInfo.Mounts[0].Name==='fncp-polis-staging_fncp-postgres');
    const wpInfo=inspect(sourceWp); validateWordPressSource(wpInfo);
    const pgNet=network(Object.values(pgInfo.Networks)[0].NetworkID); requireThat(pgNet.Internal && pgNet.Labels?.['com.docker.compose.project']===config.project);
    const wpNet=network(Object.values(wpInfo.Networks)[0].NetworkID); requireThat(wpNet.Labels?.['com.docker.compose.project']==='fncp-wordpress-synthetic' && wpNet.Options?.['com.docker.network.bridge.enable_icc']==='false');
    quiescent(sourcePg,sourceWp);
    readPrivate(SQLITE);
    sourceDb=new DatabaseSync(SQLITE,{readOnly:true}); sourceDb.exec('BEGIN');
    const snapshot=()=>{const access=accessSnapshot(sourceDb,config.conversation);const polis=pgSnapshot(sourcePg,config,seeds);const wp=wpSnapshot(sourceWp);
      return {details:{access:access.details,operations:polis.operations,journal:wp.journal},aggregate:{access:access.aggregates,polis:polis.aggregates,wordpress:wp.aggregates,consistency:validateConsistency(wp.journal,access.details,polis.operations)}};};
    phase='three-store-synthetic-scope'; before=snapshot();
    // Read-only source transaction holds SQLite stable, while every known writer is stopped.
    const sourceHash=sha256(readFileSync(SQLITE));
    const scope={classification:'SYNTHETIC_LOCAL_THREE_STORE_ONLY',context:CONTEXT,wordpressDatabase:WP_DB,wordpressSite:'http://127.0.0.1:8102',
      accessFile:'local-access/.runtime/synthetic.sqlite',polisDatabase:config.database,conversationHash:sha256(config.conversation),
      sourceImages:{postgres:pgInfo.Image,mysql:wpInfo.Image},containsSyntheticAuthenticationHashes:true,
      equivalence:'all-table row counts and selected schema metadata; exact approval/event/tombstone metadata; not byte-for-byte database equivalence',
      excluded:['live-wordpress','registration-12064-12069','real-participants','new-identity-or-activation-ledger','application-files','external-credential-files','offsite-disaster-recovery']};
    const scopeHash=sha256(canonical(scope));
    privateDirectory(RUNTIME);dir=resolve(RUNTIME,'coordinated-'+run);privateDirectory(dir,true);
    privateDirectory(resolve(RUNTIME,'coordinated-keys'));key=randomBytes(32);privateFile(resolve(RUNTIME,'coordinated-keys',run+'.key'),key);keyRetained=true;
    work=resolve(RUNTIME,'coordinated-work-'+run);privateDirectory(work,true);
    phase='coordinated-read-only-snapshots';
    const components={};
    const retain=(store,bytes)=>{components[store]=seal(bytes,key,binding(run,store,scopeHash));privateFile(resolve(dir,store+'.aesgcm'),components[store]);retainedComponentCount++;bytes.fill(0);};
    retain('polis-postgresql',docker(['exec',sourcePg,'pg_dump','--format=custom','--no-owner','--no-acl','-U',config.role,'-d',config.database],{encoding:'buffer'}));
    retain('wordpress-mysql',docker(['exec',sourceWp,'sh','-c','MYSQL_PWD="$(cat /run/secrets/db-password)" exec mysqldump --single-transaction --quick --skip-lock-tables --no-tablespaces --set-gtid-purged=OFF --skip-add-locks --skip-add-drop-table --skip-dump-date --hex-blob -u fncp_wp_synthetic fncp_wp_synthetic'],{encoding:'buffer'}));
    const sqliteCopy=resolve(work,'snapshot.sqlite'); await backup(sourceDb,sqliteCopy);chmodSync(sqliteCopy,0o600);
    retain('access-sqlite',readPrivate(sqliteCopy));unlinkSync(sqliteCopy);
    quiescent(sourcePg,sourceWp,[],true); after=snapshot();same(before.aggregate,after.aggregate);same(sourceHash,sha256(readFileSync(SQLITE)));
    sourceDb.exec('ROLLBACK'); sourceDb.close();sourceDb=null;
    const manifest={version:1,mode:MODE,run,recordedAt:new Date().toISOString(),scope,scopeHash,source:before.aggregate,
      components:Object.fromEntries(STORES.map(store=>[store,{filename:store+'.aesgcm',bytes:components[store].length,sha256:sha256(components[store]),mode:'600'}]))};
    privateFile(resolve(dir,'manifest.json'),canonical(signManifest(manifest,key))+'\n');
    // Independent disk re-read authenticates exact set, bytes and scope before any target exists.
    const onDisk=Object.fromEntries(STORES.map(store=>[store,readPrivate(resolve(dir,store+'.aesgcm'))]));
    verifyManifest(JSON.parse(readPrivate(resolve(dir,'manifest.json'))),key,run,scopeHash,onDisk);
    const plain=Object.fromEntries(STORES.map(store=>[store,unseal(onDisk[store],key,binding(run,store,scopeHash))]));
    backupsAuthenticated=true;
    phase='fresh-isolated-restore-targets';
    createdNetwork=docker(['network','create','--internal','--label',`${LABEL}=${run}`,`fncp-coordinated-${run}`]).trim();requireThat(ID.test(createdNetwork));
    const createdNetworkInfo=network(createdNetwork);requireThat(createdNetworkInfo.Internal && createdNetworkInfo.Labels?.[LABEL]===run && Object.keys(createdNetworkInfo.Containers??{}).length===0);
    for(const kind of ['postgres','mysql']) {
      const id=docker(restoreArguments(kind,run,createdNetwork,kind==='postgres'?PG_IMAGE:MYSQL_IMAGE)).trim(); requireThat(ID.test(id) && ![sourcePg,sourceWp].includes(id));created.push(id);
      validateRestoreTarget(inspect(id),kind,run,createdNetwork,[sourcePg,sourceWp],true);
      docker(['start',id]);validateRestoreTarget(inspect(id),kind,run,createdNetwork,[sourcePg,sourceWp]);
      validateRuntimeMounts(docker(['exec',id,'cat','/proc/mounts']),kind);await ready(id,kind);
    }
    const restoreConfig={...config,database:PG_RESTORE_DB,role:PG_RESTORE_ROLE};
    requireThat(pg(created[0],restoreConfig,"SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")==='0');
    requireThat(mysql(created[1],`SELECT count(*) FROM information_schema.tables WHERE table_schema='${WP_RESTORE_DB}'`,true)==='0');
    phase='restore-encrypted-component-set';
    docker(['exec','-i',created[0],'pg_restore','--exit-on-error','--no-owner','--no-privileges','-U',PG_RESTORE_ROLE,'-d',PG_RESTORE_DB],{input:plain['polis-postgresql']});
    docker(['exec','-i',created[1],'mysql','--binary-mode','-u','root',WP_RESTORE_DB],{input:plain['wordpress-mysql']});
    privateFile(resolve(work,'restored.sqlite'),plain['access-sqlite']);privateFile(resolve(work,'adversarial.sqlite'),plain['access-sqlite']);
    for(const bytes of Object.values(plain)) bytes.fill(0);
    const restoredDb=new DatabaseSync(resolve(work,'restored.sqlite'),{readOnly:true});let access;try{access=accessSnapshot(restoredDb,config.conversation);}finally{restoredDb.close();}
    const polis=pgSnapshot(created[0],restoreConfig,seeds);const wp=wpSnapshot(created[1],true);
    restored={access:access.aggregates,polis:polis.aggregates,wordpress:wp.aggregates,consistency:validateConsistency(wp.journal,access.details,polis.operations)};
    same(before.aggregate,restored);
    phase='restored-authority-negative-proof';denial=await denyOldAuthority(resolve(work,'adversarial.sqlite'),config.conversation,wp.journal,run);
    phase='independent-source-final-recheck';quiescent(sourcePg,sourceWp,created);
    const finalDb=new DatabaseSync(SQLITE,{readOnly:true});sourceDb=finalDb;after=snapshot();same(before.aggregate,after.aggregate);same(sourceHash,sha256(readFileSync(SQLITE)));finalDb.close();sourceDb=null;
    passed=true;phase='complete';
  } catch(error) { failureCode=classifyFailure(error); }
  finally {
    if(sourceDb) {try{sourceDb.close();}catch{cleanup=false;}}
    for(const id of created.reverse()) {try{const info=inspect(id);requireThat(info.Labels?.[LABEL]===run && ![sourcePg,sourceWp].includes(id));docker(['rm','--force','--volumes',id]);}catch{cleanup=false;}}
    if(createdNetwork) {try{const info=network(createdNetwork);requireThat(info.Labels?.[LABEL]===run && info.Internal && Object.keys(info.Containers??{}).length===0);docker(['network','rm',createdNetwork]);}catch{cleanup=false;}}
    if(work) {try{requireThat(lstatSync(work).isDirectory()&&!lstatSync(work).isSymbolicLink());for(const name of readdirSync(work)){requireThat(/^(snapshot|restored|adversarial)\.sqlite(-journal|-wal|-shm)?$/u.test(name));const path=resolve(work,name);requireThat(lstatSync(path).isFile()&&!lstatSync(path).isSymbolicLink());unlinkSync(path);}rmdirSync(work);}catch{cleanup=false;}}
    if(createdNetwork) {try{requireThat(docker(['ps','-a','-q','--filter',`label=${LABEL}=${run}`]).trim()==='');requireThat(docker(['network','ls','-q','--filter',`label=${LABEL}=${run}`]).trim()==='');quiescent(sourcePg,sourceWp);}catch{cleanup=false;}}
  }
  const result={outcome:passed&&cleanup?'PASS':'FAIL',run,recordedAt:new Date().toISOString(),classification:'SYNTHETIC_LOCAL_THREE_STORE_ONLY_NOT_PRODUCTION_BACKUP_ASSURANCE',
    phase,failureCode,source:before?.aggregate??null,restored:restored??null,denial:denial??null,sourceAggregatesUnchanged:passed,
    temporaryResourcesRemoved:cleanup,retainedComponentCount,retainedBackupsAuthenticatedEncrypted:backupsAuthenticated&&retainedComponentCount===3,privateKeySeparateDirectory:keyRetained,productionReady:false};
  if(dir&&key) privateFile(resolve(dir,'result.json'),canonical(signManifest(result,key))+'\n');key?.fill(0);
  console.log(canonical({outcome:result.outcome,phase,failureCode,temporaryResourcesRemoved:cleanup,productionReady:false,evidenceDirectory:dir?`deploy/fncp/local-recovery/.runtime/coordinated-${run}`:null}));
  return result;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))runCoordinated().then(result=>{process.exitCode=result.outcome==='PASS'?0:1;}).catch(()=>{console.error('COORDINATED_RECOVERY=FAIL; diagnostics redacted; no production action.');process.exitCode=1;});
