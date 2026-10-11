#!/usr/bin/env node
/**
 * Local operator export authorized by OS custody of private configuration.
 * No OIDC staff role, participant ingress or public report endpoint is provided.
 * The database response is projected to aggregates before leaving PostgreSQL.
 */
import { constants } from 'node:fs';
import { lstat, open, realpath, unlink } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { randomBytes } from 'node:crypto';
import { composeConfiguration, loadConfiguration, privateRead, sha256, validateConfiguration, validateImageLock } from './configuration.mjs';
import { createController, execute, sourceSnapshot } from './fncpctl.mjs';
import { assertContainerProfile } from './container-profile.mjs';

const fail = () => new Error('FNCP_OPERATOR_EXPORT_REJECTED');
const integer = value => Number.isSafeInteger(value) && value >= 0;
const object = value => value && Object.getPrototypeOf(value) === Object.prototype;
const sameSet = (actual, expected) => Array.isArray(actual) && actual.length === expected.length
  && new Set(actual).size === expected.length && expected.every(value => actual.includes(value));
const sqlLiteral = value => "'" + value.replaceAll("'", "''") + "'";
const equalNumber = (a, b) => typeof a === 'number' && Number.isFinite(a) && Math.abs(a - b) <= 1e-10;
const CLASSIFICATION = 'LOCAL_OPERATOR_AGGREGATE_EXPORT';
const SOURCE_ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const CLIENT = [
  'test "$PGSSLMODE" = verify-full',
  'test "$PGSSLROOTCERT" = /run/fncp/database-ca.pem',
  'export PGHOST="$FNCP_DATABASE_HOST" PGPORT="$FNCP_DATABASE_PORT"',
  'export PGUSER="$FNCP_EXPECTED_MIGRATION_ROLE" PGDATABASE="$FNCP_EXPECTED_DATABASE" PGPASSWORD="$FNCP_DATABASE_PASSWORD"',
  "export PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=15000 -c lock_timeout=2000'",
  'exec psql -X -q -A -t --no-password -v ON_ERROR_STOP=1',
].join('\n');

/** Fixed query: no caller SQL, identity columns, member maps or individual votes
 * are returned. Identifier comparisons are evaluated privately in the database.
 */
export function operatorSnapshotSql(configuration) {
  const c = validateConfiguration(configuration);
  return [
    'BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;',
    "SET LOCAL statement_timeout='15000ms';",
    "SET LOCAL lock_timeout='2000ms';",
    'WITH bound AS (SELECT c.* FROM public.conversations c JOIN public.zinvites z USING(zid)',
    ' WHERE z.zinvite=' + sqlLiteral(c.binding.conversationId) + '),',
    'latest_history AS (SELECT DISTINCT ON (pid,tid) pid,tid,vote,created FROM public.votes',
    ' WHERE zid=(SELECT zid FROM bound) ORDER BY pid,tid,created DESC),',
    "main AS (SELECT * FROM public.math_main WHERE zid=(SELECT zid FROM bound) AND math_env='dev')",
    'SELECT jsonb_build_object(',
    "'database',current_database(),'role',current_user,",
    "'readOnly',current_setting('transaction_read_only'),'isolation',current_setting('transaction_isolation'),",
    "'snapshotAt',transaction_timestamp(),",
    "'tls',(SELECT jsonb_build_object('ssl',ssl,'version',version,'bits',bits) FROM pg_stat_ssl WHERE pid=pg_backend_pid()),",
    "'boundCount',(SELECT count(*) FROM bound),",
    "'conversation',(SELECT jsonb_build_object('code'," + sqlLiteral(c.binding.conversationId) + ",'closed',NOT is_active,'gated',use_xid_whitelist,'dataOpen',is_data_open) FROM bound),",
    "'participantRows',(SELECT count(*) FROM public.participants WHERE zid=(SELECT zid FROM bound)),",
    "'identities',(SELECT count(DISTINCT uid) FROM public.participants WHERE zid=(SELECT zid FROM bound)),",
    "'identifiedRows',(SELECT count(uid) FROM public.participants WHERE zid=(SELECT zid FROM bound)),",
    "'voterCount',(SELECT count(DISTINCT pid) FROM public.votes_latest_unique WHERE zid=(SELECT zid FROM bound)),",
    "'latestVoteCount',(SELECT count(*) FROM public.votes_latest_unique WHERE zid=(SELECT zid FROM bound)),",
    "'voteWatermark',(SELECT max(created) FROM public.votes WHERE zid=(SELECT zid FROM bound)),",
    "'moderationWatermark',(SELECT max(modified) FROM public.comments WHERE zid=(SELECT zid FROM bound)),",
    "'invalidVoteEvents',(SELECT count(*) FROM public.votes WHERE zid=(SELECT zid FROM bound) AND (vote IS NULL OR vote NOT IN(-1,0,1) OR created IS NULL)),",
    "'unknownLatestVotes',(SELECT count(*) FROM public.votes_latest_unique v",
    ' LEFT JOIN public.participants p USING(zid,pid) LEFT JOIN public.comments cm ON cm.zid=v.zid AND cm.tid=v.tid',
    ' WHERE v.zid=(SELECT zid FROM bound) AND (p.pid IS NULL OR cm.tid IS NULL OR v.vote IS NULL OR v.vote NOT IN(-1,0,1))),',
    "'ambiguousVoteTimes',EXISTS(SELECT 1 FROM public.votes WHERE zid=(SELECT zid FROM bound)",
    ' GROUP BY pid,tid,created HAVING count(DISTINCT vote)>1),',
    "'latestMatchesHistory',NOT EXISTS(SELECT 1 FROM latest_history h FULL JOIN",
    ' (SELECT pid,tid,vote,modified FROM public.votes_latest_unique WHERE zid=(SELECT zid FROM bound)) v USING(pid,tid)',
    ' WHERE h.pid IS NULL OR v.pid IS NULL OR h.vote IS DISTINCT FROM v.vote OR h.created IS DISTINCT FROM v.modified),',
    "'statements',COALESCE((SELECT jsonb_agg(jsonb_build_object('id',cm.tid,'text',cm.txt,'approved',cm.mod=1,",
    "'active',cm.active,'seed',cm.is_seed,'meta',cm.is_meta,",
    "'agree',(SELECT count(*) FROM public.votes_latest_unique v WHERE v.zid=cm.zid AND v.tid=cm.tid AND v.vote=-1),",
    "'disagree',(SELECT count(*) FROM public.votes_latest_unique v WHERE v.zid=cm.zid AND v.tid=cm.tid AND v.vote=1),",
    "'pass',(SELECT count(*) FROM public.votes_latest_unique v WHERE v.zid=cm.zid AND v.tid=cm.tid AND v.vote=0)",
    ') ORDER BY cm.tid) FROM public.comments cm WHERE cm.zid=(SELECT zid FROM bound)),\'[]\'::jsonb),',
    "'math',(SELECT jsonb_build_object('environment',math_env,'tick',math_tick,'cachingTick',caching_tick,",
    "'rowVoteWatermark',last_vote_timestamp,'dataVoteWatermark',data->'lastVoteTimestamp','dataModWatermark',data->'lastModTimestamp',",
    "'bindingMatches',(data->>'zid')::integer=zid,",
    "'voterMembershipMatches',(SELECT jsonb_agg(pid ORDER BY pid) FROM (SELECT DISTINCT pid FROM public.votes_latest_unique WHERE zid=main.zid) p)=",
    " (SELECT jsonb_agg(value::integer ORDER BY value::integer) FROM jsonb_array_elements_text(data->'in-conv')),",
    "'participants',data->'n','statementCount',data->'n-cmts','statementIds',data->'tids',",
    "'modIn',data->'mod-in','modOut',data->'mod-out','metaIds',data->'meta-tids',",
    "'groupIds',(SELECT jsonb_agg(g->'id') FROM jsonb_array_elements(data->'group-clusters') g),",
    "'groupVotes',data->'group-votes','consensus',data->'group-aware-consensus') FROM main),",
    "'mathTick',(SELECT math_tick FROM public.math_ticks WHERE zid=(SELECT zid FROM bound) AND math_env='dev'),",
    "'auxiliary',jsonb_build_array(",
    "(SELECT jsonb_build_object('tick',math_tick,'voteWatermark',data->'lastVoteTimestamp','bindingMatches',(data->>'zid')::integer=zid)",
    " FROM public.math_bidtopid WHERE zid=(SELECT zid FROM bound) AND math_env='dev'),",
    "(SELECT jsonb_build_object('tick',math_tick,'voteWatermark',data->'lastVoteTimestamp','bindingMatches',(data->>'zid')::integer=zid)",
    " FROM public.math_ptptstats WHERE zid=(SELECT zid FROM bound) AND math_env='dev'))",
    ');',
    'ROLLBACK;',
    '',
  ].join('\n');
}

/** Pure fail-closed projection. Extra private properties can never be serialized
 * accidentally: every output property is constructed explicitly here.
 */
export function aggregateOperatorSnapshot(configuration, lock, s) {
  const c = validateConfiguration(configuration); validateImageLock(lock);
  if (lock.sourceRevision !== c.sourceRevision || !object(s)
    || s.database !== c.database.name || s.role !== c.database.migrationRole
    || s.readOnly !== 'on' || s.isolation !== 'repeatable read'
    || !object(s.tls) || s.tls.ssl !== true || !['TLSv1.2','TLSv1.3'].includes(s.tls.version) || !integer(s.tls.bits) || s.tls.bits < 128
    || s.boundCount !== 1 || s.conversation?.code !== c.binding.conversationId
    || s.conversation?.closed !== true || s.conversation?.gated !== true || s.conversation?.dataOpen !== false
    || !integer(s.participantRows) || s.participantRows > 20 || s.participantRows < 2
    || s.identities !== s.participantRows || s.identifiedRows !== s.participantRows
    || !integer(s.voterCount) || s.voterCount < 2 || s.voterCount > s.identities
    || !integer(s.latestVoteCount) || s.latestVoteCount < 1 || s.latestVoteCount > 300
    || !integer(s.voteWatermark) || s.voteWatermark < 1 || !integer(s.moderationWatermark) || s.moderationWatermark < 1
    || s.invalidVoteEvents !== 0 || s.unknownLatestVotes !== 0 || s.ambiguousVoteTimes !== false || s.latestMatchesHistory !== true
    || typeof s.snapshotAt !== 'string' || !Number.isFinite(Date.parse(s.snapshotAt))
    || !Array.isArray(s.statements) || !sameSet(s.statements.map(x => x.id), c.binding.statementIds)) throw fail();
  const m = s.math;
  if (!object(m) || m.environment !== 'dev' || !integer(m.tick) || m.tick !== s.mathTick
    || !integer(m.cachingTick) || m.cachingTick < 1 || m.bindingMatches !== true || m.voterMembershipMatches !== true
    || m.rowVoteWatermark !== s.voteWatermark || m.dataVoteWatermark !== s.voteWatermark || m.dataModWatermark !== s.moderationWatermark
    || m.participants !== s.voterCount || m.statementCount !== 15
    || !sameSet(m.statementIds, c.binding.statementIds) || !sameSet(m.modIn, c.binding.statementIds)
    || !sameSet(m.modOut, []) || !sameSet(m.metaIds, [])
    || !Array.isArray(s.auxiliary) || s.auxiliary.length !== 2 || s.auxiliary.some(x => !object(x)
      || x.tick !== m.tick || x.voteWatermark !== s.voteWatermark || x.bindingMatches !== true)
    || !Array.isArray(m.groupIds) || m.groupIds.length < 2 || m.groupIds.length > 5
    || !m.groupIds.every(integer) || new Set(m.groupIds).size !== m.groupIds.length
    || !object(m.groupVotes) || !sameSet(Object.keys(m.groupVotes), m.groupIds.map(String))
    || !object(m.consensus) || !sameSet(Object.keys(m.consensus), c.binding.statementIds.map(String))) throw fail();
  const groups = m.groupIds.map(id => m.groupVotes[id]);
  if (groups.some(g => !object(g) || !integer(g['n-members']) || g['n-members'] < 1 || g['n-members'] > 20
      || !object(g.votes) || !sameSet(Object.keys(g.votes), c.binding.statementIds.map(String)))
    || groups.reduce((sum, g) => sum + g['n-members'], 0) !== s.voterCount) throw fail();
  let total = 0;
  const statements = [...s.statements].sort((a,b) => a.id-b.id).map(statement => {
    if (statement.approved !== true || statement.active !== true || statement.seed !== true || statement.meta !== false
      || typeof statement.text !== 'string' || !statement.text.trim() || Buffer.byteLength(statement.text) > 10_000
      || !['agree','disagree','pass'].every(k => integer(statement[k])) || statement.agree + statement.disagree + statement.pass > s.voterCount) throw fail();
    let agree = 0; let disagree = 0; let seen = 0; let consensus = 1;
    for (const group of groups) {
      const v = group.votes[statement.id];
      if (!object(v) || !['A','D','S'].every(k => integer(v[k])) || v.S > group['n-members'] || v.A + v.D > v.S) throw fail();
      agree += v.A; disagree += v.D; seen += v.S; consensus *= (v.A + 1) / (v.S + 2);
    }
    if (agree !== statement.agree || disagree !== statement.disagree || seen-agree-disagree !== statement.pass
      || !equalNumber(m.consensus[statement.id], consensus)) throw fail();
    total += seen;
    return { statementId: statement.id, text: statement.text, agree, disagree, pass: seen-agree-disagree,
      nativeGroupAwareConsensus: m.consensus[statement.id] };
  });
  if (total !== s.latestVoteCount) throw fail();
  return {
    version: 1, classification: CLASSIFICATION, authorization: 'PRIVATE_OS_CONFIGURATION_CUSTODY',
    scope: 'CLOSED_LOCAL_CORE', oidcStaffAuthorizationImplemented: false,
    source: { revision: c.sourceRevision, fingerprint: lock.sourceFingerprint, images: { ...lock.images },
      bindingSha256: sha256(JSON.stringify(c.binding)) },
    snapshot: { at: new Date(s.snapshotAt).toISOString(), isolation: 'repeatable read', readOnly: true,
      postgresTls: true, mathEnvironment: 'dev', voteCreatedWatermark: s.voteWatermark,
      moderationModifiedWatermark: s.moderationWatermark, mathTick: m.tick, cachingTick: m.cachingTick },
    aggregate: { identities: s.identities, voters: s.voterCount, statements: 15, latestVotes: s.latestVoteCount,
      groupSizes: groups.map(g => g['n-members']).sort((a,b) => a-b) },
    consensusDefinition: 'Native Pol.is product across groups of (agree + 1) / (seen + 2); not a percentage.',
    statements,
  };
}

async function sameDirectory(directory) {
  const current = await lstat(directory.parent);
  if (!current.isDirectory() || current.isSymbolicLink() || current.uid !== process.getuid()
    || (current.mode & 0o7777) !== 0o700 || current.ino !== directory.ino || current.dev !== directory.dev
    || await realpath(directory.parent) !== directory.parent) throw fail();
}

async function destination(path) {
  if (typeof path !== 'string' || !isAbsolute(path) || resolve(path) !== path || /[\u0000-\u001f\u007f]/u.test(path)) throw fail();
  // Aggregates remain outside the checkout even when a nested directory has
  // private permissions; source snapshots and bundles must never capture them.
  const relation = relative(await realpath(SOURCE_ROOT), path);
  if (relation === '' || (relation !== '..' && !relation.startsWith('../') && !isAbsolute(relation))) throw fail();
  const parent = dirname(path), stat = await lstat(parent);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid()
    || (stat.mode & 0o7777) !== 0o700 || await realpath(parent) !== parent) throw fail();
  try { await lstat(path); throw fail(); } catch (error) { if (error.code !== 'ENOENT') throw fail(); }
  return { parent, ino: stat.ino, dev: stat.dev };
}

/** Export creation is deliberately after all snapshot validation. */
export async function writeOperatorSnapshot(configuration, lock, snapshot, outputPath) {
  const result = aggregateOperatorSnapshot(configuration, lock, snapshot);
  const directory = await destination(outputPath);
  const bytes = Buffer.from(JSON.stringify(result, null, 2) + '\n');
  if (bytes.length > 256 * 1024) throw fail();
  let file; let created;
  try {
    await sameDirectory(directory);
    file = await open(outputPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    created = await file.stat();
    await file.writeFile(bytes); await file.sync();
    await sameDirectory(directory);
    const named = await lstat(outputPath);
    if (named.ino !== created.ino || named.dev !== created.dev || named.nlink !== 1 || named.uid !== process.getuid()
      || (named.mode & 0o7777) !== 0o600 || await realpath(outputPath) !== outputPath) throw fail();
    return { result: 'PASS', classification: CLASSIFICATION, statements: 15, groups: result.aggregate.groupSizes.length,
      outputSha256: sha256(bytes), readOnlySnapshot: true };
  } catch {
    if (created) {
      const named = await lstat(outputPath).catch(() => null);
      if (named?.ino === created.ino && named.dev === created.dev && named.nlink === 1 && named.uid === process.getuid()) await unlink(outputPath);
    }
    throw fail();
  } finally { await file?.close(); }
}

export async function exportOperatorAggregate({ configurationPath, outputPath }) {
  let operation; let operationStat; let operationPath; let helperId; let inspectHelper; let docker;
  try {
    const c = await loadConfiguration(configurationPath); await destination(outputPath);
    const controller = await createController(c);
    const status = await controller.status();
    if (!status.services.some(x => x.service === 'postgres' && x.status === 'running')) throw fail();
    operationPath = join(c.stateDirectory, 'operation.lock');
    operation = await open(operationPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    operationStat = await operation.stat();
    await operation.writeFile(JSON.stringify({ pid: process.pid, operation: 'read-only-operator-export' }));
    // Recheck after taking the lifecycle operation lock.
    await controller.status();
    const owner = JSON.parse(await privateRead(join(c.stateDirectory, 'owner.json')));
    const initialized = JSON.parse(await privateRead(join(c.stateDirectory, 'initialized.json')));
    const lock = validateImageLock(JSON.parse(await privateRead(join(c.stateDirectory, 'images.json'))));
    const source = await sourceSnapshot();
    if (source.sourceRevision !== c.sourceRevision || source.sourceFingerprint !== lock.sourceFingerprint
      || initialized.engineId !== owner.engineId || initialized.configurationSha256 !== owner.configurationSha256) throw fail();
    docker = (args, options) => execute('docker', ['--host', c.engine.host, '--config', c.engine.configDirectory, ...args], options);
    for (const imageId of Object.values(lock.images)) {
      const rows = JSON.parse(await docker(['image','inspect',imageId]));
      if (rows.length !== 1 || rows[0].Id !== imageId || rows[0].Os !== 'linux' || rows[0].Architecture !== 'arm64'
        || rows[0].Config.Labels?.['org.opencontainers.image.revision'] !== c.sourceRevision) throw fail();
    }
    const name = c.deployment + '-operator-export-' + randomBytes(8).toString('hex');
    const network = c.deployment + '_private';
    const ca = join(c.stateDirectory, 'material/database-ca.pem');
    // Mount syntax rejects comma/equals in the path rather than reinterpreting it.
    if (/[,\n=]/u.test(ca)) throw fail();
    helperId = await docker(['create','--name',name,'--interactive','--network',network,'--read-only','--user','70:70',
      '--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','64','--memory','256m','--restart','no',
      '--label','org.barayamal.fncp.owner=' + owner.token,'--label','org.barayamal.fncp.classification=closed-local-core',
      '--label','com.docker.compose.project=' + c.deployment,'--label','com.docker.compose.service=migration',
      '--env-file',join(c.stateDirectory,'material/migration.env'),
      '--mount','type=bind,source=' + ca + ',target=/run/fncp/database-ca.pem,readonly',
      // Mask the inherited PostgreSQL VOLUME with bounded ephemeral storage.
      '--tmpfs','/tmp:rw,nosuid,nodev,size=128m,mode=1777',
      '--tmpfs','/var/lib/postgresql/data:ro,nosuid,nodev,size=1m,mode=0700',
      '--entrypoint','/bin/sh',lock.images.migration,'-ceu',CLIENT]);
    if (!/^[0-9a-f]{64}$/u.test(helperId)) throw fail();
    inspectHelper = async () => {
      const r = JSON.parse(await docker(['inspect',helperId]))[0];
      assertContainerProfile(r, composeConfiguration(c, lock, owner.token).services.migration, c);
      if (r.Id !== helperId || r.Image !== lock.images.migration || r.Config.Image !== lock.images.migration
        || r.Config.User !== '70:70' || r.Config.Labels?.['org.barayamal.fncp.owner'] !== owner.token
        || r.Config.Labels?.['com.docker.compose.project'] !== c.deployment || r.Config.Labels?.['com.docker.compose.service'] !== 'migration'
        || r.HostConfig.NetworkMode !== network || !r.HostConfig.ReadonlyRootfs || r.HostConfig.Privileged
        || !r.HostConfig.CapDrop?.includes('ALL') || !r.HostConfig.SecurityOpt?.includes('no-new-privileges:true')
        || r.HostConfig.RestartPolicy?.Name !== 'no' || Object.keys(r.HostConfig.PortBindings ?? {}).length
        || r.HostConfig.PidsLimit !== 64 || r.HostConfig.Memory !== 256 * 1024 * 1024
        || r.Mounts.length !== 1 || r.Mounts[0].Type !== 'bind' || r.Mounts[0].Source !== ca
        || r.Mounts[0].Destination !== '/run/fncp/database-ca.pem' || r.Mounts[0].RW !== false
        || Object.keys(r.HostConfig.Tmpfs ?? {}).length !== 2
        || r.HostConfig.Tmpfs?.['/tmp'] !== 'rw,nosuid,nodev,size=128m,mode=1777'
        || r.HostConfig.Tmpfs?.['/var/lib/postgresql/data'] !== 'ro,nosuid,nodev,size=1m,mode=0700') throw fail();
      return r;
    };
    await inspectHelper();
    const raw = await docker(['start','--attach','--interactive',helperId], { input: operatorSnapshotSql(c), timeout: 30_000 });
    const closed = await inspectHelper();
    if (closed.State.Running || closed.State.ExitCode !== 0 || closed.State.OOMKilled) throw fail();
    await docker(['rm',helperId]); helperId = undefined;
    const snapshot = JSON.parse(raw);
    await controller.status();
    const after = await sourceSnapshot();
    if (after.sourceRevision !== source.sourceRevision || after.sourceFingerprint !== source.sourceFingerprint) throw fail();
    return await writeOperatorSnapshot(c, lock, snapshot, outputPath);
  } catch { throw fail(); }
  finally {
    try {
      if (helperId && inspectHelper) {
        const row = await inspectHelper();
        if (row.State.Running) await docker(['stop','--time','5',helperId]);
        const closed = await inspectHelper();
        if (closed.State.Running) throw fail();
        await docker(['rm',helperId]);
      }
    } finally {
      await operation?.close();
      if (operationStat) {
        const row = await lstat(operationPath);
        if (row.ino !== operationStat.ino || row.dev !== operationStat.dev || row.uid !== process.getuid()) throw fail();
        await unlink(operationPath);
      }
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [operation, configurationPath, outputPath, ...extra] = process.argv.slice(2);
  if (operation !== 'export' || !configurationPath || !outputPath || extra.length) {
    console.error('FNCP_OPERATOR_EXPORT_USAGE'); process.exitCode = 1;
  } else {
    exportOperatorAggregate({ configurationPath, outputPath }).then(result => console.log(JSON.stringify(result)))
      .catch(() => { console.error('FNCP_OPERATOR_EXPORT_REJECTED'); process.exitCode = 1; });
  }
}
