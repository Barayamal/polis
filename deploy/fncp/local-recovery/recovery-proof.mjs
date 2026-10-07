/** Synthetic local PostgreSQL backup/isolated-restore proof; never production. */
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { chmodSync, closeSync, existsSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { parseEnv } from 'node:util';

export const CONTEXT = 'colima-fncp-c-20260913';
const ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const COMPOSE = resolve(ROOT, 'deploy/fncp/docker-compose.staging.yml');
const ENV_FILE = resolve(ROOT, 'deploy/fncp/.env.staging');
const RESTART_MARKER = resolve(ROOT, 'deploy/fncp/.synthetic-bootstrap-restart');
const RUNTIME = fileURLToPath(new URL('./.runtime/', import.meta.url));
const LABEL = 'org.barayamal.fncp.local-recovery-run';
const RESTORE_DB = 'fncp_synthetic_restore';
const RESTORE_ROLE = 'fncp_restore_owner';
const ID = /^[a-f0-9]{64}$/u;

export function validateConfiguration(env, mode, pendingRestart = false) {
  if (mode !== 'synthetic-local-restore-proof' || pendingRestart ||
      env.FNCP_SYNTHETIC_BOOTSTRAP_COMPLETE !== 'true' ||
      env.FNCP_GATEWAY_ENFORCEMENT !== 'true' || env.FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT !== 'true' ||
      env.FNCP_GATEWAY_CONVERSATION_ID !== env.FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID ||
      !/^[0-9][A-Za-z0-9_-]{5,99}$/u.test(env.FNCP_GATEWAY_CONVERSATION_ID ?? '') ||
      env.FNCP_GATEWAY_CONVERSATION_ID.startsWith('9fncpBootstrap') ||
      !/^fncp-[a-z0-9-]{1,60}$/u.test(env.COMPOSE_PROJECT_NAME ?? '') ||
      env.POSTGRES_DB !== 'fncp_polis_staging' || env.POSTGRES_USER !== 'fncp_polis') {
    throw new Error('Synthetic configuration boundary failed.');
  }
  return { project: env.COMPOSE_PROJECT_NAME, database: env.POSTGRES_DB,
    role: env.POSTGRES_USER, conversation: env.FNCP_GATEWAY_CONVERSATION_ID };
}

function docker(args, options = {}) {
  // Never print child errors: Docker/psql diagnostic text can contain secrets.
  return execFileSync('docker', ['--context', CONTEXT, ...args], {
    encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 30000,
    maxBuffer: 4 * 1024 * 1024, ...options,
  }).trim();
}

function inspectContainer(id) {
  if (!ID.test(id)) throw new Error('Invalid exact container identifier.');
  // Deliberately omit Config.Env (contains database passwords) and log bodies.
  const format = '{"Id":{{json .Id}},"Image":{{json .Image}},"Running":{{json .State.Running}},' +
    '"Labels":{{json .Config.Labels}},"Ports":{{json .HostConfig.PortBindings}},' +
    '"Networks":{{json .NetworkSettings.Networks}},"Mounts":{{json .Mounts}}}';
  return JSON.parse(docker(['inspect', '--type', 'container', '--format', format, id]));
}

export function validateSourceContainer(info, config, composeFile = COMPOSE) {
  const files = (info.Labels?.['com.docker.compose.project.config_files'] ?? '').split(',');
  if (!ID.test(info.Id ?? '') || !/^sha256:[a-f0-9]{64}$/u.test(info.Image ?? '') || !info.Running ||
      info.Labels?.['com.docker.compose.service'] !== 'postgres' ||
      info.Labels?.['com.docker.compose.project'] !== config.project ||
      !files.includes(composeFile) || Object.keys(info.Ports ?? {}).length !== 0 ||
      Object.keys(info.Networks ?? {}).length !== 1 ||
      !(info.Mounts ?? []).some((mount) => mount.Destination === '/var/lib/postgresql/data')) {
    throw new Error('Dedicated synthetic source container could not be verified.');
  }
}

const sqlString = (value) => "'" + value.replaceAll("'", "''") + "'";

export function aggregateQuery(conversation, seeds) {
  if (!/^[0-9][A-Za-z0-9_-]{5,99}$/u.test(conversation) || !Array.isArray(seeds) ||
      seeds.length !== 15 || new Set(seeds).size !== 15 ||
      seeds.some((value) => typeof value !== 'string' || !value || value.length > 1000)) {
    throw new Error('Exactly fifteen known synthetic seed statements are required.');
  }
  const expected = seeds.map(sqlString).join(',');
  const cid = sqlString(conversation);
  // This returns one aggregate JSON object only. No IDs, names, emails, XIDs,
  // statement text, raw vote rows, tokens or stored response contents escape.
  return `SELECT json_build_object(
    'schemaTables',(SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE'),
    'schemaColumns',(SELECT count(*) FROM information_schema.columns WHERE table_schema='public'),
    'schemaIndexes',(SELECT count(*) FROM pg_indexes WHERE schemaname='public'),
    'schemaRoutines',(SELECT count(*) FROM information_schema.routines WHERE routine_schema='public'),
    'schemaConstraints',(SELECT count(*) FROM information_schema.table_constraints WHERE table_schema='public'),
    'conversations',(SELECT count(*) FROM conversations),
    'knownSyntheticConversations',(SELECT count(*) FROM conversations c WHERE
      c.topic='FNCP Option C disposable access QA' AND
      c.description='Synthetic local staging only. No genuine participant data.' AND
      c.is_data_open=false AND EXISTS(SELECT 1 FROM zinvites z WHERE z.zid=c.zid AND z.zinvite=${cid})),
    'allStatements',(SELECT count(*) FROM comments),
    'fixedSeedStatements',(SELECT count(*) FROM comments c WHERE c.is_seed=true AND c.active=true AND
      c.txt IN (${expected}) AND EXISTS(SELECT 1 FROM zinvites z WHERE z.zid=c.zid AND z.zinvite=${cid})),
    'unexpectedEmailRows',(SELECT count(*) FROM users WHERE email IS NOT NULL AND email <> 'admin@polis.test'),
    'voteRows',(SELECT count(*) FROM votes),
    'latestVoteRows',(SELECT count(*) FROM votes_latest_unique),
    'outOfScopeVoteRows',(SELECT count(*) FROM votes v WHERE NOT EXISTS
      (SELECT 1 FROM zinvites z WHERE z.zid=v.zid AND z.zinvite=${cid}))
  );`;
}

export function validateAggregate(value) {
  const keys = ['schemaTables', 'schemaColumns', 'schemaIndexes', 'schemaRoutines', 'schemaConstraints',
    'conversations', 'knownSyntheticConversations', 'allStatements', 'fixedSeedStatements',
    'unexpectedEmailRows', 'voteRows', 'latestVoteRows', 'outOfScopeVoteRows'];
  if (!value || Object.keys(value).sort().join(',') !== keys.sort().join(',') ||
      Object.values(value).some((count) => !Number.isSafeInteger(count) || count < 0) ||
      value.schemaTables < 1 || value.schemaColumns < 1 ||
      value.conversations !== 1 || value.knownSyntheticConversations !== 1 ||
      value.allStatements !== 15 || value.fixedSeedStatements !== 15 ||
      value.unexpectedEmailRows !== 0 || value.outOfScopeVoteRows !== 0) {
    throw new Error('Aggregate source/restore synthetic guard failed.');
  }
}

export function restoreContainerArgs({ run, network, image }) {
  if (!/^[a-f0-9]{24}$/u.test(run) || !ID.test(network) || !/^sha256:[a-f0-9]{64}$/u.test(image)) {
    throw new Error('Invalid isolated restore resource binding.');
  }
  return ['create', '--pull=never', '--name', `fncp-recovery-${run}`, '--label', `${LABEL}=${run}`,
    '--network', network, '--restart=no', '--memory=1g', '--pids-limit=256',
    '--tmpfs', '/var/lib/postgresql/data:rw,nosuid,nodev,size=512m',
    '--tmpfs', '/docker-entrypoint-initdb.d:ro,nosuid,nodev,size=1m',
    '--env', 'POSTGRES_HOST_AUTH_METHOD=trust', '--env', `POSTGRES_DB=${RESTORE_DB}`,
    '--env', `POSTGRES_USER=${RESTORE_ROLE}`, image];
}

function psql(container, role, database, sql) {
  return docker(['exec', '-i', container, 'psql', '-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1',
    '-U', role, '-d', database], { input: sql });
}

export async function readiness(container, runner = docker,
  pause = () => new Promise((done) => setTimeout(done, 500)), attempts = 40) {
  for (let attempt = 0; attempt < attempts; attempt++) {
    // PostgreSQL's image entrypoint starts a temporary Unix-socket-only server
    // for initdb before launching the final TCP server. Socket readiness alone
    // can race that temporary server's shutdown. Probe final-server TCP instead.
    try {
      runner(['exec', container, 'pg_isready', '-h', '127.0.0.1', '-U', RESTORE_ROLE, '-d', RESTORE_DB], { timeout: 5000 });
      return;
    } catch { await pause(); }
  }
  throw new Error('Disposable restore database not ready.');
}

export function classifyFailure(error) {
  // Inspect bounded child diagnostics only to map to fixed non-sensitive codes.
  // Never return/log stderr, command strings, arguments, SQL or environment.
  const diagnostic = String(error?.stderr ?? '').slice(0, 8192);
  if (error?.code === 'ETIMEDOUT') return 'LOCAL_COMMAND_TIMEOUT';
  if (error?.code === 'ENOENT') return 'LOCAL_EXECUTABLE_UNAVAILABLE';
  if (/connection.*refused|could not connect|No such file.*socket|server closed the connection/iu.test(diagnostic)) return 'DATABASE_CONNECTION_UNAVAILABLE';
  if (/No such container/iu.test(diagnostic)) return 'CONTAINER_UNAVAILABLE';
  if (/address pool|Pool overlaps/iu.test(diagnostic)) return 'NETWORK_ALLOCATION_FAILURE';
  if (/invalid mount|invalid tmpfs/iu.test(diagnostic)) return 'INVALID_TEMPORARY_MOUNT';
  if (error?.code === 'ENOMEM' || /out of memory|cannot allocate memory/iu.test(diagnostic)) return 'LOCAL_MEMORY_UNAVAILABLE';
  return 'UNCLASSIFIED_LOCAL_FAILURE';
}

export async function runRecovery() {
  process.umask(0o077);
  let phase = 'configuration'; let createdContainer; let createdNetwork; let archive; let sourceCounts; let restoredCounts;
  const run = randomBytes(12).toString('hex');
  let cleanupVerified = true;
  let failureCode = null;
  try {
    const env = parseEnv(readFileSync(ENV_FILE, 'utf8'));
    const config = validateConfiguration(env, process.env.FNCP_LOCAL_RECOVERY_MODE, existsSync(RESTART_MARKER));
    const seeds = JSON.parse(readFileSync(resolve(ROOT, 'deploy/fncp/seed-statements.json'), 'utf8'));
    const query = aggregateQuery(config.conversation, seeds);
    phase = 'source-container-identity';
    const source = docker(['compose', '--project-name', config.project, '--env-file', ENV_FILE,
      '-f', COMPOSE, 'ps', '-q', 'postgres']);
    const sourceInfo = inspectContainer(source);
    validateSourceContainer(sourceInfo, config);
    const networkId = Object.values(sourceInfo.Networks)[0].NetworkID;
    if (!ID.test(networkId)) throw new Error('Source network identity missing.');
    const sourceNetwork = JSON.parse(docker(['network', 'inspect', '--format', '{{json .}}', networkId]));
    if (!sourceNetwork.Internal || sourceNetwork.Labels?.['com.docker.compose.project'] !== config.project) {
      throw new Error('Source database must be on its internal-only compose network.');
    }
    phase = 'source-aggregate-guard';
    sourceCounts = JSON.parse(psql(source, config.role, config.database, query));
    validateAggregate(sourceCounts);
    console.log('PASS dedicated synthetic source guard; only aggregate values examined.');
    phase = 'backup';
    mkdirSync(RUNTIME, { recursive: true, mode: 0o700 });
    if (!lstatSync(RUNTIME).isDirectory() || lstatSync(RUNTIME).isSymbolicLink()) throw new Error('Private archive directory must be a real local directory.');
    chmodSync(RUNTIME, 0o700);
    const partial = resolve(RUNTIME, `synthetic-recovery-${run}.partial.dump`);
    const destination = resolve(RUNTIME, `synthetic-recovery-${run}.dump`);
    const file = openSync(partial, 'wx', 0o600);
    let dump;
    try {
      dump = spawnSync('docker', ['--context', CONTEXT, 'exec', source, 'pg_dump',
        '--format=custom', '--no-owner', '--no-acl', '-U', config.role, '-d', config.database],
      { stdio: ['ignore', file, 'pipe'], timeout: 60000 });
    } finally { closeSync(file); }
    if (dump.status !== 0 || dump.error || statSync(partial).size < 5) throw new Error('Synthetic backup failed.');
    const afterDump = JSON.parse(psql(source, config.role, config.database, query));
    validateAggregate(afterDump);
    if (JSON.stringify(sourceCounts) !== JSON.stringify(afterDump)) throw new Error('Source changed during backup; stable run required.');
    renameSync(partial, destination); archive = destination;
    console.log('PASS local synthetic custom-format backup; mode0600; aggregate source stable.');

    phase = 'isolated-resource-create';
    phase = 'create-isolated-network';
    createdNetwork = docker(['network', 'create', '--internal', '--label', `${LABEL}=${run}`, `fncp-recovery-${run}`]);
    if (!ID.test(createdNetwork)) throw new Error('New network identifier invalid.');
    phase = 'create-isolated-container';
    createdContainer = docker(restoreContainerArgs({ run, network: createdNetwork, image: sourceInfo.Image }));
    phase = 'inspect-isolated-container';
    const targetInfo = inspectContainer(createdContainer);
    phase = 'validate-isolated-container';
    if (createdContainer === source || targetInfo.Labels?.[LABEL] !== run ||
        Object.keys(targetInfo.Ports ?? {}).length || targetInfo.Mounts.some((mount) => mount.Type === 'bind' || mount.Type === 'volume')) {
      throw new Error('Restore target must be newly created and have no existing mounts or ports.');
    }
    phase = 'start-isolated-container';
    docker(['start', createdContainer]);
    phase = 'wait-isolated-database';
    await readiness(createdContainer);
    phase = 'verify-empty-target';
    const emptyCount = psql(createdContainer, RESTORE_ROLE, RESTORE_DB,
      "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE';");
    if (emptyCount !== '0') throw new Error('New restore database is not empty.');
    phase = 'isolated-restore';
    const input = openSync(archive, 'r'); let restored;
    try {
      restored = spawnSync('docker', ['--context', CONTEXT, 'exec', '-i', createdContainer,
        'pg_restore', '--exit-on-error', '--no-owner', '--no-privileges', '-U', RESTORE_ROLE, '-d', RESTORE_DB],
      { stdio: [input, 'pipe', 'pipe'], timeout: 60000, maxBuffer: 4 * 1024 * 1024 });
    } finally { closeSync(input); }
    if (restored.status !== 0 || restored.error) throw new Error('Synthetic restore failed.');
    phase = 'aggregate-readback';
    restoredCounts = JSON.parse(psql(createdContainer, RESTORE_ROLE, RESTORE_DB, query));
    validateAggregate(restoredCounts);
    if (JSON.stringify(sourceCounts) !== JSON.stringify(restoredCounts)) throw new Error('Restore aggregate mismatch.');
    console.log('PASS isolated restore: schema aggregates,15knownfixedseeds and vote aggregates match.');
    phase = 'complete';
  } catch (error) {
    failureCode = classifyFailure(error);
    console.error(`SYNTHETIC_LOCAL_RECOVERY=FAIL phase=${phase} code=${failureCode}; no source contents, identifiers or child diagnostics logged.`);
  } finally {
    if (createdContainer && ID.test(createdContainer)) {
      try {
        if (inspectContainer(createdContainer).Labels?.[LABEL] !== run) throw new Error('Ownership mismatch.');
        docker(['rm', '--force', '--volumes', createdContainer]);
      } catch { cleanupVerified = false; }
    }
    if (createdNetwork && ID.test(createdNetwork)) {
      try {
        const info = JSON.parse(docker(['network', 'inspect', '--format', '{{json .}}', createdNetwork]));
        if (info.Labels?.[LABEL] !== run || Object.keys(info.Containers ?? {}).length) throw new Error('Ownership or attachment mismatch.');
        docker(['network', 'rm', createdNetwork]);
      } catch { cleanupVerified = false; }
    }
    if (!cleanupVerified) console.error('Created synthetic restore resource cleanup is incomplete; inspect only labelled local-recovery resources.');
  }
  const outcome = phase === 'complete' && cleanupVerified ? 'PASS' : 'FAIL';
  if (archive) {
    const evidence = {
      outcome, classification: 'SYNTHETIC_LOCAL_ONLY_NOT_PRODUCTION_RECOVERY_ASSURANCE',
      failurePhase: outcome === 'PASS' ? null : phase, failureCode,
      context: CONTEXT, recordedAt: new Date().toISOString(),
      archive: { filename: archive.split('/').at(-1), bytes: statSync(archive).size,
        mode: (statSync(archive).mode & 0o777).toString(8),
        sha256: createHash('sha256').update(readFileSync(archive)).digest('hex') },
      source: sourceCounts, restored: restoredCounts ?? null,
      sourceDatabaseChangedByHelper: false, isolatedRestoreCleanupVerified: cleanupVerified,
      limitation: 'Aggregate equality is not byte-for-byte verification, participant authentication, whole-service recovery, or a production RPO/RTO promise.',
    };
    writeFileSync(resolve(RUNTIME, `synthetic-recovery-${run}.evidence.json`), JSON.stringify(evidence, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    console.log(`Local backup/evidence retained privately under deploy/fncp/local-recovery/.runtime/; archive mode=${evidence.archive.mode}.`);
    if (outcome === 'PASS') console.log(JSON.stringify({ source: sourceCounts, restored: restoredCounts }));
  }
  console.log(`SYNTHETIC_LOCAL_RECOVERY=${outcome}; productionRecoveryReady=false; createdRestoreResourcesRemoved=${cleanupVerified}.`);
  return outcome === 'PASS';
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runRecovery().then((passed) => { process.exitCode = passed ? 0 : 1; }).catch(() => {
    console.error('SYNTHETIC_LOCAL_RECOVERY=FAIL; local helper error; no sensitive details logged.');
    process.exitCode = 1;
  });
}
