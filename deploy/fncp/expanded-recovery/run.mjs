/** Explicit, bounded ACTUAL four-store local recovery. Never starts source apps.
 * The caller must first close its own fresh synthetic journey and WP PHP server.
 * No import-time I/O, automatic CLI, external transport, deletion or activation.
 */
import { execFileSync, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { DatabaseSync, backup } from 'node:sqlite';
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { basename, dirname, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { parseEnv } from 'node:util';
import { canonical, readStrictStore } from '../strict-recovery/contract.mjs';
import { aggregateQuery, validateAggregate, validateConfiguration, validateSourceContainer, CONTEXT } from '../local-recovery/recovery-proof.mjs';
import { validateRuntimeMounts, validateWordPressSource as validateLegacyWordPressContainer } from '../local-recovery/coordinated-proof.mjs';
import { validateWordPressRegistration } from './wordpress-contract.mjs';
import { MODE, COMPONENTS, exact, need, sha256, header, seal, unseal, signManifest, verifyManifest } from './crypto.mjs';
import { keyPackage, fingerprints, verifyMappings, restoreStrictSqlite } from './restore-sqlite.mjs';

const DEPLOY = fileURLToPath(new URL('../', import.meta.url));
const RUNTIME = resolve(DEPLOY, 'expanded-recovery/.runtime');
const WP_RUNTIME = resolve(DEPLOY, 'wordpress-identity/.runtime');
const COMPOSE = resolve(DEPLOY, 'docker-compose.staging.yml');
const ENV = resolve(DEPLOY, '.env.staging');
const LABEL = 'org.barayamal.fncp.expanded-recovery-run';
const ID = /^[a-f0-9]{64}$/u;
export const IMAGES = Object.freeze({ postgres: 'sha256:9d9684f7a95e94c9eb370212edea832e7b9916b7bd96b2821c5bc9cf63a0e8b3',
  mysql: 'sha256:85b9bf2e29cf836ecb8c2a15a935d4ba0c606631dff1dd79531a11983c638f2a' });
const PG_DB = 'fncp_expanded_restore'; const PG_ROLE = 'fncp_restore_owner'; const WP_DB = 'fncp_wp_expanded_restore';
const WP_TABLES = ['commentmeta', 'comments', 'links', 'options', 'postmeta', 'posts', 'term_relationships', 'term_taxonomy', 'termmeta', 'terms', 'usermeta', 'users'].map(n => 'synthetic_' + n);
const sqlString = v => "'" + v.replaceAll("'", "''") + "'";
const equal = (a, b) => need(canonical(a) === canonical(b));
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

function docker(args, options = {}) {
  return execFileSync('docker', ['--context', CONTEXT, ...args], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'],
    timeout: 30000, maxBuffer: 64 * 1024 * 1024, ...options });
}
function inspect(id) {
  need(typeof id === 'string' && ID.test(id));
  // Never inspect/log Config.Env, container logs, tokens or raw DB responses.
  return JSON.parse(docker(['inspect', '--type', 'container', '--format',
    '{"Id":{{json .Id}},"Image":{{json .Image}},"Running":{{json .State.Running}},"Labels":{{json .Config.Labels}},"Tmpfs":{{json (index .HostConfig "Tmpfs")}},"Ports":{{json .HostConfig.PortBindings}},"Networks":{{json .NetworkSettings.Networks}},"Mounts":{{json .Mounts}}}', id]));
}
function network(id) { need(ID.test(id)); return JSON.parse(docker(['network', 'inspect', '--format', '{{json .}}', id])); }
function privateDirectory(path, fresh = false) {
  if (fresh) mkdirSync(path, { mode: 0o700 }); else if (!existsSync(path)) mkdirSync(path, { recursive: true, mode: 0o700 });
  const st = lstatSync(path); need(st.isDirectory() && !st.isSymbolicLink() && realpathSync(path) === path); chmodSync(path, 0o700);
}
function regularPrivate(path) {
  const s = lstatSync(path); need(s.isFile() && !s.isSymbolicLink() && s.nlink === 1 && (s.mode & 0o777) === 0o600 && realpathSync(path) === path);
  return s;
}
function readPrivate(path) { regularPrivate(path); return readFileSync(path); }
function writePrivate(path, bytes) { writeFileSync(path, bytes, { flag: 'wx', mode: 0o600 }); }
function noOpenFile(path) {
  const r = spawnSync('lsof', ['-t', path], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 5000 });
  need(!r.error && r.status === 1 && !r.stdout.trim());
}

/** Validate exact branding BEFORE reading DB files or issuing Docker calls. */
export function validateInput(input) {
  need(exact(input, ['mode', 'wordpress', 'sourceAccessPath', 'sourceActivationPath', 'sourceBinding', 'identity', 'activation', 'wordpressSecrets']));
  need(input.mode === MODE && process.env.FNCP_LOCAL_SYNTHETIC_MODE === 'fixture-only');
  const w = input.wordpress;
  need(exact(w, ['directory', 'composePath', 'containerId', 'project', 'database', 'databaseUser', 'volume']));
  const suffix = typeof w.project === 'string' && /^fncp-wp-identity-([a-f0-9]{20})$/u.exec(w.project)?.[1];
  need(suffix && typeof w.directory === 'string' && dirname(w.directory) === WP_RUNTIME && /^run-[A-Za-z0-9]{6,}$/u.test(basename(w.directory)) &&
    w.composePath === resolve(w.directory, 'compose.json') && typeof w.containerId === 'string' && ID.test(w.containerId) &&
    w.database === 'fncp_identity_' + suffix && w.databaseUser === 'fncpi_' + suffix && w.volume === 'fncp-wp-identity-data-' + suffix);
  const a = input.sourceAccessPath; const b = input.sourceActivationPath;
  need(typeof a === 'string' && typeof b === 'string' && basename(a) === 'access.sqlite' && basename(b) === 'activation.sqlite' &&
    dirname(a) === dirname(b) && /^fncp-integrated-journey-[A-Za-z0-9]{6,}$/u.test(basename(dirname(a))) &&
    // tmpdir may be /var/... while realpath is /private/var/... on macOS.
    [resolve(tmpdir()), resolve('/private' + tmpdir())].includes(dirname(dirname(a))) && a === resolve(a) && b === resolve(b));
  need(exact(input.identity, ['key', 'keyVersion', 'issuer', 'clientId', 'syntheticSubjects']) &&
    exact(input.activation, ['publicKey', 'keyId', 'priorEnvelope']) && exact(input.wordpressSecrets, ['event', 'challenge', 'registration']));
  return suffix;
}
/** Pure check of generated private PHP text; does not execute PHP or echo it. */
export function validateWordPressSigningConfiguration(text, secrets) {
  need(typeof text === 'string' && text.length <= 100000 && exact(secrets, ['event', 'challenge', 'registration']));
  for (const [name, value] of [['FNCP_WP_LOCAL_EVENT_SECRET', secrets.event],
    ['FNCP_WP_CHALLENGE_SECRET', secrets.challenge], ['FNCP_BFF_REGISTRATION_SECRET', secrets.registration]]) {
    const lines = [...text.matchAll(new RegExp("^define\\('" + name + "', '([A-Za-z0-9_-]{32,512})'\\);$", 'gm'))];
    need(lines.length === 1 && lines[0][1] === value);
  }
  return true;
}
export function validateWordPressSource(info, w) {
  const port = info.Ports?.['3306/tcp'];
  need(info.Id === w.containerId && info.Running === true && info.Image === IMAGES.mysql &&
    info.Labels?.['org.barayamal.fncp.purpose'] === 'synthetic-wordpress-identity-only' &&
    info.Labels?.['org.barayamal.fncp.identity-run'] === w.project && info.Labels?.['com.docker.compose.project'] === w.project &&
    info.Labels?.['com.docker.compose.service'] === 'db' && info.Labels?.['com.docker.compose.project.config_files'] === w.composePath &&
    Object.keys(info.Ports ?? {}).length === 1 && port?.length === 1 && port[0].HostIp === '127.0.0.1' && port[0].HostPort === '33080' &&
    Object.keys(info.Networks ?? {}).length === 1 && info.Mounts?.length === 3);
  need(info.Mounts.some(m => m.Type === 'volume' && m.Name === w.volume && m.Destination === '/var/lib/mysql'));
  for (const name of ['db-password', 'root-password']) need(info.Mounts.some(m => m.Type === 'bind' && !m.RW &&
    m.Source === resolve(w.directory, name) && m.Destination === '/run/secrets/' + name));
}
const APPLICATIONS = Object.freeze({ server: 'server', math: 'math', alpha: 'client-participation-alpha', proxy: 'nginx-proxy', simulator: 'oidc-simulator' });
export function validateApplicationContainer(info, service, expectedImage) {
  need(Object.values(APPLICATIONS).includes(service) && ID.test(info.Id ?? '') && /^sha256:[a-f0-9]{64}$/u.test(expectedImage) &&
    info.Image === expectedImage && typeof info.Running === 'boolean' &&
    info.Labels?.['com.docker.compose.project'] === 'fncp-polis-staging' && info.Labels?.['com.docker.compose.service'] === service &&
    (info.Labels?.['com.docker.compose.project.config_files'] ?? '').split(',').includes(COMPOSE) &&
    Object.values(info.Ports ?? {}).flat().every(p => p?.HostIp === '127.0.0.1'));
}
function stopSourceApplications(binding) {
  const simulator = JSON.parse(docker(['image', 'inspect', '--format', '{{json .Id}}', 'fncp-polis-staging-oidc-simulator']));
  need(JSON.parse(docker(['image', 'inspect', '--format', '{{json .Id}}', 'fncp-polis-staging-polis-migration'])) === binding.images.migration);
  const selected = Object.entries(APPLICATIONS).map(([role, service]) => {
    const id = docker(['compose', '--project-name', 'fncp-polis-staging', '--env-file', ENV, '-f', COMPOSE, 'ps', '-a', '-q', service]).trim();
    const info = inspect(id); validateApplicationContainer(info, service, role === 'simulator' ? simulator : binding.images[role]);
    return { id, service, image: info.Image, running: info.Running };
  });
  need(new Set(selected.map(s => s.id)).size === Object.keys(APPLICATIONS).length);
  // All five exact targets are validated before the first stop. Stop only;
  // never restart, recreate, reconfigure, close the native round or remove data.
  for (const s of selected) {
    if (s.running) docker(['stop', '--time', '10', s.id]);
    const after = inspect(s.id); validateApplicationContainer(after, s.service, s.image); need(after.Running === false);
  }
  return selected.length;
}
function quiescent(sourcePg, sourceWp, paths, owned = [], sourceHandlesOpen = false, bystanders = []) {
  equal(docker(['ps', '-q', '--no-trunc']).trim().split('\n').filter(Boolean).sort(), [sourcePg, sourceWp, ...owned, ...bystanders].sort());
  for (const port of [5500, 8099, 8100, 8101, 8102, 8103]) {
    const r = spawnSync('lsof', ['-nP', `-iTCP:${port}`, '-sTCP:LISTEN', '-t'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 5000 });
    need(!r.error && r.status === 1 && !r.stdout.trim());
  }
  for (const path of paths) {
    if (!sourceHandlesOpen) noOpenFile(path);
    for (const suffix of ['-wal', '-shm', '-journal']) need(!existsSync(path + suffix));
  }
}
function pg(id, config, sql) {
  return docker(['exec', '-i', id, 'psql', '-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-U', config.role, '-d', config.database], { input: sql }).trim();
}
function mysql(id, w, sql, { restored = false, root = false } = {}) {
  const args = restored ? ['mysql', '--batch', '--raw', '--skip-column-names', '-u', 'root', WP_DB] :
    ['sh', '-c', 'MYSQL_PWD="$(cat /run/secrets/' + (root ? 'root-password' : 'db-password') + ')" exec mysql --batch --raw --skip-column-names -u ' + (root ? 'root' : w.databaseUser) + ' ' + w.database];
  return docker(['exec', '-i', id, ...args], { input: sql }).trim();
}

function pgSnapshot(id, config, seeds, mappings) {
  const aggregate = JSON.parse(pg(id, config, aggregateQuery(config.conversation, seeds))); validateAggregate(aggregate);
  const extra = JSON.parse(pg(id, config, `SELECT json_build_object(
    'whitelistRows',(SELECT count(*) FROM xid_whitelist),
    'outOfScopeOperations',(SELECT count(*) FROM fncp_provider_allowlist_operations o WHERE NOT EXISTS(SELECT 1 FROM zinvites z WHERE z.zid=o.zid AND z.zinvite=${sqlString(config.conversation)})),
    'nonterminalOperations',(SELECT count(*) FROM fncp_provider_allowlist_operations WHERE operation_version<>2 OR desired_present IS NOT FALSE),
    'whitelistEnforced',(SELECT count(*) FROM conversations WHERE use_xid_whitelist IS TRUE),
    'nativeActive',(SELECT is_active FROM conversations LIMIT 1),
    'otherConnections',(SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND backend_type='client backend'))`));
  need(extra.whitelistRows === 0 && extra.outOfScopeOperations === 0 && extra.nonterminalOperations === 0 && extra.whitelistEnforced === 1 &&
    typeof extra.nativeActive === 'boolean' && extra.otherConnections === 0);
  const operations = JSON.parse(pg(id, config, "SELECT COALESCE(json_agg(o ORDER BY xid),'[]'::json) FROM (SELECT xid,operation_version,desired_present FROM fncp_provider_allowlist_operations) o"));
  need(operations.length <= 1000 && operations.every(o => /^fncp_[A-Za-z0-9_-]{16,251}$/u.test(o.xid)));
  const selected = operations.filter(o => mappings.some(m => m.xid === o.xid)).map(o => ({ xid: o.xid, operationVersion: o.operation_version, present: o.desired_present }));
  need(selected.length === mappings.length);
  const tables = JSON.parse(pg(id, config, "SELECT json_agg(table_name ORDER BY table_name) FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE'"));
  need(tables.length > 0 && tables.length <= 100 && tables.every(t => /^[a-z][a-z0-9_]*$/u.test(t)));
  const rowCounts = {}; const contentHashes = {};
  for (const table of tables) {
    const n = Number(pg(id, config, `SELECT count(*) FROM "${table}"`)); need(Number.isSafeInteger(n) && n >= 0 && n <= 50000); rowCounts[table] = n;
    contentHashes[table] = sha256(pg(id, config, `SELECT COALESCE(json_agg(r.row_value ORDER BY r.row_value),'[]'::json) FROM (SELECT row_to_json(t)::text AS row_value FROM "${table}" t) r`));
  }
  const schema = pg(id, config, `SELECT json_build_object('columns',(SELECT json_agg(r ORDER BY table_name,ordinal_position) FROM
    (SELECT table_name,column_name,ordinal_position,data_type,udt_name,is_nullable,column_default FROM information_schema.columns WHERE table_schema='public') r),
    'indexes',(SELECT json_agg(r ORDER BY tablename,indexname) FROM (SELECT tablename,indexname,indexdef FROM pg_indexes WHERE schemaname='public') r))`);
  return { provider: { conversationId: config.conversation, whitelistRows: 0, operations: selected },
    public: { ...aggregate, ...extra, rowCounts, contentHashes, schemaSha256: sha256(schema), tombstoneSha256: sha256(canonical(operations)) } };
}

function wpSnapshot(id, w, mappings, challengeSecret, now, restored = false) {
  const database = restored ? WP_DB : w.database; const query = sql => mysql(id, w, sql, { restored });
  if (!restored) need(mysql(id, w, `SELECT count(*) FROM information_schema.processlist WHERE ID<>CONNECTION_ID() AND USER IN (${sqlString(w.databaseUser)},'root')`, { root: true }) === '0');
  const tables = JSON.parse(query(`SELECT JSON_ARRAYAGG(TABLE_NAME) FROM information_schema.tables WHERE table_schema='${database}'`)).sort(); equal(tables, [...WP_TABLES].sort());
  const values = JSON.parse(query(`SELECT JSON_OBJECT(
    'nonInnoDB',(SELECT count(*) FROM information_schema.tables WHERE table_schema='${database}' AND ENGINE<>'InnoDB'),
    'users',(SELECT count(*) FROM synthetic_users),
    'knownUsers',(SELECT count(*) FROM synthetic_users WHERE user_login=${sqlString('synthetic_admin_' + w.project.slice('fncp-wp-identity-'.length))} AND user_email='synthetic_admin@example.test'),
    'siteMatches',(SELECT count(*) FROM synthetic_options WHERE option_name IN ('siteurl','home') AND option_value='http://127.0.0.1:8103'),
    'registrationDisabled',(SELECT count(*) FROM synthetic_options WHERE option_name='users_can_register' AND option_value='0'),
    'publicDisabled',(SELECT count(*) FROM synthetic_options WHERE option_name='blog_public' AND option_value='0'),
    'pluginsDisabled',(SELECT count(*) FROM synthetic_options WHERE option_name='active_plugins' AND option_value='a:0:{}'),
    'attachments',(SELECT count(*) FROM synthetic_posts WHERE post_type='attachment'),
    'sessionTokenRows',(SELECT count(*) FROM synthetic_usermeta WHERE meta_key='session_tokens' AND meta_value<>'a:0:{}'),
    'registryRows',(SELECT count(*) FROM synthetic_options WHERE option_name='fncp_wp_identity_registry_v1'),
    'journalRows',(SELECT count(*) FROM synthetic_options WHERE option_name='fncp_wp_identity_approval_journal_v1'))`));
  equal(values, { nonInnoDB: 0, users: 1, knownUsers: 1, siteMatches: 2, registrationDisabled: 1, publicDisabled: 1,
    pluginsDisabled: 1, attachments: 0, sessionTokenRows: 0, registryRows: 1, journalRows: 1 });
  const option = name => {
    const hex = query(`SELECT HEX(option_value) FROM synthetic_options WHERE option_name=${sqlString(name)}`);
    need(/^[A-Fa-f0-9]+$/u.test(hex) && hex.length <= 512 * 1024); return JSON.parse(Buffer.from(hex, 'hex').toString('utf8'));
  };
  const registry = option('fncp_wp_identity_registry_v1'); const journal = option('fncp_wp_identity_approval_journal_v1');
  const checked = validateWordPressRegistration({ registry, journal, mappings, now, challengeSecret });
  const rowCounts = {}; const contentHashes = {};
  for (const table of tables) {
    const n = Number(query(`SELECT count(*) FROM ${table}`)); need(Number.isSafeInteger(n) && n >= 0 && n <= 10000); rowCounts[table] = n;
    const columns = query(`SELECT COLUMN_NAME FROM information_schema.columns WHERE table_schema='${database}' AND table_name='${table}' ORDER BY ORDINAL_POSITION`).split('\n');
    need(columns.length > 0 && columns.every(c => /^[A-Za-z][A-Za-z0-9_]*$/u.test(c)));
    const primary = query(`SELECT COLUMN_NAME FROM information_schema.statistics WHERE table_schema='${database}' AND table_name='${table}' AND INDEX_NAME='PRIMARY' ORDER BY SEQ_IN_INDEX`).split('\n');
    need(primary.length > 0 && primary.every(c => columns.includes(c)));
    contentHashes[table] = sha256(query(`SELECT JSON_ARRAY(${columns.map(c => '`' + c + '`').join(',')}) FROM ${table} ORDER BY ${primary.map(c => '`' + c + '`').join(',')}`));
  }
  const columns = query(`SELECT TABLE_NAME,COLUMN_NAME,ORDINAL_POSITION,COLUMN_TYPE,IS_NULLABLE,COALESCE(COLUMN_DEFAULT,'<NULL>'),EXTRA FROM information_schema.columns WHERE table_schema='${database}' ORDER BY TABLE_NAME,ORDINAL_POSITION`);
  const indexes = query(`SELECT TABLE_NAME,INDEX_NAME,NON_UNIQUE,SEQ_IN_INDEX,COLUMN_NAME,COALESCE(SUB_PART,0) FROM information_schema.statistics WHERE table_schema='${database}' ORDER BY TABLE_NAME,INDEX_NAME,SEQ_IN_INDEX`);
  return { wordpress: { events: checked.events }, public: { ...values, ...checked.public, rowCounts, contentHashes,
    schemaSha256: sha256(columns + '\n' + indexes), registrySha256: sha256(canonical(registry)), journalSha256: sha256(canonical(journal)) } };
}

export function restoreArguments(kind, run, networkId) {
  need(['postgres', 'mysql'].includes(kind) && /^[a-f0-9]{24}$/u.test(run) && ID.test(networkId));
  const data = kind === 'postgres' ? '/var/lib/postgresql/data' : '/var/lib/mysql';
  const args = ['create', '--pull=never', '--name', `fncp-expanded-${kind}-${run}`, '--label', `${LABEL}=${run}`, '--network', networkId,
    '--restart=no', '--memory=1200m', '--pids-limit=256', '--tmpfs', `${data}:rw,nosuid,nodev,size=768m`,
    '--tmpfs', '/docker-entrypoint-initdb.d:ro,nosuid,nodev,size=1m'];
  if (kind === 'postgres') args.push('--env', 'POSTGRES_HOST_AUTH_METHOD=trust', '--env', `POSTGRES_DB=${PG_DB}`, '--env', `POSTGRES_USER=${PG_ROLE}`);
  else args.push('--env', 'MYSQL_ALLOW_EMPTY_PASSWORD=yes', '--env', `MYSQL_DATABASE=${WP_DB}`);
  return [...args, IMAGES[kind]];
}
export function validateRestoreTarget(info, kind, run, net, sources, beforeStart = false) {
  need(['postgres', 'mysql'].includes(kind) && ID.test(info.Id ?? '') && !sources.includes(info.Id) &&
    info.Image === IMAGES[kind] && info.Labels?.[LABEL] === run && Object.keys(info.Ports ?? {}).length === 0);
  const attached = Object.values(info.Networks ?? {});
  need(attached.length === 1 && (attached[0].NetworkID === net || beforeStart && !info.Running && attached[0].NetworkID === '' && Object.keys(info.Networks)[0] === 'fncp-expanded-' + run));
  const data = kind === 'postgres' ? '/var/lib/postgresql/data' : '/var/lib/mysql';
  const expected = { [data]: 'rw,nosuid,nodev,size=768m', '/docker-entrypoint-initdb.d': 'ro,nosuid,nodev,size=1m' };
  if (info.Mounts?.length === 0) equal(info.Tmpfs, expected);
  else need(info.Mounts?.length === 2 && info.Mounts.every(m => m.Type === 'tmpfs') &&
    info.Mounts.some(m => m.Destination === data) && info.Mounts.some(m => m.Destination === '/docker-entrypoint-initdb.d'));
}
async function ready(id, kind) {
  for (let i = 0; i < 90; i++) {
    try {
      if (kind === 'postgres') docker(['exec', id, 'pg_isready', '-h', '127.0.0.1', '-U', PG_ROLE, '-d', PG_DB]);
      else need(docker(['exec', id, 'mysql', '--protocol=TCP', '-h', '127.0.0.1', '-u', 'root', '--batch', '--skip-column-names', '-e', 'SELECT 1']).trim() === '1');
      return;
    } catch { await pause(500); }
  }
  throw new Error('Fresh isolated recovery database unavailable.');
}

/** Explicit private inputs only; output is redacted aggregate evidence. The
 * caller, not this function, must stop original apps and create a fresh journey.
 * It retains encrypted archives + separate private key + private restored SQLite
 * work, and STOPPED owned restore containers/internal network. No rm/down-v.
 */
export async function runExpandedRecovery(input) {
  let phase = 'input-boundary'; const run = randomBytes(12).toString('hex'); const owned = [];
  let networkId, sourcePg, dir, work, encryptionKey, sourceKeys, sourceAccess, sourceActivation;
  let before, final, restoredSummary, strictResult; let sourceHashes, sourcePreserved = false, stopped = true, passed = false;
  let archiveCount = 0; let authenticated = false; let sourceWp; let sourceApplicationStopCount = 0; const bystanders = [];
  let keyRetained = false; let plaintextBackupCopies = 0;
  try {
    const suffix = validateInput(input); const w = input.wordpress; sourceWp = w.containerId;
    need(realpathSync(w.directory) === w.directory && dirname(realpathSync(w.directory)) === WP_RUNTIME);
    regularPrivate(w.composePath);
    const spec = JSON.parse(readPrivate(w.composePath));
    need(spec.name === w.project && spec.services?.db?.container_name === 'fncp-wp-identity-db-' + suffix &&
      spec.services.db.environment?.MYSQL_DATABASE === w.database && spec.services.db.environment?.MYSQL_USER === w.databaseUser &&
      spec.volumes?.['identity-db']?.name === w.volume);
    // Check the supplied signing keys against THIS newly branded instance's
    // private generated configuration package; never read the old WP package.
    phase = 'new-wordpress-signing-config';
    validateWordPressSigningConfiguration(readPrivate(resolve(w.directory, 'wordpress/wp-config.php')).toString('utf8'), input.wordpressSecrets);
    // Resolve the explicitly permitted macOS /var -> /private/var tmp alias
    // once, then retain strict canonical-path and single-link requirements.
    phase = 'closed-canonical-source-paths';
    const paths = [input.sourceAccessPath, input.sourceActivationPath].map(path => realpathSync(path));
    need(dirname(paths[0]) === dirname(paths[1]) && dirname(dirname(paths[0])) === realpathSync(tmpdir()) &&
      basename(paths[0]) === 'access.sqlite' && basename(paths[1]) === 'activation.sqlite' &&
      basename(dirname(paths[0])) === basename(dirname(input.sourceAccessPath)));
    need(realpathSync(dirname(paths[0])) === dirname(paths[0]) && lstatSync(dirname(paths[0])).isDirectory() && (lstatSync(dirname(paths[0])).mode & 0o777) === 0o700);
    const a = regularPrivate(paths[0]); const b = regularPrivate(paths[1]); need(!(a.dev === b.dev && a.ino === b.ino));
    phase = 'fixed-provider-key-and-binding';
    const envBytes = readPrivate(ENV); const env = parseEnv(envBytes.toString('utf8'));
    const config = validateConfiguration(env, 'synthetic-local-restore-proof', existsSync(resolve(DEPLOY, '.synthetic-bootstrap-restart')));
    need(config.project === 'fncp-polis-staging' && input.sourceBinding.conversationId === config.conversation && input.sourceBinding.configSha256 === sha256(envBytes));
    const seedBytes = readFileSync(resolve(DEPLOY, 'seed-statements.json')); const seeds = JSON.parse(seedBytes); need(input.sourceBinding.seedSha256 === sha256(seedBytes));
    sourceKeys = keyPackage({ identity: input.identity, activation: input.activation, wordpressSecrets: input.wordpressSecrets,
      providerSecrets: { gateway: env.FNCP_GATEWAY_SHARED_SECRET, allowlist: env.FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL } });
    phase = 'exact-sources-and-quiescence';
    sourcePg = docker(['compose', '--project-name', config.project, '--env-file', ENV, '-f', COMPOSE, 'ps', '-q', 'postgres']).trim();
    const pgi = inspect(sourcePg); validateSourceContainer(pgi, config, COMPOSE); need(pgi.Image === IMAGES.postgres && pgi.Mounts.length === 1 &&
      pgi.Mounts[0].Type === 'volume' && pgi.Mounts[0].Name === 'fncp-polis-staging_fncp-postgres');
    const wpi = inspect(sourceWp); validateWordPressSource(wpi, w);
    const pgn = network(Object.values(pgi.Networks)[0].NetworkID); need(pgn.Internal && pgn.Labels?.['com.docker.compose.project'] === config.project);
    const wpn = network(Object.values(wpi.Networks)[0].NetworkID); need(wpn.Labels?.['org.barayamal.fncp.identity-run'] === w.project && wpn.Options?.['com.docker.network.bridge.enable_icc'] === 'false');
    // The parent may keep its legacy SYNTHETIC WordPress database running for
    // its own preservation comparison. Verify container metadata only: this
    // runner never reads that DB, its files, credentials, journal or contents.
    const bystander = docker(['ps', '-q', '--no-trunc', '--filter', 'name=^/fncp-wordpress-synthetic-db-1$']).trim();
    if (bystander) { validateLegacyWordPressContainer(inspect(bystander)); need(![sourcePg, sourceWp].includes(bystander)); bystanders.push(bystander); }
    phase = 'stop-exact-source-applications'; sourceApplicationStopCount = stopSourceApplications(input.sourceBinding);
    quiescent(sourcePg, sourceWp, paths, [], false, bystanders);
    sourceHashes = paths.map(path => sha256(readPrivate(path)));
    sourceAccess = new DatabaseSync(paths[0], { readOnly: true }); sourceActivation = new DatabaseSync(paths[1], { readOnly: true });
    sourceAccess.exec('BEGIN'); sourceActivation.exec('BEGIN');
    const access = readStrictStore(sourceAccess, 'access'); const activation = readStrictStore(sourceActivation, 'activation');
    const mappingProof = verifyMappings(access.tables.identity_mappings, sourceKeys);
    const now = Math.floor(Date.now() / 1000);
    const snapshot = () => {
      const access = readStrictStore(sourceAccess, 'access'); const activation = readStrictStore(sourceActivation, 'activation');
      const wp = wpSnapshot(sourceWp, w, access.tables.identity_mappings, input.wordpressSecrets.challenge, now);
      const polis = pgSnapshot(sourcePg, config, seeds, access.tables.identity_mappings);
      return { source: { binding: input.sourceBinding, access, activation, wordpress: wp.wordpress, provider: polis.provider,
        volatile: { oidcPending: 0, principalCapabilities: 0, browserSessions: 0 } },
        public: { access: { schemaSha256: access.schemaSha256, contentSha256: sha256(canonical(access)), rowCounts: Object.fromEntries(Object.entries(access.tables).map(([k, v]) => [k, v.length])) },
          activation: { schemaSha256: activation.schemaSha256, contentSha256: sha256(canonical(activation)), rowCounts: Object.fromEntries(Object.entries(activation.tables).map(([k, v]) => [k, v.length])) },
          wordpress: wp.public, polis: polis.public, identityMappingProof: mappingProof, keyFingerprints: fingerprints(sourceKeys) } };
    };
    phase = 'four-store-terminal-snapshot'; before = snapshot();
    // All closed cross-store validation is repeated below against the actual
    // restore. Reject obvious authority before creating any target or backup.
    need(access.tables.round.length === 1 && access.tables.round[0].open === 0 && activation.tables.activation_state.length === 1 &&
      activation.tables.activation_state[0].active === 0 && access.tables.sessions.length === 0 && access.tables.approvals.every(r => r.state === 'revoked') && access.tables.invitations.every(r => r.used === 1));
    const scope = { classification: 'SYNTHETIC_LOCAL_EXPANDED_FOUR_STORE_ONLY', context: CONTEXT,
      wordpressDatabaseSha256: sha256(w.database), wordpressInstanceSha256: sha256(w.project),
      conversationSha256: sha256(config.conversation), accessSourceSha256: sourceHashes[0], activationSourceSha256: sourceHashes[1],
      sourceImages: { postgres: pgi.Image, mysql: wpi.Image }, components: COMPONENTS,
      includes: ['fresh-wordpress-registry-and-journal', 'strict-identity-mappings', 'access-and-invitation-replay-state', 'activation-replay-ledger', 'synthetic-polis-votes-and-tombstones', 'encrypted-synthetic-key-continuity'],
      excludes: ['live-wordpress', 'page-12064-form-12069', 'real-participants', 'provider-accounts', 'production-signer', 'wordpress-files-and-media', 'offsite-key-custody', 'production-disaster-recovery'] };
    const scopeSha256 = sha256(canonical(scope));
    privateDirectory(RUNTIME); dir = resolve(RUNTIME, 'expanded-' + run); privateDirectory(dir, true);
    work = resolve(RUNTIME, 'work-' + run); privateDirectory(work, true);
    privateDirectory(resolve(RUNTIME, 'keys')); encryptionKey = randomBytes(32); const keyPath = resolve(RUNTIME, 'keys', run + '.key');
    writePrivate(keyPath, encryptionKey); need(readPrivate(keyPath).equals(encryptionKey)); keyRetained = true;
    const components = {};
    const retain = (name, bytes) => { try { components[name] = seal(bytes, encryptionKey, header(run, name, scopeSha256));
      writePrivate(resolve(dir, name + '.aesgcm'), components[name]); archiveCount++; } finally { bytes.fill(0); } };
    phase = 'encrypted-backup-and-independent-reread';
    retain('polis-postgresql', docker(['exec', sourcePg, 'pg_dump', '--format=custom', '--no-owner', '--no-acl', '-U', config.role, '-d', config.database], { encoding: 'buffer' }));
    retain('wordpress-mysql', docker(['exec', sourceWp, 'sh', '-c', 'MYSQL_PWD="$(cat /run/secrets/db-password)" exec mysqldump --single-transaction --quick --skip-lock-tables --no-tablespaces --set-gtid-purged=OFF --skip-add-locks --skip-add-drop-table --skip-dump-date --hex-blob -u ' + w.databaseUser + ' ' + w.database], { encoding: 'buffer' }));
    // node:sqlite's online backup API creates complete NEW files. Private work
    // copies are deliberately retained, not confused with encrypted archives.
    for (const [kind, db] of [['access', sourceAccess], ['activation', sourceActivation]]) {
      const path = resolve(work, kind + '-backup.sqlite'); need(!existsSync(path)); await backup(db, path); chmodSync(path, 0o600);
      retain(kind + '-sqlite', readPrivate(path)); plaintextBackupCopies++;
    }
    retain('key-continuity', Buffer.from(canonical(sourceKeys)));
    equal(before.public, snapshot().public); equal(sourceHashes, paths.map(path => sha256(readPrivate(path))));
    const manifest = { version: 1, mode: MODE, run, recordedAt: new Date().toISOString(), scopeSha256, scope, source: before.public,
      components: Object.fromEntries(COMPONENTS.map(name => [name, { filename: name + '.aesgcm', bytes: components[name].length, sha256: sha256(components[name]), mode: '600' }])) };
    writePrivate(resolve(dir, 'manifest.json'), canonical(signManifest(manifest, encryptionKey)) + '\n');
    const disk = Object.fromEntries(COMPONENTS.map(name => [name, readPrivate(resolve(dir, name + '.aesgcm'))]));
    verifyManifest(JSON.parse(readPrivate(resolve(dir, 'manifest.json'))), encryptionKey, run, scopeSha256, disk);
    const plaintext = Object.fromEntries(COMPONENTS.map(name => [name, unseal(disk[name], encryptionKey, header(run, name, scopeSha256))]));
    authenticated = true;
    try {
      const recoveredKeys = JSON.parse(plaintext['key-continuity']); equal(sourceKeys, recoveredKeys);
      phase = 'fresh-portless-database-targets';
      networkId = docker(['network', 'create', '--internal', '--label', `${LABEL}=${run}`, 'fncp-expanded-' + run]).trim(); need(ID.test(networkId));
      const net = network(networkId); need(net.Internal && net.Labels?.[LABEL] === run && Object.keys(net.Containers ?? {}).length === 0);
      for (const kind of ['postgres', 'mysql']) {
        const id = docker(restoreArguments(kind, run, networkId)).trim(); need(ID.test(id) && ![sourcePg, sourceWp].includes(id)); owned.push({ id, kind });
        validateRestoreTarget(inspect(id), kind, run, networkId, [sourcePg, sourceWp], true);
        docker(['start', id]); validateRestoreTarget(inspect(id), kind, run, networkId, [sourcePg, sourceWp]);
        validateRuntimeMounts(docker(['exec', id, 'cat', '/proc/mounts']), kind); await ready(id, kind);
      }
      const restoredPg = owned.find(x => x.kind === 'postgres').id; const restoredWp = owned.find(x => x.kind === 'mysql').id;
      const restoredConfig = { ...config, role: PG_ROLE, database: PG_DB };
      need(pg(restoredPg, restoredConfig, "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'") === '0');
      need(mysql(restoredWp, w, `SELECT count(*) FROM information_schema.tables WHERE table_schema='${WP_DB}'`, { restored: true }) === '0');
      phase = 'actual-restore-and-row-hash-equivalence';
      docker(['exec', '-i', restoredPg, 'pg_restore', '--exit-on-error', '--no-owner', '--no-privileges', '-U', PG_ROLE, '-d', PG_DB], { input: plaintext['polis-postgresql'] });
      docker(['exec', '-i', restoredWp, 'mysql', '--binary-mode', '-u', 'root', WP_DB], { input: plaintext['wordpress-mysql'] });
      const restoredWordPress = wpSnapshot(restoredWp, w, access.tables.identity_mappings, recoveredKeys.wordpressSecrets.challenge, now, true);
      const restoredPolis = pgSnapshot(restoredPg, restoredConfig, seeds, access.tables.identity_mappings);
      equal(before.public.wordpress, restoredWordPress.public); equal(before.public.polis, restoredPolis.public);
      phase = 'strict-mapping-replay-and-closed-cold-start-proof';
      strictResult = await restoreStrictSqlite({ directory: work, accessBytes: plaintext['access-sqlite'], activationBytes: plaintext['activation-sqlite'],
        sourcePaths: paths, source: before.source, restoredWordPress: restoredWordPress.wordpress,
        restoredProvider: restoredPolis.provider, keys: recoveredKeys });
      writePrivate(resolve(dir, 'strict-manifest.json'), canonical(strictResult.manifest) + '\n');
      restoredSummary = { wordpress: restoredWordPress.public, polis: restoredPolis.public, strict: strictResult.public };
    } finally { for (const bytes of Object.values(plaintext)) bytes.fill(0); }
    phase = 'independent-source-preservation-recheck';
    quiescent(sourcePg, sourceWp, paths, owned.map(x => x.id), true, bystanders); final = snapshot(); equal(before.public, final.public);
    equal(sourceHashes, paths.map(path => sha256(readPrivate(path)))); need(sha256(readPrivate(ENV)) === sha256(envBytes));
    sourcePreserved = true; passed = true; phase = 'complete';
  } catch { /* phase is fixed text; raw parser/SQL/Docker exceptions are NEVER returned. */ }
  finally {
    for (const db of [sourceAccess, sourceActivation]) { try { db?.close(); } catch { stopped = false; } }
    for (const target of owned.reverse()) {
      try {
        validateRestoreTarget(inspect(target.id), target.kind, run, networkId, [sourcePg, sourceWp]);
        docker(['stop', '--time', '10', target.id]); need(inspect(target.id).Running === false);
      } catch { stopped = false; }
    }
  }
  const report = { outcome: passed && stopped ? 'PASS' : 'FAIL', mode: MODE, phase,
    diagnostics: !stopped ? 'REDACTED_RESTORE_SHUTDOWN_FAILURE' : passed ? null : 'REDACTED_BOUNDARY_OR_RUNTIME_FAILURE',
    recordedAt: new Date().toISOString(), run, productionReady: false, actualDataStoresRestored: strictResult ? 4 : 0,
    actualExpandedRestoreCompleted: passed, sourceCountsAndHashesPreserved: sourcePreserved,
    source: before?.public ?? null, restored: restoredSummary ?? null,
    encryptedArchiveComponents: archiveCount, encryptedArchiveAuthenticated: authenticated && archiveCount === COMPONENTS.length,
    separatePrivateEncryptionKeyRetained: keyRetained, privatePlaintextSqliteWorkRetained: plaintextBackupCopies > 0,
    retainedPlaintextBackupCopies: plaintextBackupCopies,
    ownedRestoreContainersStopped: stopped, ownedRestoreContainersRetained: owned.length, internalNetworkRetained: !!networkId,
    noSourceWrites: true, noExternalPortsPublished: true, noSourceAppsStarted: true, sourceApplicationStopCount,
    excludedBystanderContainers: bystanders.length, noDeletionCommands: true,
    wordpressApplicationRestarted: false, realOidcProviderTested: false, productionDisasterRecoveryProven: false,
    restoredAccessServiceColdStarted: strictResult?.public.coldStart?.actualControlledAccessServiceStarted === true,
    restoredAccessServiceClosed: strictResult?.public.coldStart?.listenersClosed === true,
    restoredAccessStayedClosed: strictResult?.public.coldStart?.closedBeforeAndAfter === true,
    restoredAccessProviderCalls: strictResult?.public.coldStart?.providerCalls ?? 0,
    restoredAccessNegativeChecks: strictResult?.public.coldStart?.httpNegativeChecks ?? 0,
    oldSignedActivationRejected: strictResult?.public.coldStart?.oldSignedActivationRejected === true,
    originalRawCredentialReplayTested: false,
    evidenceDirectory: dir ? 'deploy/fncp/expanded-recovery/.runtime/expanded-' + run : null };
  if (dir && encryptionKey) { try { writePrivate(resolve(dir, 'result.json'), canonical(signManifest(report, encryptionKey)) + '\n'); }
    catch { report.outcome = 'FAIL'; report.diagnostics = 'REDACTED_EVIDENCE_WRITE_FAILURE'; } }
  encryptionKey?.fill(0);
  return report;
}
