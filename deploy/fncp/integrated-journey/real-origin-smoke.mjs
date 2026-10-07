/**
 * Explicit synthetic integrated protocol proof against the ALREADY RUNNING
 * isolated loopback Pol.is stack. This runner starts no Docker service, adopts
 * no preserved access/WordPress store, sends no external message, and grants
 * no launch authority. The helper owns only fresh temporary stores/listeners.
 * One invented vote remains in the disposable Pol.is conversation on success.
 */
import { execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual, parseEnv } from 'node:util';
import { readStagingProvider } from '../local-access/staging-config.mjs';
import { MODE } from '../local-access/access-server.mjs';
import { allScopedWhitelistCountQuery, validateApiContainer } from '../local-access/cleanup-synthetic-allowlist.mjs';
import { aggregateQuery, CONTEXT, validateAggregate, validateConfiguration,
  validateSourceContainer } from '../local-recovery/recovery-proof.mjs';
import { validateWordPressSource } from '../local-recovery/coordinated-proof.mjs';

const ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const DEPLOY = resolve(ROOT, 'deploy/fncp');
const ENV = resolve(DEPLOY, '.env.staging');
const COMPOSE = resolve(DEPLOY, 'docker-compose.staging.yml');
const ACCESS = resolve(DEPLOY, 'local-access/.runtime/synthetic.sqlite');
const SERVICES = Object.freeze({ server: 'server', math: 'math', alpha: 'client-participation-alpha', proxy: 'nginx-proxy' });
const WP_TABLES = ['commentmeta', 'comments', 'links', 'options', 'postmeta', 'posts',
  'term_relationships', 'term_taxonomy', 'termmeta', 'terms', 'usermeta', 'users'].map((name) => 'synthetic_' + name);
const ID = /^[a-f0-9]{64}$/u;
const SHA_ID = /^sha256:[a-f0-9]{64}$/u;
const sha = (value) => createHash('sha256').update(value).digest('hex');
const requireThat = (condition) => { if (!condition) throw new Error('Integrated synthetic proof boundary failed.'); };
const same = (left, right) => requireThat(isDeepStrictEqual(left, right));
const sqlString = (value) => "'" + value.replaceAll("'", "''") + "'";

function docker(args, options = {}) {
  // Never inherit stdout/stderr: child diagnostics can contain private values.
  return execFileSync('docker', ['--context', CONTEXT, ...args], { cwd: ROOT,
    encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 30_000,
    maxBuffer: 2 * 1024 * 1024, ...options }).trim();
}

function inspect(name) {
  // Fixed code-owned names only. Deliberately omit Config.Env and logs.
  requireThat(/^fncp-(polis-staging-(server|math|client-participation-alpha|nginx-proxy|postgres)|wordpress-synthetic-db)-1$/u.test(name));
  return JSON.parse(docker(['inspect', '--type', 'container', '--format',
    '{"Id":{{json .Id}},"Image":{{json .Image}},"Running":{{json .State.Running}},' +
    '"Labels":{{json .Config.Labels}},"Ports":{{json .HostConfig.PortBindings}},' +
    '"Networks":{{json .NetworkSettings.Networks}},"Mounts":{{json .Mounts}}}', name]));
}

export function observedBinding(conversationId, recoveryEpoch) {
  const images = {};
  for (const [role, service] of Object.entries(SERVICES)) {
    const info = inspect(`fncp-polis-staging-${service}-1`);
    requireThat(ID.test(info.Id ?? '') && SHA_ID.test(info.Image ?? '') && info.Running &&
      info.Labels?.['com.docker.compose.project'] === 'fncp-polis-staging' &&
      info.Labels?.['com.docker.compose.service'] === service &&
      (info.Labels?.['com.docker.compose.project.config_files'] ?? '').split(',').includes(COMPOSE) &&
      Object.values(info.Ports ?? {}).flat().every((port) => port?.HostIp === '127.0.0.1'));
    images[role] = info.Image;
  }
  images.migration = JSON.parse(docker(['image', 'inspect', '--format', '{{json .Id}}',
    'fncp-polis-staging-polis-migration']));
  requireThat(SHA_ID.test(images.migration));
  const seeds = readFileSync(resolve(DEPLOY, 'seed-statements.json'));
  const parsed = JSON.parse(seeds);
  requireThat(Array.isArray(parsed) && parsed.length === 15 && new Set(parsed).size === 15);
  return { deploymentId: 'synthetic_integrated_origin_proof', conversationId, recoveryEpoch,
    images, configSha256: sha(readFileSync(ENV)), seedSha256: sha(seeds),
    scope: { maxParticipants: 20, statementCount: 15, suggestions: false } };
}

export function accessPreservationHash() {
  // Hash opaque bytes only, without opening a write-capable SQLite connection.
  const stat = lstatSync(ACCESS);
  requireThat(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 &&
    (stat.mode & 0o777) === 0o600 && realpathSync(ACCESS) === ACCESS);
  for (const suffix of ['-wal', '-shm', '-journal']) requireThat(!existsSync(ACCESS + suffix));
  return sha(readFileSync(ACCESS));
}

export function wordpressPreservationSnapshot() {
  const info = inspect('fncp-wordpress-synthetic-db-1');
  validateWordPressSource(info);
  // SQL returns aggregate counts and an in-server hash, never journal contents,
  // email addresses, authentication hashes, credentials or registration records.
  const sql = `SELECT JSON_OBJECT(
    'tableCount',(SELECT count(*) FROM information_schema.tables WHERE table_schema='fncp_wp_synthetic'),
    'rowCounts',JSON_OBJECT(${WP_TABLES.map((table) => `${sqlString(table)},(SELECT count(*) FROM ${table})`).join(',')}),
    'journalRows',(SELECT count(*) FROM synthetic_options WHERE option_name='fncp_wp_local_journal_v1'),
    'journalHash',(SELECT SHA2(option_value,256) FROM synthetic_options WHERE option_name='fncp_wp_local_journal_v1'),
    'localSiteMatches',(SELECT count(*) FROM synthetic_options WHERE option_name IN ('siteurl','home') AND option_value='http://127.0.0.1:8102'),
    'registrationDisabled',(SELECT count(*) FROM synthetic_options WHERE option_name='users_can_register' AND option_value='0'),
    'publicDisabled',(SELECT count(*) FROM synthetic_options WHERE option_name='blog_public' AND option_value='0'))`;
  const snapshot = JSON.parse(docker(['exec', '-i', info.Id, 'sh', '-c',
    'MYSQL_PWD="$(cat /run/secrets/db-password)" exec mysql --batch --raw --skip-column-names -u fncp_wp_synthetic fncp_wp_synthetic'], { input: sql }));
  requireThat(snapshot.tableCount === 12 && snapshot.journalRows === 1 &&
    /^[a-f0-9]{64}$/u.test(snapshot.journalHash ?? '') && snapshot.localSiteMatches === 2 &&
    snapshot.registrationDisabled === 1 && snapshot.publicDisabled === 1 &&
    Object.keys(snapshot.rowCounts ?? {}).length === WP_TABLES.length &&
    Object.values(snapshot.rowCounts).every((n) => Number.isSafeInteger(n) && n >= 0));
  return { containerId: info.Id, imageId: info.Image, ...snapshot };
}

export function createPolisObservation(config, seeds, statementIds) {
  const info = inspect('fncp-polis-staging-postgres-1');
  validateSourceContainer(info, config, COMPOSE);
  const networkId = Object.values(info.Networks)[0]?.NetworkID;
  requireThat(ID.test(networkId ?? ''));
  const [network] = JSON.parse(docker(['network', 'inspect', networkId]));
  requireThat(network.Internal === true && network.Labels?.['com.docker.compose.project'] === config.project);
  validateApiContainer(inspect('fncp-polis-staging-server-1'), config, networkId, COMPOSE);
  const query = (sql) => JSON.parse(docker(['exec', '-i', info.Id, 'psql', '-X', '-A', '-t',
    '-v', 'ON_ERROR_STOP=1', '-U', config.role, '-d', config.database], { input: sql }));
  const expected = seeds.map(sqlString).join(',');
  const seedQuery = `SELECT json_build_object(
    'distinctTexts',count(DISTINCT txt),'distinctTids',count(DISTINCT tid),
    'manifestMatches',count(*) FILTER (WHERE tid IN (${statementIds.join(',')})))
    FROM comments c WHERE c.active IS TRUE AND c.is_seed IS TRUE AND c.txt IN (${expected})
      AND EXISTS (SELECT 1 FROM zinvites z WHERE z.zid=c.zid AND z.zinvite=${sqlString(config.conversation)});`;
  return () => {
    const aggregate = query(aggregateQuery(config.conversation, seeds)); validateAggregate(aggregate);
    const seedManifest = query(seedQuery);
    same(seedManifest, { distinctTexts: 15, distinctTids: 15, manifestMatches: 15 });
    const whitelistRows = query(allScopedWhitelistCountQuery(config.conversation));
    requireThat(Number.isSafeInteger(whitelistRows) && whitelistRows >= 0);
    return { aggregate, seedManifest, whitelistRows };
  };
}

export async function runIntegratedRealOriginSmoke(mode = process.env.FNCP_LOCAL_SYNTHETIC_MODE) {
  process.umask(0o077);
  const report = { classification: 'LOCAL_SYNTHETIC_INTEGRATED_JOURNEY_NOT_LAUNCH', checks: [], outcome: 'FAIL',
    cryptographicOidcProtocol: 'SYNTHETIC_INTERCEPTED_ISSUER', actualOidcProviderIntegrated: false,
    browserEvidence: 'HTTP_COOKIE_CSRF_PROTOCOL_NOT_RENDERED_BROWSER', realExternalBrowserTlsLogin: false,
    wordpressEvidence: 'SIGNED_EVENT_RECEIVER_WITH_FRESH_ACCESS_EVENT_LEDGER_NOT_WORDPRESS_UI_OR_PLUGIN_JOURNAL',
    actualLocalPolisProvider: false, mailboxOwnershipVerified: false, eligibilityVerified: false,
    runtimeBindingObservedBeforeAndAfter: false, independentDatabaseSeedManifestVerified: false,
    originalAccessBytesUnchanged: false, originalWordPressAggregateAndJournalUnchanged: false,
    wordpressPreservationEquivalence: 'ALL_TABLE_ROW_COUNTS_AND_EXACT_JOURNAL_HASH_NOT_FULL_DATABASE_EQUIVALENCE',
    allocatedAllowlistRemovalVerified: false, ownAuthorityClosed: false, ownHarnessCloseCompleted: false,
    noExternalSends: true, productionReady: false };
  let phase = 'explicit-mode'; let failurePhase; let app; let underlying; let before; let preservation;
  let observePolis; let polisBefore; let voteAttempts = 0; let voteAccepted = 0;
  const allocated = new Set(); const reserved = new Set();
  const check = (label, condition = true) => {
    requireThat(condition); report.checks.push(label); console.log(`PASS ${label}`);
  };
  try {
    requireThat(mode === MODE);
    const { createIntegratedJourney, exerciseCoreJourney } = await import('./proof-harness.mjs');
    const staging = readStagingProvider(mode); underlying = staging.provider;
    const env = parseEnv(readFileSync(ENV, 'utf8'));
    const config = validateConfiguration(env, 'synthetic-local-restore-proof',
      existsSync(resolve(DEPLOY, '.synthetic-bootstrap-restart')));
    requireThat(config.project === 'fncp-polis-staging' && config.conversation === staging.conversationId);
    const ids = (env.FNCP_FIXED_STATEMENT_IDS ?? '').split(',');
    requireThat(ids.length === 15 && ids.every((value) => /^(0|[1-9][0-9]*)$/u.test(value)));
    const statementIds = ids.map(Number);
    requireThat(new Set(statementIds).size === 15 && statementIds.every(Number.isSafeInteger));
    phase = 'runtime-and-preserved-store-preflight';
    before = observedBinding(config.conversation, randomUUID());
    preservation = { access: accessPreservationHash(), wordpress: wordpressPreservationSnapshot() };
    const seeds = JSON.parse(readFileSync(resolve(DEPLOY, 'seed-statements.json'), 'utf8'));
    observePolis = createPolisObservation(config, seeds, statementIds); polisBefore = observePolis();
    report.independentDatabaseSeedManifestVerified = true;
    check('exact isolated runtime and fifteen database seed manifest verified');
    const provider = Object.freeze({
      conversationId: config.conversation,
      async allowlist(operation, xid) {
        requireThat(/^fncp_[A-Za-z0-9_-]{43}$/u.test(xid ?? ''));
        if (operation === 'upsert' && !allocated.has(xid)) {
          requireThat(!reserved.has(xid) && allocated.size + reserved.size < 2);
          reserved.add(xid);
          try {
            const existing = await underlying.allowlist('readback', xid);
            requireThat(existing.present === false && existing.operationVersion === null);
            // Register ownership BEFORE dispatch, including uncertain responses.
            allocated.add(xid);
          } finally { reserved.delete(xid); }
        }
        requireThat(allocated.has(xid));
        return underlying.allowlist(operation, xid);
      },
      async participate(kind, xid, values) {
        requireThat(allocated.has(xid));
        if (kind === 'vote') { requireThat(voteAttempts === 0); voteAttempts++; }
        const result = await underlying.participate(kind, xid, values);
        if (kind === 'vote') voteAccepted++;
        return result;
      },
    });
    phase = 'integrated-oidc-browser-event-activation-journey';
    app = await createIntegratedJourney({ provider, binding: before, now: Date.now });
    const journey = await exerciseCoreJourney(app);
    requireThat(journey?.voteCount === 1 && Array.isArray(journey.checks) && journey.checks.length > 0 &&
      journey.checks.every((label) => typeof label === 'string' && /^[A-Za-z0-9 ()/,:.'+_-]{1,180}$/u.test(label)));
    // Labels are static assertions from the trusted local helper, not upstream
    // response fields. Never print callback URLs, credentials or raw assertions.
    for (const label of journey.checks) check(label);
    check('exactly two fresh provider identities allocated', allocated.size === 2);
    check('exactly one invented vote dispatched and accepted', voteAttempts === 1 && voteAccepted === 1);
    report.outcome = 'PASS';
  } catch {
    failurePhase = phase;
    console.error('INTEGRATED_ACTUAL_ORIGIN_PROOF=FAIL; diagnostics redacted; inspect the aggregate phase and last PASS stage.');
  } finally {
    let cleaned = true; let removed = 0;
    const cleanupFailed = (stage) => { cleaned = false; failurePhase ??= stage; };
    // Disable this proof's authority before provider cleanup. Keep its fresh
    // private mapping evidence until cleanup and preservation are established.
    // Never stop shared Docker or preserved local processes.
    try { if (app) { await app.closeAuthority(); report.ownAuthorityClosed = true; } }
    catch { cleanupFailed('own-authority-close'); }
    for (const xid of allocated) {
      try {
        await underlying.allowlist('remove', xid);
        const state = await underlying.allowlist('readback', xid);
        requireThat(state.present === false && state.operationVersion === 2); removed++;
      } catch { cleanupFailed('owned-provider-terminal-cleanup'); }
    }
    report.allocatedAllowlistRemovalVerified = allocated.size > 0 && removed === allocated.size;
    report.allocatedSyntheticIdentities = allocated.size; report.verifiedRemovedSyntheticIdentities = removed;
    report.inventedVoteDispatches = voteAttempts; report.acceptedInventedVotes = voteAccepted;
    report.actualLocalPolisProvider = voteAccepted === 1;
    if (before && preservation && polisBefore) {
      let observationPhase = 'runtime-binding-final-observation';
      try {
        same(observedBinding(before.conversationId, before.recoveryEpoch), before);
        report.runtimeBindingObservedBeforeAndAfter = true;
        observationPhase = 'original-access-preservation';
        same(accessPreservationHash(), preservation.access); report.originalAccessBytesUnchanged = true;
        observationPhase = 'original-wordpress-preservation';
        same(wordpressPreservationSnapshot(), preservation.wordpress); report.originalWordPressAggregateAndJournalUnchanged = true;
        observationPhase = 'database-vote-and-whitelist-final-observation';
        const after = observePolis();
        same(after.whitelistRows, polisBefore.whitelistRows);
        report.scopedWhitelistRestoredToBaseline = true;
        const voteDelta = after.aggregate.voteRows - polisBefore.aggregate.voteRows;
        const latestVoteDelta = after.aggregate.latestVoteRows - polisBefore.aggregate.latestVoteRows;
        // aggregateQuery counts schema, fixed seeds and votes, not provider
        // operation rows: the two new version-2 tombstones intentionally remain.
        same({ ...after.aggregate, voteRows: polisBefore.aggregate.voteRows,
          latestVoteRows: polisBefore.aggregate.latestVoteRows }, polisBefore.aggregate);
        requireThat(voteDelta === voteAccepted && latestVoteDelta === voteAccepted);
        report.aggregateVoteRowDelta = voteDelta; report.aggregateLatestVoteRowDelta = latestVoteDelta;
        report.disposableInventedVoteRetained = voteDelta > 0;
        report.imageIds = before.images; report.configSha256 = before.configSha256; report.seedSha256 = before.seedSha256;
      } catch { cleanupFailed(observationPhase); }
    }
    if (!cleaned || !report.ownAuthorityClosed || !report.allocatedAllowlistRemovalVerified ||
      !report.originalAccessBytesUnchanged || !report.originalWordPressAggregateAndJournalUnchanged ||
      !report.runtimeBindingObservedBeforeAndAfter) report.outcome = 'FAIL';
    const preserveStores = !cleaned || report.outcome !== 'PASS';
    report.temporaryStoresRetentionRequested = Boolean(app) && preserveStores;
    try { if (app) { await app.close({ preserveStores }); report.ownHarnessCloseCompleted = true; } }
    catch { cleanupFailed('own-harness-listener-close'); }
    if (!cleaned || !report.ownHarnessCloseCompleted) report.outcome = 'FAIL';
    report.phase = report.outcome === 'PASS' ? 'complete' : failurePhase ?? phase;
    report.generatedAt = new Date().toISOString();
    try {
      const folder = resolve(DEPLOY, 'evidence'); mkdirSync(folder, { recursive: true, mode: 0o700 });
      requireThat(lstatSync(folder).isDirectory() && !lstatSync(folder).isSymbolicLink() && realpathSync(folder) === folder);
      const path = resolve(folder, `integrated-origin-${report.generatedAt.replace(/[:.]/g, '-')}.json`);
      writeFileSync(path, JSON.stringify(report, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
      console.log(`INTEGRATED_ACTUAL_ORIGIN_PROOF=${report.outcome}; evidence ${path}`);
    } catch { report.outcome = 'FAIL'; console.error('INTEGRATED_ACTUAL_ORIGIN_PROOF=FAIL; aggregate evidence could not be retained.'); }
  }
  return report;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runIntegratedRealOriginSmoke().then((report) => { process.exitCode = report.outcome === 'PASS' ? 0 : 1; })
    .catch(() => { console.error('INTEGRATED_ACTUAL_ORIGIN_PROOF=FAIL; diagnostics redacted.'); process.exitCode = 1; });
}
