/** Explicit local synthetic cleanup. SQL is read-only; revocation uses the
 * existing private provider adapter. No vote, statement or database deletion.
 * Candidate synthetic XIDs are held in memory only and never logged.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseEnv } from 'node:util';
import { LocalPolisProvider } from './access-server.mjs';
import { aggregateQuery, CONTEXT, validateAggregate, validateConfiguration,
  validateSourceContainer } from '../local-recovery/recovery-proof.mjs';

export const CLEANUP_MODE = 'revoke-synthetic-allowlist-only';
const ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const COMPOSE = resolve(ROOT, 'deploy/fncp/docker-compose.staging.yml');
const ENV_FILE = resolve(ROOT, 'deploy/fncp/.env.staging');
const ID = /^[a-f0-9]{64}$/u;

export function activeCandidateQuery(conversation) {
  if (!/^[0-9][A-Za-z0-9_-]{5,99}$/u.test(conversation)) throw new Error('Invalid synthetic scope.');
  return `SELECT COALESCE(json_agg(operation.xid ORDER BY operation.xid), '[]'::json)
    FROM fncp_provider_allowlist_operations operation
    INNER JOIN xid_whitelist allowed ON allowed.zid=operation.zid AND allowed.xid=operation.xid
    INNER JOIN conversations c ON c.zid=operation.zid AND allowed.owner=c.owner
    INNER JOIN zinvites z ON z.zid=c.zid
    WHERE z.zinvite='${conversation}' AND c.use_xid_whitelist IS TRUE
      AND operation.operation_version=1 AND operation.desired_present IS TRUE;`;
}

export function validateCandidateIds(value) {
  if (!Array.isArray(value) || value.length > 100 || new Set(value).size !== value.length ||
      value.some((xid) => typeof xid !== 'string' || !/^fncp_[A-Za-z0-9_-]{16,251}$/u.test(xid))) {
    throw new Error('Synthetic cleanup candidate boundary failed.');
  }
  return value;
}

export function allScopedWhitelistCountQuery(conversation) {
  if (!/^[0-9][A-Za-z0-9_-]{5,99}$/u.test(conversation)) throw new Error('Invalid synthetic scope.');
  // Independent of the provider ledger: detect unexpected/untracked rows,
  // including legacy owner-wide rows that are not candidates for revocation.
  return `SELECT count(*) FROM xid_whitelist allowed WHERE EXISTS (
    SELECT 1 FROM conversations c INNER JOIN zinvites z ON z.zid=c.zid
    WHERE z.zinvite='${conversation}' AND
      (allowed.zid=c.zid OR (allowed.zid IS NULL AND allowed.owner=c.owner))
  );`;
}

export function validateScopedWhitelistCount(value) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error('Invalid aggregate whitelist count.');
  return value;
}

function docker(args, options = {}) {
  return execFileSync('docker', ['--context', CONTEXT, ...args], {
    encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 30000,
    maxBuffer: 1024 * 1024, ...options,
  }).trim();
}

function inspectContainer(id) {
  if (!ID.test(id)) throw new Error('Exact container identity missing.');
  // Never request Config.Env or container logs.
  const format = '{"Id":{{json .Id}},"Image":{{json .Image}},"Running":{{json .State.Running}},' +
    '"Labels":{{json .Config.Labels}},"Ports":{{json .HostConfig.PortBindings}},' +
    '"Networks":{{json .NetworkSettings.Networks}},"Mounts":{{json .Mounts}}}';
  return JSON.parse(docker(['inspect', '--type', 'container', '--format', format, id]));
}

export function validateApiContainer(info, config, networkId, composeFile = COMPOSE) {
  const files = (info.Labels?.['com.docker.compose.project.config_files'] ?? '').split(',');
  const ports = info.Ports?.['5000/tcp'];
  if (!ID.test(info.Id ?? '') || !info.Running ||
      info.Labels?.['com.docker.compose.project'] !== config.project ||
      info.Labels?.['com.docker.compose.service'] !== 'server' || !files.includes(composeFile) ||
      Object.keys(info.Ports ?? {}).length !== 1 || ports?.length !== 1 ||
      ports[0].HostIp !== '127.0.0.1' || ports[0].HostPort !== '5500' ||
      !Object.values(info.Networks ?? {}).some((network) => network.NetworkID === networkId)) {
    throw new Error('Exact loopback synthetic API container could not be verified.');
  }
}

export async function runSyntheticAllowlistCleanup(mode = process.env.FNCP_LOCAL_CLEANUP_MODE) {
  let phase = 'explicit-mode'; let selected = 0; let revoked = 0;
  try {
    if (mode !== CLEANUP_MODE) throw new Error('Explicit synthetic cleanup mode required.');
    const env = parseEnv(readFileSync(ENV_FILE, 'utf8'));
    const config = validateConfiguration(env, 'synthetic-local-restore-proof',
      existsSync(resolve(ROOT, 'deploy/fncp/.synthetic-bootstrap-restart')));
    const seeds = JSON.parse(readFileSync(resolve(ROOT, 'deploy/fncp/seed-statements.json'), 'utf8'));
    const guardQuery = aggregateQuery(config.conversation, seeds);
    const compose = ['compose', '--project-name', config.project, '--env-file', ENV_FILE, '-f', COMPOSE];
    phase = 'exact-local-container-guards';
    const source = docker([...compose, 'ps', '-q', 'postgres']);
    const sourceInfo = inspectContainer(source);
    validateSourceContainer(sourceInfo, config, COMPOSE);
    const networkId = Object.values(sourceInfo.Networks)[0].NetworkID;
    if (!ID.test(networkId)) throw new Error('Internal network identity missing.');
    const network = JSON.parse(docker(['network', 'inspect', '--format', '{{json .}}', networkId]));
    if (!network.Internal || network.Labels?.['com.docker.compose.project'] !== config.project) {
      throw new Error('Synthetic database network is not isolated.');
    }
    const server = docker([...compose, 'ps', '-q', 'server']);
    validateApiContainer(inspectContainer(server), config, networkId, COMPOSE);
    const query = (sql) => JSON.parse(docker(['exec', '-i', source, 'psql', '-X', '-A', '-t',
      '-v', 'ON_ERROR_STOP=1', '-U', config.role, '-d', config.database], { input: sql }));
    phase = 'synthetic-aggregate-guard';
    const before = query(guardQuery);
    validateAggregate(before);
    const provider = new LocalPolisProvider({ conversationId: config.conversation,
      gatewaySecret: env.FNCP_GATEWAY_SHARED_SECRET,
      providerSecret: env.FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL });
    // Raw synthetic IDs stay in this in-memory array, never stdout or files.
    const candidates = validateCandidateIds(query(activeCandidateQuery(config.conversation)));
    selected = candidates.length;
    const allWhitelistQuery = allScopedWhitelistCountQuery(config.conversation);
    const allBefore = validateScopedWhitelistCount(query(allWhitelistQuery));
    if (allBefore !== selected) {
      // Do not attempt to adopt or revoke legacy/untracked entries by guessing.
      throw new Error('Unexpected scoped whitelist entries require separate review.');
    }
    phase = 'exact-provider-revocation';
    for (const xid of candidates) {
      const current = await provider.allowlist('readback', xid);
      if (current.present === false && current.operationVersion === 2) continue;
      if (current.present !== true || current.operationVersion !== 1) throw new Error('Provider state changed.');
      await provider.allowlist('remove', xid);
      const removed = await provider.allowlist('readback', xid);
      if (removed.present !== false || removed.operationVersion !== 2) throw new Error('Revocation not verified.');
      revoked++;
    }
    phase = 'independent-final-readback';
    const remaining = validateCandidateIds(query(activeCandidateQuery(config.conversation)));
    const allRemaining = validateScopedWhitelistCount(query(allWhitelistQuery));
    const after = query(guardQuery);
    validateAggregate(after);
    if (remaining.length !== 0 || allRemaining !== 0 || JSON.stringify(before) !== JSON.stringify(after)) {
      throw new Error('Final synthetic guard failed.');
    }
    console.log(JSON.stringify({ outcome: 'PASS', selected, revoked, remainingActive: 0, remainingWhitelistRows: 0,
      voteAndStatementAggregatesUnchanged: true, conversationLifecycleChanged: false }));
    return true;
  } catch {
    console.error(JSON.stringify({ outcome: 'FAIL', phase, selected, revoked,
      detailsSuppressed: true, productionTouched: false }));
    return false;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runSyntheticAllowlistCleanup().then((passed) => { process.exitCode = passed ? 0 : 1; });
}
