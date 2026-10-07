import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { aggregateQuery, classifyFailure, CONTEXT, readiness, restoreContainerArgs, validateAggregate,
  validateConfiguration, validateSourceContainer } from './recovery-proof.mjs';

const env = {
  FNCP_SYNTHETIC_BOOTSTRAP_COMPLETE: 'true', FNCP_GATEWAY_ENFORCEMENT: 'true',
  FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT: 'true', FNCP_GATEWAY_CONVERSATION_ID: '9syntheticOnly',
  FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID: '9syntheticOnly',
  COMPOSE_PROJECT_NAME: 'fncp-local-synthetic', POSTGRES_DB: 'fncp_polis_staging', POSTGRES_USER: 'fncp_polis',
};
const aggregate = { schemaTables: 100, schemaColumns: 1000, schemaIndexes: 100,
  schemaRoutines: 80, schemaConstraints: 30, conversations: 1, knownSyntheticConversations: 1,
  allStatements: 15, fixedSeedStatements: 15, unexpectedEmailRows: 0, voteRows: 4,
  latestVoteRows: 3, outOfScopeVoteRows: 0 };

test('static boundary: explicit context and completed synthetic config are mandatory', () => {
  assert.equal(CONTEXT, 'colima-fncp-c-20260913');
  assert.equal(validateConfiguration(env, 'synthetic-local-restore-proof').database, 'fncp_polis_staging');
  for (const mode of [undefined, 'true', 'production']) assert.throws(() => validateConfiguration(env, mode));
  assert.throws(() => validateConfiguration(env, 'synthetic-local-restore-proof', true));
  for (const invalid of [{ FNCP_SYNTHETIC_BOOTSTRAP_COMPLETE: 'false' }, { POSTGRES_DB: 'production' },
    { POSTGRES_USER: 'postgres' }, { COMPOSE_PROJECT_NAME: 'unrelated' },
    { FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID: '8otherConversation' }, { FNCP_GATEWAY_ENFORCEMENT: 'false' }]) {
    assert.throws(() => validateConfiguration({ ...env, ...invalid }, 'synthetic-local-restore-proof'));
  }
});

test('static boundary: exact source compose service, project, file, running state and no ports', () => {
  const info = { Id: 'a'.repeat(64), Image: 'sha256:' + 'b'.repeat(64), Running: true,
    Labels: { 'com.docker.compose.project': env.COMPOSE_PROJECT_NAME, 'com.docker.compose.service': 'postgres',
      'com.docker.compose.project.config_files': '/exact/source.yml,/exact/override.yml' },
    Ports: {}, Networks: { internal: {} }, Mounts: [{ Destination: '/var/lib/postgresql/data' }] };
  const config = validateConfiguration(env, 'synthetic-local-restore-proof');
  assert.doesNotThrow(() => validateSourceContainer(info, config, '/exact/source.yml'));
  for (const invalid of [{ Id: 'guess' }, { Running: false }, { Ports: { '5432/tcp': [] } },
    { Networks: { one: {}, two: {} } }, { Labels: {} }, { Mounts: [] }]) {
    assert.throws(() => validateSourceContainer({ ...info, ...invalid }, config, '/exact/source.yml'));
  }
  assert.throws(() => validateSourceContainer(info, config, '/different/source.yml'));
});

test('static boundary: aggregate query is SELECT-only and never returns participant identifiers/content', () => {
  const seeds = Array.from({ length: 15 }, (_, i) => `Synthetic statement ${i + 1}`);
  seeds[0] = "Synthetic owner's statement";
  const sql = aggregateQuery(env.FNCP_GATEWAY_CONVERSATION_ID, seeds);
  assert.ok(sql.startsWith('SELECT json_build_object('));
  assert.match(sql, /Synthetic owner''s statement/u);
  assert.doesNotMatch(sql, /\b(?:INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE)\b/u);
  assert.doesNotMatch(sql, /json_build_object\([^]*?'(?:xid|uid|pid|email|topic|description|txt)'\s*,/u);
  assert.equal((sql.match(/'fixedSeedStatements'/gu) ?? []).length, 1);
  assert.throws(() => aggregateQuery('https://example.org', seeds));
  assert.throws(() => aggregateQuery(env.FNCP_GATEWAY_CONVERSATION_ID, seeds.slice(0, 14)));
  assert.throws(() => aggregateQuery(env.FNCP_GATEWAY_CONVERSATION_ID, Array(15).fill('same')));
});

test('static boundary: non-synthetic, expanded, incomplete or nonaggregate source stops export', () => {
  assert.doesNotThrow(() => validateAggregate(aggregate));
  for (const invalid of [{ conversations: 2 }, { knownSyntheticConversations: 0 }, { allStatements: 16 },
    { fixedSeedStatements: 14 }, { unexpectedEmailRows: 1 }, { outOfScopeVoteRows: 1 },
    { voteRows: '4' }, { xid: 'must-not-exist' }]) assert.throws(() => validateAggregate({ ...aggregate, ...invalid }));
});

test('static boundary: new restore container has image ID, no pull, isolated network, tmpfs and no bind/port', () => {
  const args = restoreContainerArgs({ run: 'a'.repeat(24), network: 'b'.repeat(64), image: 'sha256:' + 'c'.repeat(64) });
  assert.equal(args[0], 'create'); assert.ok(args.includes('--pull=never')); assert.ok(args.includes('--restart=no'));
  assert.ok(args.includes('/var/lib/postgresql/data:rw,nosuid,nodev,size=512m'));
  assert.ok(args.includes('/docker-entrypoint-initdb.d:ro,nosuid,nodev,size=1m'));
  assert.equal(args.at(-1), 'sha256:' + 'c'.repeat(64));
  for (const forbidden of ['run', '--publish', '-p', '--volume', '-v', '--mount', '--network=host', '--privileged']) {
    assert.ok(!args.includes(forbidden));
  }
  assert.throws(() => restoreContainerArgs({ run: 'existing', network: 'bridge', image: 'postgres:latest' }));
});

test('static lifecycle: guard before dump, brand-new empty target, private archive and exact ownership cleanup', () => {
  const source = readFileSync(new URL('./recovery-proof.mjs', import.meta.url), 'utf8');
  assert.ok(source.indexOf('validateAggregate(sourceCounts)') < source.indexOf("'pg_dump'"));
  assert.ok(source.indexOf('Source changed during backup') < source.indexOf("'isolated-resource-create'"));
  assert.ok(source.indexOf("emptyCount !== '0'") < source.indexOf("'pg_restore'"));
  assert.match(source, /openSync\(partial, 'wx', 0o600\)/u);
  assert.match(source, /network', 'create', '--internal'/u);
  assert.match(source, /inspectContainer\(createdContainer\)\.Labels\?\.\[LABEL\] !== run/u);
  assert.match(source, /info\.Labels\?\.\[LABEL\] !== run \|\| Object\.keys\(info\.Containers/u);
  assert.match(source, /docker\(\['rm', '--force', '--volumes', createdContainer\]\)/u);
  assert.doesNotMatch(source, /docker\(\['(?:rm|stop|kill)'[^\n]*source/u);
  assert.doesNotMatch(source, /(?:system|volume|network)\s+prune|DROP DATABASE|TRUNCATE|rmSync/u);
  assert.match(source, /sourceDatabaseChangedByHelper: false/u);
});

test('startup regression model: wait for TCP final-server readiness, not temporary Unix-socket initserver', async () => {
  let calls = 0; let pauses = 0;
  const runner = (args) => {
    assert.deepEqual(args.slice(0, 6), ['exec', 'synthetic-container', 'pg_isready', '-h', '127.0.0.1', '-U']);
    calls++;
    if (calls < 3) throw new Error('Temporary initserver has no TCP listener yet.');
    return 'ready';
  };
  await readiness('synthetic-container', runner, async () => { pauses++; });
  assert.equal(calls, 3); assert.equal(pauses, 2);
  await assert.rejects(readiness('synthetic-container', () => { throw new Error(); }, async () => {}, 2), /not ready/u);
});

test('diagnostic regression: fixed codes expose no child SQL, secrets, IDs or arbitrary diagnostics', () => {
  const secret = 'synthetic-secret-do-not-print';
  assert.equal(classifyFailure({ stderr: `connection refused ${secret}` }), 'DATABASE_CONNECTION_UNAVAILABLE');
  assert.equal(classifyFailure({ stderr: `invalid mount ${secret}` }), 'INVALID_TEMPORARY_MOUNT');
  assert.equal(classifyFailure({ stderr: `arbitrary ${secret}`, code: 'UNRECOGNISED' }), 'UNCLASSIFIED_LOCAL_FAILURE');
  assert.equal(classifyFailure({ code: 'ETIMEDOUT' }), 'LOCAL_COMMAND_TIMEOUT');
});
