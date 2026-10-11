import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { activeCandidateQuery, allScopedWhitelistCountQuery, CLEANUP_MODE, validateApiContainer,
  validateCandidateIds, validateScopedWhitelistCount } from './cleanup-synthetic-allowlist.mjs';

test('candidate SQL is exact-conversation, current-provider-state and SELECT-only', () => {
  const sql = activeCandidateQuery('9syntheticOnly');
  assert.match(sql, /^SELECT COALESCE/);
  assert.match(sql, /z.zinvite='9syntheticOnly'/);
  assert.match(sql, /operation.operation_version=1 AND operation.desired_present IS TRUE/);
  assert.match(sql, /allowed.owner=c.owner/);
  assert.doesNotMatch(sql, /\b(?:INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE)\b/u);
  assert.throws(() => activeCandidateQuery("bad' OR true"));
});

test('candidate rows must be bounded, unique opaque synthetic IDs', () => {
  assert.deepEqual(validateCandidateIds([]), []);
  const xid = 'fncp_synthetic_0123456789abcdef';
  assert.deepEqual(validateCandidateIds([xid]), [xid]);
  for (const invalid of [[xid, xid], ['person@example.org'], ['fncp_short'], null, Array(101).fill(xid)]) {
    assert.throws(() => validateCandidateIds(invalid));
  }
});

test('independent whitelist aggregate includes untracked and legacy owner-wide rows', () => {
  const sql = allScopedWhitelistCountQuery('9syntheticOnly');
  assert.match(sql, /^SELECT count\(\*\) FROM xid_whitelist/);
  assert.match(sql, /z.zinvite='9syntheticOnly'/);
  assert.match(sql, /allowed.zid=c.zid OR \(allowed.zid IS NULL AND allowed.owner=c.owner\)/);
  assert.doesNotMatch(sql, /operation_version|fncp_provider_allowlist_operations|\b(?:DELETE|UPDATE|INSERT|DROP)\b/u);
  assert.equal(validateScopedWhitelistCount(0), 0);
  for (const invalid of [-1, '0', 0.5, NaN, null]) assert.throws(() => validateScopedWhitelistCount(invalid));
  const source = readFileSync(new URL('./cleanup-synthetic-allowlist.mjs', import.meta.url), 'utf8');
  assert.ok(source.indexOf('if (allBefore !== selected)') < source.indexOf("provider.allowlist('remove'"));
  assert.ok(source.indexOf('allRemaining !== 0') < source.indexOf("outcome: 'PASS'"));
});

test('API transport must belong to exact compose and loopback binding', () => {
  const network = 'c'.repeat(64);
  const config = { project: 'fncp-local-synthetic' };
  const info = { Id: 'a'.repeat(64), Running: true, Labels: {
    'com.docker.compose.project': config.project, 'com.docker.compose.service': 'server',
    'com.docker.compose.project.config_files': '/exact/source.yml',
  }, Ports: { '5000/tcp': [{ HostIp: '127.0.0.1', HostPort: '5500' }] },
  Networks: { internal: { NetworkID: network } } };
  assert.doesNotThrow(() => validateApiContainer(info, config, network, '/exact/source.yml'));
  for (const invalid of [{ Running: false }, { Labels: {} }, { Networks: {} },
    { Ports: { '5000/tcp': [{ HostIp: '0.0.0.0', HostPort: '5500' }] } }]) {
    assert.throws(() => validateApiContainer({ ...info, ...invalid }, config, network, '/exact/source.yml'));
  }
});

test('cleanup gates precede provider writes; output is aggregate-only', () => {
  const source = readFileSync(new URL('./cleanup-synthetic-allowlist.mjs', import.meta.url), 'utf8');
  assert.equal(CLEANUP_MODE, 'revoke-synthetic-allowlist-only');
  assert.ok(source.indexOf('validateAggregate(before)') < source.indexOf("provider.allowlist('remove'"));
  assert.match(source, /validateSourceContainer\(sourceInfo, config, COMPOSE\)/);
  assert.match(source, /validateApiContainer\(inspectContainer\(server\)/);
  assert.match(source, /removed.present !== false \|\| removed.operationVersion !== 2/);
  assert.doesNotMatch(source, /writeFile|is_active\s*:|allowlist\('upsert'|console\.(?:log|error)\([^\n]*(?:xid|candidates|env|sourceInfo)/);
});
