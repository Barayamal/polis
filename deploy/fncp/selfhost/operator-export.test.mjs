import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, lstat, mkdtemp, open, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { aggregateOperatorSnapshot, operatorSnapshotSql, writeOperatorSnapshot } from './operator-export.mjs';

const rejected = { message: 'FNCP_OPERATOR_EXPORT_REJECTED' };
function fixture() {
  const statementIds = Array.from({ length: 15 }, (_, i) => i);
  const c = {
    version: 1, classification: 'closed-local-core', deployment: 'fncp-export-unit', platform: 'linux/arm64',
    engine: { host: 'unix:///unopened/export-test.sock', configDirectory: '/unopened/config' },
    stateDirectory: '/unopened/state', sourceRevision: 'a'.repeat(40),
    database: { name: 'unit_polis', owner: 'unit_owner', migrationRole: 'unit_migration', runtimeRole: 'unit_runtime',
      mathRole: 'unit_math', host: 'postgres', port: 5432 },
    binding: { conversationId: '9unitExportBinding', statementIds },
    identity: { issuer: 'https://issuer.invalid/', audience: 'unit-polis', jwksUri: 'https://issuer.invalid/jwks' },
  };
  const lock = { version: 1, sourceRevision: c.sourceRevision, sourceFingerprint: 'b'.repeat(64),
    images: Object.fromEntries(['api','math','migration','postgres'].map((name, i) => [name, 'sha256:' + String(i+1).repeat(64)])) };
  const groupIds = [2,7,11];
  const s = {
    database: c.database.name, role: c.database.migrationRole, readOnly: 'on', isolation: 'repeatable read',
    snapshotAt: '2026-09-14T12:00:00Z', tls: { ssl: true, version: 'TLSv1.3', bits: 256 },
    boundCount: 1, conversation: { code: c.binding.conversationId, closed: true, gated: true, dataOpen: false },
    participantRows: 19, identities: 19, identifiedRows: 19, voterCount: 18, latestVoteCount: 270,
    voteWatermark: 2000000, moderationWatermark: 1000000, invalidVoteEvents: 0,
    unknownLatestVotes: 0, ambiguousVoteTimes: false, latestMatchesHistory: true,
    statements: statementIds.map(id => ({ id, text: 'Approved statement ' + id, approved: true, active: true, seed: true,
      meta: false, agree: 6, disagree: 9, pass: 3 })),
    math: { environment: 'dev', tick: 0, cachingTick: 2, rowVoteWatermark: 2000000, dataVoteWatermark: 2000000,
      dataModWatermark: 1000000, bindingMatches: true, voterMembershipMatches: true, participants: 18,
      statementCount: 15, statementIds, modIn: statementIds, modOut: [], metaIds: [], groupIds,
      groupVotes: Object.fromEntries(groupIds.map(id => [id, { 'n-members': 6,
        votes: Object.fromEntries(statementIds.map(tid => [tid, { A: 2, D: 3, S: 6 }])) }])),
      consensus: Object.fromEntries(statementIds.map(id => [id, Math.pow(3/8,3)])) },
    mathTick: 0, auxiliary: [1,2].map(() => ({ tick: 0, voteWatermark: 2000000, bindingMatches: true })),
  };
  return { c, lock, s };
}

async function directory(t) {
  const dir = await mkdtemp(join(await realpath(tmpdir()), 'fncp-operator-export-test-'));
  await chmod(dir, 0o700); t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

test('fixed transaction is repeatable-read/read-only and returns aggregate projections only', () => {
  const { c } = fixture(), sql = operatorSnapshotSql(c);
  assert.match(sql, /^BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;/);
  assert.match(sql, /ROLLBACK;\n$/);
  assert.doesNotMatch(sql, /^\s*(?:INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|GRANT|REVOKE|TRUNCATE|COPY|DO|CALL)\b/im);
  assert.match(sql, /pg_stat_ssl/);
  assert.match(sql, /latestMatchesHistory/);
  assert.match(sql, /lastModTimestamp/);
  assert.doesNotMatch(sql, /'data'\s*,\s*data\b|'votes'\s*,\s*jsonb_agg|'uid'\s*,|'pid'\s*,|'email'\s*,|'xid'\s*,/);
  assert.throws(() => operatorSnapshotSql({ ...c, binding: { ...c.binding, conversationId: "'; DROP TABLE votes;--" } }));
});

test('aggregate output is a whitelist; private fields injected into inputs never propagate', () => {
  const { c, lock, s } = fixture();
  const sentinel = 'PRIVATE_IDENTITY_SENTINEL';
  s.email = sentinel; s.uid = sentinel; s.pid = sentinel; s.xid = sentinel;
  s.math['base-clusters'] = { members: [[sentinel]] };
  s.math['in-conv'] = [sentinel]; s.math.voteVectors = sentinel;
  s.statements.forEach(x => { x.authorEmail = sentinel; x.uid = sentinel; });
  s.math.groupVotes[2].members = [sentinel];
  const result = aggregateOperatorSnapshot(c, lock, s);
  const serialized = JSON.stringify(result);
  assert.equal(serialized.includes(sentinel), false);
  assert.deepEqual(Object.keys(result).sort(), ['aggregate','authorization','classification','consensusDefinition',
    'oidcStaffAuthorizationImplemented','scope','snapshot','source','statements','version'].sort());
  assert.deepEqual(Object.keys(result.statements[0]).sort(), ['agree','disagree','nativeGroupAwareConsensus','pass','statementId','text'].sort());
  assert.deepEqual(result.aggregate.groupSizes, [6,6,6]);
  assert.equal(result.statements[0].agree, 6); assert.equal(result.statements[0].disagree, 9);
  assert.equal(result.statements[0].pass, 3);
  assert.equal(result.statements[0].nativeGroupAwareConsensus, Math.pow(3/8,3));
  assert.equal(result.oidcStaffAuthorizationImplemented, false);
  assert.equal(result.snapshot.mathTick, 0);
});

const denials = [
  ['wrong binding', x => { x.s.conversation.code = '9anotherConversation'; }],
  ['multiple bindings', x => { x.s.boundCount = 2; }],
  ['open conversation', x => { x.s.conversation.closed = false; }],
  ['ungated conversation', x => { x.s.conversation.gated = false; }],
  ['public source data', x => { x.s.conversation.dataOpen = true; }],
  ['wrong fixed statement set', x => { x.s.statements[0].id = 40; }],
  ['unapproved statement', x => { x.s.statements[0].approved = false; }],
  ['nonseed statement', x => { x.s.statements[0].seed = false; }],
  ['over identity cap', x => { x.s.identities = x.s.participantRows = x.s.identifiedRows = 21; }],
  ['unidentified participant', x => { x.s.identifiedRows--; }],
  ['wrong migration identity', x => { x.s.role = 'postgres'; }],
  ['TLS absent', x => { x.s.tls.ssl = false; }],
  ['TLS bit count missing', x => { delete x.s.tls.bits; }],
  ['TLS bit count coerced', x => { x.s.tls.bits = '256'; }],
  ['writable snapshot', x => { x.s.readOnly = 'off'; }],
  ['weak snapshot isolation', x => { x.s.isolation = 'read committed'; }],
  ['stale main vote watermark', x => { x.s.math.dataVoteWatermark--; }],
  ['stale moderation watermark', x => { x.s.math.dataModWatermark--; }],
  ['missing moderation watermark', x => { delete x.s.math.dataModWatermark; }],
  ['incorrect moderation set', x => { x.s.math.modIn = x.s.math.modIn.slice(1); }],
  ['moderated out statement', x => { x.s.math.modOut = [0]; }],
  ['mixed persistence tick', x => { x.s.auxiliary[0].tick++; }],
  ['stale auxiliary watermark', x => { x.s.auxiliary[1].voteWatermark--; }],
  ['unknown voter membership', x => { x.s.math.voterMembershipMatches = false; }],
  ['unknown statement vote', x => { x.s.unknownLatestVotes = 1; }],
  ['latest history mismatch', x => { x.s.latestMatchesHistory = false; }],
  ['ambiguous latest time', x => { x.s.ambiguousVoteTimes = true; }],
  ['native consensus corruption', x => { x.s.math.consensus[0] = 0.9; }],
  ['group count corruption', x => { x.s.math.groupVotes[2]['n-members'] = 7; }],
  ['native aggregate mismatch', x => { x.s.math.groupVotes[2].votes[0].A++; }],
  ['incorrect total votes', x => { x.s.latestVoteCount--; }],
  ['wrong source revision', x => { x.lock.sourceRevision = 'c'.repeat(40); }],
];
for (const [name, alter] of denials) test('rejects ' + name + ' before creating any output', async t => {
  const f = fixture(), dir = await directory(t), path = join(dir, 'export.json');
  alter(f);
  await assert.rejects(writeOperatorSnapshot(f.c, f.lock, f.s, path), rejected);
  await assert.rejects(lstat(path), { code: 'ENOENT' });
});

test('successful export creates only a new0600 file and refuses overwrite', async t => {
  const { c, lock, s } = fixture(), dir = await directory(t), path = join(dir, 'export.json');
  const result = await writeOperatorSnapshot(c, lock, s, path);
  assert.equal(result.result, 'PASS'); assert.equal((await lstat(path)).mode & 0o7777, 0o600);
  const original = await readFile(path); assert.equal(JSON.parse(original).statements.length, 15);
  await assert.rejects(writeOperatorSnapshot(c, lock, s, path), rejected);
  assert.deepEqual(await readFile(path), original);
});

test('public destination directory and symlink destination are rejected without touching existing files', async t => {
  const { c, lock, s } = fixture(), dir = await directory(t), path = join(dir, 'export.json');
  await chmod(dir, 0o755);
  await assert.rejects(writeOperatorSnapshot(c, lock, s, path), rejected);
  await chmod(dir, 0o700);
  const existing = join(dir, 'keep.txt'); await writeFile(existing, 'preserve', { mode: 0o600 });
  await symlink(existing, path);
  await assert.rejects(writeOperatorSnapshot(c, lock, s, path), rejected);
  assert.equal(await readFile(existing, 'utf8'), 'preserve');
});

test('destination permissions changed during write reject and remove only the new output', async t => {
  const { c, lock, s } = fixture(), dir = await directory(t), path = join(dir, 'export.json');
  const probe = await open(join(dir, 'probe'), 'wx', 0o600);
  const prototype = Object.getPrototypeOf(probe), original = prototype.writeFile;
  await probe.close();
  prototype.writeFile = async function (...args) {
    await chmod(dir, 0o755);
    return original.apply(this, args);
  };
  try {
    await assert.rejects(writeOperatorSnapshot(c, lock, s, path), rejected);
    await assert.rejects(lstat(path), { code: 'ENOENT' });
  } finally {
    prototype.writeFile = original;
    await chmod(dir, 0o700);
  }
});

test('private folder inside the actual source checkout cannot receive an aggregate export', async t => {
  const { c, lock, s } = fixture();
  const repository = await realpath(fileURLToPath(new URL('../../../', import.meta.url)));
  const dir = await mkdtemp(join(repository, '.operator-export-private-test-'));
  await chmod(dir, 0o700);
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, 'never-package-this.json');
  await assert.rejects(writeOperatorSnapshot(c, lock, s, path), rejected);
  await assert.rejects(lstat(path), { code: 'ENOENT' });
});
