import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID, createHmac } from 'node:crypto';
import { chmodSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { DatabaseSync } from 'node:sqlite';
import { createControlledLocalAccess } from '../activation-foundation/controlled-access.mjs';
import { syntheticBinding, syntheticClaims, syntheticSigningFixture } from '../activation-foundation/synthetic-fixtures.mjs';
import { INTEGRATED_IDENTITY_MODE } from '../local-access/access-server.mjs';
import { canonical, readStrictStore } from '../strict-recovery/contract.mjs';
import { MODE, COMPONENTS, header, seal, unseal, sha256, signManifest, verifyManifest } from './crypto.mjs';
import { keyPackage, fingerprints, verifyMappings, restoreStrictSqlite } from './restore-sqlite.mjs';
import { IMAGES, restoreArguments, validateRestoreTarget, validateApplicationContainer, validateWordPressSigningConfiguration, runExpandedRecovery } from './run.mjs';

const run = 'a'.repeat(24); const scope = { synthetic: true }; const scopeHash = sha256(canonical(scope));
const clone = v => JSON.parse(JSON.stringify(v));

const secrets = { event: 'e'.repeat(43), challenge: 'c'.repeat(43), registration: 'r'.repeat(43) };
const generatedConfig = "<?php\n// GENERATED PRIVATE.\ndefine('FNCP_WP_LOCAL_EVENT_SECRET', '" + secrets.event + "');\n" +
  "define('FNCP_WP_CHALLENGE_SECRET', '" + secrets.challenge + "');\n" +
  "define('FNCP_BFF_REGISTRATION_SECRET', '" + secrets.registration + "');\n";
test('preflight reads exact generated PHP signing constants, not DB-only credentials.json', () => {
  assert.equal(validateWordPressSigningConfiguration(generatedConfig, secrets), true);
  assert.throws(() => validateWordPressSigningConfiguration(JSON.stringify({ mode: 'SYNTHETIC_ONLY', dbPassword: 'invented-secret', rootPassword: 'invented-root', adminPassword: 'invented-admin' }), secrets));
});
for (const [name, change] of Object.entries({ missing: s => s.replace(/^define\('FNCP_WP_CHALLENGE_SECRET'.*\n/mu, ''),
  duplicate: s => s + "define('FNCP_WP_LOCAL_EVENT_SECRET', '" + secrets.event + "');\n",
  mismatch: s => s.replace(secrets.registration, 'x'.repeat(43)), comment: s => s.replace('define(', '// define('),
})) test('PHP signing preflight rejects ' + name + ' with redacted diagnostic', () => {
  assert.throws(() => validateWordPressSigningConfiguration(change(generatedConfig), secrets), /^Error: Expanded synthetic recovery denied\.$/u);
});

for (const name of COMPONENTS) test('authenticated encrypted roundtrip for ' + name, () => {
  const key = randomBytes(32); const h = header(run, name, scopeHash); const plain = Buffer.from('invented-private-sentinel-' + name);
  const encoded = seal(plain, key, h);
  assert.equal(encoded.includes(plain), false); assert.deepEqual(unseal(encoded, key, h), plain);
  assert.notDeepEqual(seal(plain, key, h), encoded);
  assert.throws(() => unseal(encoded, randomBytes(32), h), /authentication failed/u);
});
const mutations = {
  nonce: e => { e.nonce = '0'.repeat(24); }, tag: e => { e.tag = '0'.repeat(32); },
  ciphertext: e => { e.ciphertext = Buffer.from('invented-tampered').toString('base64'); },
  header: e => { e.header.run = 'b'.repeat(24); }, extra: e => { e.extra = true; },
  'invalid base64': e => { e.ciphertext = 'AAAA===='; },
  'nonce trailing newline': e => { e.nonce += '\n'; },
  'tag trailing newline': e => { e.tag += '\n'; },
};
for (const [name, mutate] of Object.entries(mutations)) test('encrypted component rejects ' + name, () => {
  const key = randomBytes(32); const h = header(run, 'key-continuity', scopeHash);
  const encoded = JSON.parse(seal(Buffer.from('invented-secret-sentinel'), key, h)); mutate(encoded);
  assert.throws(() => unseal(Buffer.from(JSON.stringify(encoded)), key, h), /^Error: Expanded encrypted component authentication failed\.$/u);
});
test('component, run and scope substitution are rejected', () => {
  const key = randomBytes(32); const h = header(run, 'access-sqlite', scopeHash); const e = seal(Buffer.from('invented'), key, h);
  for (const other of [header(run, 'activation-sqlite', scopeHash), header('b'.repeat(24), 'access-sqlite', scopeHash), header(run, 'access-sqlite', 'f'.repeat(64))]) {
    assert.throws(() => unseal(e, key, other));
  }
});
function archive() {
  const key = randomBytes(32);
  const components = Object.fromEntries(COMPONENTS.map(name => [name, seal(Buffer.from('invented-' + name), key, header(run, name, scopeHash))]));
  const manifest = { version: 1, mode: MODE, run, recordedAt: new Date().toISOString(), scopeSha256: scopeHash, scope, source: { aggregate: 2 },
    components: Object.fromEntries(COMPONENTS.map(name => [name, { filename: name + '.aesgcm', bytes: components[name].length, sha256: sha256(components[name]), mode: '600' }])) };
  return { key, components, manifest, signed: signManifest(manifest, key) };
}
test('all four stores and key component are mandatory and authenticated', () => {
  const a = archive(); assert.deepEqual(verifyManifest(a.signed, a.key, run, scopeHash, a.components), a.manifest);
  for (const name of COMPONENTS) { const absent = { ...a.components }; delete absent[name]; assert.throws(() => verifyManifest(a.signed, a.key, run, scopeHash, absent)); }
});
for (const [name, mutate] of Object.entries({ filename: m => { m.components['access-sqlite'].filename = '../source.sqlite'; },
  mode: m => { m.mode = 'production'; }, permission: m => { m.components['access-sqlite'].mode = '644'; },
  hash: m => { m.components['access-sqlite'].sha256 = 'f'.repeat(64); }, extra: m => { m.extra = 'invented'; } })) {
  test('even correctly MACed manifest rejects ' + name, () => {
    const a = archive(); mutate(a.manifest); assert.throws(() => verifyManifest(signManifest(a.manifest, a.key), a.key, run, scopeHash, a.components));
  });
}

async function fixture() {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'fncp-expanded-test-'))); chmodSync(directory, 0o700);
  const work = join(directory, 'fresh-target'); mkdirSync(work, { mode: 0o700 });
  const accessPath = join(directory, 'source-access.sqlite'); const activationPath = join(directory, 'source-activation.sqlite');
  const identity = { key: randomBytes(32), keyVersion: 1, issuer: 'https://identity.example.invalid/', clientId: 'invented-client',
    syntheticSubjects: ['synthetic_alice', 'synthetic_bob'] };
  const signer = syntheticSigningFixture(); const time = Date.now(); const now = () => time; let calls = 0;
  const provider = { allowlist() { calls++; throw new Error('No network in a fixture.'); }, participate() { calls++; throw new Error('No network in a fixture.'); } };
  const binding = syntheticBinding();
  const app = createControlledLocalAccess({ mode: 'fixture-only', dbPath: accessPath, conversationId: binding.conversationId,
    identityMode: INTEGRATED_IDENTITY_MODE, identityFoundation: { isVerifiedPrincipal: () => false, participantXid: () => ({ ok: false }) },
    adminSecret: randomBytes(32).toString('base64url'), provider, now,
    activation: { mode: 'SYNTHETIC_ONLY', binding, publicKey: signer.publicKey, keyId: signer.keyId, ledgerPath: activationPath, now } });
  const sourceBinding = app.activationBinding(); const priorEnvelope = signer.signClaims(syntheticClaims(sourceBinding, Math.floor(time / 1000)));
  app.activate(priorEnvelope); await app.close();
  const wordpress = { events: [] }; const operations = [];
  const db = new DatabaseSync(accessPath);
  try {
    const hmac = value => createHmac('sha256', identity.key).update(JSON.stringify(value)).digest('base64url');
    for (const subject of identity.syntheticSubjects) {
      const account = 'acct_' + hmac(['fncp-account-v1', identity.issuer, subject]); const fixture = 'synthetic_i' + sha256(account).slice(0, 39);
      const xid = 'fncp_' + hmac(['fncp-xid-v1', account, binding.conversationId]);
      db.prepare('INSERT INTO fixtures VALUES(?,?)').run(fixture, sha256('invented-' + subject));
      db.prepare('INSERT INTO identity_mappings VALUES(?,?,?,?)').run(account, fixture, binding.conversationId, xid);
      db.prepare('INSERT INTO approvals VALUES(?,?,?,?)').run(fixture, binding.conversationId, xid, 'revoked');
      db.prepare('INSERT INTO invitations VALUES(?,?,?,?,1)').run(sha256('invented-invite-' + subject), fixture, binding.conversationId, time + 60000);
      for (const [version, state] of [[1, 'approved'], [2, 'revoked']]) {
        const event = { schema_version: 1, event_id: randomUUID(), subject: fixture, round_id: 'synthetic_round_local', version, state,
          occurred_at: new Date(time).toISOString().replace(/\.\d{3}Z$/u, 'Z') };
        wordpress.events.push({ event, acknowledged: true });
        const digest = sha256(JSON.stringify(['schema_version', 'event_id', 'subject', 'round_id', 'version', 'state', 'occurred_at'].map(k => event[k])));
        db.prepare('INSERT INTO wordpress_events VALUES(?,?,?,?,?,1)').run(event.event_id, fixture, version, state, digest);
      }
      operations.push({ xid, operationVersion: 2, present: false });
    }
  } finally { db.close(); }
  const read = (path, kind) => { const db = new DatabaseSync(path, { readOnly: true }); try { return readStrictStore(db, kind); } finally { db.close(); } };
  const source = { binding: sourceBinding, access: read(accessPath, 'access'), activation: read(activationPath, 'activation'), wordpress,
    provider: { conversationId: binding.conversationId, whitelistRows: 0, operations }, volatile: { oidcPending: 0, principalCapabilities: 0, browserSessions: 0 } };
  const keys = keyPackage({ identity, activation: { ...signer, priorEnvelope },
    wordpressSecrets: { event: 'e'.repeat(43), challenge: 'c'.repeat(43), registration: 'r'.repeat(43) },
    providerSecrets: { gateway: 'g'.repeat(43), allowlist: 'p'.repeat(43) } });
  return { directory, source, keys, calls: () => calls, work, paths: [accessPath, activationPath],
    args: () => ({ directory: work, sourcePaths: [accessPath, activationPath], accessBytes: readFileSync(accessPath), activationBytes: readFileSync(activationPath),
      source: clone(source), restoredWordPress: clone(wordpress), restoredProvider: clone(source.provider), keys: clone(keys), now }),
    close: () => rmSync(directory, { recursive: true }) };
}
test('ACTUAL fresh SQLite restore cold-starts current controlled access closed, rejects prior grant, closes its sole listener without provider calls', async () => {
  const f = await fixture();
  try {
    const sourceHashes = f.paths.map(p => sha256(readFileSync(p))); const result = await restoreStrictSqlite(f.args());
    assert.equal(result.public.ok, true); assert.equal(result.public.sqliteStoresActuallyRestored, 2);
    assert.equal(result.public.originalSignatureVerified, true); assert.equal(result.public.oldSignedActivationRejected, true);
    assert.equal(result.public.restoredAuthorityActive, false); assert.equal(result.public.noListenersStarted, false);
    assert.deepEqual(result.public.coldStart, { actualControlledAccessServiceStarted: true, loopbackOnly: true, listenersClosed: true,
      providerCalls: 0, closedBeforeAndAfter: true, oldSignedActivationRejected: true, restoredSessionsAbsent: true,
      retainedInvitationsConsumed: true, originalRawCredentialReplayTested: false, invalidReplayCanariesRejected: true,
      terminalApprovalRetriesNonGranting: true, terminalJournalUnchanged: true, httpNegativeChecks: 10,
      staleApprovalRetries: 2, terminalRevocationRetries: 2 });
    assert.equal(result.public.actualMultiStoreRestorePerformed, false); assert.equal(result.public.localRecoveryIdConsumed, true);
    assert.equal(result.public.counts.mappings, 2); assert.equal(result.public.counts.retainedActivationIds, 1);
    assert.equal(result.public.counts.retainedUsedInvitations, 2); assert.equal(result.public.identityMappingProof.emailIdentifiersUsed, false);
    assert.equal(f.calls(), 0); assert.deepEqual(f.paths.map(p => sha256(readFileSync(p))), sourceHashes);
    assert.deepEqual(result.restored.access, f.source.access);
    assert.notEqual(result.restored.binding.bootId, f.source.binding.bootId);
    assert.notEqual(result.restored.binding.recoveryEpoch, f.source.binding.recoveryEpoch);
    await assert.rejects(() => restoreStrictSqlite(f.args()));
    for (const row of f.source.access.tables.identity_mappings) assert.equal(JSON.stringify(result.public).includes(row.xid), false);
  } finally { f.close(); }
});
for (const [name, mutate] of Object.entries({
  'mapping key drift': a => { a.keys.identity.key = randomBytes(32).toString('base64url'); },
  'issuer drift': a => { a.keys.identity.issuer = 'https://other.example.invalid/'; },
  'wrong subject': a => { a.keys.identity.syntheticSubjects[0] = 'synthetic_eve'; },
  'provider tombstone absent': a => { a.restoredProvider.operations.pop(); },
  'unacknowledged WordPress event': a => { a.restoredWordPress.events[0].acknowledged = false; },
  'old activation signature tamper': a => { a.keys.activation.priorEnvelope.signature = 'a'.repeat(86); },
  'source access claim mismatch': a => { a.source.access.tables.approvals[0].state = 'approved'; },
  'existing target': a => { writeFileSync(join(a.directory, 'restored-access.sqlite'), 'invented-do-not-overwrite', { mode: 0o600 }); },
})) test('restore denies ' + name + ' and preserves source bytes', async () => {
  const f = await fixture();
  try { const hashes = f.paths.map(p => sha256(readFileSync(p))); const a = f.args(); mutate(a);
    await assert.rejects(() => restoreStrictSqlite(a)); assert.deepEqual(f.paths.map(p => sha256(readFileSync(p))), hashes); assert.equal(f.calls(), 0);
  } finally { f.close(); }
});

for (const [name, statement] of Object.entries({
  'an open restored round': 'UPDATE round SET open=1',
  'a retained warm session': "INSERT INTO sessions SELECT 'invented_prior_hash',fixture,round,'participation',9999999999999 FROM identity_mappings LIMIT 1",
  'an unconsumed invitation': 'UPDATE invitations SET used=0',
  'a nonterminal approval': "UPDATE approvals SET state='approved'",
})) test('cold-start preflight denies ' + name + ' even when the snapshot claim matches those bytes', async () => {
  const f = await fixture();
  try {
    const db = new DatabaseSync(f.paths[0]);
    try {
      db.exec(statement);
      if (name === 'a retained warm session') {
        // The strict reader rejects nonzero sessions before returning a
        // snapshot, so supply the matching altered claim explicitly here.
        f.source.access.tables.sessions = db.prepare('SELECT * FROM sessions ORDER BY 1').all().map(row => ({ ...row }));
      } else f.source.access = readStrictStore(db, 'access');
    } finally { db.close(); }
    const hashes = f.paths.map(path => sha256(readFileSync(path)));
    await assert.rejects(() => restoreStrictSqlite(f.args()), /^Error: (?:Expanded|Strict) synthetic recovery denied\.$/u);
    assert.deepEqual(f.paths.map(path => sha256(readFileSync(path))), hashes); assert.equal(f.calls(), 0);
  } finally { f.close(); }
});

test('cold-start preflight denies an active activation ledger without consuming or altering its source', async () => {
  const f = await fixture();
  try {
    const db = new DatabaseSync(f.paths[1]);
    try { db.exec('UPDATE activation_state SET active=1'); f.source.activation = readStrictStore(db, 'activation'); } finally { db.close(); }
    const hashes = f.paths.map(path => sha256(readFileSync(path)));
    await assert.rejects(() => restoreStrictSqlite(f.args()), /^Error: Expanded synthetic recovery denied\.$/u);
    assert.deepEqual(f.paths.map(path => sha256(readFileSync(path))), hashes); assert.equal(f.calls(), 0);
  } finally { f.close(); }
});

test('failure after the actual listener starts still closes every owned listener and preserves all source bytes', async () => {
  const f = await fixture();
  const servers = () => process.getActiveResourcesInfo().filter(name => name === 'TCPServerWrap').length;
  try {
    const before = servers(); const hashes = f.paths.map(path => sha256(readFileSync(path)));
    const args = f.args();
    // Valid shape but a conflicting old event identity: the actual gate must
    // reject after the negative HTTP checks rather than apply/provider-call it.
    args.source.wordpress.events[0].event.event_id = randomUUID();
    await assert.rejects(() => restoreStrictSqlite(args));
    // libuv destroys an already-closed server handle in a later loop phase.
    // Bound that bookkeeping delay; a live owned listener must not survive it.
    for (let attempt = 0; servers() !== before && attempt < 20; attempt++) await new Promise(resolve => setTimeout(resolve, 5));
    assert.equal(servers(), before);
    assert.deepEqual(f.paths.map(path => sha256(readFileSync(path))), hashes); assert.equal(f.calls(), 0);
    const db = new DatabaseSync(join(f.work, 'restored-access.sqlite'), { readOnly: true });
    try { assert.deepEqual(readStrictStore(db, 'access'), f.source.access); } finally { db.close(); }
  } finally { f.close(); }
});

test('cold-start public evidence never claims original raw bearer replay or full WordPress/IdP restart', async () => {
  const f = await fixture();
  try {
    const result = await restoreStrictSqlite(f.args()); const output = JSON.stringify(result.public);
    assert.equal(result.public.coldStart.originalRawCredentialReplayTested, false);
    assert.equal(result.public.coldStart.invalidReplayCanariesRejected, true);
    for (const secret of [f.keys.identity.key, ...Object.values(f.keys.wordpressSecrets), ...Object.values(f.keys.providerSecrets),
      f.keys.activation.priorEnvelope.payload, f.keys.activation.priorEnvelope.signature,
      ...f.source.access.tables.identity_mappings.flatMap(row => [row.account_id, row.fixture, row.xid])]) assert.equal(output.includes(secret), false);
    assert.equal(Object.hasOwn(result.public.coldStart, 'wordpressApplicationRestarted'), false);
    assert.equal(Object.hasOwn(result.public.coldStart, 'realOidcProviderTested'), false);
  } finally { f.close(); }
});

test('cold start accepts a directly revoked version-one subject without inventing an earlier approved event', async () => {
  const f = await fixture();
  try {
    const fixture = f.source.access.tables.identity_mappings[0].fixture;
    const previous = f.source.wordpress.events.find(entry => entry.event.subject === fixture && entry.event.state === 'revoked');
    previous.event.version = 1;
    f.source.wordpress.events = f.source.wordpress.events.filter(entry => entry.event.subject !== fixture || entry.event.state === 'revoked');
    const digest = sha256(JSON.stringify(['schema_version', 'event_id', 'subject', 'round_id', 'version', 'state', 'occurred_at'].map(key => previous.event[key])));
    const db = new DatabaseSync(f.paths[0]);
    try {
      db.prepare("DELETE FROM wordpress_events WHERE subject=? AND state='approved'").run(fixture);
      db.prepare('UPDATE wordpress_events SET version=1,digest=? WHERE event_id=?').run(digest, previous.event.event_id);
      f.source.access = readStrictStore(db, 'access');
    } finally { db.close(); }
    const hashes = f.paths.map(path => sha256(readFileSync(path)));
    const result = await restoreStrictSqlite(f.args());
    assert.equal(result.public.ok, true); assert.equal(result.public.coldStart.providerCalls, 0);
    assert.equal(result.public.coldStart.staleApprovalRetries, 1);
    assert.equal(result.public.coldStart.terminalRevocationRetries, 2);
    assert.equal(result.public.coldStart.terminalApprovalRetriesNonGranting, true);
    assert.deepEqual(f.paths.map(path => sha256(readFileSync(path))), hashes);
  } finally { f.close(); }
});
test('five key-role fingerprints expose no secret material', async () => {
  const f = await fixture(); try {
    const result = fingerprints(f.keys); assert.equal(Object.keys(result.fingerprints).length, 5);
    for (const secret of [f.keys.identity.key, ...Object.values(f.keys.wordpressSecrets), ...Object.values(f.keys.providerSecrets)]) assert.equal(JSON.stringify(result).includes(secret), false);
    assert.equal(verifyMappings(f.source.access.tables.identity_mappings, f.keys).issuerSubjectMappingsVerified, 2);
  } finally { f.close(); }
});

test('restore container commands use cached exact images, internal network, no ports/host mounts/deletion', () => {
  for (const kind of ['postgres', 'mysql']) {
    const args = restoreArguments(kind, run, 'b'.repeat(64)); assert.equal(args[0], 'create'); assert.equal(args.at(-1), IMAGES[kind]);
    assert.ok(args.includes('--pull=never')); assert.ok(args.includes('--network')); assert.ok(args.includes('--tmpfs'));
    for (const forbidden of ['-p', '--publish', '-v', '--volume', '--mount', '--privileged', 'rm', '--network=host']) assert.equal(args.includes(forbidden), false);
  }
});
function target() {
  return { Id: 'c'.repeat(64), Image: IMAGES.postgres, Running: true, Labels: { 'org.barayamal.fncp.expanded-recovery-run': run }, Ports: {},
    Networks: { owned: { NetworkID: 'b'.repeat(64) } }, Mounts: [], Tmpfs: { '/var/lib/postgresql/data': 'rw,nosuid,nodev,size=768m', '/docker-entrypoint-initdb.d': 'ro,nosuid,nodev,size=1m' } };
}
test('exact owned restore target validation', () => assert.doesNotThrow(() => validateRestoreTarget(target(), 'postgres', run, 'b'.repeat(64), ['d'.repeat(64)])));
for (const [name, change] of Object.entries({ source: x => { x.Id = 'd'.repeat(64); }, labels: x => { x.Labels = {}; }, ports: x => { x.Ports = { '5432/tcp': [{ HostIp: '0.0.0.0', HostPort: '5432' }] }; },
  image: x => { x.Image = IMAGES.mysql; }, network: x => { x.Networks.owned.NetworkID = 'd'.repeat(64); }, hostmount: x => { x.Mounts = [{ Type: 'bind', Source: '/invented', Destination: '/var/lib/postgresql/data' }]; } })) {
  test('restore target rejects ' + name, () => { const x = target(); change(x); assert.throws(() => validateRestoreTarget(x, 'postgres', run, 'b'.repeat(64), ['d'.repeat(64)])); });
}
test('no Docker or file operations on invalid explicit mode; result redacts attacker strings', async () => {
  const result = await runExpandedRecovery({ mode: 'invented-private-sentinel' });
  assert.equal(result.outcome, 'FAIL'); assert.equal(result.phase, 'input-boundary'); assert.equal(result.encryptedArchiveComponents, 0);
  assert.equal(result.actualDataStoresRestored, 0); assert.equal(JSON.stringify(result).includes('invented-private-sentinel'), false);
});
