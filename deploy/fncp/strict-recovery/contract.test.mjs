import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { copyFileSync, mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { DatabaseSync } from 'node:sqlite';
import { createControlledLocalAccess } from '../activation-foundation/controlled-access.mjs';
import { syntheticBinding, syntheticClaims, syntheticSigningFixture } from '../activation-foundation/synthetic-fixtures.mjs';
import { INTEGRATED_IDENTITY_MODE } from '../local-access/access-server.mjs';
import { MODE, PURPOSE, SIGNING_DOMAIN, MAPPING_ALGORITHM, canonical, SCHEMA_SHA256,
  readStrictStore, publicKeyFingerprint, prepareStrictRecoveryManifest, validateStrictRecovery } from './contract.mjs';

const sha = (value) => createHash('sha256').update(value).digest('hex');
const clone = (value) => JSON.parse(JSON.stringify(value));
const denied = { ok: false, error: 'strict_recovery_denied' };

async function fixture() {
  // Only newly created test paths; never import/open a .runtime database.
  const directory = mkdtempSync(join(tmpdir(), 'fncp-strict-recovery-test-'));
  const paths = Object.fromEntries(['source-access', 'source-activation', 'restored-access', 'restored-activation'].map((name) => [name, join(directory, name + '.sqlite')]));
  const stamp = Date.now(); const now = () => stamp;
  const signer = syntheticSigningFixture(); const manifestSigner = generateKeyPairSync('ed25519');
  let providerCalls = 0;
  const provider = { allowlist() { providerCalls++; throw new Error('No provider call belongs in this model.'); },
    participate() { providerCalls++; throw new Error('No provider call belongs in this model.'); } };
  const make = (prefix, binding) => createControlledLocalAccess({ mode: 'fixture-only',
    dbPath: paths[prefix + '-access'], conversationId: binding.conversationId,
    identityMode: INTEGRATED_IDENTITY_MODE,
    // No authentication occurs; this exists only to obtain the actual schema.
    identityFoundation: { isVerifiedPrincipal: () => false, participantXid: () => ({ ok: false }) },
    provider, now, adminSecret: randomBytes(32).toString('base64url'),
    activation: { mode: 'SYNTHETIC_ONLY', binding, publicKey: signer.publicKey,
      keyId: signer.keyId, ledgerPath: paths[prefix + '-activation'], now } });
  let sourceApp; let restoredApp;
  try {
    sourceApp = make('source', syntheticBinding());
    const sourceBinding = sourceApp.activationBinding();
    const oldActivation = signer.signClaims(syntheticClaims(sourceBinding, Math.floor(stamp / 1_000)));
    sourceApp.activate(oldActivation);
    await sourceApp.close(); sourceApp = undefined;
    const wordpress = { events: [] }; const operations = [];
    const db = new DatabaseSync(paths['source-access']);
    try {
      for (let index = 0; index < 2; index++) {
        const account = 'acct_' + randomBytes(32).toString('base64url');
        const subject = 'synthetic_i' + sha(account).slice(0, 39);
        const xid = 'fncp_' + randomBytes(32).toString('base64url');
        db.prepare('INSERT INTO fixtures VALUES(?,?)').run(subject, sha('invented-credential-' + index));
        db.prepare('INSERT INTO identity_mappings VALUES(?,?,?,?)').run(account, subject, sourceBinding.conversationId, xid);
        db.prepare('INSERT INTO approvals VALUES(?,?,?,?)').run(subject, sourceBinding.conversationId, xid, 'revoked');
        db.prepare('INSERT INTO invitations VALUES(?,?,?,?,1)').run(sha('invented-invitation-' + index), subject, sourceBinding.conversationId, stamp + 60_000);
        for (const [version, state] of [[1, 'approved'], [2, 'revoked']]) {
          const event = { schema_version: 1, event_id: randomUUID(), subject, round_id: 'synthetic_round_local', version,
            state, occurred_at: new Date(stamp).toISOString().replace(/\.\d{3}Z$/u, 'Z') };
          wordpress.events.push({ event, acknowledged: true });
          const digest = sha(JSON.stringify(['schema_version', 'event_id', 'subject', 'round_id', 'version', 'state', 'occurred_at'].map((name) => event[name])));
          db.prepare('INSERT INTO wordpress_events VALUES(?,?,?,?,?,1)').run(event.event_id, subject, version, state, digest);
        }
        operations.push({ xid, operationVersion: 2, present: false });
      }
    } finally { db.close(); }
    const read = (prefix, kind) => {
      const db = new DatabaseSync(paths[prefix + '-' + kind], { readOnly: true });
      try { return readStrictStore(db, kind); } finally { db.close(); }
    };
    const source = { binding: sourceBinding, access: read('source', 'access'), activation: read('source', 'activation'), wordpress,
      provider: { conversationId: sourceBinding.conversationId, whitelistRows: 0, operations },
      volatile: { oidcPending: 0, principalCapabilities: 0, browserSessions: 0 } };
    copyFileSync(paths['source-access'], paths['restored-access']);
    copyFileSync(paths['source-activation'], paths['restored-activation']);
    const { bootId, ...nextBinding } = sourceBinding; nextBinding.recoveryEpoch = randomUUID();
    restoredApp = make('restored', nextBinding);
    const targetBinding = restoredApp.activationBinding();
    // Actual current authority implementation must reject the prior-boot signed
    // activation, independently of this recovery manifest's model assertions.
    assert.throws(() => restoredApp.activate(oldActivation), /Synthetic activation denied/u);
    await restoredApp.close(); restoredApp = undefined;
    const restored = { ...clone(source), binding: targetBinding,
      access: read('restored', 'access'), activation: read('restored', 'activation') };
    const fingerprints = Object.fromEntries(['identityMapping', 'activationVerification', 'wordpressEvent', 'providerGateway', 'providerAllowlist']
      .map((name) => [name, sha('invented-key-fingerprint-' + name)]));
    fingerprints.activationVerification = publicKeyFingerprint(signer.publicKey);
    const keyState = { mappingAlgorithm: MAPPING_ALGORITHM, mappingKeyVersion: 1,
      issuerConfigurationSha256: sha('invented-exact-issuer-config'), fingerprints };
    const base = { mode: MODE, recoveryId: randomUUID(), keyId: 'synthetic_recovery_test_signer',
      signerFingerprint: publicKeyFingerprint(manifestSigner.publicKey), issuedAt: Math.floor(stamp / 1_000),
      expiresAt: Math.floor(stamp / 1_000) + 300, source, targetBinding,
      keyContinuity: { source: keyState, restored: clone(keyState) } };
    const seal = (claims, domain = SIGNING_DOMAIN, privateKey = manifestSigner.privateKey, serializer = canonical) => {
      const payload = Buffer.from(serializer(claims));
      return { payload: payload.toString('base64url'), signature: sign(null, Buffer.concat([domain, payload]), privateKey).toString('base64url') };
    };
    const claims = prepareStrictRecoveryManifest(base);
    return { base, source, restored, targetBinding, paths, signer, manifestSigner, claims, seal, providerCalls: () => providerCalls,
      input: () => ({ mode: MODE, envelope: seal(claims), publicKey: manifestSigner.publicKey,
        expectedRecoveryId: base.recoveryId, expectedKeyId: base.keyId, source: clone(source), restored: clone(restored),
        targetBinding: clone(targetBinding), keyContinuity: clone(base.keyContinuity), now }),
      close: () => rmSync(directory, { recursive: true }) };
  } catch (error) {
    for (const app of [sourceApp, restoredApp]) if (app) await app.close();
    rmSync(directory, { recursive: true }); throw error;
  }
}

test('actual strict SQLite schemas and signed closed-recovery plan validate without provider or listener work', async () => {
  const f = await fixture();
  try {
    const result = validateStrictRecovery(f.input());
    assert.equal(result.ok, true); assert.equal(result.action, 'KEEP_CLOSED');
    assert.equal(result.counts.mappings, 2); assert.equal(result.counts.providerTombstones, 2);
    assert.equal(result.counts.retainedActivationIds, 1); assert.equal(result.counts.sequenceFloor, 1);
    assert.equal(result.priorBootInvalidated, true); assert.equal(result.actualMultiStoreRestorePerformed, false);
    assert.equal(result.newSignedActivationRequired, true); assert.equal(result.newOidcLoginRequired, true);
    assert.equal(result.oldInvitationsReusable, false); assert.equal(f.providerCalls(), 0);
    assert.equal(f.claims.purpose, PURPOSE); assert.deepEqual(f.claims.schemas, SCHEMA_SHA256);
    assert.equal(f.claims.keyPolicy.mappingKeyVersion, 1); assert.equal(f.claims.keyPolicy.mappingAlgorithm, MAPPING_ALGORITHM);
    assert.equal(Object.values(f.claims.keyPolicy.fingerprints).every((value) => /^[a-f0-9]{64}$/u.test(value)), true);
  } finally { f.close(); }
});

const invalidSources = {
  'legacy schema omits identity mappings': (s) => { delete s.access.tables.identity_mappings; },
  'unknown schema object': (s) => { s.access.tables.extra = []; },
  'schema fingerprint drift': (s) => { s.access.schemaSha256 = 'f'.repeat(64); },
  'open round': (s) => { s.access.tables.round[0].open = 1; },
  'live authentication session': (s) => { s.access.tables.sessions.push({ kind: 'fixture' }); },
  'live participation session': (s) => { s.access.tables.sessions.push({ kind: 'participation' }); },
  'unconsumed invitation even if expired': (s) => { s.access.tables.invitations[0].used = 0; s.access.tables.invitations[0].expires = 0; },
  'pending OIDC transaction': (s) => { s.volatile.oidcPending = 1; },
  'retained in-memory principal': (s) => { s.volatile.principalCapabilities = 1; },
  'retained browser session': (s) => { s.volatile.browserSessions = 1; },
  'email identity substitution': (s) => { s.access.tables.identity_mappings[0].account_id = 'invented@example.invalid'; },
  'email-derived fixture alias': (s) => { s.access.tables.identity_mappings[0].fixture = 'synthetic_email_match'; },
  'duplicate account mapping': (s) => { s.access.tables.identity_mappings[1].account_id = s.access.tables.identity_mappings[0].account_id; },
  'cross-round mapping': (s) => { s.access.tables.identity_mappings[0].round = '9otherSynthetic'; },
  'mapping approval XID mismatch': (s) => { s.access.tables.approvals[0].xid = 'fncp_' + 'z'.repeat(43); },
  'approval remains allowed': (s) => { s.access.tables.approvals[0].state = 'approved'; },
  'WordPress acknowledgement absent': (s) => { s.wordpress.events[0].acknowledged = false; },
  'WordPress pending access event': (s) => { s.access.tables.wordpress_events[0].applied = 0; },
  'WordPress digest mismatch': (s) => { s.access.tables.wordpress_events[0].digest = 'a'.repeat(64); },
  'WordPress missing event': (s) => { s.wordpress.events.pop(); },
  'WordPress event wrong round': (s) => { s.wordpress.events[0].event.round_id = 'synthetic_other'; },
  'WordPress duplicate identity': (s) => { s.wordpress.events[1].event.event_id = s.wordpress.events[0].event.event_id; },
  'provider still allowlisted': (s) => { s.provider.whitelistRows = 1; },
  'provider pending operation': (s) => { s.provider.operations[0].operationVersion = 1; },
  'provider presence conflicts with tombstone': (s) => { s.provider.operations[0].present = true; },
  'provider missing terminal record': (s) => { s.provider.operations.pop(); },
  'provider unrelated terminal record': (s) => { s.provider.operations.push({ xid: 'fncp_' + 'q'.repeat(43), operationVersion: 2, present: false }); },
  'provider wrong conversation': (s) => { s.provider.conversationId = '9otherSynthetic'; },
  'source signed authority active': (s) => { s.activation.tables.activation_state[0].active = 1; },
  'activation row wrong boot': (s) => { s.activation.tables.activation_state[0].boot_id = 'a'.repeat(64); },
  'activation replay floor invalid': (s) => { s.activation.tables.activation_state[0].sequence = -1; },
  'activation state foreign identity': (s) => { s.activation.tables.activation_state[0].identity = 'b'.repeat(64); },
};
test('unsigned preparation rejects semantic source hazards before any signing can occur', async (t) => {
  const f = await fixture();
  try {
    for (const [name, mutate] of Object.entries(invalidSources)) await t.test(name, () => {
      const input = clone(f.base); mutate(input.source);
      assert.throws(() => prepareStrictRecoveryManifest(input), /^Error: Strict synthetic recovery denied\.$/u);
    });
  } finally { f.close(); }
});

test('key version, key role, issuer configuration and target binding drift fail closed', async (t) => {
  const f = await fixture();
  try {
    const cases = {
      'mapping key version': (o) => { o.keyContinuity.restored.mappingKeyVersion++; },
      'mapping algorithm': (o) => { o.keyContinuity.restored.mappingAlgorithm = 'email-hash'; },
      'same-role key fingerprint': (o) => { o.keyContinuity.restored.fingerprints.identityMapping = 'f'.repeat(64); },
      'cross-role key reuse': (o) => { o.keyContinuity.source.fingerprints.providerGateway = o.keyContinuity.source.fingerprints.wordpressEvent; },
      'unknown key material field': (o) => { o.keyContinuity.source.privateKey = 'INVENTED-SECRET-SENTINEL'; },
      'changed issuer config': (o) => { o.keyContinuity.restored.issuerConfigurationSha256 = 'd'.repeat(64); },
      'same prior boot': (o) => { o.targetBinding.bootId = o.source.binding.bootId; },
      'same recovery epoch': (o) => { o.targetBinding.recoveryEpoch = o.source.binding.recoveryEpoch; },
      'changed deployment': (o) => { o.targetBinding.deploymentId = 'synthetic_other'; },
      'changed conversation': (o) => { o.targetBinding.conversationId = '9otherSynthetic'; },
      'changed image': (o) => { o.targetBinding.images.server = 'sha256:' + 'e'.repeat(64); },
      'changed config': (o) => { o.targetBinding.configSha256 = 'd'.repeat(64); },
      'changed seeds': (o) => { o.targetBinding.seedSha256 = 'd'.repeat(64); },
      'larger scope': (o) => { o.targetBinding.scope.maxParticipants = 21; },
      'free text enabled': (o) => { o.targetBinding.scope.suggestions = true; },
    };
    for (const [name, mutate] of Object.entries(cases)) await t.test(name, () => {
      const input = clone(f.base); mutate(input); assert.throws(() => prepareStrictRecoveryManifest(input));
    });
  } finally { f.close(); }
});

test('cryptographic manifest verification rejects tampering, role confusion, expiry and ambiguous data', async (t) => {
  const f = await fixture();
  try {
    const cases = {
      'wrong mode': (o) => { o.mode = 'production'; },
      'wrong expected recovery identity': (o) => { o.expectedRecoveryId = randomUUID(); },
      'wrong expected signer name': (o) => { o.expectedKeyId = 'synthetic_other'; },
      'wrong public signer': (o) => { o.publicKey = f.signer.publicKey; },
      'private KeyObject supplied': (o) => { o.publicKey = f.manifestSigner.privateKey; },
      'private PEM supplied': (o) => { o.publicKey = f.manifestSigner.privateKey.export({ type: 'pkcs8', format: 'pem' }); },
      'wrong signing domain': (o) => { o.envelope = f.seal(f.claims, Buffer.from('ACTIVATION-NOT-RECOVERY')); },
      'payload bit change': (o) => { o.envelope.payload = Buffer.from(canonical({ ...f.claims, instruction: 'OPEN' })).toString('base64url'); },
      'expired manifest': (o) => { o.now = () => f.claims.expiresAt * 1_000; },
      'not-yet-issued manifest': (o) => { o.now = () => (f.claims.issuedAt - 1) * 1_000; },
      'unknown signed claim': (o) => { o.envelope = f.seal({ ...f.claims, allowOpen: true }); },
      'extra envelope field': (o) => { o.envelope.access_token = 'INVENTED-TOKEN-SENTINEL'; },
      'noncanonical signed JSON': (o) => { o.envelope = f.seal(f.claims, SIGNING_DOMAIN, f.manifestSigner.privateKey, (v) => JSON.stringify(v, null, 2)); },
      'padded base64url': (o) => { o.envelope.payload += '='; },
      'oversized payload': (o) => { o.envelope.payload = 'a'.repeat(16_001); },
      'unavailable clock': (o) => { o.now = () => { throw new Error('INVENTED-PRIVATE-DIAGNOSTIC'); }; },
      'fractional clock': (o) => { o.now = () => 1.5; },
    };
    for (const [name, mutate] of Object.entries(cases)) await t.test(name, () => {
      const input = f.input(); mutate(input); assert.deepEqual(validateStrictRecovery(input), denied);
    });
  } finally { f.close(); }
});

test('restored prior authority or altered metadata never becomes a closed recovery result', async (t) => {
  const f = await fixture();
  try {
    const cases = {
      'prior boot retained': (o) => { o.restored = clone(o.source); },
      'activation still active': (o) => { o.restored.activation.tables.activation_state[0].active = 1; },
      'old activation pointer retained': (o) => { o.restored.activation.tables.activation_state[0].activation_id = o.source.activation.tables.activation_state[0].activation_id; },
      'sequence floor rolled back': (o) => { o.restored.activation.tables.activation_state[0].sequence = 0; },
      'retained replay IDs dropped': (o) => { o.restored.activation.tables.activation_ids = []; },
      'unexpected replay ID inserted': (o) => { o.restored.activation.tables.activation_ids.push({ id: randomUUID() }); },
      'opaque mapping altered': (o) => { o.restored.access.tables.identity_mappings[0].xid = 'fncp_' + 'r'.repeat(43); },
      'used invitation resurrected': (o) => { o.restored.access.tables.invitations[0].used = 0; },
      'volatile identity revived': (o) => { o.restored.volatile.principalCapabilities = 1; },
    };
    for (const [name, mutate] of Object.entries(cases)) await t.test(name, () => {
      const input = f.input(); mutate(input); assert.deepEqual(validateStrictRecovery(input), denied);
    });
  } finally { f.close(); }
});

test('schema reader refuses added triggers, missing mappings and fake database handles', async () => {
  const f = await fixture();
  try {
    assert.throws(() => readStrictStore({ prepare() { throw new Error('INVENTED-SECRET'); } }, 'access'));
    const db = new DatabaseSync(f.paths['restored-access']);
    try {
      db.exec('CREATE TRIGGER synthetic_extra AFTER UPDATE ON round BEGIN SELECT 1; END;');
      assert.throws(() => readStrictStore(db, 'access'));
      db.exec('DROP TRIGGER synthetic_extra; CREATE TABLE sqlitex_hidden (id TEXT);');
      assert.throws(() => readStrictStore(db, 'access'));
      db.exec('DROP TABLE sqlitex_hidden; DROP TABLE identity_mappings;');
      assert.throws(() => readStrictStore(db, 'access'));
    } finally { db.close(); }
  } finally { f.close(); }
});

test('manifest and result contain hashes/aggregates, not private mappings, events, keys or capabilities', async () => {
  const f = await fixture();
  try {
    const result = validateStrictRecovery(f.input()); assert.equal(result.ok, true);
    const output = JSON.stringify({ claims: f.claims, result });
    for (const mapping of f.source.access.tables.identity_mappings) {
      for (const value of Object.values(mapping)) assert.ok(!output.includes(value));
    }
    for (const event of f.source.wordpress.events) assert.ok(!output.includes(event.event.event_id));
    assert.ok(!output.includes(f.source.binding.bootId)); assert.ok(!output.includes(f.source.binding.conversationId));
    assert.doesNotMatch(output, /BEGIN (?:PRIVATE|PUBLIC) KEY|access_token|id_token|credential_hash|fixtureAuthToken/u);
    assert.equal(Object.isFrozen(result), true); assert.equal(Object.isFrozen(result.counts), true);
    assert.deepEqual(validateStrictRecovery({ ...f.input(), source: { sentinel: 'INVENTED-SECRET-SENTINEL' } }), denied);
    let getterCalls = 0;
    const malicious = { ...f.input() }; Object.defineProperty(malicious, 'source', { enumerable: true, get() { getterCalls++; throw new Error('INVENTED-SECRET'); } });
    assert.deepEqual(validateStrictRecovery(malicious), denied); assert.equal(getterCalls, 0);
    assert.throws(() => canonical({ get secret() { getterCalls++; return 'INVENTED-SECRET'; } }));
    assert.equal(getterCalls, 0); assert.throws(() => canonical(new Array(1)));
  } finally { f.close(); }
});
