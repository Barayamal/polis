import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, chmodSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { DatabaseSync } from 'node:sqlite';
import { createActivationAuthority, canonical } from './authority.mjs';
import { syntheticSigningFixture, syntheticBinding, syntheticClaims } from './synthetic-fixtures.mjs';

function harness(t, persistent = false) {
  const directory = mkdtempSync(join(tmpdir(), 'fncp-activation-test-'));
  const signer = syntheticSigningFixture(); let ms = 1_000_000;
  const config = { mode: 'SYNTHETIC_ONLY', binding: syntheticBinding(), publicKey: signer.publicKey,
    keyId: signer.keyId, ledgerPath: persistent ? join(directory, 'authority.sqlite') : ':memory:', now: () => ms };
  const authority = createActivationAuthority(config);
  t.after(() => { authority.dispose(); rmSync(directory, { recursive: true }); });
  const claims = (changes = {}) => syntheticClaims(authority.binding(), Math.floor(ms / 1000),
    { sequence: authority.nextSequence(), ...changes });
  return { config, directory, signer, authority, claims, setTime: (next) => { ms = next; },
    activate: (changes) => authority.activate(signer.signClaims(claims(changes))) };
}

test('authority starts closed; valid signed lease is distinct from server configuration', (t) => {
  const h = harness(t); assert.throws(h.authority.assertActive, /denied/);
  assert.deepEqual(h.activate(), { active: true, mode: 'SYNTHETIC_ONLY', expiresAt: 1300 });
  assert.equal(typeof h.authority.assertActive(), 'string');
  h.authority.close(); assert.throws(h.authority.assertActive, /denied/);
});
test('canonicalization rejects ambiguous types and sorts recursively', () => {
  assert.equal(canonical({ z: [2, true], a: { b: null } }), '{"a":{"b":null},"z":[2,true]}');
  for (const value of [undefined, NaN, 1.5, new Date(), 1n]) assert.throws(() => canonical(value));
});
test('wrong mode, extra binding fields, private signing keys and invalid key types denied', (t) => {
  const h = harness(t);
  const privatePem = h.signer.privateKey.export({ type: 'pkcs8', format: 'pem' });
  for (const update of [{ mode: 'production' }, { binding: { ...h.config.binding, extra: true } },
    { publicKey: h.signer.privateKey }, { publicKey: privatePem }, { keyId: 'real_key' }]) {
    assert.throws(() => createActivationAuthority({ ...h.config, ...update }), /denied/);
  }
});
test('tampering, wrong signing key, malformed base64 and extra envelope fields denied', (t) => {
  const h = harness(t); const token = h.signer.signClaims(h.claims());
  for (const envelope of [{ ...token, payload: token.payload.slice(0, -1) + '!' },
    { ...token, signature: 'a'.repeat(86) }, { ...token, extra: true },
    { ...token, payload: token.payload + '=' }, syntheticSigningFixture().signClaims(h.claims())]) {
    assert.throws(() => h.authority.activate(envelope), /denied/);
  }
  assert.throws(h.authority.assertActive, /denied/);
});
test('signed noncanonical and duplicate-key JSON cannot activate', (t) => {
  const h = harness(t); const claims = h.claims();
  for (const serialize of [JSON.stringify, (value) => canonical(value).replace('"sequence":1', '"sequence":1,"sequence":1')]) {
    assert.throws(() => h.authority.activate(h.signer.signClaims(claims, serialize)), /denied/);
  }
});
for (const field of ['deploymentId', 'conversationId', 'recoveryEpoch', 'configSha256', 'seedSha256', 'bootId', 'images', 'scope']) {
  test(`signed ${field} mismatch cannot activate`, (t) => {
    const h = harness(t); const binding = h.authority.binding();
    const other = { ...syntheticBinding(), bootId: 'd'.repeat(64), deploymentId: 'synthetic_other',
      conversationId: '9syntheticOther', configSha256: 'e'.repeat(64), seedSha256: 'f'.repeat(64),
      images: { ...binding.images, server: 'sha256:' + 'd'.repeat(64) }, scope: { ...binding.scope, maxParticipants: 21 } };
    binding[field] = other[field];
    assert.throws(() => h.activate({ binding }), /denied/);
  });
}
test('claims schema, key ID, purpose, sequence and time bounds are strict', (t) => {
  const h = harness(t);
  for (const changes of [{ schemaVersion: 2 }, { purpose: 'live' }, { keyId: 'synthetic_other_key' },
    { sequence: 0 }, { sequence: 1.5 }, { issuedAt: 1001 }, { notBefore: 1001 },
    { expiresAt: 1000 }, { expiresAt: 2801 }, { notBefore: 999 }, { extra: true }]) {
    assert.throws(() => h.activate(changes), /denied/);
  }
});
test('exact expiry denies and clock recovery does not revive a closed lease', (t) => {
  const h = harness(t); h.activate({ expiresAt: 1002 });
  h.setTime(1001999); h.authority.assertActive();
  h.setTime(1002000); assert.throws(h.authority.assertActive, /denied/);
  h.setTime(1001000); assert.throws(h.authority.assertActive, /denied/);
});
test('clock rollback latches old activation closed even when the clock catches up', (t) => {
  const h = harness(t); h.activate(); h.setTime(999999);
  assert.throws(h.authority.assertActive, /denied/);
  h.setTime(1000000); assert.throws(h.authority.assertActive, /denied/);
  h.activate(); h.authority.assertActive();
});
test('close requires fresh sequence and activation ID; old signed authority never replays', (t) => {
  const h = harness(t); const first = h.claims(); const token = h.signer.signClaims(first);
  h.authority.activate(token); h.authority.close();
  assert.throws(() => h.authority.activate(token), /denied/);
  assert.throws(() => h.activate({ activationId: first.activationId }), /denied/);
  h.activate(); h.authority.assertActive();
});
test('binding inputs and returned objects are isolated snapshots, including getters', (t) => {
  const h = harness(t); const original = h.authority.binding();
  h.config.binding.scope.maxParticipants = 500;
  h.authority.binding().images.server = 'sha256:' + 'd'.repeat(64);
  assert.deepEqual(h.authority.binding(), original);
  let reads = 0; const input = syntheticBinding();
  Object.defineProperty(input, 'conversationId', { enumerable: true, get() { return ++reads === 1 ? '9syntheticRoundTest' : '9syntheticOther'; } });
  const other = createActivationAuthority({ ...h.config, binding: input });
  assert.equal(reads, 1); assert.equal(other.binding().conversationId, '9syntheticRoundTest'); other.dispose();
});
test('persistent restart uses a new boot ID, closed state and preserved sequence floor', (t) => {
  const h = harness(t, true); const token = h.signer.signClaims(h.claims());
  h.authority.activate(token); const firstBoot = h.authority.binding().bootId; h.authority.dispose();
  const restarted = createActivationAuthority(h.config);
  assert.notEqual(restarted.binding().bootId, firstBoot); assert.equal(restarted.nextSequence(), 2);
  assert.throws(restarted.assertActive, /denied/); assert.throws(() => restarted.activate(token), /denied/);
  restarted.dispose();
});
test('a second boot invalidates the older process, and disposal cannot close the new boot', (t) => {
  const h = harness(t, true); h.activate(); const second = createActivationAuthority(h.config);
  second.activate(h.signer.signClaims(syntheticClaims(second.binding(), 1000, { sequence: second.nextSequence() })));
  assert.throws(h.authority.assertActive, /denied/); h.authority.dispose();
  second.assertActive(); second.dispose();
});
test('live ledger rollback is detected by the in-memory sequence floor', (t) => {
  const h = harness(t, true); h.activate(); const external = new DatabaseSync(h.config.ledgerPath);
  external.exec('UPDATE activation_state SET sequence=0'); external.close();
  assert.throws(h.authority.assertActive, /denied/);
});
test('transient ledger read failure never resumes the old activation after recovery', (t) => {
  const h = harness(t, true); h.activate(); const external = new DatabaseSync(h.config.ledgerPath);
  external.exec('ALTER TABLE activation_state RENAME TO held_state');
  assert.throws(h.authority.assertActive, /denied/);
  external.exec('ALTER TABLE held_state RENAME TO activation_state'); external.close();
  assert.throws(h.authority.assertActive, /denied/);
});
test('foreign database and insecure or symlinked ledger paths are refused without changing foreign tables', (t) => {
  const h = harness(t); const path = join(h.directory, 'foreign.sqlite'); const external = new DatabaseSync(path);
  external.exec('CREATE TABLE unrelated (n INTEGER); INSERT INTO unrelated VALUES(7)'); chmodSync(path, 0o600);
  assert.throws(() => createActivationAuthority({ ...h.config, ledgerPath: path }), /denied/);
  assert.deepEqual(external.prepare('SELECT n FROM unrelated').all().map((x) => x.n), [7]);
  assert.equal(external.prepare("SELECT count(*) AS n FROM sqlite_master WHERE type='table'").get().n, 1); external.close();
  chmodSync(path, 0o644); assert.throws(() => createActivationAuthority({ ...h.config, ledgerPath: path }), /denied/);
  const linked = join(h.directory, 'linked.sqlite'); symlinkSync(path, linked);
  assert.throws(() => createActivationAuthority({ ...h.config, ledgerPath: linked }), /denied/);
});
