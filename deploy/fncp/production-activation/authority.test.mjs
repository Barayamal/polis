import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { mkdtempSync, realpathSync, chmodSync, rmSync, symlinkSync, linkSync, readFileSync, existsSync, writeFileSync, statSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { createProductionActivation, isProductionActivation } from './authority.mjs';
import { signProductionActivation } from './offline-sign.mjs';
import { IMAGE_ROLES } from './protocol.mjs';
const denied = { message: 'Production activation denied.' };
function childAuthority(h, action = 'dispose') {
  const script = `import {readFileSync} from 'node:fs'; import {createProductionActivation} from ${JSON.stringify(new URL('./authority.mjs', import.meta.url).href)};
    const x=JSON.parse(readFileSync(0,'utf8')); try { const a=createProductionActivation({...x.options,now:()=>x.time});
      if(x.action==='abandon') { process.stdout.write('ABANDONED'); process.exit(0); }
      a.dispose(); process.stdout.write('CREATED_AND_DISPOSED');
    } catch(e) { if(e.message!=='Production activation denied.') process.exit(2); process.stdout.write('DENIED'); }`;
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    input: JSON.stringify({ options: { ...h.options, now: undefined, publicKey: h.keys.publicKey.export({ type: 'spki', format: 'pem' }) }, time: h.time(), action }),
    encoding: 'utf8', timeout: 5000, maxBuffer: 8192, env: { PATH: process.env.PATH, NODE_NO_WARNINGS: '1' },
  });
  assert.equal(result.error, undefined); assert.equal(result.status, 0); assert.equal(result.stderr, ''); return result.stdout;
}
function fixture(t) {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'fncp-production-activation-test-'))); chmodSync(directory, 0o700);
  const keys = generateKeyPairSync('ed25519'); let now = 2000000000000;
  const binding = { deploymentId: 'fncp-reviewed-deployment', conversationId: '9fixedConversation', sourceRevision: '1'.repeat(40),
    configSha256: '2'.repeat(64), seedSha256: '3'.repeat(64), providerSha256: '4'.repeat(64), recoveryEpoch: randomUUID(),
    images: Object.fromEntries(IMAGE_ROLES.map(k => [k, 'sha256:' + '5'.repeat(64)])), scope: { maxParticipants: 20, statementCount: 15, suggestions: false } };
  const options = { binding, publicKey: keys.publicKey, keyId: 'reviewed-signing-key-v1', ledgerPath: join(directory, 'activation.sqlite'), now: () => now };
  const instances = [];
  const create = (overrides = {}) => { const a = createProductionActivation({ ...options, ...overrides }); instances.push(a); return a; };
  t.after(() => { for (const a of instances) try { a.dispose(); } catch {} rmSync(directory, { recursive: true, force: true }); });
  return { keys, directory, binding, options, create, time: () => now, setTime: value => { now = value; },
    envelope(a, overrides = {}) { const seconds = Math.floor(now / 1000); return signProductionActivation({ challenge: a.challenge(), privateKey: keys.privateKey,
      activationId: randomUUID(), issuedAt: seconds, notBefore: seconds, expiresAt: seconds + 600, ...overrides }); } };
}

test('branded authority starts closed, accepts offline reviewed challenge, closes and requires new signature', t => {
  const h = fixture(t), a = h.create(); assert.equal(isProductionActivation(a), true); assert.ok(Object.isFrozen(a));
  assert.equal(isProductionActivation({ ...a }), false); assert.throws(() => a.assertActive(), denied);
  const envelope = h.envelope(a), accepted = a.accept(envelope); assert.equal(a.assertActive(), accepted.generation);
  assert.equal(a.challenge().nextSequence, 2); a.close(); assert.throws(() => a.assertActive(), denied);
  assert.throws(() => a.accept(envelope), denied); assert.equal(a.accept(h.envelope(a)).active, true);
  a.dispose(); assert.throws(() => a.challenge(), denied); assert.throws(() => a.accept(envelope), denied);
});

test('restart retains replay floor and accepted IDs, starts closed with fresh boot and allows reviewed changed config/epoch', t => {
  const h = fixture(t), a = h.create(), old = h.envelope(a); a.accept(old); const first = a.challenge(); a.dispose();
  const b = h.create({ binding: { ...h.binding, configSha256: '6'.repeat(64), recoveryEpoch: randomUUID() } });
  assert.equal(b.challenge().nextSequence, 2); assert.notEqual(b.challenge().binding.bootId, first.binding.bootId);
  assert.throws(() => b.assertActive(), denied); assert.throws(() => b.accept(old), denied);
  const oldId = JSON.parse(Buffer.from(old.payload, 'base64url')).activationId;
  assert.throws(() => b.accept(h.envelope(b, { activationId: oldId })), denied);
  assert.equal(b.accept(h.envelope(b)).active, true);
});

test('invalid replacement signature revokes current authority without consuming sequence', t => {
  const h = fixture(t), a = h.create(); a.accept(h.envelope(a)); const sequence = a.challenge().nextSequence;
  const e = h.envelope(a); assert.throws(() => a.accept({ ...e, signature: 'A'.repeat(86) }), denied);
  assert.throws(() => a.assertActive(), denied); assert.equal(a.challenge().nextSequence, sequence);
  assert.equal(a.accept(h.envelope(a)).active, true);
});

for (const behavior of ['rollback', 'invalid', 'throws']) test(`${behavior} clock permanently closes, including attempted reactivation`, t => {
  const h = fixture(t); let broken = false;
  const a = h.create({ now: () => { if (broken && behavior === 'throws') throw Error('clock private detail');
    return broken ? behavior === 'rollback' ? h.time() - 1 : NaN : h.time(); } });
  const e = h.envelope(a); a.accept(e); broken = true;
  assert.throws(() => a.accept(e), denied); broken = false;
  assert.throws(() => a.assertActive(), denied); assert.throws(() => a.challenge(), denied); assert.throws(() => a.accept(e), denied);
});

test('expiry closes authority and requires a fresh reviewed envelope', t => {
  const h = fixture(t), a = h.create(); a.accept(h.envelope(a)); h.setTime(h.time() + 600000);
  assert.throws(() => a.assertActive(), denied); assert.equal(a.accept(h.envelope(a)).active, true);
});

test('storage permission drift permanently closes even after permissions are corrected', t => {
  const h = fixture(t), a = h.create(); a.accept(h.envelope(a)); chmodSync(h.options.ledgerPath, 0o644);
  assert.throws(() => a.assertActive(), denied); chmodSync(h.options.ledgerPath, 0o600); assert.throws(() => a.challenge(), denied);
});

test('unexpected persisted generation corruption permanently closes', t => {
  const h = fixture(t), a = h.create(); a.accept(h.envelope(a));
  const db = new DatabaseSync(h.options.ledgerPath); db.exec("UPDATE activation_state SET digest='corrupted'"); db.close();
  assert.throws(() => a.assertActive(), denied); assert.throws(() => a.challenge(), denied);
});

test('identity/key mismatch, extra schema and inconsistent replay state are refused on restart', t => {
  const h = fixture(t), a = h.create(); a.accept(h.envelope(a)); a.dispose();
  assert.throws(() => h.create({ binding: { ...h.binding, conversationId: '9differentConversation' } }), denied);
  assert.throws(() => h.create({ publicKey: generateKeyPairSync('ed25519').publicKey }), denied);
  const db = new DatabaseSync(h.options.ledgerPath); db.exec('CREATE TABLE unrelated(x TEXT)'); db.close();
  assert.throws(() => h.create(), denied);
});

test('ledger custody rejects symlinks, hardlinks, permissive directory and duplicate in-process writers', t => {
  const h = fixture(t), a = h.create(); assert.throws(() => h.create(), denied); a.dispose();
  const linked = join(h.directory, 'linked.sqlite'); linkSync(h.options.ledgerPath, linked);
  assert.throws(() => h.create(), denied); rmSync(linked);
  symlinkSync(h.options.ledgerPath, linked); assert.throws(() => h.create({ ledgerPath: linked }), denied); rmSync(linked);
  chmodSync(h.directory, 0o755); assert.throws(() => h.create(), denied); chmodSync(h.directory, 0o700);
});

test('exact configuration, public-only key and immutable binding reject synthetic/unsafe substitutions', t => {
  const h = fixture(t);
  for (const o of [{ publicKey: h.keys.privateKey }, { publicKey: h.keys.privateKey.export({ format: 'pem', type: 'pkcs8' }) },
    { binding: { ...h.binding, scope: { ...h.binding.scope, maxParticipants: 21 } } },
    { binding: { ...h.binding, images: { ...h.binding.images, alpha: 'sha256:' + '6'.repeat(64) } } }, { arbitrary: true }]) assert.throws(() => h.create(o), denied);
  const a = h.create(); const before = a.challenge(); h.binding.providerSha256 = '8'.repeat(64); before.binding.images.api = 'changed';
  assert.equal(a.challenge().binding.providerSha256, '4'.repeat(64)); assert.notEqual(a.challenge().binding.images.api, 'changed');
});

test('runtime import graph has no signer/private-key helper', () => {
  const authority = readFileSync(new URL('./authority.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(authority, /from ['"].*offline-sign/); assert.doesNotMatch(authority, /createPrivateKey|\bsign\(/);
});


test('signed future or wrong-binding envelopes fail closed without consuming replay floor', t => {
  const h = fixture(t), a = h.create();
  const future = Math.floor(h.time() / 1000) + 10;
  assert.throws(() => a.accept(h.envelope(a, { issuedAt: future, notBefore: future, expiresAt: future + 100 })), denied);
  const challenge = a.challenge(); challenge.binding.providerSha256 = '8'.repeat(64);
  assert.throws(() => a.accept(h.envelope(a, { challenge })), denied);
  assert.equal(a.challenge().nextSequence, 1); assert.equal(a.accept(h.envelope(a)).active, true);
});

test('deleted state with retained replay IDs cannot silently reset the floor', t => {
  const h = fixture(t), a = h.create(); a.accept(h.envelope(a)); a.dispose();
  const db = new DatabaseSync(h.options.ledgerPath); db.exec('DELETE FROM activation_state'); db.close();
  assert.throws(() => h.create(), denied);
});

test('separate-process duplicate startup cannot change the active owner boot, floor or ledger bytes', t => {
  const h = fixture(t), a = h.create(); const accepted = a.accept(h.envelope(a));
  const before = a.challenge(), ledger = readFileSync(h.options.ledgerPath), lockPath = h.options.ledgerPath + '.lock';
  const lock = readFileSync(lockPath); assert.equal(statSync(lockPath).mode & 0o7777, 0o600);
  assert.equal(childAuthority(h), 'DENIED');
  assert.deepEqual(a.challenge(), before); assert.equal(a.assertActive(), accepted.generation);
  assert.deepEqual(readFileSync(h.options.ledgerPath), ledger); assert.deepEqual(readFileSync(lockPath), lock);
  a.dispose(); assert.equal(existsSync(lockPath), false);
  assert.equal(childAuthority(h), 'CREATED_AND_DISPOSED'); assert.equal(existsSync(lockPath), false);
  const restarted = h.create(); assert.equal(restarted.challenge().nextSequence, before.nextSequence);
  assert.notEqual(restarted.challenge().binding.bootId, before.binding.bootId); assert.throws(() => restarted.assertActive(), denied);
});

test('constructor rejection releases only its own lock without changing foreign schema', t => {
  const h = fixture(t), a = h.create(); a.dispose();
  const db = new DatabaseSync(h.options.ledgerPath); db.exec('CREATE TABLE foreign_state (value TEXT)'); db.close();
  const before = readFileSync(h.options.ledgerPath); assert.equal(childAuthority(h), 'DENIED');
  assert.equal(existsSync(h.options.ledgerPath + '.lock'), false); assert.deepEqual(readFileSync(h.options.ledgerPath), before);
  const repair = new DatabaseSync(h.options.ledgerPath); repair.exec('DROP TABLE foreign_state'); repair.close();
  assert.equal(childAuthority(h), 'CREATED_AND_DISPOSED');
});

test('an abandoned process lock is never adopted or removed by restart', t => {
  const h = fixture(t); assert.equal(childAuthority(h, 'abandon'), 'ABANDONED');
  const lockPath = h.options.ledgerPath + '.lock', lock = readFileSync(lockPath), ledger = readFileSync(h.options.ledgerPath);
  assert.equal(childAuthority(h), 'DENIED'); assert.throws(() => h.create(), denied);
  assert.deepEqual(readFileSync(lockPath), lock); assert.deepEqual(readFileSync(h.options.ledgerPath), ledger);
});

test('a pre-existing lock refuses even initial ledger creation and remains untouched', t => {
  const h = fixture(t), lockPath = h.options.ledgerPath + '.lock';
  const body = 'pre-existing private sentinel'; writeFileSync(lockPath, body, { mode: 0o600 });
  assert.equal(childAuthority(h), 'DENIED'); assert.equal(existsSync(h.options.ledgerPath), false);
  assert.equal(readFileSync(lockPath, 'utf8'), body);
});

test('lost or substituted lock permanently closes and disposal preserves the replacement', t => {
  const h = fixture(t), a = h.create(); a.accept(h.envelope(a)); const lockPath = h.options.ledgerPath + '.lock';
  rmSync(lockPath); const replacement = 'replacement-owned-elsewhere'; writeFileSync(lockPath, replacement, { mode: 0o600 });
  assert.throws(() => a.assertActive(), denied); assert.throws(() => a.challenge(), denied); assert.throws(() => a.dispose(), denied);
  assert.equal(readFileSync(lockPath, 'utf8'), replacement); assert.equal(childAuthority(h), 'DENIED');
});

test('explicit ninth image role selects V2 domain and binds edge digest against replay and downgrade',t=>{
  const h=fixture(t),old=h.create(),oldEnvelope=h.envelope(old);old.accept(oldEnvelope);old.dispose();
  h.binding.images.edge='sha256:'+'9'.repeat(64);const a=h.create();assert.equal(a.profile,'FNCP_PRODUCTION_ACTIVATION_V2');assert.equal(a.challenge().purpose,'FNCP_PRODUCTION_ACTIVATION_V2');
  assert.equal(a.challenge().nextSequence,2);assert.throws(()=>a.accept(oldEnvelope),denied);const envelope=h.envelope(a);const claims=JSON.parse(Buffer.from(envelope.payload,'base64url'));assert.equal(claims.schemaVersion,2);assert.equal(claims.binding.images.edge,h.binding.images.edge);assert.equal(a.accept(envelope).active,true);
  const wrong=structuredClone(a.challenge());wrong.purpose='FNCP_PRODUCTION_ACTIVATION_V1';assert.throws(()=>h.envelope(a,{challenge:wrong}),denied);
  a.dispose();h.binding.images.edge='sha256:'+'8'.repeat(64);const changed=h.create();assert.equal(changed.challenge().nextSequence,3);assert.throws(()=>changed.accept(envelope),denied);assert.equal(changed.accept(h.envelope(changed)).active,true);
});

test('reviewed operator-access hash selects V3 domain and cannot be removed, changed or replayed as V2',t=>{
  const h=fixture(t);h.binding.images.edge='sha256:'+'9'.repeat(64);const v2=h.create();const v2Envelope=h.envelope(v2);v2.accept(v2Envelope);v2.dispose();
  h.binding.images.operator='sha256:'+'a'.repeat(64);h.binding.operatorAccessSha256='b'.repeat(64);const v3=h.create();assert.equal(v3.profile,'FNCP_PRODUCTION_ACTIVATION_V3');const challenge=v3.challenge();
  assert.equal(challenge.purpose,'FNCP_PRODUCTION_ACTIVATION_V3');assert.equal(challenge.binding.operatorAccessSha256,'b'.repeat(64));assert.equal(challenge.binding.images.operator,h.binding.images.operator);assert.throws(()=>v3.accept(v2Envelope),denied);
  const v3Envelope=h.envelope(v3),claims=JSON.parse(Buffer.from(v3Envelope.payload,'base64url'));assert.equal(claims.schemaVersion,3);assert.equal(v3.accept(v3Envelope).active,true);v3.dispose();
  delete h.binding.operatorAccessSha256;assert.throws(()=>h.create(),denied);delete h.binding.images.operator;const downgraded=h.create();assert.throws(()=>downgraded.accept(v3Envelope),denied);downgraded.dispose();
  h.binding.images.operator='sha256:'+'c'.repeat(64);h.binding.operatorAccessSha256='d'.repeat(64);delete h.binding.images.edge;assert.throws(()=>h.create(),denied);
});
