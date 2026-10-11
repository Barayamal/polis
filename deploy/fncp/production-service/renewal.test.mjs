import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { join, basename } from 'node:path';
import { randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { canonical, sha } from './contracts.mjs';
import { serviceFixture } from './test-support/service-fixture.mjs';
import { freshCertificate } from '../production-identity/test-support/https-issuer.mjs';
import { createProductionService } from './service.mjs';
import { renewClosedProductionCredentials } from './renewal.mjs';
import { holdRenewalMaterial } from './renewal-material.mjs';
import { freshLeaf } from '../production-edge/tls-fixture.mjs';
import { runRenewalCli } from './renewal-cli.mjs';

const denied = fn => assert.throws(fn, e => e.message === 'Offline production credential renewal denied.' && Object.keys(e).length === 0);
const rows = path => {
  const db = new DatabaseSync(path, { readOnly: true });
  try { return Object.fromEntries(['meta', 'accounts', 'events', 'invitations'].map(name => [name, db.prepare(`SELECT * FROM ${name} ORDER BY 1`).all()])); }
  finally { db.close(); }
};
const sql = (path, fn) => { const db = new DatabaseSync(path); try { return fn(db); } finally { db.close(); } };
async function fixture(t, { close = true } = {}) {
  const f = await serviceFixture(t);
  // Retain the normal service implementation unchanged; use proper CA-signed
  // CA:false leaves instead of the older self-signed CA-shaped test fixture.
  for (const role of ['participant', 'receiver']) {
    const leaf = freshLeaf();
    fs.writeFileSync(f.manifest.tls[role + 'CertFile'], leaf.tls.cert);
    fs.writeFileSync(f.manifest.tls[role + 'KeyFile'], leaf.tls.key);
  }
  const source = await f.create(), oldEnvelope = f.envelope(source);
  source.operator.activate(oldEnvelope);
  const sourceDescriptor = source.operator.recoveryDescriptor();
  if (close) await source.close();
  const targetMaterial = join(f.materialDirectory, '..', 'renewed-material'), targetState = join(f.materialDirectory, '..', 'renewed-state');
  fs.mkdirSync(targetMaterial, { mode: 0o700 }); fs.mkdirSync(targetState, { mode: 0o700 });
  const manifest = structuredClone(f.manifest);
  manifest.stateDirectory = fs.realpathSync(targetState); manifest.activation.recoveryEpoch = randomUUID();
  for (const group of ['identity', 'activation', 'secrets', 'tls', 'trust']) for (const [key, path] of Object.entries(manifest[group])) {
    if (!key.endsWith('File')) continue;
    const target = join(fs.realpathSync(targetMaterial), basename(path)); fs.copyFileSync(path, target); fs.chmodSync(target, 0o600); manifest[group][key] = target;
  }
  fs.writeFileSync(manifest.identity.clientSecretFile, 'RENEWED_SYNTHETIC_CLIENT_SECRET', { mode: 0o600 });
  const { tls } = freshLeaf();
  fs.writeFileSync(manifest.tls.participantCertFile, tls.cert); fs.writeFileSync(manifest.tls.participantKeyFile, tls.key);
  const targetConfigurationPath = join(fs.realpathSync(targetMaterial), 'service.json');
  const save = () => fs.writeFileSync(targetConfigurationPath, JSON.stringify(manifest, null, 2) + '\n', { mode: 0o600 }); save();
  const sourcePath = join(f.stateDirectory, 'access.sqlite'), targetPath = join(manifest.stateDirectory, 'access.sqlite');
  const run = () => renewClosedProductionCredentials({ sourceConfigurationPath: f.configurationPath, targetConfigurationPath });
  return { ...f, source, sourceDescriptor, oldEnvelope, targetConfigurationPath, manifest, save, sourcePath, targetPath, run };
}
function seedHistory(f, count = 20) {
  const at = Math.floor((Date.now() - 120000) / 1000), c = f.sourceDescriptor.binding.configuration;
  sql(f.sourcePath, db => {
    for (let n = 0; n < count; n++) {
      const accountId = 'acct_' + Buffer.from(sha('renewal-synthetic-account-' + n), 'hex').toString('base64url');
      const xid = 'fncp_' + Buffer.from(sha('renewal-synthetic-xid-' + n), 'hex').toString('base64url');
      const registrationId = randomUUID(), receiptId = randomUUID();
      const receipt = { receiptId, accountId, consentVersion: c.consentVersion, adultSelfAttested: true,
        eligibilitySelfAttested: true, registrationConsent: true, issuedAt: at, expiresAt: at + 60 };
      db.prepare('INSERT INTO accounts(account_id,xid,registration_id,receipt_id,receipt_json) VALUES(?,?,?,?,?)').run(accountId, xid, registrationId, receiptId, canonical(receipt));
      if (n % 3 === 0) {
        const eventId = randomUUID();
        const event = { schemaVersion: 1, eventId, deploymentId: c.deploymentId, conversationId: c.conversationId,
          registrationId, accountId, version: 2, state: 'revoked', occurredAt: at };
        const body = canonical(event), applied = n % 2;
        db.prepare('INSERT INTO events VALUES(?,?,?,?,?,?,?)').run(eventId, accountId, 2, 'revoked', sha(body), body, applied);
        db.prepare("UPDATE accounts SET state='revoked',provider_state=?,event_version=2,event_id=? WHERE account_id=?").run(applied ? 'removed' : 'pending_remove', eventId, accountId);
      }
      db.prepare('INSERT INTO invitations VALUES(?,?,?,1)').run(sha('renewal-consumed-token-' + n), accountId, (at + 60) * 1000);
    }
  });
}
function noTarget(f) { assert.deepEqual(fs.readdirSync(f.manifest.stateDirectory), []); }

test('material proof reproduces the real service descriptor and retains secret-free evidence', async t => {
  const f = await fixture(t), proof = holdRenewalMaterial(f.configurationPath, f.targetConfigurationPath);
  try {
    assert.equal(canonical(proof.sourceDescriptor), canonical(f.sourceDescriptor));
    assert.deepEqual(proof.changes, ['oidcClientSecret', 'participantTls']); assert.equal(proof.verify(), true);
  } finally { proof.close(); }
});

test('renewal copies both closed ledgers, preserves all lifetime slots and denials, and requires fresh activation', async t => {
  const f = await fixture(t); seedHistory(f);
  const before = rows(f.sourcePath), sourceBytes = fs.readFileSync(f.sourcePath);
  const oldActivation = fs.readFileSync(join(f.stateDirectory, 'activation.sqlite'));
  const result = f.run();
  assert.equal(result.accounts, 20); assert.equal(result.revokedAccounts, 7); assert.equal(result.pendingRemovals, 4);
  assert.equal(result.activationReplayFloor, 1); assert.equal(result.freshActivationRequired, true);
  assert.equal(result.joinedDeploymentRenewed, false); assert.equal(result.admissionGranted, false);
  assert.deepEqual(fs.readFileSync(f.sourcePath), sourceBytes);
  assert.deepEqual(fs.readFileSync(join(f.stateDirectory, 'activation.sqlite')), oldActivation);
  assert.deepEqual(fs.readFileSync(join(f.manifest.stateDirectory, 'activation.sqlite')), oldActivation);
  const expected = structuredClone(before); expected.meta[0].binding_sha = result.targetBindingSha256;
  assert.equal(canonical(rows(f.targetPath)), canonical(expected));
  assert.doesNotMatch(JSON.stringify(result), /acct_|fncp_|PRIVATE|SECRET|registration_id|receipt|token_hash|@|\/tmp\//u);
  const renewed = await createProductionService({ configurationPath: f.targetConfigurationPath });
  assert.equal(renewed.operator.challenge().nextSequence, 2);
  assert.throws(() => renewed.operator.activate(f.oldEnvelope));
  assert.equal(renewed.operator.status().roundOpen, false);
  assert.equal(renewed.operator.challenge().nextSequence, 2);
  renewed.operator.activate(f.envelope(renewed));
  assert.equal(renewed.operator.challenge().nextSequence, 3);
  assert.equal(renewed.operator.status().roundOpen, false);
  assert.equal(rows(f.targetPath).accounts.length, 20);
  assert.equal(rows(f.targetPath).accounts.filter(r => r.state === 'revoked').length, 7);
  await renewed.close();
});

for (const [name, mutate] of [
  ['identity issuer', f => { f.manifest.identity.issuer = 'https://different.example.test'; }],
  ['identity client', f => { f.manifest.identity.clientId += '-other'; }],
  ['identity pseudonym key', f => fs.writeFileSync(f.manifest.identity.identityKeyFile, Buffer.alloc(32, 66).toString('base64url'))],
  ['provider credential', f => fs.writeFileSync(f.manifest.secrets.providerKeyFile, Buffer.alloc(32, 77).toString('base64url'))],
  ['WordPress origin', f => { f.manifest.wordpress.origin = 'https://different.example.test'; }],
  ['participant origin', f => { f.manifest.participant.origin = 'https://different.example.test'; }],
  ['reviewed notice', f => { f.manifest.content.notice.adultDeclaration += ' altered'; }],
  ['source revision', f => { f.manifest.activation.sourceRevision = '3'.repeat(40); }],
  ['image lock', f => { f.manifest.activation.images.api = 'sha256:' + '3'.repeat(64); }],
  ['recovery epoch reuse', f => { f.manifest.activation.recoveryEpoch = f.sourceDescriptor.binding.activation.recoveryEpoch; }],
  ['TLS wrong hostname', f => { const tls = freshCertificate(true); fs.writeFileSync(f.manifest.tls.participantKeyFile, tls.key); fs.writeFileSync(f.manifest.tls.participantCertFile, tls.cert); }],
  ['TLS wrong key', f => fs.writeFileSync(f.manifest.tls.participantKeyFile, freshCertificate().key)],
  ['CA certificate used as target leaf', f => { const tls = freshCertificate(); fs.writeFileSync(f.manifest.tls.participantKeyFile, tls.key); fs.writeFileSync(f.manifest.tls.participantCertFile, tls.cert); }],
  ['clientAuth-only target leaf', f => { const { tls } = freshLeaf({ purpose: 'clientAuth' }); fs.writeFileSync(f.manifest.tls.participantKeyFile, tls.key); fs.writeFileSync(f.manifest.tls.participantCertFile, tls.cert); }],
  ['noncanonical state directory', f => { f.manifest.stateDirectory += '/.'; }],
]) test(`refuses ${name} without creating a target or altering source`, async t => {
  const f = await fixture(t), before = fs.readFileSync(f.sourcePath); mutate(f); f.save(); denied(f.run);
  noTarget(f); assert.deepEqual(fs.readFileSync(f.sourcePath), before);
});

test('a live source service is refused without removing its lock', async t => {
  const f = await fixture(t, { close: false }), lock = fs.readFileSync(join(f.stateDirectory, 'service.lock'));
  denied(f.run); assert.deepEqual(fs.readFileSync(join(f.stateDirectory, 'service.lock')), lock); noTarget(f);
});

for (const suffix of ['service.lock', 'access.sqlite.writer.lock', 'activation.sqlite.lock', 'activation.sqlite-wal', 'access.sqlite-journal']) {
  test(`refuses source ${suffix} and preserves unknown state`, async t => {
    const f = await fixture(t), path = join(f.stateDirectory, suffix); fs.writeFileSync(path, 'foreign sentinel', { mode: 0o600 });
    denied(f.run); assert.equal(fs.readFileSync(path, 'utf8'), 'foreign sentinel'); noTarget(f);
  });
}

for (const [name, mutate] of [
  ['active activation ledger', f => sql(join(f.stateDirectory, 'activation.sqlite'), db => db.exec('UPDATE activation_state SET active=1'))],
  ['activation replay floor corruption', f => sql(join(f.stateDirectory, 'activation.sqlite'), db => db.exec('DELETE FROM activation_ids'))],
  ['activation binding mismatch', f => sql(join(f.stateDirectory, 'activation.sqlite'), db => db.prepare('UPDATE activation_state SET binding_hash=?').run('0'.repeat(64)))],
  ['access binding mismatch', f => sql(f.sourcePath, db => db.prepare('UPDATE meta SET binding_sha=?').run('0'.repeat(64)))],
  ['unused invitation even after expiry', f => { seedHistory(f, 1); sql(f.sourcePath, db => db.exec('UPDATE invitations SET used=0')); }],
  ['non-private target directory', f => fs.chmodSync(f.manifest.stateDirectory, 0o750)],
]) test(`refuses ${name}`, async t => {
  const f = await fixture(t); mutate(f); denied(f.run); assert.equal(fs.existsSync(f.targetPath), false);
});

test('refuses an occupied target namespace rather than replacing or resetting anything', async t => {
  const f = await fixture(t), path = join(f.manifest.stateDirectory, 'activation.sqlite'); fs.writeFileSync(path, 'foreign target', { mode: 0o600 });
  denied(f.run); assert.equal(fs.readFileSync(path, 'utf8'), 'foreign target'); assert.equal(fs.existsSync(f.targetPath), false);
});

test('refuses expired or not-yet-valid target TLS material', async t => {
  const f = await fixture(t), original = Date.now;
  t.mock.method(Date, 'now', () => original() + 2 * 86400000); denied(f.run); noTarget(f);
  t.mock.restoreAll();
  t.mock.method(Date, 'now', () => original() - 2 * 86400000); denied(f.run); noTarget(f);
  t.mock.restoreAll();
});

test('material drift during the offline copy fails closed and removes only invocation-created targets', async t => {
  const f = await fixture(t), write = fs.writeSync; let injected = false;
  t.mock.method(fs, 'writeSync', (fd, ...args) => {
    const result = write(fd, ...args);
    if (!injected) { injected = true; fs.writeFileSync(f.manifest.identity.clientSecretFile, 'MATERIAL_DRIFT_SYNTHETIC_SECRET'); }
    return result;
  });
  denied(f.run); assert.equal(injected, true); noTarget(f);
});

test('partial target write failure preserves source ledgers and cleans owned targets', async t => {
  const f = await fixture(t), source = fs.readFileSync(f.sourcePath), activation = fs.readFileSync(join(f.stateDirectory, 'activation.sqlite'));
  const original = fs.writeSync; let injected = false;
  t.mock.method(fs, 'writeSync', (fd, b, offset, length, position) => {
    if (!injected) { injected = true; original(fd, b, offset, Math.min(length, 64), position); throw Error('PRIVATE_FAILURE'); }
    return original(fd, b, offset, length, position);
  });
  denied(f.run); noTarget(f); assert.deepEqual(fs.readFileSync(f.sourcePath), source);
  assert.deepEqual(fs.readFileSync(join(f.stateDirectory, 'activation.sqlite')), activation);
});

test('CLI accepts only the exact two manifest path options', async t => {
  denied(() => runRenewalCli([])); denied(() => runRenewalCli(['--client-secret', 'PRIVATE_SYNTHETIC_VALUE']));
  const f = await fixture(t);
  const result = runRenewalCli(['--source-manifest', f.configurationPath, '--target-manifest', f.targetConfigurationPath]);
  assert.equal(result.profile, 'FNCP_CLOSED_CREDENTIAL_RENEWAL_V1'); assert.equal(result.admissionGranted, false);
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE|SECRET|\/tmp\//u);
});
