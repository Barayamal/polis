import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, writeFileSync, readdirSync, copyFileSync, unlinkSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { canonical, sha } from './contracts.mjs';
import { createProductionService } from './service.mjs';
import { recoverClosedProductionAccess } from './recovery.mjs';
import { serviceFixture } from './test-support/service-fixture.mjs';
import { freshCertificate } from '../production-identity/test-support/https-issuer.mjs';

// Every file and service in these tests is freshly created by the synthetic
// local HTTPS fixture. No retained deployment or database is opened.
async function captured(x, manifest, label) {
  const directory = join(dirname(x.stateDirectory), label); mkdirSync(directory, { mode: 0o700 });
  const material = join(directory, 'material'), state = join(directory, 'state');
  mkdirSync(material, { mode: 0o700 }); mkdirSync(state, { mode: 0o700 });
  for (const name of readdirSync(x.materialDirectory)) if (name !== 'service.json') copyFileSync(join(x.materialDirectory, name), join(material, name));
  const relocate = v => typeof v === 'string' ? v.replace(x.materialDirectory + '/', material + '/')
    : Array.isArray(v) ? v.map(relocate) : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, s]) => [k, relocate(s)])) : v;
  const config = relocate(manifest); config.stateDirectory = state;
  const configurationPath = join(material, 'service.json'); writeFileSync(configurationPath, JSON.stringify(config), { mode: 0o600 });
  const service = await createProductionService({ configurationPath });
  try { return { descriptor: service.operator.recoveryDescriptor(), state, configurationPath }; }
  finally { await service.close(); }
}
const rejects = fn => assert.throws(fn, { message: 'Offline production access recovery denied.' });

test('actual service descriptors allow only private path/epoch relocation and normal startup accepts the resealed copy closed', async t => {
  const x = await serviceFixture(t), source = await x.create();
  // Establish a retained activation replay floor, then explicitly close.
  source.operator.activate(x.envelope(source)); source.operator.closeAdmission();
  const floor = source.operator.challenge().nextSequence, original = source.operator.recoveryDescriptor(); await source.close();
  const manifest = structuredClone(x.manifest); manifest.activation.recoveryEpoch = randomUUID();
  const target = await captured(x, manifest, 'relocated');
  assert.equal(target.descriptor.binding.configuration.credentialBindingSha256, original.binding.configuration.credentialBindingSha256);
  assert.equal(target.descriptor.binding.configuration.identityBindingSha256, original.binding.configuration.identityBindingSha256);
  assert.notEqual(target.descriptor.binding.activation.configSha256, original.binding.activation.configSha256);
  const comparable = structuredClone(target.descriptor.binding);
  comparable.activation.configSha256 = original.binding.activation.configSha256; comparable.activation.recoveryEpoch = original.binding.activation.recoveryEpoch;
  assert.equal(canonical(comparable), canonical(original.binding));
  // The descriptor-only target was created by this invocation with zero
  // registrations and no activation. Remove only these test-owned empty DBs.
  for (const name of ['access.sqlite', 'activation.sqlite']) unlinkSync(join(target.state, name));
  const sourcePath = join(x.stateDirectory, 'access.sqlite'), sourceHash = sha(readFileSync(sourcePath));
  const result = recoverClosedProductionAccess({ sourcePath, targetPath: join(target.state, 'access.sqlite'), sourceDescriptor: original, targetDescriptor: target.descriptor });
  assert.equal(result.sourceUnchanged, true); assert.equal(sha(readFileSync(sourcePath)), sourceHash);
  assert.deepEqual(readdirSync(target.state), ['access.sqlite']);
  // Joined activation copying is an explicit TEST action outside the helper.
  const sourceActivation = readFileSync(join(x.stateDirectory, 'activation.sqlite'));
  copyFileSync(join(x.stateDirectory, 'activation.sqlite'), join(target.state, 'activation.sqlite'));
  const restarted = await createProductionService({ configurationPath: target.configurationPath });
  try {
    assert.equal(restarted.operator.status().roundOpen, false); assert.equal(restarted.operator.status().registrations, 0);
    assert.equal(restarted.operator.challenge().nextSequence, floor); assert.throws(() => restarted.operator.admit());
  } finally { await restarted.close(); }
  assert.deepEqual(readFileSync(join(x.stateDirectory, 'activation.sqlite')), sourceActivation);
  assert.equal(sha(readFileSync(sourcePath)), sourceHash);
});

test('actual service binds secret, authority, listener and TLS changes so resealing refuses every rotation', async t => {
  const x = await serviceFixture(t), source = await x.create(), original = source.operator.recoveryDescriptor(); await source.close();
  let index = 0;
  const variants = [
    ...Object.keys(x.manifest.secrets).map(role => [role, manifest => { writeFileSync(manifest.secrets[role], randomBytes(32).toString('base64url')); }]),
    ['activation-key-id', manifest => { manifest.activation.keyId = 'replacement-key-id'; }],
    ['activation-public-key', manifest => { writeFileSync(manifest.activation.publicKeyFile, generateKeyPairSync('ed25519').publicKey.export({ format: 'pem', type: 'spki' })); }],
    ['receiver-listener-host', manifest => { manifest.receiver.host = '0.0.0.0'; }],
    ['participant-tls', manifest => { const cert = freshCertificate(); writeFileSync(manifest.tls.participantKeyFile, cert.key); writeFileSync(manifest.tls.participantCertFile, cert.cert); }],
    ['receiver-tls', manifest => { const cert = freshCertificate(); writeFileSync(manifest.tls.receiverKeyFile, cert.key); writeFileSync(manifest.tls.receiverCertFile, cert.cert); }],
  ];
  const originals = new Map(readdirSync(x.materialDirectory).map(name => [join(x.materialDirectory, name), readFileSync(join(x.materialDirectory, name))]));
  const sourcePath = join(x.stateDirectory, 'access.sqlite'), bytes = readFileSync(sourcePath);
  for (const [label, mutate] of variants) {
    const manifest = structuredClone(x.manifest); manifest.activation.recoveryEpoch = randomUUID();
    mutate(manifest);
    const target = await captured(x, manifest, 'variant-' + index++);
    assert.notEqual(target.descriptor.binding.configuration.credentialBindingSha256, original.binding.configuration.credentialBindingSha256, label);
    const path = join(target.state, 'new-access.sqlite');
    rejects(() => recoverClosedProductionAccess({ sourcePath, targetPath: path, sourceDescriptor: original, targetDescriptor: target.descriptor }));
    for (const [file, contents] of originals) writeFileSync(file, contents);
  }
  assert.deepEqual(readFileSync(sourcePath), bytes);
});

test('normal startup rejects an invented target config hash even if an offline operator resealed to it', async t => {
  const x = await serviceFixture(t), source = await x.create(), original = source.operator.recoveryDescriptor(); await source.close();
  const manifest = structuredClone(x.manifest); manifest.activation.recoveryEpoch = randomUUID();
  const target = await captured(x, manifest, 'wrong-target-config');
  for (const name of ['access.sqlite', 'activation.sqlite']) unlinkSync(join(target.state, name));
  const descriptor = structuredClone(target.descriptor); descriptor.binding.activation.configSha256 = sha('invented unrelated configuration');
  descriptor.bindingSha256 = sha(canonical(descriptor.binding));
  recoverClosedProductionAccess({ sourcePath: join(x.stateDirectory, 'access.sqlite'), targetPath: join(target.state, 'access.sqlite'), sourceDescriptor: original, targetDescriptor: descriptor });
  copyFileSync(join(x.stateDirectory, 'activation.sqlite'), join(target.state, 'activation.sqlite'));
  await assert.rejects(() => createProductionService({ configurationPath: target.configurationPath }), { message: 'Production service unavailable.' });
  const db = new DatabaseSync(join(target.state, 'access.sqlite'), { readOnly: true });
  try { assert.equal(db.prepare('SELECT binding_sha FROM meta').get().binding_sha, descriptor.bindingSha256); }
  finally { db.close(); }
});
