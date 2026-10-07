import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync,
  readdirSync, realpathSync, rmSync, symlinkSync, linkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { canonical, sha } from '../production-service/contracts.mjs';
import { prepareLocalMaterial } from '../selfhost/prepare-local-material.mjs';
import { PROFILE, stageProductionMaterial } from './stage-material.mjs';

let root, template;
const json = value => canonical(value) + '\n';
const write = (path, value) => writeFileSync(path, value, { mode: 0o600 });
const key = () => randomBytes(32).toString('base64url');
const openssl = args => execFileSync('openssl', args, { stdio: ['ignore','ignore','ignore'], timeout: 15000 });
const roles = ['api','math','postgres','migration','participant','wordpress','mariadb','proxy'];

before(async () => {
  root = realpathSync(mkdtempSync('/tmp/fncp-stage-test-')); chmodSync(root, 0o700);
  template = join(root, 'template'); mkdirSync(template, { mode: 0o700 });
  const generated = join(root, 'generated'); mkdirSync(generated, { mode: 0o700 });
  const configuration = { version: 1, profile: 'FNCP_PRODUCTION_COMPOSE_V1', platform: 'linux/arm64',
    deployment: 'fncp-fresh-synthetic', sourceRevision: 'a'.repeat(40), stateDirectory: join(root, 'unused', 'core'),
    database: { name: 'fncp_polis', owner: 'fncp_owner', migrationRole: 'fncp_migration', runtimeRole: 'fncp_runtime', mathRole: 'fncp_math', host: 'postgres', port: 5432 },
    binding: { conversationId: '9FreshSynthetic', statementIds: Array.from({ length: 15 }, (_, i) => i) },
    identity: { issuer: 'https://identity.example.invalid/', audience: 'synthetic-client', jwksUri: 'https://identity.example.invalid/jwks' } };
  const imageLock = { version: 1, sourceRevision: configuration.sourceRevision, sourceFingerprint: 'b'.repeat(64),
    images: Object.fromEntries(roles.map((r, i) => [r, 'sha256:' + String(i + 1).repeat(64)])) };
  const { profile, ...c } = configuration;
  const coreConfig = { ...c, stateDirectory: generated, classification: 'closed-local-core', engine: { host: 'unix:///unused.sock', configDirectory: root } };
  const configPath = join(root, 'synthetic-core.json'); write(configPath, json(coreConfig));
  await prepareLocalMaterial(configPath);
  for (const name of ['core','core/material','participant_material','wordpress_material','proxy_material']) mkdirSync(join(template, name), { mode: 0o700 });
  for (const name of ['api.env','database-ca.pem','database-math-password','database-migration-password','database-owner-password','database-runtime-password',
    'database-server.key','database-server.pem','jwt-private.pem','jwt-public.pem','math.env','migration.env']) {
    const from = join(generated, 'material', name), to = join(template, 'core/material', name);
    const mode = name.endsWith('.env') ? 0o600 : 0o644;
    writeFileSync(to, readFileSync(from), { mode }); chmodSync(to, mode);
  }
  const api = Object.fromEntries(readFileSync(join(template, 'core/material/api.env'), 'utf8').trim().split('\n').map(l => { const i = l.indexOf('='); return [l.slice(0, i), l.slice(i + 1)]; }));
  const materials = { 'oidc-secret.txt': key(), 'identity-key.txt': key(), 'gateway-key.txt': api.FNCP_GATEWAY_SHARED_SECRET,
    'provider-key.txt': api.FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL, 'wordpress-request-key.txt': key(), 'wordpress-response-key.txt': key(), 'wordpress-event-key.txt': key(),
    'activation-public.pem': generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }) };
  for (const [n, value] of Object.entries(materials)) write(join(template, 'participant_material', n), value);
  const certdir = join(root, 'certificates'); mkdirSync(certdir, { mode: 0o700 });
  const caKey = join(certdir, 'ca.key'), caPem = join(certdir, 'ca.pem');
  openssl(['req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=Invented staging test root','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout',caKey,'-out',caPem]);
  for (const [name, host, certTarget, keyTarget] of [
    ['participant','participant.example.invalid','participant_material/participant-cert.pem','participant_material/participant-key.pem'],
    ['receiver','participant-events','participant_material/receiver-cert.pem','participant_material/receiver-key.pem'],
    ['wordpress','wordpress','wordpress_material/server.pem','wordpress_material/server-key.pem'],
    ['proxy','polis-proxy','proxy_material/proxy-cert.pem','proxy_material/proxy-key.pem'],
  ]) {
    const certKey = join(certdir, name + '.key'), csr = join(certdir, name + '.csr'), pem = join(certdir, name + '.pem'), ext = join(certdir, name + '.ext');
    write(ext, 'subjectAltName=DNS:' + host + '\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n');
    openssl(['req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=' + host,'-keyout',certKey,'-out',csr]);
    openssl(['x509','-req','-in',csr,'-CA',caPem,'-CAkey',caKey,'-CAcreateserial','-days','2','-extfile',ext,'-out',pem]);
    write(join(template, certTarget), readFileSync(pem)); write(join(template, keyTarget), readFileSync(certKey));
  }
  for (const path of ['participant_material/wordpress-ca.pem','participant_material/provider-ca.pem','wordpress_material/receiver-ca.pem']) write(join(template, path), readFileSync(caPem));
  const p = { profile: 'FNCP_PRODUCTION_SERVICE_V1', deploymentId: configuration.deployment, conversationId: configuration.binding.conversationId,
    stateDirectory: '/var/lib/fncp', participant: { origin: 'https://participant.example.invalid', host: '0.0.0.0', port: 8443 },
    receiver: { origin: 'https://participant-events:8444', host: '0.0.0.0', port: 8444 },
    identity: { issuer: configuration.identity.issuer, authorizationEndpoint: 'https://identity.example.invalid/authorize', tokenEndpoint: 'https://identity.example.invalid/token',
      jwksUri: configuration.identity.jwksUri, callbackUri: 'https://participant.example.invalid/oidc/callback', clientId: configuration.identity.audience,
      tokenEndpointAuthMethod: 'client_secret_basic', signingAlgorithm: 'RS256', clientSecretFile: '/run/fncp/oidc-secret.txt', identityKeyFile: '/run/fncp/identity-key.txt' },
    provider: { origin: 'https://polis-proxy:8443' }, wordpress: { origin: 'https://wordpress:8443' },
    activation: { sourceRevision: configuration.sourceRevision, images: imageLock.images, recoveryEpoch: randomUUID(), keyId: 'synthetic-review-authority', publicKeyFile: '/run/fncp/activation-public.pem' },
    content: { consentVersion: 'synthetic-v1', notice: { adultDeclaration: 'Invented adult declaration.', eligibilityDeclaration: 'Invented eligibility declaration.', registrationDeclaration: 'Invented consent declaration.' },
      statementIds: configuration.binding.statementIds, statements: Array.from({ length: 15 }, (_, i) => 'Invented test statement ' + i) },
    secrets: { gatewayKeyFile: '/run/fncp/gateway-key.txt', providerKeyFile: '/run/fncp/provider-key.txt', wordpressRequestKeyFile: '/run/fncp/wordpress-request-key.txt', wordpressResponseKeyFile: '/run/fncp/wordpress-response-key.txt', wordpressEventKeyFile: '/run/fncp/wordpress-event-key.txt' },
    tls: { participantKeyFile: '/run/fncp/participant-key.pem', participantCertFile: '/run/fncp/participant-cert.pem', receiverKeyFile: '/run/fncp/receiver-key.pem', receiverCertFile: '/run/fncp/receiver-cert.pem' },
    trust: { providerCaFile: '/run/fncp/provider-ca.pem', wordpressCaFile: '/run/fncp/wordpress-ca.pem' } };
  write(join(template, 'participant_material/service.json'), json(p));
  write(join(template, 'wordpress_material/config.json'), json({ profile: 'FNCP_WORDPRESS_RUNTIME_V1', wordpressOrigin: p.wordpress.origin, databaseName: 'fncp_wordpress', databaseUser: 'fncp_wp', databasePassword: key(), tablePrefix: 'fncp_', salts: Array.from({ length: 8 }, key) }));
  write(join(template, 'wordpress_material/plugin-config.json'), json({ profile: 'FNCP_PRODUCTION_WORDPRESS_V1', deploymentId: p.deploymentId, conversationId: p.conversationId,
    wordpressOrigin: p.wordpress.origin, eventEndpoint: p.receiver.origin + '/internal/wordpress/events', consentVersion: p.content.consentVersion, noticeSha256: sha(canonical(p.content.notice)),
    serviceRequestKey: materials['wordpress-request-key.txt'], serviceResponseKey: materials['wordpress-response-key.txt'], eventKey: materials['wordpress-event-key.txt'], caFile: '/run/fncp/wordpress/receiver-ca.pem' }));
  write(join(template, 'installation.json'), json({ version: 1, profile: PROFILE, configuration, imageLock, ownerToken: randomBytes(24).toString('hex') }));
});
after(() => { if (root) rmSync(root, { recursive: true, force: true }); });

function fixture(t) {
  const parent = join(root, randomUUID()); mkdirSync(parent, { mode: 0o700 });
  t.after(() => rmSync(parent, { recursive: true, force: true }));
  const inputDirectory = join(parent, 'input'), targetDirectory = join(parent, 'staged');
  cpSync(template, inputDirectory, { recursive: true });
  // Establish declared fixture modes explicitly: creation/copy modes can be
  // masked by the caller's secure077 umask on this host.
  for (const name of readdirSync(inputDirectory, { recursive: true })) {
    const path = join(inputDirectory, name);
    if (lstatSync(path).isFile()) chmodSync(path, lstatSync(join(template, name)).mode & 0o777);
  }
  for (const path of ['','core','core/material','participant_material','wordpress_material','proxy_material']) chmodSync(join(inputDirectory, path), 0o700);
  const plan = JSON.parse(readFileSync(join(inputDirectory, 'installation.json'))); plan.configuration.stateDirectory = join(targetDirectory, 'core');
  write(join(inputDirectory, 'installation.json'), json(plan));
  return { inputDirectory, targetDirectory, parent, plan,
    edit(path, fn) { const full = join(inputDirectory, path), value = JSON.parse(readFileSync(full)); fn(value); write(full, json(value)); },
    run() { return stageProductionMaterial({ inputDirectory, targetDirectory }); } };
}
function inventory(path) { return Object.fromEntries(readdirSync(path, { recursive: true }).sort().filter(n => lstatSync(join(path, n)).isFile()).map(n => [n, { bytes: sha(readFileSync(join(path, n))), inode: lstatSync(join(path, n)).ino }])); }

test('stages exact normal-start material, no database, identity or activation side effects', async t => {
  const f = fixture(t), result = await f.run(); assert.equal(result.result, 'MATERIAL_STAGED'); assert.equal(result.filesVerified, 37);
  assert.equal(result.databaseInitialized, false); assert.equal(result.activationGranted, false);
  const receipt = JSON.parse(readFileSync(join(f.targetDirectory, 'stage.receipt.json')));
  assert.equal(receipt.linuxVolumeOwnershipEstablished, false); assert.equal(receipt.publishedPorts, 0);
  assert.equal(existsSync(join(f.targetDirectory, 'participant_state')), false);
  const compose = JSON.parse(readFileSync(join(f.targetDirectory, 'compose.json')));
  assert.equal(Object.values(compose.services).some(s => s.ports), false);
  assert.equal(lstatSync(join(f.targetDirectory, 'participant_material')).mode & 0o777, 0o700);
});
test('identical rerun verifies without changing inodes, bytes, keys or epoch', async t => {
  const f = fixture(t); await f.run(); const before = inventory(f.targetDirectory);
  assert.deepEqual(await f.run(), { result: 'ALREADY_STAGED_VERIFIED', filesVerified: 37, changed: false, databaseInitialized: false, activationGranted: false });
  assert.deepEqual(inventory(f.targetDirectory), before);
});
test('secure077 umask preserves exact reviewed modes only on newly created files', async t => {
  const previous = process.umask(0o077);
  try {
    const f = fixture(t); assert.equal((await f.run()).result, 'MATERIAL_STAGED');
    for (const name of ['database-owner-password','database-server.key','jwt-private.pem'])
      assert.equal(lstatSync(join(f.targetDirectory, 'core/material', name)).mode & 0o777, 0o644);
    for (const name of ['api.env','math.env','migration.env'])
      assert.equal(lstatSync(join(f.targetDirectory, 'core/material', name)).mode & 0o777, 0o600);
    for (const name of ['', 'core', 'core/material', 'participant_material', 'wordpress_material', 'proxy_material'])
      assert.equal(lstatSync(join(f.targetDirectory, name)).mode & 0o777, 0o700);
    assert.equal(lstatSync(join(f.targetDirectory, 'participant_material/oidc-secret.txt')).mode & 0o777, 0o600);
    const before = inventory(f.targetDirectory); assert.equal((await f.run()).changed, false); assert.deepEqual(inventory(f.targetDirectory), before);
  } finally { process.umask(previous); }
});
for (const [name, change] of [
  ['image binding', f => f.edit('participant_material/service.json', p => { p.activation.images.api = 'sha256:' + '9'.repeat(64); })],
  ['duplicate OIDC endpoints', f => f.edit('participant_material/service.json', p => { p.identity.tokenEndpoint = p.identity.authorizationEndpoint; })],
  ['provider credential mismatch', f => write(join(f.inputDirectory, 'participant_material/provider-key.txt'), key())],
  ['short OIDC client secret', f => write(join(f.inputDirectory, 'participant_material/oidc-secret.txt'), 'short')],
  ['whitespace OIDC client secret', f => write(join(f.inputDirectory, 'participant_material/oidc-secret.txt'), 'long enough secret but spaces')],
  ['WordPress event credential mismatch', f => f.edit('wordpress_material/plugin-config.json', p => { p.eventKey = key(); })],
  ['cross-role credential reuse', f => write(join(f.inputDirectory, 'participant_material/identity-key.txt'), readFileSync(join(f.inputDirectory, 'core/material/database-owner-password')))],
  ['unexpected participant key reference', f => f.edit('participant_material/service.json', p => { p.tls.participantKeyFile = '/outside/key'; })],
  ['unexpected extra private file', f => write(join(f.inputDirectory, 'participant_material/unexpected-secret'), key())],
  ['activation private key in place of public authority', f => write(join(f.inputDirectory, 'participant_material/activation-public.pem'), generateKeyPairSync('ed25519').privateKey.export({ format: 'pem', type: 'pkcs8' }))],
  ['TLS key/certificate mismatch', f => write(join(f.inputDirectory, 'participant_material/participant-key.pem'), readFileSync(join(f.inputDirectory, 'participant_material/receiver-key.pem')))],
  ['extra PEM content', f => write(join(f.inputDirectory, 'participant_material/provider-ca.pem'), Buffer.concat([readFileSync(join(f.inputDirectory, 'participant_material/provider-ca.pem')), Buffer.from('\nextra material\n')]))],
  ['wrong hostname', f => f.edit('participant_material/service.json', p => { p.participant.origin = 'https://other.example.invalid'; p.identity.callbackUri = p.participant.origin + '/oidc/callback'; })],
  ['wrong state target', f => f.edit('installation.json', p => { p.configuration.stateDirectory = join(f.parent, 'other'); })],
  ['noncanonical JSON', f => write(join(f.inputDirectory, 'installation.json'), JSON.stringify(f.plan, null, 2) + '\n')],
  ['unsafe input directory permissions', f => chmodSync(join(f.inputDirectory, 'participant_material'), 0o755)],
  ['unsafe file permissions', f => chmodSync(join(f.inputDirectory, 'participant_material/identity-key.txt'), 0o644)],
  ['symlink material', f => { const p = join(f.inputDirectory, 'participant_material/identity-key.txt'); rmSync(p); symlinkSync(join(template, 'participant_material/identity-key.txt'), p); }],
  ['hardlinked material', f => { const p = join(f.inputDirectory, 'participant_material/identity-key.txt'); rmSync(p); linkSync(join(template, 'participant_material/identity-key.txt'), p); }],
]) test('rejects ' + name + ' before target creation', async t => {
  const f = fixture(t); change(f); await assert.rejects(f.run(), /^Error: FNCP_FRESH_MATERIAL_REJECTED$/u); assert.equal(existsSync(f.targetDirectory), false);
});
test('rejects an empty unowned target without adopting it', async t => { const f = fixture(t); mkdirSync(f.targetDirectory, { mode: 0o700 }); await assert.rejects(f.run()); assert.deepEqual(readdirSync(f.targetDirectory), []); });
test('rejects stale lock without replacing it', async t => { const f = fixture(t), lock = f.targetDirectory + '.stage.lock'; write(lock, 'owned-by-another-attempt'); await assert.rejects(f.run()); assert.equal(readFileSync(lock, 'utf8'), 'owned-by-another-attempt'); assert.equal(existsSync(f.targetDirectory), false); });
test('rejects changed staged bytes without repairing or overwriting', async t => { const f = fixture(t); await f.run(); const p = join(f.targetDirectory, 'participant_material/oidc-secret.txt'); write(p, 'changed'); const before = inventory(f.targetDirectory); await assert.rejects(f.run()); assert.deepEqual(inventory(f.targetDirectory), before); });
test('rejects changed plan owner on rerun without adopting staged target', async t => { const f = fixture(t); await f.run(); f.edit('installation.json', p => { p.ownerToken = 'f'.repeat(48); }); const before = inventory(f.targetDirectory); await assert.rejects(f.run()); assert.deepEqual(inventory(f.targetDirectory), before); });
test('rejects partial interrupted target and keeps evidence untouched', async t => { const f = fixture(t); await f.run(); rmSync(join(f.targetDirectory, 'stage.receipt.json')); const before = inventory(f.targetDirectory); await assert.rejects(f.run()); assert.deepEqual(inventory(f.targetDirectory), before); });
test('rejects changed source secret on rerun without rotating target material', async t => { const f = fixture(t); await f.run(); write(join(f.inputDirectory, 'participant_material/oidc-secret.txt'), key()); const before = inventory(f.targetDirectory); await assert.rejects(f.run()); assert.deepEqual(inventory(f.targetDirectory), before); });
test('rejects extra staged file without removing it', async t => { const f = fixture(t); await f.run(); write(join(f.targetDirectory, 'participant_material/extra'), 'keep'); const before = inventory(f.targetDirectory); await assert.rejects(f.run()); assert.deepEqual(inventory(f.targetDirectory), before); });
test('rejects a symlink target without touching its destination', async t => { const f = fixture(t), actual = join(f.parent, 'unrelated'); mkdirSync(actual, { mode: 0o700 }); write(join(actual, 'keep'), 'unchanged'); symlinkSync(actual, f.targetDirectory); await assert.rejects(f.run()); assert.equal(readFileSync(join(actual, 'keep'), 'utf8'), 'unchanged'); assert.deepEqual(readdirSync(actual), ['keep']); });
test('rejects a target child named ..candidate before writing inside input', async t => {
  const f = fixture(t), targetDirectory = join(f.inputDirectory, '..candidate');
  f.edit('installation.json', p => { p.configuration.stateDirectory = join(targetDirectory, 'core'); });
  const before = inventory(f.inputDirectory);
  await assert.rejects(stageProductionMaterial({ inputDirectory: f.inputDirectory, targetDirectory }), /^Error: FNCP_FRESH_MATERIAL_REJECTED$/u);
  assert.equal(existsSync(targetDirectory), false); assert.equal(existsSync(targetDirectory + '.stage.lock'), false);
  assert.deepEqual(inventory(f.inputDirectory), before);
});
test('rejects an input child named ..candidate before adopting its parent target', async t => {
  const f = fixture(t), inputDirectory = join(f.parent, '..candidate'), targetDirectory = f.parent;
  fs.renameSync(f.inputDirectory, inputDirectory);
  const planPath = join(inputDirectory, 'installation.json'), plan = JSON.parse(readFileSync(planPath));
  plan.configuration.stateDirectory = join(targetDirectory, 'core'); write(planPath, json(plan));
  const before = inventory(f.parent);
  await assert.rejects(stageProductionMaterial({ inputDirectory, targetDirectory }), /^Error: FNCP_FRESH_MATERIAL_REJECTED$/u);
  assert.equal(existsSync(targetDirectory + '.stage.lock'), false); assert.deepEqual(inventory(f.parent), before);
});
test('CLI returns only aggregate status, never secrets or private paths', t => {
  const f = fixture(t), stdout = execFileSync(process.execPath, ['deploy/fncp/production-install/stage-material.mjs', f.inputDirectory, f.targetDirectory], { encoding: 'utf8' });
  assert.deepEqual(JSON.parse(stdout), { result: 'MATERIAL_STAGED', filesVerified: 37, changed: true, databaseInitialized: false, activationGranted: false });
  assert.equal(stdout.includes(f.inputDirectory), false); assert.equal(stdout.includes(readFileSync(join(f.inputDirectory, 'participant_material/oidc-secret.txt'), 'utf8')), false);
});
test('rejects an earlier output rewritten in place during a later output read', async t => {
  const f = fixture(t); await f.run();
  const originalOpen = fs.openSync, originalRead = fs.readSync, paths = new Map(); let changed = false;
  fs.openSync = function (path, ...args) { const fd = originalOpen.call(fs, path, ...args); paths.set(fd, String(path)); return fd; };
  fs.readSync = function (fd, ...args) {
    const result = originalRead.call(fs, fd, ...args);
    if (!changed && paths.get(fd) === join(f.targetDirectory, 'stage.receipt.json')) {
      changed = true; write(join(f.targetDirectory, 'participant_material/oidc-secret.txt'), 'x'.repeat(43));
    }
    return result;
  };
  syncBuiltinESMExports();
  try { await assert.rejects(f.run(), /^Error: FNCP_FRESH_MATERIAL_REJECTED$/u); assert.equal(changed, true); }
  finally { fs.openSync = originalOpen; fs.readSync = originalRead; syncBuiltinESMExports(); }
  assert.equal(readFileSync(join(f.targetDirectory, 'participant_material/oidc-secret.txt'), 'utf8'), 'x'.repeat(43));
});
