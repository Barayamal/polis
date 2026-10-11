import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, randomUUID, createPublicKey } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { inspectVolumeArchive, readArchiveMember, rewritePrivateVolumeArchive, VOLUMES, volumeRoles, sha } from './recovery-archive.mjs';
import { packRecoveryBundle, unpackRecoveryBundle } from './recovery-bundle.mjs';
import { encryptArchive, decryptArchive } from '../selfhost/recovery/encryption.mjs';
import { createPlaintextCustody } from '../selfhost/recovery/plaintext-custody.mjs';
import { backupStoppedProduction, restoreJoinedProduction, parseRecoveryContainerIds, assertRecoveryHelperCapabilities } from './recovery.mjs';
import { renderProductionCompose, PROFILE, PROFILE_V2, PROFILE_V3, imageRoles, ROLES } from './compose.mjs';
import { validateStoppedProductionSnapshot, validateRunningProductionSnapshot, CORE_FILES } from './recovery-ownership.mjs';
import { canonical } from '../production-service/contracts.mjs';
import { serviceFixture } from '../production-service/test-support/service-fixture.mjs';
import { deriveJoinedTargetState, validateClosedParticipantState } from './recovery-state.mjs';

const denied = { message: 'Joined production recovery denied.' };

test('container inventory keeps exact full identities and refuses truncated or ambiguous ownership references', () => {
  const first = '123456789abc' + 'a'.repeat(52), second = '123456789abc' + 'b'.repeat(52);
  const known = new Set([first, second]);
  assert.deepEqual(parseRecoveryContainerIds(''), []);
  const listed = parseRecoveryContainerIds(first + '\n' + second);
  assert.equal(listed.length, 2);
  assert.ok(listed.every(id => known.has(id)));
  // Both legitimate IDs share Docker's default twelve-character display prefix.
  // Expanding or matching a prefix would silently conflate resource owners.
  for (const raw of [first.slice(0,12), first + '\n' + first, first + '\n', '\n' + first,
    first.toUpperCase(), first + ' ', null, [first], Array.from({length:1025},(_,i)=>i.toString(16).padStart(64,'0')).join('\n')]) {
    assert.throws(() => parseRecoveryContainerIds(raw), denied);
  }
});

test('restore helper accepts Docker canonical capability names without allowing extra or missing authority', () => {
  assert.equal(assertRecoveryHelperCapabilities([], false), true);
  for (const names of [['CHOWN', 'DAC_OVERRIDE', 'FOWNER'], ['CAP_CHOWN', 'CAP_DAC_OVERRIDE', 'CAP_FOWNER'], ['CAP_FOWNER', 'CHOWN', 'CAP_DAC_OVERRIDE']]) {
    assert.equal(assertRecoveryHelperCapabilities(names, true), true);
    assert.throws(() => assertRecoveryHelperCapabilities(names, false), denied);
  }
  for (const names of [[], ['CAP_CHOWN', 'CAP_FOWNER'], ['CAP_CHOWN', 'CAP_DAC_OVERRIDE', 'CAP_SYS_ADMIN'],
    ['CAP_CHOWN', 'CAP_DAC_OVERRIDE', 'CAP_FOWNER', 'CAP_NET_ADMIN'], ['CAP_CHOWN', 'CHOWN', 'CAP_FOWNER'],
    ['CAP_CAP_CHOWN', 'CAP_DAC_OVERRIDE', 'CAP_FOWNER'], ['cap_chown', 'CAP_DAC_OVERRIDE', 'CAP_FOWNER'],
    ['CAP_CHOWN ', 'CAP_DAC_OVERRIDE', 'CAP_FOWNER'], [null, 'CAP_DAC_OVERRIDE', 'CAP_FOWNER'], null]) {
    assert.throws(() => assertRecoveryHelperCapabilities(names, true), denied);
  }
  assert.throws(() => assertRecoveryHelperCapabilities([], 'false'), denied);
});
const own = { postgres: 70, mariadb: 999, participant_state: 1000, participant_material: 1000, wordpress_material: 33, proxy_material: 101, edge_material: 1000 };
const required = { postgres: ['pgdata/', 'pgdata/global/', 'pgdata/PG_VERSION', 'pgdata/global/pg_control', 'pgdata/fncp.conf', 'pgdata/fncp-initialized', 'pgdata/server.key', 'pgdata/server.crt'],
  mariadb: ['mysql/', 'ibdata1'], participant_state: ['access.sqlite', 'activation.sqlite'], participant_material: ['service.json', 'private-key.pem'],
  wordpress_material: ['config.json', 'plugin-config.json', 'server.pem', 'server-key.pem', 'receiver-ca.pem'], proxy_material: ['proxy-cert.pem', 'proxy-key.pem'], edge_material: ['config.json', 'server.pem', 'server-key.pem', 'upstream-ca.pem'] };
function header({ name, uid, gid = uid, mode, bytes = Buffer.alloc(0), type = name.endsWith('/') ? '5' : '0', link = '' }) {
  const b = Buffer.alloc(512), oct = (at, length, n) => b.write(n.toString(8).padStart(length - 1, '0') + '\0', at, length, 'ascii');
  b.write(name, 0, 100); oct(100, 8, mode ?? (type === '5' ? 0o700 : 0o600)); oct(108, 8, uid); oct(116, 8, gid); oct(124, 12, bytes.length); oct(136, 12, 1);
  b.fill(32, 148, 156); b.write(type, 156); b.write(link, 157, 100); b.write('ustar\0', 257, 6); b.write('00', 263, 2);
  b.write(b.reduce((n, byte) => n + byte, 0).toString(8).padStart(6, '0') + '\0 ', 148, 8);
  return Buffer.concat([b, bytes, Buffer.alloc((512 - bytes.length % 512) % 512)]);
}
function volume(role, extra = [], replacements = {}) {
  const names = ['./', ...required[role]], entries = names.map(name => ({ name, uid: own[role], bytes: name.endsWith('/') ? Buffer.alloc(0) : Buffer.from(name === 'pgdata/PG_VERSION' ? '17\n' : 'synthetic private component bytes'), ...replacements[name] }));
  return Buffer.concat([...entries, ...extra].map(header).concat([Buffer.alloc(1024)]));
}
async function fixture(t) {
  const path = await fs.realpath(await fs.mkdtemp(join(tmpdir(), 'fncp-joined-recovery-test-'))); await fs.chmod(path, 0o700);
  t.after(() => fs.rm(path, { recursive: true, force: true }));
  const file = async (name, bytes) => { const target = join(path, name); await fs.writeFile(target, bytes, { mode: 0o600, flag: 'wx' }); return target; };
  return { path, file };
}

test('every fixed volume archive validates and private rewrites preserve all other member bytes and owners', async t => {
  const f = await fixture(t);
  for (const role of VOLUMES) {
    const path = await f.file(role + '.tar', volume(role)), inventory = await inspectVolumeArchive(path, role);
    assert.equal(inventory.role, role); assert.equal(inventory.records[0].path, '');
    assert.equal(inventory.archiveSha256, sha(await fs.readFile(path)));
    if (role === 'participant_state' || role === 'participant_material') {
      const name = role === 'participant_state' ? 'access.sqlite' : 'service.json', changed = Buffer.from('changed private replacement');
      const targetPath = join(f.path, role + '.changed.tar');
      const rewritten = await rewritePrivateVolumeArchive({ sourcePath: path, targetPath, inventory, replacements: new Map([[name, changed]]) });
      for (const r of inventory.records.filter(r => r.kind === 'file')) {
        const after = await readArchiveMember(targetPath, rewritten, r.path);
        assert.deepEqual(after, r.path === name ? changed : await readArchiveMember(path, inventory, r.path));
        const next = rewritten.records.find(v => v.path === r.path); assert.equal(next.uid, r.uid); assert.equal(next.gid, r.gid); assert.equal(next.mode, r.mode);
      }
    }
  }
});

for (const [name, bytes] of [
  ['symbolic link', volume('participant_material', [{ name: 'escape', uid: 1000, type: '2', link: '/private/secret' }])],
  ['hard link', volume('participant_material', [{ name: 'alias', uid: 1000, type: '1', link: 'service.json' }])],
  ['parent traversal', volume('participant_material', [{ name: '../escape', uid: 1000, bytes: Buffer.from('x') }])],
  ['absolute path', volume('participant_material', [{ name: '/escape', uid: 1000, bytes: Buffer.from('x') }])],
  ['duplicate member', volume('participant_material', [{ name: 'service.json', uid: 1000, bytes: Buffer.from('x') }])],
  ['GNU/PAX extension', volume('participant_material', [{ name: 'PaxHeaders', uid: 1000, type: 'x', bytes: Buffer.from('25 path=../private\n') }])],
  ['wrong UID', volume('participant_material', [], { 'service.json': { uid: 0 } })],
  ['wrong GID', volume('participant_material', [], { 'service.json': { gid: 0 } })],
  ['permissive private file', volume('participant_material', [], { 'service.json': { mode: 0o644 } })],
  ['executable private file', volume('participant_material', [], { 'service.json': { mode: 0o700 } })],
]) test(`fixed archive rejects ${name}`, async t => {
  const f = await fixture(t), path = await f.file('bad.tar', bytes); await assert.rejects(() => inspectVolumeArchive(path, 'participant_material'), denied);
});

test('missing mandatory ledger and retained service locks refuse a participant snapshot', async t => {
  const f = await fixture(t);
  const missing = Buffer.concat([header({ name: './', uid: 1000 }), header({ name: 'access.sqlite', uid: 1000, bytes: Buffer.from('synthetic') }), Buffer.alloc(1024)]);
  const missingPath = await f.file('missing.tar', missing);
  await assert.rejects(() => inspectVolumeArchive(missingPath, 'participant_state'), denied);
  const locked = await f.file('locked.tar', volume('participant_state', [{ name: 'service.lock', uid: 1000, bytes: Buffer.from('foreign') }]));
  await assert.rejects(() => inspectVolumeArchive(locked, 'participant_state'), denied);
});

test('archive checksum, end markers, padding and trailing material are verified', async t => {
  const f = await fixture(t), good = volume('participant_material');
  const changed = Buffer.from(good); changed[0] ^= 1;
  const badPadding = Buffer.from(good); const serviceStart = 1024; badPadding[serviceStart + Buffer.byteLength('synthetic private component bytes')] = 1;
  for (const [i, bytes] of [changed, good.subarray(0, good.length - 512), badPadding, Buffer.concat([good, header({ name: 'after', uid: 1000 })])].entries()) {
    const path = await f.file('bad-' + i + '.tar', bytes); await assert.rejects(() => inspectVolumeArchive(path, 'participant_material'), denied);
  }
});

test('single AES-GCM bundle authenticates all six roles and restores their exact private bytes', async t => {
  const f = await fixture(t), archives = {}, inventories = {}, custody = createPlaintextCustody();
  for (const role of VOLUMES) { archives[role] = await f.file(role + '.tar', volume(role)); inventories[role] = await inspectVolumeArchive(archives[role], role); }
  const plain = join(f.path, 'bundle'), metadata = { syntheticPrivateMaterial: 'secret sentinel in encrypted metadata only' };
  const packed = await packRecoveryBundle({ archives, expectedInventories: inventories, metadata, targetPath: plain });
  const keyPath = await f.file('key', randomBytes(32)), encryptedPath = join(f.path, 'cipher'), context = JSON.parse(canonical({ profile: 'synthetic-joined-bundle-test', bundleSha256: packed.bundleSha256 }));
  await encryptArchive({ plaintextPath: plain, encryptedPath, keyPath, context });
  assert.equal((await fs.readFile(encryptedPath)).includes(Buffer.from(metadata.syntheticPrivateMaterial)), false);
  const receipt = JSON.parse(canonical({ context }));
  const decrypted = join(f.path, 'decrypted'); await decryptArchive({ encryptedPath, plaintextPath: decrypted, keyPath, expectedContext: receipt.context, onPlaintextCreated: custody.record });
  assert.equal(sha(await fs.readFile(decrypted)), packed.bundleSha256);
  const unpacked = await unpackRecoveryBundle({ sourcePath: decrypted, directory: f.path, onCreated: custody.record });
  assert.deepEqual(unpacked.metadata, metadata);
  for (const role of VOLUMES) assert.deepEqual(await fs.readFile(unpacked.archives[role]), await fs.readFile(archives[role]));
  await custody.cleanup(); assert.equal((await fs.readdir(f.path)).some(n => n.endsWith('.authenticated.tar') || n === 'decrypted'), false);
});

test('bundle refuses omission and any source archive change since the validated snapshot', async t => {
  const f = await fixture(t), archives = {}, inventories = {};
  for (const role of VOLUMES) { archives[role] = await f.file(role + '.tar', volume(role)); inventories[role] = await inspectVolumeArchive(archives[role], role); }
  const without = { ...archives }; delete without.mariadb;
  await assert.rejects(() => packRecoveryBundle({ archives: without, expectedInventories: inventories, metadata: {}, targetPath: join(f.path, 'missing') }), denied);
  await fs.writeFile(archives.participant_material, volume('participant_material', [], { 'service.json': { bytes: Buffer.from('changed after validation') } }));
  await assert.rejects(() => packRecoveryBundle({ archives, expectedInventories: inventories, metadata: {}, targetPath: join(f.path, 'changed') }), denied);
});

test('tampered ciphertext or wrong key cannot produce authenticated component files', async t => {
  const f = await fixture(t), plain = await f.file('plain', Buffer.from('synthetic full plaintext')), keyPath = await f.file('key', randomBytes(32)), encryptedPath = join(f.path, 'cipher'), context = { test: 1 };
  await encryptArchive({ plaintextPath: plain, encryptedPath, keyPath, context });
  const ciphertext = await fs.readFile(encryptedPath); ciphertext[ciphertext.length - 1] ^= 1; await fs.writeFile(encryptedPath, ciphertext);
  const custody = createPlaintextCustody(), output = join(f.path, 'unauthenticated');
  await assert.rejects(() => decryptArchive({ encryptedPath, plaintextPath: output, keyPath, expectedContext: context, onPlaintextCreated: custody.record }));
  await custody.cleanup(); await assert.rejects(() => fs.lstat(output), { code: 'ENOENT' });
});

function engineSnapshot(version = 1) {
  const configuration = { version: 1, profile: PROFILE, deployment: 'fncp-joined-source-test', platform: 'linux/arm64', stateDirectory: '/private/synthetic-state', sourceRevision: 'a'.repeat(40),
    database: { name: 'polis', owner: 'polis_owner', migrationRole: 'polis_migration', runtimeRole: 'polis_runtime', mathRole: 'polis_math', host: 'postgres', port: 5432 },
    binding: { conversationId: '9fixedConversation', statementIds: Array.from({ length: 15 }, (_, i) => i) }, identity: { issuer: 'https://issuer.example.test/', audience: 'synthetic-client', jwksUri: 'https://issuer.example.test/jwks' } };
  if(version>=2){configuration.version=version;configuration.profile=version===3?PROFILE_V3:PROFILE_V2;configuration.edge={publicOrigin:'https://participants.example.test',discardCookies:[]};}
  if(version===3)configuration.operatorAccess={profile:'FNCP_OPERATOR_LOOPBACK_V1',tunnelRequired:true,participant:{hostIp:'127.0.0.1',published:8443,target:8443,protocol:'tcp'},wordpress:{hostIp:'127.0.0.1',published:9443,target:8443,protocol:'tcp'}};
  const imageLock = { version, sourceRevision: 'a'.repeat(40), sourceFingerprint: 'b'.repeat(64), images: Object.fromEntries(imageRoles(version).map((role, i) => [role, 'sha256:' + (i + 1).toString(16).padStart(64, '0')])) }, ownerToken = 'e'.repeat(48);
  const compose = renderProductionCompose(configuration, imageLock, ownerToken), images = {};
  for (const role of imageRoles(version)) images[role] = { Id: imageLock.images[role], Os: 'linux', Architecture: 'arm64', Config: { Env: ['PATH=/usr/bin'], Entrypoint: ['/synthetic-entrypoint'], Cmd: ['synthetic-command'], WorkingDir: '/', Labels: { 'org.opencontainers.image.revision': imageLock.sourceRevision } } };
  const material = Object.fromEntries(Object.keys(CORE_FILES).map(n => [n, { data: Buffer.from('SYNTHETIC=1\n').toString('base64') }]));
  const rows = Object.entries(compose.services).filter(([role]) => role !== 'migration').map(([role, s], i) => ({ Id: String(i + 1).repeat(64), Image: s.image, State: { Running: false, Paused: false, Restarting: false, Dead: false, OOMKilled: false, Status: 'exited', ExitCode: 0 },
    Config: { User: s.user, Labels: { ...s.labels, 'com.docker.compose.project': configuration.deployment, 'com.docker.compose.service': role },
      Env: Object.entries({ PATH: '/usr/bin', ...(s.env_file ? { SYNTHETIC: '1' } : {}), ...(s.environment ?? {}) }).map(([k, v]) => k + '=' + v),
      Entrypoint: s.entrypoint ?? images[role].Config.Entrypoint, Cmd: s.command ?? images[role].Config.Cmd, WorkingDir: s.working_dir ?? '/' },
    HostConfig: { ReadonlyRootfs: true, Privileged: false, PublishAllPorts: false, AutoRemove: false, RestartPolicy: { Name: 'no' }, CapDrop: ['ALL'], CapAdd: [], SecurityOpt: s.security_opt,
      PidsLimit: s.pids_limit, Memory: Number(s.mem_limit.slice(0, -1)) * 1024 * 1024, NanoCpus: Number(s.cpus) * 1e9, PidMode: '', IpcMode: 'private', PortBindings: Object.fromEntries((s.ports??[]).map(p=>[p.target+'/'+p.protocol,[{HostIp:p.host_ip,HostPort:String(p.published)}]])), NetworkMode: role === 'mariadb' ? 'none' : compose.networks[Object.keys(s.networks)[0]].name,
      Tmpfs: Object.fromEntries(s.tmpfs.map(v => { const p = v.indexOf(':'); return [v.slice(0, p), v.slice(p + 1)]; })) },
    NetworkSettings: { Ports: {}, Networks: Object.fromEntries(Object.keys(s.networks ?? {}).map(n => [compose.networks[n].name, {}])) },
    Mounts: (s.volumes ?? []).map(v => ({ Type: v.type, Destination: v.target, RW: !v.read_only, ...(v.type === 'volume' ? { Name: compose.volumes[v.source].name } : { Source: v.source }) })) }));
  const volumes = Object.entries(compose.volumes).map(([role, v]) => ({ Name: v.name, Driver: 'local', Options: v.driver_opts ?? {}, Labels: { ...v.labels, 'com.docker.compose.project': configuration.deployment, 'com.docker.compose.volume': role } }));
  const networks = Object.entries(compose.networks).map(([role, n]) => ({ Name: n.name, Driver: 'bridge', Internal: n.internal, Scope: 'local', Options: {}, Labels: { ...n.labels, 'com.docker.compose.project': configuration.deployment, 'com.docker.compose.network': role } }));
  return structuredClone({ configuration, imageLock, ownerToken, rows, images, volumes, networks, coreMaterial: material });
}

test('exact observed normal recipe is accepted only with all seven normal services stopped and all storage bound', () => {
  assert.equal(validateStoppedProductionSnapshot(engineSnapshot()).stopped, true);
});
for (const [name, mutate] of [
  ['running service', x => { x.rows[0].State.Running = true; }], ['missing participant', x => { x.rows.pop(); }],
  ['duplicate role', x => { x.rows.push(x.rows[0]); }], ['failed database shutdown', x => { x.rows[0].State.ExitCode = 137; }],
  ['different image', x => { x.rows[0].Image = x.imageLock.images.api; }], ['changed owner', x => { x.rows[0].Config.Labels['org.barayamal.fncp.owner'] = 'f'.repeat(48); }],
  ['different data volume', x => { x.rows[0].Mounts[0].Name = 'unowned-data'; }], ['writable credential bind', x => { x.rows[0].Mounts[1].RW = true; }],
  ['second data mount', x => { x.rows[0].Mounts.push(x.rows[0].Mounts[0]); }], ['unconfined security', x => { x.rows[0].HostConfig.SecurityOpt.push('seccomp=unconfined'); }],
  ['restart policy', x => { x.rows[0].HostConfig.RestartPolicy.Name = 'always'; }], ['resource limit drift', x => { x.rows[0].HostConfig.Memory *= 2; }],
  ['host PID namespace', x => { x.rows[0].HostConfig.PidMode = 'host'; }], ['changed command', x => { x.rows[0].Config.Cmd = ['initialize']; }],
  ['secret/environment drift', x => { x.rows[0].Config.Env.push('UNREVIEWED=1'); }], ['published port', x => { x.rows[0].HostConfig.PortBindings = { '5432/tcp': [{ HostPort: '5432' }] }; }],
  ['external network', x => { x.networks[0].Internal = false; }], ['extra attached network', x => { x.rows[0].NetworkSettings.Networks.unowned = {}; }],
  ['data volume driver options', x => { x.volumes[0].Options = { device: '/private/unowned' }; }],
]) test(`stopped source ownership rejects ${name}`, () => { const x = engineSnapshot(); mutate(x); assert.throws(() => validateStoppedProductionSnapshot(x), denied); });

test('entry points reject an unreviewed job before any engine command or destination creation', async t => {
  const f = await fixture(t), path = await f.file('invalid.json', Buffer.from('{"profile":"unreviewed"}'));
  await assert.rejects(() => backupStoppedProduction({ jobPath: path }), denied); await assert.rejects(() => restoreJoinedProduction({ jobPath: path }), denied);
  assert.deepEqual(await fs.readdir(f.path), ['invalid.json']);
});

async function closedService(t) {
  const x = await serviceFixture(t); x.manifest.activation.images = Object.fromEntries(ROLES.map(role => [role, 'sha256:' + sha('synthetic-exact-image-' + role)])); x.save();
  const service = await x.create(); service.operator.activate(x.envelope(service)); service.operator.closeAdmission();
  const sourceDescriptor = service.operator.recoveryDescriptor(); await service.close();
  const identity = sha(canonical([x.manifest.deploymentId, x.manifest.conversationId, x.manifest.activation.keyId,
    sha(createPublicKey(await fs.readFile(x.manifest.activation.publicKeyFile)).export({ format: 'der', type: 'spki' }))]));
  const args = { accessPath: join(x.stateDirectory, 'access.sqlite'), activationPath: join(x.stateDirectory, 'activation.sqlite'), sourceDescriptor, activationIdentity: identity };
  return { x, args };
}

test('actual closed service ledgers validate read-only with their retained activation replay floor', async t => {
  const { args } = await closedService(t), access = await fs.readFile(args.accessPath), activation = await fs.readFile(args.activationPath);
  assert.deepEqual(validateClosedParticipantState(args), { accounts: 0, events: 0, invitations: 0, activationReplayFloor: 1, acceptedActivationIds: 1, closed: true });
  assert.deepEqual(await fs.readFile(args.accessPath), access); assert.deepEqual(await fs.readFile(args.activationPath), activation);
});

for (const [name, dbName, sql] of [
  ['still-active activation', 'activationPath', 'UPDATE activation_state SET active=1'],
  ['lost replay ID history', 'activationPath', 'DELETE FROM activation_ids'],
  ['changed replay identity', 'activationPath', "UPDATE activation_state SET identity='" + '0'.repeat(64) + "'"],
  ['changed activation binding', 'activationPath', "UPDATE activation_state SET binding_hash='" + '0'.repeat(64) + "'"],
  ['changed activation schema', 'activationPath', 'CREATE INDEX unexpected ON activation_state(sequence)'],
  ['faulted access state', 'accessPath', 'UPDATE meta SET faulted=1'],
]) test(`joined ledger validation rejects ${name}`, async t => {
  const { args } = await closedService(t), db = new DatabaseSync(args[dbName]); try { db.exec(sql); } finally { db.close(); }
  const before = await fs.readFile(args[dbName]); assert.throws(() => validateClosedParticipantState(args), denied); assert.deepEqual(await fs.readFile(args[dbName]), before);
});

for(const version of [1,2,3])test('V'+version+' archived material derives only a fresh epoch/config hash and verifies all bridge secret links', async t => {
  const f = await fixture(t), { x, args } = await closedService(t), material = new Map();
  for (const name of await fs.readdir(x.materialDirectory)) material.set(name, await fs.readFile(join(x.materialDirectory, name)));
  const relocate = v => typeof v === 'string' ? v.replace(x.materialDirectory + '/', '/run/fncp/')
    : Array.isArray(v) ? v.map(relocate) : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, value]) => [k, relocate(value)])) : v;
  const manifest = relocate(x.manifest); manifest.stateDirectory = '/var/lib/fncp';
  const operatorAccess={profile:'FNCP_OPERATOR_LOOPBACK_V1',tunnelRequired:true,participant:{hostIp:'127.0.0.1',published:8443,target:8443,protocol:'tcp'},wordpress:{hostIp:'127.0.0.1',published:9443,target:8443,protocol:'tcp'}};
  if(version>=2){manifest.activation.images.edge='sha256:'+'9'.repeat(64);manifest.activation.edgeMaterialSha256=sha(canonical([...required.edge_material].sort().map(name=>({name,sha256:sha('synthetic private component bytes')}))));}
  if(version===3){manifest.activation.images.operator='sha256:'+'a'.repeat(64);manifest.activation.operatorAccessSha256=sha(canonical(operatorAccess));}
  material.set('service.json', Buffer.from(canonical(manifest) + '\n'));
  const sourceDescriptor = structuredClone(args.sourceDescriptor), fingerprints = Object.fromEntries([...material].map(([name, bytes]) => ['/run/fncp/' + name, sha(bytes)]));
  sourceDescriptor.binding.activation.images=manifest.activation.images;if(version===3)sourceDescriptor.binding.activation.operatorAccessSha256=manifest.activation.operatorAccessSha256;sourceDescriptor.binding.activation.configSha256 = sha(canonical({ manifest, material: fingerprints })); sourceDescriptor.bindingSha256 = sha(canonical(sourceDescriptor.binding));
  const get = path => material.get(path.slice('/run/fncp/'.length)).toString('utf8');
  const plugin = { profile: 'FNCP_PRODUCTION_WORDPRESS_V1', deploymentId: manifest.deploymentId, conversationId: manifest.conversationId,
    wordpressOrigin: manifest.wordpress.origin, eventEndpoint: manifest.receiver.origin + '/internal/wordpress/events', consentVersion: manifest.content.consentVersion,
    noticeSha256: sourceDescriptor.binding.configuration.noticeSha256, serviceRequestKey: get(manifest.secrets.wordpressRequestKeyFile),
    serviceResponseKey: get(manifest.secrets.wordpressResponseKeyFile), eventKey: get(manifest.secrets.wordpressEventKeyFile), caFile: '/run/fncp/wordpress/receiver-ca.pem' };
  const participant = Buffer.concat([header({ name: './', uid: 1000 }), ...[...material].map(([name, bytes]) => header({ name, uid: 1000, bytes })), Buffer.alloc(1024)]);
  const archives = { participant_material: await f.file('participant.tar', participant), wordpress_material: await f.file('wordpress.tar', volume('wordpress_material', [], { 'plugin-config.json': { bytes: Buffer.from(canonical(plugin)) } })) };
  if(version>=2)archives.edge_material=await f.file('edge-material.tar',volume('edge_material'));
  const inventories = Object.fromEntries(await Promise.all(Object.entries(archives).map(async ([role, path]) => [role, await inspectVolumeArchive(path, role)])));
  const api = { FNCP_GATEWAY_SHARED_SECRET: get(manifest.secrets.gatewayKeyFile), FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL: get(manifest.secrets.providerKeyFile),
    FNCP_GATEWAY_CONVERSATION_ID: manifest.conversationId, FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID: manifest.conversationId, FNCP_FIXED_STATEMENT_IDS: manifest.content.statementIds.join(',') };
  const coreMaterial = { 'api.env': { data: Buffer.from(Object.entries(api).map(([k, v]) => k + '=' + v).join('\n') + '\n').toString('base64') } };
  const options = { archives, inventories, sourceDescriptor, imageLock: { sourceRevision: manifest.activation.sourceRevision, images: manifest.activation.images },
    configuration: { version, binding: { conversationId: manifest.conversationId, statementIds: manifest.content.statementIds }, ...(version===3?{operatorAccess}:{}) }, coreMaterial, recoveryEpoch: randomUUID() };
  const target = await deriveJoinedTargetState(options), next = JSON.parse(target.targetManifestBytes.toString('utf8'));
  assert.equal(next.activation.recoveryEpoch, options.recoveryEpoch); next.activation.recoveryEpoch = manifest.activation.recoveryEpoch; assert.equal(canonical(next), canonical(manifest));
  assert.equal(target.targetDescriptor.binding.configuration.credentialBindingSha256, sourceDescriptor.binding.configuration.credentialBindingSha256);
  const targetFingerprints = { ...fingerprints, '/run/fncp/service.json': sha(target.targetManifestBytes) };
  assert.equal(target.targetDescriptor.binding.activation.configSha256, sha(canonical({ manifest: JSON.parse(target.targetManifestBytes), material: targetFingerprints })));
  await assert.rejects(() => deriveJoinedTargetState({ ...options, recoveryEpoch: manifest.activation.recoveryEpoch }), denied);
  const badDescriptor = structuredClone(sourceDescriptor); badDescriptor.binding.activation.configSha256 = '0'.repeat(64); badDescriptor.bindingSha256 = sha(canonical(badDescriptor.binding));
  await assert.rejects(() => deriveJoinedTargetState({ ...options, sourceDescriptor: badDescriptor }), denied);
  const changed = structuredClone(coreMaterial); changed['api.env'].data = Buffer.from('FNCP_GATEWAY_SHARED_SECRET=different\n').toString('base64');
  await assert.rejects(() => deriveJoinedTargetState({ ...options, coreMaterial: changed }), denied);
  if(version>=2){const tamperedPath=await f.file('changed-edge.tar',volume('edge_material',[],{'config.json':{bytes:Buffer.from('changed')}})),tamperedInventory=await inspectVolumeArchive(tamperedPath,'edge_material');await assert.rejects(()=>deriveJoinedTargetState({...options,archives:{...archives,edge_material:tamperedPath},inventories:{...inventories,edge_material:tamperedInventory}}),denied);}
  target.targetManifestBytes.fill(0); for (const bytes of material.values()) bytes.fill(0);
});


test('V2 stopped ownership covers ninth edge image, isolated network and seventh durable material role',()=>{
  const observed=engineSnapshot(2),result=validateStoppedProductionSnapshot(observed);assert.equal(result.services,8);assert.equal(result.durableVolumes,7);
  for(const mutate of [x=>x.rows=x.rows.filter(r=>r.Config.Labels['com.docker.compose.service']!=='edge'),x=>delete x.images.edge,x=>x.volumes=x.volumes.filter(v=>!v.Name.endsWith('_edge_material')),x=>x.networks.find(n=>n.Name.endsWith('_participant_ingress')).Internal=false,x=>x.rows.find(r=>r.Config.Labels['com.docker.compose.service']==='edge').NetworkSettings.Networks[x.configuration.deployment+'_core']={}]){const x=structuredClone(observed);mutate(x);assert.throws(()=>validateStoppedProductionSnapshot(x),denied);}
});
test('V3 stopped ownership covers tenth gateway image and exact loopback publication network',()=>{
  const observed=engineSnapshot(3),result=validateStoppedProductionSnapshot(observed);assert.equal(result.services,9);assert.equal(result.durableVolumes,7);
  const operator=observed.rows.find(r=>r.Config.Labels['com.docker.compose.service']==='operator');
  assert.deepEqual(operator.HostConfig.PortBindings,{'8443/tcp':[{HostIp:'127.0.0.1',HostPort:'8443'}],'9443/tcp':[{HostIp:'127.0.0.1',HostPort:'9443'}]});
  assert.deepEqual(operator.NetworkSettings.Ports,{});
  assert.equal(observed.networks.find(n=>n.Name.endsWith('_operator_access')).Internal,false);
  for(const mutate of [x=>x.rows=x.rows.filter(r=>r.Config.Labels['com.docker.compose.service']!=='operator'),x=>delete x.images.operator,
    x=>x.networks.find(n=>n.Name.endsWith('_operator_access')).Internal=true,
    x=>x.rows.find(r=>r.Config.Labels['com.docker.compose.service']==='operator').HostConfig.PortBindings['8443/tcp'][0].HostIp='0.0.0.0',
    x=>x.rows.find(r=>r.Config.Labels['com.docker.compose.service']==='operator').NetworkSettings.Ports={'8443/tcp':[{HostIp:'127.0.0.1',HostPort:'8443'}]},
    x=>x.rows.find(r=>r.Config.Labels['com.docker.compose.service']==='edge').HostConfig.PortBindings={'8443/tcp':[{HostIp:'127.0.0.1',HostPort:'8443'}]}]){
    const x=structuredClone(observed);mutate(x);assert.throws(()=>validateStoppedProductionSnapshot(x),denied);
  }
});
test('V2 edge archive requires exact owned private material and preserves upstream trust rewrite',async t=>{
  const f=await fixture(t);assert.equal(volumeRoles(1),VOLUMES);assert.equal(volumeRoles(2).length,7);assert.equal(volumeRoles(3).length,7);assert.throws(()=>volumeRoles(4),denied);
  const path=await f.file('edge.tar',volume('edge_material')),inventory=await inspectVolumeArchive(path,'edge_material'),targetPath=join(f.path,'rewritten.tar');
  const replacement=Buffer.from('replacement upstream trust');const next=await rewritePrivateVolumeArchive({sourcePath:path,targetPath,inventory,replacements:new Map([['upstream-ca.pem',replacement]])});
  for(const r of inventory.records.filter(r=>r.kind==='file'))assert.deepEqual(await readArchiveMember(targetPath,next,r.path),r.path==='upstream-ca.pem'?replacement:await readArchiveMember(path,inventory,r.path));
  for(const [i,bytes] of [volume('edge_material',[{name:'unexpected',uid:1000,bytes:Buffer.from('x')}]),volume('edge_material',[],{'config.json':{uid:101}}),volume('edge_material',[],{'server-key.pem':{mode:0o644}}),volume('edge_material',[],{'upstream-ca.pem':{type:'2',link:'/outside'}})].entries()){const bad=await f.file('bad-edge-'+i+'.tar',bytes);await assert.rejects(()=>inspectVolumeArchive(bad,'edge_material'),denied);}
});


test('running descriptor observations require exact live normal roles, healthy probes, mounts and limits',()=>{
  const live=engineSnapshot(2),compose=renderProductionCompose(live.configuration,live.imageLock,live.ownerToken);for(const row of live.rows){row.State.Running=true;row.State.Status='running';if(compose.services[row.Config.Labels['com.docker.compose.service']].healthcheck)row.State.Health={Status:'healthy'};}
  const result=validateRunningProductionSnapshot(live);assert.equal(result.running,true);assert.equal(result.stopped,undefined);assert.throws(()=>validateStoppedProductionSnapshot(live),denied);
  for(const mutate of [x=>x.rows[0].State.Running=false,x=>x.rows[0].State.Health.Status='starting',x=>x.rows[0].Mounts.push({Type:'bind',Destination:'/foreign',Source:'/outside',RW:true}),x=>x.rows[0].HostConfig.Memory*=2,x=>x.rows[0].Config.Env.push('UNAPPROVED=1'),x=>x.rows[0].Config.Cmd=['foreign-command'],x=>x.rows.push(x.rows[0])]){const x=structuredClone(live);mutate(x);assert.throws(()=>validateRunningProductionSnapshot(x),denied);}
});
test('V3 running ownership requires both exact configured and active loopback bindings',()=>{
  const live=engineSnapshot(3),compose=renderProductionCompose(live.configuration,live.imageLock,live.ownerToken);
  for(const row of live.rows){const service=compose.services[row.Config.Labels['com.docker.compose.service']];row.State.Running=true;row.State.Status='running';if(service.healthcheck)row.State.Health={Status:'healthy'};row.NetworkSettings.Ports=Object.fromEntries((service.ports??[]).map(p=>[p.target+'/'+p.protocol,[{HostIp:p.host_ip,HostPort:String(p.published)}]]));}
  assert.equal(validateRunningProductionSnapshot(live).running,true);
  const operator=live.rows.find(r=>r.Config.Labels['com.docker.compose.service']==='operator');operator.NetworkSettings.Ports={};
  assert.throws(()=>validateRunningProductionSnapshot(live),denied);
});
