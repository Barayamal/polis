import assert from 'node:assert/strict';
import { chmod, link, lstat, mkdir, mkdtemp, readFile, realpath, rename, rm, symlink, unlink, writeFile } from 'node:fs/promises';
import { randomBytes, createPublicKey, X509Certificate } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { snapshotMaterial, assertMaterial } from './material.mjs';
import { prepareLocalMaterial } from './prepare-local-material.mjs';

const denied = { message: 'FNCP_SELFHOST_MATERIAL_REJECTED' };
async function fixture(t) {
  const parent = await mkdtemp(join(await realpath(tmpdir()), 'fncp-material-contract-test-'));
  await chmod(parent, 0o700);
  t.after(() => rm(parent, { recursive: true, force: true }));
  const stateDirectory = join(parent, 'state'); await mkdir(stateDirectory, { mode: 0o700 });
  const c = { version: 1, classification: 'closed-local-core', deployment: 'fncp-material-contract-test',
    platform: 'linux/arm64', engine: { host: 'unix:///unused-explicit-engine/docker.sock', configDirectory: '/unused-explicit-engine/config' },
    stateDirectory, sourceRevision: 'a'.repeat(40), database: { name: 'polis', owner: 'polis_owner', migrationRole: 'polis_migration',
      runtimeRole: 'polis_runtime', mathRole: 'polis_math', host: 'postgres', port: 5432 },
    binding: { conversationId: '9fncpSelfhostFixture', statementIds: Array.from({ length: 15 }, (_, i) => i) },
    identity: { issuer: 'https://identity.example.invalid/', audience: 'local-api', jwksUri: 'https://identity.example.invalid/jwks' } };
  const configPath = join(parent, 'config.json'); await writeFile(configPath, JSON.stringify(c), { mode: 0o600 });
  // Exercise the actual producer, including fresh cryptographic material. It
  // invokes OpenSSL only; no Docker engine, service, VM or network is started.
  const result = await prepareLocalMaterial(configPath);
  assert.equal(result.materialCreated, true);
  const path = name => join(stateDirectory, 'material', name);
  const edit = async (name, mutate) => {
    const original = await readFile(path(name));
    const mode = (await lstat(path(name))).mode & 0o7777;
    try { await writeFile(path(name), await mutate(original), { mode }); }
    catch (error) { await writeFile(path(name), original, { mode }); throw error; }
    return async () => { await writeFile(path(name), original, { mode }); await chmod(path(name), mode); };
  };
  return { c, parent, path, edit };
}

test('actual local material producer satisfies the exact twelve-input private manifest', async t => {
  const h = await fixture(t); const manifest = await snapshotMaterial(h.c);
  assert.equal(manifest.version, 1); assert.equal(manifest.files.length, 12);
  assert.equal(Object.isFrozen(manifest), true); assert.equal(Object.isFrozen(manifest.files), true);
  assert.deepEqual(await assertMaterial(h.c, manifest), { materialVerified: true, filesVerified: 12,
    configurationMatched: true, criticalEnvironmentVerified: true });
  const serialized = JSON.stringify(manifest);
  for (const name of ['database-owner-password', 'database-runtime-password', 'jwt-private.pem']) {
    assert.equal(serialized.includes((await readFile(h.path(name), 'utf8')).trim()), false);
  }
  assert.equal(manifest.files.some(file => file.name === 'initialize-database.sh' || file.name === 'local-ca.key'), false);
});

test('critical API mode, TLS, credentials and conversation binding changes are rejected', async t => {
  const h = await fixture(t);
  for (const [key, value] of [
    ['FNCP_OPTION_C_RELEASE_MODE', 'local'], ['FNCP_GATEWAY_ENFORCEMENT', 'false'],
    ['FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT', 'false'], ['DATABASE_SSL', 'false'],
    ['DATABASE_SSL_CA_FILE', '/elsewhere/ca.pem'], ['FNCP_GATEWAY_CONVERSATION_ID', '9otherConversation'],
    ['FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID', '9otherConversation'], ['FNCP_FIXED_STATEMENT_IDS', '0,1'],
    ['DATABASE_URL', 'postgres://polis_owner:wrong@postgres:5432/polis'],
    ['AUTH_AUDIENCE', 'different-audience'], ['JWKS_URI', 'https://unreviewed.example.invalid/jwks'],
    ['ENABLE_TELEMETRY', 'true'], ['EMAIL_TRANSPORT_TYPES', 'smtp'], ['JWT_PRIVATE_KEY_PATH', '/elsewhere/key.pem'],
  ]) await t.test(key, async () => {
    const restore = await h.edit('api.env', bytes => bytes.toString().replace(new RegExp(`^${key}=.*$`, 'm'), `${key}=${value}`));
    try { await assert.rejects(snapshotMaterial(h.c), denied); } finally { await restore(); }
  });
});

test('extra, duplicate, unset, quoted and interpolated environment entries reject before launch', async t => {
  const h = await fixture(t);
  for (const [name, mutate] of [
    ['extra variable', value => value + 'NODE_TLS_REJECT_UNAUTHORIZED=0\n'],
    ['duplicate variable', value => value + 'NODE_ENV=production\n'],
    ['unset dedicated mode', value => value.replace('FNCP_OPTION_C_RELEASE_MODE=production', 'FNCP_OPTION_C_RELEASE_MODE')],
    ['interpolation', value => value.replace('AUTH_AUDIENCE=local-api', 'AUTH_AUDIENCE=${HOME}')],
    ['quoted value', value => value.replace('NODE_ENV=production', 'NODE_ENV="production"')],
    ['embedded carriage return', value => value.replace('NODE_ENV=production', 'NODE_ENV=production\r')],
  ]) await t.test(name, async () => {
    const restore = await h.edit('api.env', bytes => mutate(bytes.toString()));
    try { await assert.rejects(snapshotMaterial(h.c), denied); } finally { await restore(); }
  });
});

test('math/migration TLS and cross-role credential agreement are enforced', async t => {
  const h = await fixture(t);
  for (const [file, key, value] of [
    ['math.env', 'DATABASE_SSL', 'false'], ['math.env', 'FNCP_OPTION_C_RELEASE_MODE', 'local'],
    ['math.env', 'DATABASE_URL', 'postgres://polis_runtime:wrong@postgres:5432/polis'],
    ['migration.env', 'PGSSLMODE', 'require'], ['migration.env', 'FNCP_EXPECTED_MIGRATION_ROLE', 'polis_owner'],
    ['migration.env', 'FNCP_DATABASE_PASSWORD', randomBytes(32).toString('base64url')],
  ]) await t.test(`${file}:${key}`, async () => {
    const restore = await h.edit(file, bytes => bytes.toString().replace(new RegExp(`^${key}=.*$`, 'm'), `${key}=${value}`));
    try { await assert.rejects(snapshotMaterial(h.c), denied); } finally { await restore(); }
  });
  const api = await readFile(h.path('api.env'), 'utf8');
  const gateway = /^FNCP_GATEWAY_SHARED_SECRET=(.*)$/m.exec(api)[1];
  const restore = await h.edit('math.env', bytes => bytes.toString().replace(/^WEBSERVER_PASS=.*$/m, `WEBSERVER_PASS=${gateway}`));
  try { await assert.rejects(snapshotMaterial(h.c), denied); } finally { await restore(); }
});

test('a coherent secret change is still rejected against the prior private manifest', async t => {
  const h = await fixture(t); const manifest = await snapshotMaterial(h.c);
  const changed = randomBytes(32).toString('base64url');
  const original = await readFile(h.path('database-runtime-password'), 'utf8');
  const restorePassword = await h.edit('database-runtime-password', () => changed);
  const restoreEnv = await h.edit('api.env', bytes => bytes.toString().replace(original, changed));
  try {
    assert.equal((await snapshotMaterial(h.c)).files.length, 12);
    await assert.rejects(assertMaterial(h.c, manifest), denied);
  } finally { await restoreEnv(); await restorePassword(); }
  assert.equal((await assertMaterial(h.c, manifest)).materialVerified, true);
});

test('private parent, regular single-link files and exact input permissions are mandatory', async t => {
  const h = await fixture(t);
  const input = h.path('api.env'); const original = await readFile(input);
  await chmod(input, 0o644);
  await assert.rejects(snapshotMaterial(h.c), denied); await chmod(input, 0o600);
  const alias = join(h.parent, 'alias.env'); await link(input, alias);
  await assert.rejects(snapshotMaterial(h.c), denied); await unlink(alias);
  await rename(input, alias); await symlink(alias, input);
  await assert.rejects(snapshotMaterial(h.c), denied); await unlink(input); await rename(alias, input);
  await writeFile(input, original, { mode: 0o600 });
  await chmod(h.c.stateDirectory, 0o755);
  await assert.rejects(snapshotMaterial(h.c), denied); await chmod(h.c.stateDirectory, 0o700);
  const material = join(h.c.stateDirectory, 'material');
  await chmod(material, 0o755);
  await assert.rejects(snapshotMaterial(h.c), denied); await chmod(material, 0o700);
  const moved = join(h.c.stateDirectory, 'moved-material'); await rename(material, moved); await symlink(moved, material);
  await assert.rejects(snapshotMaterial(h.c), denied); await unlink(material); await rename(moved, material);
  assert.equal((await snapshotMaterial(h.c)).files.length, 12);
});

test('missing and oversized runtime inputs fail without exposing data', async t => {
  const h = await fixture(t); const input = h.path('database-runtime-password');
  const bytes = await readFile(input); await unlink(input);
  await assert.rejects(snapshotMaterial(h.c), denied);
  await writeFile(input, Buffer.alloc(65_537, 65), { mode: 0o644 });
  await assert.rejects(snapshotMaterial(h.c), denied);
  await writeFile(input, bytes, { mode: 0o644 });
});

test('database CA/leaf/key and JWT signing pair are checked, including role separation and expiry', async t => {
  const h = await fixture(t);
  for (const [target, source] of [
    ['database-ca.pem', 'database-server.pem'], ['database-server.pem', 'database-ca.pem'],
    ['database-server.key', 'jwt-private.pem'], ['jwt-private.pem', 'database-server.key'],
  ]) await t.test(`${target}:${source}`, async () => {
    const replacement = await readFile(h.path(source));
    const restore = await h.edit(target, () => replacement);
    try { await assert.rejects(snapshotMaterial(h.c), denied); } finally { await restore(); }
  });
  const serverKey = await readFile(h.path('database-server.key'));
  const restorePrivate = await h.edit('jwt-private.pem', () => serverKey);
  const restorePublic = await h.edit('jwt-public.pem', () => createPublicKey(serverKey).export({ type: 'spki', format: 'pem' }));
  try { await assert.rejects(snapshotMaterial(h.c), denied); } finally { await restorePublic(); await restorePrivate(); }
  const ca = new X509Certificate(await readFile(h.path('database-ca.pem'))); const originalNow = Date.now;
  try { Date.now = () => Date.parse(ca.validTo) + 1; await assert.rejects(snapshotMaterial(h.c), denied); }
  finally { Date.now = originalNow; }
});

test('manifest schema, exact ordered input set and configuration binding cannot be substituted', async t => {
  const h = await fixture(t); const manifest = await snapshotMaterial(h.c);
  for (const mutate of [
    value => { value.extra = 'untrusted'; }, value => { value.configurationSha256 = 'a'.repeat(64); },
    value => { value.files[0].name = '../outside'; }, value => { value.files[0].sha256 = 'a'.repeat(64); },
    value => { value.files.reverse(); }, value => { value.files.push(value.files[0]); },
  ]) {
    const value = structuredClone(manifest); mutate(value);
    await assert.rejects(assertMaterial(h.c, value), denied);
  }
  const changed = structuredClone(h.c); changed.identity.audience = 'changed-audience';
  await assert.rejects(assertMaterial(changed, manifest), denied);
  const accessor = structuredClone(manifest); let accessed = 0;
  Object.defineProperty(accessor, 'files', { enumerable: true, get() { accessed++; return manifest.files; } });
  await assert.rejects(assertMaterial(h.c, accessor), denied); assert.equal(accessed, 0);
});
