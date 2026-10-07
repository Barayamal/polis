import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, createPrivateKey, X509Certificate } from 'node:crypto';
import { chmodSync, lstatSync, readFileSync, readdirSync, renameSync,
  rmSync, symlinkSync, writeFileSync, linkSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { createBootstrapPostgresMaterial } from './bootstrap-postgres-material.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const script = readFileSync(join(here, 'bootstrap-postgres-entrypoint.sh'), 'utf8');
const generic = { name: 'Error', message: 'Fresh PostgreSQL material rejected; private details withheld.' };
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
async function material(t) {
  const owner = await createBootstrapPostgresMaterial();
  const config = owner.configuration();
  t.after(() => { owner.close(); rmSync(config.directory, { recursive: true, force: true }); });
  return { owner, config };
}

test('factory import exposes no I/O entrypoints besides the explicit zero-argument factory', async () => {
  const source = readFileSync(join(here, 'bootstrap-postgres-material.mjs'), 'utf8');
  const prefix = source.split('export async function createBootstrapPostgresMaterial()')[0];
  assert.doesNotMatch(prefix, /^\s*(?:const|let) \w+\s*=\s*(?:mkdtempSync|spawnSync|readFileSync|openSync)\(/m);
  assert.deepEqual(Object.keys(await import('./bootstrap-postgres-material.mjs')), ['createBootstrapPostgresMaterial']);
});

test('rejects all caller arguments without accessing getters or adopting paths', async () => {
  let touched = 0;
  const value = Object.defineProperty({}, 'directory', { get() { touched++; throw Error('private'); } });
  for (const arg of [undefined, null, '/tmp/retained', value, new Proxy({}, { get() { touched++; } })]) {
    await assert.rejects(createBootstrapPostgresMaterial(arg), generic);
  }
  assert.equal(touched, 0);
});

test('fresh identities, credentials and public/private TLS material are independent', async t => {
  const a = await material(t), b = await material(t);
  for (const key of ['namespaceId', 'database', 'user', 'password', 'directory', 'certificateSha256']) {
    assert.notEqual(a.config[key], b.config[key]);
  }
  assert.match(a.config.namespaceId, /^[a-f0-9]{24}$/);
  assert.match(a.config.database, /^fncp_fresh_[a-f0-9]{24}$/);
  assert.match(a.config.user, /^fncp_fresh_[a-f0-9]{24}$/);
  assert.match(a.config.password, /^[a-f0-9]{64}$/);
  assert.equal(new Set([a.config.namespaceId, a.config.database.slice(11), a.config.user.slice(11)]).size, 3);
  const cert = new X509Certificate(a.config.certificatePem);
  assert.equal(cert.checkHost(a.config.databaseHost, { subject: 'never', wildcards: false }), a.config.databaseHost);
  assert.equal(cert.checkIP('127.0.0.1'), '127.0.0.1');
  assert.equal(cert.checkIP('127.0.0.2'), undefined);
  assert.equal(sha(cert.raw), a.config.certificateSha256);
  assert.equal(cert.checkPrivateKey(createPrivateKey(readFileSync(join(a.config.directory, 'postgres-key.pem')))), true);
  assert.equal(cert.verify(cert.publicKey), true);
});

test('private archive handoff contains exactly eight verified owned files', async t => {
  const { owner, config } = await material(t);
  assert.ok(Object.isFrozen(owner)); assert.ok(Object.isFrozen(config)); assert.ok(Object.isFrozen(config.files));
  assert.equal(lstatSync(config.directory).mode & 0o777, 0o700);
  assert.equal(config.files.length, 8);
  assert.deepEqual(readdirSync(config.directory).sort(), config.files.map(file => file.name).sort());
  for (const file of config.files) {
    assert.ok(Object.isFrozen(file));
    assert.equal(file.path, join(config.directory, file.name));
    assert.equal(file.destination, `/run/fncp/postgres-material/${file.name}`);
    assert.deepEqual([file.archiveUid, file.archiveGid, file.archiveMode], [70, 70, 0o600]);
    assert.equal(lstatSync(file.path).mode & 0o777, 0o600);
    assert.equal(readFileSync(file.path).length, file.bytes);
    assert.equal(sha(readFileSync(file.path)), file.sha256);
  }
  assert.equal(owner.verify(), undefined);
});

test('configuration and HBA are literal, loopback-only, pinned and disclosure-minimizing', async t => {
  const { config } = await material(t);
  const pg = readFileSync(join(config.directory, 'postgresql.conf'), 'utf8');
  const hba = readFileSync(join(config.directory, 'pg_hba.conf'), 'utf8');
  const literal = script.split("<<'CONFIG' || fail\n")[1].split('\nCONFIG\n')[0] + '\n';
  assert.equal(pg, literal);
  assert.equal(hba, `local all postgres peer\nlocal ${config.database} ${config.user} trust\nlocal all all reject\nhostssl ${config.database} ${config.user} 127.0.0.1/32 scram-sha-256\nhost all all 0.0.0.0/0 reject\nhost all all ::0/0 reject\n`);
  assert.match(pg, /listen_addresses = '127\.0\.0\.1'/);
  assert.match(pg, /ssl = on/);
  assert.match(pg, /search_path = 'public'/);
  assert.match(pg, /ssl_min_protocol_version = 'TLSv1.2'/);
  assert.match(pg, /log_parameter_max_length_on_error = 0/);
  assert.doesNotMatch(pg + hba, /0\.0\.0\.0.*trust|include|\$\{|https?:/);
});

test('close is denial-only, idempotent and preserves generated files', async t => {
  const { owner, config } = await material(t);
  owner.close(); owner.close();
  assert.throws(() => owner.configuration(), generic);
  assert.throws(() => owner.verify(), generic);
  assert.equal(readdirSync(config.directory).length, 8);
  assert.deepEqual(owner.summary(), {
    classification: 'FRESH_POSTGRES_MATERIAL_ONLY', files: 8, closed: true, filesPreserved: true,
    databaseStarted: false, schemaApplied: false, containerOwnershipVerified: false, activationGranted: false,
  });
  assert.ok(Object.isFrozen(owner.summary()));
});

test('summary has no private paths, names, certificate, or password and makes no runtime claim', async t => {
  const { owner, config } = await material(t);
  const output = JSON.stringify(owner.summary());
  for (const key of ['namespaceId', 'database', 'user', 'password', 'directory', 'certificatePem', 'certificateSha256']) {
    assert.equal(output.includes(config[key]), false);
  }
  assert.equal(owner.summary().databaseStarted, false);
});

test('methods reject extra arguments without triggering accessor input', async t => {
  const { owner } = await material(t);
  const argument = new Proxy({}, { get() { throw Error('not touched'); } });
  for (const method of ['configuration', 'verify', 'close', 'summary']) assert.throws(() => owner[method](argument), generic);
  assert.equal(owner.summary().closed, false);
});

const drifts = {
  'content changes': config => writeFileSync(join(config.directory, 'password'), 'b'.repeat(64) + '\n'),
  'file mode changes': config => chmodSync(join(config.directory, 'password'), 0o644),
  'directory mode changes': config => chmodSync(config.directory, 0o755),
  'same bytes on a new inode': config => {
    const path = join(config.directory, 'password'), bytes = readFileSync(path);
    renameSync(path, join(config.directory, 'old-password')); writeFileSync(path, bytes, { flag: 'wx', mode: 0o600 });
  },
  'symlink replacement': config => {
    const path = join(config.directory, 'password'); renameSync(path, join(config.directory, 'old-password'));
    symlinkSync('old-password', path);
  },
  'extra directory entry': config => writeFileSync(join(config.directory, 'unexpected'), 'x', { flag: 'wx', mode: 0o600 }),
  'hardlink added': config => linkSync(join(config.directory, 'password'), join(config.directory, 'linked-password')),
  'oversized file': config => writeFileSync(join(config.directory, 'password'), Buffer.alloc(8193)),
  'missing file': config => rmSync(join(config.directory, 'password')),
};
for (const [name, alter] of Object.entries(drifts)) test(`integrity rejects ${name} without private error output`, async t => {
  const { owner, config } = await material(t); alter(config);
  assert.throws(() => owner.verify(), generic);
  assert.throws(() => owner.configuration(), generic);
  owner.close(); assert.equal(owner.summary().filesPreserved, true);
});

test('entrypoint is syntactically valid POSIX shell, not executed', () => {
  const result = spawnSync('/bin/sh', ['-n', join(here, 'bootstrap-postgres-entrypoint.sh')], {
    env: { PATH: '/usr/bin:/bin', LC_ALL: 'C' }, encoding: 'utf8', timeout: 2000,
  });
  assert.equal(result.status, 0); assert.equal(result.stdout, ''); assert.equal(result.stderr, '');
});

test('entrypoint pins exactly the actual twenty public migrations in lexical order', () => {
  const lines = script.split("done <<'HASHES'\n")[1].split('\nHASHES')[0].split('\n');
  assert.equal(lines.length, 20);
  const sourceDir = join(here, '../../../server/postgres/migrations');
  const names = lines.map((line, index) => {
    const match = /^([a-f0-9]{64}) (\d{6}_[a-z0-9_]+\.sql)$/.exec(line);
    assert.ok(match, `invalid pin ${index}`);
    assert.equal(sha(readFileSync(join(sourceDir, match[2]))), match[1], `pin mismatch ${index}`);
    return match[2];
  });
  assert.deepEqual(names, [...names].sort());
  assert.deepEqual(names, readdirSync(sourceDir).filter(name => /^\d{6}.*\.sql$/.test(name)).sort());
});

test('entrypoint records no-retry initialization before initdb and readiness only after stopped schema initialization', () => {
  const attempted = script.indexOf('mkdir -m 700 "$root/.fncp-initialization-attempted"');
  const init = script.indexOf('timeout 30 /usr/local/bin/initdb');
  const role = script.indexOf('CREATE ROLE');
  const migration = script.indexOf('for file in "$migrations"/*.sql');
  const stop = script.lastIndexOf('/usr/local/bin/pg_ctl');
  const ready = script.indexOf("'PUBLIC_MIGRATIONS_APPLIED_20'");
  const final = script.indexOf('exec env -i PATH="$PATH" LC_ALL=C /usr/local/bin/postgres');
  assert.ok(attempted > 0 && attempted < init && init < role && role < migration && migration < stop && stop < ready && ready < final);
  assert.match(script, /\[ ! -e "\$data" \] && \[ ! -L "\$data" \]/);
  assert.match(script, /set -C; printf/);
  assert.doesNotMatch(script, /\brm\b|su-exec|chown|docker|curl|wget/);
});

test('entrypoint makes app role nonsuperuser, ignores ambient libpq config and uses fixed private stdin password', () => {
  assert.match(script, /--username=postgres --auth-local=peer --auth-host=reject/);
  assert.match(script, /LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS/);
  assert.match(script, /PASSWORD '\$password';/);
  assert.match(script, /unset password/);
  assert.match(script, /env -i .*psql --no-psqlrc --no-password --set=ON_ERROR_STOP=on/g);
  assert.doesNotMatch(script, /PGPASSWORD|--password=|\beval\b|\bsource\b(?! a material)/);
  assert.match(script, /\[ "\$\(id -u\)" = 70 \] && \[ "\$\(id -g\)" = 70 \]/);
});
