/** Fresh disposable PostgreSQL material only; no database/Docker/network calls.
 * Import has no I/O. configuration() is a PRIVATE handoff, not safe evidence.
 * Integrity checks detect drift; they do not attest a container or resist a
 * same-UID ancestor-path race. close() denies future use and PRESERVES files.
 */
import { spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, randomBytes, X509Certificate } from 'node:crypto';
import { chmodSync, constants, closeSync, fstatSync, lstatSync, mkdtempSync, openSync,
  readdirSync, readSync, realpathSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const failure = () => new Error('Fresh PostgreSQL material rejected; private details withheld.');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const NAMES = Object.freeze(['namespace', 'database', 'user', 'password', 'postgres-cert.pem',
  'postgres-key.pem', 'postgresql.conf', 'pg_hba.conf']);
const MATERIAL = '/run/fncp/postgres-material';
const CONFIG = `listen_addresses = '127.0.0.1'
port = 5432
ssl = on
ssl_min_protocol_version = 'TLSv1.2'
ssl_cert_file = '/run/fncp/postgres-material/postgres-cert.pem'
ssl_key_file = '/run/fncp/postgres-material/postgres-key.pem'
hba_file = '/run/fncp/postgres-material/pg_hba.conf'
unix_socket_directories = '/var/lib/postgresql/data/socket'
unix_socket_permissions = 0700
password_encryption = 'scram-sha-256'
max_connections = 32
shared_buffers = '16MB'
shared_preload_libraries = ''
search_path = 'public'
archive_mode = off
archive_command = ''
ssl_passphrase_command = ''
logging_collector = off
log_destination = 'stderr'
log_statement = 'none'
log_min_error_statement = 'panic'
log_min_messages = 'panic'
log_connections = off
log_disconnections = off
log_duration = off
log_parameter_max_length = 0
log_parameter_max_length_on_error = 0
track_activities = off
`;
const hba = (database, user) => `local all postgres peer
local ${database} ${user} trust
local all all reject
hostssl ${database} ${user} 127.0.0.1/32 scram-sha-256
host all all 0.0.0.0/0 reject
host all all ::0/0 reject
`;
const stamp = stat => ({ dev: stat.dev, ino: stat.ino, uid: stat.uid, gid: stat.gid,
  mode: stat.mode, size: stat.size, nlink: stat.nlink, mtimeMs: stat.mtimeMs, ctimeMs: stat.ctimeMs });
const same = (a, b) => Object.keys(a).every(key => a[key] === b[key]);
function privateFile(path, expected) {
  let fd;
  try {
    const before = lstatSync(path);
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 ||
        (before.mode & 0o777) !== 0o600 || before.uid !== process.getuid() ||
        before.size < 1 || before.size > 8192 || (expected && !same(stamp(before), expected.stat))) throw failure();
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    if (!same(stamp(fstatSync(fd)), stamp(before))) throw failure();
    const buffer = Buffer.alloc(8193); let length = 0;
    while (length < buffer.length) { const read = readSync(fd, buffer, length, buffer.length - length, length); if (!read) break; length += read; }
    if (length !== before.size || !same(stamp(fstatSync(fd)), stamp(before)) ||
        !same(stamp(lstatSync(path)), stamp(before))) throw failure();
    const bytes = buffer.subarray(0, length); const hash = sha(bytes);
    if (expected && hash !== expected.sha256) throw failure();
    return { stat: stamp(before), sha256: hash, bytes };
  } finally { if (fd !== undefined) closeSync(fd); }
}

export async function createBootstrapPostgresMaterial() {
  if (arguments.length) throw failure();
  let directory;
  try {
    if (typeof process.getuid !== 'function') throw failure();
    const executable = process.platform === 'darwin' ? '/opt/homebrew/bin/openssl' :
      process.platform === 'linux' ? '/usr/bin/openssl' : undefined;
    if (!executable) throw failure();
    directory = mkdtempSync(join(realpathSync(tmpdir()), 'fncp-fresh-postgres-material-'));
    chmodSync(directory, 0o700);
    const identities = new Set();
    const identity = () => { let result; do { result = randomBytes(12).toString('hex'); } while (identities.has(result)); identities.add(result); return result; };
    const namespaceId = identity(), user = `fncp_fresh_${identity()}`, database = `fncp_fresh_${identity()}`;
    const password = randomBytes(32).toString('hex'), databaseHost = `fncp-fresh-pg-${namespaceId}`;
    const write = (name, value) => writeFileSync(join(directory, name), value, { flag: 'wx', mode: 0o600 });
    const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    write('postgres-key.pem', pair.privateKey.export({ type: 'pkcs8', format: 'pem' }));
    const generated = spawnSync(executable, ['req', '-new', '-x509', '-key', join(directory, 'postgres-key.pem'),
      '-days', '1', '-subj', `/CN=${databaseHost}`, '-addext', `subjectAltName=DNS:${databaseHost},IP:127.0.0.1`], {
      cwd: directory, shell: false, stdio: ['ignore', 'pipe', 'pipe'], timeout: 10000, maxBuffer: 8192,
      env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C', OPENSSL_CONF: '/dev/null' },
    });
    if (generated.error || generated.status !== 0 || !generated.stdout?.length || generated.stdout.length > 8192) throw failure();
    const certificatePem = generated.stdout.toString('utf8'), cert = new X509Certificate(certificatePem);
    if (!cert.verify(pair.publicKey) || cert.checkHost(databaseHost, { subject: 'never', wildcards: false }) !== databaseHost ||
        cert.checkIP('127.0.0.1') !== '127.0.0.1' ||
        !cert.publicKey.export({ type: 'spki', format: 'der' }).equals(pair.publicKey.export({ type: 'spki', format: 'der' }))) throw failure();
    const certificateSha256 = sha(cert.raw);
    write('postgres-cert.pem', certificatePem); write('namespace', namespaceId + '\n');
    write('database', database + '\n'); write('user', user + '\n'); write('password', password + '\n');
    write('postgresql.conf', CONFIG); write('pg_hba.conf', hba(database, user));
    const directoryStat = stamp(lstatSync(directory));
    const entries = Object.fromEntries(NAMES.map(name => [name, privateFile(join(directory, name))]));
    let closed = false;
    const verify = () => {
      if (closed) throw failure();
      const current = lstatSync(directory);
      if (!current.isDirectory() || current.isSymbolicLink() || (current.mode & 0o777) !== 0o700 ||
          current.uid !== process.getuid() || !same(stamp(current), directoryStat) ||
          readdirSync(directory).sort().join('\n') !== [...NAMES].sort().join('\n')) throw failure();
      for (const name of NAMES) privateFile(join(directory, name), entries[name]);
    };
    const files = Object.freeze(NAMES.map(name => Object.freeze({ name, path: join(directory, name),
      destination: `${MATERIAL}/${name}`, bytes: entries[name].stat.size, sha256: entries[name].sha256,
      archiveUid: 70, archiveGid: 70, archiveMode: 0o600 })));
    return Object.freeze({
      configuration() {
        if (arguments.length) throw failure();
        try { verify(); return Object.freeze({ namespaceId, databaseHost, database, user, password,
          certificatePem, certificateSha256, directory, files }); } catch { throw failure(); }
      },
      verify() { if (arguments.length) throw failure(); try { verify(); } catch { throw failure(); } },
      close() { if (arguments.length) throw failure(); closed = true; },
      summary() {
        if (arguments.length) throw failure();
        return Object.freeze({ classification: 'FRESH_POSTGRES_MATERIAL_ONLY', files: 8, closed, filesPreserved: true,
          databaseStarted: false, schemaApplied: false, containerOwnershipVerified: false, activationGranted: false });
      },
    });
  } catch { throw failure(); }
}
