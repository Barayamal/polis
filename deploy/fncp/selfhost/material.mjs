import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { createPrivateKey, createPublicKey, timingSafeEqual, X509Certificate } from 'node:crypto';
import { sha256, validateConfiguration } from './configuration.mjs';

const failure = () => new Error('FNCP_SELFHOST_MATERIAL_REJECTED');
const MAX_BYTES = 65_536;
const FILES = Object.freeze([
  ['api.env', 0o600], ['database-ca.pem', 0o644], ['database-math-password', 0o644],
  ['database-migration-password', 0o644], ['database-owner-password', 0o644],
  ['database-runtime-password', 0o644], ['database-server.key', 0o644], ['database-server.pem', 0o644],
  ['jwt-private.pem', 0o644], ['jwt-public.pem', 0o644], ['math.env', 0o600], ['migration.env', 0o600],
]);

function exact(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw failure();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const names = Reflect.ownKeys(descriptors);
  if (names.length !== keys.length || keys.some(key => !names.includes(key))
    || names.some(key => !Object.hasOwn(descriptors[key], 'value'))) throw failure();
}

async function directory(path) {
  const stat = await lstat(path, { bigint: true });
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== BigInt(process.getuid())
    || (stat.mode & 0o7777n) !== 0o700n || await realpath(path) !== resolve(path)) throw failure();
  return stat;
}

function unchanged(first, second) {
  return ['ino', 'dev', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs'].every(key => first[key] === second[key]);
}

async function readInput(path, mode) {
  let file;
  try {
    file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await file.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.uid !== BigInt(process.getuid())
      || (before.mode & 0o7777n) !== BigInt(mode) || before.size < 1n || before.size > BigInt(MAX_BYTES)
      || await realpath(path) !== path) throw failure();
    const bytes = Buffer.alloc(MAX_BYTES + 1); let length = 0;
    while (length < bytes.length) {
      const { bytesRead } = await file.read(bytes, length, bytes.length - length, length);
      if (bytesRead === 0) break;
      length += bytesRead;
    }
    if (length !== Number(before.size) || length > MAX_BYTES
      || !unchanged(before, await file.stat({ bigint: true }))
      || !unchanged(before, await lstat(path, { bigint: true }))
      || await realpath(path) !== path) throw failure();
    return { bytes: Buffer.from(bytes.subarray(0, length)), stat: before };
  } finally { await file?.close(); }
}

function environment(bytes, keys) {
  const value = bytes.toString('utf8');
  if (!Buffer.from(value).equals(bytes) || !value.endsWith('\n') || value.endsWith('\n\n')) throw failure();
  const result = Object.create(null);
  for (const line of value.slice(0, -1).split('\n')) {
    const found = /^([A-Z][A-Z0-9_]*)=([^\u0000-\u0020\u007f$"'\\]+)$/u.exec(line);
    if (!found || Object.hasOwn(result, found[1])) throw failure();
    result[found[1]] = found[2];
  }
  exact(result, keys);
  return result;
}

function secret(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(value)
    || Buffer.from(value, 'base64url').byteLength !== 32 || Buffer.from(value, 'base64url').toString('base64url') !== value) throw failure();
  return value;
}

function expect(actual, required) {
  for (const [key, value] of Object.entries(required)) if (actual[key] !== String(value)) throw failure();
}

function certificate(bytes) {
  const pem = bytes.toString('utf8');
  if (!/^-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\r?\n?$/u.test(pem)) throw failure();
  const cert = new X509Certificate(pem);
  const now = Date.now();
  if (!Number.isSafeInteger(now) || !Number.isFinite(Date.parse(cert.validFrom))
    || !Number.isFinite(Date.parse(cert.validTo)) || Date.parse(cert.validFrom) > now || Date.parse(cert.validTo) <= now) throw failure();
  return cert;
}

function publicDer(key) { return key.export({ type: 'spki', format: 'der' }); }
function pemKey(bytes, kind) {
  const value = bytes.toString('utf8');
  const pattern = new RegExp(`^-----BEGIN ${kind} KEY-----\\r?\\n[A-Za-z0-9+/=\\r\\n]+-----END ${kind} KEY-----\\r?\\n?$`, 'u');
  if (!pattern.test(value)) throw failure();
  return kind === 'PRIVATE' ? createPrivateKey(bytes) : createPublicKey(bytes);
}
function equalKey(first, second) {
  const a = publicDer(first); const b = publicDer(second);
  return a.length === b.length && timingSafeEqual(a, b);
}

function validateContents(c, content) {
  const passwords = Object.fromEntries(['owner', 'migration', 'runtime', 'math'].map(role => [role,
    secret(content.get(`database-${role}-password`).toString('utf8'))]));
  const apiFixed = {
    NODE_ENV: 'production', FNCP_OPTION_C_RELEASE_MODE: 'production',
    FNCP_GATEWAY_ENFORCEMENT: 'true', FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT: 'true',
    FNCP_GATEWAY_CONVERSATION_ID: c.binding.conversationId,
    FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID: c.binding.conversationId,
    FNCP_FIXED_STATEMENT_IDS: c.binding.statementIds.join(','),
    DATABASE_URL: `postgres://${c.database.runtimeRole}:${passwords.runtime}@postgres:5432/${c.database.name}`,
    DATABASE_SSL: 'true', DATABASE_SSL_CA_FILE: '/run/fncp/database-ca.pem',
    AUTH_ISSUER: c.identity.issuer, AUTH_AUDIENCE: c.identity.audience, JWKS_URI: c.identity.jwksUri,
    JWT_PRIVATE_KEY_PATH: '/run/fncp/jwt-private.pem', JWT_PUBLIC_KEY_PATH: '/run/fncp/jwt-public.pem',
    API_SERVER_PORT: '5000', API_PROD_HOSTNAME: 'polis.local.invalid', DOMAIN_OVERRIDE: 'polis.local.invalid',
    MATH_ENV: 'dev', DEV_MODE: 'false', TESTING: 'false', ENABLE_TELEMETRY: 'false',
    SHOULD_USE_TRANSLATION_API: 'false', BACKFILL_COMMENT_LANG_DETECTION: 'false',
    RUN_PERIODIC_EXPORT_TESTS: 'false', SERVER_LOG_TO_FILE: 'false', EMAIL_TRANSPORT_TYPES: 'disabled',
    ADMIN_EMAILS: '[]', ADMIN_UIDS: '[]',
  };
  const apiSecrets = ['FNCP_GATEWAY_SHARED_SECRET', 'FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL', 'LOGIN_CODE_PEPPER', 'ENCRYPTION_PASSWORD_00001'];
  const api = environment(content.get('api.env'), [...Object.keys(apiFixed), ...apiSecrets]);
  expect(api, apiFixed);
  const mathFixed = {
    FNCP_OPTION_C_RELEASE_MODE: 'production',
    DATABASE_URL: `postgres://${c.database.mathRole}:${passwords.math}@postgres:5432/${c.database.name}`,
    DATABASE_SSL: 'true', DATABASE_SSL_CA_FILE: '/run/fncp/database-ca.pem', MATH_ENV: 'dev',
    LOGGING_LEVEL: 'warn', WEBSERVER_USERNAME: 'local_unexposed', DATABASE_POOL_SIZE: '4',
  };
  const math = environment(content.get('math.env'), [...Object.keys(mathFixed), 'WEBSERVER_PASS']);
  expect(math, mathFixed);
  const migrationFixed = {
    FNCP_DATABASE_HOST: 'postgres', FNCP_DATABASE_PORT: '5432', FNCP_DATABASE_PASSWORD: passwords.migration,
    FNCP_EXPECTED_DATABASE: c.database.name, FNCP_EXPECTED_MIGRATION_ROLE: c.database.migrationRole,
    FNCP_RUNTIME_DB_ROLE: c.database.runtimeRole, PGSSLMODE: 'verify-full', PGSSLROOTCERT: '/run/fncp/database-ca.pem',
  };
  const migration = environment(content.get('migration.env'), Object.keys(migrationFixed));
  expect(migration, migrationFixed);
  const allSecrets = [...Object.values(passwords), ...apiSecrets.map(key => secret(api[key])), secret(math.WEBSERVER_PASS)];
  if (new Set(allSecrets).size !== allSecrets.length) throw failure();

  const ca = certificate(content.get('database-ca.pem'));
  const server = certificate(content.get('database-server.pem'));
  if (!ca.ca || !ca.checkIssued(ca) || !ca.verify(ca.publicKey) || server.ca
    || !server.checkIssued(ca) || !server.verify(ca.publicKey) || server.checkHost(c.database.host) !== c.database.host
    || !server.keyUsage?.includes('1.3.6.1.5.5.7.3.1')) throw failure();
  const serverPrivate = pemKey(content.get('database-server.key'), 'PRIVATE');
  const jwtPrivate = pemKey(content.get('jwt-private.pem'), 'PRIVATE');
  const jwtPublic = pemKey(content.get('jwt-public.pem'), 'PUBLIC');
  if (serverPrivate.asymmetricKeyType !== 'rsa' || (serverPrivate.asymmetricKeyDetails?.modulusLength ?? 0) < 2048
    || jwtPrivate.asymmetricKeyType !== 'rsa' || jwtPublic.asymmetricKeyType !== 'rsa'
    || (jwtPrivate.asymmetricKeyDetails?.modulusLength ?? 0) < 2048
    || !equalKey(createPublicKey(serverPrivate), server.publicKey)
    || !equalKey(createPublicKey(jwtPrivate), jwtPublic)
    || equalKey(server.publicKey, jwtPublic) || equalKey(ca.publicKey, server.publicKey)) throw failure();
}

/** Private manifest only. This function performs bounded filesystem reads and
 * cryptographic validation; it creates no file, network connection or process.
 * Known generated CA/CSR helper artifacts are not runtime inputs and are not
 * included. Never log the input bytes or parsed environment values.
 */
export async function snapshotMaterial(configuration) {
  try {
    const c = validateConfiguration(configuration);
    const stateBefore = await directory(c.stateDirectory);
    const materialPath = join(c.stateDirectory, 'material');
    const materialBefore = await directory(materialPath);
    const content = new Map(); const files = []; const stats = new Map();
    for (const [name, mode] of FILES) {
      const { bytes, stat } = await readInput(join(materialPath, name), mode);
      content.set(name, bytes);
      stats.set(name, stat);
      files.push({ name, mode, size: bytes.length, sha256: sha256(bytes) });
    }
    validateContents(c, content);
    // Catch an earlier input changed while a later input was being validated.
    // The controller must still exclude concurrent material edits through its
    // operation lock; a filesystem snapshot is not a lock on future writers.
    for (const [name] of FILES) {
      const path = join(materialPath, name);
      if (!unchanged(stats.get(name), await lstat(path, { bigint: true })) || await realpath(path) !== path) throw failure();
    }
    // Directory replacement/rename during validation is not a stable snapshot.
    const stateAfter = await directory(c.stateDirectory);
    const materialAfter = await directory(materialPath);
    if (!unchanged(stateBefore, stateAfter) || !unchanged(materialBefore, materialAfter)) throw failure();
    return Object.freeze({ version: 1, configurationSha256: sha256(JSON.stringify(c)),
      files: Object.freeze(files.map(file => Object.freeze(file))) });
  } catch { throw failure(); }
}

export async function assertMaterial(c, manifest) {
  try {
    exact(manifest, ['version', 'configurationSha256', 'files']);
    if (manifest.version !== 1 || typeof manifest.configurationSha256 !== 'string'
      || !/^[0-9a-f]{64}$/u.test(manifest.configurationSha256)
      || !Array.isArray(manifest.files) || manifest.files.length !== FILES.length) throw failure();
    const expected = manifest.files.map((record, index) => {
      exact(record, ['name', 'mode', 'size', 'sha256']);
      if (record.name !== FILES[index][0] || record.mode !== FILES[index][1]
        || !Number.isSafeInteger(record.size) || record.size < 1 || record.size > MAX_BYTES
        || typeof record.sha256 !== 'string' || !/^[0-9a-f]{64}$/u.test(record.sha256)) throw failure();
      return { name: record.name, mode: record.mode, size: record.size, sha256: record.sha256 };
    });
    const actual = await snapshotMaterial(c);
    if (actual.configurationSha256 !== manifest.configurationSha256
      || JSON.stringify(actual.files) !== JSON.stringify(expected)) throw failure();
    return Object.freeze({ materialVerified: true, filesVerified: FILES.length,
      configurationMatched: true, criticalEnvironmentVerified: true });
  } catch { throw failure(); }
}
