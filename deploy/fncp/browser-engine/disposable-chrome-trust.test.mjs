import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import { chmodSync, existsSync, linkSync, lstatSync, mkdirSync, mkdtempSync,
  readFileSync, readdirSync, renameSync, rmdirSync, symlinkSync, unlinkSync,
  writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { createDisposableChromeTrust } from './disposable-chrome-trust.mjs';

const HOSTS = ['browser.example.invalid', 'identity.issuer.invalid'];
const REJECTED = /Disposable synthetic Chrome trust profile rejected/u;

function certificate(host, { days = '1', san = `DNS:${host}`, subject = `/CN=${host}` } = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'fncp-chrome-cert-unit-'));
  chmodSync(directory, 0o700);
  const keyPath = join(directory, 'key.pem');
  const certPath = join(directory, 'cert.pem');
  try {
    const result = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt',
      'ec_paramgen_curve:prime256v1', '-noenc', '-days', days, '-subj', subject,
      '-addext', `subjectAltName=${san}`, '-keyout', keyPath, '-out', certPath],
    { stdio: ['ignore', 'pipe', 'pipe'], timeout: 10_000, maxBuffer: 8192 });
    assert.equal(result.status, 0, 'fresh synthetic test certificate creation');
    return readFileSync(certPath);
  } finally {
    for (const path of [keyPath, certPath]) {
      try { unlinkSync(path); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
    rmdirSync(directory);
  }
}

const CERTIFICATES = HOSTS.map((host) => certificate(host));
const options = (certificates = CERTIFICATES) => ({ mode: 'SYNTHETIC_ONLY', certificates });
const create = () => createDisposableChromeTrust(options());
const dbPath = (profile) => join(profile.profilePath, 'Default', 'ServerCertificate');
const cleanup = (profile) => profile.cleanup({ browserClosed: true });

test('new profile API is frozen and exposes no certificate/key/database control', () => {
  const profile = create();
  try {
    assert.deepEqual(Object.keys(profile).sort(), ['cleanup', 'profilePath', 'summary']);
    assert.ok(Object.isFrozen(profile));
    assert.match(profile.profilePath, /\/fncp-chrome-trust-[^/]+$/u);
    const summary = profile.summary();
    assert.ok(Object.isFrozen(summary)); assert.ok(Object.isFrozen(summary.trustedHosts));
    assert.deepEqual(summary.trustedHosts, HOSTS);
    assert.equal(summary.internalSchemaQaBootstrap, true);
    for (const key of ['existingProfileUsed', 'globalTrustChanged', 'certificateValidationDisabled',
      'browserLaunched', 'nativeTlsVerified', 'officialProvisioningApi', 'cleaned']) {
      assert.equal(summary[key], false);
    }
  } finally { cleanup(profile); }
});

test('profile, Default and database use private permissions', () => {
  const profile = create();
  try {
    assert.equal(lstatSync(profile.profilePath).mode & 0o777, 0o700);
    assert.equal(lstatSync(join(profile.profilePath, 'Default')).mode & 0o777, 0o700);
    assert.equal(lstatSync(dbPath(profile)).mode & 0o777, 0o600);
    assert.deepEqual(readdirSync(profile.profilePath), ['Default']);
    assert.deepEqual(readdirSync(join(profile.profilePath, 'Default')), ['ServerCertificate']);
  } finally { cleanup(profile); }
});

test('SQLite schema, meta versions, public DER/hash and trusted protobuf match pinned Chromium149', () => {
  const profile = create();
  const db = new DatabaseSync(dbPath(profile), { readOnly: true });
  try {
    assert.deepEqual(db.prepare('PRAGMA table_info(certificates)').all().map((row) => [row.name, row.type]),
      [['sha256hash_hex', 'TEXT'], ['der_cert', 'BLOB'], ['trust_settings', 'BLOB']]);
    assert.deepEqual(db.prepare('SELECT key,value FROM meta ORDER BY key').all().map((row) => [row.key, row.value]),
      [['last_compatible_version', '1'], ['version', '1']]);
    const rows = db.prepare('SELECT * FROM certificates').all();
    assert.equal(rows.length, 2);
    const expected = new Map(CERTIFICATES.map((pem) => {
      const cert = new X509Certificate(pem);
      return [createHash('sha256').update(cert.raw).digest('hex'), cert.raw];
    }));
    for (const row of rows) {
      assert.deepEqual(Buffer.from(row.der_cert), expected.get(row.sha256hash_hex));
      assert.equal(Buffer.from(row.trust_settings).toString('hex'), '0a020803');
      assert.ok(new X509Certificate(row.der_cert).verify(new X509Certificate(row.der_cert).publicKey));
    }
    assert.equal(db.prepare('PRAGMA integrity_check').get().integrity_check, 'ok');
  } finally { db.close(); cleanup(profile); }
});

test('separate invocations cannot share existing profile state', () => {
  const first = create(); const second = create();
  try {
    assert.notEqual(first.profilePath, second.profilePath);
    assert.notEqual(lstatSync(dbPath(first)).ino, lstatSync(dbPath(second)).ino);
    cleanup(first);
    assert.equal(existsSync(first.profilePath), false);
    assert.equal(existsSync(dbPath(second)), true);
  } finally { cleanup(first); cleanup(second); }
});

test('input buffers and arrays are not retained after creation', () => {
  const copies = CERTIFICATES.map((pem) => Buffer.from(pem));
  const profile = createDisposableChromeTrust(options(copies));
  const expected = CERTIFICATES.map((pem) => new X509Certificate(pem).fingerprint256).sort();
  copies[0].fill(0); copies[1].fill(0); copies.length = 0;
  const db = new DatabaseSync(dbPath(profile), { readOnly: true });
  try {
    assert.deepEqual(db.prepare('SELECT der_cert FROM certificates').all()
      .map((row) => new X509Certificate(row.der_cert).fingerprint256).sort(), expected);
  } finally { db.close(); cleanup(profile); }
});

for (const [label, invalid] of [
  ['missing options', undefined], ['null options', null], ['wrong mode', { ...options(), mode: 'PRODUCTION' }],
  ['caller profile path', { ...options(), profilePath: '/not-allowed' }],
  ['caller trust metadata', { ...options(), trust: 3 }],
  ['empty certificates', options([])], ['one certificate', options([CERTIFICATES[0]])],
  ['three certificates', options([...CERTIFICATES, CERTIFICATES[0]])],
  ['duplicate certificate', options([CERTIFICATES[0], CERTIFICATES[0]])],
  ['string PEM', options([CERTIFICATES[0].toString(), CERTIFICATES[1]])],
  ['DER input', options([new X509Certificate(CERTIFICATES[0]).raw, CERTIFICATES[1]])],
  ['oversized PEM', options([Buffer.alloc(8193), CERTIFICATES[1]])],
  ['malformed PEM', options([Buffer.from('-----BEGIN CERTIFICATE-----\n' + 'a'.repeat(250) + '\n-----END CERTIFICATE-----\n'), CERTIFICATES[1]])],
  ['PEM bundle', options([Buffer.concat([CERTIFICATES[0], CERTIFICATES[1]]), CERTIFICATES[1]])],
  ['private key material', options([Buffer.from('-----BEGIN PRIVATE KEY-----\n' + 'a'.repeat(250) + '\n-----END PRIVATE KEY-----\n'), CERTIFICATES[1]])],
  ['PEM with appended private key', options([Buffer.concat([CERTIFICATES[0], Buffer.from('-----BEGIN PRIVATE KEY-----\n')]), CERTIFICATES[1]])],
  ['shared memory input', options([Buffer.from(new SharedArrayBuffer(512)), CERTIFICATES[1]])],
]) {
  test(`rejects ${label} before creating a profile`, () => {
    assert.throws(() => createDisposableChromeTrust(invalid), REJECTED);
  });
}

test('rejects extra positional arguments and accessor option properties', () => {
  assert.throws(() => createDisposableChromeTrust(options(), {}), REJECTED);
  let calls = 0;
  const input = { mode: 'SYNTHETIC_ONLY', get certificates() { calls += 1; return CERTIFICATES; } };
  assert.throws(() => createDisposableChromeTrust(input), REJECTED);
  assert.equal(calls, 0);
});

test('rejects array accessors, sparse input and overridden array iteration before invocation', () => {
  let calls = 0;
  const getterArray = [CERTIFICATES[0], CERTIFICATES[1]];
  Object.defineProperty(getterArray, '0', { get() { calls += 1; return CERTIFICATES[0]; } });
  const mapArray = [CERTIFICATES[0], CERTIFICATES[1]];
  mapArray.map = () => { calls += 1; return []; };
  const sparse = [CERTIFICATES[0], CERTIFICATES[1]]; delete sparse[0];
  for (const input of [getterArray, mapArray, sparse]) {
    assert.throws(() => createDisposableChromeTrust(options(input)), REJECTED);
  }
  assert.equal(calls, 0);
});

test('rejects a parseable certificate whose self-signature was changed', () => {
  const der = Buffer.from(new X509Certificate(CERTIFICATES[0]).raw);
  der[der.length - 1] ^= 1;
  const pem = Buffer.from(`-----BEGIN CERTIFICATE-----\n${der.toString('base64')}\n-----END CERTIFICATE-----\n`);
  assert.doesNotThrow(() => new X509Certificate(pem));
  assert.throws(() => createDisposableChromeTrust(options([pem, CERTIFICATES[1]])), REJECTED);
});

test('rejects not-yet-valid and expired public certificates at current execution time', () => {
  const certificate = new X509Certificate(CERTIFICATES[0]);
  const actualNow = Date.now;
  try {
    for (const now of [Date.parse(certificate.validFrom) - 1000, Date.parse(certificate.validTo) + 1000]) {
      Date.now = () => now;
      assert.throws(() => createDisposableChromeTrust(options()), REJECTED);
    }
  } finally { Date.now = actualNow; }
});

for (const [label, cert] of [
  ['real hostname', certificate('example.com')],
  ['extra DNS SAN', certificate(HOSTS[0], { san: `DNS:${HOSTS[0]},DNS:example.com` })],
  ['wildcard SAN', certificate(HOSTS[0], { san: 'DNS:*.example.invalid' })],
  ['IP SAN', certificate(HOSTS[0], { san: 'IP:127.0.0.1' })],
  ['mismatched subject', certificate(HOSTS[0], { subject: '/CN=not-browser.example.invalid' })],
  ['two-day validity', certificate(HOSTS[0], { days: '2' })],
]) {
  test(`rejects certificate with ${label}`, () => {
    assert.throws(() => createDisposableChromeTrust(options([cert, CERTIFICATES[1]])), REJECTED);
  });
}

test('cleanup requires an exact affirmative browser-closed attestation', () => {
  const profile = create();
  try {
    for (const argument of [undefined, null, {}, { browserClosed: false }, { browserClosed: 'true' },
      { browserClosed: true, path: profile.profilePath }]) {
      assert.throws(() => profile.cleanup(argument), REJECTED);
      assert.equal(existsSync(dbPath(profile)), true);
    }
    assert.throws(() => profile.cleanup(), REJECTED);
    assert.throws(() => profile.cleanup({ browserClosed: true }, {}), REJECTED);
  } finally { cleanup(profile); }
});

test('cleanup removes solely fresh profile contents and is idempotent', () => {
  const profile = create();
  const nested = join(profile.profilePath, 'Default', 'Cache');
  mkdirSync(nested); writeFileSync(join(nested, 'synthetic-only'), 'test');
  const before = profile.summary();
  assert.equal(cleanup(profile).cleaned, true);
  assert.equal(existsSync(profile.profilePath), false);
  assert.equal(cleanup(profile).cleaned, true);
  assert.equal(before.cleaned, false);
  assert.equal(profile.summary().cleaned, true);
});

for (const lock of ['SingletonLock', 'SingletonCookie', 'SingletonSocket']) {
  test(`cleanup refuses residual ${lock} before deleting anything`, () => {
    const profile = create(); const lockPath = join(profile.profilePath, lock);
    try {
      writeFileSync(lockPath, 'synthetic lock marker');
      assert.throws(() => cleanup(profile), REJECTED);
      assert.equal(existsSync(dbPath(profile)), true);
      assert.equal(profile.summary().cleaned, false);
      unlinkSync(lockPath);
    } finally { cleanup(profile); }
  });
}

test('cleanup refuses a symlink without reading or removing its target', () => {
  const profile = create(); const other = create();
  const path = join(profile.profilePath, 'external-link');
  try {
    symlinkSync(other.profilePath, path);
    assert.throws(() => cleanup(profile), REJECTED);
    assert.equal(existsSync(dbPath(profile)), true); assert.equal(existsSync(dbPath(other)), true);
    unlinkSync(path);
  } finally { cleanup(profile); cleanup(other); }
});

test('cleanup refuses hard-linked files before deleting any tree entry', () => {
  const profile = create(); const other = create(); const path = join(profile.profilePath, 'hard-link');
  try {
    linkSync(dbPath(other), path);
    assert.throws(() => cleanup(profile), REJECTED);
    assert.equal(existsSync(dbPath(profile)), true); assert.equal(existsSync(dbPath(other)), true);
    unlinkSync(path);
  } finally { cleanup(profile); cleanup(other); }
});

test('cleanup rejects database inode replacement and permits restoration', () => {
  const profile = create(); const original = dbPath(profile); const saved = `${original}.saved`;
  try {
    renameSync(original, saved); writeFileSync(original, 'replacement');
    assert.throws(() => cleanup(profile), REJECTED);
    assert.equal(readFileSync(original, 'utf8'), 'replacement');
    unlinkSync(original); renameSync(saved, original);
  } finally { cleanup(profile); }
});

test('cleanup rejects Default directory inode replacement', () => {
  const profile = create(); const original = join(profile.profilePath, 'Default'); const saved = `${original}.saved`;
  try {
    renameSync(original, saved); mkdirSync(original);
    assert.throws(() => cleanup(profile), REJECTED);
    assert.equal(existsSync(join(saved, 'ServerCertificate')), true);
    rmdirSync(original); renameSync(saved, original);
  } finally { cleanup(profile); }
});

test('cleanup rejects root inode replacement without deleting the replacement', () => {
  const profile = create(); const original = profile.profilePath; const saved = `${original}-saved`;
  try {
    renameSync(original, saved); mkdirSync(original);
    assert.throws(() => cleanup(profile), REJECTED);
    assert.equal(existsSync(join(saved, 'Default', 'ServerCertificate')), true);
    rmdirSync(original); renameSync(saved, original);
  } finally { cleanup(profile); }
});

test('cleanup rejects root symlink substitution', () => {
  const profile = create(); const original = profile.profilePath; const saved = `${original}-saved`;
  try {
    renameSync(original, saved); symlinkSync(saved, original);
    assert.throws(() => cleanup(profile), REJECTED);
    assert.equal(lstatSync(original).isSymbolicLink(), true);
    unlinkSync(original); renameSync(saved, original);
  } finally { cleanup(profile); }
});
