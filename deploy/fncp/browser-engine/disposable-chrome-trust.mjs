/** TEST SUPPORT ONLY: internal Chromium 149 profile-schema QA bootstrap.
 * Not a supported Chrome provisioning API or production trust configuration.
 * Sources pinned to 149.0.7827.55:
 * https://chromium.googlesource.com/chromium/src/+/refs/tags/149.0.7827.55/components/server_certificate_database/server_certificate_database.cc
 * https://chromium.googlesource.com/chromium/src/+/refs/tags/149.0.7827.55/components/server_certificate_database/server_certificate_database.proto
 * https://chromium.googlesource.com/chromium/src/+/refs/tags/149.0.7827.55/sql/meta_table.cc
 * Only a newly created task-owned profile is written. No OS store, existing
 * profile, browser launch, certificate exception or network operation occurs.
 */
import { createHash, X509Certificate } from 'node:crypto';
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, realpathSync,
  rmdirSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const HOSTS = Object.freeze(['browser.example.invalid', 'identity.issuer.invalid']);
const MAX_CERT_BYTES = 8192;
const MAX_VALIDITY_MS = 26 * 60 * 60 * 1000;
const MAX_TREE_ENTRIES = 10_000;
const MAX_TREE_DEPTH = 32;
const PEM = /^-----BEGIN CERTIFICATE-----\r?\n(?:[A-Za-z0-9+/=]+\r?\n)+-----END CERTIFICATE-----\r?\n?$/u;
const LOCK_NAMES = new Set(['SingletonLock', 'SingletonCookie', 'SingletonSocket']);
const rejected = () => new Error('Disposable synthetic Chrome trust profile rejected.');

function record(value, names) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype) throw rejected();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).length !== names.length
    || names.some((name) => !Object.hasOwn(descriptors, name)
      || !Object.hasOwn(descriptors[name], 'value'))) throw rejected();
  return Object.fromEntries(names.map((name) => [name, descriptors[name].value]));
}

function certificatesFrom(options) {
  const { mode, certificates } = record(options, ['mode', 'certificates']);
  if (mode !== 'SYNTHETIC_ONLY' || !Array.isArray(certificates)
    || Object.getPrototypeOf(certificates) !== Array.prototype
    || certificates.length !== 2) throw rejected();
  const descriptors = Object.getOwnPropertyDescriptors(certificates);
  if (Reflect.ownKeys(descriptors).length !== 3
    || ['0', '1'].some((key) => !Object.hasOwn(descriptors, key)
      || !Object.hasOwn(descriptors[key], 'value'))) throw rejected();
  const inputs = [descriptors['0'].value, descriptors['1'].value];
  const now = Date.now();
  const seen = new Set();
  return inputs.map((input) => {
    if (!Buffer.isBuffer(input) || input.length < 200 || input.length > MAX_CERT_BYTES
      || input.buffer instanceof SharedArrayBuffer) throw rejected();
    const copy = Buffer.from(input);
    const text = copy.toString('ascii');
    if (!copy.equals(Buffer.from(text, 'ascii')) || !PEM.test(text)) throw rejected();
    let certificate;
    try { certificate = new X509Certificate(copy); } catch { throw rejected(); }
    const host = HOSTS.find((candidate) => certificate.subject === `CN=${candidate}`);
    const from = Date.parse(certificate.validFrom);
    const to = Date.parse(certificate.validTo);
    if (!host || seen.has(host) || certificate.issuer !== certificate.subject
      || certificate.subjectAltName !== `DNS:${host}`
      || certificate.checkHost(host, { subject: 'never', wildcards: false }) !== host
      || !certificate.verify(certificate.publicKey)
      || !Number.isFinite(from) || !Number.isFinite(to) || from > now || to <= now
      || to - from <= 0 || to - from > MAX_VALIDITY_MS) throw rejected();
    seen.add(host);
    const der = Buffer.from(certificate.raw);
    return { host, der, hash: createHash('sha256').update(der).digest('hex') };
  });
}

function identity(path, type) {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || (type === 'directory' ? !stat.isDirectory() : !stat.isFile())
    || (type === 'file' && stat.nlink !== 1)) throw rejected();
  return { dev: stat.dev, ino: stat.ino };
}

function unchanged(path, expected, type) {
  const actual = identity(path, type);
  if (actual.dev !== expected.dev || actual.ino !== expected.ino) throw rejected();
}

/** Creates a fresh profile; callers cannot choose paths, hosts, trust or schema.
 * cleanup({browserClosed:true}) requires the caller to have awaited Chrome close.
 * This is an attestation, not process detection; surviving Chrome locks fail shut.
 */
export function createDisposableChromeTrust(...args) {
  if (args.length !== 1) throw rejected();
  const certs = certificatesFrom(args[0]);
  // Resolve platform temp symlinks once; never accept a caller-owned root.
  const profilePath = mkdtempSync(join(realpathSync(tmpdir()), 'fncp-chrome-trust-'));
  const defaultPath = join(profilePath, 'Default');
  const databasePath = join(defaultPath, 'ServerCertificate');
  let database;
  let rootIdentity; let defaultIdentity; let databaseIdentity;
  try {
    chmodSync(profilePath, 0o700);
    rootIdentity = identity(profilePath, 'directory');
    mkdirSync(defaultPath, { mode: 0o700 });
    defaultIdentity = identity(defaultPath, 'directory');
    database = new DatabaseSync(databasePath);
    chmodSync(databasePath, 0o600);
    database.exec('BEGIN IMMEDIATE; CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR); CREATE TABLE certificates(sha256hash_hex TEXT PRIMARY KEY, der_cert BLOB NOT NULL, trust_settings BLOB NOT NULL);');
    const meta = database.prepare('INSERT INTO meta(key,value) VALUES(?,?)');
    meta.run('version', '1'); meta.run('last_compatible_version', '1');
    const insert = database.prepare('INSERT INTO certificates(sha256hash_hex,der_cert,trust_settings) VALUES(?,?,?)');
    for (const cert of certs) insert.run(cert.hash, cert.der, Buffer.from([0x0a, 0x02, 0x08, 0x03]));
    database.exec('COMMIT'); database.close(); database = undefined;
    databaseIdentity = identity(databasePath, 'file');
  } catch {
    try { database?.close(); } catch { /* Only this invocation's database. */ }
    // Setup has not exposed this root or launched a browser. Do not follow links
    // or remove an unexpected setup entry if the directory was concurrently changed.
    try {
      if (rootIdentity) unchanged(profilePath, rootIdentity, 'directory');
      if (defaultIdentity) unchanged(defaultPath, defaultIdentity, 'directory');
      for (const name of ['ServerCertificate', 'ServerCertificate-journal', 'ServerCertificate-wal', 'ServerCertificate-shm']) {
        const path = join(defaultPath, name);
        try { identity(path, 'file'); unlinkSync(path); } catch (error) { if (error.code !== 'ENOENT') throw rejected(); }
      }
      rmdirSync(defaultPath); rmdirSync(profilePath);
    } catch { /* Fail closed and leave an unexpected fresh setup tree alone. */ }
    throw rejected();
  }

  let cleaned = false;
  const summary = () => Object.freeze({
    schemaVersion: 1, mode: 'SYNTHETIC_ONLY', classification: 'KEEP_CLOSED',
    chromiumSchemaVersion: '149.0.7827.55', internalSchemaQaBootstrap: true,
    officialProvisioningApi: false, certificateCount: 2,
    trustedHosts: HOSTS, publicCertificatesOnly: true, syntheticNamesOnly: true,
    existingProfileUsed: false, globalTrustChanged: false,
    certificateValidationDisabled: false, browserLaunched: false,
    nativeTlsVerified: false, browserCloseAttestationRequired: true, cleaned,
  });

  function cleanup(...cleanupArgs) {
    if (cleanupArgs.length !== 1
      || record(cleanupArgs[0], ['browserClosed']).browserClosed !== true) throw rejected();
    if (cleaned) return summary();
    try {
      unchanged(profilePath, rootIdentity, 'directory');
      unchanged(defaultPath, defaultIdentity, 'directory');
      unchanged(databasePath, databaseIdentity, 'file');
      const entries = [];
      function inspect(path, depth) {
        if (depth > MAX_TREE_DEPTH || entries.length >= MAX_TREE_ENTRIES) throw rejected();
        const stat = lstatSync(path);
        if (stat.isSymbolicLink() || (!stat.isDirectory() && !stat.isFile())
          || (stat.isFile() && stat.nlink !== 1)) throw rejected();
        entries.push({ path, dev: stat.dev, ino: stat.ino, directory: stat.isDirectory() });
        if (stat.isDirectory()) {
          for (const name of readdirSync(path)) {
            if (LOCK_NAMES.has(name)) throw rejected();
            inspect(join(path, name), depth + 1);
          }
        }
      }
      inspect(profilePath, 0);
      // Entire tree is checked before any deletion; deletion never follows a
      // symlink and rechecks identities immediately before each owned removal.
      for (const entry of entries.reverse()) {
        unchanged(profilePath, rootIdentity, 'directory');
        unchanged(entry.path, entry, entry.directory ? 'directory' : 'file');
        if (entry.directory) rmdirSync(entry.path); else unlinkSync(entry.path);
      }
      cleaned = true;
      return summary();
    } catch { throw rejected(); }
  }
  return Object.freeze({ profilePath, summary, cleanup });
}
