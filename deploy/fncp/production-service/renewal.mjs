import fs from 'node:fs';
import { dirname, isAbsolute, relative, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { canonical, exact, sha, SHA, NAME, CONVERSATION } from './contracts.mjs';
import { ACCESS_SCHEMA } from './store-schema.mjs';
import { validateExistingProductionStore } from './store-validation.mjs';
import { validBinding, UUID } from '../production-activation/protocol.mjs';
import { holdRenewalMaterial } from './renewal-material.mjs';

const repository = fileURLToPath(new URL('../../../', import.meta.url)).replace(/\/$/u, '');
const denied = () => new Error('Offline production credential renewal denied.');
const MAX_BYTES = 16 * 1024 * 1024;
const own = stat => stat.uid === process.getuid();
const same = (a, b) => a.dev === b.dev && a.ino === b.ino;
const privateFile = s => s.isFile() && own(s) && s.nlink === 1 && (s.mode & 0o7777) === 0o600;
const stable = (a, b) => same(a, b) && privateFile(b) && a.size === b.size
  && a.mtimeMs === b.mtimeMs && a.ctimeMs === b.ctimeMs;
const integer = n => Number.isSafeInteger(n) && n >= 0;
const digest = v => typeof v === 'string' && SHA.test(v);

// Descriptors are private data, never factories or executable configuration.
// Check arrays as well as objects before canonicalization invokes any member.
function data(value, ancestors = new Set(), depth = 0) {
  if (depth > 12) throw denied();
  if (typeof value === 'string') { if (value.length > 65536) throw denied(); return; }
  if (value === null || typeof value === 'boolean' || Number.isSafeInteger(value)) return;
  if (!value || typeof value !== 'object' || ancestors.has(value)) throw denied();
  const keys = Reflect.ownKeys(value), descriptors = Object.getOwnPropertyDescriptors(value);
  if (keys.length > 1024 || keys.some(k => typeof k !== 'string')
    || Object.values(descriptors).some(d => !Object.hasOwn(d, 'value'))) throw denied();
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype || keys.length !== value.length + 1
      || keys.some(k => k !== 'length' && (!/^(0|[1-9][0-9]*)$/u.test(k) || Number(k) >= value.length))) throw denied();
  } else if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw denied();
  ancestors.add(value);
  for (const key of keys) if (key !== 'length' || !Array.isArray(value)) data(descriptors[key].value, ancestors, depth + 1);
  ancestors.delete(value);
}

function origin(value) {
  if (typeof value !== 'string') return false;
  try { const u = new URL(value); return u.protocol === 'https:' && u.origin === value && !u.username && !u.password; }
  catch { return false; }
}

function descriptor(input) {
  data(input); const encoded = canonical(input);
  if (Buffer.byteLength(encoded) > 131072) throw denied();
  const value = JSON.parse(encoded);
  exact(value, ['binding', 'bindingSha256']);
  const b = value.binding;
  exact(b, ['configuration', 'provider', 'wordpress', 'activation']);
  if (!digest(value.bindingSha256) || sha(canonical(b)) !== value.bindingSha256 || !validBinding(b.activation)) throw denied();
  const c = b.configuration, p = b.provider, w = b.wordpress, a = b.activation;
  exact(c, ['deploymentId', 'conversationId', 'consentVersion', 'noticeSha256', 'statementIds', 'statements', 'identityBindingSha256', 'credentialBindingSha256', 'notice']);
  if (!NAME.test(c.deploymentId) || !CONVERSATION.test(c.conversationId)
    || typeof c.consentVersion !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/u.test(c.consentVersion)
    || !digest(c.noticeSha256) || !digest(c.identityBindingSha256) || !digest(c.credentialBindingSha256)
    || !Array.isArray(c.statementIds) || c.statementIds.length !== 15
    || c.statementIds.some((n, i) => !integer(n) || n > 2147483647 || i > 0 && n <= c.statementIds[i - 1])
    || !Array.isArray(c.statements) || c.statements.length !== 15 || new Set(c.statements).size !== 15
    || c.statements.some(s => typeof s !== 'string' || !s.trim() || s.length > 3000)) throw denied();
  exact(c.notice, ['adultDeclaration', 'eligibilityDeclaration', 'registrationDeclaration']);
  if (Object.values(c.notice).some(s => typeof s !== 'string' || !s.trim() || s.length > 3000)
    || sha(canonical(c.notice)) !== c.noticeSha256) throw denied();
  exact(p, ['origin', 'conversationId', 'statementIds', 'trustSha256']);
  exact(w, ['schemaVersion', 'deploymentId', 'conversationId', 'origin', 'consentVersion', 'noticeSha256', 'trustSha256', 'requestKeySha256', 'responseKeySha256']);
  if (!origin(p.origin) || !digest(p.trustSha256) || !origin(w.origin) || w.schemaVersion !== 1
    || !(digest(w.trustSha256) || w.trustSha256 === 'NODE_DEFAULT_TRUST')
    || !digest(w.requestKeySha256) || !digest(w.responseKeySha256)
    || p.conversationId !== c.conversationId || canonical(p.statementIds) !== canonical(c.statementIds)
    || w.deploymentId !== c.deploymentId || w.conversationId !== c.conversationId || w.consentVersion !== c.consentVersion
    || w.noticeSha256 !== c.noticeSha256 || a.deploymentId !== c.deploymentId || a.conversationId !== c.conversationId
    || a.providerSha256 !== sha(canonical(p)) || a.seedSha256 !== sha(canonical(c.statements))) throw denied();
  return value;
}

function directory(path) {
  if (!isAbsolute(path) || resolve(path) !== path || fs.realpathSync(path) !== path) throw denied();
  const s = fs.lstatSync(path);
  if (!s.isDirectory() || !own(s) || (s.mode & 0o7777) !== 0o700) throw denied();
  return s;
}
function checkDirectory(path, expected) { if (!same(directory(path), expected)) throw denied(); }
function absent(path) {
  try { fs.lstatSync(path); } catch (e) { if (e.code === 'ENOENT') return; throw e; }
  throw denied();
}
function noSidecars(path) { for (const suffix of ['-journal', '-wal', '-shm']) absent(path + suffix); }
function read(fd, size) {
  const bytes = Buffer.alloc(size); let n = 0;
  try { while (n < size) { const got = fs.readSync(fd, bytes, n, size - n, n); if (!got) throw denied(); n += got; } return bytes; }
  catch (e) { bytes.fill(0); throw e; }
}
function write(fd, bytes) {
  let n = 0; while (n < bytes.length) { const wrote = fs.writeSync(fd, bytes, n, bytes.length - n, n); if (!wrote) throw denied(); n += wrote; }
  fs.fsyncSync(fd);
}
function snapshot(db) {
  return { meta: db.prepare('SELECT * FROM meta ORDER BY singleton').all(),
    accounts: db.prepare('SELECT * FROM accounts ORDER BY account_id').all(),
    events: db.prepare('SELECT * FROM events ORDER BY event_id').all(),
    invitations: db.prepare('SELECT * FROM invitations ORDER BY token_hash').all() };
}

function validateActivation(path, identity, binding) {
  const tables = {
    activation_state: 'CREATE TABLE activation_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), identity TEXT NOT NULL, boot_id TEXT NOT NULL, binding_hash TEXT NOT NULL, sequence INTEGER NOT NULL CHECK(sequence>=0), active INTEGER NOT NULL CHECK(active IN (0,1)), activation_id TEXT, digest TEXT)',
    activation_ids: 'CREATE TABLE activation_ids (id TEXT PRIMARY KEY)',
  };
  const normalize = value => value.replace(/\s+/gu, ' ').trim();
  const db = new DatabaseSync(path, { readOnly: true, timeout: 1000 });
  try {
    db.exec('PRAGMA query_only=ON;PRAGMA trusted_schema=OFF;BEGIN;');
    if (db.prepare('PRAGMA journal_mode').get().journal_mode !== 'delete'
      || db.prepare('PRAGMA quick_check').get().quick_check !== 'ok'
      || db.prepare('PRAGMA application_id').get().application_id !== 1179534160
      || db.prepare('PRAGMA user_version').get().user_version !== 1) throw denied();
    const objects = db.prepare("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name").all();
    if (objects.length !== 2 || objects.some(o => o.type !== 'table' || !tables[o.name] || normalize(o.sql) !== normalize(tables[o.name]))) throw denied();
    const rows = db.prepare('SELECT * FROM activation_state').all(), row = rows[0];
    const ids = db.prepare('SELECT id FROM activation_ids LIMIT 10001').all();
    if (rows.length !== 1 || row.singleton !== 1 || row.identity !== identity || row.active !== 0
      || !integer(row.sequence) || !digest(row.boot_id) || !digest(row.binding_hash)
      || row.binding_hash !== sha(canonical({ ...binding, bootId: row.boot_id }))
      || row.activation_id !== null && !UUID.test(row.activation_id) || row.digest !== null && !digest(row.digest)
      || (row.activation_id === null) !== (row.digest === null)
      || ids.length > 10000 || ids.length > row.sequence || row.sequence > 0 && ids.length === 0
      || ids.some(r => !UUID.test(r.id)) || row.activation_id !== null && !ids.some(r => r.id === row.activation_id)) throw denied();
    return row.sequence;
  } finally { db.close(); }
}

/** Offline participant-state renewal only. Both services must be drained and
 * stopped; no runtime or network calls are made. Actual held source/target
 * material proves the narrowly permitted changes. Both SQLite histories are
 * copied to a fresh private target; source material and stores stay untouched.
 * This is not a joined six-volume deployment renewal or permission to launch. */
export function renewClosedProductionCredentials(options, onTargetCreated) {
  let sourceDb, targetDb, sourceFd, targetFd, targetRecord, bytes, sourceStat;
  let result, failure, sourceParent, targetParent, sourcePath, targetPath;
  const locks = [];
  let material, sourceActivationFd, targetActivationFd, sourceActivationStat, targetActivationRecord, activationBytes;
  let sourceActivationPath, targetActivationPath, activationReplayFloor, sourceActivationSha256;

  try {
    exact(options, ['sourceConfigurationPath', 'targetConfigurationPath'], ['mountView']);
    if (onTargetCreated !== undefined && typeof onTargetCreated !== 'function') throw denied();
    material = holdRenewalMaterial(options.sourceConfigurationPath, options.targetConfigurationPath, options.mountView);
    const old = descriptor(material.sourceDescriptor), next = descriptor(material.targetDescriptor);
    ({ sourcePath, targetPath } = material);
    sourceActivationPath = join(dirname(sourcePath), 'activation.sqlite');
    targetActivationPath = join(dirname(targetPath), 'activation.sqlite');
    for (const path of [sourcePath, targetPath]) if (typeof path !== 'string' || !isAbsolute(path)
      || resolve(path) !== path || !path.endsWith('.sqlite')) throw denied();
    const repoRelative = relative(repository, targetPath);
    if (sourcePath === targetPath || repoRelative === '' || !repoRelative.startsWith('..' + '/') && repoRelative !== '..' && !isAbsolute(repoRelative)) throw denied();
    sourceParent = directory(dirname(sourcePath)); targetParent = directory(dirname(targetPath));
    const lockPaths = [...new Set([sourcePath, targetPath].flatMap(path => [dirname(path) + '/service.lock', path + '.writer.lock', dirname(path) + '/activation.sqlite.lock']))].sort();
    for (const path of lockPaths) {
      const parent = directory(dirname(path));
      const fd = fs.openSync(path, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
      // Record the exclusive inode before any operation that can fail.
      const record = { path, parent, fd, stat: fs.fstatSync(fd) }; locks.push(record);
      if (!privateFile(record.stat) || !same(record.stat, fs.lstatSync(path))) throw denied();
    }
    const verify = () => {
      material.verify();
      if (sourceActivationStat && (!stable(sourceActivationStat, fs.fstatSync(sourceActivationFd)) || !stable(sourceActivationStat, fs.lstatSync(sourceActivationPath)))) throw denied();
      checkDirectory(dirname(sourcePath), sourceParent); checkDirectory(dirname(targetPath), targetParent);
      for (const lock of locks) {
        checkDirectory(dirname(lock.path), lock.parent);
        if (!privateFile(fs.lstatSync(lock.path)) || !same(lock.stat, fs.lstatSync(lock.path)) || !same(lock.stat, fs.fstatSync(lock.fd))) throw denied();
      }
    };
    verify(); absent(targetPath); absent(targetActivationPath); noSidecars(sourcePath); noSidecars(targetPath);
    noSidecars(sourceActivationPath); noSidecars(targetActivationPath);
    if (fs.readdirSync(dirname(targetPath)).some(name => !['service.lock', 'access.sqlite.writer.lock', 'activation.sqlite.lock'].includes(name))) throw denied();
    sourceActivationFd = fs.openSync(sourceActivationPath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    sourceActivationStat = fs.fstatSync(sourceActivationFd);
    if (!privateFile(sourceActivationStat) || sourceActivationStat.size < 512 || sourceActivationStat.size > MAX_BYTES
      || !stable(sourceActivationStat, fs.lstatSync(sourceActivationPath))) throw denied();
    activationReplayFloor = validateActivation(sourceActivationPath, material.activationIdentity, old.binding.activation);
    activationBytes = read(sourceActivationFd, sourceActivationStat.size); sourceActivationSha256 = sha(activationBytes);
    verify();

    sourceFd = fs.openSync(sourcePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    sourceStat = fs.fstatSync(sourceFd);
    if (!privateFile(sourceStat) || sourceStat.size < 512 || sourceStat.size > MAX_BYTES
      || !stable(sourceStat, fs.lstatSync(sourcePath))) throw denied();
    const startedAt = Date.now(); if (!integer(startedAt)) throw denied();
    sourceDb = new DatabaseSync(sourcePath, { readOnly: true, timeout: 1000 });
    sourceDb.exec('PRAGMA query_only=ON;PRAGMA trusted_schema=OFF;PRAGMA foreign_keys=ON;BEGIN;');
    if (sourceDb.prepare('PRAGMA journal_mode').get().journal_mode !== 'delete') throw denied();
    const validated = validateExistingProductionStore(sourceDb, { schema: ACCESS_SCHEMA, configuration: old.binding.configuration, bindingSha: old.bindingSha256 });
    if (validated.fresh) throw denied();
    const before = snapshot(sourceDb);
    if (before.meta[0].last_ms > startedAt || before.invitations.some(row => row.used !== 1)) throw denied();
    bytes = read(sourceFd, sourceStat.size); const sourceSha256 = sha(bytes);
    if (!stable(sourceStat, fs.fstatSync(sourceFd)) || !stable(sourceStat, fs.lstatSync(sourcePath))) throw denied();
    verify(); noSidecars(sourcePath); noSidecars(targetPath);
    targetActivationFd = fs.openSync(targetActivationPath, fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    targetActivationRecord = fs.fstatSync(targetActivationFd);
    onTargetCreated?.(targetActivationPath, fs.fstatSync(targetActivationFd, { bigint: true }));
    if (!privateFile(targetActivationRecord) || !same(targetActivationRecord, fs.lstatSync(targetActivationPath))) throw denied();
    write(targetActivationFd, activationBytes); verify();
    if (!privateFile(fs.lstatSync(targetActivationPath)) || !same(targetActivationRecord, fs.lstatSync(targetActivationPath))) throw denied();
    if (validateActivation(targetActivationPath, material.activationIdentity, old.binding.activation) !== activationReplayFloor) throw denied();
    targetFd = fs.openSync(targetPath, fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    targetRecord = fs.fstatSync(targetFd);
    onTargetCreated?.(targetPath, fs.fstatSync(targetFd, { bigint: true }));
    if (!privateFile(targetRecord) || !same(targetRecord, fs.lstatSync(targetPath))) throw denied();
    write(targetFd, bytes); verify();
    if (!same(targetRecord, fs.lstatSync(targetPath)) || !privateFile(fs.lstatSync(targetPath))) throw denied();
    targetDb = new DatabaseSync(targetPath, { timeout: 1000 });
    targetDb.exec('PRAGMA foreign_keys=ON;PRAGMA journal_mode=DELETE;PRAGMA synchronous=FULL;PRAGMA trusted_schema=OFF;');
    validateExistingProductionStore(targetDb, { schema: ACCESS_SCHEMA, configuration: old.binding.configuration, bindingSha: old.bindingSha256 });
    targetDb.exec('BEGIN IMMEDIATE;');
    if (targetDb.prepare('UPDATE meta SET binding_sha=? WHERE singleton=1 AND binding_sha=?').run(next.bindingSha256, old.bindingSha256).changes !== 1) throw denied();
    targetDb.exec('COMMIT;');
    const checked = validateExistingProductionStore(targetDb, { schema: ACCESS_SCHEMA, configuration: next.binding.configuration, bindingSha: next.bindingSha256 });
    const expected = structuredClone(before); expected.meta[0].binding_sha = next.bindingSha256;
    if (canonical(snapshot(targetDb)) !== canonical(expected)) throw denied();
    targetDb.close(); targetDb = undefined; fs.fsyncSync(targetFd); verify();
    const targetStat = fs.fstatSync(targetFd);
    if (!privateFile(targetStat) || !same(targetRecord, targetStat) || !stable(targetStat, fs.lstatSync(targetPath))
      || targetStat.size > MAX_BYTES) throw denied();
    const finalTarget = read(targetFd, targetStat.size); let targetSha256;
    try { targetSha256 = sha(finalTarget); } finally { finalTarget.fill(0); }
    const finalSource = read(sourceFd, sourceStat.size);
    try { if (sha(finalSource) !== sourceSha256) throw denied(); } finally { finalSource.fill(0); }
    if (!stable(sourceStat, fs.fstatSync(sourceFd)) || !stable(sourceStat, fs.lstatSync(sourcePath))
      || !stable(targetStat, fs.fstatSync(targetFd)) || !stable(targetStat, fs.lstatSync(targetPath))
      || !integer(Date.now()) || Date.now() < startedAt) throw denied();
    noSidecars(sourcePath); noSidecars(targetPath); noSidecars(sourceActivationPath); noSidecars(targetActivationPath); verify();
    const activationTargetStat = fs.fstatSync(targetActivationFd);
    if (!privateFile(activationTargetStat) || !same(activationTargetStat, targetActivationRecord)
      || !stable(activationTargetStat, fs.lstatSync(targetActivationPath)) || activationTargetStat.size !== sourceActivationStat.size) throw denied();
    for (const [fd, stat] of [[sourceActivationFd, sourceActivationStat], [targetActivationFd, activationTargetStat]]) {
      const captured = read(fd, stat.size); try { if (sha(captured) !== sourceActivationSha256) throw denied(); } finally { captured.fill(0); }
    }
    verify();
    const directoryFd = fs.openSync(dirname(targetPath), fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    try { if (!same(targetParent, fs.fstatSync(directoryFd))) throw denied(); fs.fsyncSync(directoryFd); } finally { fs.closeSync(directoryFd); }
    verify();
    result = Object.freeze({ profile: 'FNCP_CLOSED_CREDENTIAL_RENEWAL_V1', copied: true,
      changedRoles: material.changes, activationReplayFloor, sourceActivationSha256, targetActivationSha256: sourceActivationSha256,
      joinedDeploymentRenewed: false, freshActivationRequired: true,
      accounts: checked.accounts, events: checked.events, invitations: checked.invitations,
      revokedAccounts: before.accounts.filter(a => a.state === 'revoked').length,
      pendingRemovals: before.accounts.filter(a => a.provider_state === 'pending_remove').length,
      sourceSha256, targetSha256, sourceBindingSha256: old.bindingSha256, targetBindingSha256: next.bindingSha256,
      sourceUnchanged: true, historiesAndClocksPreserved: true, activationLedgerUnchanged: true, admissionGranted: false });
  } catch { failure = denied(); }
  finally {
    for (const db of [targetDb, sourceDb]) if (db) try { db.close(); } catch { failure = denied(); }
    for (const fd of [targetFd, sourceFd, targetActivationFd, sourceActivationFd]) if (fd !== undefined) try { fs.closeSync(fd); } catch { failure = denied(); }
    if (failure && targetRecord) {
      // Replacements and unknown sidecars are never adopted or deleted.
      try { checkDirectory(dirname(targetPath), targetParent); const s = fs.lstatSync(targetPath);
        if (!same(s, targetRecord) || !privateFile(s)) throw denied(); fs.unlinkSync(targetPath);
      } catch { failure = denied(); }
    }
    if (failure && targetActivationRecord) {
      try { checkDirectory(dirname(targetActivationPath), targetParent); const s = fs.lstatSync(targetActivationPath);
        if (!same(s, targetActivationRecord) || !privateFile(s)) throw denied(); fs.unlinkSync(targetActivationPath);
      } catch { failure = denied(); }
    }
    for (const lock of locks.reverse()) {
      try { checkDirectory(dirname(lock.path), lock.parent); const s = fs.lstatSync(lock.path);
        if (!same(s, lock.stat) || !privateFile(s)) throw denied(); fs.unlinkSync(lock.path);
      } catch { failure = denied(); }
      try { fs.closeSync(lock.fd); } catch { failure = denied(); }
    }
    bytes?.fill(0); activationBytes?.fill(0); material?.close();
  }
  if (failure) throw failure;
  return result;
}
