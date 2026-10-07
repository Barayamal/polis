import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';

const MANIFEST = 'SHA256SUMS.txt';
const HASH = /^[a-f0-9]{64}$/;
const REV = /^[a-f0-9]{40}$/;
const ROLES = ['api', 'math', 'migration', 'postgres', 'participant', 'wordpress', 'mariadb', 'proxy'];
const LIMIT = Object.freeze({entries: 5000, manifest: 2 ** 20, file: 256 * 2 ** 20, total: 2 ** 30, json: 16 * 2 ** 20});
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
function requireThat(condition, code) { if (!condition) throw new Error(code); }
function stamp(s) { return [s.dev, s.ino, s.mode, s.nlink, s.size, s.mtimeNs, s.ctimeNs].join(':'); }
function stat(file) { return fs.lstatSync(file, {bigint: true}); }

export function parseManifest(bytes) {
  requireThat(Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= LIMIT.manifest, 'MANIFEST_SIZE');
  const text = new TextDecoder('utf-8', {fatal: true}).decode(bytes);
  requireThat(text.endsWith('\n') && !text.includes('\r'), 'MANIFEST_FORMAT');
  const lines = text.slice(0, -1).split('\n');
  requireThat(lines.length <= LIMIT.entries, 'MANIFEST_ENTRY_LIMIT');
  const entries = new Map(), aliases = new Set();
  for (const line of lines) {
    const match = /^([a-f0-9]{64})  (.+)$/.exec(line);
    requireThat(match, 'MANIFEST_FORMAT');
    const [, hash, name] = match;
    const parts = name.split('/');
    requireThat(name.length <= 512 && parts.length <= 32 && !path.isAbsolute(name) &&
      !/[\x00-\x1f\x7f\\:]/.test(name) && name === name.normalize('NFC') &&
      parts.every(p => p !== '' && p !== '.' && p !== '..' && !/[. ]$/.test(p)), 'UNSAFE_MEMBER_PATH');
    requireThat(name !== MANIFEST, 'SELF_REFERENTIAL_MANIFEST');
    const alias = name.toLowerCase();
    requireThat(!aliases.has(alias), 'DUPLICATE_MEMBER');
    aliases.add(alias); entries.set(name, hash);
  }
  return entries;
}

function inventory(root) {
  const files = new Map(), directories = new Map();
  let total = 0, objects = 0;
  const walk = (dir, relative = '', depth = 0) => {
    requireThat(depth <= 32 && ++objects <= LIMIT.entries * 2, 'DIRECTORY_LIMIT');
    const before = stat(dir);
    requireThat(before.isDirectory() && !before.isSymbolicLink(), 'UNSAFE_DIRECTORY');
    directories.set(relative, stamp(before));
    for (const entry of fs.readdirSync(dir).sort()) {
      const name = relative ? `${relative}/${entry}` : entry;
      const file = path.join(dir, entry), s = stat(file);
      requireThat(!s.isSymbolicLink(), 'SYMLINK_MEMBER');
      if (s.isDirectory()) walk(file, name, depth + 1);
      else {
        requireThat(s.isFile() && s.nlink === 1n, 'UNSAFE_MEMBER_TYPE');
        requireThat(s.size <= BigInt(LIMIT.file) && files.size < LIMIT.entries + 1, 'MEMBER_LIMIT');
        total += Number(s.size);
        requireThat(total <= LIMIT.total, 'PACKAGE_SIZE_LIMIT');
        files.set(name, stamp(s));
      }
    }
    requireThat(stamp(stat(dir)) === stamp(before), 'PACKAGE_CHANGED');
  };
  walk(root);
  return {files, directories, total};
}

function ancestorsUnchanged(root, name, observed) {
  requireThat(fs.realpathSync(root) === root, 'ROOT_CHANGED');
  const parts = name.split('/'); parts.pop();
  let relative = '';
  for (const part of ['', ...parts]) {
    if (part) relative = relative ? `${relative}/${part}` : part;
    const s = stat(path.join(root, relative));
    requireThat(s.isDirectory() && stamp(s) === observed.directories.get(relative), 'PACKAGE_CHANGED');
  }
}

function readMember(root, name, observed, collect = false, maximum = LIMIT.file) {
  ancestorsUnchanged(root, name, observed);
  const file = path.join(root, name), expected = observed.files.get(name);
  requireThat(expected && stamp(stat(file)) === expected, 'PACKAGE_CHANGED');
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    const before = fs.fstatSync(fd, {bigint: true});
    requireThat(before.isFile() && before.nlink === 1n && stamp(before) === expected, 'PACKAGE_CHANGED');
    requireThat(before.size <= BigInt(maximum), 'MEMBER_SIZE');
    const buffer = Buffer.alloc(64 * 1024), chunks = [], hash = createHash('sha256');
    let total = 0, n;
    while ((n = fs.readSync(fd, buffer, 0, buffer.length, null)) > 0) {
      total += n; requireThat(total <= maximum, 'MEMBER_SIZE');
      hash.update(buffer.subarray(0, n));
      if (collect) chunks.push(Buffer.from(buffer.subarray(0, n)));
    }
    requireThat(total === Number(before.size) && stamp(fs.fstatSync(fd, {bigint: true})) === expected &&
      stamp(stat(file)) === expected, 'PACKAGE_CHANGED');
    ancestorsUnchanged(root, name, observed);
    return {hash: hash.digest('hex'), bytes: collect ? Buffer.concat(chunks) : undefined, size: total};
  } finally { if (fd !== undefined) fs.closeSync(fd); }
}

function equalInventory(a, b) {
  for (const key of ['files', 'directories']) {
    requireThat(a[key].size === b[key].size && [...a[key]].every(([p, s]) => b[key].get(p) === s), 'PACKAGE_CHANGED');
  }
}

/** Verify an immutable *local delivery snapshot*. No execution, network, extraction or writes. */
export function verifyPackage(rootInput, expectedManifestSha256) {
  requireThat(typeof rootInput === 'string' && path.isAbsolute(rootInput), 'ABSOLUTE_ROOT_REQUIRED');
  requireThat(typeof expectedManifestSha256 === 'string' && HASH.test(expectedManifestSha256), 'TRUSTED_MANIFEST_HASH_REQUIRED');
  const root = path.resolve(rootInput);
  requireThat(fs.realpathSync(root) === root, 'CANONICAL_ROOT_REQUIRED');
  const observed = inventory(root);
  const manifest = readMember(root, MANIFEST, observed, true, LIMIT.manifest);
  requireThat(manifest.hash === expectedManifestSha256, 'TRUST_ANCHOR_MISMATCH');
  const entries = parseManifest(manifest.bytes);
  requireThat(observed.files.size === entries.size + 1 && [...observed.files.keys()].every(p => p === MANIFEST || entries.has(p)), 'MEMBERSHIP_MISMATCH');
  const directoryNames = new Set(['']);
  for (const name of entries.keys()) {
    const parts = name.split('/'); parts.pop();
    for (let n = 1; n <= parts.length; n++) directoryNames.add(parts.slice(0, n).join('/'));
  }
  requireThat(observed.directories.size === directoryNames.size && [...observed.directories.keys()].every(p => directoryNames.has(p)), 'DIRECTORY_MEMBERSHIP_MISMATCH');
  const hashes = new Map();
  for (const [name, expected] of entries) {
    const member = readMember(root, name, observed);
    requireThat(member.hash === expected, 'MEMBER_HASH_MISMATCH');
    hashes.set(name, member);
  }
  const json = name => {
    requireThat(entries.has(name), 'REQUIRED_RECEIPT_MISSING');
    const member = readMember(root, name, observed, true, LIMIT.json);
    requireThat(member.hash === entries.get(name), 'PACKAGE_CHANGED');
    let value;
    try { value = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(member.bytes)); }
    catch { throw new Error('INVALID_RECEIPT_JSON'); }
    requireThat(object(value), 'RECEIPT_OBJECT_REQUIRED');
    return value;
  };
  const v = json('VERIFICATION.json');
  requireThat(v.profile === 'FNCP_NORMAL_COMPOSE_LOCAL_DELIVERY_V1' && v.result === 'LOCAL_BUILD_AND_REHEARSAL_COMPLETE', 'UNSUPPORTED_DELIVERY_PROFILE');
  requireThat(v.publicDeployment === false && v.realOidcProviderVerified === false && v.publicBrowserTlsVerified === false && v.paidResourcesCreated === false && v.privateTaskRuntimeMaterialIncluded === false && v.publishedHostPorts === 0, 'LOCAL_ONLY_BOUNDARY_MISMATCH');
  requireThat(v.includedFileCount === observed.files.size && v.checksumEntries === entries.size && v.sha256Manifest === MANIFEST, 'DELIVERY_COUNT_MISMATCH');
  requireThat(REV.test(v.runtimeSourceRevision) && REV.test(v.finalOfflineToolRevision) && HASH.test(v.runtimeSourceFingerprint), 'SOURCE_IDENTITY_INVALID');
  const receipt = json('source/bundle-verification.json');
  const bundleName = 'source/polis-production-reviewed.bundle';
  requireThat(receipt.profile === 'REVIEWED_SOURCE_BUNDLE_VERIFICATION_V1' && receipt.result === 'PASS' && receipt.bundle === 'polis-production-reviewed.bundle' && receipt.runtimeRevision === v.runtimeSourceRevision && object(receipt.refs) && receipt.refs['refs/heads/main'] === v.finalOfflineToolRevision && Object.keys(receipt.refs).length === 1 && receipt.sha256 === v.sourceBundleSha256 && hashes.get(bundleName)?.hash === receipt.sha256 && hashes.get(bundleName)?.size === receipt.bytes, 'BUNDLE_BINDING_MISMATCH');
  const recovery = json('evidence/node22-recovery-9fcc/summary.json');
  requireThat(recovery.profile === 'NODE22_TARGETED_OFFLINE_RECOVERY_9FCC_V1' && recovery.result === 'PASS' && recovery.sourceRevision === v.finalOfflineToolRevision && recovery.runtimeRevisionUnchanged === v.runtimeSourceRevision && recovery.testCount === 47 && recovery.passed === 47 && recovery.failed === 0 && recovery.skipped === 0 && recovery.cancelled === 0 && recovery.containerExitCode === 0, 'OFFLINE_TEST_RECEIPT_MISMATCH');
  const base = 'evidence/image-assurance';
  const lock = json(`${base}/approved-runtime-lock.json`);
  requireThat(lock.version === 1 && lock.sourceRevision === v.runtimeSourceRevision && lock.sourceFingerprint === v.runtimeSourceFingerprint && v.imageRoles === ROLES.length && Object.keys(lock.images ?? {}).sort().join() === [...ROLES].sort().join(), 'IMAGE_LOCK_MISMATCH');
  for (const role of ROLES) {
    const at = `${base}/scans/${role}`;
    const binding = json(`${at}/image.binding.json`);
    const index = json(`${at}/image.root-descriptor.json`);
    const manifestDoc = json(`${at}/image.platform-manifest.json`);
    const config = json(`${at}/image.image-config.json`);
    const copied = json(`${at}/source-file-binding.json`);
    const digest = name => `sha256:${hashes.get(`${at}/${name}`)?.hash}`;
    requireThat(/^sha256:[a-f0-9]{64}$/.test(lock.images[role]) && lock.images[role] === binding.requestedDockerImageId && lock.images[role] === digest('image.root-descriptor.json'), 'IMAGE_ROOT_BINDING_MISMATCH');
    requireThat(index.schemaVersion === 2 && index.mediaType === 'application/vnd.oci.image.index.v1+json' && binding.selectedPlatform === 'linux/arm64' && config.os === 'linux' && config.architecture === 'arm64', 'IMAGE_PLATFORM_MISMATCH');
    requireThat(Array.isArray(index.manifests) && index.manifests.length > 0 && index.manifests.every(m => object(m) && object(m.platform)), 'IMAGE_INDEX_SHAPE_INVALID');
    const candidates = index.manifests.filter(m => m.platform.os === 'linux' && m.platform.architecture === 'arm64');
    requireThat(candidates?.length === 1 && candidates[0].digest === binding.selectedPlatformManifestDigest && candidates[0].digest === digest('image.platform-manifest.json') && candidates[0].size === hashes.get(`${at}/image.platform-manifest.json`).size && manifestDoc.schemaVersion === 2, 'IMAGE_MANIFEST_BINDING_MISMATCH');
    requireThat(manifestDoc.config?.digest === binding.selectedConfigDigest && manifestDoc.config.digest === digest('image.image-config.json') && manifestDoc.config.size === hashes.get(`${at}/image.image-config.json`).size, 'IMAGE_CONFIG_BINDING_MISMATCH');
    requireThat(copied.role === role && copied.allComparedBytesEqual === true && copied.imageId === lock.images[role] && copied.sourceRevision === v.runtimeSourceRevision && copied.sourceFingerprint === v.runtimeSourceFingerprint, 'IMAGE_SOURCE_RECEIPT_MISMATCH');
  }
  equalInventory(observed, inventory(root));
  return Object.freeze({profile: 'FNCP_OFFLINE_PACKAGE_CHECK_V1', result: 'PASS', checksumEntries: entries.size,
    packageFiles: observed.files.size, packageBytes: observed.total, verifiedImageDescriptorChains: ROLES.length,
    manifestSha256: manifest.hash, runtimeSourceRevision: v.runtimeSourceRevision, offlineToolRevision: v.finalOfflineToolRevision,
    trustedManifestMatched: true, fullImageLayersRehashed: false, gitPackObjectsVerified: false,
    freshRuntimeTest: false, freshVulnerabilityScan: false, realOidcVerified: false, deploymentAuthorized: false});
}

export function cli(args) {
  try {
    requireThat(args.length === 3 && args[1] === '--manifest-sha256', 'USAGE');
    return {status: 0, output: verifyPackage(args[0], args[2])};
  } catch (error) {
    // Never echo paths, JSON values, tokens, filesystem errors or file content.
    const code = /^[A-Z][A-Z0-9_]+$/.test(error.message ?? '') ? error.message : 'PACKAGE_READ_FAILED';
    return {status: 1, output: {profile: 'FNCP_OFFLINE_PACKAGE_CHECK_V1', result: 'FAIL', code, deploymentAuthorized: false}};
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const result = cli(process.argv.slice(2));
  process.stdout.write(`${JSON.stringify(result.output, null, 2)}\n`);
  process.exitCode = result.status;
}
