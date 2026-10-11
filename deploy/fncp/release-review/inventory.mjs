/** Offline source-entry review only. Imports no application or runtime modules. */
import { constants, lstatSync, realpathSync, openSync, fstatSync, readFileSync, closeSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { isAbsolute, resolve, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { FIXED_MANIFEST } from './manifest.mjs';

const MAX_SOURCE_BYTES = 8 * 1024 * 1024;
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = code => { const error = new Error(code); error.code = code; throw error; };
const codes = new Set(['MANIFEST_REJECTED', 'SOURCE_PATH_REJECTED', 'ROOT_REJECTED', 'SOURCE_UNAVAILABLE', 'SOURCE_BOUNDARY_REJECTED', 'SOURCE_CHANGED', 'IMAGE_CLAIMS_REJECTED', 'ARGUMENTS_REJECTED']);
export function safeSourcePath(path) {
  if (typeof path !== 'string' || !path || isAbsolute(path) || path.includes('\\') || path.includes('%') || path.includes('\0') ||
      path.split('/').some(part => !part || part === '.' || part === '..' || part.startsWith('.') ||
        part === 'runtime' || /^(?:node_modules|keys?|certs?|evidence|secrets?|credentials)(?:[.-]|$)/iu.test(part)) ||
      /(?:^|\/)(?:wp-config\.php|[^/]*\.env(?:\.[^/]*)?|[^/]*\.(?:pem|key|p12|pfx|sqlite|sqlite3|db)(?:[-.][^/]*)?)$/iu.test(path)) fail('SOURCE_PATH_REJECTED');
  return path;
}
export function validateManifest(manifest) {
  try {
    assertPlainData(manifest);
    if (JSON.stringify(manifest) !== JSON.stringify(FIXED_MANIFEST)) fail('MANIFEST_REJECTED');
    for (const path of manifest.sourcePaths) safeSourcePath(path);
    return manifest;
  } catch { fail('MANIFEST_REJECTED'); }
}

function assertPlainData(value, seen = new Set()) {
  if (value === null || ['string', 'boolean'].includes(typeof value) || (typeof value === 'number' && Number.isFinite(value))) return;
  if (!value || typeof value !== 'object' || seen.has(value) ||
      Object.getPrototypeOf(value) !== (Array.isArray(value) ? Array.prototype : Object.prototype)) fail('MANIFEST_REJECTED');
  seen.add(value);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (typeof key !== 'string' || !Object.hasOwn(descriptor, 'value')) fail('MANIFEST_REJECTED');
    assertPlainData(descriptor.value, seen);
  }
  seen.delete(value);
}

/** Optional in-process assertions are syntax checks ONLY, never measured images. */
export function validateArtifactClaims(claims = []) {
  const ids = FIXED_MANIFEST.components.filter(entry => entry.kind === 'POLIS_IMAGE').map(entry => entry.id);
  if (!Array.isArray(claims) || (claims.length !== 0 && claims.length !== ids.length)) fail('IMAGE_CLAIMS_REJECTED');
  const seen = new Set();
  for (const claim of claims) {
    if (!claim || typeof claim !== 'object' || Array.isArray(claim) || Object.keys(claim).sort().join(',') !== 'id,reference' ||
        !ids.includes(claim.id) || seen.has(claim.id) || typeof claim.reference !== 'string' ||
        !/^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$/u.test(claim.reference) ||
        claim.reference.includes('://') || claim.reference.includes('..') || claim.reference.length > 512) fail('IMAGE_CLAIMS_REJECTED');
    seen.add(claim.id);
  }
  return { submitted: claims.length, independentlyVerified: false };
}

function rootBoundary(root) {
  try {
    if (typeof root !== 'string' || !isAbsolute(root) || resolve(root) !== root || realpathSync(root) !== root || !lstatSync(root).isDirectory()) fail('ROOT_REJECTED');
  } catch { fail('ROOT_REJECTED'); }
}
function sourceHash(root, path) {
  safeSourcePath(path);
  const target = join(root, path);
  if (relative(root, target) !== path) fail('SOURCE_PATH_REJECTED');
  let fd;
  try {
    let current = root;
    for (const part of path.split('/').slice(0, -1)) {
      current = join(current, part);
      const stat = lstatSync(current);
      if (!stat.isDirectory() || stat.isSymbolicLink() || realpathSync(current) !== current) fail('SOURCE_BOUNDARY_REJECTED');
    }
    const before = lstatSync(target);
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size > MAX_SOURCE_BYTES || realpathSync(target) !== target) fail('SOURCE_BOUNDARY_REJECTED');
    fd = openSync(target, constants.O_RDONLY | constants.O_NOFOLLOW);
    const opened = fstatSync(fd);
    if (!opened.isFile() || opened.nlink !== 1 || opened.ino !== before.ino || opened.dev !== before.dev || opened.size !== before.size) fail('SOURCE_CHANGED');
    const bytes = readFileSync(fd);
    const after = fstatSync(fd), pathAfter = lstatSync(target);
    if (bytes.length !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs || after.size !== before.size ||
        pathAfter.ino !== before.ino || pathAfter.dev !== before.dev || pathAfter.isSymbolicLink() || pathAfter.nlink !== 1 || realpathSync(target) !== target) fail('SOURCE_CHANGED');
    return { path, bytes: bytes.length, sha256: sha256(bytes), dependencyInput: FIXED_MANIFEST.dependencyFiles.includes(path) };
  } catch (error) { if (codes.has(error?.code)) throw error; fail('SOURCE_UNAVAILABLE'); }
  finally { if (fd !== undefined) closeSync(fd); }
}

export function inventoryRepository(root, { manifest = FIXED_MANIFEST, artifactClaims = [] } = {}) {
  validateManifest(manifest); validateArtifactClaims(artifactClaims); rootBoundary(root);
  const sources = manifest.sourcePaths.map(path => sourceHash(root, path));
  // Re-read the exact same bounded entries to catch ordinary concurrent edits.
  // This is not an atomic whole-tree snapshot or adversarial race-proof sandbox.
  for (const source of sources) if (JSON.stringify(sourceHash(root, source.path)) !== JSON.stringify(source)) fail('SOURCE_CHANGED');
  return {
    schemaVersion: 1, classification: 'KEEP_CLOSED', inventoryComplete: true, deployable: false, activationAuthority: false,
    scope: 'FIXED_SOURCE_ENTRIES_NOT_COMPLETE_SOURCE_CLOSURE',
    manifestSha256: sha256(JSON.stringify(manifest)), sourceEntryDigest: sha256(JSON.stringify(sources)),
    coverage: {
      components: manifest.components.length, sourceEntries: sources.length, dependencyInputs: manifest.dependencyFiles.length,
      npmLockfiles: manifest.dependencyFiles.filter(path => path.endsWith('package-lock.json')).length,
      polisImageArtifacts: 5, measuredImages: 0, independentlyVerifiedImageClaims: 0,
      excludedFromFiveImageCoverage: manifest.components.filter(entry => entry.kind !== 'POLIS_IMAGE').map(entry => entry.id),
      packageInstallOrScriptsExecuted: false, runtimeServicesImportedOrStarted: false, networkUsed: false,
      environmentOrPrivateStateRead: false, historicalEvidenceRead: false,
    },
    components: manifest.components.map(entry => ({ ...entry, status: entry.kind === 'EXTERNAL_DEPENDENCY' ? 'UNRESOLVED_PRODUCTION_DEPENDENCY' : 'LOCAL_SOURCE_ONLY_NOT_PRODUCTION_READY', fiveImageScope: entry.kind === 'POLIS_IMAGE' })),
    sources,
    limits: [
      'Hashes cover only these fixed entry files, not all imported source, migration SQL, vendored code, operating-system packages, installed dependency trees, WordPress archive bytes or a deployable source closure.',
      'No Docker, cloud, package manager, database, Git command, image inspection, SBOM generator, vulnerability scanner or runtime service is invoked.',
      'A package lock hash is not an audit result; a Dockerfile hash or digest-form assertion is not evidence of a built, scanned or deployed artifact.',
      'The three npm dependency input pairs are server, alpha and separate host-side identity; math/deps.edn is only a declaration and host PHP/WordPress are outside that npm lock scope.',
      'Successful command exit means only that this bounded offline inventory completed. KEEP_CLOSED cannot be changed to GO and is not owner, deployment, participant-testing or activation approval.',
    ],
  };
}
export function safeFailure(error) {
  return { schemaVersion: 1, classification: 'KEEP_CLOSED', inventoryComplete: false, deployable: false, activationAuthority: false,
    error: codes.has(error?.code) ? error.code : 'INVENTORY_FAILED', message: 'Offline inventory rejected; no source content, private path or raw diagnostic is included.' };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 2) fail('ARGUMENTS_REJECTED');
    const root = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
    console.log(JSON.stringify(inventoryRepository(root), null, 2));
  } catch (error) { console.log(JSON.stringify(safeFailure(error), null, 2)); process.exitCode = 1; }
}
