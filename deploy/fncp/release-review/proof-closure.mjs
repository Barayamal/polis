#!/usr/bin/env node
/** Read-only, manually reviewed, digest-pinned FIRST-PARTY proof source closure.
 * No application imports, parser inference, runtime/configuration reads, network,
 * dependency installation, archive generation or deployment authority. */
import { constants, closeSync, fstatSync, lstatSync, openSync, readFileSync, realpathSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, isAbsolute, join, parse, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { safeSourcePath } from './inventory.mjs';

const SOURCE_DIRECTORY = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const MAX_FILE_BYTES = 131_072;
const MAX_TOTAL_BYTES = 1_048_576;
const hash = value => createHash('sha256').update(value).digest('hex');
const failure = () => new Error('Proof source closure rejected; KEEP_CLOSED.');
const need = condition => { if (!condition) throw failure(); };
const module = (path, sha256, imports = [], assets = [], packages = []) => ({ path, sha256, kind: 'JS_SOURCE', imports, assets, packages });
const input = (path, sha256, kind) => ({ path, sha256, kind, imports: [], assets: [], packages: [] });
const files = [
  module('activation-foundation/authority.mjs', '00d30718cbbc72e6988d1029ad05fae76866d3eaa1923e34f9456f112604e7de'),
  module('activation-foundation/controlled-access.mjs', 'e1514d857d56186be29694656e602d563c5afa1b5ff2422a85426bdc738bdc17', ['local-access/access-server.mjs', 'activation-foundation/authority.mjs']),
  module('activation-foundation/synthetic-fixtures.mjs', 'f505fc9b16b0d1acc9fddd51e967e590aea677909fce45afd672c62c115f709b', ['activation-foundation/authority.mjs']),
  module('identity-foundation/bounded-response.mjs', 'd4f5ef4cf0c32bc2a85569ac196734a6626d98c654a1c6cc68961df57ec2f2fc'),
  module('identity-foundation/https-redirect-driver.mjs', '59208cec8e3bfb01d0ccdac222c92874a8dbb768a24fcb68d663eb7764f1b1e0'),
  module('identity-foundation/identity.mjs', 'a184deecafc5d93f692f36a1903ae02582f89a9761a67f450984a21e7e714b9b', ['identity-foundation/bounded-response.mjs'], [], ['openid-client']),
  input('identity-foundation/package-lock.json', 'c5a6cc0ac895f020e6cee0c365841a9450f7d326ed8ed8c982a10c695e7685e4', 'DEPENDENCY_INPUT'),
  input('identity-foundation/package.json', '733d987a14e610e316c6577b875d4e7ee9dab7797f8a123d3ba3524924a18cae', 'DEPENDENCY_INPUT'),
  module('identity-foundation/synthetic-browser-driver.mjs', '815d3f0d1199579905c103bf8c4899eab76b63d4f8231aadfbfb0f57de8308f3'),
  module('identity-foundation/synthetic-harness.mjs', 'c4fa23c258d86fa4983ac9744bb074f7788a635d192078524dff84a5c56ca249', ['identity-foundation/identity.mjs'], [], ['jose']),
  module('integrated-journey/proof-harness.mjs', '51d306e19a74b49aa6568415682a91b5de0cb76e15f81ea08da545f485532872', ['identity-foundation/synthetic-harness.mjs', 'identity-foundation/synthetic-browser-driver.mjs', 'activation-foundation/controlled-access.mjs', 'activation-foundation/synthetic-fixtures.mjs', 'local-access/access-server.mjs', 'local-access/wordpress-receiver.mjs', 'local-browser/browser-server.mjs', 'local-browser/integration-client.mjs', 'wordpress-identity/registration-issuer.mjs', 'wordpress-identity/server-registration.mjs']),
  module('local-access/access-server.mjs', '8e473583d319d472b681a7b3d89944375af0a8ff67e15d325516a4816d32c02c', ['local-access/wordpress-events.mjs']),
  module('local-access/staging-config.mjs', '0d5e9a6929b1576c651b046f95b3cc221b0eb051c5e77f0b451bbfd7ec17faf9', ['local-access/access-server.mjs']),
  module('local-access/start.mjs', 'ec2cb90d799b1ce8e8f47e4bdf583985b63a257ddf231b49c8851dd6c387dbbf', ['local-access/access-server.mjs', 'local-access/staging-config.mjs', 'local-access/wordpress-receiver.mjs']),
  module('local-access/wordpress-events.mjs', '6b788642c97c40d25ab76ca6be37f62f667ad5c594d089c9221f4c3b8b0a1889'),
  module('local-access/wordpress-receiver.mjs', 'e3b18dd37326435b4d78cdc3d4cffe0bcbc8015bc5a53d4653a0059464cf5369', ['local-access/wordpress-events.mjs']),
  module('local-browser/browser-server.mjs', '62472db9c92e0d2c1f5ae3888dd22b5c7d846c5b9a7ce4c21c1f7dd25ae6ebd0', [], ['seed-statements.json', 'local-browser/public/index.html', 'local-browser/public/app.js', 'local-browser/public/style.css']),
  module('local-browser/integration-client.mjs', 'd2e244da17c1e95b522bfd0ae1c5bb289611624d2cb4f7484eafa5740a22f97b'),
  input('local-browser/public/app.js', 'b60a8d4336f7e458a760fc46ac577f0df4c80d79e37efe3bd2d7345759c365ba', 'BROWSER_ASSET'),
  input('local-browser/public/index.html', '93aae1de9d7e801e7af5d65207a4c91100eecb0a020c2bef3a3a11956fda68ec', 'BROWSER_ASSET'),
  input('local-browser/public/style.css', '3d16788066f4d38aeb142aaa4136d658aeed595cccc66ae166bee807f8657cbc', 'BROWSER_ASSET'),
  module('local-browser/start.mjs', 'f4d5a90641f1c3ad6d0e2946825d31b9b40f6f6a648f91b02219493c0a28d59e', ['local-browser/browser-server.mjs']),
  input('seed-statements.json', 'b8c49ddaab72740df997b4975e84b0a51501fa97e1c622420826f4840bc6e06b', 'BROWSER_ASSET'),
  module('strict-service/service.mjs', 'f6701d2293f87abf7ebdc65ff9f7c38e301cd3631bf530034ad0815acf101069', ['activation-foundation/controlled-access.mjs', 'local-access/access-server.mjs', 'local-access/wordpress-receiver.mjs', 'local-browser/browser-server.mjs', 'wordpress-identity/registration-issuer.mjs', 'wordpress-identity/server-registration.mjs', 'strict-service/supervisor.mjs']),
  module('strict-service/supervisor.mjs', '65ddfaad4ac3b908ae3e7ffe5aef497f0304f88c7543c067322b5d8648ef7aaf'),
  module('wordpress-identity/registration-issuer.mjs', '726f37e570c165270320d9d2a16ce4c14b1f018da3cabedfc8d9dce8b5f3aeda'),
  module('wordpress-identity/server-registration.mjs', 'c51ccedce51938b8319798f1aac46a043ca97fcaec22f8626b4a2933f4161be7', ['wordpress-identity/registration-issuer.mjs']),
];
function freeze(value) {
  for (const child of Object.values(value)) if (child && typeof child === 'object') freeze(child);
  return Object.freeze(value);
}
export const REVIEWED_PROOF_CLOSURE = freeze({ schemaVersion: 1,
  entrypoints: [
    { path: 'local-access/start.mjs', kind: 'LEGACY_FIXTURE_EXECUTABLE_NOT_STRICT_COMPOSITION' },
    { path: 'local-browser/start.mjs', kind: 'LEGACY_FIXTURE_EXECUTABLE_NOT_STRICT_COMPOSITION' },
    { path: 'integrated-journey/proof-harness.mjs', kind: 'IN_PROCESS_SYNTHETIC_PROOF_FACTORY_NOT_DEPLOYABLE_SERVICE' },
    { path: 'strict-service/service.mjs', kind: 'PROGRAMMATIC_STRICT_LOCAL_COMPOSITION_NOT_PRODUCTION_CLI' },
    { path: 'identity-foundation/https-redirect-driver.mjs', kind: 'PURE_INJECTED_HTTPS_REDIRECT_COORDINATOR_NOT_PROVIDER_OR_DEPLOYMENT' },
  ], files,
  dependencyInputs: ['identity-foundation/package.json', 'identity-foundation/package-lock.json'],
  declaredLockedPackages: [{ name: 'openid-client', version: '6.8.8' }, { name: 'jose', version: '6.2.12' }, { name: 'oauth4webapi', version: '3.8.8' }],
});
export const PROOF_SOURCE_PATHS = Object.freeze(files.map(file => file.path));

function reviewGraph() {
  const seen = new Set();
  const visit = path => {
    if (seen.has(path)) return;
    const entry = files.find(file => file.path === path); need(entry); seen.add(path);
    for (const child of [...entry.imports, ...entry.assets]) visit(child);
  };
  for (const entry of REVIEWED_PROOF_CLOSURE.entrypoints) visit(entry.path);
  for (const path of REVIEWED_PROOF_CLOSURE.dependencyInputs) visit(path);
  need(seen.size === files.length && new Set(PROOF_SOURCE_PATHS).size === files.length);
  for (const file of files) safeSourcePath(file.path);
}

/** Exact immutable review manifest only: caller-created manifests cannot bless
 * changed bytes. Hash pins are manually reviewed, not inferred from JS parsing. */
export function validateProofSourceClosure(sourceFiles, manifest = REVIEWED_PROOF_CLOSURE) {
  try {
    need(manifest === REVIEWED_PROOF_CLOSURE);
    reviewGraph();
    need(sourceFiles instanceof Map && Object.getPrototypeOf(sourceFiles) === Map.prototype &&
      Reflect.ownKeys(sourceFiles).length === 0 && sourceFiles.size === files.length);
    const sources = new Map();
    for (const [path, source] of Map.prototype.entries.call(sourceFiles)) {
      need(typeof path === 'string' && PROOF_SOURCE_PATHS.includes(path) && typeof source === 'string');
      sources.set(path, source);
    }
    let totalBytes = 0;
    const measured = files.map(file => {
      const source = Map.prototype.get.call(sources, file.path);
      need(typeof source === 'string');
      const bytes = Buffer.byteLength(source); totalBytes += bytes;
      need(bytes > 0 && bytes <= MAX_FILE_BYTES && totalBytes <= MAX_TOTAL_BYTES && hash(source) === file.sha256);
      return { ...file, bytes };
    });
    return {
      schemaVersion: 1, classification: 'KEEP_CLOSED', check: 'MANUALLY_REVIEWED_PINNED_FIRST_PARTY_PROOF_SOURCE_CLOSURE',
      reviewedSourceClosureMatches: true, fullReleaseClosure: false, deployable: false, activationAuthority: false,
      coverage: { sourceFiles: files.length, jsModules: files.filter(file => file.kind === 'JS_SOURCE').length,
        browserAssets: files.filter(file => file.kind === 'BROWSER_ASSET').length,
        dependencyInputs: REVIEWED_PROOF_CLOSURE.dependencyInputs.length,
        firstPartyImportEdges: files.reduce((count, file) => count + file.imports.length, 0),
        staticAssetEdges: files.reduce((count, file) => count + file.assets.length, 0), bytes: totalBytes,
        sourceExecuted: false, runtimeServicesImportedOrStarted: false, environmentOrPrivateStateRead: false,
        networkUsed: false, dependenciesInstalled: false, archiveWritten: false, imagesBuilt: false },
      entrypoints: REVIEWED_PROOF_CLOSURE.entrypoints,
      declaredLockedPackages: REVIEWED_PROOF_CLOSURE.declaredLockedPackages,
      manifestSha256: hash(JSON.stringify(REVIEWED_PROOF_CLOSURE)), sourceClosureSha256: hash(JSON.stringify(measured)),
      files: measured,
      gaps: [
        'This is the manually reviewed first-party import/static-asset list of two legacy launchers, one strict proof factory, one programmatic strict local composition and one pure injected HTTPS redirect coordinator, not parser-derived dependency discovery or complete runtime/release closure.',
        'The strict proof shares opaque principal objects and in-process verification capabilities. It is not a multi-process authentication protocol; splitting it into Docker services needs a separately reviewed authority boundary.',
        'The legacy launchers do not wire strict signed identity and activation. They remain fixture-only, not an alternative production entrypoint.',
        'The strict local composition has no runtime test signer/injector imports, but its identity, driver, provider and optional registration transports are trusted in-process injected adapters; their caller-selected implementations are not discovered or attested by this graph. It is not a production CLI or deployment configuration.',
        'The pure HTTPS redirect coordinator is an explicit separate component root, not a discovered service import. It injects a trusted identity foundation and contains no issuer, TLS lab, signer or network default. Source pinning does not prove real browser navigation, an approved real identity provider, production TLS, or participant readiness.',
        'Installed npm dependency bytes, Node and operating-system packages, WordPress core/PHP/plugins/MySQL, Pol.is source/images/PostgreSQL, recovery tooling and real identity/mail/hosting are outside this closure.',
        'Runtime configuration, environment files, private keys, certificates, generated stores, credentials and evidence are excluded and unread. Their source references are not packaged configuration.',
        'Source pins require explicit rereview after drift. Hash equality is neither a publisher signature nor security certification, and cannot approve deployment, external messages, participant testing or launch.',
      ],
    };
  } catch { throw failure(); }
}

function plainDirectory(path) {
  need(typeof path === 'string' && isAbsolute(path) && resolve(path) === path && realpathSync(path) === path);
  let current = parse(path).root;
  for (const part of path.slice(current.length).split('/').filter(Boolean)) {
    current = join(current, part); const stat = lstatSync(current);
    need(stat.isDirectory() && !stat.isSymbolicLink());
  }
}
function readSource(root, path) {
  safeSourcePath(path);
  const target = join(root, path); plainDirectory(dirname(target));
  const before = lstatSync(target);
  need(before.isFile() && !before.isSymbolicLink() && before.nlink === 1 &&
    before.size > 0 && before.size <= MAX_FILE_BYTES && realpathSync(target) === target);
  let fd;
  try {
    fd = openSync(target, constants.O_RDONLY | constants.O_NOFOLLOW);
    const opened = fstatSync(fd);
    need(opened.isFile() && opened.nlink === 1 && opened.dev === before.dev && opened.ino === before.ino && opened.size === before.size);
    const bytes = readFileSync(fd); const after = fstatSync(fd); const current = lstatSync(target);
    need(bytes.length === before.size && after.isFile() && after.nlink === 1 && after.size === before.size &&
      after.mtimeMs === before.mtimeMs && after.ctimeMs === before.ctimeMs &&
      current.isFile() && !current.isSymbolicLink() && current.nlink === 1 && current.ino === before.ino && current.dev === before.dev &&
      current.size === before.size && current.mtimeMs === before.mtimeMs && current.ctimeMs === before.ctimeMs && realpathSync(target) === target);
    const source = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    need(Buffer.from(source).equals(bytes)); return source;
  } finally { if (fd !== undefined) closeSync(fd); }
}

/** Reads exactly 27 fixed public-source paths twice. No traversal into runtime,
 * environment, dependencies or private state. Root override exists for tests;
 * CLI accepts none. Ordinary drift checks are not an atomic filesystem sandbox. */
export function inspectProofSourceClosure(sourceDirectory = SOURCE_DIRECTORY, manifest = REVIEWED_PROOF_CLOSURE) {
  try {
    need(manifest === REVIEWED_PROOF_CLOSURE); plainDirectory(sourceDirectory);
    const sources = new Map(PROOF_SOURCE_PATHS.map(path => [path, readSource(sourceDirectory, path)]));
    const result = validateProofSourceClosure(sources, manifest);
    for (const path of PROOF_SOURCE_PATHS) need(readSource(sourceDirectory, path) === sources.get(path));
    return result;
  } catch { throw failure(); }
}
export function proofClosureFailure() {
  return { schemaVersion: 1, classification: 'KEEP_CLOSED', reviewedSourceClosureMatches: false,
    fullReleaseClosure: false, deployable: false, activationAuthority: false,
    error: 'PROOF_SOURCE_CLOSURE_REJECTED', message: 'Pinned proof source closure rejected; no raw source, private path or diagnostic is included.' };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    need(process.argv.length === 2);
    console.log(JSON.stringify(inspectProofSourceClosure(), null, 2));
  } catch { console.log(JSON.stringify(proofClosureFailure(), null, 2)); process.exitCode = 1; }
}
