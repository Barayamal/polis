import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, writeFile, rm, realpath, stat, readFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname, resolve, relative } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createCandidateSourceLock } from './candidate-source-lock.mjs';
import { BUILD_RECIPES, WORDPRESS_CVE_2025_3891_PROOF_COMMAND, candidateBuildArguments, copiedSourceBindings,
  validateBuiltImage, validateCandidateSbom, validateWordpressCve20253891Proof, scanCandidateRelease } from './collect-candidate-release.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
const denied = /FNCP_CANDIDATE_COLLECTION_REJECTED/u;
const source = { sourceRevision: 'a'.repeat(40), sourceFingerprint: 'b'.repeat(64),
  files: Object.values(BUILD_RECIPES).map(recipe => ({ path: recipe.dockerfile, sha256: 'c'.repeat(64) })) };
const id = 'sha256:' + 'd'.repeat(64);
function image() { return { Id: id, Architecture: 'arm64', Os: 'linux', Size: 1024, RootFS: { Type: 'layers', Layers: ['sha256:' + 'e'.repeat(64)] },
  Config: { User: '1000:1000', Labels: { 'org.opencontainers.image.revision': source.sourceRevision,
    'org.barayamal.fncp.source-fingerprint': source.sourceFingerprint, 'org.barayamal.fncp.release-profile': 'FNCP_PRODUCTION_COMPOSE_V3',
    'org.barayamal.fncp.zlib.remediation':'CVE-2026-85091-df84af25dc1942490e1d1c899a07619152a46148' } } }; }
function sbom(row) {
  const config = Buffer.from(JSON.stringify({ architecture: row.Architecture, os: row.Os, rootfs: { diff_ids: row.RootFS.Layers }, config: { Labels: row.Config.Labels } }));
  const imageID = 'sha256:' + hash(config), manifest = Buffer.from(JSON.stringify({ schemaVersion: 2, config: { digest: imageID } }));
  return { artifacts: [], source: { type: 'image', metadata: { userInput: id, imageID, manifestDigest: 'sha256:' + hash(manifest),
    config: config.toString('base64'), manifest: manifest.toString('base64') } } };
}

test('all ten build recipes use immutable IDs, source labels and fixed ARM64 platform without starting Compose', () => {
  assert.equal(Object.keys(BUILD_RECIPES).length, 10);
  for (const role of Object.keys(BUILD_RECIPES)) {
    const args = candidateBuildArguments('/reviewed/repository', source, role, '/new/evidence/' + role);
    assert.equal(args[0], 'build'); assert.ok(args.includes('linux/arm64')); assert.ok(args.includes('SOURCE_REVISION=' + source.sourceRevision));
    assert.ok(args.includes('org.barayamal.fncp.source-fingerprint=' + source.sourceFingerprint));
    assert.equal(args.includes('-t'), false); assert.equal(args.includes('--push'), false); assert.equal(args.includes('--load'), false);
    assert.equal(args.includes('--target'), ['api','math'].includes(role));
  }
});
test('MariaDB candidate receives both required private-recipe arguments', () => {
  const args = candidateBuildArguments('/repository', source, 'mariadb', '/evidence/iid');
  assert.ok(args.includes('BASE_SOURCE_REVISION=' + source.sourceRevision));
  assert.ok(args.includes('CANDIDATE_DOCKERFILE_SHA256=' + 'c'.repeat(64)));
  assert.ok(args.includes('/repository/deploy/fncp/production-security/Dockerfile.mariadb-candidate'));
});
test('unknown recipe and missing Dockerfile provenance reject', () => {
  assert.throws(() => candidateBuildArguments('/repository', source, 'unreviewed', '/evidence/iid'), denied);
  assert.throws(() => candidateBuildArguments('/repository', { ...source, files: [] }, 'edge', '/evidence/iid'), denied);
  assert.throws(() => copiedSourceBindings(source, 'unknown'), denied);
});
test('exact image provenance rejects architecture, ID, source and profile substitutions', () => {
  assert.equal(validateBuiltImage(image(), source, 'edge', id).imageId, id);
  for (const mutate of [
    row => { row.Architecture = 'amd64'; }, row => { row.Id = 'sha256:' + '0'.repeat(64); },
    row => { row.Config.Labels['org.opencontainers.image.revision'] = '0'.repeat(40); },
    row => { row.Config.Labels['org.barayamal.fncp.source-fingerprint'] = '0'.repeat(64); },
    row => { row.Config.Labels['org.barayamal.fncp.release-profile'] = 'FNCP_PRODUCTION_COMPOSE_V1'; },
  ]) { const row = image(); mutate(row); assert.throws(() => validateBuiltImage(row, source, 'edge', id), denied); }
});
test('Syft config and manifest digest chains bind exact requested image and engine layer chain', () => {
  const row = image(), doc = sbom(row), result = validateCandidateSbom(doc, row, source, 'edge', id);
  assert.equal(result.diffIdsMatchEngine, true); assert.equal(result.requestedImageId, id);
  assert.notEqual(result.configDigest, id); // Index/config/platform digests have different roles.
});
test('SBOM user input, config/manifest substitution and layer-chain disagreement reject', () => {
  for (const mutate of [
    doc => { doc.source.metadata.userInput = 'mutable:tag'; },
    doc => { doc.source.metadata.config = Buffer.from('{}').toString('base64'); },
    doc => { doc.source.metadata.manifest = Buffer.from('{}').toString('base64'); },
    doc => { doc.source.type = 'directory'; },
  ]) { const row = image(), doc = sbom(row); mutate(doc); assert.throws(() => validateCandidateSbom(doc, row, source, 'edge', id), denied); }
  const row = image(), doc = sbom(row); row.RootFS.Layers = ['sha256:' + 'f'.repeat(64)];
  assert.throws(() => validateCandidateSbom(doc, row, source, 'edge', id), denied);
});
test('edge source closure includes runtime dependencies and excludes QA/signing helpers', () => {
  const files = ['production-edge/edge','production-edge/material','production-edge/main','production-service/custody','production-service/contracts']
    .map(path => ({ path: 'deploy/fncp/' + path + '.mjs', sha256: 'f'.repeat(64) }));
  files.push({ path: 'deploy/fncp/production-install/qa/actor.mjs', sha256: 'e'.repeat(64) });
  const pairs = copiedSourceBindings({ files }, 'edge'); assert.equal(pairs.length, 5);
  assert.ok(pairs.every(pair => !pair.sourcePath.includes('/qa/')));
  assert.deepEqual(pairs.map(pair => pair.imagePath), pairs.map(pair => '/app/' + pair.sourcePath));
  assert.throws(() => copiedSourceBindings({ files: files.slice(1) }, 'edge'), denied);
});
test('operator gateway source closure contains only its fixed opaque transport', () => {
  const files = ['gateway','main'].map(name => ({ path: 'deploy/fncp/production-operator/' + name + '.mjs', sha256: 'f'.repeat(64) }));
  const pairs = copiedSourceBindings({ files }, 'operator');
  assert.deepEqual(pairs.map(pair => pair.imagePath), pairs.map(pair => '/app/' + pair.sourcePath));
  assert.throws(() => copiedSourceBindings({ files: files.slice(1) }, 'operator'), denied);
});
test('participant image source inventory closes every relative runtime module import', async () => {
  const root=resolve(import.meta.dirname,'../../..');
  // This checks the import graph, not whole-tree release custody. Other suites
  // create transient build fixtures concurrently; an exact source lock requires
  // a quiescent checkout and is separately tested in candidate-source-lock.
  const files=[];
  for(const folder of ['production-identity','production-provider','production-activation','production-service']){
    for(const name of await readdir(join(root,'deploy/fncp',folder)))if(name.endsWith('.mjs'))files.push({path:'deploy/fncp/'+folder+'/'+name,sha256:'f'.repeat(64)});
  }
  for(const name of await readdir(join(root,'deploy/fncp/production-service/public')))files.push({path:'deploy/fncp/production-service/public/'+name,sha256:'f'.repeat(64)});
  const pairs=copiedSourceBindings({files},'participant'),available=new Set(pairs.map(p=>p.sourcePath));
  const recipe=await readFile(join(root,BUILD_RECIPES.participant.dockerfile),'utf8');
  for(const pair of pairs.filter(p=>p.sourcePath.endsWith('.mjs'))){
    const content=await readFile(join(root,pair.sourcePath),'utf8');
    for(const match of content.matchAll(/\bfrom\s+['"](\.[^'"]+)['"]|\bimport\s+['"](\.[^'"]+)['"]/gu)){
      const imported=relative(root,resolve(dirname(join(root,pair.sourcePath)),match[1]??match[2]));
      assert.ok(available.has(imported),'missing runtime import: '+imported);
    }
    assert.ok(recipe.split('\n').some(line=>line.startsWith('COPY ')&&line.includes(pair.sourcePath+' ')), 'missing image copy: '+pair.sourcePath);
  }
});
test('vendor-derived MariaDB has no invented source-copy assertion', () => {
  assert.deepEqual(copiedSourceBindings(source, 'mariadb'), []);
});

test('WordPress CVE-2025-3891 proof checks the affected module, directive and loaded modules without suppressing the raw finding', () => {
  assert.match(WORDPRESS_CVE_2025_3891_PROOF_COMMAND, /mod_auth_openidc\.so/u);
  assert.match(WORDPRESS_CVE_2025_3891_PROOF_COMMAND, /OIDCPreservePost/u);
  assert.match(WORDPRESS_CVE_2025_3891_PROOF_COMMAND, /httpd -M/u);
  const proof = validateWordpressCve20253891Proof(
    'affected_component_absent=true\naffected_directive_unset=true\naffected_module_unloaded=true\n', id);
  assert.equal(proof.disposition, 'NOT_APPLICABLE_TO_INSTALLED_CONFIGURATION');
  assert.equal(proof.rawFindingRetained, true); assert.equal(proof.scannerSuppression, false);
  assert.throws(() => validateWordpressCve20253891Proof('affected_component_absent=true\n', id), denied);
});

test('collector keeps one fresh advisory update bounded without using a stale shared host cache', async () => {
  const sourceText = await import('node:fs/promises').then(fs => fs.readFile(new URL('./collect-candidate-release.mjs', import.meta.url), 'utf8'));
  assert.match(sourceText, /grype-db-update[\s\S]{0,300}network: 'bridge'[\s\S]{0,300}timeout: 900000/u);
  assert.match(sourceText, /const cache = await c\.volume\('grype-cache'\)/u);
});

test('scan-only refuses stale or substituted source/image locks before any engine access or evidence creation', async t => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'fncp-scan-phase-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const git = args => {
    const result = spawnSync('git', ['-C',root,...args], { encoding: 'utf8', env: {
      PATH: process.env.PATH, HOME: root, LANG: 'C', GIT_CONFIG_NOSYSTEM: '1',
      GIT_AUTHOR_NAME: 'Synthetic', GIT_AUTHOR_EMAIL: 'synthetic@example.invalid',
      GIT_COMMITTER_NAME: 'Synthetic', GIT_COMMITTER_EMAIL: 'synthetic@example.invalid',
    }}); assert.equal(result.status, 0, result.stderr); return result.stdout.trim();
  };
  git(['init','--quiet']); await writeFile(join(root,'source.mjs'), 'export const value = 1;\n');
  git(['add','.']); git(['update-ref','HEAD',git(['commit-tree',git(['write-tree']),'-m','Synthetic fixture'])]);
  const locked = await createCandidateSourceLock(root), destination = join(root,'not-created');
  const images = Object.fromEntries(Object.keys(BUILD_RECIPES).map((role,index) => [role,'sha256:' + String(index + 1).padStart(64,'0')]));
  const imageLock = { version: 3, sourceRevision: locked.sourceRevision, sourceFingerprint: locked.sourceFingerprint, images };
  let socketRead = false;
  const options = { root, destination, sourceLock: locked, imageLock,
    get socket() { socketRead = true; throw new Error('ENGINE_MUST_NOT_BE_ACCESSED'); } };
  await writeFile(join(root,'source.mjs'), 'export const value = 2;\n');
  await assert.rejects(scanCandidateRelease(options), denied);
  await writeFile(join(root,'source.mjs'), 'export const value = 1;\n');
  options.imageLock = { ...imageLock, sourceFingerprint: '0'.repeat(64) };
  await assert.rejects(scanCandidateRelease(options), denied);
  assert.equal(socketRead, false); await assert.rejects(stat(destination), { code: 'ENOENT' });
});
