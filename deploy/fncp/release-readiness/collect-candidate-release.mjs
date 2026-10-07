// Explicit dedicated-engine build/scan collector. No deployment, application
// state, published ports, activation, pruning, tags, or external writes.
import { spawn } from 'node:child_process';
import { mkdir, writeFile, readFile, lstat, realpath } from 'node:fs/promises';
import { isAbsolute, resolve, join, relative } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash, randomBytes } from 'node:crypto';
import { createCandidateSourceLock, validateCandidateSourceLock, validateCandidateReleaseLock } from './candidate-source-lock.mjs';
import { imageRoles } from '../production-deployment/compose.mjs';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const reject = () => { throw new Error('FNCP_CANDIDATE_COLLECTION_REJECTED'); };
const DIGEST = /^sha256:[a-f0-9]{64}$/u;
const LABEL = 'org.barayamal.fncp.collection';
const RELEASE_VERSION = 3;
const RELEASE_PROFILE = 'FNCP_PRODUCTION_COMPOSE_V3';
const ZLIB_ROLES = Object.freeze(['api','math','postgres','migration','participant','wordpress','proxy','edge','operator']);
const ZLIB_COMMIT = 'df84af25dc1942490e1d1c899a07619152a46148';
const ZLIB_PATCH_SHA256 = '2e1c40f9ba33c29a2e43c9121970513ef1f70e3a0238e73d724fac56d8af4294';
export const WORDPRESS_CVE_2025_3891_PROOF_COMMAND = [
  'test ! -e /usr/lib/apache2/mod_auth_openidc.so',
  '! grep -R -E "^[[:space:]]*(LoadModule[[:space:]]+auth_openidc_module|OIDCPreservePost)" /etc/apache2 /usr/src/wordpress 2>/dev/null',
  '! httpd -M 2>/dev/null | grep -q auth_openidc_module',
  "printf '%s\\n' 'affected_component_absent=true' 'affected_directive_unset=true' 'affected_module_unloaded=true'",
].join('; ');
const publicJson = value => JSON.stringify(value, null, 2) + '\n';
/** Preserve an isolated empty Docker configuration while discovering installed
 * CLI plugins. No credentials or current context are copied from user config. */
export async function dockerPluginDirectories(names = ['buildx']) {
  if (!Array.isArray(names) || !names.length || names.some(name => !['buildx','compose'].includes(name)) || new Set(names).size !== names.length) reject();
  const candidates = ['/opt/homebrew/lib/docker/cli-plugins','/usr/local/lib/docker/cli-plugins',
    '/usr/libexec/docker/cli-plugins','/usr/lib/docker/cli-plugins',join(process.env.HOME ?? '/nonexistent', '.docker/cli-plugins')];
  const found = [];
  for (const name of names) {
    let selected = null;
    for (const directory of candidates) {
      try {
        const path = await realpath(join(directory, 'docker-' + name)), stat = await lstat(path);
        if (stat.isFile() && stat.nlink === 1 && stat.mode & 0o111 && !(stat.mode & 0o022)) { selected = await realpath(directory); break; }
      } catch {}
    }
    if (selected === null) reject(); found.push(selected);
  }
  return [...new Set(found)];
}
export const BUILD_RECIPES = Object.freeze({
  api: Object.freeze({ context: 'server', dockerfile: 'server/Dockerfile', target: 'fncp-production' }),
  math: Object.freeze({ context: 'math', dockerfile: 'math/Dockerfile', target: 'fncp-production' }),
  postgres: Object.freeze({ context: 'server', dockerfile: 'server/Dockerfile-selfhost-db' }),
  migration: Object.freeze({ context: 'server', dockerfile: 'server/Dockerfile-migrate' }),
  participant: Object.freeze({ context: '.', dockerfile: 'deploy/fncp/production-deployment/Dockerfile' }),
  wordpress: Object.freeze({ context: '.', dockerfile: 'deploy/fncp/production-deployment/Dockerfile.wordpress' }),
  mariadb: Object.freeze({ context: '.', dockerfile: 'deploy/fncp/production-security/Dockerfile.mariadb-candidate' }),
  proxy: Object.freeze({ context: '.', dockerfile: 'deploy/fncp/production-deployment/Dockerfile.proxy' }),
  edge: Object.freeze({ context: '.', dockerfile: 'deploy/fncp/production-edge/Dockerfile' }),
  operator: Object.freeze({ context: '.', dockerfile: 'deploy/fncp/production-operator/Dockerfile' }),
});

export function candidateBuildArguments(root, source, role, iidFile) {
  const recipe = BUILD_RECIPES[role];
  if (!recipe || !/^[a-f0-9]{40}$/u.test(source?.sourceRevision) || !/^[a-f0-9]{64}$/u.test(source?.sourceFingerprint)
    || !isAbsolute(root) || !isAbsolute(iidFile)) reject();
  const dockerfile = source.files.find(file => file.path === recipe.dockerfile);
  if (!dockerfile) reject();
  return ['build', '--platform', 'linux/arm64', '--build-arg', 'SOURCE_REVISION=' + source.sourceRevision,
    ...(role === 'mariadb' ? ['--build-arg', 'BASE_SOURCE_REVISION=' + source.sourceRevision,
      '--build-arg', 'CANDIDATE_DOCKERFILE_SHA256=' + dockerfile.sha256] : []),
    '--label', 'org.opencontainers.image.revision=' + source.sourceRevision,
    '--label', 'org.barayamal.fncp.source-fingerprint=' + source.sourceFingerprint,
    '--label', 'org.barayamal.fncp.release-profile=' + RELEASE_PROFILE,
    '--iidfile', iidFile, '-f', join(root, recipe.dockerfile),
    ...(recipe.target ? ['--target', recipe.target] : []), join(root, recipe.context)];
}

/** Explicit copy pairs: compilation output is deliberately not equated to source. */
export function copiedSourceBindings(source, role) {
  if (!BUILD_RECIPES[role]) reject();
  const available = new Map(source.files.map(file => [file.path, file.sha256])), pairs = [];
  const add = (sourcePath, imagePath) => {
    if (!available.has(sourcePath) || !imagePath.startsWith('/') || /[\s'"`$\\]/u.test(imagePath)) reject();
    pairs.push({ sourcePath, imagePath, sha256: available.get(sourcePath) });
  };
  const module = (folder, names) => names.forEach(name => add(`deploy/fncp/${folder}/${name}.mjs`, `/app/deploy/fncp/${folder}/${name}.mjs`));
  if (role === 'postgres') add('server/bin/fncp-initialize-database.sh', '/usr/local/bin/fncp-initialize-database');
  if (role === 'migration') {
    add('server/bin/fncp-run-migrations.sh', '/usr/local/bin/fncp-run-migrations');
    source.files.filter(file => /^server\/postgres\/migrations\/[^/]+\.sql$/u.test(file.path))
      .forEach(file => add(file.path, '/opt/fncp/migrations/' + file.path.split('/').at(-1)));
  }
  if (role === 'api') ['src/prompts/moderation/script.xml','src/prompts/report_experimental/system.xml']
    .forEach(path => add('server/' + path, '/app/' + path));
  if (role === 'math') source.files.filter(file => /^(math\/(src|resources|bin)\/|math\/system\.properties$)/u.test(file.path))
    .forEach(file => add(file.path, '/app/' + file.path.slice(5)));
  if (role === 'participant') {
    module('production-identity', ['identity','https-transport','relay-route']); module('production-provider', ['provider']);
    module('production-activation', ['authority','protocol']);
    module('production-service', ['access','browser','contracts','custody','event-receiver','main','operator','operator-cli','principal-boundary','service','store-schema','store-validation','wordpress-bridge']);
    source.files.filter(file => file.path.startsWith('deploy/fncp/production-service/public/')).forEach(file => add(file.path, '/app/' + file.path));
  }
  if (role === 'edge') { module('production-edge', ['edge','material','main']); module('production-service', ['custody','contracts']); }
  if (role === 'operator') module('production-operator', ['gateway','main']);
  if (role === 'proxy') ['nginx.conf','fncp-upstream.conf'].forEach(name => add('deploy/fncp/production-deployment/' + name, '/etc/nginx/' + name));
  if (role === 'wordpress') {
    for (const [name, path] of Object.entries({
      'apache-alpine.conf':'/etc/apache2/httpd.conf', 'apache.conf':'/etc/apache2/fncp-vhost.conf',
      'php-runtime.ini':'/etc/php83/conf.d/99-fncp.ini', 'wp-config.php':'/usr/src/wordpress/wp-config.php',
      'mu-loader.php':'/usr/src/wordpress/wp-content/mu-plugins/fncp-loader.php',
      'material.php':'/opt/fncp-wordpress/material.php', 'preflight.php':'/opt/fncp-wordpress/preflight.php',
      'start.sh':'/usr/local/bin/fncp-wordpress-start', 'apache2-foreground':'/usr/local/bin/apache2-foreground',
    })) add('deploy/fncp/production-deployment/wordpress-runtime/' + name, path);
    ['contract.php','store.php','fncp-production-wordpress.php'].forEach(name => add('deploy/fncp/production-wordpress/' + name, '/usr/src/wordpress/wp-content/mu-plugins/fncp-production/' + name));
  }
  return pairs;
}

export function validateBuiltImage(row, source, role, id) {
  if (!BUILD_RECIPES[role] || !DIGEST.test(id ?? '') || row?.Id !== id || row.Architecture !== 'arm64' || row.Os !== 'linux'
    || row.Config?.Labels?.['org.opencontainers.image.revision'] !== source.sourceRevision
    || row.Config?.Labels?.['org.barayamal.fncp.source-fingerprint'] !== source.sourceFingerprint
    || row.Config?.Labels?.['org.barayamal.fncp.release-profile'] !== RELEASE_PROFILE
    || ZLIB_ROLES.includes(role) && row.Config?.Labels?.['org.barayamal.fncp.zlib.remediation'] !== 'CVE-2026-85091-' + ZLIB_COMMIT) reject();
  return { role, imageId: id, architecture: row.Architecture, os: row.Os, user: row.Config.User,
    sourceRevision: source.sourceRevision, sourceFingerprint: source.sourceFingerprint, size: row.Size, rootfs: row.RootFS };
}

export function validateCandidateSbom(sbom, row, source, role, id) {
  validateBuiltImage(row, source, role, id);
  const metadata = sbom?.source?.metadata;
  if (!Array.isArray(sbom?.artifacts) || sbom.source.type !== 'image' || metadata?.userInput !== id
    || !DIGEST.test(metadata.imageID ?? '') || !DIGEST.test(metadata.manifestDigest ?? '')
    || typeof metadata.config !== 'string' || typeof metadata.manifest !== 'string') reject();
  const configBytes = Buffer.from(metadata.config, 'base64'), manifestBytes = Buffer.from(metadata.manifest, 'base64');
  if ('sha256:' + sha(configBytes) !== metadata.imageID || 'sha256:' + sha(manifestBytes) !== metadata.manifestDigest) reject();
  const config = JSON.parse(configBytes), manifest = JSON.parse(manifestBytes);
  if (manifest.config?.digest !== metadata.imageID || config.architecture !== 'arm64' || config.os !== 'linux'
    || JSON.stringify(config.rootfs?.diff_ids) !== JSON.stringify(row.RootFS?.Layers)
    || config.config?.Labels?.['org.opencontainers.image.revision'] !== source.sourceRevision
    || config.config?.Labels?.['org.barayamal.fncp.source-fingerprint'] !== source.sourceFingerprint) reject();
  return { requestedImageId: id, configDigest: metadata.imageID, platformManifestDigest: metadata.manifestDigest,
    diffIdsMatchEngine: true, sourceLabelsMatch: true };
}

function execute(args, { input, timeout = 600000 } = {}) {
  return new Promise(resolveResult => {
    const child = spawn('docker', args, { shell: false, env: { PATH: process.env.PATH, HOME: process.env.HOME,
      LANG: 'C', LC_ALL: 'C', DOCKER_CLI_HINTS: 'false', DOCKER_BUILDKIT: '1' }, stdio: ['pipe','pipe','pipe'] });
    const output = [], errors = []; let total = 0, failure = null;
    const timer = setTimeout(() => { failure = 'TIMEOUT'; child.kill('SIGKILL'); }, timeout);
    const consume = (target, bytes) => { total += bytes.length; if (total > 128 * 1024 * 1024) { failure = 'OUTPUT_LIMIT'; child.kill('SIGKILL'); } else target.push(bytes); };
    child.stdout.on('data', bytes => consume(output, bytes)); child.stderr.on('data', bytes => consume(errors, bytes));
    child.on('error', () => { failure = 'PROCESS'; }); child.stdin.on('error', () => {}); child.stdin.end(input);
    child.on('close', (status, signal) => { clearTimeout(timer); resolveResult({ status, signal, error: failure,
      stdout: Buffer.concat(output), stderr: Buffer.concat(errors) }); });
  });
}

async function collector({ root, socket, destination }) {
  if (typeof root !== 'string' || !isAbsolute(root) || resolve(root) !== root || await realpath(root) !== root
    || typeof destination !== 'string' || !isAbsolute(destination) || resolve(destination) !== destination
    || relative(root, destination) === '' || !relative(root, destination).startsWith('..' + '/')
    || typeof socket !== 'string' || !/^unix:\/\/\/[^\u0000-\u0020]*\/fncp-[a-z0-9-]+\/docker\.sock$/u.test(socket)) reject();
  const socketStat = await lstat(socket.slice(7));
  if (!socketStat.isSocket() || socketStat.isSymbolicLink() || socketStat.uid !== process.getuid()) reject();
  const source = await createCandidateSourceLock(root), token = randomBytes(12).toString('hex');
  await mkdir(destination, { mode: 0o700 });
  if (await realpath(destination) !== destination) reject();
  const write = (name, bytes) => writeFile(join(destination, name), typeof bytes === 'string' || Buffer.isBuffer(bytes) ? bytes : publicJson(bytes), { flag: 'wx', mode: 0o600 });
  await write('source-lock.json', source); await mkdir(join(destination, 'docker-config'), { mode: 0o700 });
  await write('docker-config/config.json', { cliPluginsExtraDirs: await dockerPluginDirectories() });
  const prefix = ['--host', socket, '--config', join(destination, 'docker-config')];
  let counter = 0, engineId = null;
  const owned = new Set(), ownedVolumes = new Set();
  const run = async (name, args, options) => {
    const startedAt = new Date().toISOString(), response = await execute([...prefix, ...args], options);
    const directory = 'commands/' + String(++counter).padStart(3, '0') + '-' + name;
    await mkdir(join(destination, directory), { recursive: true, mode: 0o700 });
    await write(directory + '/stdout', response.stdout); await write(directory + '/stderr', response.stderr);
    await write(directory + '/result.json', { startedAt, finishedAt: new Date().toISOString(), status: response.status, signal: response.signal, error: response.error });
    if (response.status !== 0 || response.signal || response.error) reject();
    return response.stdout.toString('utf8');
  };
  const engine = async () => {
    const info = JSON.parse(await run('engine', ['info','--format','{{json .}}']));
    if (!info.ID || info.OSType !== 'linux' || !['aarch64','arm64'].includes(info.Architecture) || engineId !== null && engineId !== info.ID) reject();
    engineId = info.ID; return { id: info.ID, os: info.OSType, architecture: info.Architecture, serverVersion: info.ServerVersion };
  };
  const container = async (name, image, args, { network = 'none', input, timeout, extra = [] } = {}) => {
    await engine(); const ownedName = `fncp-release-${token}-${name}`; owned.add(ownedName);
    const result = await run(name, ['run','--rm','--name',ownedName,'--label',LABEL + '=' + token,'--pull=never',
      '--platform','linux/arm64','--network',network,'--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
      '--pids-limit','128','--memory','1g','--cpus','2',...extra,...(input === undefined ? [] : ['-i']), image,...args], { input, timeout });
    owned.delete(ownedName); return result;
  };
  const cleanup = async () => {
    const results = []; await engine();
    for (const name of owned) {
      const observed = await execute([...prefix,'container','inspect',name]);
      if (observed.status !== 0) {
        if (observed.stderr.toString().includes('No such container')) { results.push({ name, absent: true }); continue; }
        reject();
      }
      const rows = JSON.parse(observed.stdout.toString());
      if (rows.length !== 1 || rows[0].Name !== '/' + name || rows[0].Config?.Labels?.[LABEL] !== token) reject();
      await run('owned-cleanup', ['rm','-f',rows[0].Id]); results.push({ name, removed: true });
    }
    for (const name of ownedVolumes) {
      const rows = JSON.parse(await run('inspect-cache-volume', ['volume','inspect',name]));
      if (rows.length !== 1 || rows[0].Name !== name || rows[0].Labels?.[LABEL] !== token) reject();
      await run('remove-cache-volume', ['volume','rm',name]); results.push({ volume: name, removed: true });
    }
    return results;
  };
  const volume = async purpose => {
    await engine(); const name = `fncp-release-${token}-${purpose}`;
    const absent = await execute([...prefix,'volume','inspect',name]);
    if (absent.status === 0 || !/no such volume/iu.test(absent.stderr.toString())) reject();
    ownedVolumes.add(name);
    await run('create-cache-volume', ['volume','create','--label',LABEL + '=' + token,name]);
    const rows = JSON.parse(await run('inspect-cache-volume', ['volume','inspect',name]));
    if (rows.length !== 1 || rows[0].Name !== name || rows[0].Labels?.[LABEL] !== token) reject();
    return name;
  };
  return { root, source, destination, token, write, run, engine, container, volume, cleanup };
}

async function copiedSourceProof(c, role, image) {
  const pairs = copiedSourceBindings(c.source, role);
  if (pairs.length) {
    const stdout = await c.container('source-' + role, image.imageId, ['-euc','sha256sum ' + pairs.map(pair => pair.imagePath).join(' ')], { extra: ['--entrypoint','/bin/sh'] });
    const lines = stdout.trim().split('\n');
    if (lines.length !== pairs.length) reject();
    for (let index = 0; index < pairs.length; index++) if (lines[index] !== pairs[index].sha256 + '  ' + pairs[index].imagePath) reject();
  }
  await c.write(`images/${role}/source-file-binding.json`, { ...image, exactCopiedSourceFiles: pairs,
    allComparedBytesEqual: true, compilationEquivalenceClaimed: false,
    scope: pairs.length ? 'Explicit copied sources only; dependency and compiled-output equivalence are not claimed.' : 'No project source is copied into this vendor-derived image; reviewed Dockerfile/build labels bind provenance.' });
  return pairs.length;
}

async function zlibRemediationProof(c, role, image) {
  if (!ZLIB_ROLES.includes(role)) return 0;
  const sourcePaths = ['server/zlib-fixed','math/zlib-fixed','deploy/fncp/production-security/zlib-fixed'];
  const source = new Map(c.source.files.map(file => [file.path,file.sha256]));
  const patchFiles = sourcePaths.map(path => ({path:path+'/df84af25.patch',sha256:source.get(path+'/df84af25.patch')}));
  const scripts = sourcePaths.map(path => ({path:path+'/build-fixed-zlib.sh',sha256:source.get(path+'/build-fixed-zlib.sh')}));
  if ([...patchFiles,...scripts].some(file => !/^[a-f0-9]{64}$/u.test(file.sha256))
    || new Set(patchFiles.map(file => file.sha256)).size !== 1 || patchFiles[0].sha256 !== ZLIB_PATCH_SHA256
    || new Set(scripts.map(file => file.sha256)).size !== 1) reject();
  const stdout=await c.container('zlib-'+role,image.imageId,['-euc',
    "cat /usr/share/fncp-security/zlib-provenance.txt; sha256sum /lib/libz.so.1.3.2; stat -c '%a:%u:%g' /usr/share/fncp-security/zlib-provenance.txt"],{extra:['--entrypoint','/bin/sh']});
  const lines=stdout.trim().split('\n'),receipt=Object.fromEntries(lines.slice(0,7).map(line=>{const i=line.indexOf('=');if(i<1)reject();return [line.slice(0,i),line.slice(i+1)];}));
  const binary=lines[7]?.split(/\s+/u)[0];
  if(lines.length!==9||receipt.profile!=='FNCP_ZLIB_SOURCE_REMEDIATION_V1'||receipt.version!=='1.3.2'
    ||receipt.archive_sha256!=='b99a0b86c0ba9360ec7e78c4f1e43b1cbdf1e6936c8fa0f6835c0cd694a495a1'
    ||receipt.patch_commit!==ZLIB_COMMIT||receipt.patch_sha256!==ZLIB_PATCH_SHA256||receipt.upstream_tests!=='PASS'
    ||!/^[a-f0-9]{64}$/u.test(binary)||binary!==receipt.binary_sha256||lines[8]!=='444:0:0')reject();
  await c.write(`images/${role}/zlib-remediation.json`,{role,imageId:image.imageId,cve:'CVE-2026-85091',upstreamCommit:ZLIB_COMMIT,
    runtimeLibrary:'/lib/libz.so.1.3.2',runtimeLibrarySha256:binary,provenance:'/usr/share/fncp-security/zlib-provenance.txt',provenanceMode:'0444',upstreamTests:'PASS',
    sourcePatchCopies:patchFiles,sourceBuildScriptCopies:scripts,scannerSuppression:false,distributionPackageRecordRetained:true});
  return 1;
}

export function validateWordpressCve20253891Proof(stdout, imageId) {
  if (stdout !== 'affected_component_absent=true\naffected_directive_unset=true\naffected_module_unloaded=true\n'
    || !DIGEST.test(imageId ?? '')) reject();
  return {
    role: 'wordpress', imageId, vulnerability: 'CVE-2025-3891', scannerMatchBasis: 'apache2 package CPE',
    affectedComponent: 'mod_auth_openidc', affectedComponentAbsent: true, affectedDirective: 'OIDCPreservePost',
    affectedDirectiveUnset: true, affectedModuleUnloaded: true,
    disposition: 'NOT_APPLICABLE_TO_INSTALLED_CONFIGURATION', rawFindingRetained: true, scannerSuppression: false,
  };
}

async function wordpressCve20253891Proof(c, role, image) {
  if (role !== 'wordpress') return 0;
  const stdout = await c.container('cve-2025-3891-wordpress', image.imageId,
    ['-euc', WORDPRESS_CVE_2025_3891_PROOF_COMMAND], { extra: ['--entrypoint','/bin/sh'] });
  await c.write('images/wordpress/cve-2025-3891-applicability.json', validateWordpressCve20253891Proof(stdout, image.imageId));
  return 1;
}

async function build(c) {
  const images = {};
  await c.write('engine.json', await c.engine());
  await c.run('buildx-version', ['buildx','version']);
  for (const role of imageRoles(RELEASE_VERSION)) {
    await validateCandidateSourceLock(c.root, c.source); await c.engine();
    await mkdir(join(c.destination, 'images', role), { recursive: true, mode: 0o700 });
    const iid = join(c.destination, 'images', role, 'iid');
    process.stdout.write(publicJson({ stage: 'BUILD', role }));
    await c.run('build-' + role, candidateBuildArguments(c.root, c.source, role, iid), { timeout: 1800000 });
    await validateCandidateSourceLock(c.root, c.source); await c.engine();
    const id = (await readFile(iid, 'utf8')).trim();
    const rows = JSON.parse(await c.run('inspect-' + role, ['image','inspect',id]));
    if (rows.length !== 1) reject();
    const image = validateBuiltImage(rows[0], c.source, role, id); images[role] = id;
    await c.write(`images/${role}/image.json`, image);
    const copiedSourceFiles = await copiedSourceProof(c, role, image);
    const zlibRemediation = await zlibRemediationProof(c, role, image);
    const wordpressCve20253891 = await wordpressCve20253891Proof(c, role, image);
    process.stdout.write(publicJson({ stage: 'BUILT', role, imageId: id, copiedSourceFiles, zlibRemediation, wordpressCve20253891 }));
  }
  const lock = validateCandidateReleaseLock(c.source, { version: RELEASE_VERSION, sourceRevision: c.source.sourceRevision, sourceFingerprint: c.source.sourceFingerprint, images }, RELEASE_VERSION);
  await validateCandidateSourceLock(c.root, c.source); await c.engine();
  await c.write('image-lock.json', lock); return lock;
}

async function scan(c, lock, verifyExistingCopies = false) {
  validateCandidateReleaseLock(c.source, lock, RELEASE_VERSION);
  const scannerSource = JSON.parse(await readFile(join(c.root, 'deploy/fncp/image-security.lock.json'), 'utf8'));
  const scanners = Object.fromEntries(['syft','grype'].map(name => {
    const matches = scannerSource.scannerImages.filter(item => item.name === name);
    if (matches.length !== 1 || !DIGEST.test(matches[0].arm64Digest) || !/^docker\.io\/anchore\/[a-z]+:v[0-9.]+$/u.test(matches[0].tag)) reject();
    return [name, matches[0].tag.replace(/:[^/:]+$/u, '') + '@' + matches[0].arm64Digest];
  }));
  await c.write('scanner-lock.json', { ...scanners, sourceLockPath: 'deploy/fncp/image-security.lock.json',
    sourceLockSha256: c.source.files.find(file => file.path === 'deploy/fncp/image-security.lock.json').sha256,
    advisoryFeed: 'One fresh feed update, followed by nine offline scans against that cache; each image retains its observed feed identity.', customIgnoreRules: [] });
  for (const [name, image] of Object.entries(scanners)) await c.run('pull-' + name, ['pull','--platform','linux/arm64',image]);
  const cache = await c.volume('grype-cache'), scratch = await c.volume('scanner-scratch');
  const scratchMount = ['--mount',`type=volume,src=${scratch},dst=/tmp,volume-nocopy`];
  const grypeOptions = ['-e','GRYPE_CHECK_FOR_APP_UPDATE=false','-e','GRYPE_EXTERNAL_SOURCES_ENABLE=false',
    '-e','GRYPE_DB_CACHE_DIR=/grype-cache', '--mount',`type=volume,src=${cache},dst=/grype-cache,volume-nocopy`,...scratchMount];
  // The signed advisory database can legitimately take longer than the generic
  // ten-minute container bound on a cold, rate-limited connection. Keep this
  // stage bounded, but give the single fresh update its own fifteen-minute cap.
  await c.container('grype-db-update', scanners.grype, ['db','update'], { network: 'bridge', extra: grypeOptions, timeout: 900000 });
  const database = JSON.parse(await c.container('grype-db-status', scanners.grype, ['db','status','-o','json'], {
    extra: [...grypeOptions,'-e','GRYPE_DB_AUTO_UPDATE=false'] }));
  if (database.valid !== true || typeof database.built !== 'string') reject();
  await c.write('scanner-database.json', database);
  const results = [];
  for (const role of imageRoles(RELEASE_VERSION)) {
    await validateCandidateSourceLock(c.root, c.source); await c.engine();
    const rows = JSON.parse(await c.run('scan-inspect-' + role, ['image','inspect',lock.images[role]]));
    if (rows.length !== 1) reject();
    const observedImage = validateBuiltImage(rows[0], c.source, role, lock.images[role]);
    if (verifyExistingCopies) {
      await mkdir(join(c.destination, 'images', role), { recursive: true, mode: 0o700 });
      await c.write(`images/${role}/image.json`, observedImage); await copiedSourceProof(c, role, observedImage); await zlibRemediationProof(c, role, observedImage);
      await wordpressCve20253891Proof(c, role, observedImage);
    }
    process.stdout.write(publicJson({ stage: 'SCAN', role, imageId: lock.images[role] }));
    await mkdir(join(c.destination, 'scans', role), { recursive: true, mode: 0o700 });
    const sbom = await c.container('sbom-' + role, scanners.syft, ['scan','docker:' + lock.images[role],'-o','syft-json'], {
      extra: ['-e','SYFT_CHECK_FOR_APP_UPDATE=false',...scratchMount,
        '-v','/var/run/docker.sock:/var/run/docker.sock:ro'] });
    const parsedSbom = JSON.parse(sbom);
    const imageBinding = validateCandidateSbom(parsedSbom, rows[0], c.source, role, lock.images[role]);
    await c.write(`scans/${role}/syft.json`, sbom);
    const raw = await c.container('grype-' + role, scanners.grype, ['-o','json'], { input: sbom,
      extra: [...grypeOptions,'-e','GRYPE_DB_AUTO_UPDATE=false'] });
    const report = JSON.parse(raw), bySeverity = { Critical: 0, High: 0, Medium: 0, Low: 0, Negligible: 0, Unknown: 0 }, ids = new Set();
    if (!Array.isArray(report.matches) || (report.ignoredMatches?.length ?? 0) !== 0 || report.descriptor?.db?.status?.valid !== true
      || report.descriptor.db.status.built !== database.built || report.descriptor.db.status.schemaVersion !== database.schemaVersion) reject();
    for (const match of report.matches) {
      const severity = match.vulnerability?.severity, id = match.vulnerability?.id;
      if (!Object.hasOwn(bySeverity, severity) || typeof id !== 'string') reject();
      bySeverity[severity]++; ids.add(id);
    }
    await c.write(`scans/${role}/grype.json`, raw);
    const result = { role, imageId: lock.images[role], scanCompleted: true, matches: report.matches.length, bySeverity,
      uniqueVulnerabilities: ids.size, ignoredMatches: 0, packages: parsedSbom.artifacts.length,
      sbomSha256: sha(sbom), scanSha256: sha(raw), imageBinding, database: report.descriptor.db.status,
      classification: 'EXACT_LOCAL_CANDIDATE_SCAN_NOT_RELEASE_APPROVAL' };
    await c.write(`scans/${role}/summary.json`, result); results.push(result);
    process.stdout.write(publicJson({ stage: 'SCANNED', role, matches: result.matches, bySeverity }));
  }
  await validateCandidateSourceLock(c.root, c.source); await c.engine(); return results;
}

/** All build and scan evidence uses a new directory. Failure never rewrites an
 * older run or resumes partial state. Built immutable images are retained. */
async function collectPhase(options, phase) {
  let c, outcome, failure = null;
  try {
    let supplied;
    if (phase === 'scan') {
      supplied = await validateCandidateSourceLock(options.root, options.sourceLock);
      validateCandidateReleaseLock(supplied, options.imageLock, RELEASE_VERSION);
    }
    c = await collector(options);
    let lock;
    if (phase === 'scan') {
      if (JSON.stringify(c.source) !== JSON.stringify(supplied)) reject();
      lock = validateCandidateReleaseLock(c.source, options.imageLock, RELEASE_VERSION);
      await c.write('image-lock.json', lock); await c.write('engine.json', await c.engine());
    } else lock = await build(c);
    const results = phase === 'build' ? [] : await scan(c, lock, phase === 'scan');
    outcome = { status: phase === 'build' ? 'BUILT_LOCAL_ONLY' : phase === 'scan' ? 'SCANNED_EXISTING_LOCAL_ONLY' : 'BUILT_AND_SCANNED_LOCAL_ONLY',
      releaseProfile:RELEASE_PROFILE,sourceRevision: c.source.sourceRevision, sourceFingerprint: c.source.sourceFingerprint, imageRoles: imageRoles(RELEASE_VERSION).length, images: lock.images, results,
      scanned: phase !== 'build', findingsRequireReview: true, joinedRuntimeRehearsed: false, deploymentAuthorized: false };
  } catch { failure = true; outcome = { status: 'FAILED_PARTIAL_EVIDENCE_RETAINED', deploymentAuthorized: false }; }
  if (c) {
    try { outcome.cleanup = await c.cleanup(); } catch { failure = true; outcome.status = 'FAILED_CLEANUP_UNCONFIRMED'; }
    await c.write('summary.json', outcome);
  }
  if (failure) reject(); return outcome;
}

export const collectCandidateRelease = options => collectPhase(options, 'all');
export const buildCandidateRelease = options => collectPhase(options, 'build');
/** Scan an already built exact lock in a NEW evidence directory. Current source,
 * ten image labels/platforms and copied source bytes are checked again. This
 * does not resume or adopt a partial build, and cannot accept a stale source lock. */
export const scanCandidateRelease = options => collectPhase(options, 'scan');

async function readLockFile(path) {
  if (typeof path !== 'string' || !isAbsolute(path) || resolve(path) !== path || await realpath(path) !== path) reject();
  const before = await lstat(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n || before.size < 1n || before.size > 4n * 1024n * 1024n) reject();
  const bytes = await readFile(path), after = await lstat(path, { bigint: true });
  if (['dev','ino','size','mode','mtimeNs','ctimeNs'].some(key => before[key] !== after[key]) || BigInt(bytes.length) !== before.size) reject();
  return JSON.parse(bytes);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const args = process.argv.slice(2); let result;
    if (args.length === 3) {
      const [root, socket, destination] = args; result = await collectCandidateRelease({ root, socket, destination });
    } else if (args.length === 4 && args[0] === 'build') {
      const [, root, socket, destination] = args; result = await buildCandidateRelease({ root, socket, destination });
    } else if (args.length === 6 && args[0] === 'scan') {
      const [, root, socket, destination, sourceFile, imageFile] = args;
      result = await scanCandidateRelease({ root, socket, destination, sourceLock: await readLockFile(sourceFile), imageLock: await readLockFile(imageFile) });
    } else reject();
    process.stdout.write(publicJson({ status: result.status, imageRoles: result.imageRoles, deploymentAuthorized: false }));
  } catch { process.stderr.write('FNCP_CANDIDATE_COLLECTION_REJECTED: preserve partial evidence and review the failed stage.\n'); process.exitCode = 1; }
}
