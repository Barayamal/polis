/** Public-source package checks only. No Docker/VM command, application import,
 * SQL execution, installation or retained data is used. Successful generated
 * contexts are deliberately preserved as reviewable public artifacts.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, readFile, readdir, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createBootstrapContainerPackage } from './bootstrap-container-package.mjs';

const PACKAGE_URL = new URL('./bootstrap-container-package.mjs', import.meta.url);
const HOLDER_URL = new URL('./bootstrap-container-holder.mjs', import.meta.url);
const ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const ERROR = 'Fresh public container package rejected; no runtime action taken.';
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const MIGRATIONS = [
  '000000_initial.sql', '000001_update_pwreset_table.sql', '000002_add_xid_constraint.sql',
  '000003_add_origin_permanent_cookie_columns.sql', '000004_drop_waitinglist_table.sql',
  '000005_drop_slack_stripe_canvas.sql', '000006_update_votes_rule.sql',
  '000007_drop_geolocation_fields.sql', '000008_add_comment_priority.sql',
  '000009_add_uuid_to_zinvites.sql', '000010_create_oidc_user_mappings.sql',
  '000011_alter_suzinvites_xid_to_text.sql', '000012_create_topic_agenda_selections.sql',
  '000013_create_treevite.sql', '000014_alter_reports_modlevel.sql', '000015_add_xid_requirements.sql',
  '000016_add_orig_id.sql', '000017_create_byod_job_table.sql', '000018_add_topics_enabled.sql',
  '000019_add_fncp_provider_allowlist_operations.sql',
];
const SERVER = new Set(['Dockerfile', 'package.json', 'package-lock.json', 'tsconfig.json',
  'index.ts', 'app.ts', 'unsupportedBrowser.html', 'busybox-fixed/build-fixed-busybox.sh',
  'busybox-fixed/CVE-2025-60876.patch'].map(name => 'server/' + name));
const rejected = promise => assert.rejects(promise, error => error.message === ERROR && error.cause === undefined);
let packagePromise;
const packaged = () => packagePromise ??= createBootstrapContainerPackage();
async function filesBelow(directory, prefix = '') {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    assert.equal(entry.isSymbolicLink(), false, 'Generated public context must contain no links.');
    const path = prefix + entry.name;
    if (entry.isDirectory()) files.push(...await filesBelow(join(directory, entry.name), path + '/'));
    else { assert.equal(entry.isFile(), true); files.push(path); }
  }
  return files.sort();
}

test('source: fixed checkout root and closed input lists, without runtime transport or ambient configuration', async () => {
  const source = await readFile(PACKAGE_URL, 'utf8');
  assert.match(source, /const ROOT = fileURLToPath\(new URL\('\.\.\/\.\.\/\.\.\/', import\.meta\.url\)\);/u);
  assert.match(source, /export async function createBootstrapContainerPackage\(\) \{\s+if \(arguments\.length\) throw fail\(\);/u);
  assert.match(source, /publicTree\('server\/src',\['\.ts','\.xml'\]\)/u);
  assert.match(source, /publicTree\('server\/types',\['\.ts'\]\)/u);
  assert.match(source, /'fncp-container-package-'/u);
  assert.match(source, /stat\.size > 2 \* 1024 \* 1024/u);
  assert.match(source, /open\(current, constants\.O_RDONLY \| constants\.O_NOFOLLOW \| constants\.O_NONBLOCK\)/u);
  assert.match(source, /Buffer\.alloc\(stat\.size \+ 1\)/u);
  assert.match(source, /length !== stat\.size \|\| !same\(await fd\.stat\(\)\) \|\| !same\(await lstat\(current\)\)/u);
  assert.match(source, /finally \{ await fd\.close\(\); \}/u);
  assert.doesNotMatch(source, /node:(?:child_process|net|https?|tls)|process\.env|runDocker\(|fetch\(|execFile\(|spawn\(/u);
  assert.equal((source.match(/^export /gmu) ?? []).length, 1);
  const dockerfile = await readFile(join(ROOT, 'server/Dockerfile'), 'utf8');
  assert.match(dockerfile, /^RUN --mount=type=cache,target=\/root\/\.npm npm ci --production=false --no-audit --no-fund$/mu);
  assert.match(dockerfile, /^RUN npm ci --production=false --no-audit --no-fund$/mu);
  assert.match(dockerfile, /^RUN npm prune --omit=dev --no-audit --no-fund && npm cache clean --force && \\$/mu);
  assert.equal((dockerfile.match(/\bnpm (?:ci|prune)\b/gu) ?? []).length, 3);
});

test('invalid arguments never read values or offer a path, source, environment or runtime override', async () => {
  let touched = 0;
  const getter = { get path() { touched++; throw new Error('not read'); } };
  const proxy = new Proxy({}, { get() { touched++; }, ownKeys() { touched++; } });
  for (const value of [undefined, null, false, '', {}, getter, proxy, { directory: '/not-adopted' },
    { root: ROOT }, { environment: {} }, { [Symbol('hidden')]: true }])
    await rejected(createBootstrapContainerPackage(value));
  await rejected(createBootstrapContainerPackage(undefined, undefined));
  assert.equal(touched, 0);
});

test('import and invalid-argument calls work with all filesystem writes and non-module reads denied', () => {
  const code = `import assert from 'node:assert/strict';
    const module = await import(${JSON.stringify(PACKAGE_URL.href)});
    assert.deepEqual(Object.keys(module), ['createBootstrapContainerPackage']);
    for (const input of [undefined, null, {}, {directory:'/not-adopted'}])
      await assert.rejects(module.createBootstrapContainerPackage(input), {message:${JSON.stringify(ERROR)}});
    process.stdout.write('DENIED_WITHOUT_SOURCE_OR_WRITE_ACCESS');`;
  const result = spawnSync(process.execPath, ['--permission', '--allow-fs-read=' + fileURLToPath(PACKAGE_URL),
    '--input-type=module', '-e', code], { cwd: dirname(fileURLToPath(PACKAGE_URL)),
    env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' }, shell: false, timeout: 5000,
    maxBuffer: 8192, encoding: 'utf8' });
  assert.equal(result.error, undefined); assert.equal(result.signal, null); assert.equal(result.status, 0);
  assert.equal(result.stdout, 'DENIED_WITHOUT_SOURCE_OR_WRITE_ACCESS');
});

test('holder source has fixed Linux UID admission, a fifteen-minute maximum and explicit stop handlers only', async () => {
  const source = await readFile(HOLDER_URL, 'utf8');
  assert.match(source, /process\.argv\.length !== 2 \|\| process\.platform !== 'linux' \|\| process\.getuid\(\) !== 1000/u);
  assert.match(source, /setTimeout\(\(\) => process\.exit\(1\), 900000\)/u);
  for (const signal of ['SIGTERM', 'SIGINT'])
    assert.ok(source.includes(`process.once('${signal}', () => { clearTimeout(limit); process.exit(0); });`));
  assert.doesNotMatch(source, /node:(?:fs|child_process|net|https?|tls)|process\.env|fetch\(|listen\(|readFile|spawn\(/u);
});

test('holder import is inert and a direct invocation with extra arguments fails immediately', () => {
  const options = { cwd: dirname(fileURLToPath(HOLDER_URL)), env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' },
    shell: false, timeout: 3000, maxBuffer: 8192, encoding: 'utf8' };
  const imported = spawnSync(process.execPath, ['--input-type=module', '-e',
    `await import(${JSON.stringify(HOLDER_URL.href)});process.stdout.write('INERT');`], options);
  assert.equal(imported.error, undefined); assert.equal(imported.status, 0); assert.equal(imported.stdout, 'INERT');
  const denied = spawnSync(process.execPath, [fileURLToPath(HOLDER_URL), 'not-authorised'], options);
  assert.equal(denied.error, undefined); assert.equal(denied.status, 1); assert.equal(denied.signal, null);
  assert.equal(denied.stdout, ''); assert.equal(denied.stderr, '');
});

test('package behavior: creates only a new private context and returns immutable inventory without runtime assurance', async t => {
  const result = await packaged();
  assert.equal(isAbsolute(result.directory), true);
  assert.equal(dirname(result.directory), await realpath(tmpdir()));
  assert.match(basename(result.directory), /^fncp-container-package-[A-Za-z0-9]+$/u);
  assert.equal(await realpath(result.directory), result.directory);
  assert.equal((await lstat(result.directory)).mode & 0o777, 0o700);
  assert.equal(result.apiContext, join(result.directory, 'api'));
  assert.equal(result.postgresContext, join(result.directory, 'postgres'));
  assert.equal(result.apiTarget, 'fncp-fresh-bootstrap');
  assert.ok(Object.isFrozen(result)); assert.ok(Object.isFrozen(result.inventory));
  assert.ok(result.inventory.every(Object.isFrozen));
  for (const key of ['containsRuntimeCredentials', 'buildExecuted', 'deployableAssurance']) assert.equal(result[key], false);
  t.diagnostic(JSON.stringify({ publicContextPreserved: result.directory, files: result.files,
    bytes: result.bytes, inventorySha256: result.inventorySha256 }));
});

test('package behavior: every generated file is inventoried once with exact byte and digest evidence', async () => {
  const result = await packaged();
  const paths = result.inventory.map(item => item.path);
  assert.equal(new Set(paths).size, paths.length);
  assert.deepEqual(paths, [...paths].sort((a, b) => a.localeCompare(b)));
  assert.deepEqual(await filesBelow(result.directory), [...paths].sort());
  assert.equal(result.files, paths.length);
  assert.equal(result.bytes, result.inventory.reduce((n, item) => n + item.bytes, 0));
  assert.equal(result.inventorySha256, sha(JSON.stringify(result.inventory)));
  for (const item of result.inventory) {
    assert.equal(isAbsolute(item.path), false); assert.equal(item.path.split('/').some(p => !p || p === '..' || p.startsWith('.')), false);
    const destination = join(result.directory, item.path);
    assert.equal(relative(result.directory, destination), item.path);
    const stat = await lstat(destination); assert.equal(stat.isFile(), true); assert.equal(stat.isSymbolicLink(), false);
    assert.equal(stat.mode & 0o777, 0o600);
    const bytes = await readFile(destination); assert.equal(bytes.length, item.bytes); assert.equal(sha(bytes), item.sha256);
    if (item.source !== 'FIXED_RECIPE') assert.equal(sha(await readFile(join(ROOT, item.source))), item.sourceSha256);
  }
});

test('package behavior: source allowlist excludes environment, keys, stores, dependencies and archives', async () => {
  const result = await packaged();
  for (const item of result.inventory) {
    assert.doesNotMatch(item.path, /(?:^|\/)(?:\.[^/]*|node_modules|archived|evidence)(?:\/|$)|\.(?:pem|key|p12|pfx|sqlite3?|db|zip|tgz|tar|gz)$/u);
    const allowed = item.source === 'FIXED_RECIPE' || SERVER.has(item.source) ||
      /^server\/src\/[^.][\s\S]*\.(?:ts|xml)$/u.test(item.source) || /^server\/types\/[^.][\s\S]*\.ts$/u.test(item.source) ||
      /^deploy\/fncp\/fresh-runtime\/bootstrap-[a-z-]+\.mjs$/u.test(item.source) ||
      ['deploy/fncp/fresh-bootstrap-result.mjs', 'deploy/fncp/seed-statements.json',
        'deploy/fncp/fresh-runtime/bootstrap-postgres-entrypoint.sh'].includes(item.source) ||
      MIGRATIONS.some(name => item.source === 'server/postgres/migrations/' + name);
    assert.equal(allowed, true, 'Unexpected package source: ' + item.source);
    assert.doesNotMatch(item.source, /\.test\.|__tests__|\/node_modules\/|\/archived\/|\/evidence\//u);
  }
});

test('package behavior: all twenty exact SQL migrations are copied byte-for-byte without execution', async () => {
  const result = await packaged();
  const sql = result.inventory.filter(item => item.path.startsWith('postgres/migrations/'));
  assert.deepEqual(sql.map(item => basename(item.path)).sort(), [...MIGRATIONS].sort());
  for (const item of sql) assert.equal(item.sha256, item.sourceSha256);
});

test('package behavior: API recipe preserves reviewed ordinary targets and adds only the explicit fresh role', async () => {
  const result = await packaged();
  const original = await readFile(join(ROOT, 'server/Dockerfile'), 'utf8');
  const recipe = await readFile(join(result.apiContext, 'Dockerfile'), 'utf8');
  assert.equal(recipe.slice(0, original.length), original);
  const added = recipe.slice(original.length);
  assert.match(added, /^\n# Fresh bootstrap only\./u);
  assert.match(added, /FROM prod AS fncp-fresh-bootstrap/u);
  assert.match(added, /COPY --from=build --chown=node:node \/app\/dist \/opt\/fncp\/server\/dist/u);
  assert.match(added, /COPY --chown=node:node fncp-runtime\/ \/opt\/fncp\/deploy\/fncp\//u);
  assert.match(added, /USER node\nWORKDIR \/opt\/fncp\nENTRYPOINT \["\/usr\/local\/bin\/node", "\/opt\/fncp\/deploy\/fncp\/fresh-runtime\/bootstrap-container-holder\.mjs"\]/u);
  assert.doesNotMatch(added, /--privileged|network=host|EXPOSE|ENV FNCP_OPTION_C_RELEASE_MODE|COPY \. \./u);
});

test('package behavior: PostgreSQL public SQL remains readable by the final UID and uses the pinned base', async () => {
  const result = await packaged(); const recipe = await readFile(join(result.postgresContext, 'Dockerfile'), 'utf8');
  assert.match(recipe, /^FROM docker\.io\/library\/postgres:17\.11-alpine@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73\n/u);
  assert.match(recipe, /COPY --chown=postgres:postgres migrations\/ \/opt\/fncp\/migrations\//u);
  assert.match(recipe, /chown postgres:postgres \/run\/fncp\/postgres-material \\\n\s+&& chmod 0700 \/run\/fncp\/postgres-material/u);
  assert.match(recipe, /RUN chmod 0555 \/opt\/fncp\/bootstrap-postgres-entrypoint\.sh/u);
  assert.match(recipe, /USER 70:70\nENTRYPOINT \["\/opt\/fncp\/bootstrap-postgres-entrypoint\.sh"\]\nCMD \[\]/u);
  assert.doesNotMatch(recipe, /ENV .*PASSWORD|trust|--privileged|EXPOSE|COPY \. \./u);
});

test('package behavior: PostgreSQL repair installs only fixed runtime libraries and drops unused gosu before the UID boundary', async () => {
  const result = await packaged();
  const recipe = await readFile(join(result.postgresContext, 'Dockerfile'), 'utf8');
  const instructions = recipe.replace(/[ \t]*\\\n\s*/gu, ' ').split('\n');
  const installs = instructions.filter(line => /\bapk\b/u.test(line));
  assert.deepEqual(installs, [
    'RUN apk add --no-cache libcrypto3=3.5.9-r0 libssl3=3.5.9-r0 libuuid=2.42.3-r1 && rm -f /usr/local/bin/gosu',
  ]);
  assert.ok(instructions.indexOf('USER root') < instructions.indexOf(installs[0]));
  assert.ok(instructions.indexOf(installs[0]) < instructions.indexOf('USER 70:70'));
  assert.deepEqual(instructions.filter(line => /\brm\b/u.test(line)), installs);
  const wrapper = await readFile(join(result.postgresContext, 'bootstrap-postgres-entrypoint.sh'));
  assert.deepEqual(wrapper, await readFile(join(ROOT, 'deploy/fncp/fresh-runtime/bootstrap-postgres-entrypoint.sh')));
  assert.doesNotMatch(wrapper.toString('utf8'), /\bgosu\b/u);
});

test('package behavior: relative runtime imports close within the context or explicitly packaged build dependencies', async () => {
  const result = await packaged();
  const paths = new Set(result.inventory.map(item => item.path));
  const recipe = await readFile(join(result.apiContext, 'Dockerfile'), 'utf8');
  assert.match(recipe, /ln -s \/app\/node_modules \/opt\/fncp\/server\/node_modules/u);
  for (const item of result.inventory.filter(entry => entry.path.endsWith('.mjs'))) {
    const source = await readFile(join(result.directory, item.path), 'utf8');
    for (const match of source.matchAll(/(?:from\s*|import\s*)['"]([^'"]+)['"]/gu)) {
      const specifier = match[1]; if (specifier.startsWith('node:')) continue;
      assert.ok(specifier.startsWith('.'), 'Runtime must not gain an undeclared external import.');
      const resolved = relative(result.directory, resolve(dirname(join(result.directory, item.path)), specifier));
      if (/^server\/node_modules\/pg\/lib\/(?:client|query)\.js$/u.test(resolved)) continue;
      assert.ok(paths.has(resolved), 'Missing packaged runtime import: ' + resolved);
    }
  }
});
