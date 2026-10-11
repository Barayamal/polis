import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const copies = [
  'server/zlib-fixed',
  'math/zlib-fixed',
  'deploy/fncp/production-security/zlib-fixed',
];
const recipes = [
  'server/Dockerfile',
  'server/Dockerfile-selfhost-db',
  'server/Dockerfile-migrate',
  'math/Dockerfile',
  'deploy/fncp/production-deployment/Dockerfile',
  'deploy/fncp/production-deployment/Dockerfile.wordpress',
  'deploy/fncp/production-deployment/Dockerfile.proxy',
  'deploy/fncp/production-edge/Dockerfile',
  'deploy/fncp/production-operator/Dockerfile',
];

test('three build contexts carry one byte-identical upstream remediation', async () => {
  for (const name of ['build-fixed-zlib.sh', 'df84af25.patch']) {
    const values = await Promise.all(copies.map(path => readFile(`${path}/${name}`)));
    assert.equal(new Set(values.map(sha)).size, 1, name);
  }
  const script = await readFile(`${copies[0]}/build-fixed-zlib.sh`, 'utf8');
  const patch = await readFile(`${copies[0]}/df84af25.patch`, 'utf8');
  for (const marker of [
    "archive_url='https://github.com/madler/zlib/archive/refs/tags/v1.3.2.tar.gz'",
    "archive_sha256='b99a0b86c0ba9360ec7e78c4f1e43b1cbdf1e6936c8fa0f6835c0cd694a495a1'",
    "patch_commit='df84af25dc1942490e1d1c899a07619152a46148'",
    'make test',
    'FNCP_ZLIB_SOURCE_REMEDIATION_V1',
  ]) assert.ok(script.includes(marker), marker);
  for (const marker of [
    'This addresses CVE-2026-85091.',
    'state->strm.avail_in = 0;',
    'state->strm.next_in = state->in;',
  ]) assert.ok(patch.includes(marker), marker);
});

test('all nine Alpine release roles replace and attest the patched shared library', async () => {
  for (const path of recipes) {
    const source = await readFile(path, 'utf8');
    assert.match(source, /build-fixed-zlib\.sh/u, path);
    assert.match(source, /COPY --from=(?:fncp-)?busybox-fixed \/out\/zlib\/lib\/libz\.so\.1\.3\.2 \/lib\/libz\.so\.1\.3\.2/u, path);
    assert.match(source, /\/usr\/share\/fncp-security\/zlib-provenance\.txt/u, path);
    assert.match(source, /CVE-2026-85091-df84af25dc1942490e1d1c899a07619152a46148/u, path);
    assert.match(source, /sha256sum \/lib\/libz\.so\.1\.3\.2/u, path);
  }
});

test('remediation does not hide the distribution package or claim a scanner waiver', async () => {
  for (const path of recipes) {
    const source = await readFile(path, 'utf8');
    assert.doesNotMatch(source, /apk del[^\n]*zlib|grype[^\n]*(?:ignore|exclude)|CVE-2026-85091[^\n]*(?:ignore|waiv)/iu, path);
  }
});

test('every deny-all root build context admits the remediation source copied by its Dockerfile', async () => {
  for(const path of recipes.filter(p=>p.startsWith('deploy/'))){
    const recipe=await readFile(path,'utf8'),rules=(await readFile(path+'.dockerignore','utf8')).split('\n').map(s=>s.replace(/\/$/u,''));
    assert.match(recipe,/COPY deploy\/fncp\/production-security\/zlib-fixed /u,path);
    for(const required of ['!deploy/fncp/production-security','!deploy/fncp/production-security/zlib-fixed','!deploy/fncp/production-security/zlib-fixed/**'])assert.ok(rules.includes(required),path+' excludes required source '+required);
  }
});
