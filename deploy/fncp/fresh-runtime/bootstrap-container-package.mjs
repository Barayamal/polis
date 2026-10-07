/** Public-source-only build contexts. No engine, config, key, credential,
 * runtime store or archive access. Fixed checkout-relative sources only.
 * Generated contexts are review artifacts, not build/deployment authority.
 */
import { mkdtemp, realpath, chmod, lstat, readdir, open, mkdir, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const fail = () => new Error('Fresh public container package rejected; no runtime action taken.');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const RUNTIME = [
  'bootstrap-container-holder.mjs', 'bootstrap-container-run.mjs',
  'bootstrap-issuer.mjs', 'bootstrap-api-trust.mjs', 'bootstrap-api-process.mjs',
  'bootstrap-jwks-service.mjs', 'bootstrap-database-contract.mjs',
  'bootstrap-database-executor.mjs', 'bootstrap-database-worker.mjs',
];
const SERVER = ['Dockerfile', 'package.json', 'package-lock.json', 'tsconfig.json',
  'index.ts', 'app.ts', 'unsupportedBrowser.html', 'busybox-fixed/build-fixed-busybox.sh',
  'busybox-fixed/CVE-2025-60876.patch'];
const MIGRATIONS = [
  '000000_initial.sql','000001_update_pwreset_table.sql','000002_add_xid_constraint.sql',
  '000003_add_origin_permanent_cookie_columns.sql','000004_drop_waitinglist_table.sql',
  '000005_drop_slack_stripe_canvas.sql','000006_update_votes_rule.sql',
  '000007_drop_geolocation_fields.sql','000008_add_comment_priority.sql',
  '000009_add_uuid_to_zinvites.sql','000010_create_oidc_user_mappings.sql',
  '000011_alter_suzinvites_xid_to_text.sql','000012_create_topic_agenda_selections.sql',
  '000013_create_treevite.sql','000014_alter_reports_modlevel.sql','000015_add_xid_requirements.sql',
  '000016_add_orig_id.sql','000017_create_byod_job_table.sql','000018_add_topics_enabled.sql',
  '000019_add_fncp_provider_allowlist_operations.sql',
];
const API_STAGE = [
  '',
  '# Fresh bootstrap only. Normal targets above are preserved.',
  'FROM prod AS fncp-fresh-bootstrap',
  'USER root',
  'RUN mkdir -p /opt/fncp/server /opt/fncp/deploy/fncp /run/fncp/bootstrap \\',
  '    && chown -R node:node /opt/fncp /run/fncp/bootstrap \\',
  '    && ln -s /app/node_modules /opt/fncp/node_modules \\',
  '    && ln -s /app/node_modules /opt/fncp/server/node_modules',
  'COPY --from=build --chown=node:node /app/dist /opt/fncp/server/dist',
  'COPY --chown=node:node fncp-runtime/ /opt/fncp/deploy/fncp/',
  'USER node',
  'WORKDIR /opt/fncp',
  'ENTRYPOINT ["/usr/local/bin/node", "/opt/fncp/deploy/fncp/fresh-runtime/bootstrap-container-holder.mjs"]',
  'CMD []','',
].join('\n');
const PG_RECIPE = [
  'FROM docker.io/library/postgres:17.11-alpine@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73',
  'USER root',
  'RUN apk add --no-cache libcrypto3=3.5.8-r0 libssl3=3.5.8-r0 libuuid=2.42.3-r1 \\',
  '    && rm -f /usr/local/bin/gosu',
  'RUN mkdir -p /run/fncp/postgres-material /opt/fncp/migrations \\',
  '    && chown postgres:postgres /run/fncp/postgres-material \\',
  '    && chmod 0700 /run/fncp/postgres-material',
  'COPY --chown=postgres:postgres migrations/ /opt/fncp/migrations/',
  'COPY bootstrap-postgres-entrypoint.sh /opt/fncp/bootstrap-postgres-entrypoint.sh',
  'RUN chmod 0555 /opt/fncp/bootstrap-postgres-entrypoint.sh',
  'USER 70:70',
  'ENTRYPOINT ["/opt/fncp/bootstrap-postgres-entrypoint.sh"]',
  'CMD []','',
].join('\n');
async function source(name) {
  if (name.startsWith('/') || name.split('/').some(p => p === '..' || p.startsWith('.'))) throw fail();
  let current = ROOT;
  for (const part of name.split('/')) {
    current = join(current, part); const stat = await lstat(current);
    if (stat.isSymbolicLink() || !(stat.isDirectory() || stat.isFile())) throw fail();
  }
  const stat = await lstat(current);
  if (!stat.isFile() || stat.size > 2 * 1024 * 1024) throw fail();
  const fd = await open(current, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const same = other => other.isFile() && ['ino','dev','size','mtimeMs','ctimeMs'].every(key => other[key] === stat[key]);
    if (!same(await fd.stat())) throw fail();
    const bytes = Buffer.alloc(stat.size + 1); let length = 0;
    while (length < bytes.length) {
      const part = await fd.read(bytes, length, bytes.length - length, length);
      if (!part.bytesRead) break;
      length += part.bytesRead;
    }
    if (length !== stat.size || !same(await fd.stat()) || !same(await lstat(current))) throw fail();
    return bytes.subarray(0,length);
  } finally { await fd.close(); }
}
async function publicTree(name, extensions, found = []) {
  const folder = join(ROOT, name); const info = await lstat(folder);
  if (!info.isDirectory() || info.isSymbolicLink()) throw fail();
  const entries = await readdir(folder, {withFileTypes:true});
  for (const entry of entries.sort((a,b)=>a.name.localeCompare(b.name))) {
    if (entry.name.startsWith('.') || entry.isSymbolicLink()) throw fail();
    const child = name + '/' + entry.name;
    if (entry.isDirectory()) await publicTree(child, extensions, found);
    else if (entry.isFile() && extensions.some(ext => entry.name.endsWith(ext))) found.push(child);
    if (found.length > 512) throw fail();
  }
  return found;
}
export async function createBootstrapContainerPackage() {
  if (arguments.length) throw fail();
  const mappings = SERVER.map(name=>['server/'+name,'api/'+name]);
  for (const name of await publicTree('server/src',['.ts','.xml'])) mappings.push([name,'api/'+name.slice(7)]);
  for (const name of await publicTree('server/types',['.ts'])) mappings.push([name,'api/'+name.slice(7)]);
  for (const name of RUNTIME) mappings.push(['deploy/fncp/fresh-runtime/'+name,'api/fncp-runtime/fresh-runtime/'+name]);
  for (const name of ['fresh-bootstrap-result.mjs','seed-statements.json']) mappings.push(['deploy/fncp/'+name,'api/fncp-runtime/'+name]);
  for (const name of MIGRATIONS) mappings.push(['server/postgres/migrations/'+name,'postgres/migrations/'+name]);
  mappings.push(['deploy/fncp/fresh-runtime/bootstrap-postgres-entrypoint.sh','postgres/bootstrap-postgres-entrypoint.sh']);
  const prepared = []; let total = 0;
  for (const [name,target] of mappings) {
    const bytes = await source(name); total += bytes.length;
    if (total > 20 * 1024 * 1024) throw fail();
    prepared.push({name,target,bytes});
  }
  const directory = await mkdtemp(join(await realpath(tmpdir()),'fncp-container-package-'));
  await chmod(directory,0o700); const inventory=[];
  for (const item of prepared) {
    const bytes = item.target==='api/Dockerfile' ? Buffer.concat([item.bytes,Buffer.from(API_STAGE)]) : item.bytes;
    const destination=join(directory,item.target); await mkdir(dirname(destination),{recursive:true,mode:0o700});
    await writeFile(destination,bytes,{mode:0o600,flag:'wx'});
    inventory.push({source:item.name,path:item.target,bytes:bytes.length,sha256:sha(bytes),sourceSha256:sha(item.bytes)});
  }
  await writeFile(join(directory,'postgres/Dockerfile'),PG_RECIPE,{mode:0o600,flag:'wx'});
  inventory.push({source:'FIXED_RECIPE',path:'postgres/Dockerfile',bytes:Buffer.byteLength(PG_RECIPE),sha256:sha(PG_RECIPE)});
  inventory.sort((a,b)=>a.path.localeCompare(b.path));
  return Object.freeze({directory,apiContext:join(directory,'api'),postgresContext:join(directory,'postgres'),
    apiTarget:'fncp-fresh-bootstrap',files:inventory.length,bytes:inventory.reduce((n,x)=>n+x.bytes,0),
    inventory:Object.freeze(inventory.map(Object.freeze)),inventorySha256:sha(JSON.stringify(inventory)),
    containsRuntimeCredentials:false,buildExecuted:false,deployableAssurance:false});
}
