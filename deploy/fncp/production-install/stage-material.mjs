#!/usr/bin/env node
/** Offline fresh-install material staging only. No engine, network, database,
 * key generation, signing, account creation or activation is performed. */
import { constants, closeSync, fchmodSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync,
  readSync, readdirSync, realpathSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { createPrivateKey, createPublicKey, X509Certificate } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { renderProductionCompose, validateProductionConfiguration, validateProductionImageLock } from '../production-deployment/compose.mjs';
import { snapshotMaterial } from '../selfhost/material.mjs';
import { canonical, exact, sha, secretBytes } from '../production-service/contracts.mjs';

export const PROFILE = 'FNCP_FRESH_MATERIAL_STAGE_V1';
export const PROFILE_V2 = 'FNCP_FRESH_MATERIAL_STAGE_V2';
export const PROFILE_V3 = 'FNCP_FRESH_MATERIAL_STAGE_V3';
const EDGE = Object.freeze(['config.json','server.pem','server-key.pem','upstream-ca.pem']);
const fail = () => new Error('FNCP_FRESH_MATERIAL_REJECTED');
const CORE = Object.freeze(['api.env', 'database-ca.pem', 'database-math-password',
  'database-migration-password', 'database-owner-password', 'database-runtime-password',
  'database-server.key', 'database-server.pem', 'jwt-private.pem', 'jwt-public.pem', 'math.env', 'migration.env']);
const WP = Object.freeze(['config.json', 'plugin-config.json', 'server.pem', 'server-key.pem', 'receiver-ca.pem']);
const PROXY = Object.freeze(['proxy-cert.pem', 'proxy-key.pem']);
const PARTICIPANT = Object.freeze({
  'identity.clientSecretFile': 'oidc-secret.txt', 'identity.identityKeyFile': 'identity-key.txt',
  'activation.publicKeyFile': 'activation-public.pem', 'secrets.gatewayKeyFile': 'gateway-key.txt',
  'secrets.providerKeyFile': 'provider-key.txt', 'secrets.wordpressRequestKeyFile': 'wordpress-request-key.txt',
  'secrets.wordpressResponseKeyFile': 'wordpress-response-key.txt', 'secrets.wordpressEventKeyFile': 'wordpress-event-key.txt',
  'tls.participantKeyFile': 'participant-key.pem', 'tls.participantCertFile': 'participant-cert.pem',
  'tls.receiverKeyFile': 'receiver-key.pem', 'tls.receiverCertFile': 'receiver-cert.pem',
  'trust.providerCaFile': 'provider-ca.pem', 'trust.wordpressCaFile': 'wordpress-ca.pem',
});
const MAX_FILE = 131072;
const same = (a, b) => ['dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs'].every(k => a[k] === b[k]);
const sameDirectory = (a, b) => ['dev', 'ino', 'uid', 'gid', 'mode'].every(k => a[k] === b[k]);
const encoded = value => Buffer.from(canonical(value) + '\n');
function pathCheck(value) {
  if (typeof value !== 'string' || !isAbsolute(value) || resolve(value) !== value || value === '/'
    || value.length > 4096 || /[\u0000-\u001f\u007f\\$]/u.test(value)) throw fail();
  return value;
}
function outside(parent, child) {
  const path = relative(parent, child);
  return path === '..' || path.startsWith('../') || isAbsolute(path);
}
function directory(path) {
  pathCheck(path); const s = lstatSync(path, { bigint: true });
  if (!s.isDirectory() || s.uid !== BigInt(process.getuid()) || (s.mode & 0o7777n) !== 0o700n
    || realpathSync(path) !== path) throw fail();
  return s;
}
function names(path, expected) {
  if (JSON.stringify(readdirSync(path).sort()) !== JSON.stringify([...expected].sort())) throw fail();
}
function read(path, mode = 0o600) {
  const parent = directory(dirname(path)); let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.uid !== BigInt(process.getuid())
      || (before.mode & 0o7777n) !== BigInt(mode) || before.size < 1n || before.size > BigInt(MAX_FILE)
      || !same(before, lstatSync(path, { bigint: true }))) throw fail();
    // Bounded descriptor read: no unbounded read after checking a mutable size.
    const bytes = Buffer.alloc(Number(before.size));
    let length = 0;
    while (length < bytes.length) { const n = readSync(fd, bytes, length, bytes.length - length, length); if (!n) break; length += n; }
    if (length !== bytes.length || !same(before, fstatSync(fd, { bigint: true }))
      || !same(before, lstatSync(path, { bigint: true })) || !same(parent, directory(dirname(path)))) throw fail();
    return { bytes, stat: before, parent, mode };
  } finally { if (fd !== undefined) closeSync(fd); }
}
function parse(bytes) {
  const text = bytes.toString('utf8'); if (!Buffer.from(text).equals(bytes)) throw fail();
  const value = JSON.parse(text);
  // JSON input is canonical to reject duplicate keys and ambiguous encodings.
  if (!encoded(value).equals(bytes)) throw fail();
  return value;
}
function text(bytes) {
  const s = bytes.toString('utf8'); if (!Buffer.from(s).equals(bytes) || s.trim() !== s) throw fail(); return s;
}
function origin(value) {
  const u = new URL(value); if (u.protocol !== 'https:' || u.origin !== value || u.username || u.password) throw fail(); return u;
}
function ca(bytes) {
  if (!/^-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\r?\n?$/u.test(bytes.toString('utf8'))) throw fail();
  const c = new X509Certificate(bytes), now = Date.now();
  if (!c.ca || !Number.isFinite(Date.parse(c.validFrom)) || !Number.isFinite(Date.parse(c.validTo))
    || Date.parse(c.validFrom) > now || Date.parse(c.validTo) <= now || !c.checkIssued(c) || !c.verify(c.publicKey)) throw fail();
  return c;
}
function leaf(certBytes, keyBytes, expectedOrigin, trustBytes) {
  if (!/^-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\r?\n?$/u.test(certBytes.toString('utf8'))
    || !/^-----BEGIN PRIVATE KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PRIVATE KEY-----\r?\n?$/u.test(keyBytes.toString('utf8'))
    || !/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(origin(expectedOrigin).hostname)
    || /^[0-9.]+$/u.test(origin(expectedOrigin).hostname)) throw fail();
  const c = new X509Certificate(certBytes), key = createPrivateKey(keyBytes), now = Date.now();
  if (c.ca || !Number.isFinite(Date.parse(c.validFrom)) || !Number.isFinite(Date.parse(c.validTo))
    || Date.parse(c.validFrom) > now || Date.parse(c.validTo) <= now || !c.checkPrivateKey(key)
    || !(key.asymmetricKeyType === 'rsa' && key.asymmetricKeyDetails.modulusLength >= 2048
      || key.asymmetricKeyType === 'ec' && ['prime256v1','secp384r1','secp521r1'].includes(key.asymmetricKeyDetails.namedCurve))
    || c.checkHost(origin(expectedOrigin).hostname, { subject: 'never', wildcards: false }) !== origin(expectedOrigin).hostname
    || !c.keyUsage?.includes('1.3.6.1.5.5.7.3.1')) throw fail();
  if (trustBytes) { const root = ca(trustBytes); if (!c.checkIssued(root) || !c.verify(root.publicKey)) throw fail(); }
  return sha(createPublicKey(key).export({ type: 'spki', format: 'der' }));
}
function serviceBindings(plan, files) {
  const get = name => files.get(name).bytes;
  const p = parse(get('participant_material/service.json')), c = plan.configuration;
  exact(p, ['profile','deploymentId','conversationId','stateDirectory','participant','receiver','identity','provider','wordpress','activation','content','secrets','tls','trust']);
  exact(p.participant, ['origin','host','port']); exact(p.receiver, ['origin','host','port']);
  exact(p.identity, ['issuer','authorizationEndpoint','tokenEndpoint','jwksUri','callbackUri','clientId','tokenEndpointAuthMethod','signingAlgorithm','clientSecretFile','identityKeyFile'], ['caFile']);
  exact(p.provider, ['origin']); exact(p.wordpress, ['origin']);
  exact(p.activation, ['sourceRevision','images','recoveryEpoch','keyId','publicKeyFile'],
    [...(c.version >= 2 ? ['edgeMaterialSha256'] : []), ...(c.version === 3 ? ['operatorAccessSha256'] : [])]);
  exact(p.content, ['consentVersion','notice','statementIds','statements']);
  exact(p.secrets, ['gatewayKeyFile','providerKeyFile','wordpressRequestKeyFile','wordpressResponseKeyFile','wordpressEventKeyFile']);
  exact(p.tls, ['participantKeyFile','participantCertFile','receiverKeyFile','receiverCertFile']); exact(p.trust, ['providerCaFile','wordpressCaFile']);
  if (p.profile !== 'FNCP_PRODUCTION_SERVICE_V1' || p.stateDirectory !== '/var/lib/fncp' || p.deploymentId !== c.deployment
    || p.conversationId !== c.binding.conversationId || canonical(p.content.statementIds) !== canonical(c.binding.statementIds)
    || p.activation.sourceRevision !== c.sourceRevision || canonical(p.activation.images) !== canonical(plan.imageLock.images)
    || !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u.test(p.activation.recoveryEpoch)
    || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/u.test(p.activation.keyId)
    || p.provider.origin !== 'https://polis-proxy:8443' || p.wordpress.origin !== 'https://wordpress:8443'
    || new Set([p.participant.origin,p.receiver.origin,p.provider.origin,p.wordpress.origin]).size !== 4
    || p.receiver.origin !== 'https://participant-events:8444' || p.participant.port !== 8443 || p.receiver.port !== 8444
    || p.participant.host !== '0.0.0.0' || p.receiver.host !== '0.0.0.0'
    || p.identity.issuer !== c.identity.issuer || p.identity.clientId !== c.identity.audience || p.identity.jwksUri !== c.identity.jwksUri
    || p.identity.callbackUri !== p.participant.origin + '/oidc/callback'
    || !['RS256','ES256'].includes(p.identity.signingAlgorithm) || !['client_secret_basic','client_secret_post'].includes(p.identity.tokenEndpointAuthMethod)
    || !Array.isArray(p.content.statements) || p.content.statements.length !== 15 || new Set(p.content.statements).size !== 15
    || p.content.statements.some(s => typeof s !== 'string' || !s.trim() || s.length > 3000)
    || p.content.statementIds.some((id, i) => i > 0 && id <= p.content.statementIds[i - 1])
    || !/^[A-Za-z0-9_-]{1,128}$/u.test(p.content.consentVersion)) throw fail();
  origin(p.participant.origin);
  for (const field of ['issuer','authorizationEndpoint','tokenEndpoint','jwksUri','callbackUri']) {
    const u = new URL(p.identity[field]); if (u.protocol !== 'https:' || u.href !== p.identity[field] || u.username || u.password || u.search || u.hash) throw fail();
  }
  if (new Set(['authorizationEndpoint','tokenEndpoint','jwksUri','callbackUri'].map(k => p.identity[k])).size !== 4) throw fail();
  exact(p.content.notice, ['adultDeclaration','eligibilityDeclaration','registrationDeclaration']);
  if (Object.values(p.content.notice).some(s => typeof s !== 'string' || !s.trim() || s.length > 3000)) throw fail();
  for (const [field, name] of Object.entries(PARTICIPANT)) { const [group, key] = field.split('.'); if (p[group][key] !== '/run/fncp/' + name) throw fail(); }
  if (p.identity.caFile !== undefined && p.identity.caFile !== '/run/fncp/identity-ca.pem') throw fail();
  if (p.identity.caFile) ca(get('participant_material/identity-ca.pem'));
  const secret = name => { const value = text(get('participant_material/' + name)); secretBytes(value).fill(0); return value; };
  const keys = Object.fromEntries(['identity-key.txt','gateway-key.txt','provider-key.txt','wordpress-request-key.txt','wordpress-response-key.txt','wordpress-event-key.txt'].map(n => [n, secret(n)]));
  const clientSecret = text(get('participant_material/oidc-secret.txt'));
  if (!/^[\x21-\x7e]{16,2048}$/u.test(clientSecret) || new Set([...Object.values(keys), clientSecret]).size !== 7) throw fail();
  const api = text(get('core/material/api.env').subarray(0, get('core/material/api.env').length - 1));
  const fields = Object.fromEntries(api.split('\n').map(line => { const i = line.indexOf('='); return [line.slice(0, i), line.slice(i + 1)]; }));
  if (keys['gateway-key.txt'] !== fields.FNCP_GATEWAY_SHARED_SECRET || keys['provider-key.txt'] !== fields.FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL) throw fail();
  const pub = text(get('participant_material/activation-public.pem').subarray(0, get('participant_material/activation-public.pem').length - 1));
  if (!/^-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+-----END PUBLIC KEY-----$/u.test(pub) || createPublicKey(pub).asymmetricKeyType !== 'ed25519') throw fail();
  const wp = parse(get('wordpress_material/config.json')), plugin = parse(get('wordpress_material/plugin-config.json'));
  exact(wp, ['profile','wordpressOrigin','databaseName','databaseUser','databasePassword','tablePrefix','salts']);
  exact(plugin, ['profile','deploymentId','conversationId','wordpressOrigin','eventEndpoint','consentVersion','noticeSha256','serviceRequestKey','serviceResponseKey','eventKey','caFile']);
  if (wp.profile !== 'FNCP_WORDPRESS_RUNTIME_V1' || wp.wordpressOrigin !== p.wordpress.origin
    || !/^[a-z][a-z0-9_]{2,62}$/u.test(wp.databaseName) || !/^[a-z][a-z0-9_]{2,31}$/u.test(wp.databaseUser)
    || !/^[a-z][a-z0-9_]{1,24}_$/u.test(wp.tablePrefix) || !Array.isArray(wp.salts) || wp.salts.length !== 8
    || plugin.profile !== 'FNCP_PRODUCTION_WORDPRESS_V1' || plugin.deploymentId !== p.deploymentId || plugin.conversationId !== p.conversationId
    || plugin.wordpressOrigin !== wp.wordpressOrigin || plugin.eventEndpoint !== p.receiver.origin + '/internal/wordpress/events'
    || plugin.consentVersion !== p.content.consentVersion || plugin.noticeSha256 !== sha(canonical(p.content.notice))
    || plugin.serviceRequestKey !== keys['wordpress-request-key.txt'] || plugin.serviceResponseKey !== keys['wordpress-response-key.txt']
    || plugin.eventKey !== keys['wordpress-event-key.txt'] || plugin.caFile !== '/run/fncp/wordpress/receiver-ca.pem') throw fail();
  for (const value of [wp.databasePassword, ...wp.salts]) secretBytes(value).fill(0);
  const extraCoreKeys = ['owner','migration','runtime','math'].map(role => text(get('core/material/database-' + role + '-password')));
  extraCoreKeys.push(fields.LOGIN_CODE_PEPPER, fields.ENCRYPTION_PASSWORD_00001);
  extraCoreKeys.push(get('core/material/math.env').toString('utf8').split('\n').find(line => line.startsWith('WEBSERVER_PASS=')).slice('WEBSERVER_PASS='.length));
  if (new Set([wp.databasePassword, ...wp.salts, ...Object.values(keys), clientSecret, ...extraCoreKeys]).size !== 23) throw fail();
  const tlsKeys = [
    leaf(get('participant_material/participant-cert.pem'), get('participant_material/participant-key.pem'), p.participant.origin),
    leaf(get('participant_material/receiver-cert.pem'), get('participant_material/receiver-key.pem'), p.receiver.origin, get('wordpress_material/receiver-ca.pem')),
    leaf(get('wordpress_material/server.pem'), get('wordpress_material/server-key.pem'), p.wordpress.origin, get('participant_material/wordpress-ca.pem')),
    leaf(get('proxy_material/proxy-cert.pem'), get('proxy_material/proxy-key.pem'), p.provider.origin, get('participant_material/provider-ca.pem')),
  ];
  for (const file of ['core/material/database-server.key','core/material/jwt-private.pem'])
    tlsKeys.push(sha(createPublicKey(createPrivateKey(get(file))).export({ type: 'spki', format: 'der' })));
  if (c.version === 3 && p.activation.operatorAccessSha256 !== sha(canonical(c.operatorAccess))) throw fail();
  if (c.version >= 2) {
    if (p.activation.edgeMaterialSha256 !== sha(canonical([...EDGE].sort().map(name => ({name,sha256:sha(get('edge_material/'+name))}))))) throw fail();
    const edge = parse(get('edge_material/config.json'));
    exact(edge, ['version','profile','publicOrigin','discardCookies']);
    if (edge.version !== 1 || edge.profile !== 'FNCP_PARTICIPANT_EDGE_CONTAINER_V1'
      || edge.publicOrigin !== p.participant.origin || edge.publicOrigin !== c.edge.publicOrigin
      || canonical(edge.discardCookies) !== canonical(c.edge.discardCookies)) throw fail();
    tlsKeys.push(leaf(get('edge_material/server.pem'), get('edge_material/server-key.pem'), edge.publicOrigin));
    leaf(get('participant_material/participant-cert.pem'), get('participant_material/participant-key.pem'),
      edge.publicOrigin, get('edge_material/upstream-ca.pem'));
  }
  if (new Set(tlsKeys).size !== (c.version >= 2 ? 7 : 6)) throw fail();
  return p;
}
function put(path, bytes, mode = 0o600) {
  let fd; try {
    fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, mode);
    // Preserve the exact reviewed recipient-readable bind modes even under a
    // secure077 umask. Only this invocation's newly exclusive-created FD is
    // changed; existing files and the mandatory0700 parent are never repaired.
    fchmodSync(fd, mode); writeFileSync(fd, bytes); fsyncSync(fd);
  }
  finally { if (fd !== undefined) closeSync(fd); }
}
function syncDirectory(path) {
  let fd; try { fd = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW); fsyncSync(fd); }
  finally { if (fd !== undefined) closeSync(fd); }
}
function verifyCaptured(files, base) {
  for (const [name, captured] of files) {
    const now = read(join(base, name), captured.mode);
    if (!same(now.stat, captured.stat) || !same(now.parent, captured.parent) || !now.bytes.equals(captured.bytes)) throw fail();
    now.bytes.fill(0);
  }
  // A later read must not hide an in-place rewrite of an earlier file.
  for (const [name, captured] of files) {
    if (!same(captured.stat, lstatSync(join(base, name), { bigint: true }))
      || !same(captured.parent, directory(dirname(join(base, name))))) throw fail();
  }
}
/** The output is only an offline operator-owned staging directory. Its receipts
 * do not attest to Linux volume ownership, database initialization or readiness. */
export async function stageProductionMaterial(options) {
  const files = new Map(); let lockFd, lockStat;
  let inputDirectory, targetDirectory;
  try {
    exact(options, ['inputDirectory','targetDirectory']); ({ inputDirectory, targetDirectory } = options);
    pathCheck(inputDirectory); pathCheck(targetDirectory);
    if (!outside(inputDirectory, targetDirectory) || !outside(targetDirectory, inputDirectory)) throw fail();
    const inputStat = directory(inputDirectory), targetParent = directory(dirname(targetDirectory));
    const capture = (name, mode = 0o600) => { const r = read(join(inputDirectory, name), mode); files.set(name, r); return r.bytes; };
    const plan = parse(capture('installation.json'));
    exact(plan, ['version','profile','configuration','imageLock','ownerToken']);
    if (!(plan.version === 1 && plan.profile === PROFILE && plan.configuration?.version === 1 && plan.imageLock?.version === 1
      || plan.version === 2 && plan.profile === PROFILE_V2 && plan.configuration?.version === 2 && plan.imageLock?.version === 2
      || plan.version === 3 && plan.profile === PROFILE_V3 && plan.configuration?.version === 3 && plan.imageLock?.version === 3)) throw fail();
    const groups = ['participant_material','wordpress_material','proxy_material', ...(plan.version >= 2 ? ['edge_material'] : [])];
    const directories = ['','core','core/material', ...groups];
    names(inputDirectory, ['installation.json','core',...groups]);
    validateProductionConfiguration(plan.configuration); validateProductionImageLock(plan.imageLock);
    if (plan.configuration.stateDirectory !== join(targetDirectory, 'core')) throw fail();
    const compose = renderProductionCompose(plan.configuration, plan.imageLock, plan.ownerToken);
    const core = join(inputDirectory, 'core'); directory(core); names(core, ['material']); names(join(core, 'material'), CORE);
    const { profile: ignoredProfile, oidcEgress: ignoredEgress, edge: ignoredEdge,
      operatorAccess: ignoredOperatorAccess, ...coreConfiguration } = plan.configuration;
    const coreSnapshot = await snapshotMaterial({ ...coreConfiguration, version: 1, classification: 'closed-local-core',
      engine: { host: 'unix:///unused-offline.sock', configDirectory: inputDirectory }, stateDirectory: core });
    for (const entry of coreSnapshot.files) { const bytes = capture('core/material/' + entry.name, entry.mode); if (sha(bytes) !== entry.sha256) throw fail(); }
    const manifest = parse(capture('participant_material/service.json'));
    const participantFiles = ['service.json', ...Object.values(PARTICIPANT), ...(manifest.identity?.caFile ? ['identity-ca.pem'] : [])];
    for (const [group, expected] of [['participant_material', participantFiles], ['wordpress_material', WP], ['proxy_material', PROXY], ...(plan.version >= 2 ? [['edge_material', EDGE]] : [])]) {
      directory(join(inputDirectory, group)); names(join(inputDirectory, group), expected);
      for (const name of expected) if (!files.has(group + '/' + name)) capture(group + '/' + name);
    }
    serviceBindings(plan, files);
    verifyCaptured(files, inputDirectory);
    if (!same(inputStat, directory(inputDirectory)) || !same(targetParent, directory(dirname(targetDirectory)))) throw fail();
    const output = new Map([...files].map(([name, r]) => [name, { bytes: r.bytes, mode: r.mode }]));
    output.set('compose.json', { bytes: encoded(compose), mode: 0o600 });
    const receipt = { version: plan.version, profile: plan.profile, ownerToken: plan.ownerToken, deployment: plan.configuration.deployment,
      configurationSha256: sha(canonical(plan.configuration)), imageLockSha256: sha(canonical(plan.imageLock)),
      files: [...output].sort(([a], [b]) => a.localeCompare(b)).map(([name, r]) => ({ name, mode: r.mode, size: r.bytes.length, sha256: sha(r.bytes) })),
      databaseInitialized: false, linuxVolumeOwnershipEstablished: false, activationGranted: false, publishedPorts: plan.version === 3 ? 2 : 0 };
    output.set('stage.receipt.json', { bytes: encoded(receipt), mode: 0o600 });
    const verifyOutput = () => {
      const heldDirectories = new Map(directories.map(group => [join(targetDirectory, group), directory(join(targetDirectory, group))]));
      names(targetDirectory, ['installation.json','compose.json','stage.receipt.json','core',...groups]);
      directory(join(targetDirectory, 'core')); names(join(targetDirectory, 'core'), ['material']);
      for (const group of ['core/material',...groups]) {
        directory(join(targetDirectory, group)); names(join(targetDirectory, group), [...output.keys()].filter(n => dirname(n) === group).map(n => n.slice(group.length + 1)));
      }
      const capturedOutput = new Map();
      try {
        for (const [name, r] of output) { const actual = read(join(targetDirectory, name), r.mode); capturedOutput.set(name, actual); if (!actual.bytes.equals(r.bytes)) throw fail(); }
        verifyCaptured(capturedOutput, targetDirectory);
      } finally { for (const r of capturedOutput.values()) r.bytes.fill(0); }
      for (const [path, held] of heldDirectories) if (!same(held, directory(path))) throw fail();
      if (!sameDirectory(targetParent, directory(dirname(targetDirectory)))) throw fail();
    };
    // A sibling lock uses exclusive creation. A crash leaves it deliberately;
    // neither a PID nor elapsed time authorizes takeover or repair.
    const lockPath = targetDirectory + '.stage.lock';
    lockFd = openSync(lockPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    writeFileSync(lockFd, sha(encoded(receipt))); fsyncSync(lockFd); lockStat = fstatSync(lockFd, { bigint: true });
    const custody = () => {
      if (!sameDirectory(targetParent, directory(dirname(targetDirectory))) || !same(lockStat, fstatSync(lockFd, { bigint: true }))
        || !same(lockStat, lstatSync(lockPath, { bigint: true }))) throw fail();
    };
    custody();
    let exists = false; try { lstatSync(targetDirectory); exists = true; } catch (e) { if (e.code !== 'ENOENT') throw e; }
    if (exists) { verifyOutput(); verifyCaptured(files, inputDirectory); custody(); return Object.freeze({ result: 'ALREADY_STAGED_VERIFIED', filesVerified: output.size, changed: false, databaseInitialized: false, activationGranted: false }); }
    mkdirSync(targetDirectory, { mode: 0o700 });
    const createdDirectories = new Map([[targetDirectory, directory(targetDirectory)]]);
    const targetCustody = () => { custody(); for (const [path, held] of createdDirectories) if (!sameDirectory(held, directory(path))) throw fail(); };
    for (const group of ['core','core/material',...groups]) {
      targetCustody(); const path = join(targetDirectory, group); mkdirSync(path, { mode: 0o700 }); createdDirectories.set(path, directory(path)); targetCustody();
    }
    for (const [name, r] of output) {
      targetCustody();
      if (name === 'stage.receipt.json') {
        verifyCaptured(files, inputDirectory); if (!same(inputStat, directory(inputDirectory))) throw fail();
        for (const path of [...createdDirectories.keys()].reverse()) syncDirectory(path);
      }
      put(join(targetDirectory, name), r.bytes, r.mode); targetCustody();
    }
    syncDirectory(targetDirectory); syncDirectory(dirname(targetDirectory)); verifyOutput(); targetCustody();
    return Object.freeze({ result: 'MATERIAL_STAGED', filesVerified: output.size, changed: true, databaseInitialized: false, activationGranted: false });
  } catch { throw fail(); }
  finally {
    if (lockFd !== undefined) {
      const owned = fstatSync(lockFd, { bigint: true }); closeSync(lockFd);
      try { const path = targetDirectory + '.stage.lock', current = lstatSync(path, { bigint: true });
        if (lockStat && same(lockStat, owned) && same(owned, current)) unlinkSync(path); } catch { /* Never remove a substituted or missing lock. */ }
    }
    for (const r of files.values()) r.bytes.fill(0);
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.argv.length !== 4) { console.error('Usage: stage-material.mjs ABSOLUTE_PRIVATE_INPUT ABSOLUTE_NEW_TARGET'); process.exitCode = 1; }
  else stageProductionMaterial({ inputDirectory: process.argv[2], targetDirectory: process.argv[3] })
    .then(result => console.log(JSON.stringify(result))).catch(() => { console.error('FNCP_FRESH_MATERIAL_REJECTED'); process.exitCode = 1; });
}
