import { createPublicKey, createPrivateKey, X509Certificate } from 'node:crypto';
import { isIP } from 'node:net';
import { join, dirname } from 'node:path';
import { createMaterialCustody, privateDirectory } from './custody.mjs';
import { canonical, exact, sha, secretBytes, SHA } from './contracts.mjs';

const denied = () => new Error('Offline production credential renewal denied.');
const seal = binding => ({ binding, bindingSha256: sha(canonical(binding)) });
const same = (a, b) => canonical(a) === canonical(b);

export function validateRenewalTls({ certificate, privateKey, origin }) {
  try {
      const pem = certificate.toString('utf8');
      const encoded = pem.match(/-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----/gu);
      if (!encoded?.length || pem.replace(/-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----/gu, '').trim()) throw denied();
      const chain = encoded.map(value => new X509Certificate(value));
      const cert = chain[0], key = createPrivateKey(privateKey);
      const hostname = new URL(origin).hostname.replace(/^\[|\]$/gu, '');
      const now = Date.now(), from = Date.parse(cert.validFrom), until = Date.parse(cert.validTo);
      if (!Number.isSafeInteger(now) || !Number.isFinite(from) || !Number.isFinite(until) || from > now || until <= now + 3600000
        || cert.ca || cert.keyUsage && !cert.keyUsage.includes('1.3.6.1.5.5.7.3.1')
        || !cert.checkPrivateKey(key) || !(isIP(hostname) ? cert.checkIP(hostname) : cert.checkHost(hostname, { subject: 'never' }))) throw denied();
      for (let i = 1; i < chain.length; i++) {
        if (Date.parse(chain[i].validFrom) > now || Date.parse(chain[i].validTo) <= now + 3600000
          || !chain[i].ca || !chain[i - 1].verify(chain[i].publicKey)) throw denied();
      }
    return true;
  } catch { throw denied(); }
}

// Keep this derivation in lockstep with service.mjs. Integration tests compare
// it with the descriptor produced by the real service, not a duplicate fixture.
export function holdRenewalMaterial(sourceConfigurationPath, targetConfigurationPath, mountView) {
  if (mountView !== undefined) {
    exact(mountView, ['profile', 'sourceStateDirectory', 'targetStateDirectory']);
    if (mountView.profile !== 'FNCP_ARCHIVED_MOUNT_VIEW_V1') throw denied();
    for (const path of [sourceConfigurationPath, targetConfigurationPath]) if (!path.endsWith('/service.json')) throw denied();
    privateDirectory(mountView.sourceStateDirectory); privateDirectory(mountView.targetStateDirectory);
  }
  const custody = createMaterialCustody(), buffers = [];
  const bytes = (path, max) => { const b = custody.read(path, max); buffers.push(b); return b; };
  const text = (path, max = 8192) => {
    const b = bytes(path, max), value = b.toString('utf8');
    if (!Buffer.from(value).equals(b) || value.trim() !== value) throw denied();
    return value;
  };
  const keyHash = value => { const b = secretBytes(value); try { return sha(b); } finally { b.fill(0); } };
  const inspect = (path, stateDirectory) => {
    const physical = logical => {
      if (!mountView) return logical;
      if (logical === path) return path;
      if (typeof logical !== 'string' || !/^\/run\/fncp\/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/u.test(logical)) throw denied();
      return join(dirname(path), logical.slice('/run/fncp/'.length));
    };
    const localBytes = (logical, max) => bytes(physical(logical), max);
    const localText = (logical, max = 8192) => text(physical(logical), max);
    const raw = localBytes(path, 131072), m = JSON.parse(raw.toString('utf8'));
    exact(m, ['profile', 'deploymentId', 'conversationId', 'stateDirectory', 'participant', 'receiver', 'identity', 'provider', 'wordpress', 'activation', 'content', 'secrets', 'tls', 'trust']);
    if (m.profile !== 'FNCP_PRODUCTION_SERVICE_V1') throw denied();
    if (mountView && m.stateDirectory !== '/var/lib/fncp') throw denied();
    privateDirectory(stateDirectory ?? m.stateDirectory);
    exact(m.participant, ['origin', 'host', 'port']); exact(m.receiver, ['origin', 'host', 'port']);
    exact(m.identity, ['issuer', 'authorizationEndpoint', 'tokenEndpoint', 'jwksUri', 'callbackUri', 'clientId', 'tokenEndpointAuthMethod', 'signingAlgorithm', 'clientSecretFile', 'identityKeyFile'], ['caFile']);
    exact(m.provider, ['origin']); exact(m.wordpress, ['origin']);
    exact(m.activation, ['sourceRevision', 'images', 'recoveryEpoch', 'keyId', 'publicKeyFile'], ['edgeMaterialSha256','operatorAccessSha256']);
    if (Object.hasOwn(m.activation.images, 'edge') !== Object.hasOwn(m.activation, 'edgeMaterialSha256')
      || Object.hasOwn(m.activation.images, 'operator') !== Object.hasOwn(m.activation, 'operatorAccessSha256')
      || m.activation.edgeMaterialSha256 !== undefined && !SHA.test(m.activation.edgeMaterialSha256)
      || m.activation.operatorAccessSha256 !== undefined && (!Object.hasOwn(m.activation.images, 'edge') || !SHA.test(m.activation.operatorAccessSha256))) throw denied();
    exact(m.content, ['consentVersion', 'notice', 'statementIds', 'statements']);
    exact(m.secrets, ['gatewayKeyFile', 'providerKeyFile', 'wordpressRequestKeyFile', 'wordpressResponseKeyFile', 'wordpressEventKeyFile']);
    exact(m.tls, ['participantKeyFile', 'participantCertFile', 'receiverKeyFile', 'receiverCertFile']);
    exact(m.trust, [], ['providerCaFile', 'wordpressCaFile']);
    const { clientSecretFile, identityKeyFile, caFile, ...idPublic } = m.identity;
    const identityKey = secretBytes(localText(identityKeyFile)); buffers.push(identityKey);
    const clientSecret = localText(clientSecretFile, 2048);
    if (!/^[\x21-\x7e]{16,2048}$/u.test(clientSecret)) throw denied();
    const secrets = Object.fromEntries(Object.entries(m.secrets).map(([role, p]) => [role, localText(p, 43)]));
    const identityKeySha256 = sha(identityKey), secretHashes = Object.values(secrets).map(keyHash);
    if (new Set([identityKeySha256, ...secretHashes]).size !== 6 || Object.values(secrets).includes(clientSecret)
      || clientSecret === identityKey.toString('base64url')) throw denied();
    const idCa = caFile ? localBytes(caFile) : undefined;
    const providerCa = m.trust.providerCaFile ? localBytes(m.trust.providerCaFile) : undefined;
    const wpCa = m.trust.wordpressCaFile ? localBytes(m.trust.wordpressCaFile) : undefined;
    const tls = Object.fromEntries(Object.entries(m.tls).map(([role, p]) => [role, localBytes(p, role.includes('Key') ? 32768 : 65536)]));
    const tlsHashes = Object.fromEntries(Object.entries(tls).map(([role, b]) => [role.replace('File', 'Sha256'), sha(b)]));
    const publicPem = localBytes(m.activation.publicKeyFile, 8192);
    if (!/^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\r?\n?$/u.test(publicPem.toString('ascii')) || publicPem.some(b => b > 127)) throw denied();
    const publicKey = createPublicKey(publicPem);
    if (publicKey.asymmetricKeyType !== 'ed25519') throw denied();
    const activationAuthority = { keyId: m.activation.keyId, publicKeySha256: sha(publicKey.export({ format: 'der', type: 'spki' })) };
    const identityProof = { configuration: idPublic, identityKeySha256, clientSecretSha256: sha(clientSecret), trustSha256: idCa ? sha(idCa) : null };
    const credentialProof = { listeners: { participant: m.participant, receiver: m.receiver },
      secrets: Object.fromEntries(Object.entries(secrets).map(([role, value]) => [role, sha(value)])), activationAuthority, tls: tlsHashes };
    const configuration = { deploymentId: m.deploymentId, conversationId: m.conversationId, ...m.content,
      noticeSha256: sha(canonical(m.content.notice)), credentialBindingSha256: sha(canonical(credentialProof)), identityBindingSha256: sha(canonical(identityProof)) };
    const provider = { origin: m.provider.origin, conversationId: m.conversationId, statementIds: m.content.statementIds,
      trustSha256: sha(providerCa ?? Buffer.from('NODE_DEFAULT_VERIFIED_TRUST_V1')) };
    const wordpress = { schemaVersion: 1, deploymentId: m.deploymentId, conversationId: m.conversationId,
      origin: m.wordpress.origin, consentVersion: configuration.consentVersion, noticeSha256: configuration.noticeSha256,
      trustSha256: wpCa ? sha(wpCa) : 'NODE_DEFAULT_TRUST', requestKeySha256: keyHash(secrets.wordpressRequestKeyFile), responseKeySha256: keyHash(secrets.wordpressResponseKeyFile) };
    // Each manifest has its own exact material inventory even when immutable
    // files are intentionally shared between source and candidate directories.
    const paths = new Set([mountView ? '/run/fncp/service.json' : path, clientSecretFile, identityKeyFile, caFile, ...Object.values(m.secrets), ...Object.values(m.tls), ...Object.values(m.trust), m.activation.publicKeyFile].filter(Boolean));
    const held = custody.fingerprints();
    const fingerprints = Object.fromEntries([...paths].map(p => [p, held[physical(p)]]));
    if (Object.values(fingerprints).some(value => value === undefined)) throw denied();
    const activation = { deploymentId: m.deploymentId, conversationId: m.conversationId, sourceRevision: m.activation.sourceRevision,
      configSha256: sha(canonical({ manifest: m, material: fingerprints })), seedSha256: sha(canonical(configuration.statements)),
      providerSha256: sha(canonical(provider)), images: m.activation.images, recoveryEpoch: m.activation.recoveryEpoch,
      ...(m.activation.operatorAccessSha256 ? { operatorAccessSha256: m.activation.operatorAccessSha256 } : {}),
      scope: { maxParticipants: 20, statementCount: 15, suggestions: false } };
    return { manifest: m, stateDirectory: stateDirectory ?? m.stateDirectory, descriptor: seal({ configuration, provider, wordpress, activation }), identityProof, credentialProof, tls,
      activationIdentity: sha(canonical([m.deploymentId, m.conversationId, activationAuthority.keyId, activationAuthority.publicKeySha256])) };
  };
  const close = () => { custody.close(); for (const b of buffers) b.fill(0); };
  try {
    const source = inspect(sourceConfigurationPath, mountView?.sourceStateDirectory), target = inspect(targetConfigurationPath, mountView?.targetStateDirectory);
    const before = source.descriptor.binding, after = target.descriptor.binding;
    const comparable = structuredClone(after);
    comparable.configuration.identityBindingSha256 = before.configuration.identityBindingSha256;
    comparable.configuration.credentialBindingSha256 = before.configuration.credentialBindingSha256;
    comparable.activation.configSha256 = before.activation.configSha256;
    comparable.activation.recoveryEpoch = before.activation.recoveryEpoch;
    if (!same(comparable, before) || before.activation.recoveryEpoch === after.activation.recoveryEpoch
      || source.stateDirectory === target.stateDirectory) throw denied();
    const identity = { ...target.identityProof, clientSecretSha256: source.identityProof.clientSecretSha256 };
    const credentials = { ...target.credentialProof, tls: source.credentialProof.tls };
    if (!same(identity, source.identityProof) || !same(credentials, source.credentialProof)) throw denied();
    const changes = [];
    if (source.identityProof.clientSecretSha256 !== target.identityProof.clientSecretSha256) changes.push('oidcClientSecret');
    for (const role of ['participant', 'receiver']) {
      validateRenewalTls({ certificate: target.tls[role + 'CertFile'], privateKey: target.tls[role + 'KeyFile'], origin: target.manifest[role].origin });
      if (source.credentialProof.tls[role + 'CertSha256'] !== target.credentialProof.tls[role + 'CertSha256']
        || source.credentialProof.tls[role + 'KeySha256'] !== target.credentialProof.tls[role + 'KeySha256']) changes.push(role + 'Tls');
    }
    const participantPublic = createPublicKey(createPrivateKey(target.tls.participantKeyFile)).export({ format: 'der', type: 'spki' });
    const receiverPublic = createPublicKey(createPrivateKey(target.tls.receiverKeyFile)).export({ format: 'der', type: 'spki' });
    if (source.manifest.activation.edgeMaterialSha256 !== target.manifest.activation.edgeMaterialSha256) {
      if (!mountView) throw denied();
      changes.push('edgeMaterial');
    }
    if (!changes.length || participantPublic.equals(receiverPublic)) throw denied();
    custody.verify();
    return Object.freeze({ sourceDescriptor: source.descriptor, targetDescriptor: target.descriptor,
      sourcePath: join(source.stateDirectory, 'access.sqlite'), targetPath: join(target.stateDirectory, 'access.sqlite'),
      activationIdentity: source.activationIdentity, changes: Object.freeze(changes), verify: () => custody.verify(), close });
  } catch { close(); throw denied(); }
}
