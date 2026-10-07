// Disposable invented material factory for the complete closed-install rehearsal.
// Not production provisioning: two-day local CA, invented accounts, no network.
import {mkdirSync,writeFileSync,readFileSync,chmodSync,renameSync,realpathSync,lstatSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {execFileSync} from 'node:child_process';
import {generateKeyPairSync,randomBytes,randomUUID} from 'node:crypto';
import {canonical,sha} from '../production-service/contracts.mjs';
import {prepareLocalMaterial} from '../selfhost/prepare-local-material.mjs';
import {PROFILE_V2,PROFILE_V3} from './stage-material.mjs';
import {validateProductionImageLock} from '../production-deployment/compose.mjs';
const json=value=>canonical(value)+'\n';
const write=(path,value)=>writeFileSync(path,value,{mode:0o600,flag:'wx'});
const key=()=>randomBytes(32).toString('base64url');
const openssl=args=>execFileSync('openssl',args,{stdio:['ignore','ignore','ignore'],timeout:15000});
export async function createSyntheticInstallation({directory,targetDirectory,imageLock,version=imageLock?.version}) {
  validateProductionImageLock(imageLock); if(![2,3].includes(version)||imageLock.version!==version||resolve(directory)!==directory||resolve(targetDirectory)!==targetDirectory)throw Error('Synthetic fixture rejected.');
  mkdirSync(directory,{mode:0o700}); const root=realpathSync(directory); if(root!==directory)throw Error('Synthetic fixture rejected.');
  const template=join(root,'input');mkdirSync(template,{mode:0o700});
  const generated = join(root, 'generated'); mkdirSync(generated, { mode: 0o700 });
  const operatorAccess={profile:'FNCP_OPERATOR_LOOPBACK_V1',tunnelRequired:true,participant:{hostIp:'127.0.0.1',published:8443,target:8443,protocol:'tcp'},wordpress:{hostIp:'127.0.0.1',published:9443,target:8443,protocol:'tcp'}};
  const configuration = { version, profile: 'FNCP_PRODUCTION_COMPOSE_V'+version, platform: 'linux/arm64',
    deployment: 'fncp-joined-' + randomBytes(6).toString('hex'), sourceRevision: imageLock.sourceRevision, stateDirectory: join(targetDirectory,'core'),
    database: { name: 'fncp_polis', owner: 'fncp_owner', migrationRole: 'fncp_migration', runtimeRole: 'fncp_runtime', mathRole: 'fncp_math', host: 'postgres', port: 5432 },
    binding: { conversationId: '9Synthetic' + randomBytes(6).toString('hex'), statementIds: Array.from({ length: 15 }, (_, i) => i) },
    edge: {publicOrigin:'https://pulse.synthetic.invalid',discardCookies:[]},...(version===3?{operatorAccess}:{}),
    identity: { issuer: 'https://qa-issuer:8443/', audience: 'fncp-main-qa', jwksUri: 'https://qa-issuer:8443/jwks' } };
  const { profile, edge, operatorAccess: ignoredOperatorAccess, ...c } = configuration;
  const coreConfig = { ...c, version:1, stateDirectory: generated, classification: 'closed-local-core', engine: { host: 'unix:///unused.sock', configDirectory: root } };
  const configPath = join(root, 'synthetic-core.json'); write(configPath, json(coreConfig));
  await prepareLocalMaterial(configPath);
  for (const name of ['core','core/material','participant_material','wordpress_material','proxy_material','edge_material','qa_material']) mkdirSync(join(template, name), { mode: 0o700 });
  for (const name of ['api.env','database-ca.pem','database-math-password','database-migration-password','database-owner-password','database-runtime-password',
    'database-server.key','database-server.pem','jwt-private.pem','jwt-public.pem','math.env','migration.env']) {
    const from = join(generated, 'material', name), to = join(template, 'core/material', name);
    const mode = name.endsWith('.env') ? 0o600 : 0o644;
    writeFileSync(to, readFileSync(from), { mode }); chmodSync(to, mode);
  }
  const api = Object.fromEntries(readFileSync(join(template, 'core/material/api.env'), 'utf8').trim().split('\n').map(l => { const i = l.indexOf('='); return [l.slice(0, i), l.slice(i + 1)]; }));
  const authority = generateKeyPairSync('ed25519');
  const materials = { 'oidc-secret.txt': key(), 'identity-key.txt': key(), 'gateway-key.txt': api.FNCP_GATEWAY_SHARED_SECRET,
    'provider-key.txt': api.FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL, 'wordpress-request-key.txt': key(), 'wordpress-response-key.txt': key(), 'wordpress-event-key.txt': key(),
    'activation-public.pem': authority.publicKey.export({ type: 'spki', format: 'pem' }) };
  for (const [n, value] of Object.entries(materials)) write(join(template, 'participant_material', n), value);
  const certdir = join(root, 'certificates'); mkdirSync(certdir, { mode: 0o700 });
  const caKey = join(certdir, 'ca.key'), caPem = join(certdir, 'ca.pem');
  openssl(['req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=Invented staging test root','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout',caKey,'-out',caPem]);
  for (const [name, host, certTarget, keyTarget] of [
    ['participant','pulse.synthetic.invalid','participant_material/participant-cert.pem','participant_material/participant-key.pem'],
    ['receiver','participant-events','participant_material/receiver-cert.pem','participant_material/receiver-key.pem'],
    ['wordpress','wordpress','wordpress_material/server.pem','wordpress_material/server-key.pem'],
    ['proxy','polis-proxy','proxy_material/proxy-cert.pem','proxy_material/proxy-key.pem'],
    ['edge','pulse.synthetic.invalid','edge_material/server.pem','edge_material/server-key.pem'],
    ['issuer','qa-issuer','qa_material/server.pem','qa_material/server-key.pem'],
  ]) {
    const certKey = join(certdir, name + '.key'), csr = join(certdir, name + '.csr'), pem = join(certdir, name + '.pem'), ext = join(certdir, name + '.ext');
    write(ext, 'subjectAltName=DNS:' + host + '\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n');
    openssl(['req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=' + host,'-keyout',certKey,'-out',csr]);
    openssl(['x509','-req','-in',csr,'-CA',caPem,'-CAkey',caKey,'-CAcreateserial','-days','2','-extfile',ext,'-out',pem]);
    write(join(template, certTarget), readFileSync(pem)); write(join(template, keyTarget), readFileSync(certKey));
  }
  for (const path of ['participant_material/wordpress-ca.pem','participant_material/provider-ca.pem','wordpress_material/receiver-ca.pem','edge_material/upstream-ca.pem','participant_material/identity-ca.pem']) write(join(template, path), readFileSync(caPem));
  const p = { profile: 'FNCP_PRODUCTION_SERVICE_V1', deploymentId: configuration.deployment, conversationId: configuration.binding.conversationId,
    stateDirectory: '/var/lib/fncp', participant: { origin: 'https://pulse.synthetic.invalid', host: '0.0.0.0', port: 8443 },
    receiver: { origin: 'https://participant-events:8444', host: '0.0.0.0', port: 8444 },
    identity: { issuer: configuration.identity.issuer, authorizationEndpoint: 'https://qa-issuer:8443/authorize', tokenEndpoint: 'https://qa-issuer:8443/token',
      jwksUri: configuration.identity.jwksUri, callbackUri: 'https://pulse.synthetic.invalid/oidc/callback', clientId: configuration.identity.audience,
      tokenEndpointAuthMethod: 'client_secret_basic', signingAlgorithm: 'ES256', caFile: '/run/fncp/identity-ca.pem', clientSecretFile: '/run/fncp/oidc-secret.txt', identityKeyFile: '/run/fncp/identity-key.txt' },
    provider: { origin: 'https://polis-proxy:8443' }, wordpress: { origin: 'https://wordpress:8443' },
    activation: { sourceRevision: configuration.sourceRevision, images: imageLock.images, recoveryEpoch: randomUUID(), keyId: 'synthetic-review-authority', publicKeyFile: '/run/fncp/activation-public.pem' },
    content: { consentVersion: 'synthetic-v1', notice: { adultDeclaration: 'Invented adult declaration.', eligibilityDeclaration: 'Invented eligibility declaration.', registrationDeclaration: 'Invented consent declaration.' },
      statementIds: configuration.binding.statementIds, statements: Array.from({ length: 15 }, (_, i) => 'Invented test statement ' + (i+1) + '.') },
    secrets: { gatewayKeyFile: '/run/fncp/gateway-key.txt', providerKeyFile: '/run/fncp/provider-key.txt', wordpressRequestKeyFile: '/run/fncp/wordpress-request-key.txt', wordpressResponseKeyFile: '/run/fncp/wordpress-response-key.txt', wordpressEventKeyFile: '/run/fncp/wordpress-event-key.txt' },
    tls: { participantKeyFile: '/run/fncp/participant-key.pem', participantCertFile: '/run/fncp/participant-cert.pem', receiverKeyFile: '/run/fncp/receiver-key.pem', receiverCertFile: '/run/fncp/receiver-cert.pem' },
    trust: { providerCaFile: '/run/fncp/provider-ca.pem', wordpressCaFile: '/run/fncp/wordpress-ca.pem' } };
  write(join(template, 'wordpress_material/config.json'), json({ profile: 'FNCP_WORDPRESS_RUNTIME_V1', wordpressOrigin: p.wordpress.origin, databaseName: 'fncp_wordpress', databaseUser: 'fncp_wp', databasePassword: key(), tablePrefix: 'fncp_', salts: Array.from({ length: 8 }, key) }));
  write(join(template, 'wordpress_material/plugin-config.json'), json({ profile: 'FNCP_PRODUCTION_WORDPRESS_V1', deploymentId: p.deploymentId, conversationId: p.conversationId,
    wordpressOrigin: p.wordpress.origin, eventEndpoint: p.receiver.origin + '/internal/wordpress/events', consentVersion: p.content.consentVersion, noticeSha256: sha(canonical(p.content.notice)),
    serviceRequestKey: materials['wordpress-request-key.txt'], serviceResponseKey: materials['wordpress-response-key.txt'], eventKey: materials['wordpress-event-key.txt'], caFile: '/run/fncp/wordpress/receiver-ca.pem' }));
  write(join(template, 'installation.json'), json({ version, profile: version===3?PROFILE_V3:PROFILE_V2, configuration, imageLock, ownerToken: randomBytes(24).toString('hex') }));
  write(join(template,'edge_material/config.json'),json({version:1,profile:'FNCP_PARTICIPANT_EDGE_CONTAINER_V1',...configuration.edge}));
  p.activation.edgeMaterialSha256=sha(canonical(['config.json','server.pem','server-key.pem','upstream-ca.pem'].sort().map(name=>({name,sha256:sha(readFileSync(join(template,'edge_material',name)))}))));
  if(version===3)p.activation.operatorAccessSha256=sha(canonical(configuration.operatorAccess));
  write(join(template, 'participant_material/service.json'), json(p));
  const operator = {profile:'FNCP_WORDPRESS_INITIALIZE_V1',siteTitle:'Invented closed Community Pulse',operatorLogin:'qa_operator',operatorEmail:'operator@example.invalid',operatorPassword:key()};
  write(join(root,'operator.json'),json(operator));
  const signing = generateKeyPairSync('ec',{namedCurve:'prime256v1'});
  const qa = {profile:'FNCP_JOINED_INSTALL_QA_OWNER_V'+version,issuer:{profile:'FNCP_NORMAL_MAIN_QA_IDP_V1',origin:'https://qa-issuer:8443',host:'0.0.0.0',port:8443,
    tls:{cert:readFileSync(join(template,'qa_material/server.pem'),'utf8'),key:readFileSync(join(template,'qa_material/server-key.pem'),'utf8')},
    signingKey:signing.privateKey.export({format:'pem',type:'pkcs8'}),clientId:configuration.identity.audience,clientSecret:materials['oidc-secret.txt'],
    callbackUri:p.identity.callbackUri,ownerKey:key()},issuerCa:readFileSync(caPem,'utf8'),edgeCa:readFileSync(caPem,'utf8'),wordpressCa:readFileSync(caPem,'utf8'),
    operatorPassword:operator.operatorPassword,activationPrivateKey:authority.privateKey.export({format:'pem',type:'pkcs8'}),
    expectedBinding:{deploymentId:p.deploymentId,conversationId:p.conversationId,sourceRevision:imageLock.sourceRevision,images:imageLock.images,
      ...(version===3?{operatorAccessSha256:p.activation.operatorAccessSha256}:{})}};
  write(join(root,'qa-owner.json'),json(qa));
  renameSync(join(template,'qa_material'),join(root,'qa_material'));
  return {inputDirectory:template,targetDirectory,operatorFile:join(root,'operator.json'),qaOwnerFile:join(root,'qa-owner.json'),configuration};

}
