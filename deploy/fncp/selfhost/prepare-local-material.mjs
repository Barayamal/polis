#!/usr/bin/env node
/** Fresh test material only. Generates no activation, invitations, real accounts
 * or provider configuration. The parent directory is private; individually
 * mounted files are readable by their explicit non-root container recipients. */
import { mkdir, open, readFile, chmod, lstat, realpath } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { randomBytes } from 'node:crypto';
import { loadConfiguration, fail } from './configuration.mjs';
import { execute } from './fncpctl.mjs';

export async function prepareLocalMaterial(configPath){
  const c=await loadConfiguration(configPath);const dir=join(c.stateDirectory,'material');
  const custody=await lstat(c.stateDirectory);
  if(!custody.isDirectory()||custody.isSymbolicLink()||custody.uid!==process.getuid()||(custody.mode&0o777)!==0o700||await realpath(c.stateDirectory)!==c.stateDirectory)throw fail('PRIVATE_DIRECTORY');
  await mkdir(dir,{mode:0o700});
  const write=async(name,content,mode=0o600)=>{
    // Apply recipient-readable modes only to a newly exclusive-created file.
    // A restrictive caller umask must not silently break the Linux UID bind.
    const file=await open(join(dir,name),'wx',mode);
    try{await file.chmod(mode);await file.writeFile(content);await file.sync();}finally{await file.close();}
  };
  const secret=()=>randomBytes(32).toString('base64url');
  const secrets={owner:secret(),migration:secret(),runtime:secret(),math:secret(),gateway:secret(),provider:secret()};
  for(const role of ['owner','migration','runtime','math'])await write(`database-${role}-password`,secrets[role],0o644);
  await execute('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','7','-subj','/CN=FNCP local database CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout',join(dir,'local-ca.key'),'-out',join(dir,'database-ca.pem')]);
  await execute('openssl',['req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=postgres','-keyout',join(dir,'database-server.key'),'-out',join(dir,'database-server.csr')]);
  await write('database-server.ext','subjectAltName=DNS:postgres\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n');
  await execute('openssl',['x509','-req','-in',join(dir,'database-server.csr'),'-CA',join(dir,'database-ca.pem'),'-CAkey',join(dir,'local-ca.key'),'-CAcreateserial','-days','7','-extfile',join(dir,'database-server.ext'),'-out',join(dir,'database-server.pem')]);
  await execute('openssl',['genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',join(dir,'jwt-private.pem')]);
  await execute('openssl',['pkey','-in',join(dir,'jwt-private.pem'),'-pubout','-out',join(dir,'jwt-public.pem')]);
  await chmod(join(dir,'local-ca.key'),0o600);
  for(const name of ['database-ca.pem','database-server.pem','database-server.key','jwt-private.pem','jwt-public.pem'])await chmod(join(dir,name),0o644);
  const mathDb=`postgres://${c.database.mathRole}:${secrets.math}@postgres:5432/${c.database.name}`;
  const db=`postgres://${c.database.runtimeRole}:${secrets.runtime}@postgres:5432/${c.database.name}`;
  const env=object=>Object.entries(object).map(([k,v])=>{if(/[\r\n\0]/.test(String(v)))throw fail('ENV_VALUE');return `${k}=${v}`;}).join('\n')+'\n';
  await write('api.env',env({NODE_ENV:'production',FNCP_OPTION_C_RELEASE_MODE:'production',FNCP_GATEWAY_ENFORCEMENT:'true',FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT:'true',FNCP_GATEWAY_CONVERSATION_ID:c.binding.conversationId,FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID:c.binding.conversationId,FNCP_GATEWAY_SHARED_SECRET:secrets.gateway,FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL:secrets.provider,FNCP_FIXED_STATEMENT_IDS:c.binding.statementIds.join(','),DATABASE_URL:db,DATABASE_SSL:'true',DATABASE_SSL_CA_FILE:'/run/fncp/database-ca.pem',AUTH_ISSUER:c.identity.issuer,AUTH_AUDIENCE:c.identity.audience,JWKS_URI:c.identity.jwksUri,JWT_PRIVATE_KEY_PATH:'/run/fncp/jwt-private.pem',JWT_PUBLIC_KEY_PATH:'/run/fncp/jwt-public.pem',API_SERVER_PORT:'5000',API_PROD_HOSTNAME:'polis.local.invalid',DOMAIN_OVERRIDE:'polis.local.invalid',MATH_ENV:'dev',DEV_MODE:'false',TESTING:'false',ENABLE_TELEMETRY:'false',SHOULD_USE_TRANSLATION_API:'false',BACKFILL_COMMENT_LANG_DETECTION:'false',RUN_PERIODIC_EXPORT_TESTS:'false',SERVER_LOG_TO_FILE:'false',EMAIL_TRANSPORT_TYPES:'disabled',ADMIN_EMAILS:'[]',ADMIN_UIDS:'[]',LOGIN_CODE_PEPPER:secret(),ENCRYPTION_PASSWORD_00001:secret()}));
  await write('math.env',env({FNCP_OPTION_C_RELEASE_MODE:'production',DATABASE_URL:mathDb,DATABASE_SSL:'true',DATABASE_SSL_CA_FILE:'/run/fncp/database-ca.pem',MATH_ENV:'dev',LOGGING_LEVEL:'warn',WEBSERVER_USERNAME:'local_unexposed',WEBSERVER_PASS:secret(),DATABASE_POOL_SIZE:'4'}));
  await write('migration.env',env({FNCP_DATABASE_HOST:'postgres',FNCP_DATABASE_PORT:'5432',FNCP_DATABASE_PASSWORD:secrets.migration,FNCP_EXPECTED_DATABASE:c.database.name,FNCP_EXPECTED_MIGRATION_ROLE:c.database.migrationRole,FNCP_RUNTIME_DB_ROLE:c.database.runtimeRole,PGSSLMODE:'verify-full',PGSSLROOTCERT:'/run/fncp/database-ca.pem'}));
  return {result:'PASS',classification:'synthetic-local-configuration',activationGranted:false,identityProviderConfigured:false,materialCreated:true};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  if(process.argv.length!==3){console.error('FNCP_SELFHOST_USAGE');process.exitCode=1;}else prepareLocalMaterial(process.argv[2]).then(r=>console.log(JSON.stringify(r))).catch(()=>{console.error('FNCP_SELFHOST_MATERIAL_FAILED');process.exitCode=1;});
}
