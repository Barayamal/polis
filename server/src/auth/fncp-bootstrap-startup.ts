/**
 * Local synthetic bootstrap configuration, not production admission or proof of
 * resource ownership. Pure: importing or checking this module performs no I/O.
 * A concrete fresh-only launcher must generate these inputs and verify runtime
 * isolation independently. The ordinary HTTP entrypoint refuses this profile.
 */
export type FreshBootstrapProfile = Readonly<{
  localOnly: true;
  namespaceId: string;
  databaseCertificateSha256: string;
  jwksCertificateSha256: string;
}>;

const invalid = (): never => {
  // Never include environment values, URLs, secrets or paths in diagnostics.
  throw new Error("FNCP_FRESH_BOOTSTRAP_CONFIGURATION_INVALID");
};

const disabled = [
  "DEV_MODE",
  "TESTING",
  "ENABLE_TELEMETRY",
  "USE_NETWORK_HOST",
  "SHOULD_USE_TRANSLATION_API",
  "BACKFILL_COMMENT_LANG_DETECTION",
  "RUN_PERIODIC_EXPORT_TESTS",
  "SERVER_LOG_TO_FILE",
];

const absent = [
  "AUTH_DOMAIN",
  "AUTH0_DOMAIN",
  "AUTH_CLIENT_ID",
  "AUTH0_CLIENT_ID",
  "AUTH_CLIENT_SECRET",
  "AUTH0_CLIENT_SECRET",
  "AUTH_NAMESPACE",
  "AKISMET_ANTISPAM_API_KEY",
  "ANTHROPIC_API_KEY",
  "GEMINI_API_KEY",
  "OPENAI_API_KEY",
  "GOOGLE_CREDENTIALS_BASE64",
  "GOOGLE_CREDS_STRINGIFIED",
  "GOOGLE_APPLICATION_CREDENTIALS",
  "MAILGUN_API_KEY",
  "MAILGUN_DOMAIN",
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  "AWS_PROFILE",
  "AWS_SHARED_CREDENTIALS_FILE",
  "AWS_CONFIG_FILE",
  "AWS_WEB_IDENTITY_TOKEN_FILE",
  "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
  "AWS_CONTAINER_CREDENTIALS_FULL_URI",
  "AWS_REGION",
  "SES_ENDPOINT",
  "DYNAMODB_ENDPOINT",
  "AWS_S3_ENDPOINT",
  "AWS_S3_PUBLIC_ENDPOINT",
  "AWS_S3_BUCKET_NAME",
  "AWS_S3_JOB_BUCKET_NAME",
  "SQS_LOCAL_ENDPOINT",
  "SQS_QUEUE_URL",
  "ADMIN_EMAIL_DATA_EXPORT",
  "ADMIN_EMAIL_DATA_EXPORT_TEST",
  "ADMIN_EMAIL_EMAIL_TEST",
  "POLIS_FROM_ADDRESS",
  "WEBSERVER_PASS",
  "WEBSERVER_USERNAME",
  "JWT_PRIVATE_KEY",
  "JWT_PUBLIC_KEY",
  "PORT",
  "NODE_OPTIONS",
  "NODE_PATH",
  "NODE_EXTRA_CA_CERTS",
  "NODE_USE_SYSTEM_CA",
  "NODE_TLS_REJECT_UNAUTHORIZED",
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
  "PGHOST",
  "PGHOSTADDR",
  "PGPORT",
  "PGDATABASE",
  "PGUSER",
  "PGPASSWORD",
  "PGPASSFILE",
  "PGSERVICE",
  "PGSERVICEFILE",
  "PGSSLMODE",
  "PGSSLROOTCERT",
  "PGSSLCERT",
  "PGSSLKEY",
  "PGOPTIONS",
  "PGCLIENT_ENCODING",
  "PGREPLICATION",
  "PGAPPNAME",
  "PGCONNECT_TIMEOUT",
  "PGBINARY",
  "NODE_PG_FORCE_NATIVE",
];

export function freshBootstrapStartup(
  env: Readonly<Record<string, string | undefined>>
): FreshBootstrapProfile | null {
  const flag = env.FNCP_FRESH_BOOTSTRAP_LOCAL_ONLY;
  if (flag === undefined) return null;
  if (flag !== "true") invalid();
  // Generated environment values are single-line only, including any optional
  // inputs. Enforce that invariant independently of individual field parsers.
  if (
    Object.values(env).some(
      (value) => typeof value === "string" && /[\r\n]/.test(value)
    )
  )
    invalid();
  if (
    env.NODE_ENV !== "production" ||
    disabled.some((key) => env[key] !== "false")
  )
    invalid();
  if (absent.some((key) => env[key] !== undefined)) invalid();

  const allowedFncp = new Set([
    "FNCP_FRESH_BOOTSTRAP_LOCAL_ONLY",
    "FNCP_BOOTSTRAP_DATABASE_CERTIFICATE_SHA256",
    "FNCP_BOOTSTRAP_JWKS_CERTIFICATE_SHA256",
  ]);
  if (
    Object.keys(env).some(
      (key) =>
        (key.startsWith("FNCP_") && !allowedFncp.has(key)) ||
        key.startsWith("DOMAIN_WHITELIST_ITEM_")
    )
  )
    invalid();

  if (
    env.EMAIL_TRANSPORT_TYPES !== "disabled" ||
    env.ADMIN_EMAILS !== "[]" ||
    env.ADMIN_UIDS !== "[]" ||
    env.API_SERVER_PORT !== "5000" ||
    env.DATABASE_SSL !== "true" ||
    env.AUTH_AUDIENCE !== "fncp-fresh-synthetic-bootstrap"
  )
    invalid();

  const hex = /^[a-f0-9]{64}$/;
  const databasePin = env.FNCP_BOOTSTRAP_DATABASE_CERTIFICATE_SHA256;
  const jwksPin = env.FNCP_BOOTSTRAP_JWKS_CERTIFICATE_SHA256;
  if (
    !databasePin ||
    !jwksPin ||
    !hex.test(databasePin) ||
    !hex.test(jwksPin) ||
    databasePin === jwksPin
  )
    invalid();
  if (
    !hex.test(env.LOGIN_CODE_PEPPER || "") ||
    !hex.test(env.ENCRYPTION_PASSWORD_00001 || "") ||
    env.LOGIN_CODE_PEPPER === env.ENCRYPTION_PASSWORD_00001
  )
    invalid();

  const db =
    /^postgres:\/\/fncp_fresh_([a-f0-9]{24}):([a-f0-9]{64})@fncp-fresh-pg-([a-f0-9]{24}):5432\/fncp_fresh_([a-f0-9]{24})$/.exec(
      env.DATABASE_URL || ""
    );
  if (!db || env.READ_ONLY_DATABASE_URL !== env.DATABASE_URL) invalid();
  // The session owner generates independent user/database identities. Only the
  // fresh service DNS namespace is shared; shape validation is not ownership.
  const namespaceId = db![3];
  if (
    db![2] === env.LOGIN_CODE_PEPPER ||
    db![2] === env.ENCRYPTION_PASSWORD_00001
  )
    invalid();
  if (
    env.JWKS_URI !==
    `https://fncp-fresh-jwks-${namespaceId}:8444/.well-known/jwks.json`
  )
    invalid();
  const issuer = /^https:\/\/127\.0\.0\.1:([1-9][0-9]{3,4})\/$/.exec(
    env.AUTH_ISSUER || ""
  );
  if (!issuer || Number(issuer[1]) < 1024 || Number(issuer[1]) > 65535)
    invalid();
  const hostname = `fncp-fresh-api-${namespaceId}:8443`;
  if (
    env.API_PROD_HOSTNAME !== hostname ||
    env.DOMAIN_OVERRIDE !== hostname ||
    env.POLIS_JWT_ISSUER !== `https://${hostname}/` ||
    env.POLIS_JWT_AUDIENCE !== "fncp-fresh-synthetic-participants" ||
    env.JWT_PRIVATE_KEY_PATH !==
      "/run/fncp/bootstrap/participant-private.pem" ||
    env.JWT_PUBLIC_KEY_PATH !== "/run/fncp/bootstrap/participant-public.pem"
  )
    invalid();

  return Object.freeze({
    localOnly: true,
    namespaceId,
    databaseCertificateSha256: databasePin!,
    jwksCertificateSha256: jwksPin!,
  });
}

/** The existing app.listen entrypoint is plaintext, not a bootstrap TLS server. */
export function assertOrdinaryHttpEntrypoint(
  env: Readonly<Record<string, string | undefined>>
): void {
  if (env.FNCP_FRESH_BOOTSTRAP_LOCAL_ONLY !== undefined) {
    throw new Error("FNCP_FRESH_BOOTSTRAP_REQUIRES_OWNED_HTTPS_ENTRYPOINT");
  }
}
