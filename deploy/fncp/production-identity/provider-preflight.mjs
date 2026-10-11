import { constants, closeSync, fstatSync, lstatSync, openSync, readSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, parse, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

export const MAX_PUBLIC_INPUT_BYTES = 65_536;
const PROFILE = 'OIDC_PARTICIPANT_V1';
const PUBLIC_FIELDS = Object.freeze(['issuer', 'authorizationEndpoint', 'tokenEndpoint', 'jwksUri',
  'callbackUri', 'clientId', 'tokenEndpointAuthMethod', 'signingAlgorithm']);
const DENIED_KEYS = new Set(['__proto__', 'prototype', 'constructor', 'clientsecret', 'clientsecretfile',
  'identitykey', 'identitykeyfile', 'privatekey', 'privatekeyfile', 'password', 'accesstoken',
  'refreshtoken', 'idtoken', 'authorizationcode', 'codeverifier', 'authorization', 'cookie', 'tokens']);
const RUNTIME_GATES = Object.freeze(['METADATA_PROVENANCE_AND_FRESHNESS', 'CLIENT_REGISTRATION_AND_CALLBACK',
  'HTTPS_ENDPOINTS_AND_JWKS_ROTATION', 'CODE_QUERY_S256_STATE_NONCE_AND_ISS',
  'ID_TOKEN_EMAIL_AND_TRUE_EMAIL_VERIFIED', 'ID_TOKEN_SIGNATURE_AUDIENCE_AND_TIME',
  'REAL_BROWSER_SESSION_AND_REPLAY', 'DEPLOYMENT_INTEGRATION_AND_OWNER_APPROVAL']);
const failure = () => new Error('Public provider preflight input rejected.');
const plain = value => value !== null && typeof value === 'object'
  && [Object.prototype, null].includes(Object.getPrototypeOf(value));

// Validate data descriptors before reading values. No toJSON/getter execution.
// The CLI accepts JSON, not executable JS objects; hostile Proxies are outside
// this in-process API's trust boundary.
function publicCopy(input) {
  const seen = new Set(); let nodes = 0;
  function copy(value, depth = 0) {
    if (++nodes > 4096 || depth > 16) throw failure();
    if (value === null || typeof value === 'boolean') return value;
    if (typeof value === 'string') {
      if (value.length > 8192 || /[\u0000-\u001f\u007f]/u.test(value)) throw failure();
      return value;
    }
    if (typeof value === 'number' && Number.isFinite(value)) return value;
    if ((!plain(value) && !Array.isArray(value)) || seen.has(value)) throw failure();
    seen.add(value);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length > 1025 || keys.some(key => typeof key !== 'string'
      || !Object.hasOwn(descriptors[key], 'value'))) throw failure();
    let result;
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype || value.length > 1024
        || keys.length !== value.length + 1 || keys.some(key => key !== 'length'
          && !/^(0|[1-9][0-9]*)$/u.test(key))) throw failure();
      result = Array.from({ length: value.length }, (_, index) => {
        if (!Object.hasOwn(descriptors, index)) throw failure();
        return copy(descriptors[index].value, depth + 1);
      });
    } else {
      result = Object.create(null);
      for (const key of keys) {
        if (key.length > 256 || /[\u0000-\u001f\u007f]/u.test(key)
          || DENIED_KEYS.has(key.toLowerCase().replace(/[-_]/gu, ''))
          || ['__proto__', 'prototype', 'constructor'].includes(key)) throw failure();
        result[key] = copy(descriptors[key].value, depth + 1);
      }
    }
    seen.delete(value);
    return result;
  }
  const result = copy(input);
  if (Buffer.byteLength(JSON.stringify(result)) > MAX_PUBLIC_INPUT_BYTES) throw failure();
  return result;
}

function exact(value, fields) {
  if (!plain(value) || Object.keys(value).length !== fields.length
    || fields.some(field => !Object.hasOwn(value, field))) throw failure();
}

// Same URL acceptance rules as https-transport.mjs, without importing a network
// module or constructing an adapter. Exact strings, including slash, matter.
function canonicalHttps(value) {
  if (typeof value !== 'string' || !value.length || value.length > 2048
    || /[\u0000-\u0020\u007f]/u.test(value)) throw failure();
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash
    || url.href !== value) throw failure();
  return value;
}

function requirementsCopy(input) {
  const requirements = publicCopy(input); exact(requirements, PUBLIC_FIELDS);
  for (const field of PUBLIC_FIELDS.slice(0, 5)) canonicalHttps(requirements[field]);
  if (new Set(PUBLIC_FIELDS.slice(1, 5).map(field => requirements[field])).size !== 4
    || typeof requirements.clientId !== 'string' || !requirements.clientId.length || requirements.clientId.length > 256
    || !['client_secret_basic', 'client_secret_post'].includes(requirements.tokenEndpointAuthMethod)
    || !['RS256', 'ES256'].includes(requirements.signingAlgorithm)) throw failure();
  return requirements;
}

function report(checks, inputRejected = false) {
  const counts = { MATCH: 0, UNVERIFIED: 0, INCOMPATIBLE: 0, REJECTED: 0 };
  for (const check of checks) counts[check.status]++;
  const metadataAssessment = inputRejected || counts.REJECTED ? 'INPUT_REJECTED'
    : counts.INCOMPATIBLE ? 'INCOMPATIBLE' : counts.UNVERIFIED ? 'UNVERIFIED' : 'METADATA_MATCH';
  return Object.freeze({ version: 1, profile: PROFILE, status: 'HOLD', metadataAssessment,
    providerRuntimeVerified: false, deploymentAuthorized: false, participantAccessGranted: false,
    networkRequestsMade: 0, filesWritten: 0, counts: Object.freeze(counts),
    checks: Object.freeze(checks.map(check => Object.freeze(check))),
    runtimeGates: Object.freeze(RUNTIME_GATES.map(code => Object.freeze({ code, status: 'UNVERIFIED' }))) });
}

/** Pure offline comparison of public metadata against the public subset of the
 * current adapter constructor. A metadata match is never runtime assurance.
 * No credentials, manifests, CA/key files, identity objects or provider claims.
 */
export function evaluateProviderPreflight(input) {
  const checks = [];
  const add = (id, status, code) => checks.push({ id, status, code });
  try {
    // Copy the wrapper too, so a metadata/requirements getter cannot run.
    const safe = publicCopy(input); exact(safe, ['metadata', 'requirements']);
    const metadata = safe.metadata;
    if (!plain(metadata)) throw failure();
    const requirements = requirementsCopy(safe.requirements);
    add('public-requirements', 'MATCH', 'ADAPTER_PUBLIC_CONFIGURATION_VALID');
    for (const [field, configuration] of [['issuer', 'issuer'], ['authorization_endpoint', 'authorizationEndpoint'],
      ['token_endpoint', 'tokenEndpoint'], ['jwks_uri', 'jwksUri']]) {
      if (!Object.hasOwn(metadata, field)) add(field, 'UNVERIFIED', 'REQUIRED_ENDPOINT_NOT_SUPPLIED');
      else {
        let valid = true;
        try { canonicalHttps(metadata[field]); } catch { valid = false; }
        add(field, valid && metadata[field] === requirements[configuration] ? 'MATCH' : 'INCOMPATIBLE',
          !valid ? 'ENDPOINT_UNSUPPORTED_BY_ADAPTER' : metadata[field] !== requirements[configuration]
            ? 'EXACT_ENDPOINT_MISMATCH' : 'EXACT_ENDPOINT_MATCH');
      }
    }
    function list(field, required, missingCode, nonExhaustive = false) {
      if (!Object.hasOwn(metadata, field)) { add(field, 'UNVERIFIED', missingCode); return; }
      const values = metadata[field];
      if (!Array.isArray(values) || !values.length || values.length > 256
        || values.some(value => typeof value !== 'string' || !value.length || value.length > 256)
        || new Set(values).size !== values.length) {
        add(field, 'REJECTED', 'METADATA_LIST_INVALID'); return;
      }
      const satisfied = required.every(value => values.includes(value));
      add(field, satisfied ? 'MATCH' : nonExhaustive ? 'UNVERIFIED' : 'INCOMPATIBLE',
        satisfied ? 'REQUIRED_CAPABILITY_ADVERTISED' : nonExhaustive
          ? 'NONEXHAUSTIVE_CAPABILITY_NOT_ADVERTISED' : 'REQUIRED_CAPABILITY_NOT_SUPPORTED');
    }
    list('response_types_supported', ['code'], 'REQUIRED_CODE_METADATA_NOT_SUPPLIED');
    list('response_modes_supported', ['query'], 'QUERY_STANDARD_DEFAULT_UNVERIFIED');
    list('grant_types_supported', ['authorization_code'], 'CODE_GRANT_STANDARD_DEFAULT_UNVERIFIED');
    list('code_challenge_methods_supported', ['S256'], 'PKCE_OMISSION_DOES_NOT_ESTABLISH_SUPPORT');
    list('token_endpoint_auth_methods_supported', [requirements.tokenEndpointAuthMethod],
      requirements.tokenEndpointAuthMethod === 'client_secret_basic'
        ? 'BASIC_STANDARD_DEFAULT_UNVERIFIED' : 'BASIC_DEFAULT_DOES_NOT_ESTABLISH_POST');
    list('id_token_signing_alg_values_supported', [requirements.signingAlgorithm], 'REQUIRED_SIGNING_METADATA_NOT_SUPPLIED');
    list('scopes_supported', ['openid', 'email'], 'SCOPE_METADATA_NOT_SUPPLIED', true);
    list('claims_supported', ['sub', 'email', 'email_verified'], 'CLAIM_METADATA_NOT_SUPPLIED', true);
    function boolean(field, expected, missingCode) {
      if (!Object.hasOwn(metadata, field)) add(field, 'UNVERIFIED', missingCode);
      else if (typeof metadata[field] !== 'boolean') add(field, 'REJECTED', 'METADATA_BOOLEAN_INVALID');
      else add(field, metadata[field] === expected ? 'MATCH' : 'INCOMPATIBLE',
        metadata[field] === expected ? 'REQUIRED_BOOLEAN_ADVERTISED' : 'ADAPTER_PROTOCOL_REQUIREMENT_CONFLICT');
    }
    boolean('authorization_response_iss_parameter_supported', true, 'RFC9207_DEFAULT_FALSE_UNVERIFIED');
    boolean('require_pushed_authorization_requests', false, 'PAR_DEFAULT_FALSE_UNVERIFIED');
    boolean('require_signed_request_object', false, 'JAR_DEFAULT_FALSE_UNVERIFIED');
    // Do not mistake a claims list, email scope, or claims_parameter_supported
    // for proof that the required email claims occur in this client's ID token.
    return report(checks);
  } catch { return report([{ id: 'input', status: 'REJECTED', code: 'PUBLIC_INPUT_REJECTED' }], true); }
}

function unchanged(a, b) {
  return ['dev', 'ino', 'mode', 'nlink', 'size', 'mtimeMs', 'ctimeMs'].every(field => a[field] === b[field]);
}

function noSymlinks(path) {
  let current = parse(path).root;
  for (const segment of path.slice(current.length).split(sep)) {
    if (!segment) continue;
    current = resolve(current, segment);
    const stat = lstatSync(current);
    if (stat.isSymbolicLink() || current !== path && !stat.isDirectory()) throw failure();
  }
  if (realpathSync(path) !== path) throw failure();
}

// JSON.parse validates grammar; this bounded second pass additionally rejects
// duplicate object member names, including names spelled with JSON escapes.
function parseUniqueJson(source) {
  const parsed = JSON.parse(source); let offset = 0; let nodes = 0;
  const skip = () => { while (/\s/u.test(source[offset] ?? '') && offset < source.length) offset++; };
  function string() {
    const start = offset++;
    while (offset < source.length) {
      const character = source[offset++];
      if (character === '\\') offset++;
      else if (character === '"') return JSON.parse(source.slice(start, offset));
    }
    throw failure();
  }
  function value(depth = 0) {
    if (++nodes > 4096 || depth > 16) throw failure();
    skip();
    if (source[offset] === '"') { string(); return; }
    if (source[offset] === '{') {
      offset++; skip(); const names = new Set();
      if (source[offset] === '}') { offset++; return; }
      while (offset < source.length) {
        skip(); const name = string();
        if (names.has(name)) throw failure(); names.add(name);
        skip(); offset++; value(depth + 1); skip();
        if (source[offset++] === '}') return;
      }
      throw failure();
    }
    if (source[offset] === '[') {
      offset++; skip();
      if (source[offset] === ']') { offset++; return; }
      while (offset < source.length) {
        value(depth + 1); skip();
        if (source[offset++] === ']') return;
      }
      throw failure();
    }
    while (offset < source.length && !/[\s,\]}]/u.test(source[offset])) offset++;
  }
  value(); skip();
  if (offset !== source.length) throw failure();
  return publicCopy(parsed);
}

/** Read exactly one small public JSON file. No output path, writes, stdin,
 * environment-selected configuration, expansion, symlinks or special files.
 */
export function readPublicJson(path) {
  let descriptor;
  try {
    if (typeof path !== 'string' || path.length > 4096 || !isAbsolute(path) || resolve(path) !== path
      || /[\u0000-\u001f\u007f]/u.test(path) || dirname(path) === path) throw failure();
    noSymlinks(path);
    const before = lstatSync(path);
    if (!before.isFile() || before.nlink !== 1 || before.size < 1 || before.size > MAX_PUBLIC_INPUT_BYTES) throw failure();
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    if (!unchanged(before, fstatSync(descriptor))) throw failure();
    const bytes = Buffer.alloc(MAX_PUBLIC_INPUT_BYTES + 1); let size = 0;
    while (size < bytes.length) {
      const count = readSync(descriptor, bytes, size, bytes.length - size, null);
      if (!count) break; size += count;
    }
    if (size !== before.size || size > MAX_PUBLIC_INPUT_BYTES || !unchanged(before, fstatSync(descriptor))) throw failure();
    noSymlinks(path);
    if (!unchanged(before, lstatSync(path))) throw failure();
    const source = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, size));
    return parseUniqueJson(source);
  } catch { throw failure(); } finally { if (descriptor !== undefined) closeSync(descriptor); }
}

export function runProviderPreflightCli(args) {
  let result;
  try {
    if (!Array.isArray(args) || args.length !== 4 || args[0] !== '--metadata' || args[2] !== '--requirements') throw failure();
    result = evaluateProviderPreflight({ metadata: readPublicJson(args[1]), requirements: readPublicJson(args[3]) });
  } catch { result = report([{ id: 'input', status: 'REJECTED', code: 'PUBLIC_INPUT_REJECTED' }], true); }
  const exitCode = { METADATA_MATCH: 0, UNVERIFIED: 2, INCOMPATIBLE: 1, INPUT_REJECTED: 64 }[result.metadataAssessment];
  return Object.freeze({ report: result, exitCode });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = runProviderPreflightCli(process.argv.slice(2));
  process.stdout.write(JSON.stringify(result.report) + '\n');
  process.exitCode = result.exitCode;
}
