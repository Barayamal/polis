import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { linkSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { evaluateProviderPreflight, MAX_PUBLIC_INPUT_BYTES, readPublicJson, runProviderPreflightCli } from './provider-preflight.mjs';

const cli = fileURLToPath(new URL('./provider-preflight.mjs', import.meta.url));
const requirements = () => ({ issuer: 'https://issuer.example.invalid/',
  authorizationEndpoint: 'https://issuer.example.invalid/authorize', tokenEndpoint: 'https://issuer.example.invalid/token',
  jwksUri: 'https://keys.example.invalid/jwks', callbackUri: 'https://participant.example.invalid/oidc/callback',
  clientId: 'public-example-client', tokenEndpointAuthMethod: 'client_secret_basic', signingAlgorithm: 'RS256' });
const metadata = () => ({ issuer: requirements().issuer, authorization_endpoint: requirements().authorizationEndpoint,
  token_endpoint: requirements().tokenEndpoint, jwks_uri: requirements().jwksUri,
  response_types_supported: ['code', 'code id_token'], response_modes_supported: ['query', 'fragment'],
  grant_types_supported: ['authorization_code'], code_challenge_methods_supported: ['S256'],
  token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
  id_token_signing_alg_values_supported: ['RS256', 'ES256'], scopes_supported: ['openid', 'email'],
  claims_supported: ['sub', 'email', 'email_verified'], authorization_response_iss_parameter_supported: true,
  require_pushed_authorization_requests: false, require_signed_request_object: false });
const evaluate = (m = metadata(), r = requirements()) => evaluateProviderPreflight({ metadata: m, requirements: r });
const check = (result, id) => result.checks.find(item => item.id === id);
const rejected = { message: 'Public provider preflight input rejected.' };
function fixture(t) {
  const directory = mkdtempSync(join(realpathSync(tmpdir()), 'fncp-public-preflight-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const m = join(directory, 'public-metadata.json'); const r = join(directory, 'public-requirements.json');
  writeFileSync(m, JSON.stringify(metadata()), { flag: 'wx' });
  writeFileSync(r, JSON.stringify(requirements()), { flag: 'wx' });
  return { directory, m, r, args: ['--metadata', m, '--requirements', r] };
}

test('explicit metadata matches public contract without granting runtime, deployment or participant authority', () => {
  const m = metadata(); const r = requirements(); const before = JSON.stringify({ m, r });
  const result = evaluate(m, r);
  assert.equal(result.metadataAssessment, 'METADATA_MATCH'); assert.equal(result.status, 'HOLD');
  assert.equal(result.providerRuntimeVerified, false); assert.equal(result.deploymentAuthorized, false);
  assert.equal(result.participantAccessGranted, false); assert.equal(result.filesWritten, 0); assert.equal(result.networkRequestsMade, 0);
  assert.equal(result.counts.MATCH, result.checks.length);
  assert.ok(result.runtimeGates.length >= 8); assert.ok(result.runtimeGates.every(item => item.status === 'UNVERIFIED'));
  assert.equal(JSON.stringify({ m, r }), before);
  assert.ok(Object.isFrozen(result) && Object.isFrozen(result.checks) && Object.isFrozen(result.checks[0]));
  assert.doesNotMatch(JSON.stringify(result), /https:|example\.invalid|public-example-client/u);
});

for (const algorithm of ['RS256', 'ES256']) for (const method of ['client_secret_basic', 'client_secret_post']) {
  test(`matches supported ${algorithm}/${method} combination`, () => {
    assert.equal(evaluate(metadata(), { ...requirements(), signingAlgorithm: algorithm,
      tokenEndpointAuthMethod: method }).metadataAssessment, 'METADATA_MATCH');
  });
}

for (const field of ['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri']) {
  test(`rejects a different explicit ${field} without displaying it`, () => {
    const m = metadata(); m[field] = 'https://wrong.example.invalid/exact';
    const result = evaluate(m);
    assert.equal(result.metadataAssessment, 'INCOMPATIBLE');
    assert.equal(check(result, field).code, 'EXACT_ENDPOINT_MISMATCH');
    assert.doesNotMatch(JSON.stringify(result), /wrong|https:/u);
  });
  test(`absent ${field} remains unverified rather than guessing discovery`, () => {
    const m = metadata(); delete m[field];
    assert.equal(check(evaluate(m), field).status, 'UNVERIFIED');
  });
}

for (const endpoint of ['http://issuer.example.invalid/', 'https://user:SECRET@issuer.example.invalid/token',
  'https://issuer.example.invalid:443/token', 'https://issuer.example.invalid/token?scope=email',
  'https://issuer.example.invalid/token#fragment', 'https://ISSUER.example.invalid/token',
  'https://issuer.example.invalid/a/../token', 'https://issuer.example.invalid']) {
  test(`adapter-restricted endpoint case ${['http:', '?', '#'].find(part => endpoint.includes(part)) ?? endpoint.length} is not normalized into acceptance`, () => {
    assert.equal(evaluate({ ...metadata(), token_endpoint: endpoint }).metadataAssessment, 'INCOMPATIBLE');
    assert.equal(evaluate(metadata(), { ...requirements(), tokenEndpoint: endpoint }).metadataAssessment, 'INPUT_REJECTED');
  });
}

for (const [field, values] of [
  ['response_types_supported', ['code id_token']], ['response_modes_supported', ['form_post', 'query.jwt']],
  ['grant_types_supported', ['implicit']], ['code_challenge_methods_supported', ['plain']],
  ['token_endpoint_auth_methods_supported', ['none', 'private_key_jwt']], ['id_token_signing_alg_values_supported', ['HS256']],
]) test(`explicit ${field} incompatibility is rejected`, () => {
  const result = evaluate({ ...metadata(), [field]: values });
  assert.equal(result.metadataAssessment, 'INCOMPATIBLE'); assert.equal(check(result, field).status, 'INCOMPATIBLE');
});

for (const field of ['response_types_supported', 'response_modes_supported', 'grant_types_supported',
  'code_challenge_methods_supported', 'token_endpoint_auth_methods_supported', 'id_token_signing_alg_values_supported',
  'authorization_response_iss_parameter_supported', 'require_pushed_authorization_requests', 'require_signed_request_object']) {
  test(`missing ${field} never becomes an explicit capability match through a default`, () => {
    const m = metadata(); delete m[field];
    const result = evaluate(m);
    assert.equal(result.metadataAssessment, 'UNVERIFIED'); assert.equal(check(result, field).status, 'UNVERIFIED');
  });
}

test('basic default does not establish post and cannot resolve missing client registration', () => {
  const m = metadata(); delete m.token_endpoint_auth_methods_supported;
  const result = evaluate(m, { ...requirements(), tokenEndpointAuthMethod: 'client_secret_post' });
  assert.equal(check(result, 'token_endpoint_auth_methods_supported').code, 'BASIC_DEFAULT_DOES_NOT_ESTABLISH_POST');
  assert.equal(result.metadataAssessment, 'UNVERIFIED');
});

for (const [field, conflicting] of [['authorization_response_iss_parameter_supported', false],
  ['require_pushed_authorization_requests', true], ['require_signed_request_object', true]]) {
  test(`explicit ${field} conflict is unsupported by the actual adapter`, () => {
    assert.equal(evaluate({ ...metadata(), [field]: conflicting }).metadataAssessment, 'INCOMPATIBLE');
  });
  test(`string booleans cannot claim ${field} compatibility`, () => {
    assert.equal(evaluate({ ...metadata(), [field]: 'false' }).metadataAssessment, 'INPUT_REJECTED');
  });
}

for (const field of ['claims_supported', 'scopes_supported']) {
  test(`missing or non-exhaustive ${field} is not a definitive provider failure`, () => {
    const m = metadata(); delete m[field];
    assert.equal(evaluate(m).metadataAssessment, 'UNVERIFIED');
    assert.equal(evaluate({ ...metadata(), [field]: ['profile'] }).metadataAssessment, 'UNVERIFIED');
  });
}

test('email scope, advertised claims and claims-parameter support do not prove ID-token placement or true verification', () => {
  const result = evaluate({ ...metadata(), claims_parameter_supported: true });
  assert.equal(result.metadataAssessment, 'METADATA_MATCH');
  assert.equal(result.runtimeGates.find(item => item.code === 'ID_TOKEN_EMAIL_AND_TRUE_EMAIL_VERIFIED').status, 'UNVERIFIED');
});

for (const bad of [null, 'code', [], ['code', 'code'], [1], [''], ['code', null], Array(257).fill('code')]) {
  test(`invalid capability list ${JSON.stringify(bad).slice(0, 32)} fails generically`, () => {
    assert.equal(evaluate({ ...metadata(), response_types_supported: bad }).metadataAssessment, 'INPUT_REJECTED');
  });
}

for (const mutation of [{ clientSecret: 'DO_NOT_DISPLAY' }, { clientSecretFile: '/private/never/read' },
  { identityKey: 'DO_NOT_DISPLAY' }, { tokenEndpointAuthMethod: 'none' }, { signingAlgorithm: 'HS256' },
  { callbackUri: requirements().tokenEndpoint }, { clientId: '' }, { clientId: 'x'.repeat(257) }]) {
  test(`rejects invalid or private requirements field ${Object.keys(mutation)[0]}`, () => {
    const result = evaluate(metadata(), { ...requirements(), ...mutation });
    assert.equal(result.metadataAssessment, 'INPUT_REJECTED'); assert.doesNotMatch(JSON.stringify(result), /DO_NOT_DISPLAY|private\/never/u);
  });
}

test('rejects nested credential keys and executable objects without executing accessors', () => {
  for (const value of [{ extension: { client_secret: 'PRIVATE' } }, { access_token: 'PRIVATE' },
    { nested: { identityKeyFile: '/private/never/read' } }, { extension: () => 'PRIVATE' }]) {
    assert.equal(evaluate({ ...metadata(), ...value }).metadataAssessment, 'INPUT_REJECTED');
  }
  let called = 0; const getter = { ...metadata() };
  Object.defineProperty(getter, 'issuer', { get() { called++; throw new Error('PRIVATE'); } });
  assert.equal(evaluate(getter).metadataAssessment, 'INPUT_REJECTED');
  const wrapper = { requirements: requirements() };
  Object.defineProperty(wrapper, 'metadata', { get() { called++; return metadata(); } });
  assert.equal(evaluateProviderPreflight(wrapper).metadataAssessment, 'INPUT_REJECTED'); assert.equal(called, 0);
});

test('rejects cycles, sparse arrays, symbol fields, custom prototypes and excessive depth/size', () => {
  const cycle = metadata(); cycle.self = cycle;
  const sparse = metadata(); sparse.scopes_supported = Array(2); sparse.scopes_supported[1] = 'email';
  const symbol = metadata(); symbol[Symbol('PRIVATE')] = true;
  const custom = Object.assign(Object.create({ inherited: true }), metadata());
  let deep = {}; for (let index = 0; index < 18; index++) deep = { child: deep };
  for (const m of [cycle, sparse, symbol, custom, { ...metadata(), deep }, { ...metadata(), enormous: 'x'.repeat(MAX_PUBLIC_INPUT_BYTES) }]) {
    assert.equal(evaluate(m).metadataAssessment, 'INPUT_REJECTED');
  }
});

test('ordinary public extension metadata is ignored, never copied to the report', () => {
  const result = evaluate({ ...metadata(), service_documentation: 'https://docs.example.invalid/',
    vendor_extension: { public_version: 3, flags: ['one', 'two'] } });
  assert.equal(result.metadataAssessment, 'METADATA_MATCH'); assert.doesNotMatch(JSON.stringify(result), /vendor_extension|docs.example/u);
});

test('repeated read-only CLI prints aggregate codes, changes neither input and creates no files', t => {
  const f = fixture(t); const before = [readFileSync(f.m), readFileSync(f.r)];
  const response = spawnSync(process.execPath, [cli, ...f.args], { encoding: 'utf8', timeout: 5000 });
  assert.equal(response.status, 0); assert.equal(response.stderr, '');
  const result = JSON.parse(response.stdout); assert.equal(result.metadataAssessment, 'METADATA_MATCH');
  assert.doesNotMatch(response.stdout, /example\.invalid|public-example-client|fncp-public-preflight-/u);
  const again = spawnSync(process.execPath, [cli, ...f.args], { encoding: 'utf8', timeout: 5000 });
  assert.equal(again.status, 0); assert.equal(again.stderr, ''); assert.equal(again.stdout, response.stdout);
  assert.deepEqual([readFileSync(f.m), readFileSync(f.r)], before);
  assert.deepEqual(readdirSync(f.directory).sort(), ['public-metadata.json', 'public-requirements.json']);
  assert.equal(result.status, 'HOLD'); assert.equal(result.filesWritten, 0);
});

test('CLI exit 2 distinguishes insufficient metadata; exit 1 distinguishes explicit incompatibility', t => {
  const f = fixture(t); const m = metadata(); delete m.response_modes_supported;
  writeFileSync(f.m, JSON.stringify(m)); assert.equal(runProviderPreflightCli(f.args).exitCode, 2);
  writeFileSync(f.m, JSON.stringify({ ...metadata(), authorization_response_iss_parameter_supported: false }));
  assert.equal(runProviderPreflightCli(f.args).exitCode, 1);
});

test('no output flag, extra argument, duplicate option, stdin or URL input is accepted', t => {
  const f = fixture(t);
  for (const args of [[], [...f.args, '--output', f.m], ['--metadata', f.m, '--metadata', f.m],
    ['--metadata', '-', '--requirements', f.r], ['--metadata', 'https://issuer.example.invalid/', '--requirements', f.r],
    ['--requirements', f.r, '--metadata', f.m]]) {
    const result = runProviderPreflightCli(args);
    assert.equal(result.exitCode, 64); assert.equal(result.report.metadataAssessment, 'INPUT_REJECTED');
  }
});

test('symlink files, symlink ancestors, relative paths, hard links and directories are rejected', t => {
  const f = fixture(t); const symbolic = join(f.directory, 'symbolic.json'); symlinkSync(f.m, symbolic);
  const folder = join(f.directory, 'real'); mkdirSync(folder);
  const nested = join(folder, 'nested.json'); writeFileSync(nested, '{}');
  const alias = join(f.directory, 'alias'); symlinkSync(folder, alias);
  const hard = join(f.directory, 'hard.json'); linkSync(nested, hard);
  for (const path of [symbolic, join(alias, 'nested.json'), hard, folder, '.', join(f.directory, 'missing.json')]) {
    assert.throws(() => readPublicJson(path), rejected);
  }
});

test('special FIFO is rejected before opening, without blocking', t => {
  const f = fixture(t); const fifo = join(f.directory, 'fifo');
  execFileSync('mkfifo', [fifo]);
  const result = spawnSync(process.execPath, [cli, '--metadata', fifo, '--requirements', f.r], { encoding: 'utf8', timeout: 2000 });
  assert.equal(result.status, 64); assert.equal(result.error, undefined);
});

test('oversized, empty, malformed UTF-8 and ambiguous duplicate-key JSON are rejected', t => {
  const f = fixture(t);
  for (const bytes of [Buffer.alloc(MAX_PUBLIC_INPUT_BYTES + 1, 32), Buffer.alloc(0), Buffer.from([0xff, 0xfe]),
    Buffer.from('{"issuer":"a","issuer":"b"}'), Buffer.from('{"issuer":"a","\\u0069ssuer":"b"}'),
    Buffer.from('{"extension":{"same":1,"same":2}}'), Buffer.from('{"__proto__":{"yes":true}}'), Buffer.from('{')]) {
    writeFileSync(f.m, bytes); assert.throws(() => readPublicJson(f.m), rejected);
  }
});

test('valid escaped JSON strings, braces inside strings, arrays and null extensions remain parseable', t => {
  const f = fixture(t); const m = { ...metadata(), extensions: [{ string: 'quoted "value" {}[] \\ tail', nil: null }] };
  writeFileSync(f.m, JSON.stringify(m));
  assert.equal(evaluate(readPublicJson(f.m)).metadataAssessment, 'METADATA_MATCH');
});

test('CLI failure reports no filename, filesystem error, raw endpoint, data or stack', t => {
  const f = fixture(t); const missing = join(f.directory, 'PRIVATE_FILENAME.json');
  const result = spawnSync(process.execPath, [cli, '--metadata', missing, '--requirements', f.r], { encoding: 'utf8', timeout: 5000 });
  assert.equal(result.status, 64); assert.equal(result.stderr, '');
  assert.doesNotMatch(result.stdout, /PRIVATE_FILENAME|ENOENT|\/private\/|Error:|stack|example\.invalid/u);
});

test('preflight has no provider, credential, store, fetch or network module dependency', () => {
  const source = readFileSync(cli, 'utf8');
  assert.doesNotMatch(source, /from ['"](?:node:(?:https?|net|tls)|openid-client|\.\/identity\.mjs|.*store.*)['"]|\bfetch\s*\(/u);
  assert.doesNotMatch(source, /\b(?:writeFile|appendFile|mkdir|createProductionIdentity|createProductionService)\s*\(/u);
});
