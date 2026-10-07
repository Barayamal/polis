import test from 'node:test';
import assert from 'node:assert/strict';
import { Agent, request } from 'node:https';
import { connect } from 'node:net';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { createBootstrapIssuer, claimBootstrapIssuerForTransport } from './bootstrap-issuer.mjs';

// Existing checked workspace dependencies only; no install or source acquisition.
const identityRequire = createRequire(new URL('../identity-foundation/package.json', import.meta.url));
const { createLocalJWKSet, decodeJwt, decodeProtectedHeader, jwtVerify } = await import(pathToFileURL(identityRequire.resolve('jose')).href);
const serverRequire = createRequire(new URL('../../../server/package.json', import.meta.url));
const { expressjwt } = serverRequire('express-jwt');
const { expressJwtSecret } = serverRequire('jwks-rsa');

const MESSAGE = 'Local synthetic bootstrap issuer rejected; private details withheld.';
async function fixture(t) {
  const issuer = await createBootstrapIssuer(); t.after(() => issuer.close()); return issuer;
}
const rejected = promise => assert.rejects(promise, error => error.message === MESSAGE && error.cause === undefined);
const throws = fn => assert.throws(fn, { message: MESSAGE });

// This deliberately narrow test client can contact only a factory-owned literal
// loopback port. It never follows a Location header or accepts an external URL.
function localRequest(config, options = {}) {
  const url = new URL(config.jwksUri);
  assert.equal(url.hostname, '127.0.0.1'); assert.equal(url.protocol, 'https:');
  return new Promise((resolve, reject) => {
    let req; let response; let finished = false;
    const finish = (error, result) => {
      if (finished) return; finished = true; clearTimeout(timer);
      if (error) { response?.destroy(); req?.destroy(); reject(error); } else resolve(result);
    };
    const timer = setTimeout(() => finish(new Error('Bounded test request timed out.')), 1500);
    req = request({ hostname: '127.0.0.1', port: Number(url.port), path: options.path ?? url.pathname,
      method: options.method ?? 'GET', ca: Object.hasOwn(options, 'ca') ? options.ca : config.certificatePem,
      rejectUnauthorized: true, minVersion: 'TLSv1.2', agent: false,
      // Verify literal-IP SAN even when testing a different HTTP Host header;
      // never disable certificate validation or redirect to that header value.
      servername: options.servername ?? '',
      headers: { host: url.host, connection: 'close', ...options.headers },
    }, res => {
      response = res; const chunks = []; let size = 0;
      res.on('data', chunk => { size += chunk.length; if (size > 8192) finish(new Error('Bounded test response too large.')); else chunks.push(chunk); });
      res.on('error', error => finish(error)); res.on('aborted', () => finish(new Error('Test response aborted.')));
      res.on('end', () => finish(null, { status: res.statusCode, headers: res.headers,
        body: Buffer.concat(chunks).toString('utf8'), authorized: req.socket.authorized, protocol: req.socket.getProtocol() }));
    });
    req.on('error', error => finish(error)); req.end(options.body);
  });
}
async function closedPort(port) {
  await new Promise((resolve, reject) => {
    const socket = connect({ host: '127.0.0.1', port }); socket.setTimeout(500);
    socket.once('connect', () => { socket.destroy(); reject(new Error('Owned test listener remained open.')); });
    socket.once('timeout', () => { socket.destroy(); reject(new Error('Owned test closure check timed out.')); });
    socket.once('error', error => { socket.destroy(); error.code === 'ECONNREFUSED' ? resolve() : reject(error); });
  });
}

test('factory has no configuration, claim, host, key, path, clock or transport override', async () => {
  let reads = 0;
  const getter = { get issuer() { reads++; throw new Error('private'); } };
  const proxy = new Proxy({}, { get() { reads++; throw new Error('private'); } });
  for (const input of [undefined, null, {}, getter, proxy, { port: 1234 }, { privateKey: 'private' },
    { now: () => 0 }, { issuer: 'https://external.example/' }, '/private/retained']) await rejected(createBootstrapIssuer(input));
  assert.equal(reads, 0);
});

test('actual verified loopback HTTPS serves one public RSA JWKS and the fixed short-lived claims validate', async t => {
  const issuer = await fixture(t); const config = issuer.configuration(); const token = issuer.issueToken();
  const jwks = await issuer.fetchJwks();
  const verified = await jwtVerify(token, createLocalJWKSet(jwks), { issuer: config.issuer, audience: config.audience, algorithms: ['RS256'] });
  const { payload, protectedHeader } = verified;
  assert.deepEqual(Object.keys(config), ['issuer', 'audience', 'jwksUri', 'certificatePem']);
  assert.match(config.issuer, /^https:\/\/127\.0\.0\.1:[1-9][0-9]*\/$/u);
  assert.equal(config.jwksUri, config.issuer + '.well-known/jwks.json');
  assert.equal(config.audience, 'fncp-fresh-synthetic-bootstrap');
  assert.deepEqual(Object.keys(jwks), ['keys']); assert.equal(jwks.keys.length, 1);
  assert.deepEqual(Object.keys(jwks.keys[0]), ['kty', 'n', 'e', 'kid', 'use', 'alg']);
  assert.equal(jwks.keys[0].kty, 'RSA'); assert.equal(jwks.keys[0].alg, 'RS256'); assert.equal(jwks.keys[0].use, 'sig');
  assert.equal(Buffer.from(jwks.keys[0].n, 'base64url').length, 256); assert.equal(jwks.keys[0].e, 'AQAB');
  assert.deepEqual(protectedHeader, { alg: 'RS256', typ: 'JWT', kid: jwks.keys[0].kid });
  assert.match(payload.sub, /^fncp-invented-bootstrap-admin-[a-f0-9]{48}$/u);
  assert.equal(payload.email, 'bootstrap-admin@bootstrap.example.invalid'); assert.equal(payload.email_verified, false);
  assert.equal(payload.name, 'Invented local bootstrap administrator');
  assert.equal(payload.nbf, payload.iat); assert.ok(payload.exp > payload.iat && payload.exp - payload.iat <= 120);
  assert.match(payload.jti, /^[a-f0-9]{48}$/u); assert.ok(Buffer.byteLength(token) <= 4096);
  assert.deepEqual(Object.keys(payload).sort(), ['aud', 'email', 'email_verified', 'exp', 'iat', 'iss', 'jti', 'name', 'nbf', 'sub']);
  const summary = issuer.summary(); assert.equal(summary.verifiedTlsFetches, 1); assert.equal(summary.jwksRequests, 1);
  assert.equal(summary.tokensIssued, 1); assert.equal(summary.temporaryCertificateFilesRemoved, true);
});

test('each fresh issuer independently generates its subject, signing key and TLS certificate', async t => {
  const a = await fixture(t); const b = await fixture(t);
  const ca = a.configuration(); const cb = b.configuration(); const ta = a.issueToken(); const tb = b.issueToken();
  const ja = await a.fetchJwks(); const jb = await b.fetchJwks();
  assert.notEqual(ca.issuer, cb.issuer); assert.notEqual(ca.certificatePem, cb.certificatePem);
  assert.notEqual(decodeJwt(ta).sub, decodeJwt(tb).sub); assert.notEqual(ja.keys[0].n, jb.keys[0].n);
  assert.notEqual(ja.keys[0].kid, jb.keys[0].kid);
  await assert.rejects(jwtVerify(ta, createLocalJWKSet(jb), { issuer: ca.issuer, audience: ca.audience, algorithms: ['RS256'] }));
});

test('installed express-jwt and jwks-rsa interoperate over actual trusted HTTPS using the reviewed Pol.is validation options', async t => {
  const issuer = await fixture(t); const config = issuer.configuration(); const token = issuer.issueToken();
  const agent = new Agent({ ca: config.certificatePem, rejectUnauthorized: true, minVersion: 'TLSv1.2', keepAlive: false, maxSockets: 1 });
  t.after(() => agent.destroy());
  const middleware = overrides => expressjwt({
    secret: expressJwtSecret({ cache: true, rateLimit: true, jwksRequestsPerMinute: 5,
      jwksUri: config.jwksUri, requestAgent: agent, timeout: 1000,
      handleSigningKeyError: (error, callback) => callback(error) }),
    audience: config.audience, issuer: config.issuer, algorithms: ['RS256'], requestProperty: 'jwtPayload', ...overrides,
  });
  const validate = (handler, suppliedToken) => new Promise((resolve, reject) => {
    const req = { method: 'GET', headers: { authorization: 'Bearer ' + suppliedToken } };
    const timer = setTimeout(() => reject(new Error('Bounded installed JWT-library check timed out.')), 2000);
    handler(req, {}, error => { clearTimeout(timer); error ? reject(error) : resolve(req); });
  });
  const correct = middleware({}); const validated = await validate(correct, token);
  assert.equal(validated.jwtPayload.sub, decodeJwt(token).sub); assert.equal(validated.auth, undefined);
  assert.equal(validated.jwtPayload.email, 'bootstrap-admin@bootstrap.example.invalid');
  assert.equal(validated.jwtPayload.email_verified, false); assert.equal(issuer.summary().jwksRequests, 1);
  const parts = token.split('.'); parts[2] = (parts[2][0] === 'A' ? 'B' : 'A') + parts[2].slice(1);
  await assert.rejects(validate(correct, parts.join('.')), error => error.code === 'invalid_token');
  await assert.rejects(validate(middleware({ audience: 'wrong-audience' }), token), error => error.code === 'invalid_token');
  await assert.rejects(validate(middleware({ issuer: 'https://other.example.invalid/' }), token), error => error.code === 'invalid_token');
  await assert.rejects(validate(middleware({ clockTimestamp: decodeJwt(token).exp }), token), error => error.inner?.name === 'TokenExpiredError');
  await assert.rejects(validate(middleware({ algorithms: ['HS256'] }), token), error => error.code === 'invalid_token');
  // Only isolated JWT libraries ran. No Pol.is app/config/middleware module, DB,
  // user-creation handler, Docker route or real identity is imported/executed.
  assert.equal(issuer.summary().polisMiddlewareExecuted, false); assert.equal(issuer.summary().bootstrapExecuted, false);
});

test('one-time issuance cannot be refreshed or supplied with different caller claims', async t => {
  const issuer = await fixture(t); let reads = 0;
  const claims = { get sub() { reads++; return 'real-user'; } };
  throws(() => issuer.issueToken(claims)); assert.equal(issuer.summary().tokensIssued, 0);
  const token = issuer.issueToken(); assert.equal(typeof token, 'string');
  throws(() => issuer.issueToken()); throws(() => issuer.issueToken(undefined));
  assert.equal(reads, 0); assert.equal(issuer.summary().tokensIssued, 1);
});

test('all capability methods reject any extra argument without reading it or adopting paths/URLs', async t => {
  const issuer = await fixture(t); let reads = 0;
  const proxy = new Proxy({}, { get() { reads++; throw new Error('private'); } });
  for (const value of [undefined, null, {}, proxy, 'https://external.example/', '/private/retained']) {
    throws(() => issuer.configuration(value)); throws(() => issuer.summary(value));
    await rejected(issuer.fetchJwks(value)); await rejected(issuer.close(value));
  }
  assert.equal(issuer.summary().closed, false); assert.equal(issuer.summary().clientFetches, 0); assert.equal(reads, 0);
});

test('default trust and an unrelated fresh certificate cannot authorize the local HTTPS endpoint', async t => {
  const a = await fixture(t); const b = await fixture(t); const config = a.configuration();
  await assert.rejects(localRequest(config, { ca: undefined }));
  await assert.rejects(localRequest(config, { ca: b.configuration().certificatePem }));
  assert.equal(a.summary().jwksRequests, 0);
});

test('explicit CA trust still requires the exact IP SAN instead of bypassing hostname checks', async t => {
  const issuer = await fixture(t); const config = issuer.configuration();
  await assert.rejects(localRequest(config, { servername: 'wrong-san.example.invalid' }), error => error.code === 'ERR_TLS_CERT_ALTNAME_INVALID');
  assert.equal(issuer.summary().jwksRequests, 0);
});

test('raw JWKS route returns only public JSON over TLS and sets no-store/no-redirect/no-CORS headers', async t => {
  const issuer = await fixture(t); const result = await localRequest(issuer.configuration());
  assert.equal(result.status, 200); assert.equal(result.authorized, true);
  assert.ok(['TLSv1.2', 'TLSv1.3'].includes(result.protocol));
  assert.equal(result.headers['content-type'], 'application/json'); assert.equal(result.headers['cache-control'], 'no-store');
  assert.equal(result.headers.location, undefined); assert.equal(result.headers['access-control-allow-origin'], undefined);
  assert.equal(result.headers['set-cookie'], undefined); assert.equal(result.headers['x-content-type-options'], 'nosniff');
  assert.ok(Buffer.byteLength(result.body) <= 4096);
  assert.deepEqual(JSON.parse(result.body), await issuer.fetchJwks());
  assert.doesNotMatch(result.body, /PRIVATE KEY|"d"\s*:|"p"\s*:|"q"\s*:|access_token|refresh_token/u);
});

test('no authorize, token, login, discovery, redirect, query or arbitrary method route exists', async t => {
  const issuer = await fixture(t); const config = issuer.configuration();
  for (const path of ['/', '/authorize', '/token', '/login', '/.well-known/openid-configuration',
    '/.well-known/jwks.json?next=https://external.example/', '/.well-known/JWKS.json', '/.well-known/%6awks.json']) {
    const result = await localRequest(config, { path }); assert.equal(result.status, 403); assert.equal(result.body, '{}');
    assert.equal(result.headers.location, undefined);
  }
  for (const method of ['POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']) {
    const result = await localRequest(config, { method }); assert.equal(result.status, 403);
    assert.equal(result.body, method === 'HEAD' ? '' : '{}');
  }
  assert.equal(issuer.summary().tokensIssued, 0); assert.equal(issuer.summary().jwksRequests, 0);
});

test('foreign Host, browser Origin, credentials, cookies and GET request bodies are denied', async t => {
  const issuer = await fixture(t); const config = issuer.configuration();
  for (const options of [{ headers: { host: 'external.example' } }, { headers: { origin: 'https://external.example' } },
    { headers: { authorization: 'Bearer invented-not-authority' } }, { headers: { cookie: 'synthetic=only' } },
    { headers: { 'content-length': '1' }, body: 'x' }, { headers: { 'transfer-encoding': 'chunked' }, body: 'x' }]) {
    const result = await localRequest(config, options); assert.equal(result.status, 403); assert.equal(result.body, '{}');
  }
  assert.equal(issuer.summary().jwksRequests, 0); assert.equal(issuer.summary().rejectedRequests, 6);
});

test('internal verified JWKS fetches have a fixed lifetime budget and no transport selector', async t => {
  const issuer = await fixture(t);
  for (let i = 0; i < 8; i++) await issuer.fetchJwks();
  await rejected(issuer.fetchJwks());
  assert.equal(issuer.summary().clientFetches, 8); assert.equal(issuer.summary().verifiedTlsFetches, 8);
});

test('HTTP JWKS service has a fixed request budget independent of the private fetch helper', async t => {
  const issuer = await fixture(t); const config = issuer.configuration();
  for (let i = 0; i < 32; i++) assert.equal((await localRequest(config)).status, 200);
  assert.equal((await localRequest(config)).status, 403);
  assert.equal(issuer.summary().jwksRequests, 32); assert.equal(issuer.summary().rejectedRequests, 1);
});

test('aggregate summary never contains private endpoint/token/subject or key material and states unproved scope', async t => {
  const issuer = await fixture(t); const config = issuer.configuration(); const token = issuer.issueToken();
  const jwks = await issuer.fetchJwks(); const summary = issuer.summary(); const text = JSON.stringify(summary);
  for (const secret of [config.issuer, config.certificatePem, token, decodeJwt(token).sub, jwks.keys[0].n, jwks.keys[0].kid]) assert.equal(text.includes(secret), false);
  assert.equal(summary.realIdentityProvider, false); assert.equal(summary.oidcLoginImplemented, false);
  assert.equal(summary.containerReachabilityVerified, false); assert.equal(summary.polisMiddlewareExecuted, false);
  assert.equal(summary.bootstrapExecuted, false); assert.equal(summary.globalTrustChanged, false); assert.equal(summary.productionReady, false);
  assert.equal(Object.isFrozen(summary), true); assert.equal(Object.isFrozen(issuer), true); assert.equal(Object.isFrozen(config), true);
  assert.equal(Object.isFrozen(jwks), true); assert.equal(Object.isFrozen(jwks.keys), true); assert.equal(Object.isFrozen(jwks.keys[0]), true);
});

test('close synchronously latches new issuance/JWKS serving, is idempotent and independently leaves its port refused', async t => {
  const issuer = await fixture(t); const config = issuer.configuration();
  const closing = issuer.close(); assert.equal(issuer.close(), closing);
  throws(() => issuer.configuration()); throws(() => issuer.issueToken()); await rejected(issuer.fetchJwks());
  await closing; assert.equal(issuer.summary().closed, true); assert.equal(issuer.summary().listenersClosed, true);
  await closedPort(Number(new URL(config.issuer).port)); await issuer.close();
});

test('closing this issuer does not falsely claim revocation of an already-issued token verified with cached JWKS', async t => {
  const issuer = await fixture(t); const config = issuer.configuration(); const token = issuer.issueToken();
  const jwks = await issuer.fetchJwks(); await issuer.close();
  const verified = await jwtVerify(token, createLocalJWKSet(jwks), { issuer: config.issuer,
    audience: config.audience, algorithms: ['RS256'] });
  assert.equal(verified.payload.sub, decodeJwt(token).sub);
  assert.equal(issuer.summary().closed, true); assert.equal(issuer.summary().cachedTokenRevocationImplemented, false);
  assert.ok(verified.payload.exp - verified.payload.iat <= 120);
});

test('close cancels its in-flight verified request rather than allowing a late successful response', async t => {
  const issuer = await fixture(t); const pending = rejected(issuer.fetchJwks());
  await issuer.close(); await pending; assert.equal(issuer.summary().listenersClosed, true);
});

test('close destroys an owned incomplete TLS connection and does not wait for a handshake', async t => {
  const issuer = await fixture(t); const port = Number(new URL(issuer.configuration().issuer).port);
  const socket = connect({ host: '127.0.0.1', port }); socket.on('error', () => {});
  await new Promise(resolve => socket.once('connect', resolve));
  const ended = new Promise(resolve => socket.once('close', resolve));
  await issuer.close(); await ended; assert.equal(issuer.summary().listenersClosed, true);
});

test('JWT expiry and issuer lifetime deny further use without a caller-controlled clock or refresh', async t => {
  const issuer = await fixture(t); const config = issuer.configuration(); const token = issuer.issueToken();
  const jwks = await issuer.fetchJwks(); const payload = decodeJwt(token);
  await assert.rejects(jwtVerify(token, createLocalJWKSet(jwks), { issuer: config.issuer, audience: config.audience,
    algorithms: ['RS256'], currentDate: new Date(payload.exp * 1000) }), error => error.code === 'ERR_JWT_EXPIRED');
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() }); t.mock.timers.tick(120_000);
  throws(() => issuer.configuration()); await rejected(issuer.fetchJwks()); throws(() => issuer.issueToken());
  await issuer.close(); assert.equal(issuer.summary().expired, true); assert.equal(issuer.summary().listenersClosed, true);
});

test('a backwards or invalid wall clock fails closed instead of extending token-issuing authority', async t => {
  const issuer = await fixture(t);
  t.mock.method(Date, 'now', () => 0); throws(() => issuer.issueToken()); await issuer.close();
  assert.equal(issuer.summary().tokensIssued, 0); assert.equal(issuer.summary().expired, true);
});

test('the token cannot validate under a different audience, issuer or algorithm', async t => {
  const issuer = await fixture(t); const config = issuer.configuration(); const token = issuer.issueToken(); const jwks = await issuer.fetchJwks();
  const key = createLocalJWKSet(jwks);
  await assert.rejects(jwtVerify(token, key, { issuer: config.issuer, audience: 'other-audience', algorithms: ['RS256'] }));
  await assert.rejects(jwtVerify(token, key, { issuer: 'https://other.example.invalid/', audience: config.audience, algorithms: ['RS256'] }));
  await assert.rejects(jwtVerify(token, key, { issuer: config.issuer, audience: config.audience, algorithms: ['HS256'] }));
  assert.equal(decodeProtectedHeader(token).alg, 'RS256');
});

test('source contract matches Pol.is RS256/issuer/audience/JWKS and required email mapping, without executing middleware', async () => {
  const middleware = await readFile(new URL('../../../server/src/auth/jwt-middleware.ts', import.meta.url), 'utf8');
  const users = await readFile(new URL('../../../server/src/auth/create-user.ts', import.meta.url), 'utf8');
  const transactions = await readFile(new URL('../../../server/src/db/pg-query.ts', import.meta.url), 'utf8');
  const config = await readFile(new URL('../../../server/src/config.ts', import.meta.url), 'utf8');
  assert.match(middleware, /jwksUri: Config\.jwksUri/u); assert.match(middleware, /audience: Config\.authAudience/u);
  assert.match(middleware, /issuer: Config\.authIssuer/u); assert.match(middleware, /algorithms: \["RS256"\]/u);
  assert.match(middleware, /const oidcSub = req\.jwtPayload\.sub/u);
  assert.match(users, /^\s+email = oidcUser\.email \|\| oidcUser\[`\$\{namespace\}email`\];$/mu);
  assert.match(users, /return await pg\.withTransaction\(async \(query\) => \{/u);
  assert.match(users, /if \(!pg\.transactionRolledBack\(error\) \|\| error\.code !== "23505"\) throw error;/u);
  assert.match(transactions, /client = await readWritePool\.connect\(\);/u);
  assert.match(transactions, /commitAttempted = true;\s+const commitResult = await client\.query\("COMMIT"\);/u);
  assert.match(transactions, /if \(commitResult\.command !== "COMMIT"\) throw new Error/u);
  assert.match(transactions, /if \(client && begun && !commitAttempted && !connectionFailed\)/u);
  for (const [name, environment] of [['authIssuer', 'AUTH_ISSUER'], ['authAudience', 'AUTH_AUDIENCE'], ['jwksUri', 'JWKS_URI']]) {
    assert.match(config, new RegExp(`${name}: process\\.env\\.${environment} \\|\\| null`, 'u'));
  }
});

test('source has no Docker/global trust/external transport or private-key export and scopes exact TLS cleanup', async () => {
  const source = await readFile(new URL('./bootstrap-issuer.mjs', import.meta.url), 'utf8');
  assert.match(source, /const executable = process\.platform === 'darwin' \? '\/opt\/homebrew\/bin\/openssl' :\s+process\.platform === 'linux' \? '\/usr\/bin\/openssl' : undefined;/u);
  assert.match(source, /if \(!executable\) throw failure\(\);\s+const directory = mkdtempSync/u);
  assert.match(source, /const result = spawnSync\(executable, \['req', '-x509'/u);
  assert.match(source, /subjectAltName=IP:127\.0\.0\.1/u); assert.match(source, /rejectUnauthorized: true/u);
  assert.match(source, /for \(const path of \[keyPath, certPath\]\)/u); assert.match(source, /rmdirSync\(directory\)/u);
  assert.doesNotMatch(source, /process\.env|checkServerIdentity\s*:|rejectUnauthorized:\s*false|privateKey\.export|console\.|fetch\(|runDocker\(/u);
  assert.equal((source.match(/^export /gmu) ?? []).length, 4);
});

test('private HTTP handoff rejects fabricated, copied or proxy issuers without getters or network', async t => {
  const issuer = await fixture(t); let touched = 0;
  for (const value of [undefined, null, {}, { ...issuer }, new Proxy(issuer, { get() { touched++; } })]) {
    throws(() => claimBootstrapIssuerForTransport(value));
  }
  throws(() => claimBootstrapIssuerForTransport(issuer, undefined));
  assert.equal(touched, 0); assert.equal(issuer.summary().tokensIssued, 0);
  assert.equal(issuer.summary().jwksRequests, 0);
});

test('branded HTTP handoff consumes the sole invented token and its active check follows issuer closure', async t => {
  const issuer = await fixture(t); const credential = claimBootstrapIssuerForTransport(issuer);
  assert.deepEqual(Object.keys(credential), ['token', 'assertActive']);
  assert.equal(typeof credential.token, 'string'); assert.equal(credential.assertActive(), undefined);
  throws(() => claimBootstrapIssuerForTransport(issuer)); throws(() => issuer.issueToken());
  throws(() => credential.assertActive(undefined));
  await issuer.close(); throws(() => credential.assertActive());
  assert.equal(issuer.summary().tokensIssued, 1);
});

test('closed issuer cannot mint a private transport credential', async t => {
  const issuer = await fixture(t); await issuer.close();
  throws(() => claimBootstrapIssuerForTransport(issuer)); assert.equal(issuer.summary().tokensIssued, 0);
});
