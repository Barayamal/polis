// TEST SUPPORT ONLY: fresh loopback HTTPS, invented accounts and ephemeral keys.
// This file is never imported by the production adapter.
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { chmodSync, mkdtempSync, readFileSync, rmdirSync, unlinkSync } from 'node:fs';
import { createServer } from 'node:https';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { createProductionIdentity } from '../identity.mjs';

const failure = () => new Error('Test issuer operation failed.');
export const browserBinding = () => randomBytes(32).toString('base64url');

export function freshCertificate(wrongHost = false, host = '127.0.0.1') {
  const directory = mkdtempSync(join(tmpdir(), 'fncp-oidc-adapter-test-'));
  const keyPath = join(directory, 'key.pem'); const certPath = join(directory, 'certificate.pem');
  try {
    chmodSync(directory, 0o700);
    const run = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt',
      'ec_paramgen_curve:prime256v1', '-noenc', '-days', '1', '-subj', '/CN=FNCP adapter test',
      '-addext', wrongHost ? 'subjectAltName=DNS:wrong.example.invalid' : host === 'localhost' ? 'subjectAltName=DNS:localhost' : 'subjectAltName=IP:127.0.0.1',
      '-keyout', keyPath, '-out', certPath], { stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 10_000, maxBuffer: 8192 });
    if (run.error || run.status !== 0) throw failure();
    chmodSync(keyPath, 0o600); chmodSync(certPath, 0o600);
    return { key: readFileSync(keyPath), cert: readFileSync(certPath) };
  } finally {
    for (const path of [keyPath, certPath]) {
      try { unlinkSync(path); } catch (error) { if (error.code !== 'ENOENT') throw failure(); }
    }
    rmdirSync(directory);
  }
}

async function assertRefused(port) {
  await new Promise((resolve, reject) => {
    const socket = connect({ host: '127.0.0.1', port });
    socket.setTimeout(500);
    socket.once('connect', () => { socket.destroy(); reject(failure()); });
    socket.once('timeout', () => { socket.destroy(); reject(failure()); });
    socket.once('error', error => { socket.destroy(); error.code === 'ECONNREFUSED' ? resolve() : reject(failure()); });
  });
}

export async function createTestIssuer(overrides = {}) {
  if (overrides.host !== undefined && overrides.host !== 'localhost') throw failure();
  const tls = freshCertificate(overrides.wrongHost, overrides.host);
  const signingAlgorithm = overrides.signingAlgorithm ?? 'ES256';
  const { privateKey, publicKey } = await generateKeyPair(signingAlgorithm);
  const jwk = { ...await exportJWK(publicKey), kid: 'fresh-test-key', use: 'sig', alg: signingAlgorithm };
  const codes = new Map(); const sockets = new Set();
  const calls = []; const adapters = new Set();
  let behavior = 'normal'; let gate; let issuer; let options; let closed = false;
  const json = (res, body, status = 200) => {
    res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body));
  };
  const server = createServer({ ...tls, minVersion: 'TLSv1.2' }, async (req, res) => {
    req.on('error', () => {}); res.on('error', () => {});
    const endpoint = req.url === '/token' && req.method === 'POST' ? 'token'
      : req.url === '/jwks' && req.method === 'GET' ? 'jwks' : 'unexpected';
    calls.push({ endpoint, method: req.method, host: req.headers.host, servername: req.socket.servername });
    try {
      if (endpoint === 'unexpected' || req.socket.remoteAddress !== '127.0.0.1') throw failure();
      const chunks = []; let size = 0;
      for await (const chunk of req) { size += chunk.length; if (size > 16_384) throw failure(); chunks.push(chunk); }
      if (behavior === 'slow-headers') return;
      if (behavior === 'stalled-body') { res.writeHead(200, { 'content-type': 'application/json' }); res.write('{'); return; }
      if (behavior === 'redirect') { res.writeHead(302, { 'content-type': 'application/json', location: `${issuer}never-follow` }); res.end('{}'); return; }
      if (behavior === 'oversized') { res.writeHead(200, { 'content-type': 'application/json' }); res.end('x'.repeat(65_537)); return; }
      if (behavior === 'wrong-content-type') { res.writeHead(200, { 'content-type': 'text/html' }); res.end('provider-secret'); return; }
      if (behavior === 'compressed') { res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'gzip' }); res.end('{}'); return; }
      if (behavior === 'truncated') {
        res.writeHead(200, { 'content-type': 'application/json', 'content-length': '1000' });
        res.write('{'); res.flushHeaders(); setImmediate(() => res.destroy()); return;
      }
      if (endpoint === 'jwks') { json(res, { keys: [jwk] }); return; }
      const body = new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
      const code = body.get('code'); const entry = codes.get(code); codes.delete(code);
      let validClient = false;
      if (options.tokenEndpointAuthMethod === 'client_secret_basic') {
        const header = req.headers.authorization ?? '';
        const parts = header.startsWith('Basic ') ? Buffer.from(header.slice(6), 'base64').toString('utf8').split(':') : [];
        const decode = value => decodeURIComponent(value.replace(/\+/gu, ' '));
        validClient = parts.length === 2 && decode(parts[0]) === options.clientId && decode(parts[1]) === options.clientSecret;
      } else validClient = body.get('client_id') === options.clientId && body.get('client_secret') === options.clientSecret && !req.headers.authorization;
      if (!entry || !validClient || body.get('grant_type') !== 'authorization_code'
        || body.get('redirect_uri') !== options.callbackUri || !body.get('code_verifier')
        || createHash('sha256').update(body.get('code_verifier')).digest('base64url') !== entry.challenge) {
        json(res, { error: 'invalid_grant', error_description: 'sensitive-provider-description' }, 400); return;
      }
      if (gate) await gate;
      // Align signed fixture timestamps with the adapter's trusted test clock.
      // Fresh certificate/key setup can cross a real second boundary while a
      // rollback test intentionally keeps its clock fixed. Production validation
      // remains unchanged; a future-issued ID token must still be rejected.
      const instant = overrides.now ? overrides.now() : Date.now();
      if (!Number.isSafeInteger(instant) || instant < 0) throw failure();
      const seconds = Math.floor(instant / 1000);
      const claims = { iss: issuer, aud: options.clientId, sub: 'invented-subject-one', iat: seconds,
        exp: seconds + 300, nonce: entry.nonce, email: 'invented@example.invalid', email_verified: true, ...entry.claims };
      for (const name of entry.omit ?? []) delete claims[name];
      const idToken = await new SignJWT(claims).setProtectedHeader({ alg: signingAlgorithm, kid: jwk.kid, ...entry.header })
        .sign(entry.key ?? privateKey);
      json(res, { token_type: 'Bearer', access_token: 'SENSITIVE_ACCESS_TOKEN', refresh_token: 'SENSITIVE_REFRESH_TOKEN',
        id_token: idToken, expires_in: 300 });
    } catch { if (!res.destroyed) json(res, { error: 'test_issuer_failed' }, 400); }
  });
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  server.on('tlsClientError', () => {});
  server.requestTimeout = 2000; server.headersTimeout = 2000;
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const port = server.address().port;
  issuer = `https://${overrides.host ?? '127.0.0.1'}:${port}/`;
  options = { issuer, authorizationEndpoint: `${issuer}authorize`, tokenEndpoint: `${issuer}token`,
    jwksUri: `${issuer}jwks`, callbackUri: overrides.callbackUri ?? 'https://participant.example.invalid/oidc/callback',
    clientId: 'invented-client', clientSecret: 'PRIVATE_CLIENT_SECRET',
    tokenEndpointAuthMethod: overrides.tokenEndpointAuthMethod ?? 'client_secret_basic', signingAlgorithm,
    identityKey: overrides.identityKey ?? randomBytes(32), ca: overrides.wrongCa ? freshCertificate().cert : tls.cert,
    ...(overrides.now ? { now: overrides.now } : {}) };
  const createAdapter = patch => {
    const adapter = createProductionIdentity({ ...options, ...patch }); adapters.add(adapter); return adapter;
  };
  const identity = createAdapter();

  function authorizationResponse(authorizationUrl, entry = {}) {
    const url = new URL(authorizationUrl);
    if (url.origin + url.pathname !== options.authorizationEndpoint || url.searchParams.get('client_id') !== options.clientId
      || url.searchParams.get('response_type') !== 'code' || url.searchParams.get('redirect_uri') !== options.callbackUri
      || url.searchParams.get('code_challenge_method') !== 'S256') throw failure();
    const code = browserBinding();
    codes.set(code, { ...entry, challenge: url.searchParams.get('code_challenge'), nonce: url.searchParams.get('nonce') });
    const callback = new URL(options.callbackUri);
    callback.search = new URLSearchParams({ code, state: url.searchParams.get('state'), iss: issuer });
    return callback.href;
  }
  async function authenticate(entry = {}, adapter = identity) {
    const browserSessionId = browserBinding();
    const start = await adapter.begin({ browserSessionId });
    if (!start.ok) return start;
    return adapter.complete({ browserSessionId, callbackUrl: authorizationResponse(start.authorizationUrl, entry) });
  }
  return { identity, options, calls, authenticate, authorizationResponse, createAdapter,
    setBehavior(value) { behavior = value; }, setGate(value) { gate = value; },
    async close() {
      if (closed) return; closed = true;
      for (const adapter of adapters) adapter.close();
      const stopped = new Promise((resolve, reject) => server.close(error => error ? reject(failure()) : resolve()));
      for (const socket of sockets) socket.destroy();
      await stopped; await assertRefused(port); codes.clear();
    } };
}
