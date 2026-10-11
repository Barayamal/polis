/** Public-only API admission handoff. Import performs no I/O; creation reads
 * only the fixed pinned synthetic seed source and claims the original issuer's
 * independent API role. No listener, process, SQL, token or new lifetime is
 * created here. An owned launcher must retain the original signal/activity
 * check; serializing public data alone does not carry revocation authority.
 */
import { createHash, createPublicKey } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import { isProxy } from 'node:util/types';
import { claimBootstrapIssuerApiTrust } from './bootstrap-issuer.mjs';

const SEED_URL = new URL('../seed-statements.json', import.meta.url);
const SEED_SHA = 'b8c49ddaab72740df997b4975e84b0a51501fa97e1c622420826f4840bc6e06b';
const MAX_SEED_BYTES = 16384;
const claims = new WeakMap();
const fail = () => new Error('Fresh bootstrap API trust rejected; private details withheld.');
const sha = value => createHash('sha256').update(value).digest('hex');
const same = (a, b) => ['dev', 'ino', 'uid', 'mode', 'nlink', 'size', 'mtimeMs', 'ctimeMs']
  .every(name => a[name] === b[name]);

function exact(input) {
  if (!input || typeof input !== 'object' || isProxy(input) || Object.getPrototypeOf(input) !== Object.prototype ||
      Reflect.ownKeys(input).length !== 1) throw fail();
  const field = Object.getOwnPropertyDescriptor(input, 'issuer');
  if (!field || !Object.hasOwn(field, 'value')) throw fail();
  return field.value;
}
async function pinnedSeedText() {
  const before = await lstat(SEED_URL);
  if (!before.isFile() || before.isSymbolicLink() || before.size < 1 || before.size > MAX_SEED_BYTES) throw fail();
  const file = await open(SEED_URL, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  let bytes;
  try {
    const initial = await file.stat();
    if (!initial.isFile() || !same(initial, before)) throw fail();
    // Bound the read itself, even if a concurrent writer grows the file after
    // the initial stat. No path, retained archive or caller source is accepted.
    const buffer = Buffer.alloc(MAX_SEED_BYTES + 1); let length = 0;
    while (length < buffer.length) {
      const read = await file.read(buffer, length, buffer.length - length, length);
      if (!read.bytesRead) break;
      length += read.bytesRead;
    }
    if (length !== before.size || !same(await file.stat(), before)) throw fail();
    bytes = buffer.subarray(0, length);
  } finally { await file.close(); }
  if (!same(await lstat(SEED_URL), before) || sha(bytes) !== SEED_SHA) throw fail();
  const text = bytes.toString('utf8'); const statements = JSON.parse(text);
  if (!Array.isArray(statements) || statements.length !== 15 || new Set(statements).size !== 15 ||
      statements.some(value => typeof value !== 'string' || !value.length || value.length > 1000)) throw fail();
  return text;
}
function publicKey(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > 4096) throw fail();
  const document = JSON.parse(text);
  if (JSON.stringify(document) !== text || !document || Array.isArray(document) ||
      Object.keys(document).join() !== 'keys' || !Array.isArray(document.keys) || document.keys.length !== 1) throw fail();
  const key = document.keys[0];
  if (!key || Array.isArray(key) || Object.keys(key).sort().join() !== 'alg,e,kid,kty,n,use' ||
      key.kty !== 'RSA' || key.alg !== 'RS256' || key.use !== 'sig' || key.e !== 'AQAB' ||
      typeof key.n !== 'string' || !/^[A-Za-z0-9_-]{342}$/u.test(key.n) ||
      typeof key.kid !== 'string' || !/^[a-f0-9]{64}$/u.test(key.kid)) throw fail();
  const modulus = Buffer.from(key.n, 'base64url');
  if (modulus.length !== 256 || modulus.toString('base64url') !== key.n || (modulus[0] & 128) === 0 ||
      sha(createPublicKey({ key, format: 'jwk' }).export({ format: 'der', type: 'spki' })) !== key.kid) throw fail();
  return Object.freeze(key);
}

/** Only a genuine original issuer is accepted. This reserves its API role,
 * not its separate JWKS-service or one-token role. Failure consumes the role;
 * it does not fall back to caller configuration or reconstruct an issuer. */
export async function createBootstrapApiTrust(options) {
  if (arguments.length !== 1) throw fail();
  try {
    const issuer = exact(options);
    const original = await claimBootstrapIssuerApiTrust(issuer);
    original.assertActive();
    const key = publicKey(original.publicJwksText);
    const seedStatementsJson = await pinnedSeedText();
    original.assertActive();
    // Original issuer constructs this exact literal loopback value. Checking
    // it again prevents an accidental future widening of this public handoff.
    const url = new URL(original.issuer);
    if (url.protocol !== 'https:' || url.hostname !== '127.0.0.1' || url.username || url.password ||
        url.pathname !== '/' || url.search || url.hash || url.href !== original.issuer ||
        !/^[1-9][0-9]{3,4}$/u.test(url.port) || Number(url.port) < 1024 || Number(url.port) > 65535) throw fail();
    const state = { claimed: false, original, key, seedStatementsJson };
    const capability = Object.freeze({
      summary() {
        if (arguments.length) throw fail();
        return Object.freeze({ mode: 'PUBLIC_API_TRUST_HANDOFF_ONLY', originalIssuerLifetime: true,
          listenerHandoffClaimed: state.claimed, pinnedSyntheticStatements: 15,
          tokensMintedByThisCapability: 0, listenersStarted: 0, processesStarted: 0,
          actualPolisVerified: false, runtimeOwnershipVerified: false, productionReady: false });
      },
    });
    claims.set(capability, state); return capability;
  } catch { throw fail(); }
}

/** One in-process listener role, never a structural/copyable credential. The
 * returned public bytes remain public after expiry; a launcher MUST continue
 * observing this same signal/assertActive rather than resetting a lifetime. */
export function claimBootstrapApiTrust(capability) {
  if (arguments.length !== 1 || !claims.has(capability)) throw fail();
  const state = claims.get(capability);
  if (state.claimed) throw fail();
  state.claimed = true;
  try {
    state.original.assertActive();
    return Object.freeze({ issuer: state.original.issuer, publicJwk: state.key,
      seedStatementsJson: state.seedStatementsJson, signal: state.original.signal,
      assertActive: state.original.assertActive });
  } catch { throw fail(); }
}
