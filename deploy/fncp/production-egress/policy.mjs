import { createHash } from 'node:crypto';
import { isIP } from 'node:net';

export const EGRESS_PROFILE = 'FNCP_OIDC_FIXED_RELAY_V1';
const policies = new WeakSet();
const deny = () => new Error('OIDC egress policy rejected.');
export function exactData(value, required, optional = []) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw deny();
  const fields = Reflect.ownKeys(value), descriptors = Object.getOwnPropertyDescriptors(value);
  if (required.some(name => !fields.includes(name)) || fields.some(name => typeof name !== 'string'
    || ![...required, ...optional].includes(name) || !Object.hasOwn(descriptors[name], 'value'))) throw deny();
}
export function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') return '{' + Object.keys(value).sort()
    .map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
  return JSON.stringify(value);
}
export function freeze(value) {
  if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); }
  return value;
}
export const hashPolicy = value => createHash('sha256').update(canonical(value)).digest('hex');

export function endpoint(value) {
  try {
    if (typeof value !== 'string' || value.length < 1 || value.length > 2048
      || /[\u0000-\u0020\u007f]/u.test(value)) throw deny();
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.href !== value || url.port || url.username || url.password
      || url.search || url.hash) throw deny();
    return value;
  } catch { throw deny(); }
}
function v4(value) {
  if (isIP(value) !== 4) return null;
  const bytes = value.split('.').map(Number);
  return bytes.join('.') === value ? bytes : null;
}
export function isPrivateListenAddress(value) {
  const b = typeof value === 'string' && v4(value);
  return Boolean(b && (b[0] === 10 || b[0] === 172 && b[1] >= 16 && b[1] <= 31
    || b[0] === 192 && b[1] === 168));
}
export function isPublicNumericAddress(value) {
  if (typeof value !== 'string' || value.length > 64) return false;
  const bytes = v4(value);
  if (bytes) {
    const [a, b, c] = bytes;
    return !(a === 0 || a === 10 || a === 127 || a >= 224
      || a === 100 && b >= 64 && b <= 127 || a === 169 && b === 254
      || a === 172 && b >= 16 && b <= 31 || a === 192 && b === 168
      || a === 192 && b === 0 && [0, 2].includes(c) || a === 192 && b === 88 && c === 99
      || a === 198 && [18, 19].includes(b) || a === 198 && b === 51 && c === 100
      || a === 203 && b === 0 && c === 113);
  }
  if (isIP(value) !== 6 || value.includes('.')) return false;
  try {
    if (new URL('https://[' + value + ']/').hostname !== '[' + value + ']') return false;
    const [left, right] = value.split('::'), a = left ? left.split(':') : [], b = right ? right.split(':') : [];
    const groups = right === undefined ? a : [...a, ...Array(8 - a.length - b.length).fill('0'), ...b];
    if (groups.length !== 8) return false;
    const number = BigInt('0x' + groups.map(x => x.padStart(4, '0')).join(''));
    const prefix = (network, bits) => number >> BigInt(128 - bits) === BigInt(network) >> BigInt(128 - bits);
    // Conservative public-unicast set. Transition and special-purpose ranges
    // fail closed; this does not claim to accept every globally routable address.
    return prefix('0x20000000000000000000000000000000', 3)
      && !prefix('0x20010000000000000000000000000000', 23)
      && !prefix('0x20010db8000000000000000000000000', 32)
      && !prefix('0x20020000000000000000000000000000', 16)
      && !prefix('0x3fff0000000000000000000000000000', 20);
  } catch { return false; }
}
function create(input) {
  exactData(input, ['tokenEndpoint', 'jwksUri', 'targets']); exactData(input.targets, ['token', 'jwks']);
  const tokenEndpoint = endpoint(input.tokenEndpoint), jwksUri = endpoint(input.jwksUri);
  if (tokenEndpoint === jwksUri || !isPublicNumericAddress(input.targets.token)
    || !isPublicNumericAddress(input.targets.jwks)) throw deny();
  const descriptor = { version: 1, profile: EGRESS_PROFILE, routes: {
    token: { endpoint: tokenEndpoint, listenPort: 8445, targetAddress: input.targets.token, targetPort: 443 },
    jwks: { endpoint: jwksUri, listenPort: 8446, targetAddress: input.targets.jwks, targetPort: 443 },
  } };
  const policy = freeze({ ...descriptor, policySha256: hashPolicy(descriptor) });
  policies.add(policy); return policy;
}
export function createProductionEgressPolicy(input) { try { return create(input); } catch { throw deny(); } }
export const isProductionEgressPolicy = value => Boolean(value && policies.has(value));
export function validateProductionEgressPolicy(input) {
  try {
    exactData(input, ['version', 'profile', 'routes', 'policySha256']); exactData(input.routes, ['token', 'jwks']);
    for (const name of ['token', 'jwks']) exactData(input.routes[name], ['endpoint', 'listenPort', 'targetAddress', 'targetPort']);
    const policy = create({ tokenEndpoint: input.routes.token.endpoint, jwksUri: input.routes.jwks.endpoint,
      targets: { token: input.routes.token.targetAddress, jwks: input.routes.jwks.targetAddress } });
    if (canonical(policy) !== canonical(input)) throw deny();
    return policy;
  } catch { throw deny(); }
}
