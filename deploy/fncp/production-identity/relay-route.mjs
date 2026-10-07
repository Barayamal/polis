// Fixed private transport routing. It does not make a participant network
// externally reachable or provide a general HTTP proxy.
import { isIP } from 'node:net';

export const OIDC_RELAY_PROFILE = 'OIDC_FIXED_RELAY_V1';
const fail = () => new Error('OIDC relay configuration rejected.');
const fields = ['profile', 'host', 'tokenPort', 'jwksPort', 'policySha256'];

export function validateOidcRelayRoute(value) {
  try {
    if (!value || Object.getPrototypeOf(value) !== Object.prototype
      || Reflect.ownKeys(value).length !== fields.length
      || fields.some(key => !Object.hasOwn(value, key))
      || Object.values(Object.getOwnPropertyDescriptors(value)).some(d => !Object.hasOwn(d, 'value'))
      || value.profile !== OIDC_RELAY_PROFILE || value.host !== 'oidc-relay'
      || value.tokenPort !== 8445 || value.jwksPort !== 8446
      || typeof value.policySha256 !== 'string' || !/^[a-f0-9]{64}$/u.test(value.policySha256)) throw fail();
    return Object.freeze({ ...value });
  } catch { throw fail(); }
}

// A named loopback-only transport fixture. The production identity constructor
// and file-backed service accept only validateOidcRelayRoute above.
export function validateTransportRelay(value, tokenEndpoint, jwksUri) {
  const profile = value && typeof value === 'object' ? Object.getOwnPropertyDescriptor(value, 'profile') : undefined;
  if (!profile || !Object.hasOwn(profile, 'value') || profile.value !== 'OIDC_SYNTHETIC_RELAY_V1') return validateOidcRelayRoute(value);
  try {
    const names = ['profile', 'host', 'tokenPort', 'jwksPort'];
    if (!value || Object.getPrototypeOf(value) !== Object.prototype
      || Reflect.ownKeys(value).length !== names.length || names.some(key => !Object.hasOwn(value, key))
      || Object.values(Object.getOwnPropertyDescriptors(value)).some(d => !Object.hasOwn(d, 'value'))
      || value.host !== '127.0.0.1' || ![value.tokenPort, value.jwksPort].every(p => Number.isSafeInteger(p) && p >= 1024 && p <= 65535)) throw fail();
    for (const endpoint of [tokenEndpoint, jwksUri]) {
      const host = new URL(endpoint).hostname;
      if (host !== 'localhost' && !(isIP(host) === 4 && host === '127.0.0.1')) throw fail();
    }
    return Object.freeze({ ...value });
  } catch { throw fail(); }
}
