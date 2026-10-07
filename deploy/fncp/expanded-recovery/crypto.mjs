/** Bounded, domain-separated synthetic backup envelopes. No I/O or authority. */
import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { canonical } from '../strict-recovery/contract.mjs';

export const MODE = 'expanded-synthetic-restore-only';
export const COMPONENTS = Object.freeze(['wordpress-mysql', 'access-sqlite', 'activation-sqlite', 'polis-postgresql', 'key-continuity']);
export const sha256 = value => createHash('sha256').update(value).digest('hex');
export const need = value => { if (!value) throw new Error('Expanded synthetic recovery denied.'); };
export const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const HEX = /^[a-f0-9]{64}$/u;
const RUN = /^[a-f0-9]{24}$/u;
const MAX = 64 * 1024 * 1024;
const matches = (regex, value) => typeof value === 'string' && regex.exec(value)?.[0] === value;

export function header(run, component, scopeSha256) {
  need(matches(RUN, run) && COMPONENTS.includes(component) && matches(HEX, scopeSha256));
  return { version: 1, mode: MODE, algorithm: 'AES-256-GCM', run, component, scopeSha256 };
}
export function seal(plaintext, key, binding) {
  need(Buffer.isBuffer(plaintext) && plaintext.length > 0 && plaintext.length <= MAX && Buffer.isBuffer(key) && key.length === 32);
  need(canonical(binding) === canonical(header(binding.run, binding.component, binding.scopeSha256)));
  const nonce = randomBytes(12); const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
  cipher.setAAD(Buffer.from(canonical(binding)));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  // Large ciphertext is deliberately outside the strict snapshot JSON budget.
  return Buffer.from(JSON.stringify({ header: binding, nonce: nonce.toString('hex'), tag: cipher.getAuthTag().toString('hex'), ciphertext: ciphertext.toString('base64') }));
}
export function unseal(encoded, key, expected) {
  try {
    need(Buffer.isBuffer(encoded) && encoded.length <= MAX * 1.4 && Buffer.isBuffer(key) && key.length === 32);
    const e = JSON.parse(encoded.toString('utf8'));
    need(exact(e, ['header', 'nonce', 'tag', 'ciphertext']) && canonical(e.header) === canonical(expected));
    need(canonical(expected) === canonical(header(expected.run, expected.component, expected.scopeSha256)));
    need(matches(/^[a-f0-9]{24}$/u, e.nonce) && matches(/^[a-f0-9]{32}$/u, e.tag));
    need(typeof e.ciphertext === 'string' && /^[A-Za-z0-9+/]+={0,2}$/u.test(e.ciphertext));
    const ciphertext = Buffer.from(e.ciphertext, 'base64'); need(ciphertext.toString('base64') === e.ciphertext && ciphertext.length <= MAX);
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(e.nonce, 'hex'), { authTagLength: 16 });
    decipher.setAAD(Buffer.from(canonical(expected))); decipher.setAuthTag(Buffer.from(e.tag, 'hex'));
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch { throw new Error('Expanded encrypted component authentication failed.'); }
}
export function signManifest(manifest, key) {
  need(Buffer.isBuffer(key) && key.length === 32);
  return { manifest, mac: createHmac('sha256', key).update('FNCP-EXPANDED-RECOVERY-MANIFEST-v1\n' + canonical(manifest)).digest('hex') };
}
export function verifyManifest(envelope, key, run, scopeSha256, components) {
  try {
    need(exact(envelope, ['manifest', 'mac']) && matches(HEX, envelope.mac));
    const expected = signManifest(envelope.manifest, key).mac;
    need(timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(envelope.mac, 'hex')));
    const m = envelope.manifest;
    need(exact(m, ['version', 'mode', 'run', 'recordedAt', 'scopeSha256', 'scope', 'source', 'components']));
    need(m.version === 1 && m.mode === MODE && m.run === run && m.scopeSha256 === scopeSha256 && sha256(canonical(m.scope)) === scopeSha256);
    need(exact(m.components, COMPONENTS) && exact(components, COMPONENTS));
    for (const name of COMPONENTS) {
      const item = m.components[name]; const bytes = components[name];
      need(exact(item, ['filename', 'bytes', 'sha256', 'mode']) && Buffer.isBuffer(bytes) &&
        item.filename === name + '.aesgcm' && item.bytes === bytes.length && item.sha256 === sha256(bytes) && item.mode === '600');
    }
    return m;
  } catch { throw new Error('Expanded exact manifest authentication failed.'); }
}
