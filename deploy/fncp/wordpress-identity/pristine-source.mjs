/** Pinned pristine source bytes only. No file, network, archive extraction or
 * runtime I/O. A source handle proves bytes match the fixed release digest;
 * it does not prove when/where the caller acquired them or authorize execution.
 */
import { createHash } from 'node:crypto';
import { types } from 'node:util';

const RELEASE = '7.1';
const SHA256 = '05a5f89138f632b7329f1202f2a0553c5f7fe4daf8e4b9ca7ebae9b9466b9e86';
const MAX_BYTES = 64 * 1024 * 1024;
const sources = new WeakMap();
const byteLength = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength').get;
const resizable = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'resizable')?.get;
const failure = () => new Error('Pinned pristine WordPress source rejected.');
const digest = value => createHash('sha256').update(value).digest('hex');
const verify = bytes => {
  if (bytes.length < 18 || bytes.length > MAX_BYTES || bytes[0] !== 0x1f || bytes[1] !== 0x8b || bytes[2] !== 8 ||
      digest(bytes) !== SHA256) throw failure();
};

/** Exactly one plain, fixed-length, unshared ArrayBuffer; no path, URL, hash or
 * environment override. Buffer/views/subclasses/proxies are deliberately not
 * accepted. Copy an exact binary range into an ArrayBuffer before calling.
 */
export function createPristineWordPressSource(...args) {
  try {
    const input = args[0];
    // Native type predicates reject proxies/shared buffers before property access.
    if (args.length !== 1 || !types.isArrayBuffer(input) || Object.getPrototypeOf(input) !== ArrayBuffer.prototype ||
        Reflect.ownKeys(input).length !== 0 || (resizable && Reflect.apply(resizable, input, []))) throw failure();
    const size = Reflect.apply(byteLength, input, []);
    if (!Number.isSafeInteger(size) || size < 18 || size > MAX_BYTES) throw failure();
    const bytes = Buffer.from(new Uint8Array(input));
    verify(bytes);
    const source = Object.freeze({ mode: 'PINNED_PRISTINE_SOURCE', release: RELEASE, sha256: SHA256, sizeBytes: size });
    sources.set(source, bytes);
    return source;
  } catch { throw failure(); }
}

/** Runtime-only consumption boundary: brand and digest are checked again, then
 * a defensive copy is returned. No caller can mutate the private stored bytes.
 */
export function readPristineWordPressBytes(...args) {
  try {
    if (args.length !== 1 || !sources.has(args[0])) throw failure();
    const bytes = sources.get(args[0]); verify(bytes);
    return Buffer.from(bytes);
  } catch { throw failure(); }
}
