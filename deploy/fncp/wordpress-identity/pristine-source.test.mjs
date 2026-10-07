/** Synthetic byte-boundary tests only. Positive fixtures replace the pin in an
 * isolated in-memory test module, never in production source or a public API.
 * No acquisition, actual WordPress bytes, retained archive or extraction.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { createPristineWordPressSource, readPristineWordPressBytes } from './pristine-source.mjs';

const pin = '05a5f89138f632b7329f1202f2a0553c5f7fe4daf8e4b9ca7ebae9b9466b9e86';
const denied = error => error.message === 'Pinned pristine WordPress source rejected.';
const arrayBuffer = bytes => Uint8Array.from(bytes).buffer;
async function model() {
  const bytes = gzipSync(Buffer.from('Invented inert model bytes. This is not a WordPress archive.'));
  const hash = createHash('sha256').update(bytes).digest('hex');
  const source = await readFile(new URL('./pristine-source.mjs', import.meta.url), 'utf8');
  assert.equal(source.split(pin).length, 2);
  const module = await import('data:text/javascript;base64,' + Buffer.from(source.replace(pin, hash)).toString('base64'));
  return { bytes, hash, module };
}

test('production factory has a fixed release digest and rejects synthetic bytes or caller hash overrides', () => {
  const bytes = gzipSync(Buffer.from('invented bytes cannot equal the official source pin'));
  for (const input of [arrayBuffer(bytes), { bytes: arrayBuffer(bytes), sha256: pin }, undefined, null, 'private/path', new URL('https://example.test/source')]) {
    assert.throws(() => createPristineWordPressSource(input), denied);
  }
  assert.throws(() => createPristineWordPressSource(arrayBuffer(bytes), pin), denied);
  assert.throws(() => createPristineWordPressSource(), denied);
});

test('model-only successful byte brand copies input and each consumed result; metadata carries no path or acquisition claim', async () => {
  const f = await model(); const input = arrayBuffer(f.bytes);
  const source = f.module.createPristineWordPressSource(input);
  assert.deepEqual(source, { mode: 'PINNED_PRISTINE_SOURCE', release: '7.1', sha256: f.hash, sizeBytes: f.bytes.length });
  assert.equal(Object.isFrozen(source), true);
  new Uint8Array(input).fill(0);
  assert.deepEqual(f.module.readPristineWordPressBytes(source), f.bytes);
  const consumed = f.module.readPristineWordPressBytes(source); consumed.fill(0);
  assert.deepEqual(f.module.readPristineWordPressBytes(source), f.bytes);
});

test('brand cannot be reconstructed, proxied, transferred from another module, or accompanied by extra arguments', async () => {
  const f = await model(); const source = f.module.createPristineWordPressSource(arrayBuffer(f.bytes));
  for (const candidate of [null, undefined, {}, { ...source }, Object.freeze({ ...source }), new Proxy(source, {})]) {
    assert.throws(() => f.module.readPristineWordPressBytes(candidate), denied);
  }
  assert.throws(() => readPristineWordPressBytes(source), denied);
  assert.throws(() => f.module.readPristineWordPressBytes(source, 'extra'), denied);
  assert.throws(() => f.module.readPristineWordPressBytes(), denied);
});

test('source requires a plain ArrayBuffer and rejects views, Buffer subclasses, proxies, shared and resizable memory', async () => {
  const f = await model(); let traps = 0;
  class CustomBuffer extends Buffer {}
  class CustomArrayBuffer extends ArrayBuffer {}
  const bufferSubclass = Buffer.from(f.bytes); Object.setPrototypeOf(bufferSubclass, CustomBuffer.prototype);
  const proxy = new Proxy(arrayBuffer(f.bytes), { getPrototypeOf() { traps++; throw Error('private'); }, ownKeys() { traps++; throw Error('private'); } });
  const shared = new SharedArrayBuffer(f.bytes.length); new Uint8Array(shared).set(f.bytes);
  const resizable = new ArrayBuffer(f.bytes.length, { maxByteLength: f.bytes.length * 2 }); new Uint8Array(resizable).set(f.bytes);
  for (const input of [f.bytes, bufferSubclass, new Uint8Array(f.bytes), new DataView(arrayBuffer(f.bytes)), proxy,
    shared, new Uint8Array(shared), resizable, new CustomArrayBuffer(f.bytes.length)]) {
    assert.throws(() => f.module.createPristineWordPressSource(input), denied);
  }
  assert.equal(traps, 0);
});

test('source rejects own extra, accessor, hidden and symbol properties before invoking any getter', async () => {
  const f = await model(); let invoked = 0;
  for (const key of ['path', Symbol('private')]) {
    const input = arrayBuffer(f.bytes);
    Object.defineProperty(input, key, { get() { invoked++; throw Error('private'); } });
    assert.throws(() => f.module.createPristineWordPressSource(input), denied);
  }
  const hidden = arrayBuffer(f.bytes); Object.defineProperty(hidden, 'sha256', { value: f.hash });
  assert.throws(() => f.module.createPristineWordPressSource(hidden), denied);
  assert.equal(invoked, 0);
});

test('size, detached-memory, gzip magic and digest failures are fixed and reveal no input', async () => {
  const f = await model();
  const detached = arrayBuffer(f.bytes); structuredClone(detached, { transfer: [detached] });
  const badMagic = Buffer.from(f.bytes); badMagic[0] = 0;
  const badDigest = Buffer.from(f.bytes); badDigest[badDigest.length - 1] ^= 1;
  for (const input of [new ArrayBuffer(0), new ArrayBuffer(17), new ArrayBuffer(64 * 1024 * 1024 + 1), detached,
    arrayBuffer(badMagic), arrayBuffer(badDigest)]) {
    assert.throws(() => f.module.createPristineWordPressSource(input), denied);
  }
});
