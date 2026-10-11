import test from 'node:test';
import assert from 'node:assert/strict';
import { validateFreshBootstrapResult } from './fresh-bootstrap-result.mjs';

const ids = () => [40, 22, 93, 17, 26, 48, 100, 2, 69, 21, 51, 67, 99, 115, 203];
const valid = () => ({ conversationId: '2InventedOnly', statementIds: ids() });
const rejected = error => error?.code === 'INVALID_BOOTSTRAP_RESULT'
  && error.message === 'Fresh synthetic bootstrap result rejected.';

test('fresh bootstrap preserves fifteen observed IDs without inventing sequence or granting authority', () => {
  const input = valid(); const result = validateFreshBootstrapResult(input);
  assert.deepEqual(result, input); assert.notEqual(result, input); assert.notEqual(result.statementIds, input.statementIds);
  assert.equal(Object.isFrozen(result), true); assert.equal(Object.isFrozen(result.statementIds), true);
  input.statementIds[0] = 800; input.conversationId = '4Different';
  assert.equal(result.statementIds[0], 40); assert.equal(result.conversationId, '2InventedOnly');
  assert.deepEqual(Object.keys(result), ['conversationId', 'statementIds']);
});
test('fresh bootstrap accepts real integer boundary values and null-prototype observation envelopes', () => {
  const input = Object.assign(Object.create(null), valid()); input.statementIds[0] = 0; input.statementIds[1] = 2147483647;
  assert.deepEqual(validateFreshBootstrapResult(input).statementIds, input.statementIds);
});
test('fresh bootstrap rejects missing, extra, symbolic, inherited and caller-selected authority fields', () => {
  for (const input of [undefined, null, [], {}, 'private-sentinel', 1, true, Object.create(valid()),
    { ...valid(), activation: true }, { ...valid(), host: 'https://invalid.example' },
    { ...valid(), [Symbol('private')]: true }, { conversationId: '2Valid' }, { statementIds: ids() }]) {
    assert.throws(() => validateFreshBootstrapResult(input), rejected);
  }
  assert.throws(() => validateFreshBootstrapResult(valid(), undefined), rejected);
});
test('fresh bootstrap never invokes caller accessors, proxy traps or coercions', () => {
  let calls = 0;
  const envelope = valid(); Object.defineProperty(envelope, 'conversationId', { get() { calls++; return '2Private'; } });
  const array = ids(); Object.defineProperty(array, '0', { get() { calls++; return 40; } });
  const trap = { getPrototypeOf() { calls++; return Object.prototype; }, ownKeys() { calls++; return []; } };
  const revoked = Proxy.revocable(valid(), {}); revoked.revoke();
  for (const value of [envelope, { ...valid(), statementIds: array }, new Proxy(valid(), trap), revoked.proxy,
    { ...valid(), statementIds: new Proxy(ids(), trap) },
    { ...valid(), conversationId: { toString() { calls++; return '2Private'; } } }]) {
    assert.throws(() => validateFreshBootstrapResult(value), rejected);
  }
  assert.equal(calls, 0);
});
test('fresh bootstrap rejects noncanonical, absent-binding and out-of-contract conversation results', () => {
  for (const conversationId of ['', '2tiny', 'notnumeric', '2a_bcd', '2a-bcd', '2abcde\n', ' 2abcde', '2abcde ',
    '2abcde/../', '2' + 'a'.repeat(100), '9fncpBootstrap' + 'a'.repeat(48), null, 22]) {
    assert.throws(() => validateFreshBootstrapResult({ ...valid(), conversationId }), rejected);
  }
  for (const conversationId of ['2abcde', '2' + 'A'.repeat(99)]) assert.equal(validateFreshBootstrapResult({ ...valid(), conversationId }).conversationId, conversationId);
});
test('fresh bootstrap rejects wrong count, sparse, subclassed, decorated and non-array statement lists', () => {
  const sparse = ids(); delete sparse[4];
  const decorated = ids(); decorated.extra = 'private-sentinel';
  const symbolic = ids(); symbolic[Symbol('extra')] = true;
  class CustomIds extends Array {}
  for (const statementIds of [[], ids().slice(1), [...ids(), 1000], sparse, decorated, symbolic,
    new CustomIds(...ids()), new Uint32Array(ids()), { ...ids(), length: 15 }, null, ids().join(',')]) {
    assert.throws(() => validateFreshBootstrapResult({ ...valid(), statementIds }), rejected);
  }
});
test('fresh bootstrap rejects duplicates, coercions, non-integers and PostgreSQL integer overflow', () => {
  for (const invalid of [22, -0, -1, 0.5, NaN, Infinity, -Infinity, 2147483648, Number.MAX_SAFE_INTEGER,
    Number.MAX_SAFE_INTEGER + 1, '40', 40n, null, undefined, {}, new Number(40)]) {
    const statementIds = ids(); statementIds[0] = invalid;
    assert.throws(() => validateFreshBootstrapResult({ ...valid(), statementIds }), rejected);
  }
});
