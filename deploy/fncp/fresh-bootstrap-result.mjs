/** Pure shape check for a trusted fresh bootstrap adapter's observations.
 * No I/O, activation, provider verification or authority is conferred here.
 * Returned capability values are private and must never enter public evidence.
 */
import { types } from 'node:util';

const CONVERSATION = /^[0-9][0-9A-Za-z]{5,99}$/u;
const ABSENT_BINDING = /^9fncpBootstrap[0-9a-f]{48}$/u;
const error = () => Object.assign(new Error('Fresh synthetic bootstrap result rejected.'), { code: 'INVALID_BOOTSTRAP_RESULT' });

export function validateFreshBootstrapResult(value) {
  try {
    if (arguments.length !== 1 || !value || typeof value !== 'object' || types.isProxy(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw error();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length !== 2 || !keys.includes('conversationId') || !keys.includes('statementIds')
      || keys.some(key => !Object.hasOwn(descriptors[key], 'value'))) throw error();
    const conversationId = descriptors.conversationId.value;
    const ids = descriptors.statementIds.value;
    if (typeof conversationId !== 'string' || !CONVERSATION.test(conversationId) || ABSENT_BINDING.test(conversationId)
      || !Array.isArray(ids) || types.isProxy(ids) || Object.getPrototypeOf(ids) !== Array.prototype) throw error();
    const items = Object.getOwnPropertyDescriptors(ids);
    if (items.length?.value !== 15 || Reflect.ownKeys(items).length !== 16) throw error();
    const copied = [];
    for (let index = 0; index < 15; index++) {
      const slot = items[String(index)];
      if (!slot || !Object.hasOwn(slot, 'value')) throw error();
      const id = slot.value;
      // Pol.is comments.tid is PostgreSQL integer; reject coercion and -0.
      if (!Number.isSafeInteger(id) || id < 0 || Object.is(id, -0) || id > 2147483647) throw error();
      copied.push(id);
    }
    if (new Set(copied).size !== 15) throw error();
    return Object.freeze({ conversationId, statementIds: Object.freeze(copied) });
  } catch { throw error(); }
}
