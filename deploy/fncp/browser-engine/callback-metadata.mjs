/** Pure TEST evidence collector, not application authorization.
 * CDP ExtraInfo order is independent of request events and may omit redirect
 * legs. Presence flags, not assumed one-for-one positions, govern correlation.
 * No raw URL, Cookie value or other header is retained beyond each call.
 */
const LIMIT = 120;
const COOKIE_NAMES = ['__Host-fncp_browser', '__Host-fncp_oidc_tx'];
const enums = {
  'sec-fetch-site': new Set(['same-origin', 'same-site', 'cross-site', 'none']),
  'sec-fetch-mode': new Set(['navigate', 'same-origin', 'cors', 'no-cors', 'websocket']),
  'sec-fetch-dest': new Set(['document', 'empty', 'iframe', 'script', 'style', 'image', 'font', 'worker', 'serviceworker']),
};
const invalid = () => { throw new Error('Invalid callback evidence event.'); };
function data(object, name, optional = false) {
  if (!object || typeof object !== 'object' || Array.isArray(object)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(object))) invalid();
  const descriptor = Object.getOwnPropertyDescriptor(object, name);
  if (!descriptor) { if (optional) return undefined; invalid(); }
  if (!Object.hasOwn(descriptor, 'value')) invalid();
  return descriptor.value;
}
function metadata(headers) {
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(headers))) invalid();
  const values = new Map();
  for (const [name, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(headers))) {
    const key = name.toLowerCase();
    if (key !== 'cookie' && !Object.hasOwn(enums, key)) continue;
    if (values.has(key) || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'string'
      || descriptor.value.length > (key === 'cookie' ? 8192 : 32)) invalid();
    values.set(key, descriptor.value);
  }
  const field = key => values.has(key) ? enums[key].has(values.get(key)) ? values.get(key) : 'INVALID' : 'ABSENT';
  const pairs = (values.get('cookie') ?? '').split(';').map(part => part.trim());
  const counts = COOKIE_NAMES.map(name => pairs.filter(pair => pair.startsWith(name + '=')).length);
  if (counts.some(count => count > 1)) invalid();
  return Object.freeze({ site: field('sec-fetch-site'), mode: field('sec-fetch-mode'), dest: field('sec-fetch-dest'),
    appCookiePresent: counts[0] === 1, transactionCookiePresent: counts[1] === 1 });
}

export function createCallbackMetadataCollector(...args) {
  const origin = args[0];
  try {
    if (args.length !== 1 || typeof origin !== 'string'
      || !/^https:\/\/browser\.example\.invalid:[1-9][0-9]{0,4}$/u.test(origin)
      || new URL(origin).origin !== origin || Number(new URL(origin).port) > 65535) invalid();
  } catch { throw new Error('Exact synthetic browser origin required for callback evidence.'); }
  const entries = new Map(); let pendingEvents = 0; let requestEvents = 0; let rejectedEvents = 0;
  function reject() { rejectedEvents++; }
  function entryFor(event) {
    const id = data(event, 'requestId');
    if (typeof id !== 'string' || !/^[A-Za-z0-9._:-]{1,128}$/u.test(id)) invalid();
    let entry = entries.get(id);
    if (!entry) {
      if (entries.size >= LIMIT) invalid();
      entry = { legs: [], extras: [], callbacks: [], tail: undefined, hasCallback: false, final: false, completed: false };
      entries.set(id, entry);
    }
    return entry;
  }
  function reserve() { if (pendingEvents >= LIMIT) invalid(); pendingEvents++; }
  function drain(entry) {
    while (entry.legs.length && entry.legs[0].hasExtra !== undefined) {
      const leg = entry.legs[0];
      if (leg.hasExtra && !entry.extras.length) break;
      entry.legs.shift(); pendingEvents--;
      if (leg.hasExtra) {
        const headers = entry.extras.shift(); pendingEvents--;
        if (leg.callback) entry.callbacks.push(headers);
      } else if (leg.callback) {
        // A callback without ExtraInfo cannot support on-wire cookie claims.
        invalid();
      }
    }
    if (entry.final && entry.legs.length === 0) {
      if (entry.extras.length !== 0) invalid();
      entry.completed = true;
    }
  }
  function receive(kind, event) {
    if (rejectedEvents) return; // A failed collector can never recover into PASS.
    try {
      const entry = entryFor(event);
      if (entry.completed || entry.final && kind !== 'extra') invalid();
      if (kind === 'request') {
        if (requestEvents >= LIMIT) invalid();
        const raw = data(data(event, 'request'), 'url');
        if (typeof raw !== 'string' || raw.length > 8192) invalid();
        const url = new URL(raw);
        if (url.href !== raw || url.username || url.password || url.hash) invalid();
        const callback = url.origin === origin && url.pathname === '/oidc/callback';
        const redirect = data(event, 'redirectResponse', true);
        const flag = data(event, 'redirectHasExtraInfo', true);
        if (entry.tail) {
          if (!redirect || typeof redirect !== 'object' || Array.isArray(redirect) || typeof flag !== 'boolean'
            || entry.tail.hasExtra !== undefined) invalid();
          entry.tail.hasExtra = flag;
        } else if (redirect !== undefined || flag !== undefined && typeof flag !== 'boolean') invalid();
        reserve(); requestEvents++;
        const leg = { callback, hasExtra: undefined }; entry.legs.push(leg); entry.tail = leg;
        entry.hasCallback ||= callback;
      } else if (kind === 'extra') {
        const headers = metadata(data(event, 'headers'));
        reserve(); entry.extras.push(headers);
      } else {
        const flag = data(event, 'hasExtraInfo');
        if (!entry.tail || typeof flag !== 'boolean' || entry.tail.hasExtra !== undefined) invalid();
        entry.tail.hasExtra = flag; entry.final = true;
      }
      drain(entry);
    } catch { reject(); }
  }
  function observations() {
    const relevant = [...entries.values()].filter(entry => entry.hasCallback);
    const complete = rejectedEvents === 0 && relevant.length > 0 && relevant.every(entry => entry.completed);
    // Never publish possibly shifted callback metadata from an unfinished chain.
    const callbacks = complete ? relevant.flatMap(entry => entry.callbacks).map(value => Object.freeze({ ...value })) : [];
    return Object.freeze({ complete, callbacks: Object.freeze(callbacks), callbackCount: callbacks.length,
      requestIds: entries.size, requestEvents, pendingEvents, rejectedEvents });
  }
  return Object.freeze({ request: event => receive('request', event), extra: event => receive('extra', event),
    response: event => receive('response', event), observations });
}
