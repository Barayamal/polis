// Local lifecycle ownership only: this module neither grants participant
// authority nor supplies a deployable hosting/authentication configuration.
const MAX_SERVICES = 8;
const NAME = /^[a-z][a-z0-9-]{0,31}$/;
const RESERVED_NAMES = new Set(['constructor', 'prototype', '__proto__']);

function failure(code) {
  const messages = {
    INVALID_CONFIG: 'Invalid local service supervisor configuration.',
    START_UNAVAILABLE: 'Local service startup is unavailable after an earlier start or close.',
    START_FAILED: 'Local service startup failed; owned services were instructed to close.',
    START_CANCELLED: 'Local service startup was cancelled by closure.',
    CLOSE_FAILED: 'Local service closure was not fully confirmed.',
  };
  return Object.assign(new Error(messages[code]), { code });
}

function dataFields(value, keys, optional = []) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw failure('INVALID_CONFIG');
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw failure('INVALID_CONFIG');
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const actual = Reflect.ownKeys(descriptors);
  if (keys.some(key => !actual.includes(key)) || actual.some(key => ![...keys, ...optional].includes(key))) throw failure('INVALID_CONFIG');
  const result = Object.create(null);
  for (const key of actual) {
    if (!Object.hasOwn(descriptors[key], 'value')) throw failure('INVALID_CONFIG');
    result[key] = descriptors[key].value;
  }
  return result;
}

function method(service, key) {
  if (!service || typeof service !== 'object') throw failure('INVALID_CONFIG');
  const descriptor = Object.getOwnPropertyDescriptor(service, key);
  if (!descriptor || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'function') {
    throw failure('INVALID_CONFIG');
  }
  return descriptor.value.bind(service);
}

function ownedServices(configuration) {
  const config = dataFields(configuration, ['services', 'closeAuthority']);
  if (typeof config.closeAuthority !== 'function' || !Array.isArray(config.services)
    || config.services.length < 1 || config.services.length > MAX_SERVICES) throw failure('INVALID_CONFIG');
  const serviceKeys = Reflect.ownKeys(config.services);
  if (Object.getPrototypeOf(config.services) !== Array.prototype
    || serviceKeys.length !== config.services.length + 1
    || serviceKeys.some(key => key !== 'length' && !/^(0|[1-7])$/.test(String(key)))) {
    throw failure('INVALID_CONFIG');
  }
  const names = new Set();
  const instances = new Set();
  const ports = new Set();
  const services = [];
  for (let index = 0; index < config.services.length; index += 1) {
    const slot = Object.getOwnPropertyDescriptor(config.services, String(index));
    if (!slot || !Object.hasOwn(slot, 'value')) throw failure('INVALID_CONFIG');
    const fields = dataFields(slot.value, ['name', 'service', 'port'], ['expectedOrigin']);
    const { name, service, port } = fields;
    if (typeof name !== 'string' || !NAME.test(name) || RESERVED_NAMES.has(name) || names.has(name)
      || !Number.isInteger(port) || port < 0 || port > 65535
      || (port !== 0 && ports.has(port)) || instances.has(service)) throw failure('INVALID_CONFIG');
    const listen = method(service, 'listen');
    const close = method(service, 'close');
    let expectedOrigin;
    if (Object.hasOwn(fields, 'expectedOrigin')) {
      expectedOrigin = fields.expectedOrigin;
      if (port === 0 || typeof expectedOrigin !== 'string'
        || expectedOrigin !== `https://browser.example.invalid:${port}`
        || new URL(expectedOrigin).origin !== expectedOrigin) throw failure('INVALID_CONFIG');
    }
    names.add(name); instances.add(service); if (port !== 0) ports.add(port);
    services.push({ name, port, listen, close, expectedOrigin, state: 'CONSTRUCTED' });
  }
  return { services, closeAuthority: config.closeAuthority };
}

function checkedOrigin(origin, requestedPort, expectedOrigin) {
  if (expectedOrigin !== undefined) {
    if (origin !== expectedOrigin) throw failure('START_FAILED');
    return origin;
  }
  if (typeof origin !== 'string' || !/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/.test(origin)) {
    throw failure('START_FAILED');
  }
  const port = Number(origin.slice('http://127.0.0.1:'.length));
  if (port > 65535 || (requestedPort !== 0 && requestedPort !== port)) throw failure('START_FAILED');
  return origin;
}

export function createServiceSupervisor(configuration) {
  // Validation/capture completes before any listen, close, or authority call.
  let validated;
  try { validated = ownedServices(configuration); } catch { throw failure('INVALID_CONFIG'); }
  const { services, closeAuthority } = validated;
  let state = 'CREATED';
  let startAttempted = false;
  let closing = false;
  let startupFailed = false;
  let closePromise;
  let signalClose;
  const closeSignal = new Promise(resolve => { signalClose = resolve; });
  const CLOSED = Symbol('closed');

  function close() {
    if (closePromise) return closePromise;
    closing = true;
    state = 'CLOSING';
    let resolveClose;
    let rejectClose;
    // Publish the latch/promise before calling external methods: even a
    // re-entrant close sees exactly the same promise and cannot repeat work.
    closePromise = new Promise((resolve, reject) => { resolveClose = resolve; rejectClose = reject; });
    signalClose(CLOSED);
    const pending = [];
    let authorityResult;
    try { authorityResult = closeAuthority(); } catch { authorityResult = Promise.reject(failure('CLOSE_FAILED')); }
    pending.push(authorityResult === closePromise ? Promise.resolve(false)
      : Promise.resolve(authorityResult).then(() => true, () => false));
    // Start every reverse-order close without waiting for the previous drain.
    // A later service may depend on another service's cancellation to drain.
    for (const owned of [...services].reverse()) {
      owned.state = 'CLOSING';
      let result;
      try { result = owned.close(); } catch { result = Promise.reject(failure('CLOSE_FAILED')); }
      if (result === closePromise) result = Promise.reject(failure('CLOSE_FAILED'));
      pending.push(Promise.resolve(result).then(() => {
        owned.state = 'CLOSED'; return true;
      }, () => {
        owned.state = 'CLOSE_FAILED'; return false;
      }));
    }
    Promise.all(pending).then(results => {
      if (results.some(result => !result)) {
        state = 'FAILED'; rejectClose(failure('CLOSE_FAILED'));
      } else {
        state = startupFailed ? 'FAILED' : 'CLOSED'; resolveClose();
      }
    });
    return closePromise;
  }

  async function start() {
    if (startAttempted || closing) throw failure('START_UNAVAILABLE');
    startAttempted = true;
    state = 'STARTING';
    const origins = Object.create(null);
    const returnedOrigins = new Set();
    try {
      for (const owned of services) {
        if (closing) throw failure('START_CANCELLED');
        owned.state = 'STARTING';
        const origin = await Promise.race([Promise.resolve(owned.listen(owned.port)), closeSignal]);
        if (closing || origin === CLOSED) throw failure('START_CANCELLED');
        origins[owned.name] = checkedOrigin(origin, owned.port, owned.expectedOrigin);
        if (returnedOrigins.has(origin)) throw failure('START_FAILED');
        returnedOrigins.add(origin);
        owned.state = 'STARTED';
      }
      if (closing) throw failure('START_CANCELLED');
      state = 'RUNNING';
      return Object.freeze({ origins: Object.freeze(origins) });
    } catch {
      const cancelled = closing;
      if (!cancelled) startupFailed = true;
      // Closure never awaits startup, so this rollback cannot form a cycle.
      // A genuinely non-settling adapter drain remains pending, without a
      // timeout, retry, or false claim that its side effects are complete.
      try { await close(); } catch { /* Closure status remains visible in snapshot. */ }
      throw failure(cancelled ? 'START_CANCELLED' : 'START_FAILED');
    }
  }

  function snapshot() {
    return Object.freeze({
      state,
      services: Object.freeze(services.map(({ name, state: serviceState }) => Object.freeze({ name, state: serviceState }))),
    });
  }

  return Object.freeze({ start, close, snapshot });
}
