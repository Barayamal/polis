import test from 'node:test';
import assert from 'node:assert/strict';
import { createServiceSupervisor } from './supervisor.mjs';

function deferred() {
  let resolve; let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function fixture(overrides = {}) {
  const events = [];
  const services = ['access', 'receiver', 'browser'].map((name, index) => ({
    name,
    port: 22001 + index,
    service: {
      listen(port) { events.push(`listen:${name}:${port}`); return `http://127.0.0.1:${port}`; },
      close() { events.push(`close:${name}`); },
    },
  }));
  const config = { services, closeAuthority() { events.push('authority:close'); }, ...overrides };
  return { events, services: config.services, config };
}

function errorCode(code) {
  return error => {
    assert.equal(error.code, code);
    assert.equal(error.cause, undefined);
    assert.doesNotMatch(error.message, /SECRET|PRIVATE|127\.0\.0\.1|https?:|password/i);
    return true;
  };
}

test('sequential start returns private immutable origins only after every service starts', async () => {
  const f = fixture();
  const first = deferred(); const last = deferred();
  f.services[0].service.listen = port => { f.events.push(`listen:access:${port}`); return first.promise; };
  f.services[2].service.listen = port => { f.events.push(`listen:browser:${port}`); return last.promise; };
  const owner = createServiceSupervisor(f.config);
  assert.equal(owner.snapshot().state, 'CREATED');
  const starting = owner.start();
  assert.deepEqual(f.events, ['listen:access:22001']);
  first.resolve('http://127.0.0.1:22001');
  await Promise.resolve(); await Promise.resolve(); await Promise.resolve(); await Promise.resolve();
  assert.deepEqual(f.events, ['listen:access:22001', 'listen:receiver:22002', 'listen:browser:22003']);
  assert.equal(owner.snapshot().state, 'STARTING');
  last.resolve('http://127.0.0.1:22003');
  const result = await starting;
  assert.equal(owner.snapshot().state, 'RUNNING');
  assert.deepEqual({ ...result.origins }, { access: 'http://127.0.0.1:22001', receiver: 'http://127.0.0.1:22002', browser: 'http://127.0.0.1:22003' });
  assert.equal(Object.getPrototypeOf(result.origins), null);
  assert.ok(Object.isFrozen(result)); assert.ok(Object.isFrozen(result.origins));
  await owner.close();
});

test('close synchronously revokes authority and invokes every close in reverse order', async () => {
  const f = fixture(); const drains = [deferred(), deferred(), deferred()];
  for (const [index, owned] of f.services.entries()) owned.service.close = () => {
    f.events.push(`close:${owned.name}`); return drains[index].promise;
  };
  const owner = createServiceSupervisor(f.config);
  await owner.start(); f.events.length = 0;
  const closing = owner.close();
  assert.deepEqual(f.events, ['authority:close', 'close:browser', 'close:receiver', 'close:access']);
  assert.equal(owner.snapshot().state, 'CLOSING');
  assert.equal(owner.close(), closing);
  for (const drain of drains) drain.resolve();
  await closing;
  assert.equal(owner.snapshot().state, 'CLOSED');
  assert.equal(owner.close(), closing);
  assert.equal(f.events.filter(value => value === 'authority:close').length, 1);
});

test('close before start owns and closes unstarted services and permanently rejects startup', async () => {
  const f = fixture(); const owner = createServiceSupervisor(f.config);
  const closing = owner.close();
  await assert.rejects(owner.start(), errorCode('START_UNAVAILABLE'));
  await closing;
  assert.deepEqual(f.events, ['authority:close', 'close:browser', 'close:receiver', 'close:access']);
  await assert.rejects(owner.start(), errorCode('START_UNAVAILABLE'));
});

test('duplicate start during startup rejects without repeating a listener', async () => {
  const f = fixture(); const gate = deferred();
  f.services[0].service.listen = () => { f.events.push('listen:access'); return gate.promise; };
  const owner = createServiceSupervisor(f.config); const starting = owner.start();
  await assert.rejects(owner.start(), errorCode('START_UNAVAILABLE'));
  gate.resolve('http://127.0.0.1:22001');
  await starting;
  assert.equal(f.events.filter(value => value === 'listen:access').length, 1);
  await assert.rejects(owner.start(), errorCode('START_UNAVAILABLE'));
  await owner.close();
});

test('close cancels a pending listen even if that listen ignores cancellation', async () => {
  const f = fixture(); const gate = deferred();
  f.services[0].service.listen = () => { f.events.push('listen:access'); return gate.promise; };
  const owner = createServiceSupervisor(f.config); const starting = owner.start();
  const rejected = assert.rejects(starting, errorCode('START_CANCELLED'));
  const closing = owner.close();
  await Promise.all([rejected, closing]);
  gate.reject(new Error('SECRET late listener failure'));
  await Promise.resolve();
  assert.deepEqual(f.events, ['listen:access', 'authority:close', 'close:browser', 'close:receiver', 'close:access']);
  assert.equal(owner.snapshot().state, 'CLOSED');
});

test('closure while a listen resolves prevents the next listener and private origins result', async () => {
  const f = fixture(); const gate = deferred();
  f.services[0].service.listen = () => { f.events.push('listen:access'); return gate.promise; };
  const owner = createServiceSupervisor(f.config); const starting = owner.start();
  const rejected = assert.rejects(starting, errorCode('START_CANCELLED'));
  gate.resolve('http://127.0.0.1:22001');
  await owner.close(); await rejected;
  assert.ok(!f.events.some(value => value.startsWith('listen:receiver')));
});

for (const kind of ['sync', 'async']) {
  test(`${kind} startup failure rolls back all constructed services and sanitizes errors`, async () => {
    const f = fixture();
    f.services[1].service.listen = () => {
      f.events.push('listen:receiver');
      if (kind === 'sync') throw new Error('SECRET https://PRIVATE password');
      return Promise.reject(new Error('SECRET https://PRIVATE password'));
    };
    const owner = createServiceSupervisor(f.config);
    await assert.rejects(owner.start(), errorCode('START_FAILED'));
    assert.deepEqual(f.events, ['listen:access:22001', 'listen:receiver', 'authority:close', 'close:browser', 'close:receiver', 'close:access']);
    assert.equal(owner.snapshot().state, 'FAILED');
    assert.ok(owner.snapshot().services.every(service => service.state === 'CLOSED'));
    await assert.rejects(owner.start(), errorCode('START_UNAVAILABLE'));
    await owner.close();
  });
}

test('startup rollback waits for real service drains without reporting early completion', async () => {
  const f = fixture(); const drain = deferred();
  f.services[1].service.listen = () => { throw new Error('SECRET'); };
  f.services[2].service.close = () => drain.promise;
  const owner = createServiceSupervisor(f.config); let settled = false;
  const rejected = assert.rejects(owner.start(), errorCode('START_FAILED')).then(() => { settled = true; });
  await Promise.resolve(); await Promise.resolve(); await Promise.resolve();
  assert.equal(owner.snapshot().state, 'CLOSING'); assert.equal(settled, false);
  drain.resolve(); await rejected;
  assert.equal(owner.snapshot().state, 'FAILED');
});

test('a failing close does not suppress later close attempts or leak the adapter error', async () => {
  const f = fixture();
  f.services[2].service.close = () => { f.events.push('close:browser'); throw new Error('SECRET PRIVATE'); };
  f.services[1].service.close = () => { f.events.push('close:receiver'); return Promise.reject(new Error('SECRET PRIVATE')); };
  const owner = createServiceSupervisor(f.config);
  await assert.rejects(owner.close(), errorCode('CLOSE_FAILED'));
  assert.deepEqual(f.events, ['authority:close', 'close:browser', 'close:receiver', 'close:access']);
  assert.equal(owner.snapshot().state, 'FAILED');
  assert.deepEqual(owner.snapshot().services.map(service => service.state), ['CLOSED', 'CLOSE_FAILED', 'CLOSE_FAILED']);
});

for (const kind of ['sync', 'async']) {
  test(`${kind} authority closure failure still closes every service once`, async () => {
    const f = fixture();
    f.config.closeAuthority = () => {
      f.events.push('authority:close');
      if (kind === 'sync') throw new Error('SECRET PRIVATE');
      return Promise.reject(new Error('SECRET PRIVATE'));
    };
    const owner = createServiceSupervisor(f.config); const closing = owner.close();
    assert.equal(owner.close(), closing);
    await assert.rejects(closing, errorCode('CLOSE_FAILED'));
    assert.deepEqual(f.events, ['authority:close', 'close:browser', 'close:receiver', 'close:access']);
    assert.ok(owner.snapshot().services.every(service => service.state === 'CLOSED'));
  });
}

test('startup error remains sanitized when rollback itself fails', async () => {
  const f = fixture();
  f.services[0].service.listen = () => { throw new Error('SECRET START'); };
  f.services[2].service.close = () => { throw new Error('SECRET CLOSE'); };
  const owner = createServiceSupervisor(f.config);
  await assert.rejects(owner.start(), errorCode('START_FAILED'));
  await assert.rejects(owner.close(), errorCode('CLOSE_FAILED'));
  assert.equal(owner.snapshot().state, 'FAILED');
});

test('re-entrant close during authority closure shares the published promise', async () => {
  const f = fixture(); let owner; let nested;
  f.config.closeAuthority = () => { f.events.push('authority:close'); nested = owner.close(); };
  owner = createServiceSupervisor(f.config);
  const closing = owner.close();
  assert.equal(closing, nested); await closing;
  assert.equal(f.events.filter(value => value === 'authority:close').length, 1);
});

for (const source of ['authority', 'service']) {
  test(`direct ${source} self-wait is refused instead of deadlocking the close promise`, async () => {
    const f = fixture(); let owner;
    if (source === 'authority') f.config.closeAuthority = () => owner.close();
    else f.services[2].service.close = () => owner.close();
    owner = createServiceSupervisor(f.config);
    await assert.rejects(owner.close(), errorCode('CLOSE_FAILED'));
    assert.equal(owner.snapshot().state, 'FAILED');
  });
}

test('reverse close invocation is not serialized behind an earlier drain dependency', async () => {
  const f = fixture(); const dependency = deferred();
  f.services[2].service.close = () => { f.events.push('close:browser'); return dependency.promise; };
  f.services[0].service.close = () => { f.events.push('close:access'); dependency.resolve(); };
  const owner = createServiceSupervisor(f.config); await owner.close();
  assert.equal(owner.snapshot().state, 'CLOSED');
  assert.deepEqual(f.events, ['authority:close', 'close:browser', 'close:receiver', 'close:access']);
});

test('snapshots are immutable, bounded lifecycle-only copies without origins or configuration', async () => {
  const f = fixture(); f.services[0].service.secret = 'SECRET';
  const owner = createServiceSupervisor(f.config); const before = owner.snapshot();
  assert.deepEqual(Object.keys(before).sort(), ['services', 'state']);
  assert.ok(Object.isFrozen(owner)); assert.ok(Object.isFrozen(before));
  assert.ok(Object.isFrozen(before.services)); assert.ok(before.services.every(Object.isFrozen));
  await owner.start(); const during = owner.snapshot();
  assert.equal(before.state, 'CREATED'); assert.equal(during.state, 'RUNNING');
  assert.doesNotMatch(JSON.stringify(during), /SECRET|22001|127\.0\.0\.1|http/);
  assert.deepEqual(Object.keys(during.services[0]).sort(), ['name', 'state']);
  await owner.close();
});

test('construction captures ports, services, methods, and authority before caller mutation', async () => {
  const f = fixture(); const owner = createServiceSupervisor(f.config);
  f.services[0].port = 65500; f.services[0].name = 'changed';
  f.services[0].service.listen = () => { throw new Error('SECRET replacement'); };
  f.services[0].service.close = () => { throw new Error('SECRET replacement'); };
  f.services.reverse(); f.config.closeAuthority = () => { throw new Error('SECRET replacement'); };
  const result = await owner.start(); await owner.close();
  assert.equal(result.origins.access, 'http://127.0.0.1:22001');
  assert.deepEqual(f.events, ['listen:access:22001', 'listen:receiver:22002', 'listen:browser:22003', 'authority:close', 'close:browser', 'close:receiver', 'close:access']);
});

test('method receiver binding is preserved', async () => {
  const service = { origin: 'http://127.0.0.1:22000', closed: false, listen() { return this.origin; }, close() { this.closed = true; } };
  const owner = createServiceSupervisor({ services: [{ name: 'bound', port: 22000, service }], closeAuthority() {} });
  assert.equal((await owner.start()).origins.bound, service.origin);
  await owner.close(); assert.equal(service.closed, true);
});

test('distinct port-zero adapters may return independently assigned loopback ports', async () => {
  const f = fixture();
  f.services.forEach((owned, index) => { owned.port = 0; owned.service.listen = () => `http://127.0.0.1:${23001 + index}`; });
  const owner = createServiceSupervisor(f.config); const result = await owner.start();
  assert.equal(result.origins.browser, 'http://127.0.0.1:23003'); await owner.close();
});

test('different adapter names cannot report the same ephemeral origin', async () => {
  const f = fixture();
  f.services.forEach(owned => { owned.port = 0; owned.service.listen = () => 'http://127.0.0.1:23000'; });
  const owner = createServiceSupervisor(f.config);
  await assert.rejects(owner.start(), errorCode('START_FAILED'));
  assert.equal(owner.snapshot().state, 'FAILED');
});

const invalidOrigins = [null, {}, '', 'https://127.0.0.1:22001', 'http://localhost:22001', 'http://0.0.0.0:22001', 'http://127.0.0.1:0', 'http://127.0.0.1:65536', 'http://127.0.0.1:022001', 'http://127.0.0.1:22001/', 'http://127.0.0.1:22001?SECRET', 'http://127.0.0.1:22002'];
for (const [index, origin] of invalidOrigins.entries()) {
  test(`invalid returned origin ${index + 1} rolls back without exposing that value`, async () => {
    const f = fixture(); f.services[0].service.listen = () => origin;
    const owner = createServiceSupervisor(f.config);
    await assert.rejects(owner.start(), errorCode('START_FAILED'));
    assert.deepEqual(f.events, ['authority:close', 'close:browser', 'close:receiver', 'close:access']);
  });
}

const invalidConfigs = [
  ['null config', () => null],
  ['extra config key', config => ({ ...config, secret: true })],
  ['missing authority', config => ({ services: config.services })],
  ['non-callable authority', config => ({ ...config, closeAuthority: true })],
  ['empty services', config => ({ ...config, services: [] })],
  ['non-array services', config => ({ ...config, services: {} })],
  ['too many services', config => ({ ...config, services: Array(9).fill(config.services[0]) })],
  ['sparse services', config => ({ ...config, services: Array(1) })],
  ['extra array key', config => { config.services.extra = true; return config; }],
  ['inherited array wrapper', config => { Object.setPrototypeOf(config.services, Object.create(Array.prototype)); return config; }],
  ['extra entry key', config => { config.services[0].extra = true; return config; }],
  ['missing entry port', config => { delete config.services[0].port; return config; }],
  ['invalid entry', config => { config.services[0] = null; return config; }],
  ['duplicate name', config => { config.services[1].name = config.services[0].name; return config; }],
  ['empty name', config => { config.services[0].name = ''; return config; }],
  ['unbounded name', config => { config.services[0].name = 'a'.repeat(33); return config; }],
  ['noncanonical name', config => { config.services[0].name = 'Access SECRET'; return config; }],
  ['reserved name', config => { config.services[0].name = 'constructor'; return config; }],
  ['nonstring name', config => { config.services[0].name = 1; return config; }],
  ['negative port', config => { config.services[0].port = -1; return config; }],
  ['oversized port', config => { config.services[0].port = 65536; return config; }],
  ['fractional port', config => { config.services[0].port = 1.5; return config; }],
  ['string port', config => { config.services[0].port = '22001'; return config; }],
  ['NaN port', config => { config.services[0].port = NaN; return config; }],
  ['duplicate bound port', config => { config.services[1].port = config.services[0].port; return config; }],
  ['duplicate service instance', config => { config.services[1].service = config.services[0].service; return config; }],
  ['missing listen', config => { delete config.services[0].service.listen; return config; }],
  ['missing close', config => { delete config.services[0].service.close; return config; }],
  ['inherited listen', config => { config.services[0].service = Object.create(config.services[0].service); return config; }],
  ['non-callable close', config => { config.services[0].service.close = true; return config; }],
  ['symbol key', config => { config[Symbol('extra')] = true; return config; }],
  ['inherited config', config => Object.create(config)],
];
for (const [label, change] of invalidConfigs) {
  test(`rejects ${label} before any lifecycle side effect`, () => {
    const f = fixture();
    assert.throws(() => createServiceSupervisor(change(f.config)), errorCode('INVALID_CONFIG'));
    assert.deepEqual(f.events, []);
  });
}

for (const target of ['config', 'entry', 'slot', 'listen', 'close']) {
  test(`rejects ${target} accessor without invoking it`, () => {
    const f = fixture(); let called = false;
    const accessor = { configurable: true, enumerable: true, get() { called = true; throw new Error('SECRET'); } };
    if (target === 'config') Object.defineProperty(f.config, 'closeAuthority', accessor);
    if (target === 'entry') Object.defineProperty(f.services[0], 'port', accessor);
    if (target === 'slot') Object.defineProperty(f.services, '0', accessor);
    if (target === 'listen' || target === 'close') Object.defineProperty(f.services[0].service, target, accessor);
    assert.throws(() => createServiceSupervisor(f.config), errorCode('INVALID_CONFIG'));
    assert.equal(called, false); assert.deepEqual(f.events, []);
  });
}

test('hostile configuration inspection failures are sanitized', () => {
  const config = new Proxy({}, { getPrototypeOf() { throw new Error('SECRET PRIVATE'); } });
  assert.throws(() => createServiceSupervisor(config), errorCode('INVALID_CONFIG'));
});

test('explicit HTTPS expected origin is admitted only for the configured fixed lab hostname and port', async () => {
  const f = fixture(); const browser = f.services[2];
  browser.expectedOrigin = 'https://browser.example.invalid:22003';
  browser.service.listen = () => browser.expectedOrigin;
  const owner = createServiceSupervisor(f.config);
  const result = await owner.start();
  assert.equal(result.origins.browser, 'https://browser.example.invalid:22003');
  assert.doesNotMatch(JSON.stringify(owner.snapshot()), /https:|example|22003/);
  await owner.close();
});

test('explicit HTTPS expectation is captured before caller mutation', async () => {
  const f = fixture(); const browser = f.services[2];
  browser.expectedOrigin = 'https://browser.example.invalid:22003';
  browser.service.listen = () => 'https://browser.example.invalid:22003';
  const owner = createServiceSupervisor(f.config);
  browser.expectedOrigin = 'https://PRIVATE.example.invalid:22003';
  const result = await owner.start();
  assert.equal(result.origins.browser, 'https://browser.example.invalid:22003');
  await owner.close();
});

for (const origin of ['http://127.0.0.1:22003', 'https://browser.example.invalid:22004', 'https://other.example.invalid:22003']) {
  test(`a mismatching HTTPS adapter result ${origin.startsWith('http:') ? 'downgrade' : origin.includes('other.') ? 'host' : 'port'} rolls back`, async () => {
    const f = fixture(); const browser = f.services[2];
    browser.expectedOrigin = 'https://browser.example.invalid:22003'; browser.service.listen = () => origin;
    const owner = createServiceSupervisor(f.config);
    await assert.rejects(owner.start(), errorCode('START_FAILED'));
    assert.ok(owner.snapshot().services.every(service => service.state === 'CLOSED'));
  });
}

test('HTTPS remains refused without explicit expectedOrigin opt-in', async () => {
  const f = fixture(); f.services[2].service.listen = () => 'https://browser.example.invalid:22003';
  const owner = createServiceSupervisor(f.config);
  await assert.rejects(owner.start(), errorCode('START_FAILED'));
});

for (const [label, value, port = 22003] of [
  ['undefined expectation', undefined], ['null expectation', null], ['HTTP expectation', 'http://127.0.0.1:22003'],
  ['wrong fixed host', 'https://other.example.invalid:22003'], ['mismatched port', 'https://browser.example.invalid:22004'],
  ['trailing slash', 'https://browser.example.invalid:22003/'], ['query', 'https://browser.example.invalid:22003?secret=PRIVATE'],
  ['fragment', 'https://browser.example.invalid:22003#PRIVATE'], ['userinfo', 'https://PRIVATE@browser.example.invalid:22003'],
  ['implicit port', 'https://browser.example.invalid'], ['default port', 'https://browser.example.invalid:443', 443],
  ['ephemeral port', 'https://browser.example.invalid:22003', 0], ['leading zero port', 'https://browser.example.invalid:022003'],
]) {
  test(`HTTPS config rejects ${label} before lifecycle side effects`, () => {
    const f = fixture(); f.services[2].port = port; f.services[2].expectedOrigin = value;
    assert.throws(() => createServiceSupervisor(f.config), errorCode('INVALID_CONFIG'));
    assert.deepEqual(f.events, []);
  });
}

test('HTTPS expectedOrigin getter is rejected without evaluation', () => {
  const f = fixture(); let called = 0;
  Object.defineProperty(f.services[2], 'expectedOrigin', { enumerable: true, get() { called++; return 'https://browser.example.invalid:22003'; } });
  assert.throws(() => createServiceSupervisor(f.config), errorCode('INVALID_CONFIG'));
  assert.equal(called, 0); assert.deepEqual(f.events, []);
});
