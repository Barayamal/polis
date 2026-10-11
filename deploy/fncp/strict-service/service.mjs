/** Dedicated STRICT LOCAL composition, not a production/OIDC deployment.
 * No synthetic signer, token injector, model provider or test-client imports.
 * Adapters are trusted in-process operator inputs, never HTTP/config-file input.
 * Original local-only guards remain mandatory. No default provider or transport.
 */
import { randomBytes } from 'node:crypto';
import { isAbsolute } from 'node:path';
import { createControlledLocalAccess } from '../activation-foundation/controlled-access.mjs';
import { INTEGRATED_IDENTITY_MODE } from '../local-access/access-server.mjs';
import { createWordPressReceiver } from '../local-access/wordpress-receiver.mjs';
import { createLocalBrowser } from '../local-browser/browser-server.mjs';
import { createRegistrationIssuer } from '../wordpress-identity/registration-issuer.mjs';
import { createServerRegistrationBridge } from '../wordpress-identity/server-registration.mjs';
import { createServiceSupervisor } from './supervisor.mjs';

export const STRICT_SERVICE_MODE = 'STRICT_LOCAL_ONLY';
const fail = () => new Error('Strict local service configuration rejected; KEEP_CLOSED.');
const required = (value) => { if (!value) throw fail(); };
const opaque = /^[A-Za-z0-9_-]{32,512}$/u;
const routes = new Map([['/health', 'GET'], ['/invitations/redeem', 'POST'],
  ['/polis/participation-init', 'GET'], ['/polis/next-comment', 'GET'],
  ['/polis/votes', 'POST'], ['/session/logout', 'POST']]);
function shape(value, requiredKeys, optional = []) {
  required(value && typeof value === 'object' && !Array.isArray(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value)) &&
    Reflect.ownKeys(value).every(key => typeof key === 'string' && [...requiredKeys, ...optional].includes(key)) &&
    requiredKeys.every(key => Object.hasOwn(value, key)) &&
    Object.values(Object.getOwnPropertyDescriptors(value)).every(descriptor => Object.hasOwn(descriptor, 'value')));
}
function methods(object, names) {
  required(object && names.every(name => typeof object[name] === 'function'));
  return Object.freeze(Object.fromEntries(names.map(name => [name, object[name].bind(object)])));
}
function ownData(object, key) {
  required(object && typeof object === 'object');
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  required(descriptor && Object.hasOwn(descriptor, 'value'));
  return descriptor.value;
}
function driverMethods(driver) {
  return Object.freeze(Object.fromEntries(['begin', 'complete', 'discard'].map(name => {
    const method = ownData(driver, name); required(typeof method === 'function');
    return [name, method.bind(driver)];
  })));
}
function storagePath(path) {
  required(typeof path === 'string' && (path === ':memory:' ||
    (isAbsolute(path) && path.endsWith('.sqlite') && !/[\u0000-\u001f\u007f]/u.test(path))));
}

/** Constructs, but does not listen. Caller owns explicit store paths and adapters.
 * For tests use two :memory: stores. Existing store/key custody is not invented.
 * The returned operator object is private process authority, never a web API.
 */
export async function createStrictLocalService(options) {
  let settings;
  try {
    shape(options, ['mode', 'identity', 'oidcDriver', 'provider', 'activation', 'storage', 'eventSecret'], ['ports', 'now', 'registration', 'httpsRedirect']);
    required(options.mode === STRICT_SERVICE_MODE);
    shape(options.storage, ['access', 'activation']);
    storagePath(options.storage.access); storagePath(options.storage.activation);
    shape(options.activation, ['binding', 'publicKey', 'keyId']);
    const binding = structuredClone(options.activation.binding);
    const identity = methods(options.identity, ['isVerifiedPrincipal', 'principalDeadline', 'participantXid']);
    required(ownData(options.oidcDriver, 'mode') === 'SYNTHETIC_ONLY');
    const driver = driverMethods(options.oidcDriver);
    const providerMethods = methods(options.provider, ['allowlist', 'participate']);
    required(options.provider.conversationId === binding.conversationId);
    const providerSource = options.provider;
    let providerDrift = false;
    const assertProviderBinding = (afterCall = false) => {
      let matches = false;
      try { matches = !providerDrift && providerSource.conversationId === binding.conversationId; } catch { /* Invalid metadata fails closed. */ }
      if (matches) return;
      providerDrift = true;
      try { app?.closeAuthority(); } catch { /* Denial stays latched even if ledger closure fails. */ }
      throw new Error(afterCall ? 'Provider binding outcome unconfirmed; KEEP_CLOSED.' : 'Provider binding drift; KEEP_CLOSED.');
    };
    const provider = Object.freeze({ conversationId: binding.conversationId,
      ...Object.fromEntries(['allowlist', 'participate'].map(name => [name, async (...args) => {
        assertProviderBinding();
        // A post-call mismatch cannot undo a side effect. Withhold the result;
        // never retry automatically or describe it as definitely unapplied.
        try { return await providerMethods[name](...args); }
        finally { assertProviderBinding(true); }
      }])) });
    required(typeof options.eventSecret === 'string' && opaque.test(options.eventSecret));
    required(![options.provider.gatewaySecret, options.provider.providerSecret].includes(options.eventSecret));
    const ports = options.ports ?? { access: 0, receiver: 0, browser: 0 };
    shape(ports, ['access', 'receiver', 'browser']);
    const values = Object.values(ports);
    required(values.every(port => Number.isInteger(port) && port >= 0 && port <= 65535));
    required(new Set(values.filter(Boolean)).size === values.filter(Boolean).length);
    let httpsRedirect; let driverMetadata;
    if (options.httpsRedirect !== undefined) {
      shape(options.httpsRedirect, ['mode', 'origin', 'key', 'cert']);
      const tls = options.httpsRedirect;
      required(tls.mode === 'SYNTHETIC_HTTPS_REDIRECT' && ports.browser > 0
        && typeof tls.origin === 'string' && tls.origin === `https://browser.example.invalid:${ports.browser}`
        && new URL(tls.origin).origin === tls.origin);
      required(Buffer.isBuffer(tls.key) && Buffer.isBuffer(tls.cert)
        && [tls.key, tls.cert].every(value => value.length > 0 && value.length <= 65536));
      shape(options.oidcDriver, ['mode', 'transport', 'authorizationEndpoint', 'callbackUri', 'begin', 'complete', 'discard'], ['isVerifiedPrincipal']);
      const transport = ownData(options.oidcDriver, 'transport');
      const authorizationEndpoint = ownData(options.oidcDriver, 'authorizationEndpoint');
      const callbackUri = ownData(options.oidcDriver, 'callbackUri');
      required(transport === 'HTTPS_REDIRECT_LAB' && typeof authorizationEndpoint === 'string'
        && authorizationEndpoint.length <= 2048 && callbackUri === tls.origin + '/oidc/callback');
      const authorization = new URL(authorizationEndpoint);
      required(authorization.protocol === 'https:' && authorization.hostname.endsWith('.invalid')
        && authorization.hostname !== '.invalid' && authorization.hostname !== 'browser.example.invalid'
        && !authorization.username && !authorization.password && !authorization.search && !authorization.hash
        && !/[?#]/u.test(authorizationEndpoint)
        && authorization.href === authorizationEndpoint);
      driverMetadata = Object.freeze({ transport, authorizationEndpoint, callbackUri });
      httpsRedirect = Object.freeze({ mode: tls.mode, origin: tls.origin, key: Buffer.from(tls.key), cert: Buffer.from(tls.cert) });
    } else {
      // Redirect transport must never silently fall back to an HTTP listener.
      const transport = Object.getOwnPropertyDescriptor(options.oidcDriver, 'transport');
      required(!transport || Object.hasOwn(transport, 'value') && transport.value === undefined);
    }
    const now = options.now ?? Date.now;
    required(typeof now === 'function');
    const instant = now(); required(Number.isSafeInteger(instant) && instant >= 0);
    let registration;
    if (options.registration !== undefined) {
      shape(options.registration, ['challengeSecret', 'registrationSecret', 'fetch']);
      registration = { ...options.registration };
      required(typeof registration.fetch === 'function');
      required([registration.challengeSecret, registration.registrationSecret].every(secret =>
        typeof secret === 'string' && /^[A-Za-z0-9_-]{43}$/u.test(secret)));
      required(new Set([registration.challengeSecret, registration.registrationSecret, options.eventSecret,
        options.provider.gatewaySecret, options.provider.providerSecret].filter(value => value !== undefined)).size ===
        [registration.challengeSecret, registration.registrationSecret, options.eventSecret,
          options.provider.gatewaySecret, options.provider.providerSecret].filter(value => value !== undefined).length);
    }
    settings = { identity, driver, driverMetadata, httpsRedirect, binding, provider,
      activation: { publicKey: options.activation.publicKey, keyId: options.activation.keyId },
      storage: { ...options.storage }, eventSecret: options.eventSecret, ports: { ...ports }, now, registration };
  } catch { throw fail(); }

  let app; let receiver; let browser; let supervisor; let apiOrigin;
  try {
    // Never persisted, logged or returned. strict-service HTTP cannot use this
    // secret to invoke test administration; only the private operator can.
    const adminSecret = randomBytes(32).toString('base64url');
    app = createControlledLocalAccess({ mode: 'fixture-only', httpProfile: 'strict-service',
      identityMode: INTEGRATED_IDENTITY_MODE, identityFoundation: settings.identity,
      dbPath: settings.storage.access, adminSecret, conversationId: settings.binding.conversationId,
      provider: settings.provider, now: settings.now, activation: { mode: 'SYNTHETIC_ONLY',
        ...settings.activation, binding: settings.binding, ledgerPath: settings.storage.activation, now: settings.now } });
    required(app.operator);
    const backend = Object.freeze({
      async request(path, body, credential) {
        const method = routes.get(path);
        if (!apiOrigin || !method || (method === 'GET' ? body !== undefined : body === undefined) ||
            credential !== undefined && !opaque.test(credential)) throw new Error('Private backend operation rejected.');
        const response = await fetch(apiOrigin + path, { method, redirect: 'error', signal: AbortSignal.timeout(11000),
          headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
            ...(credential ? { Authorization: 'Bearer ' + credential } : {}) },
          ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
        let size = 0; const chunks = [];
        for await (const chunk of response.body ?? []) {
          size += chunk.length; if (size > 512 * 1024) throw new Error('Private backend response rejected.');
          chunks.push(chunk);
        }
        return { status: response.status, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) };
      },
      authenticateIdentity: principal => app.authenticateIdentity(principal),
    });
    // The access authority and BFF both check the SAME foundation instance.
    // A driver's own boolean or a serialized/look-alike principal is not proof.
    const oidcDriver = Object.freeze({ mode: 'SYNTHETIC_ONLY', ...settings.driverMetadata,
      begin: input => settings.driver.begin(input),
      complete: input => settings.driver.complete(input),
      discard: input => settings.driver.discard(input),
      isVerifiedPrincipal: principal => settings.identity.isVerifiedPrincipal(principal) === true });
    const registrationIssuer = settings.registration ? createRegistrationIssuer({ mode: 'SYNTHETIC_ONLY',
      challengeSecret: settings.registration.challengeSecret, registrationSecret: settings.registration.registrationSecret,
      registrationIdentity: principal => app.registrationIdentity(principal),
      principalDeadline: principal => settings.identity.principalDeadline(principal), now: settings.now }) : undefined;
    const registrationBridge = registrationIssuer ? createServerRegistrationBridge({ registrationIssuer,
      fetchImpl: settings.registration.fetch, now: settings.now }) : undefined;
    receiver = createWordPressReceiver({ mode: 'fixture-only', secret: settings.eventSecret,
      ingest: event => app.ingestWordPressEvent(event), now: settings.now });
    browser = createLocalBrowser({ mode: 'fixture-only', backend, oidcDriver, registrationIssuer, registrationBridge,
      now: settings.now, ...(settings.httpsRedirect ? { httpsRedirect: settings.httpsRedirect } : {}) });
    supervisor = createServiceSupervisor({
      services: [
        { name: 'access', service: { async listen(port) { const origin = await app.listen(port); apiOrigin = origin; return origin; },
          close: () => app.close() }, port: settings.ports.access },
        { name: 'receiver', service: receiver, port: settings.ports.receiver },
        { name: 'browser', service: browser, port: settings.ports.browser,
          ...(settings.httpsRedirect ? { expectedOrigin: settings.httpsRedirect.origin } : {}) },
      ],
      closeAuthority: () => app.closeAuthority(),
    });
    const running = () => {
      if (supervisor.snapshot().state !== 'RUNNING') throw new Error('Strict local service is not running.');
    };
    return Object.freeze({
      start: () => supervisor.start(),
      close: () => supervisor.close(),
      snapshot: () => Object.freeze({ mode: STRICT_SERVICE_MODE, productionReady: false,
        realIdentityEnabled: false, realEmailEnabled: false, httpTestAdministration: false,
        ...supervisor.snapshot() }),
      operator: Object.freeze({
        status(...args) { running(); return app.operator.status(...args); },
        setRoundOpen(...args) { running(); return app.operator.setRoundOpen(...args); },
        issueInvitation(...args) { running(); return app.operator.issueInvitation(...args); },
        activationBinding() { running(); return app.activationBinding(); },
        nextActivationSequence() { running(); return app.nextActivationSequence(); },
        activate(envelope) { running(); return app.activate(envelope); },
        closeAuthority() { running(); return app.closeAuthority(); },
      }),
    });
  } catch {
    // No store deletion on failed construction: caller owns the explicit paths.
    let clean = true;
    for (const service of [browser, receiver, app]) {
      try { if (service) await service.close(); } catch { clean = false; }
    }
    throw new Error(clean ? 'Strict local service setup failed; KEEP_CLOSED.' :
      'Strict local service setup/cleanup unconfirmed; retain stores; KEEP_CLOSED.');
  }
}
