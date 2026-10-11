/** Binds original branded public API trust to the one fixed compiled child
 * owner. No I/O on import, arbitrary loader, executable or environment fallback.
 * Importing that reviewed owner is NOT image/resource attestation. Its fresh
 * child, not this bridge, owns application exit; DB/container ownership remain
 * separate. configuration() is a private handoff, not aggregate evidence.
 */
import { isProxy, isPromise } from 'node:util/types';
import { claimBootstrapApiTrust } from './bootstrap-api-trust.mjs';

const OWNER_URL = new URL('../../../server/dist/src/bootstrap/child-owner.js', import.meta.url);
const failure = () => new Error('Fresh bootstrap API process rejected; private details withheld.');
const add = EventTarget.prototype.addEventListener;
const remove = EventTarget.prototype.removeEventListener;
function plain(value) {
  return !!value && typeof value === 'object' && !isProxy(value) && Object.getPrototypeOf(value) === Object.prototype;
}
function fields(value, keys) {
  if (!plain(value)) throw failure();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).length !== keys.length || keys.some(key => !Object.hasOwn(descriptors, key) ||
      !Object.hasOwn(descriptors[key], 'value'))) throw failure();
  return Object.fromEntries(keys.map(key => [key, descriptors[key].value]));
}
function environmentSnapshot(value) {
  if (!plain(value)) throw failure();
  const descriptors = Object.getOwnPropertyDescriptors(value); const keys = Reflect.ownKeys(descriptors);
  if (keys.length !== 33 || keys.some(key => typeof key !== 'string')) throw failure();
  const copy = {};
  for (const key of keys) {
    const field = descriptors[key];
    if (!Object.hasOwn(field, 'value') || typeof field.value !== 'string' || field.value.length < 1 ||
        field.value.length > 1024 || /[\0\r\n]/u.test(field.value) || key === '__proto__') throw failure();
    copy[key] = field.value;
  }
  // Exact field names, fixed locale/path and profile coherence are validated by
  // the fixed owner's pure child-profile module before any fork. Snapshot now
  // so caller mutation across the dynamic-import await cannot change its input.
  return Object.freeze(copy);
}
function ownerSummary(owner) {
  const summary = fields(owner.summary(), ['spawnAttempted', 'ready', 'closed', 'failed', 'childExitVerified',
    'ipcDisconnected', 'listenerClosureVerified', 'exitCode', 'signalCode', 'databaseOwnershipVerified',
    'containerOwnershipVerified', 'activationGranted']);
  if (['spawnAttempted', 'ready', 'closed', 'failed', 'childExitVerified', 'ipcDisconnected', 'listenerClosureVerified']
      .some(key => typeof summary[key] !== 'boolean') ||
      !(summary.exitCode === null || (Number.isSafeInteger(summary.exitCode) && summary.exitCode >= 0 && summary.exitCode <= 255)) ||
      !(summary.signalCode === null || ['SIGTERM', 'SIGKILL', 'SIGINT', 'SIGABRT', 'SIGSEGV', 'SIGBUS', 'SIGILL', 'SIGTRAP', 'SIGFPE', 'SIGHUP', 'SIGQUIT', 'SIGPIPE', 'SIGALRM'].includes(summary.signalCode)) ||
      summary.databaseOwnershipVerified !== false || summary.containerOwnershipVerified !== false || summary.activationGranted !== false) throw failure();
  return Object.freeze(summary);
}
function privateConfiguration(owner) {
  const value = fields(owner.configuration(), ['origin', 'certificatePem', 'certificateSha256']);
  if (typeof value.origin !== 'string' || !/^https:\/\/127\.0\.0\.1:[1-9][0-9]{3,4}$/u.test(value.origin) ||
      Number(new URL(value.origin).port) < 1024 || Number(new URL(value.origin).port) > 65535 ||
      typeof value.certificatePem !== 'string' || Buffer.byteLength(value.certificatePem) > 8192 ||
      !/^-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+\n-----END CERTIFICATE-----\n?$/u.test(value.certificatePem) ||
      typeof value.certificateSha256 !== 'string' || !/^[a-f0-9]{64}$/u.test(value.certificateSha256)) throw failure();
  return Object.freeze(value);
}

export async function createBootstrapApiProcess(options) {
  let original, owner, cleanup, ownerPending, watch, closePromise;
  let closed = false, failed = false, imported = false, creationAttempted = false, closureAcknowledged = false;
  const rawActive = () => {
    if (closed) throw failure();
    original.assertActive();
    if (owner) {
      const summary = ownerSummary(owner);
      if (!summary.ready || summary.closed || summary.failed) throw failure();
    }
    original.assertActive();
  };
  const onAbort = () => { failed = true; void close().catch(() => {}); };
  function close() {
    if (arguments.length) return Promise.reject(failure());
    if (closePromise) return closePromise;
    closed = true; clearInterval(watch);
    if (original) remove.call(original.signal, 'abort', onAbort);
    closePromise = Promise.resolve().then(async () => {
      // Never report closure while a dispatched owner factory can still return
      // a live child. The real fixed owner is bounded. If a trusted factory
      // never settles, this remains uncertain/pending rather than pretending
      // that cancellation undid its side effects.
      if (ownerPending) await ownerPending.catch(() => {});
      if (cleanup) {
        const completion = cleanup();
        if (!isPromise(completion)) throw failure();
        await completion; closureAcknowledged = true;
      }
    }).catch(() => { failed = true; throw failure(); });
    return closePromise;
  }
  const assertActive = function () {
    if (arguments.length) throw failure();
    try { rawActive(); }
    catch { onAbort(); throw failure(); }
  };
  try {
    if (arguments.length !== 1) throw failure();
    const input = fields(options, ['trust', 'environment']);
    const environment = environmentSnapshot(input.environment);
    original = claimBootstrapApiTrust(input.trust);
    rawActive();
    add.call(original.signal, 'abort', onAbort, { once: true });
    rawActive();
    watch = setInterval(() => {
      try { rawActive(); } catch { onAbort(); }
    }, 25);
    watch.unref();
    const module = await import(OWNER_URL.href);
    rawActive(); imported = true;
    const factory = module.createBootstrapChildOwner;
    if (typeof factory !== 'function' || isProxy(factory)) throw failure();
    const publicTrust = Object.freeze({ issuer: original.issuer, publicJwk: original.publicJwk,
      seedStatementsJson: original.seedStatementsJson });
    ownerPending = Promise.resolve().then(() => {
      rawActive(); creationAttempted = true;
      return factory(Object.freeze({ environment, trust: publicTrust, signal: original.signal }));
    }).then(value => {
      // Capture a safe own close method even when another return field is bad,
      // so a malformed trusted factory return does not strand its known child.
      if (plain(value)) {
        const method = Object.getOwnPropertyDescriptor(value, 'close');
        if (method && Object.hasOwn(method, 'value') && typeof method.value === 'function' && !isProxy(method.value))
          cleanup = () => Reflect.apply(method.value, value, []);
      }
      const candidate = fields(value, ['configuration', 'close', 'summary']);
      if (Object.values(candidate).some(method => typeof method !== 'function' || isProxy(method))) throw failure();
      owner = Object.freeze({ configuration: () => Reflect.apply(candidate.configuration, value, []),
        summary: () => Reflect.apply(candidate.summary, value, []) });
      return owner;
    });
    await ownerPending;
    rawActive(); privateConfiguration(owner); rawActive();
    return Object.freeze({
      configuration() {
        if (arguments.length) throw failure();
        try { rawActive(); const config = privateConfiguration(owner); rawActive(); return config; }
        catch { onAbort(); throw failure(); }
      },
      assertActive,
      close,
      summary() {
        if (arguments.length) throw failure();
        try {
          return Object.freeze({ classification: 'ORIGINAL_ISSUER_BOUND_API_CHILD_BRIDGE', imported,
            ownerCreationAttempted: creationAttempted, closed, failed, ownerClosureAcknowledged: closureAcknowledged,
            activityWatchActive: !!watch && !closed, tokensMintedByBridge: 0, issuerOwnershipClaimed: false,
            imageAttestationVerified: false, databaseOwnershipVerified: false, containerOwnershipVerified: false,
            activationGranted: false, owner: owner ? ownerSummary(owner) : null });
        } catch { onAbort(); throw failure(); }
      },
    });
  } catch {
    failed = true; await close().catch(() => {}); throw failure();
  }
}
