import { createHash, createHmac } from 'node:crypto';
import { isProxy } from 'node:util/types';

// This profile is intentionally incapable of production authentication,
// participant admission or provider operations. Do not adopt its test stores.
export const FOUNDATION_PROFILE = 'FNCP_NATIVE_STORE_FOUNDATION_V1';
export const FOUNDATION_MODE = 'SYNTHETIC_ONLY';
export const LIFETIME_CAPACITY = 20;
export const SHA256 = /^[a-f0-9]{64}$/u;
export const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;

export class NativeFoundationError extends Error {
  constructor(code = 'foundation_closed', faultPersistenceVerified = false) {
    super(code);
    this.name = 'NativeFoundationError';
    this.code = code;
    this.faultPersistenceVerified = faultPersistenceVerified;
  }
}
export const reject = (code = 'foundation_input_rejected') => { throw new NativeFoundationError(code); };

export function exactRecord(value, required, optional = []) {
  if (!value || typeof value !== 'object' || isProxy(value)
    || Object.getPrototypeOf(value) !== Object.prototype) reject();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.some(k => typeof k !== 'string' || ![...required, ...optional].includes(k))
    || Object.values(descriptors).some(d => !Object.hasOwn(d, 'value'))
    || required.some(k => !Object.hasOwn(descriptors, k))) reject();
  return value;
}

export function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isSafeInteger(value)) return String(value);
  if (Array.isArray(value)) {
    if (isProxy(value) || Object.getPrototypeOf(value) !== Array.prototype
      || Object.keys(value).length !== value.length
      || Reflect.ownKeys(value).length !== value.length + 1
      || Object.values(Object.getOwnPropertyDescriptors(value)).some(d => !Object.hasOwn(d, 'value'))) reject();
    return '[' + value.map(canonical).join(',') + ']';
  }
  if (!value || typeof value !== 'object' || isProxy(value)
    || Object.getPrototypeOf(value) !== Object.prototype) reject();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).some(k => typeof k !== 'string')
    || Object.values(descriptors).some(d => !Object.hasOwn(d, 'value'))) reject();
  return '{' + Object.keys(descriptors).sort().map(k => JSON.stringify(k) + ':' + canonical(descriptors[k].value)).join(',') + '}';
}
export const sha256 = text => createHash('sha256').update(text).digest('hex');
export const deriveOpaque = (key, domain, value) => createHmac('sha256', Buffer.from(key, 'hex'))
  .update(canonical({ domain, value })).digest('hex');
export const validTime = value => Number.isSafeInteger(value) && value >= 0;

export function validateConfiguration(value) {
  exactRecord(value, ['profile', 'mode', 'deploymentId', 'epochId', 'consentVersion', 'notice', 'noticeSha256']);
  if (value.profile !== FOUNDATION_PROFILE || value.mode !== FOUNDATION_MODE
    || typeof value.deploymentId !== 'string' || !/^invented-[a-z0-9-]{3,64}$/u.test(value.deploymentId)
    || typeof value.epochId !== 'string' || !UUID.test(value.epochId)
    || typeof value.consentVersion !== 'string' || !/^native-synthetic-[a-z0-9-]{1,48}$/u.test(value.consentVersion)
    || typeof value.noticeSha256 !== 'string' || !SHA256.test(value.noticeSha256)) reject();
  exactRecord(value.notice, ['adultDeclaration', 'eligibilityDeclaration', 'registrationDeclaration']);
  if (Object.values(value.notice).some(v => typeof v !== 'string' || !v.trim() || v.length > 1000)
    || sha256(canonical(value.notice)) !== value.noticeSha256) reject();
  const copy = JSON.parse(canonical(value));
  Object.freeze(copy.notice);
  return Object.freeze(copy);
}

export function validateSyntheticIdentity(value, at) {
  exactRecord(value, ['subject', 'expiresAt']);
  if (typeof value.subject !== 'string' || !/^invented-participant-[a-z0-9-]{1,48}$/u.test(value.subject)
    || !validTime(value.expiresAt) || value.expiresAt <= at
    || value.expiresAt - at > 900_000) reject('synthetic_identity_rejected');
  return value;
}

export function validateConsent(value, configuration) {
  exactRecord(value, ['consentVersion', 'noticeSha256', 'adultDeclaration', 'eligibilityDeclaration', 'registrationDeclaration']);
  if (value.consentVersion !== configuration.consentVersion || value.noticeSha256 !== configuration.noticeSha256
    || value.adultDeclaration !== true || value.eligibilityDeclaration !== true || value.registrationDeclaration !== true) reject('consent_rejected');
  return JSON.parse(canonical(value));
}

export function validateSyntheticDecision(value) {
  exactRecord(value, ['decisionId', 'registrationReference', 'kind', 'reviewer', 'expectedVersion']);
  if (typeof value.decisionId !== 'string' || !UUID.test(value.decisionId)
    || typeof value.registrationReference !== 'string' || !UUID.test(value.registrationReference)
    || !['approve', 'decline', 'revoke'].includes(value.kind)
    || typeof value.reviewer !== 'string' || !/^invented-reviewer-[a-z0-9-]{1,48}$/u.test(value.reviewer)
    || !Number.isSafeInteger(value.expectedVersion) || value.expectedVersion < 0 || value.expectedVersion > 2) reject('decision_rejected');
  return value;
}
