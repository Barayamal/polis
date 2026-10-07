export const PROFILE = 'FNCP_PRODUCTION_ACTIVATION_V1';
export const PURPOSE = PROFILE;
export const SIGNING_DOMAIN = 'Barayamal\0FNCP\0ProductionActivation\0v1\0';
export const IMAGE_ROLES = Object.freeze(['api', 'math', 'postgres', 'participant', 'wordpress', 'mariadb', 'proxy', 'migration']);
export const IMAGE_ROLES_V2 = Object.freeze([...IMAGE_ROLES, 'edge']);
export const IMAGE_ROLES_V3 = Object.freeze([...IMAGE_ROLES_V2, 'operator']);
export function activationProtocol(binding) {
  const imageDescriptor = plain(binding) ? Object.getOwnPropertyDescriptor(binding, 'images') : undefined;
  const accessDescriptor = plain(binding) ? Object.getOwnPropertyDescriptor(binding, 'operatorAccessSha256') : undefined;
  const images = imageDescriptor && Object.hasOwn(imageDescriptor, 'value') ? imageDescriptor.value : undefined;
  const hasEdge = plain(images) && Object.hasOwn(images, 'edge');
  const hasOperator = plain(images) && Object.hasOwn(images, 'operator');
  const hasOperatorAccess = Boolean(accessDescriptor && Object.hasOwn(accessDescriptor, 'value'));
  if (hasOperatorAccess !== hasOperator || hasOperator && !hasEdge) fail();
  const version = hasOperatorAccess ? 3 : hasEdge ? 2 : 1;
  return Object.freeze({ version, profile: 'FNCP_PRODUCTION_ACTIVATION_V' + version,
    purpose: 'FNCP_PRODUCTION_ACTIVATION_V' + version,
    signingDomain: 'Barayamal\0FNCP\0ProductionActivation\0v' + version + '\0',
    roles: version === 3 ? IMAGE_ROLES_V3 : version === 2 ? IMAGE_ROLES_V2 : IMAGE_ROLES });
}
export const fail = () => { throw new Error('Production activation denied.'); };
export const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value)
  && [Object.prototype, null].includes(Object.getPrototypeOf(value));
export const exact = (value, keys, optional = []) => plain(value)
  && Reflect.ownKeys(value).every(k => typeof k === 'string' && [...keys, ...optional].includes(k))
  && keys.every(k => Object.hasOwn(value, k))
  && Object.values(Object.getOwnPropertyDescriptors(value)).every(d => Object.hasOwn(d, 'value'));
export const SHA = /^[a-f0-9]{64}$/u;
export const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
export const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/u;
export function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (plain(value)) {
    if (!exact(value, Object.keys(value))) fail();
    return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
  }
  if (typeof value === 'string' || typeof value === 'boolean' || value === null || Number.isSafeInteger(value)) return JSON.stringify(value);
  return fail();
}
export function validBinding(v, boot = false) {
  let protocol; try { protocol = activationProtocol(v); } catch { return false; }
  const roles = protocol.roles;
  return exact(v, ['deploymentId', 'conversationId', 'sourceRevision', 'configSha256', 'seedSha256', 'providerSha256', 'images', 'recoveryEpoch', 'scope',
    ...(protocol.version === 3 ? ['operatorAccessSha256'] : []), ...(boot ? ['bootId'] : [])])
    && typeof v.deploymentId === 'string' && /^[a-z0-9][a-z0-9_-]{2,63}$/u.test(v.deploymentId)
    && typeof v.conversationId === 'string' && /^[0-9][A-Za-z0-9_-]{5,99}$/u.test(v.conversationId)
    && typeof v.sourceRevision === 'string' && /^[a-f0-9]{40}$/u.test(v.sourceRevision)
    && ['configSha256', 'seedSha256', 'providerSha256', ...(protocol.version === 3 ? ['operatorAccessSha256'] : [])]
      .every(k => typeof v[k] === 'string' && SHA.test(v[k]))
    && typeof v.recoveryEpoch === 'string' && UUID.test(v.recoveryEpoch)
    && exact(v.images, roles) && roles.every(k => typeof v.images[k] === 'string' && /^sha256:[a-f0-9]{64}$/u.test(v.images[k]))
    && exact(v.scope, ['maxParticipants', 'statementCount', 'suggestions'])
    && v.scope.maxParticipants === 20 && v.scope.statementCount === 15 && v.scope.suggestions === false
    && (!boot || typeof v.bootId === 'string' && SHA.test(v.bootId));
}
export function validClaims(v, keyId) {
  const descriptor = plain(v) ? Object.getOwnPropertyDescriptor(v, 'binding') : undefined;
  const protocol = activationProtocol(descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined);
  return exact(v, ['schemaVersion', 'purpose', 'keyId', 'activationId', 'sequence', 'issuedAt', 'notBefore', 'expiresAt', 'binding'])
    && v.schemaVersion === protocol.version && v.purpose === protocol.purpose && v.keyId === keyId
    && typeof v.activationId === 'string' && UUID.test(v.activationId)
    && Number.isSafeInteger(v.sequence) && v.sequence > 0
    && ['issuedAt', 'notBefore', 'expiresAt'].every(k => Number.isSafeInteger(v[k]) && v[k] >= 0)
    && v.notBefore >= v.issuedAt && v.expiresAt > v.notBefore && v.expiresAt - v.issuedAt <= 1800
    && validBinding(v.binding, true);
}
