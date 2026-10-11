import { createHash, timingSafeEqual } from 'node:crypto';
export const ACCOUNT=/^acct_[A-Za-z0-9_-]{43}$/u;
export const XID=/^fncp_[A-Za-z0-9_-]{43}$/u;
export const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
export const SHA=/^[0-9a-f]{64}$/u;
export const OPAQUE=/^[A-Za-z0-9_-]{43}$/u;
export const NAME=/^[a-z][a-z0-9-]{2,63}$/u;
export const CONVERSATION=/^[0-9][A-Za-z0-9_-]{5,99}$/u;
export class ProductionAccessError extends Error {
  constructor(status=503,code='operation_unavailable'){super(code);this.status=status;this.code=code;}
}
export function exact(value,required,optional=[]){
  if(!value||typeof value!=='object'||Array.isArray(value)||![Object.prototype,null].includes(Object.getPrototypeOf(value))
    ||Reflect.ownKeys(value).some(k=>typeof k!=='string'||![...required,...optional].includes(k))
    ||required.some(k=>!Object.hasOwn(value,k))||Object.values(Object.getOwnPropertyDescriptors(value)).some(d=>!Object.hasOwn(d,'value')))
    throw new ProductionAccessError(400,'invalid_request');
  return value;
}
export function canonical(value){
  if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
  if(value&&typeof value==='object'){exact(value,Object.keys(value));return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';}
  if(value===null||typeof value==='boolean'||typeof value==='string'||Number.isSafeInteger(value))return JSON.stringify(value);
  throw new ProductionAccessError(400,'invalid_request');
}
export const sha=value=>createHash('sha256').update(value).digest('hex');
export const same=(a,b)=>typeof a==='string'&&typeof b==='string'&&timingSafeEqual(Buffer.from(sha(a)),Buffer.from(sha(b)));
export function secretBytes(value){if(typeof value!=='string'||!OPAQUE.test(value))throw new ProductionAccessError();const b=Buffer.from(value,'base64url');if(b.length!==32||b.toString('base64url')!==value)throw new ProductionAccessError();return b;}
export function validDeclarations(input,version){exact(input,['consentVersion','adultSelfAttested','eligibilitySelfAttested','registrationConsent']);if(input.consentVersion!==version||input.adultSelfAttested!==true||input.eligibilitySelfAttested!==true||input.registrationConsent!==true)throw new ProductionAccessError(400,'declarations_required');return true;}
