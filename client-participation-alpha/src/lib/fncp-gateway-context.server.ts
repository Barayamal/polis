import { createHash, timingSafeEqual } from 'node:crypto'
import {
  createPolisServerRequest,
  type FncpGatewayHeaders,
  type PolisServerRequest
} from './polis-request'

const CONVERSATION_ID = /^[0-9][A-Za-z0-9_-]{5,99}$/
const PARTICIPANT_XID = /^[A-Za-z0-9_-]{16,256}$/
const GATEWAY_HEADER_NAMES = new Set([
  'x-fncp-gateway-key',
  'x-fncp-conversation-id',
  'x-fncp-participant-xid'
])
const IDENTITY_QUERY_KEYS = new Set([
  'access_token',
  'authorization',
  'email',
  'id_token',
  'jwt',
  'name',
  'password',
  'pid',
  'refresh_token',
  'session',
  'token',
  'uid',
  'x_name',
  'x_profile_image_url',
  'xid'
])

type RuntimeEnvironment = Record<string, string | undefined>

export interface FncpAlphaRequestContext {
  readonly gatewayEnforced: boolean
  readonly polisRequest: PolisServerRequest
}

export class FncpGatewayContextError extends Error {
  readonly status: 400 | 403 | 503

  constructor(status: 400 | 403 | 503, message: string) {
    super(message)
    this.name = 'FncpGatewayContextError'
    this.status = status
  }
}

function failConfiguration(): never {
  throw new FncpGatewayContextError(503, 'Participant service is not configured.')
}

function hasFncpHeader(headers: Headers): boolean {
  for (const [name] of headers) {
    if (name.toLowerCase().startsWith('x-fncp-')) {
      return true
    }
  }
  return false
}

function hasUnexpectedFncpHeader(headers: Headers): boolean {
  for (const [name] of headers) {
    const normalized = name.toLowerCase()
    if (normalized.startsWith('x-fncp-') && !GATEWAY_HEADER_NAMES.has(normalized)) {
      return true
    }
  }
  return false
}

function hasIdentityQuery(searchParams: URLSearchParams): boolean {
  for (const key of searchParams.keys()) {
    const normalized = key.toLowerCase()
    if (normalized.startsWith('x-fncp-') || IDENTITY_QUERY_KEYS.has(normalized)) {
      return true
    }
  }
  return false
}

function sameSecret(supplied: string, expected: string): boolean {
  if (!supplied || !expected) {
    return false
  }
  const left = createHash('sha256').update(supplied).digest()
  const right = createHash('sha256').update(expected).digest()
  return timingSafeEqual(left, right)
}

function readGatewayHeaders(headers: Headers, expectedSecret: string): FncpGatewayHeaders {
  const suppliedSecret = headers.get('x-fncp-gateway-key') || ''
  const conversationId = headers.get('x-fncp-conversation-id') || ''
  const participantXid = headers.get('x-fncp-participant-xid') || ''

  if (
    !sameSecret(suppliedSecret, expectedSecret) ||
    !CONVERSATION_ID.test(conversationId) ||
    !PARTICIPANT_XID.test(participantXid)
  ) {
    throw new FncpGatewayContextError(403, 'Gateway access required.')
  }

  return {
    'X-FNCP-Gateway-Key': suppliedSecret,
    'X-FNCP-Conversation-ID': conversationId,
    'X-FNCP-Participant-XID': participantXid
  }
}

export function resolveFncpAlphaRequest(
  request: Request,
  routeConversationId: string,
  env: RuntimeEnvironment = process.env
): FncpAlphaRequestContext {
  let legacyPolisRequest: PolisServerRequest
  try {
    legacyPolisRequest = createPolisServerRequest(env.INTERNAL_SERVICE_URL)
  } catch {
    failConfiguration()
  }

  const enforcementValue = env.FNCP_GATEWAY_ENFORCEMENT
  if (
    enforcementValue !== undefined &&
    enforcementValue !== '' &&
    enforcementValue !== 'false' &&
    enforcementValue !== 'true'
  ) {
    failConfiguration()
  }

  if (enforcementValue !== 'true') {
    if (hasFncpHeader(request.headers)) {
      throw new FncpGatewayContextError(403, 'Gateway access required.')
    }
    return { gatewayEnforced: false, polisRequest: legacyPolisRequest }
  }

  const configuredConversationId = env.FNCP_GATEWAY_CONVERSATION_ID || ''
  const sharedSecret = env.FNCP_GATEWAY_SHARED_SECRET || ''
  if (
    !CONVERSATION_ID.test(configuredConversationId) ||
    sharedSecret.length < 32 ||
    sharedSecret.length > 512
  ) {
    failConfiguration()
  }

  if (routeConversationId !== configuredConversationId) {
    if (hasFncpHeader(request.headers)) {
      throw new FncpGatewayContextError(403, 'Gateway access required.')
    }
    return { gatewayEnforced: false, polisRequest: legacyPolisRequest }
  }

  const requestUrl = new URL(request.url)
  if (
    request.headers.has('authorization') ||
    request.headers.has('cookie') ||
    hasUnexpectedFncpHeader(request.headers) ||
    hasIdentityQuery(requestUrl.searchParams)
  ) {
    throw new FncpGatewayContextError(400, 'Conflicting participant identity.')
  }

  const gatewayHeaders = readGatewayHeaders(request.headers, sharedSecret)
  if (gatewayHeaders['X-FNCP-Conversation-ID'] !== configuredConversationId) {
    throw new FncpGatewayContextError(403, 'Gateway access required.')
  }

  let polisRequest: PolisServerRequest
  try {
    polisRequest = createPolisServerRequest(env.INTERNAL_SERVICE_URL, gatewayHeaders)
  } catch {
    failConfiguration()
  }

  return { gatewayEnforced: true, polisRequest }
}
