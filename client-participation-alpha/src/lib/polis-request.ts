export const BROWSER_POLIS_API_BASE = '/api/v3'

export const FNCP_GATEWAY_HEADER_NAMES = [
  'X-FNCP-Gateway-Key',
  'X-FNCP-Conversation-ID',
  'X-FNCP-Participant-XID'
] as const

export type FncpGatewayHeaderName = (typeof FNCP_GATEWAY_HEADER_NAMES)[number]
export type FncpGatewayHeaders = Readonly<Record<FncpGatewayHeaderName, string>>

export interface PolisServerRequest {
  readonly apiBaseUrl: string
  readonly gatewayHeaders?: FncpGatewayHeaders
}
const API_PATH = /^\/[A-Za-z0-9][A-Za-z0-9/_-]*$/
const CONVERSATION_ID = /^[0-9][A-Za-z0-9_-]{5,99}$/
const PARTICIPANT_XID = /^[A-Za-z0-9_-]{16,256}$/

export function normalizePolisApiPath(api: string): string {
  if (typeof api !== 'string') {
    throw new Error('Polis API path must be a string.')
  }

  const path = api.startsWith('/') ? api : `/${api}`
  if (
    !API_PATH.test(path) ||
    path.startsWith('//') ||
    path.includes('/../') ||
    path.endsWith('/..') ||
    path.includes('/./') ||
    path.endsWith('/.')
  ) {
    throw new Error('Polis API path must be a relative path.')
  }

  return path
}

export function normalizePolisServerApiBase(value: string | undefined): string {
  if (!value) {
    throw new Error('Polis server API base is not configured.')
  }

  let parsed: URL
  try {
    parsed = new URL(value)
  } catch {
    throw new Error('Polis server API base is invalid.')
  }

  const pathname = parsed.pathname.replace(/\/+$/, '')
  if (
    (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash ||
    pathname !== BROWSER_POLIS_API_BASE
  ) {
    throw new Error('Polis server API base is invalid.')
  }

  return `${parsed.origin}${BROWSER_POLIS_API_BASE}`
}

function validateGatewayHeaders(value: FncpGatewayHeaders): FncpGatewayHeaders {
  const keys = Object.keys(value)
  if (
    keys.length !== FNCP_GATEWAY_HEADER_NAMES.length ||
    FNCP_GATEWAY_HEADER_NAMES.some((name) => !keys.includes(name))
  ) {
    throw new Error('FNCP gateway headers are invalid.')
  }

  const gatewayKey = value['X-FNCP-Gateway-Key']
  const conversationId = value['X-FNCP-Conversation-ID']
  const participantXid = value['X-FNCP-Participant-XID']
  if (
    gatewayKey.length < 32 ||
    gatewayKey.length > 512 ||
    !CONVERSATION_ID.test(conversationId) ||
    !PARTICIPANT_XID.test(participantXid)
  ) {
    throw new Error('FNCP gateway headers are invalid.')
  }

  return Object.freeze({
    'X-FNCP-Gateway-Key': gatewayKey,
    'X-FNCP-Conversation-ID': conversationId,
    'X-FNCP-Participant-XID': participantXid
  })
}

export function createPolisServerRequest(
  apiBaseUrl: string | undefined,
  gatewayHeaders?: FncpGatewayHeaders
): PolisServerRequest {
  return Object.freeze({
    apiBaseUrl: normalizePolisServerApiBase(apiBaseUrl),
    ...(gatewayHeaders && { gatewayHeaders: validateGatewayHeaders(gatewayHeaders) })
  })
}

export function buildBrowserPolisApiUrl(api: string): string {
  return `${BROWSER_POLIS_API_BASE}${normalizePolisApiPath(api)}`
}

export function buildServerPolisApiUrl(api: string, request: PolisServerRequest): string {
  return `${normalizePolisServerApiBase(request.apiBaseUrl)}${normalizePolisApiPath(api)}`
}
