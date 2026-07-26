/** @jest-environment node */

import {
  FncpGatewayContextError,
  resolveFncpAlphaRequest
} from '../fncp-gateway-context.server'

const SECRET = 'gateway-secret-that-is-at-least-32-bytes'
const WRONG_SECRET = 'wrong-secret-that-is-also-at-least-32'
const CONVERSATION_ID = '2abcde'
const OTHER_CONVERSATION_ID = '3fghij'
const PARTICIPANT_XID = 'participant_xid_01'
const INTERNAL_API = 'http://polis-api.internal:5000/api/v3'

const enabledEnvironment = {
  INTERNAL_SERVICE_URL: INTERNAL_API,
  FNCP_GATEWAY_ENFORCEMENT: 'true',
  FNCP_GATEWAY_CONVERSATION_ID: CONVERSATION_ID,
  FNCP_GATEWAY_SHARED_SECRET: SECRET
}

function gatewayHeaders(): Record<string, string> {
  return {
    'X-FNCP-Gateway-Key': SECRET,
    'X-FNCP-Conversation-ID': CONVERSATION_ID,
    'X-FNCP-Participant-XID': PARTICIPANT_XID
  }
}

function makeRequest(
  headers: Record<string, string> = {},
  search = ''
): Request {
  return new Request(`https://private-alpha.invalid/${CONVERSATION_ID}${search}`, {
    headers
  })
}

function expectContextError(
  callback: () => unknown,
  status: FncpGatewayContextError['status']
): FncpGatewayContextError {
  try {
    callback()
  } catch (error) {
    expect(error).toBeInstanceOf(FncpGatewayContextError)
    expect((error as FncpGatewayContextError).status).toBe(status)
    return error as FncpGatewayContextError
  }
  throw new Error('Expected FNCP context resolution to fail.')
}

describe('FNCP alpha server request context', () => {
  it('accepts a complete gateway context and returns only server request headers', () => {
    const context = resolveFncpAlphaRequest(
      makeRequest(gatewayHeaders()),
      CONVERSATION_ID,
      enabledEnvironment
    )

    expect(context.gatewayEnforced).toBe(true)
    expect(context.polisRequest).toEqual({
      apiBaseUrl: INTERNAL_API,
      gatewayHeaders: gatewayHeaders()
    })
  })

  it.each([
    {},
    {
      'X-FNCP-Gateway-Key': SECRET
    },
    {
      ...gatewayHeaders(),
      'X-FNCP-Gateway-Key': WRONG_SECRET
    },
    {
      ...gatewayHeaders(),
      'X-FNCP-Conversation-ID': OTHER_CONVERSATION_ID
    },
    {
      ...gatewayHeaders(),
      'X-FNCP-Participant-XID': 'short'
    },
    {
      ...gatewayHeaders(),
      'X-FNCP-Untrusted': 'value'
    }
  ])(
    'fails closed for incomplete or invalid gateway headers',
    (headers: Record<string, string>) => {
      const error = expectContextError(
        () =>
          resolveFncpAlphaRequest(
            makeRequest(headers),
            CONVERSATION_ID,
            enabledEnvironment
          ),
        'X-FNCP-Untrusted' in headers ? 400 : 403
      )

      expect(error.message).not.toContain(SECRET)
      expect(error.message).not.toContain(WRONG_SECRET)
      expect(error.message).not.toContain(PARTICIPANT_XID)
      expect(error.message).not.toContain(INTERNAL_API)
    }
  )

  it.each([
    '?xid=attacker_xid_1234',
    '?x_name=Attacker',
    '?x_profile_image_url=https%3A%2F%2Fattacker.invalid%2Fimage',
    '?token=attacker-token',
    '?X-FNCP-Participant-XID=attacker_xid_1234'
  ])('rejects URL-carried identity: %s', (search: string) => {
    expectContextError(
      () =>
        resolveFncpAlphaRequest(
          makeRequest(gatewayHeaders(), search),
          CONVERSATION_ID,
          enabledEnvironment
        ),
      400
    )
  })

  it.each([
    { Cookie: 'participant=attacker' },
    { Authorization: 'Bearer attacker-token' }
  ])(
    'rejects browser credentials that conflict with gateway identity',
    (extraHeaders: Record<string, string>) => {
      expectContextError(
        () =>
          resolveFncpAlphaRequest(
            makeRequest({ ...gatewayHeaders(), ...extraHeaders }),
            CONVERSATION_ID,
            enabledEnvironment
          ),
        400
      )
    }
  )

  it.each([
    { ...enabledEnvironment, INTERNAL_SERVICE_URL: 'http://polis-api.internal/private' },
    { ...enabledEnvironment, FNCP_GATEWAY_ENFORCEMENT: 'TRUE' },
    { ...enabledEnvironment, FNCP_GATEWAY_CONVERSATION_ID: 'invalid' },
    { ...enabledEnvironment, FNCP_GATEWAY_SHARED_SECRET: 'too-short' }
  ])(
    'returns a safe 503 for malformed runtime configuration',
    (environment: Record<string, string>) => {
      const error = expectContextError(
        () =>
          resolveFncpAlphaRequest(
            makeRequest(gatewayHeaders()),
            CONVERSATION_ID,
            environment
          ),
        503
      )

      expect(error.message).toBe('Participant service is not configured.')
      expect(error.message).not.toContain(INTERNAL_API)
      expect(error.message).not.toContain(SECRET)
    }
  )

  it('rejects spoofed FNCP headers when gateway enforcement is disabled', () => {
    expectContextError(
      () =>
        resolveFncpAlphaRequest(makeRequest(gatewayHeaders()), CONVERSATION_ID, {
          INTERNAL_SERVICE_URL: INTERNAL_API,
          FNCP_GATEWAY_ENFORCEMENT: 'false'
        }),
      403
    )
  })

  it('keeps unrelated conversations in legacy mode without forwarding gateway headers', () => {
    const context = resolveFncpAlphaRequest(
      makeRequest(),
      OTHER_CONVERSATION_ID,
      enabledEnvironment
    )

    expect(context).toEqual({
      gatewayEnforced: false,
      polisRequest: { apiBaseUrl: INTERNAL_API }
    })
  })
})
