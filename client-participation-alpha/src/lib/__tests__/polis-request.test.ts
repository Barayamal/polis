/** @jest-environment node */

import {
  BROWSER_POLIS_API_BASE,
  buildBrowserPolisApiUrl,
  buildServerPolisApiUrl,
  createPolisServerRequest,
  normalizePolisServerApiBase
} from '../polis-request'

const SECRET = 'gateway-secret-that-is-at-least-32-bytes'
const CONVERSATION_ID = '2abcde'
const PARTICIPANT_XID = 'participant_xid_01'

describe('Polis request boundary', () => {
  it('always builds browser API URLs on the same-origin /api/v3 path', () => {
    expect(BROWSER_POLIS_API_BASE).toBe('/api/v3')
    expect(buildBrowserPolisApiUrl('/participationInit')).toBe('/api/v3/participationInit')
    expect(buildBrowserPolisApiUrl('votes')).toBe('/api/v3/votes')
  })

  it.each([
    'https://private.invalid/api/v3/participationInit',
    '//private.invalid/api/v3/participationInit',
    '/../participationInit',
    '/participationInit?xid=attacker',
    '/participationInit#fragment'
  ])('rejects a non-relative API path: %s', (api: string) => {
    expect(() => buildBrowserPolisApiUrl(api)).toThrow('relative path')
  })

  it('normalizes an internal server base without exposing it to browser URL building', () => {
    const internalBase = 'http://polis-api.internal:5000/api/v3/'
    expect(normalizePolisServerApiBase(internalBase)).toBe(
      'http://polis-api.internal:5000/api/v3'
    )
    expect(buildBrowserPolisApiUrl('/comments')).toBe('/api/v3/comments')
  })

  it.each([
    undefined,
    '/api/v3',
    'ftp://polis-api.internal/api/v3',
    'http://user:password@polis-api.internal/api/v3',
    'http://polis-api.internal/api/v3?x=1',
    'http://polis-api.internal/not-api-v3'
  ])('rejects an invalid internal API base: %s', (apiBase: string | undefined) => {
    expect(() => normalizePolisServerApiBase(apiBase)).toThrow()
  })

  it('builds a private SSR URL and preserves only the three validated gateway headers', () => {
    const request = createPolisServerRequest('http://polis-api.internal:5000/api/v3', {
      'X-FNCP-Gateway-Key': SECRET,
      'X-FNCP-Conversation-ID': CONVERSATION_ID,
      'X-FNCP-Participant-XID': PARTICIPANT_XID
    })

    expect(buildServerPolisApiUrl('/participationInit', request)).toBe(
      'http://polis-api.internal:5000/api/v3/participationInit'
    )
    expect(request.gatewayHeaders).toEqual({
      'X-FNCP-Gateway-Key': SECRET,
      'X-FNCP-Conversation-ID': CONVERSATION_ID,
      'X-FNCP-Participant-XID': PARTICIPANT_XID
    })
    expect(Object.keys(request.gatewayHeaders || {})).toHaveLength(3)
  })

  it('rejects partial, malformed, or additional server gateway headers', () => {
    expect(() =>
      createPolisServerRequest('http://polis-api.internal:5000/api/v3', {
        'X-FNCP-Gateway-Key': SECRET,
        'X-FNCP-Conversation-ID': CONVERSATION_ID
      } as never)
    ).toThrow('gateway headers')

    expect(() =>
      createPolisServerRequest('http://polis-api.internal:5000/api/v3', {
        'X-FNCP-Gateway-Key': SECRET,
        'X-FNCP-Conversation-ID': CONVERSATION_ID,
        'X-FNCP-Participant-XID': 'short'
      })
    ).toThrow('gateway headers')

    expect(() =>
      createPolisServerRequest('http://polis-api.internal:5000/api/v3', {
        'X-FNCP-Gateway-Key': SECRET,
        'X-FNCP-Conversation-ID': CONVERSATION_ID,
        'X-FNCP-Participant-XID': PARTICIPANT_XID,
        Authorization: 'Bearer must-not-forward'
      } as never)
    ).toThrow('gateway headers')
  })
})
