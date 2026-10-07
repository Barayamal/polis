import { fetchParticipationInit } from '../participation'
import PolisNet from '../../lib/net'
import * as langModule from '../../lib/lang'
import { createPolisServerRequest } from '../../lib/polis-request'

jest.mock('../../lib/net')
jest.mock('../../lib/lang')

const mockedPolisNet = PolisNet as jest.Mocked<typeof PolisNet>
const mockedLang = langModule as jest.Mocked<typeof langModule>

describe('participationInit API', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    mockedLang.uiLanguage.mockReturnValue('en')
  })

  it('passes a validated SSR request context separately from API parameters', async () => {
    const serverRequest = createPolisServerRequest('http://polis-api.internal:5000/api/v3', {
      'X-FNCP-Gateway-Key': 'gateway-secret-that-is-at-least-32-bytes',
      'X-FNCP-Conversation-ID': '2abcde',
      'X-FNCP-Participant-XID': 'participant_xid_01'
    })
    mockedPolisNet.polisGet.mockResolvedValue({
      conversation: {
        topic: 'Synthetic topic',
        description: '',
        treevite_enabled: false,
        is_active: true,
        conversation_id: '2abcde',
        vis_type: 0
      }
    })

    await fetchParticipationInit(
      '2abcde',
      { includePCA: false, lang: 'en' },
      serverRequest
    )

    expect(mockedPolisNet.polisGet).toHaveBeenCalledWith(
      '/participationInit',
      {
        conversation_id: '2abcde',
        includePCA: false,
        lang: 'en'
      },
      serverRequest
    )
    expect(mockedPolisNet.polisGet.mock.calls[0][1]).not.toHaveProperty('xid')
  })
})
