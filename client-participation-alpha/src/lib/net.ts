import {
  getConversationIdFromUrl,
  getConversationToken,
  getXidFromUrl,
  getXNameFromUrl,
  getXProfileImageUrlFromUrl,
  handleJwtFromResponse
} from './auth'
import {
  buildBrowserPolisApiUrl,
  buildServerPolisApiUrl,
  createPolisServerRequest,
  FNCP_GATEWAY_HEADER_NAMES,
  type PolisServerRequest
} from './polis-request'

// Default request timeout (ms)
const REQUEST_TIMEOUT_MS: number = Number(import.meta.env.PUBLIC_REQUEST_TIMEOUT_MS) || 10000

// Type definitions
type OidcTokenGetter = (options?: { cacheMode?: string }) => Promise<string | null>
type OidcLoginRedirect = () => void

interface PolisApiError extends Error {
  responseText?: string
  status?: number
}

// Auth/OIDC token getter function - this should be set by the app when Auth is initialized
let getOidcAccessToken: OidcTokenGetter | null = null

let authReady = false
let authReadyPromise: Promise<void> | null = null
let authReadyResolve: ((value: void) => void) | null = null

// Create a promise that resolves when auth is ready
const initAuthReadyPromise = () => {
  authReadyPromise = new Promise((resolve) => {
    authReadyResolve = resolve
  })
}

// Initialize the promise immediately
initAuthReadyPromise()

export const setOidcTokenGetter = (getter: OidcTokenGetter | null) => {
  getOidcAccessToken = getter

  if (getter) {
    // Auth is now ready
    authReady = true
    if (authReadyResolve) {
      authReadyResolve()
    }
  } else {
    // Auth is being cleared, reset the ready state
    authReady = false
    initAuthReadyPromise()
  }
}

// Store Auth hooks for login redirect
let oidcLoginRedirect: OidcLoginRedirect | null = null

interface OidcActions {
  signinRedirect?: OidcLoginRedirect
}

export const setOidcActions = (actions: OidcActions | null) => {
  if (actions && typeof actions === 'object') {
    oidcLoginRedirect = actions.signinRedirect || null
  } else {
    // Clear if null/undefined passed
    oidcLoginRedirect = null
  }
}

// Export functions to check auth readiness
export const isAuthReady = () => authReady
export const waitForAuthReady = () => authReadyPromise

const getAccessTokenSilentlySPA = async (options?: {
  cacheMode?: string
}): Promise<string | null | undefined> => {
  // On the server, skip OIDC entirely
  if (typeof window === 'undefined') {
    return undefined
  }

  // If no getter is registered, skip immediately (do not wait)
  if (!getOidcAccessToken) {
    return undefined
  }

  // Wait for auth to be ready
  if (!authReady && authReadyPromise) {
    await authReadyPromise
  }

  if (getOidcAccessToken) {
    try {
      const token = await getOidcAccessToken({
        cacheMode: 'on', // Use cached token if valid
        ...options
      })
      return token
    } catch (e: unknown) {
      // Handle specific OIDC errors
      const error = e as { error?: string }
      if (
        error.error === 'login_required' &&
        oidcLoginRedirect &&
        typeof oidcLoginRedirect === 'function'
      ) {
        oidcLoginRedirect()
        return null
      }

      // Let the error bubble up to be handled by the calling code
      throw e
    }
  } else {
    console.warn('⚠️ Token getter not available even after waiting')
    return Promise.resolve(undefined)
  }
}

// Request interceptor for handling auth errors
const handleAuthError = (error: PolisApiError, response: Response): PolisApiError => {
  if (response && (response.status === 401 || response.status === 403)) {
    console.warn('Authentication/authorization error:', response.status)
    // For 401 (unauthorized), try to redirect to login
    if (response.status === 401) {
      // Check if we should force signout
      if (oidcLoginRedirect && typeof oidcLoginRedirect === 'function') {
        oidcLoginRedirect()
        return error
      }
    }
  }

  throw error
}

async function polisFetch<T = unknown>(
  api: string,
  data?: Record<string, unknown>,
  type?: string,
  serverRequest?: PolisServerRequest
): Promise<T> {
  const isBrowser = typeof window !== 'undefined'
  let url: string
  if (isBrowser) {
    if (serverRequest) {
      throw new Error('Server request context cannot be used in the browser.')
    }
    url = buildBrowserPolisApiUrl(api)
  } else {
    if (!serverRequest) {
      throw new Error('Server request context is required during SSR.')
    }
    serverRequest = createPolisServerRequest(
      serverRequest.apiBaseUrl,
      serverRequest.gatewayHeaders
    )
    url = buildServerPolisApiUrl(api, serverRequest)
  }

  const headers: Record<string, string> = {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'max-age=0'
  }
  if (!isBrowser && serverRequest?.gatewayHeaders) {
    for (const headerName of FNCP_GATEWAY_HEADER_NAMES) {
      headers[headerName] = serverRequest.gatewayHeaders[headerName]
    }
  }

  let body: string | null = null
  const method = type ? type.toUpperCase() : 'GET'

  // Add XID parameters from URL if present (unless already in data)
  const enrichedData: Record<string, unknown> = { ...data }
  if (typeof window !== 'undefined') {
    const xid = getXidFromUrl()
    const x_name = getXNameFromUrl()
    const x_profile_image_url = getXProfileImageUrlFromUrl()

    if (xid && !enrichedData.xid) {
      enrichedData.xid = xid
    }
    if (x_name && !enrichedData.x_name) {
      enrichedData.x_name = x_name
    }
    if (x_profile_image_url && !enrichedData.x_profile_image_url) {
      enrichedData.x_profile_image_url = x_profile_image_url
    }
  }

  if (method === 'GET' && enrichedData && Object.keys(enrichedData).length > 0) {
    // URLSearchParams handles various types reasonably well
    const queryParams = new URLSearchParams(enrichedData as Record<string, string>)
    url += `?${queryParams.toString()}`
  } else if (
    (method === 'POST' || method === 'PUT') &&
    enrichedData &&
    Object.keys(enrichedData).length > 0
  ) {
    body = JSON.stringify(enrichedData)
  }

  try {
    // First try OIDC token
    const oidcToken = await getAccessTokenSilentlySPA()
    if (oidcToken) {
      headers.Authorization = `Bearer ${oidcToken}`
    } else {
      // Fall back to conversation-specific JWT if available
      // Extract conversation_id from data or current URL path
      let conversationId: string | null = null

      // First check if conversation_id is in the request data
      // Use type narrowing safely
      if (data && typeof data.conversation_id === 'string') {
        conversationId = data.conversation_id
      } else if (typeof window !== 'undefined') {
        // Try to extract from current page URL path using shared helper
        conversationId = getConversationIdFromUrl()
      }

      if (conversationId) {
        const conversationToken = getConversationToken(conversationId)
        if (conversationToken && conversationToken.token) {
          headers.Authorization = `Bearer ${conversationToken.token}`
        }
      }
    }
  } catch (error) {
    // If getting the token fails, continue without it
    // The server will decide if auth is required
    console.warn('⚠️ Error getting access token:', error)
  }

  // Add timeout to avoid indefinite hangs (especially during SSR)
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)
  let response: Response
  try {
    response = await fetch(url, {
      method: method,
      headers: headers,
      body: body,
      signal: controller.signal
    })
  } catch (err: unknown) {
    const error = err as Error & { status?: number }
    if (error && error.name === 'AbortError') {
      const timeoutError: PolisApiError = new Error('Polis API request timed out.')
      timeoutError.status = 408
      throw timeoutError
    }
    throw err
  } finally {
    clearTimeout(timeout)
  }

  if (!response.ok && response.status !== 304) {
    const errorBody = await response.text()

    const error: PolisApiError = new Error(`Polis API request failed with status ${response.status}.`)
    error.responseText = errorBody
    error.status = response.status

    // handleAuthError will throw, so this never returns normally
    handleAuthError(error, response)
    throw error // TypeScript needs this for type checking even though it's unreachable
  }

  const jsonResponse = await response.json()

  // Automatically handle JWT tokens in response
  handleJwtFromResponse(jsonResponse)

  return jsonResponse
}

async function polisPost<T = unknown>(
  api: string,
  data?: Record<string, unknown>,
  serverRequest?: PolisServerRequest
): Promise<T> {
  return await polisFetch<T>(api, data, 'POST', serverRequest)
}

async function polisPut<T = unknown>(
  api: string,
  data?: Record<string, unknown>,
  serverRequest?: PolisServerRequest
): Promise<T> {
  return await polisFetch<T>(api, data, 'PUT', serverRequest)
}

async function polisGet<T = unknown>(
  api: string,
  data?: Record<string, unknown>,
  serverRequest?: PolisServerRequest
): Promise<T> {
  try {
    const response = await polisFetch<T>(api, data, 'GET', serverRequest)
    return response
  } catch (error: unknown) {
    // If we have a 403, it might be the initial race condition. Retry once.
    const err = error as PolisApiError
    if (err.status === 403) {
      console.warn('⚠️ Received 403 on GET, retrying request once after a short delay...')
      await new Promise((resolve) => setTimeout(resolve, 500)) // wait 500ms
      return await polisFetch<T>(api, data, 'GET', serverRequest) // This is the retry
    }
    throw error
  }
}

// Download a CSV (or other blob) while including the correct Authorization header
async function downloadCsv(
  api: string,
  data?: Record<string, unknown>,
  filename?: string
): Promise<void> {
  if (typeof window === 'undefined') {
    throw new Error('CSV downloads are only available in the browser.')
  }

  let url = buildBrowserPolisApiUrl(api)

  const method = 'GET'

  // Add XID parameters from URL if present (unless already in data)
  const enrichedData: Record<string, unknown> = { ...data }
  if (typeof window !== 'undefined') {
    const xid = getXidFromUrl()
    const x_name = getXNameFromUrl()
    const x_profile_image_url = getXProfileImageUrlFromUrl()

    if (xid && !enrichedData.xid) {
      enrichedData.xid = xid
    }
    if (x_name && !enrichedData.x_name) {
      enrichedData.x_name = x_name
    }
    if (x_profile_image_url && !enrichedData.x_profile_image_url) {
      enrichedData.x_profile_image_url = x_profile_image_url
    }
  }

  if (enrichedData && Object.keys(enrichedData).length > 0) {
    const queryParams = new URLSearchParams(enrichedData as Record<string, string>)
    url += `?${queryParams.toString()}`
  }

  const headers: Record<string, string> = {
    Accept: 'text/csv'
  }

  // Authorization: prefer OIDC access token, fall back to conversation JWT
  try {
    const oidcToken = await getAccessTokenSilentlySPA()
    if (oidcToken) {
      headers.Authorization = `Bearer ${oidcToken}`
    } else {
      let conversationId: string | null = null
      if (data && typeof data.conversation_id === 'string') {
        conversationId = data.conversation_id
      } else if (typeof window !== 'undefined') {
        conversationId = getConversationIdFromUrl()
      }
      if (conversationId) {
        const conversationToken = getConversationToken(conversationId)
        if (conversationToken && conversationToken.token) {
          headers.Authorization = `Bearer ${conversationToken.token}`
        }
      }
    }
  } catch (error) {
    console.warn('⚠️ Error getting access token for CSV download:', error)
  }

  // Timeout
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)
  let response: Response
  try {
    response = await fetch(url, {
      method,
      headers,
      signal: controller.signal
    })
  } catch (err: unknown) {
    const error = err as Error & { status?: number }
    if (error && error.name === 'AbortError') {
      const timeoutError: PolisApiError = new Error('Polis API request timed out.')
      timeoutError.status = 408
      throw timeoutError
    }
    throw err
  } finally {
    clearTimeout(timeout)
  }

  if (!response.ok) {
    const errorText = await response.text()
    const error: PolisApiError = new Error(`Polis API request failed with status ${response.status}.`)
    error.responseText = errorText
    error.status = response.status
    handleAuthError(error, response)
    throw error
  }

  const blob = await response.blob()
  const downloadUrl = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  // Safe cast/check for conversation_id
  const dataConvId = data && typeof data.conversation_id === 'string' ? data.conversation_id : null
  const convId =
    dataConvId || (typeof window !== 'undefined' ? getConversationIdFromUrl() : '') || ''
  const ts = new Date().toISOString().replace(/[:.]/g, '-')
  anchor.href = downloadUrl
  anchor.download = filename || `my_treevite_invites_${convId}_${ts}.csv`
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  setTimeout(() => URL.revokeObjectURL(downloadUrl), 0)
}

const PolisNet = {
  polisFetch,
  polisPost,
  polisPut,
  polisGet,
  getAccessTokenSilentlySPA,
  downloadCsv
}
export default PolisNet
