/** Test-only network allowlist. Continue allowed requests completely unmodified. */
const appGet = new Set(['/', '/app.js', '/style.css', '/favicon.ico', '/api/session', '/api/participation-init', '/api/next-comment']);
const appPost = new Set(['/api/oidc/start', '/api/registration', '/api/redeem', '/api/logout', '/api/votes']);
const keysExactly = (url, keys) => keys.length === [...url.searchParams.keys()].length && keys.every(key => url.searchParams.getAll(key).length === 1 && url.searchParams.get(key));
/** Smaller boundary for the two-account journey: no certificate-negative origins. */
export function nativeCrossAccountRequestAllowed({ appOrigin, issuerOrigin }, raw, method) {
  try {
    for (const [origin, host] of [[appOrigin, 'browser.example.invalid'], [issuerOrigin, 'identity.issuer.invalid']]) {
      const parsed = new URL(origin);
      if (parsed.origin !== origin || parsed.protocol !== 'https:' || parsed.hostname !== host || !parsed.port ||
        parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash) return false;
    }
    if (typeof raw !== 'string' || raw.length > 8192 || raw.includes('#')) return false;
    const url = new URL(raw);
    if (url.href !== raw || url.protocol !== 'https:' || url.username || url.password || url.hash || raw.endsWith('?')) return false;
    if (url.origin === issuerOrigin) return method === 'GET' && url.pathname === '/authorize' &&
      keysExactly(url, ['client_id', 'redirect_uri', 'response_type', 'response_mode', 'scope', 'code_challenge', 'code_challenge_method', 'state', 'nonce']);
    if (url.origin !== appOrigin) return false;
    if (url.pathname === '/oidc/callback') return method === 'GET' && keysExactly(url, ['code', 'iss', 'state']);
    return !url.search && (method === 'GET' && appGet.has(url.pathname) || method === 'POST' && appPost.has(url.pathname));
  } catch { return false; }
}
export function nativeHttpsRequestAllowed({ appOrigin, issuerOrigin, untrustedOrigin, wrongHostOrigin }, raw, method) {
  try {
    for (const [origin, host] of [[appOrigin, 'browser.example.invalid'], [issuerOrigin, 'identity.issuer.invalid'],
      [untrustedOrigin, 'browser.example.invalid'], [wrongHostOrigin, 'wrong.example.invalid']]) {
      const parsed = new URL(origin);
      if (parsed.origin !== origin || parsed.protocol !== 'https:' || parsed.hostname !== host || !parsed.port ||
        parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash) return false;
    }
    if (appOrigin === untrustedOrigin || new URL(appOrigin).port !== new URL(wrongHostOrigin).port ||
      typeof raw !== 'string' || raw.length > 8192 || raw.includes('#')) return false;
    const url = new URL(raw);
    if (url.href !== raw || url.protocol !== 'https:' || url.username || url.password || url.hash || raw.endsWith('?')) return false;
    if ([untrustedOrigin, wrongHostOrigin].includes(url.origin)) return method === 'GET' && url.pathname === '/' && !url.search;
    return nativeCrossAccountRequestAllowed({ appOrigin, issuerOrigin }, raw, method);
  } catch { return false; }
}
