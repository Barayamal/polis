/** Protocol helper, not browser-rendering evidence. Never prints cookies or CSRF. */
import { request as httpRequest } from 'node:http';

export function createBrowserClient(origin = 'http://127.0.0.1:8100') {
  if (!/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/u.test(origin) || Number(new URL(origin).port) > 65535) {
    throw new Error('Exact local browser origin required.');
  }
  let cookie = ''; let csrf = '';
  async function request(path, body) {
    if (!['/api/session', '/api/login', '/api/oidc/start', '/api/oidc/callback', '/api/registration', '/api/registration/receipt', '/api/redeem', '/api/participation-init', '/api/next-comment', '/api/votes', '/api/logout'].includes(path)) {
      throw new Error('Unknown browser proof operation.');
    }
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const result = await new Promise((resolve, reject) => {
      const req = httpRequest(origin + path, {
        method: body === undefined ? 'GET' : 'POST', timeout: 15000,
        headers: { 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'same-origin', 'Sec-Fetch-Dest': 'empty',
          ...(cookie ? { Cookie: cookie } : {}),
          ...(body === undefined ? {} : { Origin: origin, 'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload), 'X-CSRF-Token': csrf }) },
      }, (res) => {
        const chunks = []; let size = 0;
        res.on('data', (chunk) => { size += chunk.length; if (size > 512 * 1024) res.destroy(new Error('Response limit.')); else chunks.push(chunk); });
        res.on('error', reject);
        res.on('end', () => {
          try {
            const setCookie = res.headers['set-cookie']?.[0];
            if (setCookie) cookie = setCookie.includes('Max-Age=0') ? '' : setCookie.split(';')[0];
            const decoded = JSON.parse(Buffer.concat(chunks).toString('utf8'));
            if (typeof decoded.csrf === 'string') csrf = decoded.csrf;
            const { csrf: omitted, ...safe } = decoded;
            resolve({ status: res.statusCode, body: safe });
          } catch { reject(new Error('Invalid local browser response.')); }
        });
      });
      req.on('error', () => reject(new Error('Local browser request failed.')));
      req.on('timeout', () => req.destroy(new Error('Local browser timeout.')));
      if (payload) req.write(payload); req.end();
    });
    return result;
  }
  return {
    session: () => request('/api/session'),
    login: (fixture, fixtureSecret) => request('/api/login', { fixture, fixtureSecret }),
    oidcStart: () => request('/api/oidc/start', {}),
    oidcCallback: (callbackUrl) => request('/api/oidc/callback', { callbackUrl }),
    registrationReceipt: (input) => request('/api/registration/receipt', input),
    register: (input) => request('/api/registration', input),
    redeem: (invitationToken) => request('/api/redeem', { invitationToken }),
    initialize: () => request('/api/participation-init'),
    next: () => request('/api/next-comment'),
    vote: (tid, vote) => request('/api/votes', { tid, vote }),
    logout: () => request('/api/logout', {}),
  };
}
