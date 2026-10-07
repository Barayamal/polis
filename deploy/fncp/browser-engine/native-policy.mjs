/** Pure opt-in browser-test containment; not application authorization. */
const routes = new Map([
  ['/', 'GET'], ['/app.js', 'GET'], ['/style.css', 'GET'], ['/favicon.ico', 'GET'],
  ['/api/session', 'GET'], ['/api/oidc/start', 'POST'], ['/api/oidc/callback', 'POST'],
  ['/api/registration', 'POST'], ['/api/redeem', 'POST'], ['/api/logout', 'POST'],
  ['/api/participation-init', 'GET'], ['/api/next-comment', 'GET'], ['/api/votes', 'POST'],
]);
export function nativeRequestAllowed(origin, rawUrl, method) {
  try {
    if (typeof origin !== 'string' || !/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/u.test(origin)) return false;
    const base = new URL(origin); if (base.origin !== origin || Number(base.port) > 65535) return false;
    if (typeof rawUrl !== 'string' || typeof method !== 'string' || /[\u0000-\u0020\u007f]/u.test(rawUrl)) return false;
    const url = new URL(rawUrl);
    return url.href === rawUrl && rawUrl === origin + url.pathname && url.origin === origin && !url.username && !url.password && !url.search && !url.hash
      && routes.get(url.pathname) === method;
  } catch { return false; }
}
