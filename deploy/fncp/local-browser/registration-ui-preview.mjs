/** UI MODEL ONLY. No identity driver, database, cookies, credentials or upstream.
 * Starts only with explicit CLI --ui-model. Exact loopback routes and fixed body.
 * Production HTML/CSS/JS rendering evidence is distinct from actual HTTP proofs.
 */
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

export function createRegistrationUiPreview() {
  let submitted = false;
  const origin = 'http://127.0.0.1:8114';
  const state = () => ({ phase: 'authenticated', csrf: 'UI_MODEL_NOT_A_CREDENTIAL',
    authentication: 'SIGNED_SYNTHETIC_OIDC', registrationEnabled: true,
    registrationStatus: submitted ? 'SUBMITTED_NOT_APPROVED' : 'NOT_SUBMITTED',
    ...(submitted ? { registrationId: '00000000-0000-4000-8000-000000000001' } : {}) });
  const server = createServer(async (req, res) => {
    res.setHeader('Cache-Control', 'no-store'); res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'");
    const json = (status, value) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(value)); };
    if (req.headers.host !== '127.0.0.1:8114' || req.url?.includes('?')) return json(403, { error: 'UI model route denied.' });
    if (req.method === 'GET' && req.url === '/api/session') return json(200, state());
    if (req.method === 'POST' && req.url === '/api/registration' && req.headers.origin === origin) {
      let body = ''; for await (const chunk of req) { body += chunk; if (body.length > 1024) return json(400, { error: 'UI model input denied.' }); }
      let input; try { input = JSON.parse(body); } catch { return json(400, { error: 'UI model input denied.' }); }
      const keys = ['adultSelfAttested', 'eligibilitySelfAttested', 'registrationConsent', 'consentVersion'];
      if (!input || Object.keys(input).length !== 4 || !keys.every(k => Object.hasOwn(input, k)) ||
          input.adultSelfAttested !== true || input.eligibilitySelfAttested !== true || input.registrationConsent !== true ||
          input.consentVersion !== 'synthetic-registration-v1') return json(400, { error: 'UI model input denied.' });
      if (submitted) return json(409, { error: 'UI model already submitted.' });
      submitted = true; return json(200, state());
    }
    const files = new Map([['/', ['index.html', 'text/html']], ['/style.css', ['style.css', 'text/css']], ['/app.js', ['app.js', 'text/javascript']]]);
    const file = files.get(req.url);
    if (req.method !== 'GET' || !file) return json(404, { error: 'No real operation exists in this UI model.' });
    let content = readFileSync(new URL('./public/' + file[0], import.meta.url), 'utf8');
    if (file[0] === 'index.html') content = content.replace('<body>', '<body><p class="ui-model-banner">UI MODEL ONLY — no authentication, WordPress, Pol.is, email or real registration. Visual check using production assets.</p>');
    if (file[0] === 'style.css') content += '\n.ui-model-banner{margin:0;background:#143932;color:#fff;padding:12px 24px;font-size:13px;text-align:center;font-weight:650}';
    res.writeHead(200, { 'Content-Type': file[1] + '; charset=utf-8' }); res.end(content);
  });
  return server;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3 || process.argv[2] !== '--ui-model') throw new Error('Explicit UI model flag required.');
  const server = createRegistrationUiPreview();
  server.listen(8114, '127.0.0.1', () => console.log('UI_MODEL_ONLY=http://127.0.0.1:8114'));
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => server.close(() => process.exit(0)));
}
