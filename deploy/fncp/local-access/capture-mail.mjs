/** Local fixture credentials/invitations only. No SMTP, API delivery or real addresses. */
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { SUBJECT } from './wordpress-events.mjs';
process.umask(0o077);
try {
  if (process.env.FNCP_LOCAL_SYNTHETIC_MODE !== 'fixture-only') throw new Error('Mode required.');
  const [action, fixture] = process.argv.slice(2);
  if (!['register', 'capture-invitation'].includes(action) || !SUBJECT.test(fixture ?? '')) throw new Error('Use register or capture-invitation with a synthetic fixture.');
  const runtime = new URL('./.runtime/', import.meta.url);
  const mailbox = new URL('captured-mail/', runtime); mkdirSync(mailbox, { recursive: true, mode: 0o700 });
  const credentialFile = new URL(fixture + '.json', mailbox);
  const { adminSecret } = JSON.parse(readFileSync(new URL('admin.json', runtime), 'utf8'));
  const request = async (path, body) => {
    const res = await fetch('http://127.0.0.1:8099/test-admin/' + path, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminSecret}` },
      body: JSON.stringify(body), redirect: 'error', signal: AbortSignal.timeout(12000),
    });
    if (!res.ok) throw new Error('Local fixture operation denied; no unknown credentials are recovered.');
    return res.json();
  };
  if (action === 'register') {
    if (existsSync(credentialFile)) throw new Error('Private fixture file already exists; no overwrite.');
    const result = await request('fixtures', { fixture });
    writeFileSync(credentialFile, JSON.stringify({ mode: 'SYNTHETIC_ONLY', fixture, fixtureSecret: result.fixtureSecret,
      warning: 'This local file simulates mailbox access. It does not prove ownership of a real email address.' }, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  } else {
    const credential = JSON.parse(readFileSync(credentialFile, 'utf8'));
    if (credential.mode !== 'SYNTHETIC_ONLY' || credential.fixture !== fixture) throw new Error('Fixture binding mismatch.');
    const result = await request('invitations', { fixture, ttlSeconds: 900 });
    writeFileSync(credentialFile, JSON.stringify({ ...credential, invitationToken: result.invitationToken,
      expiresAt: new Date(result.expiresAt).toISOString(), browserUrl: 'http://127.0.0.1:8100/',
      delivery: 'CAPTURED_LOCALLY_ONLY_NOT_SENT' }, null, 2) + '\n', { mode: 0o600 });
  }
  chmodSync(credentialFile, 0o600);
  console.log(`Synthetic ${action} complete. Private local capture: ${credentialFile.pathname}`);
  console.log('No email/message sent; no real mailbox ownership or heritage verified.');
} catch {
  // JSON parser and transport errors may contain private input excerpts. Never
  // print their message, stack, cause or response body, even for local fixtures.
  console.error('Local synthetic capture could not be confirmed. Check fixture-only mode, the invented fixture and private local files. Do not replay an uncertain operation blindly. No credentials logged.');
  process.exitCode = 1;
}
