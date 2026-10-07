import { readFileSync } from 'node:fs';
process.umask(0o077);
try {
  const action = process.argv[2];
  if (process.env.FNCP_LOCAL_SYNTHETIC_MODE !== 'fixture-only' || !['open', 'close', 'status'].includes(action)) throw new Error('Use explicit fixture-only mode and open, close or status.');
  const { adminSecret } = JSON.parse(readFileSync(new URL('./.runtime/admin.json', import.meta.url), 'utf8'));
  const response = await fetch('http://127.0.0.1:8099/test-admin/' + (action === 'status' ? 'status' : 'round'), {
    method: action === 'status' ? 'GET' : 'POST', headers: { Authorization: `Bearer ${adminSecret}`,
      ...(action === 'status' ? {} : { 'Content-Type': 'application/json' }) },
    ...(action === 'status' ? {} : { body: JSON.stringify({ open: action === 'open' }) }),
    redirect: 'error', signal: AbortSignal.timeout(12000),
  });
  if (!response.ok) throw new Error('Local round operation denied.');
  console.log(JSON.stringify(await response.json()));
  console.log('Local gateway only. No public launch, provider-wide lifecycle change, or real messages.');
} catch {
  // Parser errors can include credential/response excerpts. Keep all failure
  // diagnostics fixed and redacted; an uncertain change is not a success.
  console.error('Local synthetic round operation could not be confirmed. Check fixture-only mode, the requested action and private local configuration. No credentials or response details logged.');
  process.exitCode = 1;
}
