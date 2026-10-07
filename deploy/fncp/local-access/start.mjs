import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { createLocalAccess } from './access-server.mjs';
import { readStagingProvider } from './staging-config.mjs';
import { createWordPressReceiver } from './wordpress-receiver.mjs';

// Runtime-generated secrets never appear in logs, URLs, command-line arguments
// or tracked files. This executable is the only long-running harness entrypoint.
process.umask(0o077);
let app; let receiver;
const cleanup = async () => { if (receiver) await receiver.close(); if (app) await app.close(); };
try {
  const mode = process.env.FNCP_LOCAL_SYNTHETIC_MODE;
  const config = readStagingProvider(mode);
  const runtime = new URL('./.runtime/', import.meta.url);
  mkdirSync(runtime, { recursive: true, mode: 0o700 });
  chmodSync(runtime, 0o700);
  const credentialFile = new URL('admin.json', runtime);
  if (!existsSync(credentialFile)) writeFileSync(credentialFile,
    JSON.stringify({ adminSecret: randomBytes(32).toString('base64url') }), { mode: 0o600, flag: 'wx' });
  chmodSync(credentialFile, 0o600);
  const { adminSecret } = JSON.parse(readFileSync(credentialFile, 'utf8'));
  app = createLocalAccess({ mode, ...config, adminSecret,
    dbPath: fileURLToPath(new URL('synthetic.sqlite', runtime)) });
  const eventSecretFile = new URL('wordpress-secret.json', runtime);
  if (!existsSync(eventSecretFile)) writeFileSync(eventSecretFile,
    JSON.stringify({ secret: randomBytes(32).toString('base64url') }), { mode: 0o600, flag: 'wx' });
  chmodSync(eventSecretFile, 0o600);
  const { secret } = JSON.parse(readFileSync(eventSecretFile, 'utf8'));
  if (secret === adminSecret || secret === config.provider.gatewaySecret || secret === config.provider.providerSecret) throw new Error('Separate event secret required.');
  receiver = createWordPressReceiver({ mode, secret, ingest: (event) => app.ingestWordPressEvent(event) });
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, async () => { await cleanup(); process.exit(0); });
  const address = await app.listen(8099);
  await receiver.listen(8101);
  console.log(`SYNTHETIC-ONLY API running at ${address}; no real authentication or email.`);
  console.log('Administrator credential: deploy/fncp/local-access/.runtime/admin.json (private local file).');
  console.log('Public surfaces remain unchanged. Local round starts closed for a new database.');
  console.log('Signed synthetic WordPress receiver: http://127.0.0.1:8101 (not browser-accessible).');
} catch {
  await cleanup();
  console.error('Local access proof could not start. Check explicit synthetic mode, staging bootstrap and local runtime configuration. No secrets logged.');
  process.exitCode = 1;
}
