import { createLocalBrowser, LocalAccessBackend } from './browser-server.mjs';

try {
  if (process.env.FNCP_LOCAL_SYNTHETIC_MODE !== 'fixture-only') throw new Error();
  const backend = new LocalAccessBackend();
  await backend.verifySynthetic();
  const app = createLocalBrowser({ mode: process.env.FNCP_LOCAL_SYNTHETIC_MODE, backend });
  const origin = await app.listen(8100);
  console.log(`SYNTHETIC-ONLY browser proof at ${origin}/; no real mailbox or heritage verification.`);
  console.log('No email or SMS. Restart clears browser sessions. Public surfaces remain unchanged.');
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, async () => { await app.close(); process.exit(0); });
} catch {
  console.error('Local browser proof could not start. Confirm explicit fixture-only mode and the synthetic API on 127.0.0.1:8099. No credentials logged.');
  process.exitCode = 1;
}
