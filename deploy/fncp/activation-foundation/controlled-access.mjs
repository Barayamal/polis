/** Mandatory admission wrapper. The underlying API remains fixture-only. */
import { resolve, dirname, basename, join } from 'node:path';
import { existsSync, statSync, realpathSync } from 'node:fs';
import { createLocalAccess, MODE } from '../local-access/access-server.mjs';
import { createActivationAuthority } from './authority.mjs';

export function createControlledLocalAccess({ activation, ...access }) {
  let settings;
  try { settings = { ...activation }; settings.binding = structuredClone(settings.binding); }
  catch { throw new Error('Controlled synthetic access configuration denied.'); }
  if (access.mode !== MODE || !activation || Object.hasOwn(access, 'admissionGuard') ||
      settings.binding?.conversationId !== access.conversationId ||
      (access.provider?.conversationId !== undefined && access.provider.conversationId !== access.conversationId) ||
      (settings.ledgerPath !== ':memory:' && access.dbPath !== ':memory:' &&
       resolve(settings.ledgerPath ?? '') === resolve(access.dbPath ?? ''))) {
    throw new Error('Controlled synthetic access configuration denied.');
  }
  if (settings.ledgerPath !== ':memory:' && access.dbPath !== ':memory:') {
    try {
      const normalized = (path) => existsSync(path) ? realpathSync(path) : join(realpathSync(dirname(resolve(path))), basename(path));
      if (normalized(settings.ledgerPath) === normalized(access.dbPath)) throw new Error();
      if (existsSync(settings.ledgerPath) && existsSync(access.dbPath)) {
        const a = statSync(settings.ledgerPath); const b = statSync(access.dbPath);
        if (realpathSync(settings.ledgerPath) === realpathSync(access.dbPath) ||
            a.dev === b.dev && a.ino === b.ino) throw new Error();
      }
    } catch { throw new Error('Controlled synthetic access configuration denied.'); }
  }
  const authority = createActivationAuthority(settings);
  let app;
  try { app = createLocalAccess({ ...access, admissionGuard: authority }); }
  catch { authority.dispose(); throw new Error('Controlled synthetic access unavailable.'); }
  return Object.freeze({
    listen: (port) => app.listen(port),
    ingestWordPressEvent: (event) => app.ingestWordPressEvent(event),
    ...(typeof app.authenticateIdentity === 'function' ? { authenticateIdentity: (principal) => app.authenticateIdentity(principal) } : {}),
    ...(typeof app.registrationIdentity === 'function' ? { registrationIdentity: (principal) => app.registrationIdentity(principal) } : {}),
    ...(app.operator ? { operator: app.operator } : {}),
    activationBinding: () => authority.binding(),
    nextActivationSequence: () => authority.nextSequence(),
    // In-process test/operator API only. No signer or activation HTTP endpoint.
    activate: (envelope) => authority.activate(envelope),
    closeAuthority: () => authority.close(),
    async close() {
      let failed = false;
      try { authority.close(); } catch { failed = true; }
      try { await app.close(); } catch { failed = true; }
      try { authority.dispose(); } catch { failed = true; }
      if (failed) throw new Error('Controlled synthetic cleanup could not be fully verified.');
    },
  });
}
