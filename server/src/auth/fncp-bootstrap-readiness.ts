/**
 * Application registration readiness only, not database/runtime health.
 * Import is pure. The existing helper and registration callbacks remain trusted
 * application code; this promise cannot cancel or time-bound their work.
 */
export function createFncpApplicationReadiness<T>(
  initialization: PromiseLike<T>,
  register: (helpers: T) => void | PromiseLike<void>,
  freshProfile: boolean,
  reportOrdinaryFailure: (error: unknown) => void
): Promise<void> {
  const ready = Promise.resolve(initialization)
    .then(register)
    .then(() => undefined)
    .catch((error: unknown) => {
      if (freshProfile) {
        // No cause, original message or caller-controlled metadata escapes.
        throw new Error("FNCP_FRESH_BOOTSTRAP_APPLICATION_NOT_READY");
      }
      try {
        reportOrdinaryFailure(error);
      } catch {
        // A logging failure must not replace the original readiness failure.
      }
      throw error;
    });

  // Ordinary legacy startup does not await readiness. Observe rejection without
  // converting the exported promise into success or introducing an unhandled
  // rejection. A fresh HTTPS owner must explicitly await this same promise.
  void ready.catch(() => undefined);
  return ready;
}
