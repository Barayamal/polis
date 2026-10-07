/** Fixed public projection; never persist an arbitrary private runner result. */
export function recoverySummary(value) {
  const deny = () => { throw new Error('Expanded recovery public evidence rejected.'); };
  if (!value || !['PASS', 'FAIL'].includes(value.outcome)) deny();
  const result = { outcome: value.outcome };
  const phases = new Set(['input-boundary', 'exact-sources-and-quiescence', 'four-store-terminal-snapshot',
    'new-wordpress-signing-config', 'closed-canonical-source-paths', 'fixed-provider-key-and-binding', 'stop-exact-source-applications',
    'encrypted-backup-and-independent-reread', 'fresh-portless-database-targets', 'actual-restore-and-row-hash-equivalence',
    'strict-mapping-replay-and-prior-boot-proof', 'strict-mapping-replay-and-closed-cold-start-proof',
    'independent-source-preservation-recheck', 'complete']);
  if (phases.has(value.phase)) result.phase = value.phase;
  const flags = ['actualExpandedRestoreCompleted', 'sourceCountsAndHashesPreserved', 'encryptedArchiveAuthenticated',
    'ownedRestoreContainersStopped', 'internalNetworkRetained', 'noSourceWrites', 'noExternalPortsPublished',
    'noSourceAppsStarted', 'noDeletionCommands', 'wordpressApplicationRestarted', 'realOidcProviderTested',
    'productionDisasterRecoveryProven', 'productionReady', 'restoredAccessServiceColdStarted',
    'restoredAccessServiceClosed', 'restoredAccessStayedClosed', 'oldSignedActivationRejected', 'originalRawCredentialReplayTested'];
  for (const key of flags) { if (typeof value[key] !== 'boolean') deny(); result[key] = value[key]; }
  for (const [key, limit] of [['actualDataStoresRestored', 4], ['encryptedArchiveComponents', 5], ['ownedRestoreContainersRetained', 2],
    ['restoredAccessProviderCalls', 100], ['restoredAccessNegativeChecks', 200]]) {
    if (!Number.isSafeInteger(value[key]) || value[key] < 0 || value[key] > limit) deny(); result[key] = value[key];
  }
  if (value.evidenceDirectory !== null && (typeof value.evidenceDirectory !== 'string' ||
      !/^deploy\/fncp\/expanded-recovery\/\.runtime\/expanded-[a-f0-9]{24}$/u.test(value.evidenceDirectory))) deny();
  result.evidenceDirectory = value.evidenceDirectory;
  if (result.outcome === 'PASS' && (result.actualDataStoresRestored !== 4 || result.encryptedArchiveComponents !== 5 ||
      result.ownedRestoreContainersRetained !== 2 || !result.actualExpandedRestoreCompleted || !result.sourceCountsAndHashesPreserved ||
      !result.encryptedArchiveAuthenticated || !result.ownedRestoreContainersStopped || !result.noSourceWrites ||
      !result.noExternalPortsPublished || !result.noSourceAppsStarted || !result.noDeletionCommands || result.productionReady ||
      result.productionDisasterRecoveryProven || result.realOidcProviderTested || result.wordpressApplicationRestarted || !result.evidenceDirectory ||
      !result.restoredAccessServiceColdStarted || !result.restoredAccessServiceClosed || !result.restoredAccessStayedClosed ||
      !result.oldSignedActivationRejected || result.originalRawCredentialReplayTested || result.restoredAccessProviderCalls !== 0 ||
      result.restoredAccessNegativeChecks < 1)) deny();
  return result;
}
