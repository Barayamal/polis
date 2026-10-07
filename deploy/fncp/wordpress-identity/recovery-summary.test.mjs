import test from 'node:test';
import assert from 'node:assert/strict';
import { recoverySummary } from './recovery-summary.mjs';
const fixture = () => ({ outcome: 'PASS', actualExpandedRestoreCompleted: true, sourceCountsAndHashesPreserved: true,
  encryptedArchiveAuthenticated: true, ownedRestoreContainersStopped: true, internalNetworkRetained: true,
  noSourceWrites: true, noExternalPortsPublished: true, noSourceAppsStarted: true, noDeletionCommands: true,
  wordpressApplicationRestarted: false, realOidcProviderTested: false, productionDisasterRecoveryProven: false, productionReady: false,
  actualDataStoresRestored: 4, encryptedArchiveComponents: 5, ownedRestoreContainersRetained: 2,
  restoredAccessServiceColdStarted: true, restoredAccessServiceClosed: true, restoredAccessStayedClosed: true,
  oldSignedActivationRejected: true, originalRawCredentialReplayTested: false, restoredAccessProviderCalls: 0,
  restoredAccessNegativeChecks: 6,
  evidenceDirectory: 'deploy/fncp/expanded-recovery/.runtime/expanded-' + 'a'.repeat(24) });
test('expanded recovery evidence copies only fixed public counts, flags and generated relative directory', () => {
  const publicFields = fixture();
  assert.deepEqual(recoverySummary({ ...publicFields, privateKey: 'SECRET', phase: 'SECRET', source: { identity: 'SECRET' }, diagnostics: 'SECRET' }), publicFields);
});

for (const changes of [
  { restoredAccessServiceColdStarted: false }, { restoredAccessServiceClosed: false },
  { restoredAccessStayedClosed: false }, { oldSignedActivationRejected: false },
  { originalRawCredentialReplayTested: true }, { restoredAccessProviderCalls: 1 },
  { restoredAccessNegativeChecks: 0 }, { restoredAccessNegativeChecks: 'SECRET' },
  { restoredAccessNegativeChecks: 201 },
]) test('cold-start evidence rejects contradictory claim: ' + Object.keys(changes)[0] + ':' + String(Object.values(changes)[0]), () => {
  assert.throws(() => recoverySummary({ ...fixture(), ...changes }), /public evidence rejected/);
});

test('known cold-start and source-stop phases are reported without private callback fields', () => {
  for (const phase of ['strict-mapping-replay-and-closed-cold-start-proof', 'stop-exact-source-applications']) {
    const projected = recoverySummary({ ...fixture(), phase, coldStart: { session: 'SECRET' } });
    assert.equal(projected.phase, phase); assert.equal(Object.hasOwn(projected, 'coldStart'), false);
  }
});
test('expanded evidence denies wrong types, paths and contradictory success instead of persisting them', () => {
  for (const changes of [{ outcome: 'SECRET' }, { productionReady: true }, { noSourceWrites: false },
    { actualDataStoresRestored: 3 }, { encryptedArchiveComponents: 'SECRET' }, { encryptedArchiveComponents: 9 },
    { evidenceDirectory: '/private/secret' }, { evidenceDirectory: undefined }, { sourceCountsAndHashesPreserved: 'true' }])
    assert.throws(() => recoverySummary({ ...fixture(), ...changes }), /public evidence rejected/);
});
