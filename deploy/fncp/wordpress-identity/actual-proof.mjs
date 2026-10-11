/** Explicit actual-local WordPress + Pol.is proof. Never external; one invented vote.
 * Source/stores are fresh except the already-authorised disposable Pol.is stack.
 * Original WordPress DB is read only by aggregate/hash observation helpers.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync, existsSync, writeFileSync, mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual, parseEnv } from 'node:util';
import { createIntegratedJourney } from '../integrated-journey/proof-harness.mjs';
import { observedBinding, accessPreservationHash, wordpressPreservationSnapshot, createPolisObservation } from '../integrated-journey/real-origin-smoke.mjs';
import { validateConfiguration } from '../local-recovery/recovery-proof.mjs';
import { readStagingProvider } from '../local-access/staging-config.mjs';
import { prepareIdentityWordPress, startIdentityWordPress, stopIdentityWordPress, stopIdentityWordPressApplication, recoveryWordPressSource, runIdentityPhp } from './runtime.mjs';
import { createWordPressIdentityClient } from './wordpress-client.mjs';
import { exerciseWordPressIdentityJourney } from './journey.mjs';
import { recoverySummary } from './recovery-summary.mjs';

const DEPLOY = fileURLToPath(new URL('../', import.meta.url));
const assert = (value) => { if (!value) throw new Error('WordPress identity proof boundary failed.'); };
const same = (a, b) => assert(isDeepStrictEqual(a, b));
export async function runWordPressIdentityProof({ seamless = false, recovery } = {}) {
  if (typeof seamless !== 'boolean' || recovery !== undefined && (typeof recovery !== 'function' || !seamless)) throw new Error('Explicit local proof mode required.');
  process.umask(0o077);
  const report = { classification: 'ACTUAL_LOCAL_WORDPRESS_STRICT_IDENTITY_POLIS_SYNTHETIC_PROOF', outcome: 'FAIL', checks: [],
    browserEvidence: 'HTTP_COOKIE_CSRF_PROTOCOL_NOT_RENDERED_BROWSER', issuerEvidence: 'CRYPTOGRAPHIC_INTERCEPTED_SYNTHETIC_OIDC',
    operatorEvidence: 'INVENTED_WP_OPERATOR_COOKIE_FROM_PRIVATE_CLI_NOT_REAL_LOGIN',
    registrationEvidence: 'FRESH_LOCAL_WORDPRESS_IMMUTABLE_ACCOUNT_BOUND_ROWS',
    eligibilityVerified: false, realEmailDelivery: false, publicSurfacesChanged: false, productionReady: false,
    offlineReceiptCaveat: 'REGISTRATION_ONLY_VALID_UNTIL_EXPIRY_EVEN_AFTER_LOGOUT_NOT_ENCRYPTED',
    originalAccessBytesUnchanged: false, originalWordPressAggregateAndJournalUnchanged: false,
    wordpressPreservationEquivalence: 'ALL_TABLE_ROW_COUNTS_AND_EXACT_JOURNAL_HASH_NOT_FULL_DATABASE_EQUIVALENCE' };
  if (seamless) {
    report.classification = 'ACTUAL_LOCAL_SEAMLESS_REGISTRATION_STRICT_IDENTITY_POLIS_SYNTHETIC_PROOF';
    report.registrationEvidence = 'THREE_DECLARATIONS_THROUGH_BFF_PRIVATE_WORDPRESS_HANDOFF';
    report.offlineReceiptCaveat = 'REGISTRATION_ONLY_RECEIPT_REMAINS_SERVER_SIDE_NOT_BROWSER_VISIBLE';
  }
  let phase = 'preflight'; let h; let wp; let underlying; let binding; let preservation; let observe; let polisBefore;
  let voteAttempts = 0; let votes = 0; const allocated = new Set(); const terminalChecked = new Set();
  try {
    assert(process.env.FNCP_LOCAL_SYNTHETIC_MODE === 'fixture-only');
    const env = parseEnv(readFileSync(resolve(DEPLOY, '.env.staging'), 'utf8'));
    const config = validateConfiguration(env, 'synthetic-local-restore-proof', existsSync(resolve(DEPLOY, '.synthetic-bootstrap-restart')));
    const staging = readStagingProvider('fixture-only'); underlying = staging.provider;
    assert(config.conversation === staging.conversationId && config.project === 'fncp-polis-staging');
    binding = observedBinding(config.conversation, randomUUID());
    preservation = { access: accessPreservationHash(), wordpress: wordpressPreservationSnapshot() };
    const seeds = JSON.parse(readFileSync(resolve(DEPLOY, 'seed-statements.json')));
    const ids = env.FNCP_FIXED_STATEMENT_IDS.split(',').map(Number);
    assert(ids.length === 15 && ids.every(Number.isSafeInteger) && new Set(ids).size === 15);
    observe = createPolisObservation(config, seeds, ids); polisBefore = observe();
    const provider = { conversationId: config.conversation,
      async allowlist(operation, xid) {
        assert(/^fncp_[A-Za-z0-9_-]{43}$/u.test(xid));
        if (operation === 'upsert' && !allocated.has(xid)) {
          assert(allocated.size < 2); const current = await underlying.allowlist('readback', xid);
          assert(!current.present && current.operationVersion === null); allocated.add(xid);
        }
        assert(allocated.has(xid)); return underlying.allowlist(operation, xid);
      },
      async participate(kind, xid, values) {
        assert(allocated.has(xid)); if (kind === 'vote') { assert(voteAttempts === 0); voteAttempts++; }
        const result = await underlying.participate(kind, xid, values); if (kind === 'vote') votes++; return result;
      },
    };
    const secrets = { eventSecret: randomBytes(32).toString('base64url'), challengeSecret: randomBytes(32).toString('base64url'), registrationSecret: randomBytes(32).toString('base64url') };
    phase = 'fresh-wordpress-preparation'; wp = await prepareIdentityWordPress(secrets);
    phase = 'strict-harness-start'; h = await createIntegratedJourney({ provider, binding, wordpressRegistration: { ...secrets, receiverPort: 8101, seamlessRegistration: seamless } });
    phase = 'fresh-wordpress-start'; await startIdentityWordPress(wp);
    const helper = fileURLToPath(new URL('./operator-proof.php', import.meta.url));
    phase = 'fresh-wordpress-aggregate';
    const fresh = JSON.parse((await runIdentityPhp(wp, helper, ['aggregate'])).stdout);
    assert(fresh.freshInstance && fresh.users === 1 && fresh.legacyHandlerAbsent && fresh.externalMailBlocked);
    report.freshWordPressLegacyHandlerAbsent = true; report.externalMailBlocked = true;
    phase = 'invented-private-operator-session';
    const operatorSession = JSON.parse((await runIdentityPhp(wp, helper, ['operator-session'])).stdout);
    phase = 'wordpress-to-polis-journey';
    const journey = await exerciseWordPressIdentityJourney({ h, seamless, wordpress: () => createWordPressIdentityClient(),
      operator: createWordPressIdentityClient(undefined, operatorSession), observer(label) {
        report.checks.push(label); console.log('PASS ' + label);
      } });
    assert(journey.inventedVotes === 1 && journey.registrations === 2 && votes === 1 && allocated.size === 2);
    phase = 'fresh-wordpress-final-independent-readback';
    const finalWp = JSON.parse((await runIdentityPhp(wp, helper, ['aggregate'])).stdout);
    assert(finalWp.registrations === 2 && finalWp.approvalSubjects === 2 && finalWp.acknowledgedTerminalSubjects === 2 && finalWp.pendingEvents === 0);
    report.freshWordPressFinalAggregate = finalWp;
    if (recovery) {
      phase = 'expanded-recovery-quiescence';
      for (const xid of allocated) {
        const row = await underlying.allowlist('readback', xid);
        assert(!row.present && row.operationVersion === 2); terminalChecked.add(xid);
      }
      await h.closeAuthority(); report.ownAuthorityClosed = true;
      same(observedBinding(binding.conversationId, binding.recoveryEpoch), binding);
      report.runtimeBindingUnchanged = true;
      await h.close({ preserveStores: true }); report.ownHarnessClosed = true;
      await stopIdentityWordPressApplication(wp);
      const closed = JSON.parse((await runIdentityPhp(wp, helper, ['close-guests'])).stdout);
      assert(closed.remainingGuestSessions === 0 && closed.registrationsPreserved === 2 && closed.operatorSessionsClosed && closed.terminalOnly);
      report.freshWordPressQuiescence = closed;
      phase = 'expanded-recovery';
      const expanded = await recovery({ mode: 'expanded-synthetic-restore-only',
        wordpress: await recoveryWordPressSource(wp), ...h.privateRecoveryContext(),
        wordpressSecrets: { event: secrets.eventSecret, challenge: secrets.challengeSecret, registration: secrets.registrationSecret } });
      report.expandedRecovery = recoverySummary(expanded);
      if (report.expandedRecovery.phase) phase = 'expanded-recovery:' + report.expandedRecovery.phase;
      assert(expanded.outcome === 'PASS');
    }
    report.outcome = 'PASS';
  } catch (error) {
    // Only our static journey assertion label is safe, never an upstream message.
    if (error.message?.startsWith('WP journey: ') && /^[A-Za-z0-9 :,-]{1,180}$/u.test(error.message)) phase = error.message;
    report.failurePhase = phase;
  } finally {
    let cleaned = true;
    try { if (h && !report.ownHarnessClosed) { await h.closeAuthority(); report.ownAuthorityClosed = true; } } catch { cleaned = false; }
    let removed = 0;
    for (const xid of allocated) {
      if (terminalChecked.has(xid)) { removed++; continue; }
      try { await underlying.allowlist('remove', xid); const row = await underlying.allowlist('readback', xid);
        assert(!row.present && row.operationVersion === 2); removed++; } catch { cleaned = false; }
    }
    report.allocatedIdentities = allocated.size; report.terminallyRemovedIdentities = removed;
    report.inventedVoteAttempts = voteAttempts; report.acceptedInventedVotes = votes;
    if (binding && preservation && polisBefore) {
      try {
        if (!report.runtimeBindingUnchanged) {
          same(observedBinding(binding.conversationId, binding.recoveryEpoch), binding);
          report.runtimeBindingUnchanged = true;
        }
        same(accessPreservationHash(), preservation.access); report.originalAccessBytesUnchanged = true;
        same(wordpressPreservationSnapshot(), preservation.wordpress); report.originalWordPressAggregateAndJournalUnchanged = true;
        const after = observe(); same(after.whitelistRows, polisBefore.whitelistRows);
        same({ ...after.aggregate, voteRows: polisBefore.aggregate.voteRows, latestVoteRows: polisBefore.aggregate.latestVoteRows }, polisBefore.aggregate);
        same(after.aggregate.voteRows - polisBefore.aggregate.voteRows, votes);
        same(after.aggregate.latestVoteRows - polisBefore.aggregate.latestVoteRows, votes);
        report.finalAggregate = { whitelistRows: after.whitelistRows, fixedStatements: 15, inventedVoteRows: after.aggregate.voteRows,
          inventedVoteRowDelta: votes };
        report.imageIds = binding.images; report.configSha256 = binding.configSha256; report.seedSha256 = binding.seedSha256;
      } catch { cleaned = false; report.failurePhase ??= 'independent-final-observation'; }
    }
    try { if (wp) { await stopIdentityWordPress(wp); report.freshWordPressStopped = true; } } catch { cleaned = false; }
    try { if (h) { await h.close({ preserveStores: true }); report.ownHarnessClosed = true; } } catch { cleaned = false; }
    report.newStoresRetained = Boolean(wp && h && report.ownHarnessClosed);
    report.newWordPressPrepared = Boolean(wp);
    if (!cleaned || !report.ownHarnessClosed || !report.freshWordPressStopped || removed !== 2 ||
        !report.originalAccessBytesUnchanged || !report.originalWordPressAggregateAndJournalUnchanged) report.outcome = 'FAIL';
    report.generatedAt = new Date().toISOString();
    mkdirSync(resolve(DEPLOY, 'evidence'), { recursive: true, mode: 0o700 });
    const path = resolve(DEPLOY, 'evidence', `${seamless ? 'seamless-registration' : 'wordpress-identity'}-${report.generatedAt.replace(/[:.]/g, '-')}.json`);
    writeFileSync(path, JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    console.log(`WORDPRESS_IDENTITY_PROOF=${report.outcome}; phase=${report.failurePhase ?? 'complete'}; evidence=${path}`);
  }
  return report;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runWordPressIdentityProof().then((report) => { process.exitCode = report.outcome === 'PASS' ? 0 : 1; })
    .catch(() => { console.error('WORDPRESS_IDENTITY_PROOF=FAIL; diagnostics redacted.'); process.exitCode = 1; });
}
