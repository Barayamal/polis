# Option C — fresh-only self-hosting foundation

> Portability note — 7 October 2026: workstation paths were removed, and artifacts outside this source snapshot are labelled retained local evidence. Dated results below remain historical; this edit adds no runtime or release claim.

**KEEP_CLOSED / SYNTHETIC_FOUNDATION_ONLY · 2026-09-13T21:21:52+10:00 · Australia/Sydney**

The next self-hosting increment is implemented: new private configuration and ownership tracking, guarded lifecycle coordination, exact Pol.is bootstrap-result validation, and a separate WordPress preparation path accepting only verified pristine release bytes. These replace neither the retained historical runtime nor the existing public pages.

**This is source/model-tested infrastructure, not a completed fresh WordPress/Pol.is deployment. Concrete Docker and ordinary-bootstrap adapters, actual egress isolation and the combined native-browser/actual-service journey remain unimplemented or unrun.**

## Completed in this increment

1. **Fresh private Pol.is foundation.** The zero-argument factory creates a new exclusive private temporary directory, independent database/gateway/provider/encryption/login secrets, JWT keys, random owned resource names and literal local configuration. Both participation gates begin enabled and bound to the same absent conversation. There is no caller-selected existing directory, project, environment template or manifest to adopt.
2. **Guarded lifecycle coordination.** The foundation checks exact context, recorded image subjects/architecture, required loopback ports and absence of newly named resources through an injected probe. It repeats that probe immediately before starting. Attempt records precede injected mutation dispatch; returned container IDs, labels and configuration must match before they can be used for a later stop. This is fake-driver coverage, not Docker inspection.
3. **Cancellation and uncertain-result handling.** A valid stop latches cancellation even during a pending callback, preventing later startup/bootstrap progress. A busy call rejects to avoid reentrant deadlock; the caller retries after the pending operation settles. Stops target only verified owned IDs in reverse order, continue after another stop fails and never replay uncertain dispatched stops. New private files/resources are preserved on uncertainty; there is no volume deletion or prune operation.
4. **Pol.is result validation.** The pure validator accepts exactly one conversation ID and fifteen distinct PostgreSQL integer statement IDs in their observed order. It rejects coercion, proxy/accessor inputs, extra fields, duplicates, overflow and the initial absent binding. It does not assume statement IDs 0–14. A complete bound configuration is published exclusively, still closed and unapplied; validation does not authenticate its provider source or grant activation.
5. **Separate pristine WordPress input.** The new source factory takes exact plain fixed unshared ArrayBuffer bytes, checks size/gzip/digest and holds a defensive copy behind a private brand. The fresh preparation API accepts that brand plus three independent signing secrets, with no path/URL/hash override or legacy archive fallback. It rechecks the copied archive and complete fresh core/configuration tree before later runtime commands. The legacy API remains for historical workflows only.
6. **Fresh official release verification.** A normally certificate-validated HTTPS GET from the official WordPress archive produced 35,356,041 bytes matching the pinned 7.1 SHA-256. The real source factory accepted them in memory. No archive was saved, extracted, installed or started. Future runtime acquisition must fetch and verify its own bytes again.
7. **Tests and documentation.** Added 49 tests, included the new tests in the local CI definition, updated the fresh-runtime specification and WordPress guide, and refreshed the four files in Barayamal → Community Pulse. No remote CI was requested.

Review fixed four issues before final verification: the statement-ID configuration field, the actual Pol.is login/encryption secret fields, stale preflight reuse and shutdown requests arriving during an awaited start/bootstrap callback. Attempt journal counts now advance only after the exclusive file write succeeds.

## Verification

| Check | Result | Scope |
| --- | --- | --- |
| Full ordinary suite, Node 24.21.0 | 1,549/1,549 | No failed, cancelled or skipped tests |
| Full ordinary suite, Node 26.8.2 | 1,549/1,549 | Same unique suite, not another 1,549 distinct cases |
| New tests included above | 49 | Bootstrap 7 + lifecycle 31 + WordPress 11 |
| Focused lifecycle suite | 31/31 on each runtime | Fake probes/drivers; no containers |
| Focused WordPress suite | 23/23 on each runtime | Includes 12 existing checks and 11 new checks |
| PHP checks | 59/59 | Three pure PHP/WordPress-stub groups: 23 + 23 + 13 |
| Actual official WordPress bytes | PASS | Memory-only digest/brand verification |
| Limited runtime source graph | PASS, unchanged 27 files / 230,564 bytes | Not complete release closure; new files inventoried separately |
| Final known local test ports | All 12 refused connections | Only listed loopback ports, not a system-wide process claim |
| Dedicated Colima profile | NOT_RUNNING | Read-only status; no VM or Docker start |

Positive WordPress preparation tests use newly generated inert tar fixtures and isolated copies of the test modules with fixture-only pins. They do not demonstrate extraction/preparation of the real 7.1 release. The production source pin was not changed.

The [earlier two-account native HTTPS result](./LOCAL-C-CROSS-ACCOUNT-2026-09-13.md), dated 20:57:15, remains historical: 14 native journeys with modeled WordPress/Pol.is and an invented issuer. It was **not rerun** in this increment. Its revocation proof occurs after both accounts are revoked; selective revocation while the second stays approved is still outstanding.

## Evidence and limitations

- Aggregate continuation evidence (retained local evidence, `evidence/fresh-foundation-continuation-2026-09-13.json`; not included in this source snapshot) records final tests, source verification, exact changed-source hashes and boundaries.
- Source inventory (retained local evidence, `evidence/fresh-foundation-source-closure-2026-09-13.json`; not included in this source snapshot) contains the unchanged limited runtime graph and nine additional source/test/CI files. It is not a complete image/dependency closure, SBOM or deployable release.
- [Fresh-runtime API guide](./fresh-runtime/README.md) gives the focused test command, callback contract and remaining implementation sequence.
- [Full actual-service plan](./LOCAL-C-FRESH-RUNTIME-PLAN-2026-09-13.md) remains the specification for the unexecuted end-to-end integration.

Injected callbacks are trusted functions and can run arbitrary code; they are not a sandbox or authenticated Docker evidence. Their test booleans do not prove egress denial. The current two-image foundation lacks the separately pinned ordinary-bootstrap image, full runnable configuration and concrete runtime adapter. It cannot start a real service by itself.

WordPress member paths are checked before extraction; link/type checks follow extraction. Safety relies on the exact trusted release digest, not a generic hostile-archive guarantee. File identity checks detect ordinary link/mode/content drift but are not race-proof against concurrent same-user ancestor replacement. Generated private material and callback arguments must never be included in public evidence.

No retained configuration, private keys, stores or archives were read; no retained resource was restarted, stopped or deleted. The ordinary tests removed only their exclusively created synthetic temporary fixtures. All 12 known test ports were independently refused; nothing was started for manual participant testing.

No public surface was modified or freshly inspected. No external messages, submissions, Git commits/pushes/PRs, remote CI, package installation, image pull/build/scan, retention operation, spending or deployment occurred. The only new binary acquisition was the disclosed memory-only official WordPress source check. PR#27 is not GO authority.

## Next steps — in order

1. **Implement the concrete runtime adapter locally.** Use the new capability and exact owned-resource records for a narrowly scoped Docker preflight/start/inspect/stop adapter. Do not use old staging scripts, `.env.staging`, old archives or broad cleanup. Fake-driver development can continue while Colima is stopped.
2. **Complete bootstrap prerequisites.** Review and pin the ordinary Pol.is bootstrap image and local identity/TLS inputs separately from the dedicated gated server image. Implement deny-egress topology and verify exact loopback exposure. Do not pull/build, switch contexts or start a shared VM as an automatic fallback.
3. **Perform the fresh actual-service proof only when that path is complete and its runtime prerequisite is resolved.** Create only new databases/configuration/keys; bootstrap an actual conversation and observed seed IDs; close the bootstrap helper; compose native authentication with actual WordPress registration/decision/outbox and actual Pol.is access. Use two invented accounts, no sent invitations or real records.
4. **Prove forwarded-link denial, rightful redemption and selective warm revocation.** Then verify terminal revocation, fresh-state recovery and exact owned-resource closure. A successful model test does not satisfy these actual-service assertions.
5. **Keep production decisions separate.** C is the selected direction, but C1/C2/C3 hosting/operations and all-inclusive costs remain undecided/NOT COSTED. The owner pack (retained local evidence, `C-PRODUCTION-DECISIONS.md`; outside this repository) retains practical choices and exact replies. No spending, external communication, deployment or participant test is approved by this work.

The [official Pol.is Docker/source instructions](https://github.com/compdemocracy/polis/blob/stable/README.md) and [configuration guide](https://github.com/compdemocracy/polis/blob/stable/docs/configuration.md) were consulted for the upstream foundation. Their quick-start does not certify Barayamal's custom eligibility, invitation or activation controls; its global certificate-installation step was not executed. The [official WordPress archive](https://wordpress.org/download/releases/) supplied the separately checked release.
