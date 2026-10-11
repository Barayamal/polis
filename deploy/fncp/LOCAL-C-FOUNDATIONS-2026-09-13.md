# Option C — identity, activation and coordinated recovery increment

**13 September 2026 · Local implementation completed and tested · Production/launch HOLD.**

**Final shutdown verified `2026-09-13T13:52:21+10:00`:** no running task containers before VM shutdown; both task Compose projects and isolated Colima profile stopped; ports 3000, 5500, 5501, 8088, 8099, 8100, 8101, 8102 and 33079 closed. Original volumes, source, images and encrypted recovery evidence/key sets retained. [Pre-shutdown local WIP source/runtime snapshot](evidence/local-wip-2026-09-13T03-51-07-660Z/runtime.json) predates this final status paragraph; it is not a release attestation.

This continuation uses the official Pol.is fork/source and technical documentation. It adds Barayamal-specific local controls, not upstream-certified features. Source remains in `local/c-selfhost-20260913`, uncommitted and unpushed, based on `2898471efe889976670b09977ca6c08946dc04d9`. The earlier WordPress/browser proof remains preserved. No public surface, live account, correspondence, hosting resource, registration-retention record or participant data was changed.

## Delivered and verified

| Increment | Implemented | Evidence and boundary |
| --- | --- | --- |
| Identity protocol foundation | Maintained OIDC authorization-code flow, PKCE/state/nonce, real RSA/EC ID-token signatures, strict issuer/audience/expiry checks, one-use callbacks and issuer+subject-based opaque IDs | **48/48** intercepted synthetic protocol tests; scoped dependency audit **0 known advisories**. No real provider, browser callback or mailbox ownership proof. [Identity guide](identity-foundation/README.md) |
| Signed activation foundation | Ed25519 verifier, exact declared deployment/config/image/seed binding, fresh boot/recovery epoch, time-limited authority, monotonic replay ledger, separate local round opening and per-operation checks | **33/33** authority/API model tests, included in the combined suite. Expiry/restart/new authority invalidate old sessions/invitations. Declared bindings are not trusted production measurements. [Activation guide](activation-foundation/README.md) |
| Actual Pol.is origin integration | New temporary access/activation DBs, one invented account, one fixed-statement vote, expiry denial, new-activation stale-session denial and verified allowlist removal | **16/16** labelled checks passed at `2026-09-13T13:45:33+10:00`; [aggregate evidence](evidence/signed-origin-2026-09-13T03-45-33-599Z.json). Mailbox authentication deliberately remains simulated; OIDC is a separate foundation, not yet this end-to-end path. |
| Coordinated three-store recovery | Quiescent WordPress/MySQL + access SQLite + Pol.is/PostgreSQL snapshots; authenticated encryption; restore into fresh isolated targets; stale authority/replay tests | Actual restore **PASS** and **13/13** boundary tests, included in the combined suite. Checkpoint completed `2026-09-13T13:43:37+10:00`, before the later origin vote. [Verification](local-recovery/coordinated-VERIFICATION-2026-09-13.md), [procedure](local-recovery/README-C-COORDINATED-RECOVERY.md) |
| Repeatable local and future CI checks | New suites added to the local PR-gate definition; isolated locked identity job is a required dependency of the final gate | Combined local deployment/access/browser/WP/recovery/activation suite **235/235**, separate OIDC **48/48**; whitespace check passed. Workflow permission/runner/checkout invariants updated and passing. **GitHub CI was not submitted or run.** |

Reported suites overlap with earlier component checks; their totals are not a unique security-coverage metric. Node 26.8.2 ran the current local tests. The workflow targets Node 24 for contracts/OIDC, but that remote execution is not claimed here.

## Review fixes completed

- Snapshot activation bindings before validating them, including accessor-bearing inputs.
- Latch activation closed through transient ledger failure; recovered storage cannot resume the old lease.
- Always attempt API and authority cleanup independently, even if storage fails.
- Reject store aliases through lexical/canonical paths and device/inode identity; reject guard override and known provider/conversation mismatch.
- Enforce the 20-fixture capacity in controlled mode, including startup rejection of an oversized existing store.
- Correct recovery failure flags so directory creation cannot be mistaken for authenticated backups; explicitly include synthetic credential hashes inside the encrypted scope.
- Verify distinct seed texts/TIDs, exact new restore destinations, pending/running mount and network state, and independent cleanup inventories. Fix PostgreSQL's function-argument limit in the 62-table count query without weakening the scope checks.

Independent read-only reviews found no remaining concrete bypass in the bounded synthetic activation path or source-overwrite/cleanup/encryption-authentication defect in the bounded recovery helper. That review does not establish complete security or production readiness.

## Final synthetic data position

The original WordPress/access state was not reopened by this increment: three persistent fixture approvals remain revoked, six approval/revocation events remain applied, the round remains closed, and no original sessions were created. The later activation smoke used a separate temporary access store and removed its own one allocated provider entry.

Independent PostgreSQL readback after that smoke: **0 whitelist rows, 15 distinct fixed seeds, 28 synthetic vote rows, 21 terminal provider-operation records**. The recovery checkpoint contained 27 votes/20 tombstones; it is not retroactively claimed to include the later vote. No genuine response content was read or reported. Temporary test/restore files, containers and networks were removed; original source/data and private encrypted archives/keys were preserved.

The five application image IDs observed by the actual-origin proof match the previously scanned artifacts. Their previous **0 Critical / 0 High / 15 Medium** result remains a dated, scoped result; no new scan or complete release assurance is claimed. QA database/identity-simulator findings and the separate root-user assertion remain unresolved. New host-side identity/activation code is not automatically included in those five Docker images or their scan evidence.

## Reproduce locally

From the isolated clone root, with Node 26 installed:

```sh
node --test deploy/fncp/*.test.mjs deploy/fncp/local-access/*.test.mjs deploy/fncp/local-recovery/*.test.mjs deploy/fncp/local-browser/*.test.mjs deploy/fncp/local-wordpress-runtime/*.test.mjs deploy/fncp/activation-foundation/*.test.mjs
npm --prefix deploy/fncp/identity-foundation ci --ignore-scripts --no-fund
npm --prefix deploy/fncp/identity-foundation test
```

The `npm ci` step downloads only the locked public packages; it does not contact an identity provider or send project correspondence. The tests need no cloud account. The actual-origin and coordinated-recovery procedures are separate: **never run a voting smoke concurrently with the recovery writer freeze**. Use each linked guide's exact scope/sequence.

## What remains, in order

1. Choose the production-specific infrastructure/identity target using the owner decision pack. The existing recommendation is C1 managed databases/identity; C2 single-host and C3 self-hosted identity remain alternatives. None is provisioned or costed as an all-inclusive service. Provider-neutral local review can continue without this decision.
2. Implement a separately reviewed production adapter joining genuine OIDC account sessions to WordPress approvals, invitations and the participant gateway. Add secure browser/callback behavior, account recovery and approved mail delivery. Do not convert the fixture-only proof by deleting guards.
3. Integrate trusted deployment measurement, operator signer custody, distributed revocation/whole-round closure, identity/activation-state recovery, cross-instance concurrency and independent backup/key storage. The local verifier cannot reverse a vote already dispatched before expiry; no automatic replay is allowed.
4. Prepare a source-frozen review candidate and complete required CI, current upstream/security review, exact-image provenance, full application failure/recovery checks and operating-cost evidence. Sending code or opening a PR requires Dean's exact approval; no repository submission occurred here.
5. Only after owner acceptance of that exact candidate, seek separate approval for infrastructure deployment and later synthetic hosted QA. Real participant testing, invitations and opening any public surface require their own approval. PR #27 is not GO authority; provisional October dates do not activate anything.

Approval/identity/heritage are distinct: the recorded owner scope is self-attestation plus round approval, not verification of Indigenous heritage. This engineering increment does not add ancestry-document collection, alter eligibility policy or perform historical registration deletion.

## Primary source trail

- [Official Pol.is source/self-hosting instructions](https://github.com/compdemocracy/polis) and [configuration reference](https://github.com/compdemocracy/polis/blob/edge/docs/configuration.md).
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html); exact maintained-library references are in the identity guide.
- [PostgreSQL 17 dump](https://www.postgresql.org/docs/17/app-pgdump.html) and [restore](https://www.postgresql.org/docs/17/app-pgrestore.html); MySQL/SQLite and authenticated-encryption references are in the recovery guide.

No external sends, publication, deployment, funds committed, real identities, participant testing or live registration-retention action were performed.
