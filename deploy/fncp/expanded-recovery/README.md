# Expanded synthetic recovery proof

This is a local, closed-recovery experiment for the **new** WordPress identity-registration journey. It is not a production backup service, launch approval, migration of the real site, or extension of the earlier legacy three-store restore claim.

The entry point is `runExpandedRecovery(input)` in `run.mjs`. Importing it performs no I/O. There is deliberately no CLI that accepts private keys, credentials or source paths as shell arguments.

## Latest continuation: actual restored access service

The [cold-restart continuation](../LOCAL-C-COLD-RESTART-REVIEW-2026-09-13.md) passed
at `2026-09-13T05:51:16.108Z`. It performed a new four-store restore, then exercised
the actual controlled access/activation service on its fresh restored SQLite files:
10 negative loopback HTTP checks, old signed activation rejected, zero provider
calls, terminal journal retries non-granting and listener closure verified. The
current two-subject journey added one invented vote; final aggregate was 0 whitelist,
15 fixed statements and 34 invented vote rows. [Aggregate evidence](../evidence/seamless-registration-2026-09-13T05-51-16-108Z.json).

The current expanded suite is **124/124 PASS**, included in the 736-test combined
suite verified on macOS Node 24.21.0 and 26.8.2. The cold identity verifier accepts
no principal. Invalid replay canaries are explicitly not original raw credentials.
This is still not a real issuer, rendered browser or full WordPress/BFF/provider
application restart. The prior data-only record below remains historical.

## Earlier data-only evidence levels

- `node --test deploy/fncp/expanded-recovery/*.test.mjs`: **116/116 passed** during implementation. Tests use invented buffers, pure contracts and newly allocated temporary SQLite files. They do not query Docker, existing databases, WordPress or an external identity provider. The SQLite tests really create/copy/read fresh stores and instantiate the current activation authority without starting listeners.
- Full expanded runtime restore: use the exact `outcome` and signed aggregate result for the particular invocation. A passing unit suite does **not** mean the MySQL/PostgreSQL restore ran. An initial invocation failed at signing-configuration preflight before source app stops, database snapshots or target creation; it was not a successful restore. That check was corrected to use the fresh instance's generated private PHP constants rather than its DB/admin-only credentials JSON, with a regression test.
- A successful expanded invocation requires all four actual restored stores, source preservation checks, prior-boot denial and owned target shutdown to finish. Failure retains the newly created private evidence/work and reports a fixed redacted phase; it must not be silently called success or replay the registration/vote journey.

### Earlier actual data-only result — 13 September 2026

**PASS**, recorded at `2026-09-13T05:27:00.308Z`, in the [aggregate seamless-registration evidence](../evidence/seamless-registration-2026-09-13T05-27-00-308Z.json). The expanded recovery run reference is `8e993c62547983a86d0b7a07`.

- Four actual data stores restored; five encrypted archive components authenticated.
- Original source counts and hashes preserved; fresh restore state passed the strict registration/mapping/replay/terminal-tombstone checks and old signed-boot rejection.
- Two newly allocated portless restore containers stopped and retained; their new internal network retained. No source app was started, no external port published, and no deletion command used by the recovery runner.
- The fresh WordPress source contained two registrations and two acknowledged terminal subjects, zero pending events and zero remaining guest sessions; its invented operator sessions were closed before backup.
- The enclosing fresh journey passed 26 protocol stages, including one accepted invented Pol.is vote, forwarded-invitation denial, warm-session revocation and a post-close denial. Its final dedicated Pol.is aggregate was zero whitelist entries, 15 fixed statements and 33 historical synthetic vote rows, a delta of **one** for this successful new journey.

The earlier preflight-failed recovery followed a separately completed, verified one-vote synthetic journey. Its accepted vote was not replayed as an uncertain operation or erased: there were two separately allocated, verified one-vote journeys in the implementation turn. Only the later invocation established the successful expanded restore above.

This runtime result is still **not** a rendered post-restore WordPress/BFF browser run, real OIDC login, real mailbox/heritage verification or production disaster-recovery assurance. The parent run separately records the original legacy store preservation; the expanded runner excluded that old WordPress database from its backup and restore scope.

## Exact scope

| Component | Backed up and checked | Restore target |
| --- | --- | --- |
| Fresh WordPress MySQL | All 12 synthetic WordPress tables; immutable registration registry; consent/self-attestation facts; assertion tombstones; consumed challenges; acknowledged approval/revocation journal; no warm guest/admin sessions | New cached-image MySQL container, empty database, internal network, no published ports |
| Strict access SQLite | Exact seven-table schema, issuer/subject-derived mappings, revoked approvals, used invitations, zero sessions, applied WordPress event digests | New private SQLite file; never the source path |
| Activation SQLite | Exact two-table schema, closed state, signed activation history and replay sequence floor | New private SQLite file; current authority assigns a fresh boot and recovery epoch, remains inactive |
| Dedicated synthetic Pol.is PostgreSQL | Entire dedicated database, exact 15 synthetic seeds, synthetic votes, zero whitelist entries, terminal provider tombstones | New cached-image PostgreSQL container, empty database, internal network, no published ports |
| Synthetic key continuity | Mapping key/version and invented subjects; configured issuer/client; activation **public** verification key and prior envelope; three WordPress keys; two private provider credentials | Separate authenticated encrypted component, decrypted only in memory for verification |

The five archive components use independent random AES-256-GCM nonces and associated data binding the run, component name and exact scope hash. An HMAC-authenticated manifest binds the complete component set, byte counts, file modes and hashes. Each file is independently re-read and authenticated before a target is created. The encryption key is mode `0600` in a separate private directory. This is **same-machine** separation, not offsite key custody.

Private `0700` working directories retain SQLite backup and restored copies at `0600`; these restored/work files are **not encrypted**. Only the archive components are encrypted. `.runtime/` is ignored by Git. Do not attach, publish, commit or print the archive, key, SQLite files, source snapshots, recovered key package or returned private contract events. Aggregate reports contain counts and hashes, not identifiers or credentials.

## Safe execution contract

The parent proof owns creation and closure of the fresh WordPress instance and strict journey. Pass the following only as private in-process values:

```js
const result = await runExpandedRecovery({
  mode: 'expanded-synthetic-restore-only',
  wordpress: await recoveryWordPressSource(freshWordPressInstance),
  ...closedJourney.privateRecoveryContext(),
  wordpressSecrets: { event, challenge, registration },
});
```

`FNCP_LOCAL_SYNTHETIC_MODE=fixture-only` must already be set. The context is fixed to `colima-fncp-c-20260913`.

The exact input contains:

- `wordpress`: `{directory, composePath, containerId, project, database, databaseUser, volume}` from the newly branded identity runtime, never the old WordPress database.
- `sourceAccessPath`, `sourceActivationPath`: canonical, private, single-link files in the same newly allocated `fncp-integrated-journey-*` temporary directory. Known macOS temporary-directory aliases are resolved once after strict path containment checks.
- `sourceBinding`: the complete source activation binding including boot ID, recovery epoch, configuration/seed hashes and five application-image identities.
- `identity`: `{key: Buffer, keyVersion: 1, issuer, clientId, syntheticSubjects}`. Only the fixed intercepted synthetic issuer/client and bounded explicitly invented subjects are allowed. The HMAC mapping is re-derived from **issuer + subject**, not email or an email hash.
- `activation`: `{publicKey, keyId, priorEnvelope}`. No activation private signing key is backed up or used to open the restored installation.
- `wordpressSecrets`: the three independent signing keys, checked against exact generated constant lines in the fresh private WordPress configuration. PHP is not executed for that comparison.

## Step-by-step operator sequence

1. Complete one specifically authorized **new synthetic** registration journey. Keep its stable test identity key and private recovery context in memory; do not print them. A recovery failure is not permission to duplicate an uncertain vote.
2. Revoke every mapped identity through the actual new WordPress approval path and verify delivery to the strict access/provider ledgers. No unregistered orphan mappings are allowed in this checkpoint.
3. Close the strict round and signed authority. In the fresh WordPress instance only, clear guest sessions, mark retained challenges consumed, and destroy the sole invented admin's WordPress session tokens. Preserve registrations, assertion tombstones and the delivered journal.
4. Close the BFF, access server, signed-event receiver and fresh WordPress PHP listener; preserve their new SQLite files. Keep the fresh MySQL and dedicated synthetic PostgreSQL databases running. The runner accepts the exact old synthetic WordPress database as a metadata-verified bystander only, without querying it or reading its files.
5. Invoke the runner privately. It verifies the exact five source application containers and their bound images, **stops** those containers, and checks quiescence. It never starts or reconfigures a source service. It verifies empty authority/session/whitelist state, schemas, registration/mapping/journal/tombstone correspondence and all-table content hashes before backup.
6. The runner creates five authenticated encrypted archive components. It takes both SQLite snapshots using Node's backup API, and uses database-native MySQL and PostgreSQL dump tools. Source hashes/counts are rechecked before target creation.
7. It creates two brand-new empty database containers from exact cached images using `--pull=never`, on a new internal network, with no published ports or host data mounts. Database data and initialization directories are bounded tmpfs mounts. It refuses any source container ID, image/label/network/mount mismatch or non-empty destination. It never uses `--clean`, `DROP`, `down -v`, `rm` or source overwrite as a recovery shortcut.
8. It restores the MySQL/PostgreSQL archives and two fresh SQLite files. MySQL and PostgreSQL schema metadata, row counts and deterministic **all-table row-content hashes** must match. Registration/journal metadata, strict mappings and tombstones must agree exactly. SQLite schema and contents must match before the intentional fresh-boot change.
9. The current controlled access/activation implementation opens only the fresh restored SQLite files, assigns a new boot/recovery binding, retains replay history and rejects the genuine prior signed envelope. One temporary loopback listener exercises negative routes while closed; no provider calls, new activation, voter session or invitation are allowed. Stale approval and terminal journal retries remain non-granting. The listener is closed and independently checked before return, and exact access/journal state must be preserved. Original raw bearer/invitation strings are not retained or replayed; invalid canaries test route denial only. The strict recovery manifest is separately signed and locally consumed by exclusive creation.
10. The runner independently rechecks source counts and hashes, then stops only its newly allocated target containers. It does not delete containers, networks, source data or private evidence. Tmpfs target database data is ephemeral and disappears when those containers stop; the authenticated archives and private SQLite work remain. The parent subsequently handles its own source runtime shutdown.
11. Report only the allowlisted aggregate result and generated evidence-directory reference. Inspect `outcome`, `actualExpandedRestoreCompleted`, `sourceCountsAndHashesPreserved`, `encryptedArchiveAuthenticated` and `ownedRestoreContainersStopped` together. Do not infer success merely from archive existence.

## What this establishes—and what it does not

On a successful actual run, this establishes a bounded, local four-store restore of this specific synthetic source set, with stronger cross-store registration/mapping/replay consistency and source preservation checks than the earlier legacy proof. PostgreSQL and MySQL comparisons include all-table row-content hashes, not only row counts. It does not establish byte-identical database storage, global roles/tablespaces, every database setting, offsite disaster recovery, point-in-time recovery or a production RPO/RTO.

The native Pol.is `is_active` value is reported and preserved. If it is true, the report does **not** call the native conversation closed: effective participation is blocked by the empty server-enforced whitelist, terminal access state, stopped source applications and portless restore targets. No shared native round is changed just to pass this proof.

The WordPress contract returns private events only for comparison against the strict event digest ledger. Public results are separately nested counts/hashes. Stored assertion tombstones contain UUID/expiry, not the original receipt signature; a restore cannot reconstruct a pruned receipt or retroactively verify that original receipt signature. Consumed challenge signatures can be verified where retained. Registration self-attestations are not Indigenous heritage verification, and synthetic OIDC claims are not real mailbox verification.

The existing strict policy reports five separately named key fingerprints. The two additional WordPress challenge/registration keys are protected by the authenticated encrypted key-continuity component and whole-package equality, not falsely described as separately reported strict-policy roles.

No actual WordPress application restart from the restored database, rendered post-restore browser journey, live OIDC provider, real email/SMS, production signing-key custody, owner-approved new activation, real participant data, page `12064` / form `12069`, or original WordPress/access store is part of this proof. Those remain distinct work and approval boundaries.

## Primary technical guidance

- [PostgreSQL `pg_dump`](https://www.postgresql.org/docs/current/app-pgdump.html): custom-format database export and archive restoration; whole clusters/global roles and production backup strategy are separate concerns. A restore executes trusted source database definitions, which is why this runner restricts source and target scope.
- [MySQL 8.4 `mysqldump`](https://dev.mysql.com/doc/refman/8.4/en/mysqldump.html): transactional dump options; this proof additionally requires InnoDB and stopped writers rather than treating one transactional dump as cross-store coordination.
- [Node SQLite backup API](https://nodejs.org/api/sqlite.html#sqlitebackupsource-db-path-options): actual SQLite backup into newly created destination files.

These are database backup/restore techniques, not a claim that upstream Pol.is supplies this custom identity/activation/WordPress recovery design.
