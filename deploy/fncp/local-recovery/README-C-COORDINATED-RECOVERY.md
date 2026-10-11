# Option C — coordinated local recovery proof

This is a **synthetic, local-only engineering proof**, not production backup assurance or deployment authority. It does not contact the public Barayamal WordPress, registration page/form 12064/12069, participant accounts, email/SMS or a hosted Pol.is provider. The existing PostgreSQL-only proof remains unchanged.

## What is coordinated

The helper snapshots the existing synthetic WordPress/MySQL database, the local access SQLite database and the synthetic Pol.is PostgreSQL database while all known application writers are stopped. It restores all three into newly created isolated destinations, compares their bounded evidence, and proves restored revocation wins over stale authority.

| Store | Required source state | Restore destination |
| --- | --- | --- |
| WordPress/MySQL | Exact synthetic Compose project/database, loopback site URL, two known synthetic WP users, stock-generated post metadata, no attachments/registration, three revoked journal subjects | New, labelled MySQL container; fresh database on tmpfs; no source volumes or published ports |
| Access SQLite | Exact private synthetic database, one closed round, three revoked fixture approvals, six applied WordPress events, no sessions or unused invitations | New private SQLite file; a second fresh copy is used for adversarial authority tests |
| Pol.is/PostgreSQL | Exact labelled/pinned source, one synthetic conversation, 15 distinct expected fixed seed texts/TIDs, zero whitelist, terminal provider operation records | New, labelled PostgreSQL container; fresh database on tmpfs; no source volumes or published ports |

The current local database snapshot **does not include the new, separate identity/activation ledger foundation**. A later smoke or schema/data change is not retroactively covered by an earlier recovery result.

## Run safely, step by step

1. Work only in this disposable clone. Keep every public surface closed. Do not apply this helper to a live database or alter its fixed scope to make an unexpected state pass.
2. Stop the local access API, signed WordPress receiver, browser backend and PHP server. Stop all application containers; keep only the existing synthetic PostgreSQL and WordPress/MySQL DB containers running in `colima-fncp-c-20260913`. The helper checks all running container IDs, ports 8099–8102, source SQLite open-file state and source DB client connections. It does not automatically stop an unknown process.
3. Run the isolated model tests from the clone root:

   ```sh
   node --test deploy/fncp/local-recovery/coordinated-proof.test.mjs
   ```

4. Explicitly run the guarded proof:

   ```sh
   FNCP_COORDINATED_RECOVERY_MODE=coordinated-synthetic-restore-only \
     node deploy/fncp/local-recovery/coordinated-proof.mjs
   ```

5. Require `outcome=PASS`, `phase=complete` and `temporaryResourcesRemoved=true`. The result reports only an aggregate-evidence directory; no database contents, event identifiers, credentials or raw child diagnostics are printed. `productionReady` always remains `false`.
6. Keep the encrypted set and its separate private key. Each run creates three `.aesgcm` components plus authenticated `manifest.json`/`result.json` under `.runtime/coordinated-<run>/`; the key is separately retained under `.runtime/coordinated-keys/<run>.key`. Files are mode 0600, directories 0700. **Do not publish or attach either directory or the key.** The archives include synthetic password/credential/token hashes and internal synthetic identifiers; they are not public evidence. The standalone verification report is aggregate-only.
7. Resume only the separately authorised local work after the helper has finished and cleanup is verified. The helper never stops the isolated VM or original DB containers. It never migrates, bootstraps, resets, imports into or drops a source database.

## Controls and failure handling

- PostgreSQL uses a custom logical `pg_dump`; MySQL uses a single-transaction InnoDB logical dump without table locks, tablespaces, GTID changes or drop-table statements; SQLite uses the online backup API from a read-only source transaction. All known writers remain quiescent across the three snapshots.
- Each component uses AES-256-GCM with a fresh 96-bit nonce. The authenticated associated data binds exact run, store and scope hash. A separate HMAC-SHA256 authenticates the full manifest. The restore path independently re-reads and authenticates the exact three-component set before creating targets. Swapped, missing, extra, mismatched or tampered components fail closed.
- Temporary DBs use exact existing image IDs, a new labelled internal-only network, no published ports, and protected tmpfs data directories. The init-script directory is masked read-only. Both Docker configuration and the running container's actual mount table are checked. MySQL's temporary restore instance permits empty local root authentication only inside that isolated, unpublished throwaway container; it is never a source or production configuration.
- Source metadata is compared before/after snapshots and again after restore tests. The SQLite source file hash also remains unchanged. The restore compares all table row counts, selected schema metadata, exact in-memory event/approval/provider-tombstone metadata and the 15 distinct known fixed seeds.
- The original restored SQLite copy is inspected read-only. A **second fresh copy** receives deliberately stale but valid warm-session and unused-invitation rows; actual local access code rejects them because approval is revoked/round closed. Three historical approval events are replayed as stale no-ops, terminal reapproval is denied, and no provider request is made. These are synthetic adversarial rows, not recovery/reuse of real historical bearer tokens.
- Cleanup verifies each temporary ID's run label and excludes both source IDs before removal. It independently checks that no matching temporary containers/networks remain, deletes only known files from the new work directory and removes that directory. Retained encrypted sets/keys are not deleted. A crash, forced interruption or cleanup failure can leave labelled temporary resources; never use a broad Docker prune or delete source volumes to resolve this.
- A failure may retain an encrypted partial/complete attempt for diagnosis. Only a complete authenticated **PASS result** is a successful restore. Retention/authentication flags advance only at their real checkpoints, not merely because a directory exists.

## Limits and next production work

This is a quiescent single-laptop proof, not an atomic distributed snapshot protocol. It relies on the operator's writer freeze plus fail-closed process/connection checks; it cannot protect against a privileged concurrent process deliberately bypassing that freeze. It is not byte-for-byte verification of every restored row or every routine/constraint definition. PostgreSQL column/index definitions and schema counts, MySQL column/index metadata, SQLite schema/integrity/foreign keys and all table counts are checked; identity/event/tombstone metadata gets stronger exact comparisons.

There is no production key custody/rotation, off-site copy, RPO/RTO commitment, disaster recovery exercise, future identity/activation-ledger inclusion, attachment/filesystem backup, real participant authentication, eligibility verification or deployment-bound activation assurance here. The key and archives are on the same laptop, despite separate private directories. Future production work needs a real coordinated writer fence, all authoritative stores in the backup contract, independent key custody and storage, tested recovery in a separate failure domain, and explicit approval before external infrastructure or participant use.

## Primary references

- [Official Pol.is source and self-hosting README](https://github.com/compdemocracy/polis) — use the checked-out upstream README as the base; this bounded recovery helper is a local extension, not an upstream endorsed production recipe.
- [PostgreSQL 17 `pg_dump`](https://www.postgresql.org/docs/17/app-pgdump.html) and [`pg_restore`](https://www.postgresql.org/docs/17/app-pgrestore.html) — logical single-database archives and isolated restoration, matching this proof's pinned PostgreSQL 17 source image.
- [MySQL 8.4 `mysqldump`](https://dev.mysql.com/doc/refman/8.4/en/mysqldump.html) — single-transaction consistency is suitable for the verified InnoDB scope; concurrent DDL/writers are excluded by this proof's freeze.
- [SQLite online backup API](https://sqlite.org/backup.html) and [Node SQLite backup API](https://nodejs.org/api/sqlite.html) — consistent SQLite copies without copying a live database unsafely.
- [Node authenticated encryption APIs](https://nodejs.org/api/crypto.html) — AES-GCM associated data and authentication tags.

Current completed evidence: [coordinated verification, 13 September 2026](coordinated-VERIFICATION-2026-09-13.md).
