# Coordinated synthetic three-store recovery — 13 September 2026

**Result: PASS, local synthetic scope only. Production remains HOLD.**

Final revised actual run: `3ce5188eaf48c6a5faf7bcc4`, completed `2026-09-13T03:43:37.080Z` (13:43:37 Australia/Sydney, UTC+10). Source applications were stopped throughout; only the exact synthetic PostgreSQL and MySQL source containers were running. This result precedes any subsequent activation smoke and cannot attest to changes made after its snapshot.

## Completed

- Three logical/database snapshots encrypted with AES-256-GCM and bound to the exact run/store/scope; authenticated aggregate manifest independently re-read from disk before restore.
- New internal-network, pinned-image, tmpfs PostgreSQL and MySQL targets, with source IDs/mounts excluded. Actual running mount tables verified. Original DB volumes were never attached to restore targets.
- Fresh SQLite restore inspected read-only, with integrity check `ok`, zero foreign-key violations and matching schema/content hash. No source migrations, resets, bootstrap or writes performed by the helper.
- Independent restore comparisons passed: all table row counts; selected schema metadata; exact in-memory approval/event/provider-tombstone metadata; seed uniqueness; closed/revoked state.
- A second fresh SQLite copy deliberately given valid stale session/invitation rows denied warm-session participation, unused invitation redemption and terminal reapproval. All three historical approval events replayed as stale no-ops. Provider calls: **0**. These are adversarial synthetic authority tests, not real participant token reuse.
- All newly created restore containers, network and plaintext work copies removed, with final label-inventory checks. Original sources retained. Final source aggregates and SQLite file hash unchanged.
- **13/13 isolated model/boundary regressions passed**, including ciphertext/tag/nonce/key/AAD tampering, mismatched/missing/extra component sets, stale approvals, pending events, missing tombstones, exact source/target boundaries, mount verification and rejection of the source SQLite path before adversarial writes.

## Aggregate comparison

| Store | Before and independently restored |
| --- | --- |
| WordPress/MySQL | 12 tables; 2 known synthetic users; 5 stock/generated posts; 1 stock comment; 0 attachments; registration/public flag disabled; 3 revoked journal subjects / 6 acknowledged events |
| Access SQLite | 6 tables; 1 closed round; 3 fixtures; 3 revoked approvals; 2 used invitations; 0 sessions; 6 applied WordPress events; 0 foreign-key violations |
| Pol.is/PostgreSQL | 62 tables; 427 columns; 116 indexes; 11 routine and 331 constraint records; 1 synthetic conversation; 15 expected seed rows / 15 distinct texts / 15 distinct TIDs; 27 synthetic vote rows; 0 provider whitelist rows; 20 terminal version-2 removal records |
| Cross-store authority | All 3 fixture approvals and WordPress terminal versions match; all 6 event digests/applied states match; corresponding provider tombstones exist; no pending event, active session or unused invitation |

The two extra WordPress records beyond standard install content were the automatically generated navigation and empty dashboard auto-draft; provenance was checked against the local official WordPress source. The second user was the previously created synthetic subscriber capability-test account. No live WordPress content or registration record was copied or read.

## Retained evidence

Private directory: `deploy/fncp/local-recovery/.runtime/coordinated-3ce5188eaf48c6a5faf7bcc4/`.

| Encrypted component | Bytes | SHA-256 |
| --- | ---: | --- |
| `wordpress-mysql.aesgcm` | 150604 | `6197781f77af2dc3e52d45f7b20e2b47fd4959fe0bd017c83382e8745680d978` |
| `access-sqlite.aesgcm` | 82198 | `2c52e5010a416fe9230cc7475ef6cd51a8bd1ebeedc6f9f5cacfc6b0a8d34873` |
| `polis-postgresql.aesgcm` | 206621 | `85364394ae7617705773774154f179696fe1807e9d0d455909ea215fabe55625` |

The final manifest and result HMACs and all three component AES-GCM tags were independently verified after execution. Every retained file is 0600; containing directories are 0700; the separate private key file is 0600. The key is not reproduced in this report. Encrypted archives contain synthetic authentication hashes/internal identifiers and must not be published.

Earlier local attempt sets remain privately retained and are superseded by this final run. The initial read-only scope attempt hit PostgreSQL's 100-function-argument limit; the 62-table count query was changed to row aggregation. Further fail-closed attempts revealed that this Docker daemon omits tmpfs entries from `.Mounts` and only assigns network IDs on startup; the final helper verifies exact pending configuration, strict post-start network binding and actual `/proc/mounts`. No failing attempt imported into a source or left its temporary restore resources running. An earlier PASS predates review hardening and is not the final evidence cited here.

## Scope limits

These comparisons are **not** byte-for-byte equality of arbitrary database contents or every stored routine/constraint definition. They are the bounded all-table counts, selected schema metadata and stronger approval/event/tombstone checks described above. The proof covers the existing synthetic three-store application only, not the new separate identity/activation-ledger foundation, credential configuration files, application files, future schema/data changes, live participants or WordPress page/form 12064/12069. Quiescence is operator-coordinated, not a distributed writer-fencing implementation.

No external sends, public changes, deployment, real email/SMS, participant/heritage testing, source deletion or live registration-retention action occurred. Same-laptop encrypted storage does not supply independent disaster recovery or production key custody. Use the [coordinated recovery guide](README-C-COORDINATED-RECOVERY.md) for the exact guarded procedure and primary documentation links.
