# Native registration ledger foundation

This isolated foundation implements the WordPress-free ledger algorithms using
fresh invented identities. It is **not a production approval authority**. Its
only profile is `FNCP_NATIVE_STORE_FOUNDATION_V1`, its mode is `SYNTHETIC_ONLY`,
and every projection denies participant access. Never attach it to a production
registration route or adopt its fixture databases as production state.

## Implemented behavior

- Atomic lifetime-slot, registration and canonical receipt creation; 20 slots
  maximum, with no recycling after decline or revocation.
- Internally derived opaque fixture-account references. Callers cannot supply
  account IDs, participant XIDs, receipt IDs or registration references.
- Three separately affirmative consent declarations bound to the exact notice
  digest and version; every required notice data property is checked, including
  non-enumerable properties. Key-order-independent retries preserve the receipt.
- Distinct approve, decline and revoke audit kinds, exact decision retries,
  immutable digest-linked events and terminal denial. Approval grants no access.
- Revocation and a durable pending removal intent commit in the same local
  transaction. No provider operation is executed or acknowledged here.
- Exact STRICT schema and uniqueness/foreign-key checks; replay rejects missing,
  changed or inconsistent receipts, events, projections and removal intents.
- Clock high-water and sticky faults persist under tested trusted custody,
  including failures inside a transaction and ordinary transaction rollback.
- Key fingerprints bind account derivation to receipts and events. Mutable
  caller inputs are snapshotted before invoking the trusted clock seam.
- One writer, canonical private paths, `0700` fixture directory, `0600` store
  and lock, no symlinks/hardlinks, bounded row reads and a 2 MiB file limit.
  Custody is checked after the trusted clock seam and immediately before a
  transaction commit; a detected loss rolls back rather than committing the
  requested registration, decision or pending removal intent.
- Fresh disk initialization requires exclusive creation of the store inode;
  an existing empty file or foreign SQLite namespace is never initialized.
  Existing stores must pass read-only exact-schema/profile checks before any
  writable SQLite handle or persistent setting is used. Foreign application
  markers, WAL-format headers and journal/WAL/SHM artifacts reject without
  recovery, sidecar creation or changes to their existing bytes.
- Aggregate-only status. Faulted or closed stores report unavailable counts,
  not fabricated zero counts or damaged-row data.
- In-memory faults stay process-latched but always report durable fault
  persistence unverified; a new memory instance is a different ephemeral store.

## Verification

```sh
node --test deploy/fncp/native-registration/ledger.test.mjs \
  deploy/fncp/native-registration/store-schema.test.mjs
```

The initial foundation passed 124 tests on Node 22.23.2 and Node 24.19.0 on
Darwin ARM64: 88 ledger cases and 36 schema cases, with no skips or failures.
The 12 October local hardening adds 22 foreign-store/custody and memory-fault
regressions; all 146 cases pass on both reviewed runtimes on Darwin ARM64.
The follow-up review adds 33 notice-property and transaction-boundary custody
regressions; all 179 native/schema cases pass on both reviewed runtimes on
Darwin ARM64. Fault errors reflect persistence checked after transaction
rollback, not an earlier tentative latch.
The fixtures use fresh temporary SQLite databases and clean them up afterward.
No added package dependency or running service is required. Node 22 reports
`node:sqlite` as experimental; these results do not qualify Linux, Windows or
an installed PC/container candidate. See the [pinned Node SQLite API](https://nodejs.org/download/release/v22.23.2/docs/api/sqlite.html)
and [SQLite transaction semantics](https://sqlite.org/lang_transaction.html).

## Security boundaries still ahead

The `invented-participant-*` and `invented-reviewer-*` inputs are test fixtures,
not authenticated principals. This module does not implement real sign-in,
staff MFA/CSRF/reauthentication, participant invitations/capabilities, provider
readback/removal, voting, a native deployment, activation or encrypted recovery.

An intact local digest chain cannot prove that a snapshot contains every later
denial. `currentDenialHistoryVerified` always remains false. Production restore
needs independent current decision-history custody and reconciliation; none is
implemented here. Restored admission remains unauthorized.

A mode-only custody fault can persist a closing flag only when the same owned
store/lock inodes, links and unchanged private parent remain trustworthy. Lost
or substituted custody closes the process and reports fault persistence
unverified. There is no independent storage-fault witness or automatic repair.
Do not infer restart safety after an unverified persistence failure.
These checks bound the trusted local execution seams, not atomic protection
against an actively hostile same-UID process changing custody between system
calls. They do not replace independent custody, secure-host qualification or
recovery authority.
Existing journal/WAL/SHM artifacts also require separate recovery review;
this foundation rejects them rather than attempting automatic SQLite recovery.

Fresh-install proof of an empty Pol.is namespace, real provider/identity
integration, the 15-statement journey, exact PC images/scans, renewal and joined
recovery all remain separate work. Existing WordPress/participant stores,
source profiles and live services are neither imported nor changed by this
foundation. No WordPress-branded compatibility bridge is manufactured.
