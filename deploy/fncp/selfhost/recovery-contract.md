# Recovery contract

This is the contract for the complete future deployment. The current Compose executable contains only PostgreSQL, API, migration and math; it cannot claim joined WordPress/access recovery.

The atomic recovery unit contains:

- Pol.is schema/data, sequences, migration ledger, owners, memberships and ACLs.
- WordPress registrations/decisions/outbox plus its database and required plugin/configuration versions.
- Access identities, invitation consumption, provider operations and terminal removal tombstones.
- Activation sequence/replay history and versioned identity/event verification key references.
- Exact source/image/configuration versions and protected secret references.

Close the round, stop new approvals/invitations, drain outbox work and quiesce every writer before capturing these stores. Encrypt backups and keep keys under separately documented custody. Restore to new owned resources; never overwrite a retained deployment. Verify data, schema, grants, effective runtime denials and record checksums.

Clear transient login transactions/sessions/capabilities. Preserve stable identity mapping and terminal/replay history. Start a new recovery epoch closed, without activation. Old cookies, used invitations and old activation envelopes must deny. Then run joined API/WordPress/access/math tests before a separate opening action. A database dump comparison alone is insufficient.

RPO, RTO, off-host retention/custody and second-operator verification remain unmeasured/unverified until the full joined deployment is available. The controller currently preserves volumes on stop and intentionally has no destructive cleanup or production restore command.
