# Bound native-round maintenance

`native-round.mjs` generates a fixed PostgreSQL maintenance plan for the dedicated
production composition. It reads no files, imports no database client and makes
no engine, process or network call. It accepts no credentials, adapters or caller
SQL. The caller separately owns an explicitly authorized, verified-TLS maintenance
session against the exact deployment.

Native Pol.is voting requires `conversations.is_active=true`. Dedicated API
startup requires the same bound conversation to be closed. This helper provides
the explicit maintenance transition between those states; it does not weaken
either existing server guard and never activates participant admission.

## API and seed identity

```js
import {nativeRoundMaintenance, validateNativeRoundReceipt} from './native-round.mjs';

const plan = nativeRoundMaintenance(productionComposeConfiguration, {
  operation: 'open', // exactly 'open' or 'close'
  statements: reviewedParticipantStatements,
  seedSha256: reviewedActivationSeedSha256,
});
```

The configuration must pass `validateProductionConfiguration` from `compose.mjs`.
The helper additionally requires strictly ascending IDs, matching the participant
service's ordered binding. `statements` is the same ordered array of **15 strings**
as the participant manifest. Its digest is SHA256 of canonical string-array JSON,
the exact `sha(canonical(c.statements))` used by production activation. Each string
must be unique, nonblank and valid Unicode, with no NUL and at most 1,000 Unicode
code points/4,000 UTF-8 bytes, matching the native comments column. Text is never
trimmed, normalized, escaped into SQL syntax or replaced with a fixture.

The frozen plan contains:

- `queries`: five ordered query objects with fixed `text` and `values`. Only the
  second query has a parameter: the validated public binding JSON. Execute all
  five on **one owned connection**, and roll back/discard it on any failure.
- `psql.arguments` and `psql.stdin`: the equivalent fixed psql input. Public JSON
  is base64 data in one fixed psql variable, then decoded as a SQL value. Quotes,
  dollar-quoted delimiters, backslashes, newlines and psql commands inside statement
  text never become executable input. Do not append caller SQL or interpolate
  statement text into another script.
- `binding`, `operation` and `participantAdmissionActivated:false` for review.

The psql runner must retain its existing `PGSSLMODE=verify-full`, exact CA path,
exact hostname/database/migration-role checks, private credential custody,
read-only root filesystem, bounded resources and no published port. It must use
the approved immutable maintenance image. The SQL can verify that the current
session uses TLS; **only the correctly configured client verifies CA and hostname**.
The runner must use a writable primary maintenance session, not the read-only
operator-export default. No privileged owner/superuser fallback is permitted.

Only after successful COMMIT and psql exit0 (or successful completion of the last
parameterized query) may the caller parse the single JSON result and call
`validateNativeRoundReceipt(plan, receipt)`. Validation accepts the original
locally generated plan and an exact receipt shape. It binds the operation,
deployment, conversation and seed digest; it is not an execution signature.
Never treat the pre-COMMIT result row alone as success.

## Database preconditions and single-field change

Every operation runs as one SERIALIZABLE transaction with a 15-second statement
and idle-transaction limit and a two-second lock limit. It checks PostgreSQL17,
the configured database and migration role, same session/current user, a writable
primary, live TLS1.2/1.3 with at least128 bits, and the dedicated non-superuser role
without role membership, inheritance, database ownership or administrative flags.

It acquires the existing migration runner's advisory lock and reads the owned
`fncp_deploy.schema_migrations` table under a shared lock. All **20 exact filenames
and SHA256 values** must match the reviewed source constant. Missing, modified or
additional migration records reject the operation. The host test detects source
migration changes, so a deliberate schema update needs a reviewed helper update.
This checks migration history and the queried schema contract; it is not a general
forensic attestation against a malicious database administrator.

Bounded table locks prevent invite remapping or statement writes during checks.
The dedicated database must contain exactly one conversation, exactly one mapping
from the configured conversation code and no alternate invite code for that
conversation. The helper locks those rows and compares all native statement IDs
and exact text values with the ordered binding. It never assumes zid1 or fixture
statement IDs, and never creates a conversation, seed, participant or allowlist row.

**Opening** requires the bound round to be closed, nonpublic, data export closed,
XID-required and allowlisted, anonymous in Pol.is, not draft, strictly moderated,
with profanity/spam filters off, topics/treevite off, `write_type=0` and `vis_type=0`.
Its owner/org binding must exist, and all15 statements must be active, approved,
seed statements and not metadata. Nullable or mismatched flags reject opening.
`write_type=0` hides the native comment form; the unchanged dedicated route
allowlist remains responsible for refusing suggestion endpoints.

**Closing** retains the exact database, schema, conversation and ID/text identity
checks but can close after privacy/moderation flags drift. It changes only the
bound row's `is_active` field. Closing an already closed bound row is idempotent;
opening an already open row rejects. Row counts and the final actual database flag
are checked before COMMIT. No setting, statement text or moderation field is repaired.

The table locks can briefly block writes in this dedicated single-conversation
database. They are held only through the bounded transaction. Serialization or
lock errors require a new deliberate maintenance attempt; there is no automatic
retry that could reopen a round later.

## Operator sequence and validation scope

Keep participant admission closed while starting the API against the closed native
round. Review the actual deployment/material/seed/image binding and activation
challenge. The operator then explicitly opens this native round and separately
accepts the reviewed activation/admission sequence. Native opening alone cannot
produce invitations, approved registrations, provider allowlist entries or active
participant access.

For closure, close participant admission and drain in-flight application operations
before this native close. The helper does not itself cancel a vote already in
flight or revoke an activation authority. Close the native round before restarting
the dedicated API. If statement identity/schema has drifted so that even bound
closing rejects, keep participant admission closed and stop the owned participant
process while the operator reviews that separate mismatch.

Host tests cover deterministic plans, data-only transport, malformed/hooks/sparse
inputs, exact migration source hashes, configuration rejection and receipt binding.
They do not execute PostgreSQL. Native integration must still exercise successful
open→close and idempotent close, private-setting/moderation/seed/schema mismatches,
wrong database/role/TLS, transaction rollback and actual field postconditions with
the existing owned maintenance runner. Retain failure evidence instead of weakening
the assertions to fit a fixture.
