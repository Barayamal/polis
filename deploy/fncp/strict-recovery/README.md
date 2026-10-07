# Strict identity/activation recovery contract

**Implemented and tested as a local synthetic model. Not a new actual coordinated
backup/restore, a production recovery procedure, or activation authority.**

The later [expanded runner](../expanded-recovery/README.md) uses this contract
against actual fresh WordPress/MySQL, strict access/activation SQLite and
synthetic Pol.is/PostgreSQL restores. Its13 September2026 PASS is a separate
dated result, not a production guarantee supplied by this library.

This deliberately conservative profile handles a closed, fully revoked round.
It refuses to recover an approved/pending account as eligible. Its only successful
action is `KEEP_CLOSED`. Existing public services, providers, stores and controls
are not changed by this package.

## What is verified

- Exact current strict access SQLite schema, including `identity_mappings`, all
  table definitions/constraints, and the exact activation ledger schema. Unexpected
  tables, triggers, views, explicit indexes, changed columns/constraints, failed
  integrity or foreign-key checks are rejected. Only engine-generated implicit
  constraint indexes are excluded from the schema comparison.
- One closed conversation, 1–20 one-to-one opaque account/fixture/round/XID
  mappings, matching approvals, and no session rows. Every retained invitation
  must be used—even an expired but unconsumed invitation is refused.
- No pending OIDC transactions, live principal capabilities or browser sessions
  in the supplied volatile-state observation. Restoring SQLite is never treated
  as restoring a verified in-memory identity.
- Every mapped subject has an acknowledged WordPress event history whose latest
  decision is terminal revocation. Every retained event has the same ID, subject,
  version, decision and digest in the access ledger and is applied. Each account
  has a matching absent/version-2 provider tombstone; scoped whitelist count is
  zero. Unrelated provider records are rejected, not silently adopted or revoked.
- The current mapping algorithm is pinned to the identity foundation's JSON-array
  HMAC-SHA256 domains `fncp-account-v1` and `fncp-xid-v1`. A positive mapping-key
  version, exact issuer-configuration digest and five distinct role fingerprints
  must match across source and restored observations. Key rotation/remapping is
  refused; it needs a separate reviewed migration design.
- Domain-separated Ed25519 recovery-manifest signatures, canonical bounded JSON,
  exact fields, trusted expected recovery ID/signer ID, public-key fingerprint and
  a maximum 30-minute validity window. A private KeyObject or private-key PEM is
  not accepted as the verifier. Activation envelopes are not recovery envelopes.
- Same deployment, conversation, five images, configuration, fixed-seed digest and
  scope (20 people, 15 fixed statements, no suggestions), but a **new boot ID and
  recovery epoch**. The restored activation row must be closed, clear its prior
  activation pointer/digest, preserve the exact sequence floor and replay-ID set,
  and match its fresh binding. Recovery does not reset replay protection.

The signed manifest contains component/binding hashes, schema fingerprints,
mapping/key versions, key fingerprints and aggregate counts. It contains no raw
account/fixture/XID/event IDs, credential hashes, tokens, emails or key material.
Private snapshots contain operational identifiers and must not be logged,
published, attached or included in ordinary evidence.

## Reusable interface

`contract.mjs` has no executable entrypoint and opens no filesystem path:

1. `readStrictStore(db, 'access' | 'activation')` uses read-only SQL/PRAGMA queries
   against an already-open caller-owned `node:sqlite` `DatabaseSync` handle. It
   returns a private snapshot. The caller must first independently establish the
   exact allowed store, quiescence, snapshot consistency and read-only handle.
   Do not supply preserved/live stores merely to try this library.
2. Assemble private source/restored observations, each with exactly `binding`,
   `access`, `activation`, `wordpress`, `provider` and `volatile`. WordPress input
   is `{events: [{event, acknowledged: true}]}` using the existing event schema;
   provider input is `{conversationId, whitelistRows, operations}`, where each
   operation is `{xid, operationVersion, present}`. These are metadata contracts,
   not network adapters or trusted claims that a remote service was checked.
3. Supply `keyContinuity: {source, restored}`. Both sides have exactly
   `mappingAlgorithm`, `mappingKeyVersion`, `issuerConfigurationSha256` and
   `fingerprints`. Fingerprint roles are `identityMapping`,
   `activationVerification`, `wordpressEvent`, `providerGateway` and
   `providerAllowlist`. All are SHA-256 hex digests, never raw keys. Effective-key
   discovery, secure key custody and version storage are outside this module.
4. Call `prepareStrictRecoveryManifest({mode, recoveryId, keyId,
   signerFingerprint, issuedAt, expiresAt, source, targetBinding, keyContinuity})`.
   Use `mode = MODE`; timestamps are Unix seconds. The caller supplies a fresh
   expected recovery UUID and a separately obtained target binding. Preparation
   validates source semantics before returning unsigned hash-only claims.
5. A separate **synthetic** signing step signs
   `SIGNING_DOMAIN || Buffer.from(canonical(claims))` with Ed25519. The envelope
   contains exactly `{payload, signature}`, both unpadded base64url. This package
   does not provision or persist a signing key. `publicKeyFingerprint(publicKey)`
   computes the SHA-256 digest of a public Ed25519 SPKI DER key only.
6. Call `validateStrictRecovery({mode, envelope, publicKey, expectedRecoveryId,
   expectedKeyId, source, restored, targetBinding, keyContinuity, now})`.
   `now` is a trusted function returning integer Unix milliseconds. Do not obtain
   the expected IDs/key/fingerprints from the untrusted envelope itself.
7. On success, retain only the aggregate result and signed manifest. Continue to
   keep the round closed. A new signed activation and new OIDC login are still
   required. The terminally revoked accounts and old invitations remain unusable.
   Any failure returns only `{ok:false,error:'strict_recovery_denied'}`.

This is a planning/validation function, not a restore command. It does not consume
a recovery ID durably. Repeated validation is harmless because it mutates nothing;
a future execution adapter must durably consume the expected recovery ID before
performing a separately authorised restore, and must recheck all observations.

## Run the isolated tests

From the clone root:

```sh
node --test deploy/fncp/strict-recovery/contract.test.mjs
```

Tested with Node **26.8.2**. No extra package or install is needed. The suite uses
Node's crypto and SQLite plus current checked-in access/activation modules. It
creates only new `fncp-strict-recovery-test-*` temporary directories and removes
those test-owned directories afterward. It opens no listener and makes no provider
request. No Docker command or existing database is used.

The tests obtain schemas by instantiating the **actual current strict wrapper** in
new stores, not by constructing a matching alternative schema. They also copy
those new test SQLite stores, restart the actual activation module with a fresh
binding, and verify rejection of an old signed activation. WordPress/provider
metadata is invented in memory; no actual WordPress/MySQL/PostgreSQL snapshot or
restore occurs. Cryptographic manifest signatures use newly generated ephemeral
test keys. Negative checks cover source-state hazards, schema drift, mapping/key
drift, signature/domain confusion, time limits, replay-floor loss, old invitations,
volatile capability revival, extra fields/getters and diagnostic leakage.

## Exact limitations / next implementation boundary

- Passing fingerprints proves agreement with **provided trusted observations**,
  not secure custody, possession of a recovery key, recomputation of issuer+subject
  HMACs, effective runtime configuration, or any real identity-provider claim.
- It does not independently verify WordPress acknowledgements, provider readback,
  actual image IDs, source contents, live volatile state or cross-store timing.
  A future scoped observer must gather those facts without exposing response data.
- It does not encrypt/archive components, restore MySQL/PostgreSQL, coordinate
  store snapshots, measure RPO/RTO, exercise infrastructure failure, or update the
  previous coordinated recovery evidence. The earlier actual recovery proof does
  not automatically cover these newer strict identity/activation schemas.
- This is metadata consistency, not full-byte equivalence of all provider data.
  It does not read or delete participant statements/votes, count registrations,
  send email/SMS, determine heritage/eligibility, deploy anything or reopen a round.
- Limits are intentionally bounded: 20 mappings, 220 retained event rows, 1,000
  retained used invitations and 1,000 activation replay IDs. Capacity exhaustion
  refuses recovery; no evidence is pruned to force a pass.

Before any actual strict multi-store restore, separately implement the trusted
observer, encrypted component capture, isolated target/path checks, coordinated
quiescence, durable one-use execution record, effective-key custody verification
and independent post-restore readback. Obtain the required action-specific
approval. A successful contract result or PR is never launch/GO authority.
