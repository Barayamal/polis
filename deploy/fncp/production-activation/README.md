# Production activation verification

`createProductionActivation()` is a public-key-only verifier and private persistent ledger. It does not sign or auto-activate, expose HTTP, open a Pol.is conversation, approve a person or grant a participant session. The synthetic activation module remains unchanged.

The constructor accepts exactly `{binding, publicKey, keyId, ledgerPath, now?}`. The key must be an Ed25519 public KeyObject or public-key PEM; private keys are rejected. Binding has exactly:

```text
deploymentId, conversationId, sourceRevision, configSha256, seedSha256,
providerSha256, images, recoveryEpoch, scope
images: api, math, postgres, participant, wordpress, mariadb, proxy, migration
scope: {maxParticipants:20, statementCount:15, suggestions:false}
```

Every image is an immutable SHA256 ID. Source revision is 40 hexadecimal characters; configuration, seed and provider digests are 64. Recovery epoch is a UUIDv4. `providerSha256` is SHA256 of the canonical public provider binding, covering origin, 15 IDs and its trust profile. The participant image represents the same-process BFF/access single writer. The launcher owns accurate source/image/configuration provenance; this verifier does not discover or attest running infrastructure.

The frozen result is registered in a private WeakSet and is recognized by `isProductionActivation()`. Its public API:

- `challenge()` returns a fresh copy of `{purpose,keyId,binding,nextSequence,maxLifetimeSeconds:1800}`. Binding includes a new random `bootId` generated for this instance. This is review information, not an activation.
- `accept({payload,signature})` verifies a canonical base64url Ed25519 envelope against the production signing domain, exact binding, fresh sequence/ID and validity window. Signed claims are exactly `{schemaVersion:1,purpose,keyId,activationId,sequence,issuedAt,notBefore,expiresAt,binding}`. The accepted lifetime cannot exceed 30 minutes. Every replacement attempt first revokes the old activation; invalid replacements cannot leave old authority active. Success returns `{active:true,generation,expiresAt}`.
- `assertActive()` checks the current clock, owned file identity, persisted boot/binding/sequence/state and the signed window, then returns the activation-ID generation string. Callers must compare this same generation again after every awaited positive effect.
- `close()` revokes current authority. A new reviewed signature with the next sequence may activate the same healthy instance. `dispose()` is permanent and closes the database.

Invalid/backward/throwing clocks and storage/custody/row-generation failures permanently fault the instance. Correcting the clock or permissions cannot revive it. Expiration, ordinary close and an invalid signature revoke without turning a valid later reviewed signature into an automatic restart. No browser/request clock or store selection is supported.

Ledger custody requires an absolute canonical path, a real owned 0700 parent directory, and an owned 0600 regular single-link `.sqlite` file. Before creating or opening the ledger, the constructor exclusively creates `<ledgerPath>.lock` with `O_EXCL` and `O_NOFOLLOW`. The private 0600 lock binds the stable activation identity, process ID and random owner token. Every operation checks the held descriptor, path inode, ownership, mode, link count and exact lock contents. A second process cannot rewrite the active owner's boot or sequence. The constructor refuses symlinks, hardlinks, foreign objects/schema and unexpected application/user versions. Version 1 creates exactly the state and accepted-ID tables; it never converts the synthetic ledger or drops replay history. DELETE journal mode and FULL synchronous writes are explicit. A failed write closes in memory even if the denial cannot be persisted.

`dispose()` first revokes authority and closes SQLite, then removes the verified owned lock and closes its descriptor. Rejected construction also releases its acquired lock only after SQLite closes; a lock owned by another process, a damaged lock or a replacement is preserved. Ordinary `close()` does not release ownership. An unclean exit leaves the lock behind and future startup refuses it, regardless of the recorded PID. There is no automatic stale-lock adoption or deletion. A reviewed, stopped recovery procedure must establish that the old process is gone and preserve current replay history before clearing an abandoned lock. A process must call `dispose()` during clean shutdown; process exit alone is not clean lock release.

Stable ledger identity binds deployment, conversation, key ID and public-key fingerprint. Every restart keeps the sequence floor/accepted IDs, issues a new boot challenge and starts inactive. Reviewed source/configuration/provider/image/recovery-epoch changes can therefore use the same ledger and retained floor, but need a new offline signature. Changing the stable identity/key requires a separately reviewed migration; a fresh empty ledger is not a recovery shortcut. At most 10000 accepted IDs are retained; exhaustion refuses new activation without deleting history.

The launcher must additionally guarantee one compositor process before constructing any owned component, and coordinate closed/drained backup of access, activation, Pol.is and WordPress state. The activation lock protects this ledger; it does not acquire the access writer or make multi-store initialization atomic. File ownership and SQLite do not by themselves detect restoring an old complete ledger snapshot; approved recovery must preserve the latest replay history and create a fresh recovery epoch. Old envelopes also fail the fresh boot challenge. Activation cannot replace a joined recovery proof or runtime custody review.

`offline-sign.mjs` is a separate operator helper, never imported by runtime code. `signProductionActivation({challenge,privateKey,activationId,issuedAt,notBefore,expiresAt})` returns an envelope in memory. It does not create keys, send a message, write an artifact or activate a service. The private signer stays outside the participant process, and the operator must review the complete challenge before using it. Neither a challenge nor this helper supplies approval.

Tests use temporary private SQLite ledgers and newly generated synthetic Ed25519 keys. They prove signatures, restart/replay, failed replacement, expiry, clock/storage failure latching, schema/custody checks and changed-configuration review. Separate child processes prove that duplicate startup leaves the active owner's boot, floor and ledger bytes unchanged, constructor failures release only their own lock, clean disposal permits a closed fresh boot, and abandoned/replaced locks are never adopted or deleted. They use no retained private keys, network, Docker or live activation.

```sh
node --test deploy/fncp/production-activation/authority.test.mjs
```

## Explicit nine-image activation (V2)

An exact `images` binding containing the original eight roles plus `edge` selects
`FNCP_PRODUCTION_ACTIVATION_V2`, claims schemaVersion2 and signature domain
`Barayamal\0FNCP\0ProductionActivation\0v2\0`. The same verifier/signing APIs
operate on either explicit shape; unknown or missing roles still reject. V1
constants and eight-role behavior remain compatible. The challenge identifies
the selected purpose, and signatures from the other domain cannot activate it.

The new edge digest is part of the complete binding hash. Changing it requires a
fresh boot-bound signature while preserving the ledger's sequence/replay history
and starting closed. A V2 composition must supply the ninth exact image ID in its
participant manifest; this activation change does not authorize publishing a port
or admit a participant automatically.

For V2 the participant manifest also requires
`activation.edgeMaterialSha256`: SHA-256 of canonical JSON for the lexically
sorted array of `{name,sha256}` covering `config.json`, `server-key.pem`,
`server.pem` and `upstream-ca.pem`. Staging compares that digest with the four
actual edge files. The service's `configSha256` already includes the complete
manifest, so the signature binds this edge material digest without exposing the
edge private key to the participant service. Joined restore independently
recomputes it from archived edge bytes; renewal must recompute it after changing
edge material and obtain a fresh closed activation. This is a staged artifact
binding; the edge runtime additionally enforces its own private-file custody.

## Operator-loopback activation (V3)

An exact ten-image binding (the V2 images plus the credential-free operator
gateway) and `operatorAccessSha256` select
`FNCP_PRODUCTION_ACTIVATION_V3`, claims schema version3 and uses the distinct
`Barayamal\0FNCP\0ProductionActivation\0v3\0` signing domain. The digest is
SHA-256 of the canonical `FNCP_OPERATOR_LOOPBACK_V1` access object containing
only the fixed participant and WordPress loopback bindings. It is not optional
for V3 and is forbidden in V1/V2.

The staged service manifest, full configuration, activation challenge, recovery
state and renewal material must agree on that digest. A V2 envelope cannot be
replayed as V3, and a V3 envelope for a different port or address cannot be
accepted. The digest proves reviewed configuration agreement only; it does not
prove firewall state, start a tunnel, grant activation, open admission or make a
loopback listener public.
