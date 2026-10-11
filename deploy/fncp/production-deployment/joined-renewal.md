# Joined closed credential renewal

`joined-renewal.mjs` transforms one authenticated, complete stopped backup into
another independently encrypted complete backup. It supports the six-volume
V1 profile and seven-volume V2 profile with the ninth edge image. It performs
no Docker action, network request, provider change, signing, opening or sending.
The result must be independently restored and rehearsed before any rollout.

## Exact credential scope

The operation permits the existing confidential OIDC client secret,
participant TLS pair, receiver TLS pair and, in V2, the public edge TLS pair to
change. Receiver renewal coordinates WordPress's `receiver-ca.pem`; participant
renewal coordinates the edge's `upstream-ca.pem`. A changed trust file is allowed
only alongside its corresponding changed TLS pair, and must contain exactly one
currently valid CA that authenticates the target leaf/chain. The target leaf
must match its existing hostname and private key, be CA:false, permit server
use, and have more than one hour of validity remaining.

**It does not rotate every credential.** PostgreSQL and MariaDB credentials,
JWT, gateway/provider secrets, WordPress request/response/event HMAC keys,
pseudonym key, activation authority and native WordPress/proxy TLS are retained
exactly. Rotating those roles needs separate coordinated rekey contracts. The
pseudonym key cannot change without changing participant identities.

Source revision, source fingerprint, all image IDs, provider identity,
origins/listeners, reviewed content and notices remain fixed. Edge config/cookie
policy also remains unchanged. The V2 edge material hash is recalculated from
its four actual target files and bound into the participant manifest, hence the
new activation configuration. It is not accepted on the strength of a supplied
hash alone.

## Preparation and invocation

Obtain the complete stopped backup using the reviewed joined backup operation.
The source participant ledger must be closed, nonfaulted, inactive and contain
no unconsumed invitations. The source backup and key are retained without
rewriting either file. This command is engineering tooling, not permission to
use retained/live data or issue production credentials.

Prepare a new private directory containing **all** participant material with
exactly the archived names. Keep the service manifest's logical paths
`/run/fncp/...` and state directory `/var/lib/fncp`; never substitute host paths.
Change only the permitted credential files and set one new UUIDv4 recovery
epoch. Preserve all other manifest fields. For V2, the coordinator computes the
edge digest itself in its private copy. Input material is never rewritten.

Create a private JSON job file with these fields:

```json
{
  "profile": "FNCP_JOINED_RENEWAL_JOB_V1",
  "backupDirectory": "/private/old-backup",
  "keyDirectory": "/private/old-key",
  "candidateMaterialDirectory": "/private/candidate-participant-material",
  "recoveryEpoch": "NEW-UUID-V4",
  "targetBackupDirectory": "/private/new-backup",
  "targetKeyDirectory": "/private/new-key"
}
```

Optional `receiverTrustFile` and `edgeUpstreamTrustFile` supply replacement CA
files when the existing trust cannot authenticate a renewed leaf. Optional
`edgeCertificateFile` and `edgePrivateKeyFile` must be supplied together and
require V2. A changed public edge pair can be the only credential rotation.
The example is a shape, not a usable UUID or ready-to-run deployment job.

All input directories must be canonical, owned and mode 0700; files must be
single-link, owned, private 0400/0600 material or 0600 backup/job files. Backup,
key, material and target directories must be distinct and nonoverlapping.
The two target directories must not exist. No force/reuse/adoption is available.

```sh
node deploy/fncp/production-deployment/joined-renewal.mjs /private/renewal-job.json
```

Only aggregate counts, changed roles and digests are printed. The new key is
`targetKeyDirectory/recovery.key`; `targetBackupDirectory` receives the encrypted
bundle, `renewal.json`, and a final `backup.json` success marker. The existing
`restoreJoinedProduction` accepts this backup into another new stopped target.
It does not start that target or grant admission.

## Preserved state and activation

Both native database archives remain byte-for-byte identical, retaining voting,
analysis and WordPress state. Access accounts, lifetime quota slots, terminal
revocations, pending provider removals, approval/event history, consumed
invitations and access clock remain identical; only the access binding hash is
resealed. `activation.sqlite` remains byte-identical, including accepted IDs and
sequence floor. The encrypted metadata retains the original activation binding
so restore can validate the copied inactive ledger without inventing a new
activation. All invariant activation fields must still match the renewed
binding; only configuration digest and epoch can differ.

Normal startup still requires a new signed activation and starts with admission
closed. A renewed backup cannot be renewed again before a normal closed startup
and fresh backup; this prevents silently stacking unactivated transitions.

The implementation authenticates the whole source bundle before opening
members, verifies role-specific owners/modes and exact inventories, preserves
logical runtime fingerprints while using private host scratch paths, verifies
the final encrypted output by independent decryption, rechecks source/candidate
custody, and removes only its own recorded scratch inodes. `backup.json` is
written only after successful plaintext cleanup. A crash or failure can leave
partial target ciphertext/key material or an explicit lock; never infer success
from directory existence, remove another lock, or reuse a partial namespace.

## Evidence limits

`node --test deploy/fncp/production-deployment/joined-renewal.test.mjs` covers
complete V1/V2 encrypted transformations, independent decryption/inspection,
20 lifetime slots, seven terminal revocations, four pending removals, retained
activation sequence, coordinated CA changes, public edge-only TLS renewal and
rejection of mismatched trust, key, image/source, path, epoch, tampering,
symlinks and occupied targets. Native database archive members in these tests
are **synthetic placeholder bytes**, not running PostgreSQL/MariaDB evidence.
Existing participant renewal tests separately exercise real normal-service
activation rejection and closed restart using local synthetic fixtures.

A native joined restore, actual database/application restart, browser journey,
real OIDC secret acceptance and approved HTTPS trust remain separate proofs.
No live provider credential is changed by this operation, and no certificate
is installed into machine trust. Do not claim every secret was rotated or a
public rollout was completed from these tests.
