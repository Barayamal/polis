# Joined cold backup and recovery

`recovery.mjs` backs up a stopped, preprovisioned normal deployment and restores its complete durable state into a fresh resource namespace. Backup and restore are separate commands: a later restore uses the authenticated backup and does not require the source engine or source volumes to exist.

The target keeps the logical deployment ID, conversation, fifteen statements, identity mapping, endpoints, the exact versioned image set (eight in V1, nine in V2 or ten in V3), credentials and container paths. Only the Compose resource namespace, host state path and recovery epoch change. It starts no application or database service and grants no participant admission.

This module is separate from `production-service/recovery.mjs`, which reseals only an access SQLite copy. The joined module also preserves the activation replay ledger, native PostgreSQL and MariaDB clusters, WordPress approvals/outbox/receipts, and all required runtime material.

## Before backup

1. Close participant admission and the native Pol.is round using their reviewed operator/maintenance interfaces. Capture the private service `recovery-descriptor` after closing admission. Do not publish that descriptor or private material.
2. Gracefully stop the normal deployment and its native operator listener. All normal services must be stopped (seven in V1, eight in V2 or nine in V3); an optional completed migration container may remain. PostgreSQL, MariaDB and participant must have exit code zero. The module does not stop source services for you. V3 retains its exact configured loopback bindings while stopped, but Docker must report no active runtime port attachment.
3. Confirm that this is the exact normal `compose.mjs` deployment. The older four-service controller and arbitrary QA overlays are not accepted as equivalent. Every image must be present by exact ID, `linux/arm64`, with the same source revision label. Source labels, commands, environment, UID, resource limits, private networks, ports, isolation, volume/bind paths and read-only settings are independently inspected against the fixed renderer.
4. Prepare a private job file, mode0600, inside a canonical current-user-owned0700 directory. Use an explicitly owned local Unix Docker socket and private Docker config directory. No ambient Docker context, remote daemon, image pull or arbitrary command is accepted.

The source host `material/` must contain the twelve reviewed core files: API/math/migration env files, PostgreSQL CA/server certificate/key and four passwords, and the JWT pair. The four existing CA-generation files may also be present and are preserved. Unknown files reject the job. Required recipient-readable0644 files remain protected by their0700 host material directory; this preserves the normal per-file bind contract.

## Private backup job

Create this JSON from the already verified source records; angle-bracket values below are descriptions, not runnable defaults:

```json
{
  "profile": "FNCP_JOINED_BACKUP_JOB_V1",
  "engine": {
    "binary": "/opt/homebrew/bin/docker",
    "host": "unix://<owned-absolute-socket-path>",
    "configDirectory": "<owned-absolute-0700-Docker-config-directory>",
    "id": "<freshly-verified-engine-ID>"
  },
  "source": {
    "configuration": "<parsed configuration.json object>",
    "imageLock": "<parsed images.json object>",
    "ownerToken": "<owner.json token>",
    "accessDescriptor": "<private closed-service recovery-descriptor object>"
  },
  "backupDirectory": "<new-absolute-backup-directory>",
  "keyDirectory": "<separate-new-absolute-key-directory>"
}
```

The backup/key directories must not exist. Their existing parents must be canonical, owned0700 directories. Neither may overlap the source, repository or each other. Linux Docker binaries `/usr/bin/docker` and `/usr/local/bin/docker` are also accepted. The supplied engine ID and socket inode are rechecked; this is not permission to adopt an unrelated engine.

```sh
node deploy/fncp/production-deployment/recovery.mjs backup /private/operator/backup-job.json
```

The command holds a source operation lock, verifies every reference to every source volume, and reads source volumes through bounded, no-network, nonroot helpers with read-only mounts. PostgreSQL must report a clean shutdown through its exact image's `pg_controldata`. Source volumes are read twice, and each file's content/owner/mode inventory must match. Runtime material hashes must match the captured access binding, including the WordPress and Pol.is bridge secret links. Access state must pass the complete store validator, have no fault or unused invitation, and not have a future clock. The activation ledger must be inactive with the exact authority/binding/schema and its retained replay floor/accepted IDs.

The resulting backup directory contains `joined.aes256gcm` and its private `backup.json` receipt. The separate key directory contains the new32-byte `recovery.key`. Keep both under their existing custody and retain the key separately from the ciphertext. The offline activation signing private key is never requested or included.

The complete backup includes six durable volumes in V1 or seven in V2/V3 in one AES-256-GCM-authenticated bundle:

| Volume | Preserved state |
| --- | --- |
| `postgres` | Complete stopped PostgreSQL17 cluster, roles, native votes/math/moderation data and database TLS configuration |
| `mariadb` | Complete stopped MariaDB cluster, native WordPress accounts, registration receipts, approval and terminal-revocation history, immutable outbox bodies |
| `participant_state` | `access.sqlite` and `activation.sqlite`, including clocks, revocations, consumed invitations and activation replay floor |
| `participant_material` | `service.json` and every referenced identity/bridge/TLS/public activation file |
| `wordpress_material` | Native runtime/plugin configuration, independent bridge keys and TLS material |
| `proxy_material` | Private proxy TLS pair |
| `edge_material` (V2/V3) | Participant edge configuration, independent TLS pair and upstream CA |

The core host material and source descriptors are inside the encrypted metadata. The transient MariaDB socket volume is excluded and recreated empty. Missing required components, live references, locks, SQLite sidecars, unexpected files, links, devices, traversal, ambiguous TAR extensions or incompatible numeric owners reject the operation. The entire uncompressed bundle is bounded to512MiB, with at most20,000 TAR members per volume; larger deployments require a separately reviewed profile.

## Private restore job

Use the retained backup/key directories and a new namespace, state path and UUID4 epoch:

```json
{
  "profile": "FNCP_JOINED_RESTORE_JOB_V1",
  "engine": {
    "binary": "/opt/homebrew/bin/docker",
    "host": "unix://<owned-absolute-socket-path>",
    "configDirectory": "<owned-absolute-0700-Docker-config-directory>",
    "id": "<freshly-verified-target-engine-ID>"
  },
  "backupDirectory": "<existing-private-backup-directory>",
  "keyDirectory": "<existing-separate-private-key-directory>",
  "target": {
    "deployment": "fncp-new-recovery-namespace",
    "stateDirectory": "<new-absolute-private-state-directory>",
    "recoveryEpoch": "<fresh-UUID4>"
  }
}
```

```sh
node deploy/fncp/production-deployment/recovery.mjs restore /private/operator/restore-job.json
```

Authentication and complete inventory validation finish before any volume extraction. The complete exact versioned image set must already exist on the explicitly owned target engine. Every target volume/network/container name and project label namespace must be unused. A different owned engine is permitted when those exact images are present; no old engine identity is silently adopted.

The module derives `service.json` by changing only `activation.recoveryEpoch`, computes its exact new material/configuration hash, and reseals only `access.sqlite.meta.binding_sha`. All other access rows, timestamps and bytes of immutable receipts/events remain unchanged. `activation.sqlite` is copied verbatim; no replay floor or accepted activation ID is reset. Native PostgreSQL/MariaDB archives and every other private material file remain byte-identical.

Fresh volumes are created with the new ownership/project labels. A temporary network-isolated helper uses UID0 and only `CHOWN`, `DAC_OVERRIDE` and `FOWNER` to restore numeric owners into an empty, exclusively created target volume. It has no host binds or source mounts. Readback helpers use the relevant service UID with all capabilities dropped. Each restored file-content/owner/mode inventory is compared with the authenticated archive. Helpers are stopped/removed only after their exact ownership/profile is rechecked.

The target host state contains `configuration.json`, `images.json`, `compose.json`, `owner.json`, private `recovery-descriptor.json`, core `material/`, and a `recovery-prepared.json` aggregate receipt. Six V1 or seven V2/V3 durable volumes plus one empty transient socket volume are prepared. Application networks and services are left for the reviewed normal launcher. V3 retains the tenth stateless gateway image and its activation-bound loopback access profile; it adds no durable volume. Do not merge a Compose override into this document or substitute its exact images.

## Required verification before admission

A successful restore means the complete target state was prepared and its bytes verified. It does **not** mean the normal deployment has started, native database rows have been queried, or restored participation is authorized.

The operator must separately perform the normal closed start, verify PostgreSQL TLS/roles/migrations and native round closure, verify native WordPress/MariaDB preflight and the preserved outbox/receipt history, check access and activation replay floors, and compare native conversation/statement/vote/math/moderation aggregates plus identity attribution. Confirm old browser sessions and used invitations cannot be reused, terminal revocations still deny, and pending removals reconcile. Only then may a separately reviewed fresh activation signature and explicit round/admission action be considered.

No schema, database major version, image/source, identity, credential, endpoint or signing-authority migration is supported by this recovery path. Such a change is rejected instead of treated as a recovery epoch update.

## Failures and evidence

Public return values contain counts, hashes and explicit preparation/closure limits. They contain no account IDs, WordPress users, individual votes, invitation tokens, receipt bodies, private keys or database credentials. A thrown error may carry only a fixed operation-stage label for private diagnosis; CLI errors are generic. Do not export private job files, backups, keys, TAR inventories, runtime state or raw helper output.

Normal cleanup unlinks only invocation-created private plaintext inodes and owned helpers. It is not secure erasure. A SIGKILL, custody replacement, cleanup error or late lock-release failure can leave a private staging directory or an unconfirmed target. Every thrown result means **unconfirmed**: preserve it for explicit custody review; never auto-adopt, resume, activate, remove source state or prune unrelated resources. The encrypted backup/key are retained after later restore failures. There is no overwrite/resume or stale-lock takeover mode.

Source checks and helper tests:

```sh
node --test deploy/fncp/production-deployment/recovery.test.mjs
node --test deploy/fncp/production-service/recovery.test.mjs deploy/fncp/production-service/recovery-service.test.mjs
```

The joined tests use synthetic private TAR contents, actual SQLite and actual service composition against local synthetic HTTPS peers. They do not start Docker or native PostgreSQL/MariaDB. A separately retained exact-image engine rehearsal is required before claiming end-to-end joined runtime recovery.
