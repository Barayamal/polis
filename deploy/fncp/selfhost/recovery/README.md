# Offline closed-core recovery rehearsal

This is a reviewable local rehearsal script. Authoring and primitive tests perform no Docker operations. Running its explicit `prepare` command does create a new owned volume/network and short-lived helper containers. It does not start PostgreSQL, API or math. The owner must first prove the final source core, stop it with its matching `fncpctl`, and review this script before invocation.

The recovery unit is the **closed local core**: a complete physical PostgreSQL cluster (including global roles, role memberships, database/schema/table/function ACLs, defaults, sequences, application data and math data), the exact four source image identities, public configuration, and private runtime/certificate/key material. It does not include WordPress/MariaDB, a production BFF/access/activation service, real provider sessions or pilot authority. No joined WordPress or production participant recovery claim follows from this rehearsal.

## Preconditions

- Use the final successfully validated core's configuration, never an older failed attempt or unrelated environment. The source database is a fresh single-cluster PostgreSQL 17 volume created by this project's initializer.
- Stop the source with its matching `fncpctl stop`. All source services must be exited; the PostgreSQL cluster must report **shut down**, with no postmaster marker or special files. No other container may reference its database volume. The script holds the source controller's `operation.lock` during the operation.
- Use the same explicit Unix-socket Docker engine, Linux ARM64 platform and exact PostgreSQL image. All four image IDs, revision labels, source revision/fingerprint, engine ID, resource ownership and source material must still match.
- Choose a new deployment name, a nonexistent state directory and a separate nonexistent key directory. Their parents must already be canonical, owned directories with mode 0700. Neither new directory nor the target config can live in the source repository or source state. The key directory must be outside both source and restored state.
- The target config must not exist. Its parent may be the new state directory or another already-owned private parent. Private files use exclusive creation; no adoption/overwrite/force mode exists.

## Invocation — owner-run only

The paths below are placeholders for newly selected private paths, not commands that have already executed:

```sh
node /absolute/path/polis-selfhost-dev/deploy/fncp/selfhost/recovery/offline-core-restore.mjs prepare \
  --repository /absolute/path/polis-selfhost-dev \
  --source-config /absolute/private/path/final-source-config.json \
  --target-config /absolute/private/path/new-restored-state/config.json \
  --deployment fncp-new-core-restore \
  --state /absolute/private/path/new-restored-state \
  --key-directory /absolute/private/key-custody/new-core-recovery
```

The same operation is exported as:

```js
await prepareOfflineCoreRestore({
  repositoryRoot,
  sourceConfigurationPath,
  targetConfigurationPath,
  targetDeployment,
  targetStateDirectory,
  keyDirectory,
});
```

Require process exit 0 and the final aggregate `result: "PASS"`. A private `offline-recovery-result.json` records the scope and explicitly reports `applicationRestartProven: false` and all three application processes unstarted. No raw archive, key, environment value, SQL content or private identifier is printed.

## What preparation verifies

1. Validate the selected source controller, private material manifest, images, engine, exact source volume and stopped state. Reject extra references to the source volume or any target namespace/resource collision.
2. Use short-lived UID/GID 70 helpers from the exact PostgreSQL image. Helpers have network `none`, a read-only root filesystem, all capabilities dropped, no published ports, no privilege escalation, bounded resources and exactly one explicit volume mount. Source volume mounts are always read-only. The only writable volume mount is the newly created target during extraction.
3. Read `pg_controldata` and PostgreSQL's own version tool without starting the server. Require clean PG17 shutdown and no diagnostic bytes on stderr; warning-only exit 0 is rejected. Stream a private uncompressed USTAR archive into an exclusive mode-0600 host file. Limit it to 512 MiB, 20,000 entries, the fixed `pgdata` subtree, UID/GID70, regular files mode0600 and directories mode0700. Reject links, device/special entries, PAX/GNU extensions, traversal, missing parents, duplicates, unsafe sizes, invalid checksums, truncation and data after end markers.
4. Encrypt the archive using a fresh AES-256-GCM key and IV. Authenticate the bounded header containing scope, engine/source/image/config/material and content digests. Store the raw32-byte key only in the distinct newly owned0700 key directory, as a mode0600 file; the key ID is recorded privately next to the encrypted archive. The key is not embedded in the ciphertext or copied into public evidence.
5. Decrypt into a separate exclusive private ephemeral file. Validate the authentication tag and expected context **before** archive inspection or any target extraction. Tampering or a wrong key fails and removes only that invocation's newly created unauthenticated plaintext.
6. Create a new labelled local volume and internal bridge network. Reinspect exact names and new owner labels; an existing or racing resource is not adopted. Mount the volume at the image's own `/var/lib/postgresql/data` path so Docker's normal image-directory copy-up supplies the existing postgres UID70 directory custody. UID70 must find it empty and writable; no root chown or privileged helper is used. Extract only the previously authenticated and validated archive.
7. Require clean shutdown again on the restored physical cluster. Retar it read-only and compare normalized path/type/mode/UID/GID/size/content hashes against the source archive. Retar the source read-only a second time and compare again. This verifies complete cluster file contents, including global role catalogs and ACL state, before any server mutates the restored cluster. It does not depend on a partial SQL dump or omitted ownership grants.
8. Copy the twelve validated runtime inputs and four locally generated CA recovery artifacts into a new private material directory, preserving bytes and modes. The local CA private key remains private and is checked against the CA public key. The target keeps the same database names/roles/passwords, public binding and identity settings; only deployment/state ownership changes. Verify source material again after copying. Runtime material remains private plaintext because the restored services must read it; it is not a public backup artifact.
9. Recreate the target source/image locks, owner token, material manifest and Compose configuration. Validate Compose and target ownership with no app containers present. Remove only the four exact, exclusively created, revalidated ephemeral tar files whose original inode/device and private custody still match. Then publish the initialized marker that permits a later ordinary start. Retain the encrypted snapshot, separate key, private manifests and receipts.

The normalized comparison includes bytes and file permissions/ownership, not filesystem inode numbers, traversal order or timestamps. This is an offline content-equivalence check. The PostgreSQL cluster's system identifier is intentionally preserved by the physical copy; the clone remains in its own internal local network.

## Finish the rehearsal through the normal launcher

After preparation exits successfully, run the ordinary matching source controller with the **target** config:

```sh
node /absolute/path/polis-selfhost-dev/deploy/fncp/selfhost/fncpctl.mjs start /absolute/private/path/new-restored-state/config.json
node /absolute/path/polis-selfhost-dev/deploy/fncp/selfhost/fncpctl.mjs status /absolute/private/path/new-restored-state/config.json
# Run the existing closed-core API/database-role and math observers against this target.
node /absolute/path/polis-selfhost-dev/deploy/fncp/selfhost/fncpctl.mjs stop /absolute/private/path/new-restored-state/config.json
```

Do **not** run `init` or the SQL fixture command on the restored target. The offline physical restore replaces initialization; the previous data and math state are already present. A completed core restoration claim additionally needs normal API readiness, current role/ACL checks, closed conversation/15-seed checks, persisted vote/math observations, no participant ingress and verified final shutdown. Record the restored result separately from source results. Preserve the source stopped and unchanged.

## Failure and custody

The script preserves the source, target volume/network, encrypted snapshot/key and private failure receipt. It never runs `down -v`, deletes a volume/network or touches an unrelated resource. Short-lived helpers are stopped/removed only after their exact ID, image, owner token and restricted mount/network profile are reverified. Private helper receipts record those IDs. Source lock removal checks the exact lock inode created by this invocation.

If the host process is killed uncleanly, keep the private recovery intent and helper receipts. Do not force a stale lock or adopt the partial target automatically; inspect the exact owned helper/process and preserve failed-attempt evidence. Normal success and failure paths remove invocation-created ephemeral plaintext through an inode-bound finally registry. The registry continues cleanup of other files if one path has been replaced, retains the replacement, and reports failure. An abrupt interruption such as SIGKILL can still leave private ephemeral plaintext; the script does not claim secure erasure or cleanup after process termination. No plaintext/key/recovery directory belongs in `outputs/` or a public source bundle. Store and back up ciphertext and its separate key under the selected private custody process.

## Tests already available

```sh
node --test archive.test.mjs encryption.test.mjs plaintext-custody.test.mjs
```

These 29 tests exercise archive bounds/traversal/link/type/custody rejection, AES-GCM round-trip/tampering/key/context/truncation behavior, normal failure plaintext cleanup, replacement-inode custody, existing-path collisions, and rejection of command diagnostics even with exit 0. They use temporary local files only and start no Docker or network service. They do not prove the Docker orchestration or a restored application's startup; those require the owner-run rehearsal above.
