# Closed participant-state credential renewal — candidate, not a live rollout

`renewal.mjs` is a separate, offline operation. It does not relax the existing
same-credential `recovery.mjs` contract and does not start a service, call an
identity provider, send messages, issue certificates, write to source material,
or open admission. It remains a participant-ledger helper. The [joined backup renewal coordinator](../production-deployment/joined-renewal.md) now composes it into complete six-/seven-volume encrypted backup renewal.

## What it does

The helper holds the actual source and target service manifests and material
under the same private-file custody checks as normal startup. It derives both
binding descriptors from those bytes, then proves that only these changes occur:

- The confidential OIDC client's **secret**, not its issuer, client ID, endpoints,
  callback, algorithm, authentication method, trust root or pseudonym key.
- Participant and/or WordPress-event-receiver TLS key/certificate pairs, not
  their listener addresses or origins.
- A fresh recovery epoch and the configuration digest necessarily changed by
  the new material and new state directory.

The deployment, conversation, source revision, complete versioned image hashes, approval
keys, activation public key, all content, notices, participant identity key and
provider/WordPress contracts must remain identical. At least one credential or
TLS pair must actually change. It cannot authorize an image/source upgrade or
an identity-provider migration.

Only a drained, stopped, non-faulted source with **all invitations consumed**
and an inactive, valid activation ledger is eligible. A crash-left lock,
SQLite sidecar, active ledger, future access clock, missing ledger, material
drift, unrelated file in the target state directory, symlink, hard link or
non-private directory refuses the operation. Locks are never taken over.

Both `access.sqlite` and `activation.sqlite` are copied into a fresh private
target. Only the access metadata binding hash changes. Every account, lifetime
registration slot, receipt, approval/revocation event, pending provider removal,
consumed invitation and access clock is preserved. The activation ledger is
byte-identical, preserving all accepted activation IDs and the sequence floor.
The old signed activation cannot activate the new epoch/configuration. Normal
target startup stays closed and requires a fresh signed activation; even that
does not open admission automatically.

The target TLS leaf must have CA:false, match its key and exact host/IP, permit
server authentication if it has an Extended Key Usage restriction, be currently
valid and have more than one hour remaining. A supplied chain must be well-formed,
currently valid, and correctly signed in leaf-to-issuer order. This checks
material consistency, **not browser trust, revocation/OCSP, real-provider secret
acceptance or a public HTTPS deployment**. Source certificates may be expired;
source bytes still must reproduce the exact stored source binding.

## Operator procedure (not approval to operate on retained/live data)

1. Obtain a separately approved, joined closed-deployment maintenance window.
   Close admission and the native conversation, drain and stop services, and
   preserve a tested backup of all six V1 or seven V2/V3 durable volumes. Do not stop at copying
   only these two SQLite files.
2. Prepare a separate candidate material directory and an **empty** state
   directory, both canonical, owned by the executing service UID and mode 0700.
   Referenced material must be single-link, owned, mode 0400 or 0600. Source and
   target state directories must differ; target state cannot be in this source
   repository. Copy unchanged material exactly and change only approved roles.
   Keep the offline activation private key outside the runtime material.
3. Point the target manifest at those candidate files/state and set a new UUIDv4
   recovery epoch. Retain the original source manifest and all source material.
   Do not edit them in place. Reissue the correct certificate hostnames and
   securely configure the same real OIDC client through the separately approved
   provider process. Never pass credentials on the CLI.
4. Run under the appropriate service UID with Node's `node:sqlite` support:

   ```sh
   node deploy/fncp/production-service/renewal-cli.mjs \
     --source-manifest /private/source-material/service.json \
     --target-manifest /private/candidate-material/service.json
   ```

   The paths above are placeholders, not ready-to-run deployment paths. Output
   contains only aggregate counts, changed role names and digests. A failure
   returns a generic error without participant content, paths or credentials.
5. **Do not mount/publish the candidate yet.** Complete the missing joined
   deployment work described below, independently verify preservation, then
   boot closed and test with a fresh activation under explicit authorization.

Files and the target parent directory are fsynced before success. This is not
an atomic two-file filesystem transaction: a process/host crash can leave a
partial target and locks. Treat any error/interruption as an unusable candidate,
keep admission closed, preserve unknown/foreign files, and investigate before a
new invocation with a fresh empty namespace. Do not remove a lock based on PID,
age or this document. The helper only removes inodes it created when custody
still proves ownership; late cleanup failure can preserve an unusable target.

## Joined deployment integration and remaining proof

- Build this reviewed candidate into new images and rerun immutable release,
  security-scan and all joined recovery evidence; frozen September delivery
  images do not contain this new helper.
- Use the joined renewal coordinator to authenticate every durable volume,
  retain both native database archives and immutable secrets, coordinate receiver/edge
  trust and public edge TLS, then produce a complete independently encrypted
  candidate for the existing fresh-target restore. Its archive resolver keeps
  logical runtime paths in binding fingerprints. This helper alone does not
  provide that complete workflow or validate peer trust files.
- Rehearse that exact candidate through a native joined restore and closed
  startup; synthetic archive tests are not native database or provider proof.
- Verify actual OIDC secret acceptance, HTTPS/browser trust, session/logout,
  account disable, approval/revocation, event delivery and restore on the real
  approved closed staging environment before any participants are invited.
- Implement certificate expiry monitoring and an approved renewal ceremony;
  this helper does not install an ACME client, schedule rotation or permit
  hot-reloading material. Runtime custody deliberately closes on file changes.

## Synthetic validation

`node --test deploy/fncp/production-service/renewal.test.mjs` uses fresh,
disposable loopback fixtures only. It compares derived binding evidence with
the real normal service descriptor; preserves 20 lifetime slots, seven revoked
accounts and four pending removals; copies the used-activation replay floor;
refuses old signed grants; and exercises material, time, locks, drift and
partial-copy failure boundaries. It does not claim real OIDC or whole-stack
renewal has been executed.
