# Synthetic local PostgreSQL backup and isolated restore proof

**Not production recovery assurance. No real participant data is allowed.**

This helper backs up only the dedicated completed synthetic Pol.is database in
the exact Docker context `colima-fncp-c-20260913`, then restores the archive into
a **new** disposable, isolated PostgreSQL container. It never restores over the
source or any existing database and never changes the source database.

## Before running

1. Complete the fifteen-statement synthetic bootstrap and activation; no pending
   `.synthetic-bootstrap-restart` marker may remain.
2. Finish all synthetic vote smoke tests and stop generating new synthetic votes
   during this proof. It checks source aggregates before and after the backup and
   fails if they change; it does not pause the source services or claim a shared
   snapshot across separate checks.
3. Verify that this dedicated context and clone contain **synthetic data only**.
   The helper independently checks exact compose identity, a private source DB
   network without published ports, the configured synthetic conversation marker,
   all fifteen known seed statements, no other conversations/comments or out-of-scope
   votes, and no email other than the documented `admin@polis.test` fixture.
   These guards are not forensic proof of every database field's provenance.
4. Do not substitute a public Pol.is, WordPress, production or unrelated database.

## Static checks — no Docker actions or database reads

From this repository root:

```sh
node --test deploy/fncp/local-recovery/recovery-proof.test.mjs
```

## Execute the local synthetic recovery proof

Only after the stable synthetic vote checkpoint is ready:

```sh
FNCP_LOCAL_RECOVERY_MODE=synthetic-local-restore-proof node deploy/fncp/local-recovery/recovery-proof.mjs
```

The exact confirmation-style mode is required; no default enables recovery work.
The helper internally reads the existing `.env.staging`, without printing secrets.
It does **not** accept database, host, Docker context, source container, target
container or archive overrides from a command line.

## What happens

1. Resolve the source PostgreSQL service via this clone's exact compose path and
   configured synthetic project. Verify its running container ID, project/service
   labels, compose file, one internal-only network and absence of published ports.
2. Run an aggregate-only guard against the exact dedicated synthetic database.
   The SQL returns schema/count values, not names, participant identifiers,
   statement contents, raw votes, tokens or credentials.
3. Export a custom-format `pg_dump --no-owner --no-acl` archive to a newly created
   permission-0600 file beneath gitignored `.runtime/` (directory0700, umask0077).
   Verify stable source aggregates before accepting the archive as complete.
4. Create a random, run-labelled internal Docker network and **new container** from
   the exact source image ID with `--pull=never`. No external image is downloaded.
   The target has no published ports, no existing volumes/bind mounts and tmpfs
   PostgreSQL storage. A separate empty init-directory tmpfs masks the source
   image's migration initialisers, so the target database must prove empty first.
   Readiness uses the final server's TCP listener, not the temporary Unix-socket
   server used by PostgreSQL's init process; this avoids an init/shutdown race.
5. Restore into the new target database only. Local trust authentication is used
   solely inside that disposable private target; this is unsuitable for production.
6. Independently recheck aggregate schema table/column/index/routine/constraint
   counts, the known fifteen fixed seeds, and total/current vote-row counts.
7. Remove only the exact container and network created by this execution after
   verifying their unique run ownership labels. It never performs a Docker prune,
   compose down, source stop, source volume removal or existing-database deletion.

## Local evidence and retention

- `.runtime/synthetic-recovery-<random-run>.dump`: private local synthetic archive.
- `.runtime/synthetic-recovery-<random-run>.evidence.json`: aggregate-only result,
  archive size/mode/SHA-256, before/restored counts and cleanup outcome.
- A failed export can leave a `.partial.dump`, which is **not a verified backup**.
- Failures report precise lifecycle stages and fixed, redacted diagnostic codes;
  they never print child stderr, database contents, SQL, credentials or IDs.
- Successful synthetic archives/evidence are retained locally; do not upload,
  commit or send them. They can contain synthetic credentials/identifiers even
  though the report never exposes those values.
- If the process is forcibly interrupted, a labelled target/network may remain.
  Inspect only resources with `org.barayamal.fncp.local-recovery-run` in the exact
  context, verify the execution-owned targets, then request scoped cleanup if
  uncertain. Never reuse a partial target or delete broadly.

## What a PASS means—and does not mean

A PASS establishes that this **synthetic PostgreSQL archive** restored into a new
isolated local database and matched the specified aggregate checks. It does not
prove byte-for-byte row equality, every schema definition, whole-service restore,
encryption at rest, managed backup access, retention policy, off-machine durability,
production RPO/RTO, production secrets recovery or deployed session/approval-state
reconciliation. The separate local-access SQLite database is **not** included.
These remain deployment/operational assurance work before any live approval.

All public Pulse surfaces remain closed and unchanged. No messages, cloud
resources, external transfers or production operations are performed.
