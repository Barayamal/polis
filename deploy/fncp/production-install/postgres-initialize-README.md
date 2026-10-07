# Fresh PostgreSQL maintenance candidate

This is a separate, fresh-only maintenance plan for the existing normal eight-image deployment. It does not turn normal startup into an installer. It reuses:

- `server/bin/fncp-initialize-database.sh` in the reviewed PostgreSQL image for four restricted roles and an empty dedicated database;
- `server/bin/fncp-run-migrations.sh` in the reviewed short-lived migration image for the current twenty checksummed migrations and runtime ACLs;
- `production-deployment/native-round.mjs` for the exact migration-hash, statement-text/hash and normal configuration contracts;
- the existing narrowly scoped math grants from `selfhost/fncpctl.mjs`.

`postgresInitializationPlan(configuration, imageLock, ownerToken, request)` performs **no I/O**. It returns four maintenance service descriptors, parameterized SQL and equivalent psql stdin. It does not inspect Docker, create volumes, validate private material, execute the database operations or attest that a deployment is safe. The executor must establish those prerequisites before acting. Never report a rendered plan as a completed installation.

The request is exactly `{statements, seedSha256, topic, description}`. Supply fifteen approved ordered strings and their SHA-256 of `JSON.stringify(statements)`. Fresh native statement IDs must be exactly `0..14`; Pol.is's actual trigger assigns them and the transaction verifies its result. Conversation and owner numeric IDs come from PostgreSQL `RETURNING`, not an assumed `zid=1` or `uid=1`. The exact conversation code is the normal configuration binding. There is no real participant identifier, staff email, password or arbitrary SQL input.

The transaction creates a credentialless internal seed author, that author's native participant row, one **closed** nonpublic conversation, its native conversation-code mapping and fifteen active/moderator-approved seeds. The author has no email, password, OIDC mapping or XID. This is not a real voter account or participant invitation. The native participant count is one internal seed author; the receipt separately records `seedAuthors:1` and `participantAccounts:0`. No votes, provider allowlist entries, Treevite invitations or participant activation are created.

## Fail-closed behavior

The fresh volume wrapper checks UID/GID70, exact root mode0700, no symlink and an entirely empty `/var/lib/postgresql/data`, then invokes the unchanged role initializer. It has no force, adopt, reset, cleanup or path override. Existing/partially initialized volumes reject. A failed or interrupted role initialization is not automatically retried or deleted.

Closed-round SQL requires PostgreSQL17, a writable primary, verified-TLS client configuration, an actual TLS1.2/1.3 session, the configured migration role, no owner/superuser/role-membership privileges, the reviewed migration history and migration-owned invoker-security public objects. Every public base table is locked and checked empty before any seed write. Existing rows anywhere in the public schema reject, including a previously successful initializer. The single serializable transaction holds bounded locks and checks the final IDs, text, privacy flags and counts before COMMIT. There is no partial seed adoption or data repair. PostgreSQL sequences can advance on a rolled-back attempt; no step resets them, and no fixed numeric owner/conversation ID is assumed.

The math role must begin with no effective public table, sequence or function privileges and no migration-schema usage. After its reviewed grants, the transaction checks the exact effective table/function allowlist. An accidental pre-existing `UPDATE` privilege on native votes therefore rejects; the initializer never silently revokes or repairs drift. The fixed psql client explicitly rejects invalid TLS mode, host, port or CA path before attempting a connection. It does not rely on shell `set -e` to stop a failed AND-list.

This is schema/history-contract checking, not forensic attestation against a hostile database administrator. The operator must prevent concurrent DDL, migrations, application writers, volume tampering and same-user material modification. Never point a fresh initializer at a retained QA, staging or production database.

## Native execution recipe for the owned local rehearsal

Only the scoped executor—not this module—may run these steps. Use an explicit task-owned Docker socket, pinned image IDs already verified in that engine, zero published ports, an internal-only core network and a **new** owner-labelled PostgreSQL volume. Use invented local certificates and secrets for the rehearsal. Keep all WordPress, API, math, participant and proxy application services stopped during initialization.

1. Validate the material-stage receipt and exact bytes. Render and revalidate the normal descriptor. Assert the new deployment's named resources are absent; create them exclusively with the expected independent ownership labels. Establish only the new PostgreSQL volume's Linux UID/GID70 and mode0700. Do not chmod or adopt an existing volume.
2. Run `plan.maintenance.initialize` once as a short-lived container. It has `network_mode:none`; it uses only the local Unix socket during role creation. Wait for successful exit, independently inspect exact ownership, and retain aggregate-only evidence. No role password belongs in argv, logs or reports.
3. Start only `plan.maintenance.start` on the owned internal core network, using the normal `postgres` alias. Verify the actual image, mounts, labels, network and absence of published ports, then wait for PostgreSQL readiness.
4. Run `plan.maintenance.migration` unchanged. Its TLS `verify-full` connection uses the existing migration env/CA material. Require exit0 and the complete twenty-file checksum ledger. Do not bypass an error by manually marking migrations applied.
5. Start a short-lived `plan.maintenance.seed` process with stdin attached (`-T`/non-TTY). Pass `plan.psql.stdin` directly as stdin, not through an interpolated shell command. Its fixed client requires `postgres:5432`, `PGSSLMODE=verify-full` and `/run/fncp/database-ca.pem`. It accepts no arbitrary connection string or SQL file path.
6. Require exit0/COMMIT before using `validatePostgresInitializationReceipt(plan, parsedReceipt)`. That validator checks only the returned shape/binding; independently connect again and verify persisted closed flags, fifteen exact seed IDs/texts, one seed author/native participant, zero votes/XIDs/allowlists/auth mappings/invitations and the intended role privileges. Retain aggregate counts and hashes only.
7. Repeat the seed attempt deliberately as a negative test. It must reject with `FNCP_FRESH_POSTGRES_NOT_EMPTY`, exit nonzero, and preserve all verified rows and seed bytes. An initialize repeat against the existing volume must also fail before invoking `initdb`.
8. Before successful seeding in this **new task-owned synthetic database**, the rehearsal checks wrong database/role/TLS settings and injects deliberately mismatched statement IDs, a changed migration-ledger digest, an unrelated public row and an excess math grant. Database mutations for these negative cases occur inside serializable transactions; their expected rejection closes the psql session and rolls the transaction back. Later independent probes verify the original migration hashes, empty unrelated table, intended math ACL and exact successful seed state. Sequence allocation may advance on a rolled-back attempt; the harness never resets numeric identifiers. Error markers must match the intended rejection: an unrelated connection/tool failure cannot count as a passing negative test. Never inject these faults into a retained QA, staging, participant or production database.
9. Stop the owned PostgreSQL process, restart with the **unchanged** normal start descriptor and independently repeat closed-state/role/schema verification. Then continue the complete normal-stack and joined recovery rehearsal. No maintenance success opens native voting or participant admission.

The plan deliberately returns service fragments, not an automatically executable replacement Compose project: a reviewed executor must connect them to the exact owned normal volume/network descriptors and keep the normal seven-service profile immutable. Do not merge the initializer or seed client into a public or normal-start service.

## Disposable synthetic CLI

`rehearse-postgres.mjs` implements the local recipe against two explicit immutable images already loaded into an explicit task-owned Docker engine. It does not start a VM, pull/build images or change the default Docker context. Supply a new evidence directory; there is no resume, adoption or overwrite flag:

```sh
node deploy/fncp/production-install/rehearse-postgres.mjs \
  unix:///absolute/task-owned/docker.sock \
  sha256:EXACT_POSTGRES_IMAGE_ID \
  sha256:EXACT_MIGRATION_IMAGE_ID \
  /absolute/new-private-evidence-directory
```

The CLI currently accepts a local macOS socket path under `/Users/`; the illustrative socket above must be replaced with the actual verified path. Image IDs must each be `sha256:` followed by 64 lowercase hexadecimal characters. The source configuration uses **six explicit unexecuted image placeholders** solely to satisfy the pure plan's complete normal descriptor shape. Those roles are not loaded, inspected or started. This is not an eight-image release lock, full-stack integration or joined-recovery attestation.

The executor generates new invented secrets and a local certificate hierarchy using `selfhost/prepare-local-material.mjs`, validates that material, tar-copies only required PostgreSQL material into new labelled volumes, and uses an internal-only network with no published ports or host bind mounts. Every mounted volume and removed resource must have the expected independent ownership label on the unchanged engine. Attempted creations are tracked before dispatch so an ambiguous client failure can still be inspected safely. Container/network cleanup uses inspected immutable IDs. Private scratch material and only those verified synthetic resources are removed in `finally`; any cleanup failure makes the final outcome incomplete.

Evidence contains selected source hashes, actual two-image metadata, verified in-image initializer/migration-file hashes, migration output, aggregate closed-state receipts before/after restart, per-check results and cleanup status. It does not retain generated credentials, TLS keys, statements or a reusable private runtime. `summary.json` explicitly records `fullStackIntegration:false`, `joinedRecovery:false` and `launchAuthorized:false`. Read the checks and source hashes alongside a PASS; a historical receipt is not proof of a changed image/source combination.

## Tests and remaining evidence

```sh
node --test --test-reporter=spec deploy/fncp/production-install/postgres-initialize.test.mjs
```

The thirteen host tests cover data-only SQL transport, immutable snapshots, current source migration pins, malformed inputs, object hooks, fixed empty-volume guard, restricted maintenance descriptors, exact math ACLs, closed seed invariants, receipt binding and actual shell client-guard rejection. They do not execute PostgreSQL. The separate native rehearsal verifies real initialization, all twenty migrations, seed creation, expected negative rejections, DML/DDL/tracking privileges, restart and independently observed persisted state for its exact source/two-image pair. Its successful receipt is not a complete deployment claim. Full-stack integration, real issuer/HTTPS, current image scans, joined closed recovery, exact staging approval and separate opening gates remain unchanged.

Official upstream background: [Pol.is self-hosting README](https://github.com/compdemocracy/polis/blob/stable/README.md), [configuration](https://github.com/compdemocracy/polis/blob/stable/docs/configuration.md), [TLS guidance](https://github.com/compdemocracy/polis/blob/stable/docs/ssl.md). These project-specific WordPress/access/activation safeguards are not an upstream guarantee.
