# Disposable WordPress runtime — local proof only

Never point these scripts at live WordPress or import production content. No historical registration records are used. The PHP development server is deliberately not an Internet server; do not tunnel or publish any of these ports.

## Verified source and runtime

- WordPress 7.1 from `https://wordpress.org/wordpress-7.1.tar.gz`, matching the official HTTPS SHA-1 response `e0ca593bc062f7a8c5a956ca44aff7375b0841e0`; locally recorded SHA-256 `05a5f89138f632b7329f1202f2a0553c5f7fe4daf8e4b9ca7ebae9b9466b9e86`. SHA-1 here is a transport checksum comparison, not a modern code-signing guarantee.
- Existing host PHP 8.5.10; no new global PHP install.
- MySQL 8.4.11 official image pinned by digest in `compose.yml`; new `fncp-wordpress-synthetic` project and synthetic database volume only.
- Entire `.runtime/` is Git-ignored. Generated credentials and configuration are private. Do not copy credentials, fixture secrets, invitations, source archives or database files into the owner documentation folder or Git.

## Resume the prepared proof

From the isolated clone root, start the existing Pol.is stack as described in the owner guide. Then keep each host process in its own terminal.

1. Start the API and signed receiver:

   ```sh
   FNCP_LOCAL_SYNTHETIC_MODE=fixture-only node deploy/fncp/local-access/start.mjs
   ```

2. Check generated configuration, resume the separate WordPress database and verify the installed instance:

   ```sh
   FNCP_LOCAL_SYNTHETIC_MODE=fixture-only node deploy/fncp/local-wordpress-runtime/prepare.mjs
   DOCKER_CONTEXT=colima-fncp-c-20260913 docker compose -f deploy/fncp/local-wordpress-runtime/compose.yml up -d
   FNCP_LOCAL_SYNTHETIC_MODE=fixture-only php deploy/fncp/local-wordpress-runtime/install.php
   ```

   If the database is still starting, the installer now exits before WordPress setup with a fixed local error. Wait for database readiness and retry; it preserves an installed instance. Exact generated-configuration or database secret-file drift also stops instead of silently replacing the file. Diagnostics never echo private parser input.

3. Run the local WordPress server:

   ```sh
   FNCP_LOCAL_SYNTHETIC_MODE=fixture-only php -S 127.0.0.1:8102 -t deploy/fncp/local-wordpress-runtime/.runtime/wordpress deploy/fncp/local-wordpress-runtime/router.php
   ```

4. Run the separate voter browser service:

   ```sh
   FNCP_LOCAL_SYNTHETIC_MODE=fixture-only node deploy/fncp/local-browser/start.mjs
   ```

5. Open [local WordPress login](http://127.0.0.1:8102/wp-login.php) as `synthetic_admin`, using the private `adminPassword` in `.runtime/credentials.json` locally. Do not share it. Go to **Tools → FNCP synthetic approvals**. This has no relationship to the live Barayamal administrator account.

## Prepare a new synthetic browser test

The completed test fixtures are terminally revoked; choose a **new invented** name matching `synthetic_[a-z][a-z0-9_]{0,39}`. The example below must not already exist.

```sh
FNCP_LOCAL_SYNTHETIC_MODE=fixture-only node deploy/fncp/local-access/capture-mail.mjs register synthetic_next_demo
```

In the local WordPress Tools screen, approve that exact fixture. Only continue when its journal shows **ACKNOWLEDGED**. This confirms local synchronisation, not eligibility or heritage verification.

```sh
FNCP_LOCAL_SYNTHETIC_MODE=fixture-only node deploy/fncp/local-access/round-control.mjs open
FNCP_LOCAL_SYNTHETIC_MODE=fixture-only node deploy/fncp/local-access/capture-mail.mjs capture-invitation synthetic_next_demo
```

Read the newly generated private file at `deploy/fncp/local-access/.runtime/captured-mail/synthetic_next_demo.json` locally. Open [the synthetic voter screen](http://127.0.0.1:8100/), enter the fixture and fixture secret, then paste its invitation. Invitations expire in 15 minutes; the capture command issues a new one and invalidates the previous unused invitation. No SMTP, email or SMS is used.

Test response save/next statement, then revoke the fixture in the local WordPress screen and confirm an already-open session is denied. A failed delivery is not a verified revocation: close the local round and reconcile the retained outbox before proceeding.

```sh
FNCP_LOCAL_SYNTHETIC_MODE=fixture-only node deploy/fncp/local-access/round-control.mjs close
FNCP_LOCAL_SYNTHETIC_MODE=fixture-only node deploy/fncp/local-access/round-control.mjs status
```

Closing this gateway does not close every provider lifecycle route. It invalidates local invitations/participation sessions. Independently verified per-fixture revocation is still required.

## Stop without erasing evidence

Stop each of the three host processes with Ctrl-C, then:

```sh
DOCKER_CONTEXT=colima-fncp-c-20260913 docker compose -f deploy/fncp/local-wordpress-runtime/compose.yml stop
DOCKER_CONTEXT=colima-fncp-c-20260913 docker compose --env-file deploy/fncp/.env.staging -f deploy/fncp/docker-compose.staging.yml stop
colima stop --profile fncp-c-20260913
```

Do not run `down -v`, reset an existing database, clear the outbox, or remove a terminal revocation to reuse a fixture. Source, volumes and ignored proof files remain local.

## Test scope

`node --test deploy/fncp/local-wordpress-runtime/*.test.mjs` executes copied preparation code against temporary invented files, checking exact configuration preservation, secret-file drift, permission modes, local-only controls and redacted malformed-input errors. It does not use the installed runtime or connect to a database.

`php deploy/fncp/wordpress-local/tests.php` and `php deploy/fncp/wordpress-local/plugin-boundary-tests.php` are model/contract checks. Read the plugin README for the real WordPress integration command and its one-use synthetic fixture requirements. The complete browser proof and its limitations are recorded in [the continuation report](../LOCAL-C-JOURNEY-2026-09-13.md).
