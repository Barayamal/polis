# Barayamal Pol.is self-hosting implementation

This package implements a **closed local core** using upstream Dockerfiles and Docker Compose. It is an engineering milestone, not the full production participant deployment. Read `services.json` for the exact included and outstanding components. All commands require explicit configuration and an explicitly selected Docker engine. No services publish host ports.

## What is implemented

- Separate dedicated API, math, PostgreSQL and migration images. Dedicated API and math heaps are capped at 1024 MiB inside their 1536 MiB containers; upstream targets retain their existing defaults.
- A private Compose network and persistent owned PostgreSQL volume.
- New initialization distinct from ordinary startup; source-controlled migrations.
- Separate owner, migration, API runtime and restricted math roles.
- Certificate/hostname-verifying database TLS for API, migrations and math.
- Dedicated API initialization/readiness before listening, default closed.
- Exact participant/provider route manifest; upstream mapping, report and export routes are unavailable in this dedicated process until a separate authenticated staff interface exists.
- Image digest, private input manifest and exact resource ownership checks for lifecycle actions.
- A separate production identity adapter under `../production-identity`; it is not yet wired to a complete participant service.

The original synthetic-only services remain unchanged. The old voting evidence does not certify this new layout. The separate 18-person math fixture is an engine test using SQL; it does not stand in for participant approval or browser voting.

## Configuration

Copy `configuration.example.json` outside the source tree, replace its paths/revision/binding, and give it mode 0600. The deployment/state name must be new. Use the current source checkpoint and manifest; the prior upstream baseline alone does not describe modifications. `configuration.mjs` is the strict executable contract and rejects extra fields. No password belongs in the public configuration.

The core requires an exact pre-established, closed conversation with 15 approved active fixed seeds. Local rehearsal may insert an explicitly labelled synthetic SQL fixture after migrations. The public sample contains fixture identifiers, not a real conversation binding.

Docker must run Linux ARM64. On macOS, mount only the task's private runtime parent into the selected VM; Compose bind mounts are resolved on the Docker daemon. The source is sent as a Docker build context. Never mount the user's home directory just to resolve secrets. Use a new Colima profile with activation and SSH-config updates disabled; the controller never chooses or starts a VM.

## Commands

From the repository root, where `<config>` is the absolute private configuration path:

```sh
node deploy/fncp/selfhost/fncpctl.mjs validate <config>
node deploy/fncp/selfhost/fncpctl.mjs source-lock <config>
node deploy/fncp/selfhost/fncpctl.mjs build <config>
node deploy/fncp/selfhost/prepare-local-material.mjs <config>
node deploy/fncp/selfhost/fncpctl.mjs init <config>
# For the supplied synthetic binding only; inserts an SQL engine/startup fixture:
node deploy/fncp/selfhost/fncpctl.mjs fixture <config>
node deploy/fncp/selfhost/fncpctl.mjs start <config>
node deploy/fncp/selfhost/fncpctl.mjs status <config>
node deploy/fncp/selfhost/fncpctl.mjs stop <config>
```

`build` creates a fresh state directory and stores image/source identities plus build logs. It refuses an existing directory. `prepare-local-material` generates seven-day synthetic database certificates and local-only secrets in a new private subdirectory; this is not a production key/certificate management process. Mount-readable inputs remain protected by their private host parent and are mounted only into their intended services.

`init` rejects existing resources with the same project or exact names, verifies credentials/certificates and their private manifest, claims a new Compose namespace, initializes the empty database, runs migrations, then grants the math role. It does not start the API. `start` requires the initialization record and source-bound images; API readiness rejects an absent, open or incorrect conversation. `stop` closes the API, stops math and any maintenance writer, then stops PostgreSQL; it verifies ownership and preserves data. Commands never perform `down -v`, delete unrelated resources or operate through an ambient Docker context.

A failed build or initialization remains available for diagnosis. Use a fresh state/deployment after correcting a failed attempt; do not delete its evidence or invent a force/adopt flag. An operation lock is intentionally not removed after an unclean process crash: inspect the owned process/resources before an operator removes the exact stale lock.

## Restricted local export and offline recovery

An operator who owns the private configuration can export current aggregate results to a new mode-0600 file inside an owned mode-0700 directory:

```sh
node deploy/fncp/selfhost/operator-export.mjs export <config> <absolute-private-directory>/results.json
```

The fixed read-only query and output validator require the current closed conversation, its 15 fixed approved seeds and complete current math/moderation watermarks. The export contains statement totals, group sizes and consensus values. It excludes identities, individual votes and participant/group mappings. It is an operator tool; the browser-facing OIDC staff interface is not implemented.

For a complete encrypted physical recovery of this closed core into new owned resources, use the reviewed procedure in [recovery/README.md](recovery/README.md). Stop with the matching source controller first, prepare the restored target, then start and verify it with the ordinary launcher. This core recovery does not include the WordPress/access/activation stores of the future full participant deployment.

## Verification and completion limits

Run the package tests with `node --test deploy/fncp/selfhost/configuration.test.mjs deploy/fncp/selfhost/material.test.mjs`. Server and math have their own meaningful startup/TLS tests. Release status comes from executed evidence bound to exact source and image identities, not from passing configuration tests alone.

Remaining full-deployment work includes the production participant composition, actual provider login, WordPress/MariaDB wiring, TLS edge, restricted staff result/export interface, joined WordPress/access restoration and target operations. Real accounts, cloud resources and pilot opening require their applicable authorization. The current core stays closed with no participant route.

See `recovery-contract.md` for the complete required recovery unit. Upstream references: [self-hosting](https://github.com/compdemocracy/polis/blob/stable/README.md), [configuration](https://github.com/compdemocracy/polis/blob/stable/docs/configuration.md), [math](https://github.com/compdemocracy/polis/blob/stable/math/README.md), [HTTPS](https://github.com/compdemocracy/polis/blob/stable/docs/ssl.md).
