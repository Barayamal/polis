# Joined installation continuation

See [INSTALL-CLOSED.md](INSTALL-CLOSED.md) for the explicit joined installer,
independent edge material and ordinary closed startup. V3 adds the exact
operator-loopback access contract and credential-free gateway documented in
[OPERATOR-LOOPBACK.md](../production-deployment/OPERATOR-LOOPBACK.md); it does
not create public access or approve launch.

# Fresh installation: separate material and maintenance candidates

This directory now also contains [fresh PostgreSQL maintenance](postgres-initialize-README.md)
and [fresh MariaDB/WordPress maintenance](wordpress-initialize-README.md), with separate
disposable native rehearsal entrypoints. They are not invoked by the stager or
normal startup. Their test receipts are distinct from material staging, full-stack
integration, renewal, recovery and release approval. Read those guides before
running an initializer; never target retained or live data.

`stage-material.mjs` turns an explicitly supplied, operator-owned material set
into a repeatable, verified staging directory for the supported V1, V2 or V3
normal-start composition. It copies supplied bytes; it **never generates or
silently rotates a credential, key, certificate or recovery epoch**. An identical
rerun verifies the existing target without rewriting files. A changed,
incomplete, unowned or unexpected target rejects rather than being repaired or
adopted.

This is **not a full installer or production-ready release**. It initializes no
database, site, volume, identity-provider account or participant. It starts no
process or container, uses no network, creates no activation and sends no
message. The receipt records `databaseInitialized:false`,
`linuxVolumeOwnershipEstablished:false`, `activationGranted:false` and the
descriptor's expected port count (`0` for V1/V2; two loopback-only bindings for
V3). Staging itself publishes nothing. Source tests cannot satisfy the remaining
runtime or launch gates.

## Why this exists

The normal Compose profile deliberately refuses to initialize PostgreSQL, MariaDB or WordPress at startup and mounts material volumes with `nocopy:true`. An empty host therefore cannot be made ready merely by running `docker compose up`. This tool closes the **material assembly and safe rerun** gap without weakening that separation. It is not an upstream Pol.is command; it is Barayamal-specific code around the [upstream self-hosting guidance](https://github.com/compdemocracy/polis/blob/stable/README.md), [configuration guidance](https://github.com/compdemocracy/polis/blob/stable/docs/configuration.md) and [TLS guidance](https://github.com/compdemocracy/polis/blob/stable/docs/ssl.md).

## Input contract

Use a **new, dedicated, canonical absolute path** for the target. Its immediate parent and the entire input tree must be owned by the current operator and mode0700. No symlinks, hard links, extra files, private activation-signing key or mutable runtime database are accepted. The input and target must not contain each other. All input files are mode0600 except the core's specifically reviewed recipient-readable files listed below. The private0700 parent remains mandatory around those0644 files.

The input root contains exactly:

```text
input/
  installation.json
  core/material/
    api.env, math.env, migration.env
    database-ca.pem, database-server.pem, database-server.key
    database-owner-password, database-migration-password
    database-runtime-password, database-math-password
    jwt-private.pem, jwt-public.pem
  participant_material/
    service.json
    oidc-secret.txt, identity-key.txt, activation-public.pem
    gateway-key.txt, provider-key.txt
    wordpress-request-key.txt, wordpress-response-key.txt, wordpress-event-key.txt
    participant-cert.pem, participant-key.pem, receiver-cert.pem, receiver-key.pem
    provider-ca.pem, wordpress-ca.pem
    identity-ca.pem (only if explicitly referenced)
  wordpress_material/
    config.json, plugin-config.json, server.pem, server-key.pem, receiver-ca.pem
  proxy_material/
    proxy-cert.pem, proxy-key.pem
```

`installation.json` has exactly `{version,profile,configuration,imageLock,ownerToken}` for the selected V1/V2/V3 profile. Configuration, the exact eight-, nine- or ten-role image lock and the48-hex-character independent owner token use the [normal Compose contract](../production-deployment/COMPOSE.md). `configuration.stateDirectory` must equal the **target** path plus `/core`; it must not reference the input or an existing runtime. No image is pulled or verified against a registry by this tool.

All JSON inputs use `canonical(value) + '\n'` from `production-service/contracts.mjs` (sorted object keys, compact UTF-8 JSON, one final newline). This is intentionally stricter than free-form JSON and rejects duplicate keys. Do not canonicalize existing live material in place: write a new offline input set and review it. Every source byte is rechecked before the final receipt. The input must remain untouched throughout staging.

Core environment files and cryptographic material must pass the existing `selfhost/material.mjs` validator. `api.env`, `math.env` and `migration.env` are0600; the other nine core files are0644 within their private0700 parent, preserving the current per-file-container-bind contract. This tool is not permission repair.

The writer explicitly applies the required mode to its **newly exclusive-created file descriptor**, so a secure077 umask does not silently turn the recipient-readable core binds into0600. Input validation and rerun validation still require the exact existing modes; the tool never chmods an existing target or relaxes parent-directory privacy.

`service.json` uses the existing [production-service contract](../production-service/README.md) with these narrower staging requirements:

- Participant and event listeners: host`0.0.0.0`, ports8443 and8444. The event origin is exactly`https://participant-events:8444`; WordPress is`https://wordpress:8443`; native Pol.is proxy is`https://polis-proxy:8443`. Participant origin is the separately reviewed public HTTPS origin. State directory is exactly`/var/lib/fncp`.
- The source revision, exact versioned image set (eight for V1, nine for V2,
  ten for V3), deployment, conversation, fifteen ordered statement IDs,
  statement texts and WordPress notice/event binding must agree. These inputs
  do **not** prove that a corresponding native conversation or database seed
  exists.
- Every file reference is exactly`/run/fncp/<filename>` from the participant list above. All three WordPress bridge keys match their plugin counterparts; gateway/provider keys match the API environment. Independent secret roles cannot reuse a value. The identity client secret is16–2048 printable ASCII characters with no whitespace.
- Only the Ed25519 **public** activation authority is staged. The offline signing key must remain outside the input and output.
- This v1 staging profile supports exact DNS SANs only (not IP, wildcard or CN-only certificates), unencrypted PKCS#8 RSA≥2048-bit or standard P-256/P-384/P-521 EC leaf keys, a single PEM leaf per role, and a single self-signed PEM CA per internal trust file. It validates time bounds, hostnames, leaf/private-key pairing, internal issuer signatures, serverAuth purpose and independent key roles. Certificate chains, other trust arrangements and public CA trust/renewal are **not** established by a PASS. A broader chain profile needs its own implementation and tests, not an ad-hoc validator bypass.

WordPress `config.json` and `plugin-config.json` follow the normal runtime schemas. This copies their private database credentials/salts; it does **not** establish that MariaDB contains that account or WordPress was installed with the correct site/administrator/plugin state.

## Run locally after input review

Run with a Node version supporting the existing repository dependencies (tested with Node26.8.2). Do not put any credential in command-line arguments or terminal output.

```sh
node deploy/fncp/production-install/stage-material.mjs /absolute/private/input /absolute/private/new-stage
node --test --test-reporter=spec deploy/fncp/production-install/stage-material.test.mjs
```

API: `await stageProductionMaterial({inputDirectory,targetDirectory})`.

The initial result is`MATERIAL_STAGED`; an identical verified rerun is`ALREADY_STAGED_VERIFIED`. Without optional identity CA there are37 output files: supplied material plus`compose.json` and a private`stage.receipt.json`. The receipt contains digests and binding metadata, not raw secret values, but remains private; do not publish it. The CLI emits aggregate status only.

The tool uses an exclusive sibling`<target>.stage.lock`. It never treats an existing lock as stale. An interrupted write may leave an incomplete target and/or lock. Do not delete either blindly, rerun with an override, or regenerate keys to “fix” it. First stop and inspect the exact private attempt under operator control. Preserve evidence; prepare a separately approved new target if recovery cannot be justified. The program has no force, takeover, cleanup or repair flag. Success rereads every output and rechecks directory/file/lock custody. As with the existing runtime custody checks, the operator must exclude concurrent same-user filesystem writers; this is not an OS sandbox against a hostile root/operator.

## What must still happen before a fresh runtime can start

1. **Approve the host/OIDC plan and spending separately.** Existing programme/domain/owner decisions need not be repeated. No host, real issuer or external changes are created by staging.
2. **Produce and review fresh deployment material securely.** Establish certificate issuance/renewal, a real confidential OIDC application and its exact callback/claims, separate WordPress staff authentication, offline activation authority and secret custody. The test helper's short-lived synthetic CA/material is not production material.
3. **Run the separate database/site initialization under reviewed ownership.** PostgreSQL roles/schema/migrations and a fixed closed native round/fifteen statements use `postgres-initialize.mjs`; MariaDB/WordPress schema/user/site/sole-operator/plugin state uses the three `wordpress-initialize.php` maintenance phases. The stager deliberately does not invoke them. Use their independently recorded native positive/negative receipts, and then prove the joined executor against one exact deployment. Do not run normal startup against empty volumes or reuse retained QA databases as fresh production state.
4. **Transfer to new owned Linux volumes under exact custody.** Establish the normal contract's UID1000 participant material/state, UID33 WordPress material, UID101 proxy material, UID70 PostgreSQL and UID999 MariaDB. The output remains current-operator-owned, not Linux-volume-ready. Preserve exact bytes/modes/paths/labels, verify the six durable volumes as one recovery unit, and never replace a live volume through this tool.
5. **Start admission closed and prove the full journey on synthetic accounts.** Use the separately reviewed edge/OIDC policy, actual image locks and no public admission. Verify login, staff approval, bound invitation, native vote, negative access tests, terminal revocation, restart/recovery and aggregate disclosure. Material PASS is not an authorization or native runtime PASS.
6. **Obtain separate launch approval.** Review current image scan results, real TLS/browser/identity evidence, an independently restored closed backup, operator runbook and closure copy. Only then may an exact fresh signed activation and explicit opening be considered. No automatically renewed date or historic approval opens this build.

## Tests and limits

Tests generate invented secrets/certificates in a fresh test-owned temporary directory, exercise the CLI/API, and remove only that temporary tree. They do not contact an identity provider or start Docker, WordPress, PostgreSQL, MariaDB or a network listener. Coverage includes verified no-op reruns; changed source, output, owner or receipt; unexpected files; ambiguous JSON; wrong binding/path/key/hostname; secret reuse; permission failures; symlinks/hard links; existing targets and stale locks. These tests prove offline material assembly only.
