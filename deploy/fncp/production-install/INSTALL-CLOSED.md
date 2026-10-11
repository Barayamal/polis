# Joined closed installation candidate

`install-closed.mjs` joins verified material staging, fresh database maintenance,
Linux volume ownership and ordinary startup. V3 includes ten exact image roles,
seven durable volumes, the transient MariaDB socket, an independent HTTPS
participant edge and a credential-free opaque operator gateway. Only the gateway
publishes the exact `127.0.0.1:8443` and `127.0.0.1:9443` operator bindings; there
is no public listener and outbound identity access is disabled.
This is local engineering until an exact release has native evidence and Dean
approves a separately specified staging destination.

## Inputs and execution

1. Review the official [Pol.is self-hosting instructions](https://github.com/compdemocracy/polis/blob/stable/README.md),
   [configuration](https://github.com/compdemocracy/polis/blob/stable/docs/configuration.md)
   and [TLS guidance](https://github.com/compdemocracy/polis/blob/stable/docs/ssl.md).
   The registration, activation, edge and recovery controls here are custom code.
2. Freeze the source. Use `release-readiness/collect-candidate-release.mjs` to build
   every image with one source fingerprint, inspect copied source, and scan the
   exact image IDs. A build or scan receipt is engineering evidence, not approval.
3. Supply the private input tree from [README.md](README.md). V3 installation.json
   has `version:3`, `profile:FNCP_FRESH_MATERIAL_STAGE_V3`, matching V3 Compose and
   image-lock versions. It retains exactly `edge_material/{config.json,server.pem,
   server-key.pem,upstream-ca.pem}`. Config is canonical JSON plus LF:
   `{version:1,profile:"FNCP_PARTICIPANT_EDGE_CONTAINER_V1",publicOrigin,discardCookies}`.
   These values must match configuration.edge; publicOrigin must match the
   participant origin. The upstream CA must verify the participant TLS leaf.
   Each private file is0600 under0700 parents. Edge and participant private keys
   must differ. `service.json.activation.edgeMaterialSha256` is SHA256 of canonical
   JSON of the filename-sorted array of `{name,sha256}` for those four files.
   The service configuration fingerprint therefore binds the edge material into
   the activation challenge. V3 also binds the exact fixed
   `FNCP_OPERATOR_LOOPBACK_V1` access object and tenth `operator` image. V1/V2
   material remains supported by the stager.
4. Supply a separate0600 operator JSON under an owned0700 parent, using the exact
   `FNCP_WORDPRESS_INITIALIZE_V1` shape described in
   [wordpress-initialize-README.md](wordpress-initialize-README.md). No email is sent.
5. Select an explicit dedicated local Linux ARM64 Docker socket. A macOS VM must
   mount only the new task runtime parent; core material retains its reviewed
   per-file bind contract. The installer never selects or starts a VM.
6. Invoke from the source checkout with five explicit arguments:

   ```sh
   node deploy/fncp/production-install/install-closed.mjs \
     unix:///absolute/task/docker.sock \
     /absolute/private/input /absolute/private/new-stage \
     /absolute/private/operator.json /absolute/private/new-evidence
   ```

All paths must be canonical. The stager verifies exact bytes on an identical
rerun; the installer requires an entirely new namespace and evidence directory.
There is no adoption, force, repair, pull, activation or open option. The installed
services intentionally remain running closed on success. All evidence is private;
it includes configuration, owner tokens and source/image bindings. Publish only
reviewed aggregate receipts, never input material or private journey state.

## Separation and failure behavior

The normal Compose descriptor is generated once and validated without overrides.
Maintenance uses a separate descriptor referencing the same owned resources.
Only maintenance creates schema/users, runs20 migrations and seeds15 statements.
The WordPress installer and sole operator password use an installer-only volume,
which is removed and verified absent before normal startup. The runtime images
contain no new QA or installer helpers. All ordinary roles are checked against
their exact expected commands, images, mounts, networks, environments and limits.

Host material archives use portable ustar format. This excludes macOS AppleDouble
sidecars and extended metadata; the recipient independently checks every directory
entry, including hidden names, before accepting file hashes and ownership. Raw
maintenance shell commands also pass through an explicit Compose dollar-escaping
boundary so host environment variables cannot rewrite database initialization.

A failed attempt stops only independently owner-checked containers and retains
its data and evidence for diagnosis. It never deletes databases or retries a
partial initialization. Inspect any failure before using a fresh namespace;
normal startup must not be used as a repair step. Installation has no invitation,
mailbox, public HTTPS, full journey or recovery proof simply because services start.

`synthetic-input.mjs` creates invented two-day/local-certificate QA inputs. Its
private activation key and synthetic issuer belong solely to the test harness;
that factory is not a live credentials workflow. `qa/` exercises the native
participant edge, WordPress staff controls, private operator protocol, bound
invitations,270 API vote responses and warm-session terminal revocation. Source
checks alone do not certify that journey; keep executed native receipts bound to
one exact release. See the delivered evidence for what actually ran.
