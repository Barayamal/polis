# Private production normal-start composition

`compose.mjs` is a pure descriptor renderer and validator for a versioned set of separately reviewed image roles: eight in V1, nine in V2 and ten in V3. It reads no files, contacts no registry or engine, creates no resources, and performs no installation, migration, account creation, seeding, signing or conversation opening. V1/V2 publish zero ports; V3 publishes only its two fixed IPv4-loopback operator bindings. Every version starts from separately provisioned state with participant admission closed. Existing local/synthetic entrypoints and the core launcher remain unchanged.

The renderer is not a release attestation or a runtime proof. The image locks, private material, initialized databases, source provenance, container isolation and joined recovery require their own verification. Passing these source tests does not approve the current candidate images or establish a working native WordPress/Pol.is deployment.

## API and public inputs

```js
import {
  renderProductionCompose, validateProductionCompose,
} from './compose.mjs';

const document = renderProductionCompose(configuration, imageLock, ownerToken);
validateProductionCompose(document, configuration, imageLock, ownerToken);
// A caller may save JSON.stringify(document, null, 2) as a Compose document.
```

Configuration has exactly these fields:

- `version: 1`, `profile: 'FNCP_PRODUCTION_COMPOSE_V1'` and `platform: 'linux/arm64'`.
- `deployment`: a task-specific `fncp-` namespace, matching `^fncp-[a-z0-9][a-z0-9-]{4,40}$`. Allocate a new unique namespace and independent owner token; do not adopt resources merely because names match.
- `sourceRevision`: 40 lowercase hexadecimal characters.
- `stateDirectory`: an absolute, lexically canonical path to the already prepared core state. Its fixed `material/` files supply the reviewed core env files, CA, keys and role-password files. Relative aliases, controls, backslashes and Compose variable interpolation are rejected. Pure rendering does not follow symlinks or establish filesystem ownership; the separate core material/custody preflight must do that.
- `database`: exactly `{name,owner,migrationRole,runtimeRole,mathRole,host:'postgres',port:5432}`. Four distinct restricted roles and safe database identifiers are required.
- `binding`: exactly `{conversationId,statementIds}` with fifteen distinct canonical nonnegative integer IDs. The conversation and IDs are retained in the descriptor's binding metadata; they must also match both core env files and the staged participant configuration/seed text digest.
- `identity`: exactly `{issuer,audience,jwksUri}`. Issuer and JWKS URLs must be explicit canonical HTTPS URLs without credentials, query or fragment. These public values must agree with the core env and the participant service's separately reviewed OIDC configuration. They do not discover an issuer or verify one.
- Optional `oidcEgress`: only `false`, which is also the default. Current profiles reject `true`; no implicit network exception follows from an HTTPS issuer URL.

The image lock has exactly `{version:1,sourceRevision,sourceFingerprint,images}`. The source fingerprint is 64 lowercase hexadecimal characters. `images` contains exactly eight distinct full local image IDs: `api`, `math`, `postgres`, `migration`, `participant`, `wordpress`, `mariadb`, `proxy`; each is `sha256:` plus 64 lowercase hexadecimal characters. Tags, missing roles, shared-image shortcuts and additional QA roles reject. Source revision must match configuration. The independent `ownerToken` is 48 lowercase hexadecimal characters. Containers, networks and volumes carry that owner plus source/resource labels; labels describe intended ownership and do not replace inspecting actual image/resource provenance.

The output is deeply frozen and independent of caller mutations. `validateProductionCompose` compares a saved raw JSON descriptor to the complete expected descriptor, rejecting unknown nested fields or any changed command, image, mount, network, port, profile or security setting. It is for the generated document, not Docker Compose's normalized `config` output. Do not merge an override file afterward or substitute another Compose document. The caller must independently inspect effective runtime configuration and existing resource ownership before any start.

## Roles and networking

| Role | UID:GID | Memory | Normal command and storage |
| --- | --- | --- | --- |
| PostgreSQL | 70:70 | 1536 MiB | Reviewed database image's `start`; preinitialized PostgreSQL data volume; original per-file material binds |
| Migration | 70:70 | 256 MiB | Original reviewed migration entrypoint, isolated behind the explicit `maintenance` profile |
| API | 1000:1000 | 1536 MiB | Reviewed dedicated normal entrypoint; original API env, verified database CA and JWT key binds |
| Math | 65532:65532 | 1536 MiB | Reviewed normal math entrypoint, including its dedicated 1024 MiB JVM heap; original math env and database CA |
| Participant | 1000:1000 | 512 MiB | Normal `production-service/main.mjs`, 384 MiB Node heap, private material and access/activation state volumes |
| WordPress | 33:33 | 512 MiB | `/usr/local/bin/fncp-wordpress-start`, then native Apache HTTPS on 8443; immutable site/plugin code |
| MariaDB | 999:999 | 768 MiB | Direct `mariadbd` on a preinitialized data volume, networking disabled; no official initialization entrypoint |
| Proxy | 101:101 | 128 MiB | Fixed nginx configuration forwarding only the reviewed private Pol.is routes to `api:5000` |

Every role has a read-only root filesystem, all capabilities dropped, no new privileges, bounded CPU/PIDs/tmpfs, a TERM stop policy and `restart: 'no'`. There is no build or pull fallback. Migration is declared but does not run during ordinary startup without its explicit profile. Starting that profile is a separate maintenance action; this renderer never authorizes migrations or database initialization.

The default `core` network is private/internal. It contains the API, math, PostgreSQL, maintenance migration, participant, WordPress and proxy roles. MariaDB uses `network_mode: 'none'`. Fixed service DNS names include `postgres`, `api`, `wordpress`, `participant`, proxy alias `polis-proxy` and participant receiver alias `participant-events`. PostgreSQL still requires its reviewed verified-TLS authentication; a shared internal network does not grant database credentials.

Current profiles reject the former broad `oidcEgress: true` network. The [fixed OIDC relay foundation](../production-egress/README.md) is separately source-tested with a credential-free relay and end-to-end provider TLS; it is not added to this Compose descriptor. Its full installer, material, host-policy and recovery integration still requires a new qualified deployment path. The participant stays on internal networks. The real issuer and exact endpoints remain explicit in staged `service.json`; there is no discovery or caller transport override. Default private rendering does not include a synthetic issuer or configure external OIDC access, so it alone is not a reproducible authenticated QA journey.

All host ports remain unpublished even when OIDC egress is enabled. Participant ingress and native staff WordPress access require a separately reviewed edge/network composition and matching TLS/origin configuration. No edge, host network, port publication or external network adoption is silently added here.

## Provisioned material and durable state

Compose volume names are the exact deployment prefix plus the listed suffix. They use the local driver, carry owner labels, and mount with `nocopy: true`; image content is never copied automatically into empty data/material volumes. Empty volumes do not provision a service. The operator must prepare, inspect and label the owned state before ordinary start.

| Volume suffix | Mount and custody contract |
| --- | --- |
| `postgres` | `/var/lib/postgresql/data`, writable only by PostgreSQL. Preserve the reviewed initialized marker, configuration, certificate and restricted roles; no `initialize` command is rendered. |
| `mariadb` | `/var/lib/mysql`, writable only by UID999. Preinitialize the reviewed database, WordPress database user and native site separately. The normal daemon must not create these. |
| `mariadb_socket` | `/run/mysqld`, shared only between MariaDB and WordPress. A fixed 16 MiB local-driver tmpfs uses UID999:GID33 mode0750; MariaDB writes it and WordPress mounts it read-only. The observed MariaDB11.8.9 socket is mode0777; directory traversal permits WP33 to connect without granting a writable mount. This is transient socket state, not backup data. |
| `participant_material` | Read-only `/run/fncp`, root of this volume mode0700 UID1000. Contains `service.json` and every referenced private file, each a regular single-link owned0400/0600 file with a canonical owned0700 direct parent. |
| `participant_state` | Writable `/var/lib/fncp`, mode0700 UID1000, containing access/activation SQLite history and their owned locks. The staged `service.json.stateDirectory` must be exactly `/var/lib/fncp`. |
| `wordpress_material` | Read-only `/run/fncp/wordpress`, mode0700 UID33, with `config.json`, `plugin-config.json`, `server.pem`, `server-key.pem` and `receiver-ca.pem`; each owned0400/0600, single-link and regular. |
| `proxy_material` | Read-only `/run/fncp`, mode0700 UID101, with `proxy-cert.pem` and `proxy-key.pem`, readable only by the configured nginx UID. |

Host macOS files owned by UID501 do not satisfy the participant's Linux UID1000 custody. Stage the new private material volumes offline with the required Linux ownership; do not weaken runtime checks or use ephemeral material that disappears on restart. New material is separate from the existing core's deliberate per-file bind contract: host-private0700 material directory, reviewed0600 env files, and the core's recipient-readable0644 mounted key/password files. Keep the existing strict core material/env validation, verified PostgreSQL CA and `DATABASE_SSL=true`/`PGSSLMODE=verify-full` requirements unchanged. This renderer neither creates nor reads those secret bytes.

The participant manifest must bind the same deployment, conversation, fifteen statement IDs/texts, exact versioned image set, source/configuration/seed/provider digests and recovery epoch. It must use native listeners on 8443 and 8444, private WordPress HTTPS at `wordpress:8443`, Pol.is HTTPS at `polis-proxy:8443`, and the explicitly reviewed OIDC endpoints. WordPress event delivery targets the separately configured receiver HTTPS origin on 8444, with the matching CA and independent HMAC credentials. The relevant certificates and configured Host/origin values must agree; no untrusted forwarded-protocol header supplies TLS authority.

The normal WordPress image must bake the upstream source, production plugin, fixed Apache HTTPS configuration and normal-only startup verifier. Its entrypoint checks an already installed database/site, reviewed site URL, version and operator/plugin state before Apache. It must contain no QA installer, inspection helper, material wait loop or arbitrary runtime PHP hook. `/usr/src/wordpress` remains image-backed and read-only. The unused inherited `/var/www/html` image volume is overridden by a small read-only tmpfs to prevent anonymous writable state. Approval needs no writable uploads directory. Runtime package tests and native WordPress/MariaDB validation remain separate from this descriptor test.

## Startup, closure and evidence limits

The health probes establish bounded local listener/socket readiness; they do not assert TLS trust, correct data, approval or participant authorization. The MariaDB probe uses explicit Unix-socket `mariadb-admin ... ping --silent`, verified against the selected11.8.9 image. The official default healthcheck's TCP-connect behavior is unsuitable for this intentionally socket-only role. WordPress's normal startup verifier and separate runtime proofs establish the initialized site contract.

No service automatically activates or opens the native Pol.is conversation. An unclean participant exit leaves ownership locks; there is no stale-lock takeover. A reviewed stopped recovery must retain all replay floors, terminal revocations, WordPress outbox/receipts and native database state, clear only proven abandoned ownership, and restart closed under a fresh recovery epoch and reviewed signature. The existing core-only `fncpctl` ownership profile does not manage this larger composition and must not be presented as doing so.

Thirteen source tests cover descriptor validation, role/resource constraints, fixed socket sharing, private material separation, explicit egress and rejection of hidden ports/mounts/networks/commands. Tests use invented IDs and paths and start no engine or container:

```sh
node --test deploy/fncp/production-deployment/compose.test.mjs
```

## Version 2: explicit closed participant edge

V1 remains the eight-role/six-durable-volume compatibility contract. V2 is opt-in:
configuration must set `version:2`, `profile:'FNCP_PRODUCTION_COMPOSE_V2'` and
`edge:{publicOrigin:'https://approved-host',discardCookies:[]}`. The only optional
reviewed discard cookie is `__cf_bm`. The image lock must also use `version:2`,
with all eight original independent image IDs plus the ninth `edge` ID; mixed
versions and overrides reject. `imageRoles(2)` exposes the exact V2 role list.

V2 adds one internal `participant_ingress` bridge, joined only by participant and
edge. The edge joins no core or OIDC egress network. Its fixed verified-TLS
upstream is `participant-edge-upstream:8443`, an alias on the participant's new
bridge. The edge listens on container port8443 and publishes **zero host ports**.
The native Pol.is nginx proxy remains a separate unchanged internal service.
Compose isolation limits network membership; it is not proof of public ingress,
firewall policy or external provider reachability.

The edge uses UID1000:GID1000, read-only root,128MiB RAM,96MiB Node heap, half CPU,
64PID limit, no capabilities and a16MiB private tmpfs. `edge_material` is the
seventh durable volume, mounted read-only at `/run/fncp/edge`, with directory0700
and exactly four owned regular single-link files0400/0600: `config.json`,
`server.pem`, `server-key.pem`, `upstream-ca.pem`. Configuration uses canonical
JSON plus newline:

```json
{"discardCookies":[],"profile":"FNCP_PARTICIPANT_EDGE_CONTAINER_V1","publicOrigin":"https://approved-host","version":1}
```

The front leaf and the participant upstream leaf must both cover the configured
public hostname. Neither HTTP Host nor forwarding headers select a backend.
The runtime rechecks file identity/content/custody every second and closes on
drift; renewal therefore uses stopped, inspected replacement material. The V2
activation challenge selects a separate V2 signature domain and binds the edge
image ID. V1 signatures cannot activate V2. Joined archive and ownership checks
use `volumeRoles(2)` and require edge material in addition to the original six
roles. Native build, scan, joined renewal/recovery and participant journey evidence
must be recorded for the exact V2 release before closed-staging approval.

## Version 3: operator-only loopback access

V3 retains the V2 isolated-edge and seven-durable-volume contract, adds a tenth
independently locked, credential-free opaque TCP gateway image, and exposes
exactly two loopback-only operator bindings under the fixed
`FNCP_OPERATOR_LOOPBACK_V1` access profile:

```text
127.0.0.1:8443 -> edge:8443/tcp
127.0.0.1:9443 -> wordpress:8443/tcp
```

The application edge and WordPress services remain exclusively on internal
networks and publish no ports. The gateway alone joins the non-internal
`operator_access` bridge required for Docker host publication, plus the two
internal destination networks. It holds no material or durable state and
forwards only opaque TLS bytes to the two fixed service names. The host IP,
published ports, targets, protocol and `tunnelRequired:true` are
all fixed. Wildcard/IPv6/alternate addresses, alternate ports, direct API or
database exposure, `publish_all_ports`, extra Compose overrides and a missing
tunnel requirement reject. These are operator access points on the host only;
they are not public listeners or launch authorization. Remote operation requires
a separately reviewed authenticated tunnel that terminates at these loopback
ports. No firewall, tunnel, DNS record or certificate is created here.

`operatorAccessSha256` is SHA-256 of canonical JSON for the complete access
object. It is included in staged participant material, recovery state and the V3
activation binding. V1/V2 signatures cannot authorize V3 and a changed listener
profile requires a fresh boot-bound V3 signature. Runtime ownership validation
compares both Docker port-binding views against the gateway's exact two expected
bindings and confirms that neither destination application has a published port.
An absent, additional or externally bound port fails the closed-install/recovery
check.

See [OPERATOR-LOOPBACK.md](OPERATOR-LOOPBACK.md) for the exact boundary and
operator connection procedure.
