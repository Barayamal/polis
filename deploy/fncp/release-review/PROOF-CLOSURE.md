# Pinned host-side proof source closure

**KEEP_CLOSED. This is an offline source check, not a Docker package or deployment.**

The general release inventory records selected entry files. This separate check
adds a narrower, explicit closure for the two legacy fixture launchers, the
strict in-process proof factory, dedicated programmatic strict local composition
and pure injected HTTPS redirect coordinator: **27 files — 21 JavaScript modules, four browser assets, and the
identity package/lock pair**. It includes the fifteen fixed seed
statements and the strict proof's synthetic signing, identity, browser-client and
registration dependencies that an entry-file inventory alone does not establish.

```sh
node deploy/fncp/release-review/proof-closure.mjs
node --test deploy/fncp/release-review/proof-closure.test.mjs
```

Run from the clone root using the existing Node runtime. No installation or
service start is needed. JSON contains only reviewed paths, hashes, graph,
dependency declarations, aggregate sizes and limitations. The command reads no
environment file, key, certificate, credential, application store, historical
evidence, WordPress archive, installed dependency or Docker state. It creates no
archive, source copy, image or deployment configuration. Failure stays
`KEEP_CLOSED`, emits a fixed content-free error and exits nonzero.

Local verification on 13 September 2026: **54/54 tests passed on Node 24.21.0 and
Node 26.8.2**, including the exact current source and fresh source-only temporary
fixtures. This is the same 54 checks on two runtimes, not 108 unique controls.
The reviewed 27 files total 227,871 bytes, with 30 first-party import edges and
four static-asset edges. Their measured source-closure SHA-256
is `59fe745d604ea3f0b57e7589e6ec272409221e8d190c74baca447b5b42b221cc`.
The reviewed manifest SHA-256 is
`3e2181738d39cdee97968123c00e3bdc1b59c3e5ee216f7a563e23022e39c6fb`.
Tests remove only their own temporary fixtures; no application data is opened.
The earlier 24-file/49-test and 26-file/52-test evidence remain historical
snapshots, not the current source pin set.

## What the entrypoints actually mean

| Entry | Current role | Not established |
| --- | --- | --- |
| `local-access/start.mjs` | Starts fixture API and signed local WordPress event receiver, with local runtime inputs when actually executed | Strict signed identity and activation composition; production service |
| `local-browser/start.mjs` | Starts the legacy fixture browser BFF | Real OIDC login, strict activation or production HTTPS |
| `integrated-journey/proof-harness.mjs` | Factory composing strict synthetic identity, signed activation, BFF, access and optional registration bridge in one process | Deployable entrypoint, real issuer, standalone cross-process authentication protocol |
| `strict-service/service.mjs` | Dedicated programmatic local composition with private operator capability, no HTTP test administration, owned startup/shutdown and injected trusted adapters | Production CLI, real identity/operator integration, hosting configuration or complete adapter source closure |
| `identity-foundation/https-redirect-driver.mjs` | Pure injected redirect-flow coordinator; bounded, one-use callback state and exact synthetic HTTPS URLs | Identity issuer, default network/TLS transport, signer, test lab, production provider or browser-engine verification |

The strict path deliberately shares opaque principal objects and private
in-process verification capabilities. A JSON serialization or splitting modules
into containers does not preserve that authority. An actual multi-process build
needs a reviewed service boundary; bundling legacy launchers must not silently
replace the stricter proof. Current fixture-only modes, loopback destinations,
synthetic identity and closure guards are unchanged.

The optional HTTPS BFF profile keeps exact synthetic hosts, secure host-only
application/transaction cookies and top-level callback handling distinct from the
legacy HTTP profile. Reviewed cancellation now prevents a stale callback from
deleting a newer transaction cookie and drains disconnected admitted callbacks
before confirming closure. These source pins cover the server and revised browser
asset, but do not themselves execute a browser or establish production TLS.

The new strict local root reaches 14 pinned first-party files, including its
supervisor, access/activation modules, signed-event receiver, BFF/assets and
registration bridge. That subtree has no runtime test signer, identity injector,
proof harness or synthetic browser-client imports. Its identity foundation,
OIDC driver, provider and optional registration transport arrive as trusted
in-process adapters. The graph does not discover or attest those caller-supplied
implementations. The identity test harness is still included under the separate
proof-factory root; it must not be mistaken for the deployed login service.

The pure redirect coordinator is a fifth explicit component root because the
service receives its driver as an in-process adapter; there is no static import
from the service to discover. Its first-party subtree contains only that module.
The new TLS issuer/lab helper remains excluded: test infrastructure is not a
production provider, and the root must not import a signer or automatic identity
injector. The separate proof factory still retains its previously reviewed test
dependencies, including its now-configurable exact callback URI.

## How drift is handled

`proof-closure.mjs` holds a manually reviewed import/static-asset graph and SHA-256
pins for the exact source bytes. It does **not** claim regex or runtime import
discovery. All fixed entries must be reachable from the five roots or the
declared dependency-input pair. Unknown/missing source paths, changed bytes,
substitute manifests, source aliases, symlinks, hard links, nonregular/oversized
files and ordinary concurrent changes fail closed. It reads the fixed entries
twice; this is not an atomic snapshot or a hardened malicious-writer sandbox.

A legitimate source edit requires a reviewer to recheck its imports, static
assets and dependency declarations before updating the affected pin. Never
automatically regenerate pins to turn a failed review green. A SHA-256 match is
not a publisher signature, vulnerability audit or proof of safe code.

## Still outside this check

- Installed npm bytes and transitive runtime files: the lock declares
  `openid-client 6.8.8`, `jose 6.2.12` and `oauth4webapi 3.8.8`, but this command
  neither installs nor audits them. Node/OS packages are also outside scope.
- WordPress core, the separately reviewed PHP plugin closure, PHP/MySQL,
  Pol.is server/math/alpha/proxy/migration artifacts and PostgreSQL.
- Recovery tooling, real issuer/mail integration, target hosting/network/TLS,
  production operator authorization and secret custody.
- Runtime configuration, generated stores, private keys and retained evidence.

The [official Pol.is self-hosting source](https://github.com/compdemocracy/polis/blob/stable/README.md)
and [HTTPS guidance](https://github.com/compdemocracy/polis/blob/stable/docs/ssl.md)
remain upstream implementation references. They do not package or certify these
Barayamal-specific host-side identity, registration or admission controls.

The dedicated strict local composition is now source-pinned, but the next
production packaging step still requires the selected hosting/login target,
reviewed executable adapter wiring, complete dependency artifacts and durable
service boundaries. This check does not select a vendor, authorize spending,
external contact, deployment or participant tests.
