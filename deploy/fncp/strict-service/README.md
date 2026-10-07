# Strict local service composition

**KEEP CLOSED · local-only · no production login, deployment or launch authority.**

`service.mjs` is a dedicated programmatic entrypoint for the existing strict local components. It does not import the integrated test harness, a token injector, synthetic signer, model provider or test client. It accepts explicitly supplied private in-process adapters; no environment/configuration file, default identity issuer or provider is loaded.

This separates runtime composition and lifecycle ownership from the test driver. An explicit HTTPS redirect lab can now exercise the browser-facing callback protocol over actual loopback TLS with invented identities; this does **not** convert the SYNTHETIC_ONLY foundation into real production OIDC. There is deliberately no ready-to-run production CLI, Docker image or cloud configuration in this increment.

## What is connected

- One shared identity foundation verifies opaque principal objects for access, the browser service and optional WordPress registration. Driver-supplied success or a copied/foreign principal cannot replace that authority.
- Mandatory deployment-bound activation wraps the access service. Construction starts closed; starting listeners does not activate or open a round.
- The new strict HTTP profile denies every `/test-admin*` and `/test-auth*` request even with the correct bearer. Private `operator` methods retain only status, round open/close, invitation issuance and activation control; there is no direct approval/revocation or fixture-provisioning export.
- WordPress events enter through the HMAC-protected receiver. Optional registration uses the explicit server-side transport and the same principal; it returns a pending reference, never approval or invitation authority.
- Access, receiver and browser listeners are owned by the [supervisor](./supervisor-proof.md). Startup rolls back all constructed services on failure; shutdown closes authority first and drains every owned component.
- Provider conversation metadata is checked before and after every operation, including rejected operations. Observed drift or unreadable metadata latches denial and closes activation. Restoring the string does not clear the latch. A call already performed cannot be undone; no automatic retry or false rollback is claimed.

## Run the local checks

Use the dedicated clone, with the already installed isolated identity dependencies:

```sh
node --test deploy/fncp/local-access/strict-service-profile.test.mjs deploy/fncp/strict-service/*.test.mjs
node deploy/fncp/release-review/proof-closure.mjs
```

Run Node 24 and Node 26 suites sequentially. Service tests use in-memory databases and short-lived loopback listeners only. The supervisor tests use deterministic adapters without sockets. The full owner-guide suite remains required before recording a complete pass. These commands neither require nor start Docker.

## Private application API

Create with `await createStrictLocalService(options)`; construction does not listen. The exact mode is `STRICT_LOCAL_ONLY`.

| Input | Required boundary |
| --- | --- |
| `identity` | Same trusted foundation instance: `isVerifiedPrincipal`, `principalDeadline`, `participantXid`. No HTTP-provided claims or serialized principal. |
| `oidcDriver` | Explicit SYNTHETIC_ONLY own data `begin`, `complete`, `discard` methods. HTTPS opt-in additionally requires exact `HTTPS_REDIRECT_LAB` transport, canonical HTTPS `.invalid` authorization endpoint and matching browser callback URI. Only those selected methods/metadata are captured; the service uses the foundation, not the driver's verification boolean. |
| `provider` | Explicit `conversationId`, `allowlist`, `participate`; must match activation binding. Adapter internals remain trusted, not sandboxed or attested. |
| `activation` | Exact binding, public Ed25519 key and key ID. No private signing key or auto-activation. |
| `storage` | Separate `access`/`activation` SQLite paths, or both `:memory:` for a disposable test. Caller owns file selection, custody and recovery; the service never deletes stores. |
| `eventSecret` | Explicit separate secret, retained only in process. Never put it in URLs, command arguments, logs or shared artifacts. |
| `ports` (optional) | Exact access/receiver/browser ports; zero defaults select ephemeral loopback ports. Nonzero values cannot collide. No host/address option. |
| `httpsRedirect` (optional) | Explicit `SYNTHETIC_HTTPS_REDIRECT` mode, exact canonical `https://browser.example.invalid:<port>` origin, and separate nonempty test TLS key/certificate Buffers of at most 65,536 bytes each. Browser port must match and cannot be zero or 443. Buffers are copied; no key files, global trust or DNS are read/changed by this component. |
| `registration` (optional) | Separate challenge and registration secrets plus explicit private `fetch` adapter. No default transport is inferred. |
| `now` (optional) | Trusted clock function for deterministic tests; production clock assurance is not established. |

Call `start()` once. It returns private `{ origins: { access, receiver, browser } }` only after every listener starts. `snapshot()` reports bounded lifecycle state without addresses, secrets or database paths. `close()` synchronously latches shutdown, closes activation and returns the same drain promise on repeated calls. No restart of the same instance is allowed.

`operator` is trusted private process authority. Never mount it as an unauthenticated RPC/HTTP endpoint, expose it to browser scripts, serialize its capabilities, or log its invitation results. The private invitation result is local-only; it is not permission to send it. A future operator interface needs its own authentication, MFA, authorization and review.

Graceful service shutdown means the local gateway stops admitting work. It does not itself prove provider-wide allowlist removal, complete round closure, coordinated production recovery or termination of a remote side effect. A non-settling drain remains pending; there is no force-kill timeout.

## Optional synthetic HTTPS redirect composition

The HTTP-only default is preserved. Selecting a redirect driver without an explicit matching HTTPS configuration is refused; TLS failure never silently downgrades to HTTP. Access and signed-event receiver origins stay HTTP loopback. Only the BFF uses the fixed test hostname, still binding the loopback interface.

The supplied pure driver's callback URI must exactly equal the configured origin plus `/oidc/callback`; its authorization endpoint must be canonical HTTPS on an `.invalid` hostname. Extra HTTPS-driver capabilities and getter-bearing metadata are rejected. Runtime composition does not import the lab issuer, synthetic signing fixtures or a token injector. Positive tests supply a separate lab explicitly and keep its test credentials out of logs and artifacts.

The new service configuration checks cover wrong mode/host/port, noncanonical URL, insecure or real authorization endpoint, mismatched callback, malformed TLS buffers, unsupported driver capabilities and accessor-bearing inputs. A positive test verifies actual certificate-checked loopback TLS, Secure/HttpOnly session-cookie issuance, unchanged closed round state, private metadata/method capture despite caller mutation, TLS byte copying and listener closure. It does not follow the complete login redirect chain; full redirect-journey assurance is recorded separately.

## Demonstrated scope and remaining work

Tests separately verify signed invented login, signed model approval, account-bound invitation, a model vote and warm revocation; optional registration uses an in-memory WordPress HTTP model. The optional TLS test adds real loopback HTTPS using newly generated disposable test credentials, with no global trust/hosts-file changes. These are real local protocol/signature checks against invented services, **not a fresh actual Pol.is/WordPress runtime run**, rendered-browser proof or heritage verification.

The existing standalone `local-access/start.mjs` and `local-browser/start.mjs` launchers remain legacy fixtures and are not replaced by a production launcher. Rendered-browser assurance, a real identity issuer, operator MFA, identity/mail provider configuration, secure durable store/key custody, production target/images and post-restore full-service assurance remain outstanding.

Build the real login and operator adapters before packaging for a selected hosting target. Preserve same-process opaque authority or explicitly design and review a cross-process protocol. Never obtain a deployable configuration by deleting the local-only guards.

## Official reference

[Pol.is self-hosting/source README](https://github.com/compdemocracy/polis/blob/stable/README.md) and [configuration guidance](https://github.com/compdemocracy/polis/blob/stable/docs/configuration.md) describe the upstream Docker system and configuration. This custom WordPress/identity/activation composition is Barayamal integration work, not a capability certified by upstream documentation.
