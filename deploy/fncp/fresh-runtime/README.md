# Fresh-only self-hosting foundation

**LOCAL_ONLY / KEEP_CLOSED. Actual disposable participant integration verified; production remains closed.**

The [latest participant integration report](../LOCAL-C-PARTICIPANT-INTEGRATION-2026-09-14.md) supersedes the bootstrap-only checkpoint. Three native53 runs and an independent protocol26 run passed against actual fresh WordPress, strict access and Pol.is/PostgreSQL. Independent vote attribution, selective revocation, closed restart and logical recovery passed. Exact image scans, source mapping, retained failure chronology and restored/stopped VM receipts are supplied in the handoff.

`participant-container-run.mjs` starts only after bootstrap closure; `journey-container-run.mjs`, `wordpress-container-runtime.mjs` and `journey-native-browser.mjs` own the fresh actual journey. `journey-vote-observation.mjs` independently validates the one participant vote, and `postgres-recovery.sh` compares closed logical restoration. No general persistent launcher, real identity provider or production launch is supplied. Component-model descriptions below describe their narrower test scope; consult the latest actual-runtime report for integration evidence.

- [Public container package](./bootstrap-container-package.mjs), [PostgreSQL initialization](./bootstrap-postgres-entrypoint.sh), [fresh material](./bootstrap-postgres-material.mjs) and [one-shot actual runner](./bootstrap-container-run.mjs): credential-free source packaging, separate non-root/read-only resources, private material handoff, schema admission, actual 19-request bootstrap and independent final SQL readback. No adoption/resume of old stores or credentials. These do not yet provide a general persistent hosting launcher.

- [Fixed child owner](../../../server/src/bootstrap/child-owner.ts), [environment profile](../../../server/src/bootstrap/child-profile.ts) and [issuer-bound bridge](./bootstrap-api-process.mjs): one fixed child, minimal environment, original cancellation/lifetime and independently verified process/listener closure. Database/container ownership is explicitly not claimed.

- [Fixed application child](../../../server/src/bootstrap/https-entrypoint.ts) and [HTTPS kernel](../../../server/src/bootstrap/https-runtime.ts): private IPC, fixed app import, scoped TLS, bounded readiness/close and independent listener refusal. Child exit and DB/container cleanup are separate.
- [Public API trust](./bootstrap-api-trust.mjs): original-issuer branded handoff of public key/pinned seeds and the same signal/activity check; one shared verified fetch with the separate JWKS role. No token or new lifetime.

- [Application admission](../../../server/src/auth/fncp-bootstrap-admission.ts) accepts only the fixed19-request protocol with one verified invented bootstrap token and validates responses before sending. Failure/deadline closes admission; it is not SQL rollback or application drain.
- [Application readiness](../../../server/src/auth/fncp-bootstrap-readiness.ts) resolves after route/error-handler registration, not database health. Actual app use still requires the separate bounded owner.
- [Public-only JWKS service](./bootstrap-jwks-service.mjs) consumes one independent public handoff from the original issuer, generates its own scoped TLS material, binds only fresh loopback and closes with original issuer lifetime. It exports no private key/bearer and does not revoke already cached tokens.

## Components and scope

- `foundation.mjs` exports zero-argument `createFreshPolisFoundation()`. It creates only a new private temporary directory, independently generated credentials/JWT keys, random resource names and literal closed configuration. It neither imports retained configuration nor accepts a caller-selected root, project or existing manifest. The returned `privateDirectory`, generated files and callback arguments are private; only `summary()` is intended for aggregate evidence.
- The returned capability offers `verifyIntegrity()`, `preflight({ probe })`, `start({ driver })`, `bootstrap({ driver })`, `cancel()` and `stop({ driver })`. Probes/drivers are explicitly trusted injected functions. There is no default Docker or network implementation in the foundation itself. A caller supplying arbitrary code can perform arbitrary side effects; these interfaces do not sandbox or authenticate that code.
- `verifyFreshPolisRequest(request)` verifies an active request created by that exact foundation. A copied, fabricated or expired request cannot authorize the concrete adapters. The brand expires when its callback finishes; a stop latch invalidates pending new-work requests. This is in-process authority, not a transferable token or cross-process protocol.
- `docker-cli.mjs` provides a fixed executable and dedicated local Unix socket, per-call new empty private client configuration, minimal environment, exact argument grammar, bounded output/deadline and sanitized errors. It does not read ambient Docker account/context configuration or accept another host. Raw successful/nonzero output remains private. CLI `close` must be observed before its temporary client configuration is removed; uncertain process termination preserves that new directory.
- `createDockerPreflight()` selects that concrete transport and bounded loopback bind probes. The probe checks Engine 28 or newer, Linux/ARM64, both exact image IDs, absence of four newly generated resource names and four required loopback ports. It does not start the VM, change context, pull/build or read any existing container's environment/logs. The earlier adapter milestone's read-only preflight did not complete; its separate 21:46:51 AEST status check found the dedicated Colima profile stopped. Neither check was repeated for the bootstrap/issuer increment.
- `createDockerLifecycle()` creates only a new private adapter ledger and returns `driver`, `close`, `summary` and a private directory. Its driver accepts active start requests, records network/volume ownership and captures each concrete container ID before start. It checks image-declared volumes, exact network identity/membership, volume identity, mount/security/port metadata and cancellation. It is not the foundation's generic stop callback: always call **adapter.close()** independently, including when foundation start fails. No deletion or prune capability exists.
- `../fresh-bootstrap-result.mjs` checks the trusted bootstrap adapter's exact `{ conversationId, statementIds }` result. It requires fifteen distinct PostgreSQL integer IDs in observed order, not assumed0–14; rejects the initial absent-binding ID, coercion, extra fields, accessors and proxies. Shape validation alone does not prove the result came from Pol.is.
- `../wordpress-identity/pristine-source.mjs` accepts exactly one plain, fixed-length, unshared ArrayBuffer and validates the pinned WordPress7.1 gzip bytes. The defensive-copy brand accepts no path, URL or hash override and does not itself establish acquisition provenance. Consumption returns another checked copy.
- `prepareIdentityWordPressFromPristine({ source, eventSecret, challengeSecret, registrationSecret })` in the WordPress runtime is the separate local-file preparation API. It requires the branded source and three independent signing secrets. It cannot fall back to the retained archive. It pins the copied archive and complete newly extracted core/configuration tree before later runtime operations.

Do not replace these inputs with live registrations, identity records, credentials, installed WordPress content or retained test stores. The existing WordPress/Pol.is actual-proof commands are historical retained-state workflows, not this fresh-only path.

## Local verification only

`bootstrap-http.mjs` supplies the real HTTPS client for active protocol requests.
It binds one opaque protocol scope, uses the factory-branded issuer's sole token,
requires canonical loopback HTTPS, verifies the normal IP SAN and exact leaf
certificate before sending the bearer, and rejects redirects/retries. A two-second
whole-send deadline and protocol/client cancellation cover ownership waits and
HTTP work; late completion cannot dispatch or grant success. A required trusted
`assertOwned` callback receives the private origin/certificate fingerprint and
must recheck the future manager's exact resources. This is not independently
proved Docker ownership. Close the helper and issuer separately; client close
only aborts/denies transport. The 19-request model sequence is exercised over
actual HTTPS with all tokens verified; no actual Pol.is middleware or DB runs.

`bootstrap-database-contract.mjs` provides original-branded fixed parameterized SELECTs, immutable worker handoffs and exact aggregate validators. Required catalog objects/signatures do not prove full schema/function bodies or readiness. The closed baseline distinguishes fifteen raw from fifteen latest-unique seed-owner Pass rows and checks applicable whitelist/XID/operation entries. Parameters remain private.

`bootstrap-database-executor.mjs` and its fixed worker implement one schema check then one baseline, separate clean child processes/connections, IP-SAN and exact leaf pinning before startup, READ ONLY / REPEATABLE READ, fixed search path/timeouts, strict one-row typing, rollback and worker closure before acceptance. No pool, arbitrary SQL, retry or auxiliary cancel connection. Parent operation/cleanup limits are six seconds/1.3 seconds; decrypted wire limit is 131,072 bytes. Tests exercise synthetic PostgreSQL wire replies, not engine execution/authentication. Ownership is a mandatory trusted callback, not independent database provenance or a malicious-database sandbox.

`bootstrap-owned-session.mjs` owns newly generated private identities/credentials and one-shot evidence, joins issuer/protocol/transports, checks schema before API and response-bound raw/latest baseline before exact helper stop. It supplies **no concrete ordinary-helper lifecycle**: create/inspect/stop callbacks and optional model factories are trusted. They must enforce their own bounds; cancellation cannot terminate callback code that never returns. Unknown IDs are not adopted and uncertain stops are not replayed. Independent component closure gates completion. Its result remains INJECTED_LIFECYCLE_COMPOSITION, actualRuntime NOT_RUN and no activation.

`bootstrap-protocol.mjs` implements a one-shot journaled sequence with a trusted
injected driver, and a fixed HTTP request mapper that sends nothing. It records
an attempt before the first callback: even authenticated GET can create an OIDC
user/mapping. It checks actual-returned IDs and seed readbacks, closes through
PUT, reads closed/gated flags, and requires exact-ID helper closure before a
private result is returned. Reported readiness/image/network facts remain
injected attestations, not independently verified runtime ownership or pins.
Unknown helper IDs never authorize cleanup; the future runtime manager needs its
own independent ledger. An uncertain stop is not replayed. Private evidence is
preserved and no disk adoption/resume is implemented.

`bootstrap-issuer.mjs` supplies a fresh host-loopback HTTPS JWKS endpoint with
explicit certificate trust and one invented-subject RS256 token lasting at most
120 seconds. It has no login/token HTTP endpoint, caller-selected claims, external
transport or global trust modification. Its tests execute actual loopback TLS and
the installed JWT/JWKS libraries, not Pol.is application/user-mapping code or a
container. Closing the issuer stops issuance/JWKS/listeners but does **not** revoke
an issued token validated from cached keys before expiry; helper closure remains
necessary. Only `summary()` is aggregate-safe; configuration/token handoffs stay
private. Do not insert its host-loopback issuer URL into a container configuration
and assume reachability.

From the current Pol.is clone, using already installed Node/PHP/tar prerequisites:

```sh
node --test deploy/fncp/fresh-bootstrap-result.test.mjs deploy/fncp/fresh-runtime/*.test.mjs deploy/fncp/wordpress-identity/pristine-source.test.mjs deploy/fncp/wordpress-identity/runtime.test.mjs
```

Tests create only fresh synthetic files, model drivers, loopback HTTPS fixtures and PostgreSQL-wire servers. Actual pg child processes are exercised without a PostgreSQL engine. Session lifecycle/API/database are models; full concrete transport/session composition was not run. Test-owned directories/listeners/workers are removed/closed. No Docker, VM, WordPress server or retained store is accessed; remote CI was not run.

Positive Docker lifecycle tests use isolated copies of the foundation with only its three empty AUTH/JWKS defaults replaced by invented local values. They run a fake Docker state model, including one pass through the real argument grammar with a fake process. The original missing-input guard is separately tested to dispatch zero Docker commands. These fixtures do not prove an actual issuer, usable container-to-host JWKS connection, schema initialization, database readiness or application health.

The extraction boundary is for the exact trusted pinned release. Member paths are checked before extraction; file/link types and the complete resulting tree are checked afterward. It is not a generic hostile-archive extractor.

Separately, fresh official WordPress7.1 bytes were fetched over normally validated HTTPS and passed through the real source-brand factory:35,356,041 bytes, SHA-256 `05a5f89138f632b7329f1202f2a0553c5f7fe4daf8e4b9ca7ebae9b9466b9e86`. This check was memory-only: no saved archive, extraction, installation or runtime execution. It is not an actual-service integration result. The [official release archive](https://wordpress.org/download/releases/) lists that release; any future acquisition must verify its bytes again.

## What remains before an actual-service run

Historical planning (superseded by the latest participant integration report): the ordered [startup/TLS next steps](../LOCAL-C-BOOTSTRAP-STARTUP-2026-09-13.md#next-steps--in-order) take precedence over earlier planning detail below. The application trust primitives and side-effect guards now exist, but no ordinary HTTPS launcher or complete runtime ownership/topology has been supplied. Fresh dependency parity is also required; the failing CSV checks cannot be waived by a passing typecheck.

1. Resolve complete fresh runtime inputs and availability. The concrete preflight/lifecycle source is implemented, but no mutation has been run. Verify the selected context is already available; never start a shared VM, switch context, pull/build an image or target retained resources as a fallback. The dedicated Colima profile was last observed stopped at21:46:51 AEST; it was not rechecked here. Source/model-test work can continue without starting it.
2. Implement the concrete **ordinary-bootstrap lifecycle** for the new session, with bounded exact-ID callbacks and a reviewed ordinary image. Resolve fresh PostgreSQL 17 schema/TLS, Auth0 startup and container-reachable issuer/JWKS/trust. The dedicated gated image is not a substitute. The SQL executor exists, but synthetic wire fixtures do not prove PostgreSQL acceptance or readiness. Model assertions are not independent image/network approval.
3. Verify the proposed isolated internal bridge and exact loopback exposure. The driver specifies an internal IPv4 bridge with isolated gateway mode, no masquerade, one exact network ID and no additional networks. This is configured policy, not actual negative-egress assurance. The old Colima staging source warns that internal-only host publishing is incompatible; do not restore its normal bridge fallback. Test reachability and denial with controlled local canaries before any actual-service assurance claim.
4. Create only fresh databases, source/configuration and keys. Record the bootstrap attempt before mutation, obtain the actual conversation and statement IDs, stop the bootstrap helper, and replace/reconfigure only the owned dedicated process. Publishing bound configuration does not update a running container, grant activation or open a round.
5. Compose native browser authentication with actual fresh WordPress registration/decision/outbox and actual Pol.is gateway/provider work. Verify valid forwarded-link denial, rightful token preservation, selective and terminal revocation, recovery and exact resource cleanup using aggregate-only observations.

The foundation preserves new files and uncertain resources; it offers no adoption, resume-from-disk, volume deletion, prune or broad cleanup operation. A successful stop callback must be separately implemented and verified for real resources. Integrity checks detect ordinary file/link/mode drift; they do not prove race-free protection against a concurrent same-user attacker replacing ancestor directories. Never turn a partial result into a readiness claim.

A valid `stop({ driver })` request latches cancellation immediately. If another operation is awaiting its callback, stop rejects as busy to avoid a reentrant deadlock while preventing subsequent starts or bootstrap binding. Retry stop after that operation settles; only verified owned IDs can be dispatched. An uncertain dispatched stop is never automatically repeated. A callback that never settles does not yield successful cleanup evidence.

The concrete adapter has its own independent `close()` latch and ledger. When ending a composed run, synchronously call `foundation.cancel()` to deny subsequent foundation work, then independently await `adapter.close()`, even after a failed start. Cancellation performs no I/O or stop and is not cleanup evidence. Retry a busy close only after its active driver settles. Read-only inspection failures may be retried; dispatched uncertain stops may not. A known already-stopped container is an independently verified no-op. A create with no trustworthy returned ID is never rediscovered by name. Network and volume objects are preserved intentionally; unknown infrastructure creation is reported as uncertain, not successful full cleanup.

Pol.is seed creation also creates seed-owner Pass rows. The protocol checks fifteen latest-unique seed-owner votes from API readback, not the raw historical votes table. Record that baseline separately from later participant deltas. Read seeds before enabling the whitelist; then PUT `is_active:false`, both XID gates and `send_created_email:false`, independently read back flags and stop the helper. The unawaited legacy POST close handler is not used. Later positive QA requires a separate exact-owned transition to active: config binding or strict activation alone does not reopen Pol.is. Creation hardcodes `is_public:true`; data-open false is not a privacy boundary, so the ordinary helper must remain isolated throughout.

Production identity/operator authentication, durable state/key custody, delivery, hosting costs, deployment-bound activation and complete release evidence remain separate. No public page, real invitation, message, submission, account, expenditure or deployment is authorized by these tests.

Upstream references: [Pol.is source/Docker instructions](https://github.com/compdemocracy/polis/blob/stable/README.md), [configuration guidance](https://github.com/compdemocracy/polis/blob/stable/docs/configuration.md), and the [full fresh-runtime specification](../LOCAL-C-FRESH-RUNTIME-PLAN-2026-09-13.md). The Pol.is quick-start supplies the upstream setup, not certification of Barayamal's custom controls; its global certificate-installation step has not been run.

Docker references: [internal networks](https://docs.docker.com/reference/cli/docker/network/create/) and [publishing/gateway modes](https://docs.docker.com/engine/network/port-publishing/). Engine 28 is the minimum because older releases have a documented localhost-publishing exposure. An internal bridge normally still permits host-gateway communication; isolated mode removes the bridge address. Neither documentation nor configuration inspection substitutes for testing this exact Colima topology.
