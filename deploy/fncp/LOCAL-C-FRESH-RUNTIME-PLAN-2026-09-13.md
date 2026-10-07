# Fresh actual WordPress / Pol.is strict-native integration plan

**Status: ACTUAL DISPOSABLE POL.IS/POSTGRESQL BOOTSTRAP PASS; JOINED WORDPRESS/PARTICIPANT INTEGRATION NOT_RUN. Updated 2026-09-14T02:18:43+10:00 (Australia/Sydney).**

The [fresh-only foundation](./fresh-runtime/README.md) now includes actual fresh Linux API/PostgreSQL/JWKS integration: all 19 bootstrap requests, 15 synthetic seeds, final closed/gated state and independent SQL baseline passed. All ten task containers and the VM were stopped; no persistent stack or public URL exists. The [current report and ordered steps](./LOCAL-C-CONTAINER-INTEGRATION-2026-09-14.md) records 1,936 foundation +568 fresh server +12 CSV tests on each Node22/24/26, 59 PHP checks and TypeScript PASS. Next is the actual joined WordPress/approval/invitation/voter journey and negative/recovery assurance. This header supersedes the original plan's unfinished-bootstrap wording; retained historical resources remain out of scope.

This plan describes the smallest isolated continuation from the native HTTPS
strict-service proof to a new run using actual WordPress and Pol.is services.
It is not a runnable command guide, evidence of a completed integration, permission
to start a VM/container, or deployment GO. The original planning review started no runtime; the separately authorised continuation recorded above created and stopped a new disposable VM and actual services.
No retained configuration, credentials, database contents or archives were read.
All public surfaces remain closed and unchanged; no invitations, mail, messages,
publication, production changes or purchases are part of this plan.

## Intended result and limits

Use two invented browser identities and fresh, task-owned browser profiles to
exercise this chain:

1. Native HTTPS authentication and strict-service registration.
2. An actual fresh WordPress session, challenge, registration receipt and
   administrator decision delivered through its signed event outbox.
3. The strict service's real in-memory access and activation stores.
4. One newly bootstrapped Pol.is conversation in a new private database, reached
   through the real `LocalPolisProvider` adapter.
5. Closed-round denial, approval without opening, account-bound invitation,
   cross-account denial, a legitimate vote and warm-session revocation denial.

The identity issuer remains an invented local test issuer. The Pol.is database,
WordPress application and event outbox would be actual local services; they must
not be replaced with model approval events or model provider counters while
calling this an actual-service result. This would not prove Indigenous heritage,
delivery of an email/message, an operator's real browser login, a production
identity provider, persistent-store recovery, or production hosting readiness.

## Do not reuse these entrypoints unchanged

Paths below are relative to `deploy/fncp/`. Their existing bounded tests can remain;
this is a restriction on using their runtime paths for this new isolated run.

| Existing entrypoint | Why it is unsuitable for this fresh run |
| --- | --- |
| `local-wordpress-runtime/prepare.mjs` and `local-wordpress-runtime/compose.yml` | Use the earlier fixed runtime directory, credentials/configuration, WordPress secret and named database resources. They are not a fresh ownership boundary. |
| `prepare-staging.sh` | Targets the existing `.env.staging`, certificate and server-key locations. It is not a new private run manifest. |
| `start-colima-staging.sh` | Uses the existing staging configuration/project, includes `down --remove-orphans` and `build --pull`, and writes/copies into that stack. Do not use it to start or repair this experiment. |
| `bootstrap-synthetic-conversation.sh` | Sources the existing staging environment, uses its keys/project and bootstrap marker, and rewrites its conversation binding and statement IDs. Preserve its fail-closed bootstrap ideas, not its targets. |
| `integrated-journey/real-origin-smoke.mjs` | Reads the existing staging provider/configuration and retained access/WordPress preservation evidence, and observes the fixed staging containers/database. |
| `wordpress-identity/actual-proof.mjs` and `wordpress-identity/expanded-proof.mjs` | Couple fresh WordPress work to the retained Pol.is stack and preservation/recovery workflow. They are not native HTTPS strict-service runners. |
| `integrated-journey/proof-harness.mjs` | The legacy journey harness exposes test-admin routes, uses its own temporary disk stores and manually driven authentication. Do not insert it between the new native browser and strict service. |
| `expanded-recovery/run.mjs` | Reads existing staging configuration and source stores, validates/stops particular source applications and handles backup/restore material. It is not a fresh-service provisioner or a drop-in proof for in-memory strict stores. |
| `wordpress-identity/runtime.mjs` legacy `prepareIdentityWordPress` API | Still reads a fixed earlier `.runtime/wordpress-7.1.tar.gz`. Preserve that historical API; use the new separate `prepareIdentityWordPressFromPristine` API for this plan. The latter has no retained-archive fallback. |

Do not “prove preservation” by hashing or querying prior stores. For this run,
non-interference means never opening or addressing those resources. Do not stop
occupied listeners, restart old containers, clear old bootstrap markers or use a
previous run after an uncertain bootstrap result.

## Reusable source components

| Component | Reuse and boundary |
| --- | --- |
| `strict-service/service.mjs` — `createStrictLocalService` | Compose the real local access, event, activation, registration and browser services with `:memory:` access/activation stores. Keep private operator controls private; add no HTTP approval/admin route. |
| `local-access/access-server.mjs` — `LocalPolisProvider` | Construct directly with the new conversation ID and independently generated gateway/provider secrets. Do not call the staging-config reader. The present adapter targets loopback port `5500`. |
| `wordpress-identity/runtime.mjs` | The new `prepareIdentityWordPressFromPristine` API supplies the fresh source boundary. Reuse its branded instance, private files, full fresh-tree integrity checks, random resources, pinned MySQL image and exact tracked stop logic; actual fresh-release preparation/install/runtime remain unexecuted. |
| `wordpress-identity/wordpress-client.mjs` | Use the real WordPress HTTP bridge and `decide(registrationId, state)` against the newly returned instance. Keep cookie, nonce, receipt and registration references private. |
| `wordpress-identity/operator-proof.php` | Reuse `operator-session`, `aggregate` and `close-guests` only through `runIdentityPhp` on the new branded instance. The CLI-created operator session is a synthetic administrator capability, not evidence of a human browser login. |
| `browser-engine/native-https-proof.mjs` and local HTTPS lab | Reuse strict certificate validation, ephemeral profile trust, browser request observations and owned-resource cleanup. Add an actual-service adapter rather than making the model fixture contact real services. |
| `browser-engine/strict-native-fixture.mjs` | Use its assertions as a comparison checklist only. Its modeled WordPress approval and Pol.is provider are not substitutes for the new actual-service adapter. |

`operator-proof.php` currently expects exactly two registrations and two terminal,
delivered approval-journal subjects before `close-guests`. Use two real invented
registrations produced by the native flow; do not manufacture a row to satisfy
cleanup. If the intended run scope changes, separately revise and test that
cleanup contract before runtime work.

## Source and image inputs: evidence, not availability

The existing WordPress runtime pins WordPress `7.1` archive bytes to SHA-256
`05a5f89138f632b7329f1202f2a0553c5f7fe4daf8e4b9ca7ebae9b9466b9e86`.
For the new path, independently acquire pristine release bytes from the official
WordPress distribution into bounded memory or a newly owned acquisition directory,
record the verified source and digest, and pass only the validated new input into
the runtime helper. Do not copy an installed WordPress tree, old `wp-content`, old
`wp-config.php`, database export or the earlier retained archive. Availability of
that official release/input was rechecked: a fresh normally validated HTTPS
download of35,356,041 bytes passed the real pinned source-brand API in memory.
No archive was saved, extracted or installed. A future run must reacquire and
revalidate its own bytes; a mismatch or unavailable release is a stop, not a
reason to disable the source hash check.

The implemented source brand accepts exact plain fixed unshared ArrayBuffer
bytes, not an unrestricted path or an environment override. The separate fresh
preparation API checks size, digest, member paths, extracted tree and generated
file/secret integrity. Link/type checks occur after extraction: this depends on
the exact trusted release pin and is not a generic hostile-archive extractor.
Source acquisition remains a separate network step; the integration phase must
not fetch packages, images, core updates or plugins.

Use these existing aggregate source/evidence files to select exact image subjects:

- `image-security.lock.json`: reviewed image/toolchain pins.
- `evidence/exact-images-wip-20260913-arm64-patched/image-index.json`: exact rebuilt
  five-artifact ARM64 subjects; SHA-256
  `475f1e948ec89bdf8a714f0b92fa1d3785bf9c7dbfe46ed1897c6a4d3789be16`.
- `evidence/exact-images-wip-20260913-arm64-patched/scan-summary.json`: associated
  unsuppressed scan; SHA-256
  `cf89d995be6b3ccb8f7105d6851a15c0b2ae2070ad752bf064945eb6c4526af2`.
- `evidence/exact-images-wip-20260913-arm64-02/image-index.json` and its scan
  summary: earlier seven-image snapshot, including QA infrastructure. Do not
  transfer the patched production-image result to the QA images.
- `VERIFY-IMAGE-REMEDIATION-2026-09-13.md`: interpretation and remaining findings.

The recorded server subject is
`sha256:07f8a21105ed90963ccdf0981d884323116187583a464bb581db14c621d33a98`.
The reviewed recovery source records the QA PostgreSQL subject
`sha256:9d9684f7a95e94c9eb370212edea832e7b9916b7bd96b2821c5bc9cf63a0e8b3`.
The WordPress helper pins MySQL to
`mysql:8.4.11@sha256:85b9bf2e29cf836ecb8c2a15a935d4ba0c606631dff1dd79531a11983c638f2a`.

These records do not prove that any image is currently cached or startable. A
future scoped preflight must match actual image identity/architecture to the
selected record and use `pull_policy: never` / no-build execution. Missing images
must stop the run. Do not automatically pull, rebuild, change tags or start a VM
to recover availability. The ordinary bootstrap server image and any local QA
identity component needed by Pol.is bootstrap also need their own exact approved
local identities; the native browser's invented issuer is not automatically a
drop-in Pol.is administrator bootstrap issuer.

The five patched production-artifact scan recorded zero Critical/High and fifteen
Medium matches, not a vulnerability-free or production-approved stack. The QA
PostgreSQL/OIDC findings and OIDC root-user assertion failure were not repaired by
that result. Do not execute the migration image simply because it was scanned;
its recorded verification did not run its migration entrypoint.

## Proposed sequence — implementation requirements, not commands

### 1. Add one fresh ownership manifest and preflight

The fresh foundation and concrete Docker adapter source now implement the bounded
ownership/preflight/lifecycle layer described here. Active callback brands expire
after each operation, the CLI uses only the dedicated socket with empty private
client configuration, and the independent adapter ledger captures concrete IDs
before start. Missing AUTH/JWKS inputs reject before any Docker mutation. One
actual read-only preflight did not complete; a separate Colima status check found
the dedicated profile stopped. No availability, startup or health result is claimed.

Continue completing the test-only Pol.is runtime adapter. Importing it must do no I/O or
runtime work. It must create a new random run identity, project, container names,
private network, empty PostgreSQL database volume and independently generated
keys/secrets in a new exclusive private directory. It must not read
`.env.staging`, old certificates/keys, old volume metadata or an existing run's
manifest. Do not accept arbitrary project, host, database, archive or key paths.

Capture ownership before the first mutation. Verify generated configuration and
run labels before every start/stop. Track attempted starts as well as successful
ones so partial startup has a bounded cleanup path. Match concrete container
IDs and the new manifest, not a broad name prefix or a workspace-wide query.

Preflight the selected, already available runtime context without starting or
restarting it. Starting a shared VM can resume retained resources and is not an
implicit prerequisite. If the context is unavailable, stop and report the exact
runtime prerequisite separately. Do not create a replacement profile or choose a
hosting target automatically.

### 2. Keep the present fixed-origin guards intact

The real WordPress bridge is currently source-guarded to
`http://127.0.0.1:8103`, and WordPress events to
`http://127.0.0.1:8101/internal/wordpress/events`. Its MySQL helper uses loopback
port `33080`; `LocalPolisProvider` uses loopback `5500`.

Require these ports to be free before mutation. Use strict receiver port `8101`,
an ephemeral strict access port and the new lab's browser port. If a required
port is occupied, do not discover/read the owning service or stop it. Report the
conflict; a later separately tested fixed-test-origin adaptation may be needed.
Do not turn the bridge into an arbitrary-origin fetcher to avoid a conflict.

### 3. Initialize only the new Pol.is database and conversation

The dedicated server image is not an ordinary-bootstrap substitute. Its mandatory
access gates must not be disabled to create the conversation. A separate exact
ordinary production image, container-reachable local issuer/JWKS and scoped trust
remain prerequisites. The new actual host-loopback issuer also does not supply
that topology; container loopback is not the host. The proposed internal isolated bridge/loopback publishing must also
be proved on this Colima version. Do not use the old normal-bridge fallback.

Adapt the source-reviewed bootstrap sequence to the new private configuration,
empty database and exact owned containers. Initialize a schema only in that new
database. Keep the participant gateway unavailable/closed during bootstrap and
retain the absent-conversation binding until bootstrap completes.

The new protocol's durable attempt marker precedes its first driver callback:
even authenticated GET may create an OIDC user/mapping. Require one invented
issuer subject throughout. Creation hardcodes `is_public:true`, so local isolation
must precede API work; `is_data_open:false` alone is not a privacy boundary. Disable
translation, mail, telemetry and optional external integrations in the reviewed
ordinary runtime; the absent dedicated binding does not protect a new conversation.

Create one invented conversation and the fixed fifteen harmless seed statements
through the actual Pol.is bootstrap/API path. Obtain the real resulting
conversation and statement IDs; do not assume IDs `0..14` or a model's statement
order. Record an attempted-bootstrap marker before the first mutation. An
uncertain response must not trigger automatic replay or a new conversation.

Record seed-owner Pass vote rows separately: upstream seed creation can create a
Pass row per statement. The protocol checks API latest-unique counts, not raw vote
history. Read all seeds before enabling the XID whitelist; then use awaited PUT
with `is_active:false`, both XID gates and `send_created_email:false`, followed by
exact conversation/owner/flag readback. Do not use the unawaited POST close handler.
Fifteen seeds are not a zero-vote baseline. Participant vote assertions must
compare against the observed bootstrap baseline.

Bind both provider and participation gates atomically to the new exact
conversation and the observed seed-ID set. Stop the new bootstrap helper before
participant authority can be admitted. No unrestricted bootstrap endpoint may
remain reachable through the strict browser path. The native assertions must
follow actual returned statements while validating membership in the known
seed set, rather than assuming modeled ordering.

Closing the JWKS issuer is not cached-token revocation; its issued token can
remain valid for its bounded lifetime. Stop and independently verify the exact
helper process. Later positive QA needs a separately reviewed exact-owned change
from Pol.is `is_active:false`; binding config or strict activation does not make
that change. Neither the protocol nor issuer implements that future transition.

### 4. Create fresh WordPress and compose the strict service

Use the revised pristine-source boundary to create a new WordPress installation,
random database/user and independent secrets. Reuse the existing mail block,
disabled cron/updates and exact local event HTTP allowlist. Source the operator
capability only from this branded instance.

Construct `LocalPolisProvider` directly with the new private credentials. Supply
the real WordPress registration transport, not the model fetch implementation.
Use fresh in-memory access/activation stores and a deployment binding derived
only from the new run's actual subjects/configuration. Generate the activation
signing material freshly. Start and activate the strict supervisor before the
browser authenticates, since activation invalidates earlier capabilities.

Assert that opening before activation fails and that activation alone leaves the
round closed. Do not change the production activation or expiry rules.

### 5. Exercise two isolated native browser identities

Use fresh task-owned browser profiles for the two fixed invented accounts. Each
must complete the native authentication and real WordPress registration path;
do not copy cookies, inject a principal, reuse a user's browser profile or change
global certificate trust. Preserve normal certificate/hostname validation and
the existing launch/network policy. Never log identity subjects or auth material.

For both accounts, assert that login/registration alone cannot obtain a valid
invitation or vote. Use real `WordPressIdentityClient.decide` and verify actual
signed outbox delivery/ACK before claiming approval. Assert that approval alone
still does not open participation. Do not call a fixture's model `approve()` or
hand-sign an event in place of the WordPress decision.

Explicitly open the round through the strict private operator API, issue an
invitation for the intended verified registration, and prove that the second
invented browser identity cannot redeem it. Prove that the failed cross-account
attempt does not consume or transfer the intended account's authority. Keep any
invitation capability entirely inside the test; send nothing by email/message.

Allow an intended account to cast a legitimate vote, then revoke it through an
actual new WordPress decision and delivered event. Attempt another vote with the
already warm browser session. Independently observe that this POST reached the
strict access service and was denied there, that real provider participation did
not occur for the denied request and that the actual new Pol.is vote aggregate
did not increase. A BFF-only denial or a model counter is insufficient evidence.

### 6. Enforce local-only traffic and exact cleanup

The new container network must deny external egress; publish only the reviewed
loopback listeners needed by the test. Browser/identity routing must remain
limited to the fresh lab and exact local services. Explicitly disable outgoing
mail, analytics, telemetry, updates and external API integrations. Verify these
boundaries before authentication/bootstrap that could send traffic. The existing
WordPress mail/HTTP hooks alone do not prove container-wide egress denial.

At successful completion, drive both invented registrations to terminal revoked
states through WordPress, verify delivered outbox ACKs/no pending events, and
read back zero active allowlist entries for only the owned conversation/subjects.
Then clear the fresh guest/admin sessions through its exact cleanup helper, close
strict authority, close tracked browser profiles/lab listeners, stop tracked PHP
and stop only the newly owned API/database containers. Verify the owned listeners
are closed. No retained resource may be restarted, stopped or removed.

Cleanup must be idempotent and still attempt remaining owned stops when one step
throws. Do not hide failures. If terminal delivery/readback fails, stop admission
and the owned runtime and record incomplete cleanup; do not claim a successful
revocation or erase evidence. Preserve new private files/volumes on uncertain
failure. This plan includes no volume deletion, prune, recursive removal or
automatic disposal of retained resources.

### 7. Produce aggregate-only evidence

Record the exact reviewed source closure, image IDs/architecture, test runtimes,
named non-empty assertions and independent cleanup results. Include aggregate
registrations, approvals, outbox ACKs/pending events, legitimate votes, denied
warm requests reaching access, denied cross-account redemptions and remaining
active allowlist entries. Keep real database checks limited to the new owned
resources and known synthetic scope.

Exclude raw participant/identity subjects, registration references, XIDs,
conversation/statement capabilities, cookies, tokens, keys, passwords, private
URLs, raw SQL/log dumps and retained data. Do not publish an archive as evidence.
Distinguish native browser assertions, actual WordPress/Pol.is assertions and
modeled issuer behavior in the report. A successful result still means local
synthetic integration only, with all public surfaces closed and no deployment GO.

## Next small code piece

The next code piece is the **concrete ordinary-helper lifecycle adapter and complete fresh startup/TLS configuration**. Reuse the implemented protocol, issuer, HTTPS client, bounded SQL executor and one-use owned-session composition. Its create/inspect/stop callbacks are currently injected; tests do not prove Docker ownership or full concrete transport composition. Bind a reviewed ordinary image and exact new IDs; establish fresh PostgreSQL 17 schema/TLS and container-reachable JWKS. Current foundation AUTH defaults remain blank. Do not approve readiness/topology from model booleans, wire replies or binding files. Verify negative egress, actual API/SQL baselines, closed readback and exact helper closure before a native run.

The last read-only Colima check found the dedicated profile NOT_RUNNING. Do not
start a shared VM or retained resources to overcome that runtime prerequisite.
Source implementation and isolated fake-driver tests can continue independently.

Only after those source boundaries are reviewed should a new actual-service
native adapter and a separately scoped runtime preflight be considered. Do not
retrofit the modeled proof silently, reuse retained staging as a shortcut, or
claim the older expanded recovery result covers this new in-memory strict run.
No price, provider selection, production target or new approval is inferred by
this plan.
