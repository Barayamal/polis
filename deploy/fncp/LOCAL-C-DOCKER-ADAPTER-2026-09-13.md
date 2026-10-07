# Option C — concrete Docker adapter continuation

> Portability note — 7 October 2026: workstation paths were removed, and artifacts outside this source snapshot are labelled retained local evidence. Dated results below remain historical; this edit adds no runtime or release claim.

Recorded: **2026-09-13T21:55:00+10:00**. Status: **LOCAL_ONLY / KEEP_CLOSED**.

Implemented the next fresh-only self-hosting source layer: a bounded Docker CLI
transport, read-only runtime preflight and independently owned-resource lifecycle.
The complete ordinary regression suite passes **1,620 tests on each Node24 and
Node26**, plus **59 PHP checks**. This is not a running or deployable stack.

One real read-only preflight was attempted and **did not complete**. Separately,
`colima status --profile fncp-c-20260913` reported that the dedicated profile was
not running at 21:46:51 AEST. No VM was started and no Docker mutation was requested.
The generated disposable preflight fixture was removed; no retained state was read.

## Completed source and fixes

| Component | What is implemented | Evidence boundary |
| --- | --- | --- |
| [Docker CLI](./fresh-runtime/docker-cli.mjs) | Fixed executable and dedicated Unix socket; new empty private client configuration; minimal environment; no shell; exact command grammar; output/deadline bounds and sanitized failures |24 fake-process tests; not successful real container execution |
| [Preflight](./fresh-runtime/docker-preflight.mjs) | Engine28+, Linux/ARM64, two exact image subjects, absence of four newly generated names, four loopback ports; no VM start, context switch, pull/build or existing-environment/log query |20 model tests; actual read-only attempt BLOCKED |
| [Lifecycle](./fresh-runtime/docker-lifecycle.mjs) | New private ledger, exact network/volume ownership, concrete container IDs recorded before start, restricted mounts/security/ports, independent stop path and uncertain-result preservation |22 fake-Docker tests, including real argument grammar with fake spawn; no actual network/start/stop result |
| [Foundation](./fresh-runtime/foundation.mjs) | Active in-process callback authority, drift checks and denial-only synchronous cancellation |36 tests, five more than the prior foundation milestone; not a sandbox for arbitrary trusted callbacks |

The increment adds 71 tests over the earlier 1,549-test suite. Review strengthened
canonical Docker JSON handling: duplicate keys, extra projection fields and
ambiguous metadata fail closed. A newly created, not-yet-running container may
legitimately have an empty endpoint network ID; that case is accepted only with
the exact owned HostConfig network and independent network inspection. Running
containers still require the concrete network ID.

Partial starts have an independent cleanup owner. End a composed run with
`foundation.cancel()`, then `await adapter.close()`, including after failed start.
Cancellation only denies future work. A busy close must wait for its active
operation to settle before retry. Read-only inspection failures can be retried;
an uncertain dispatched stop is never automatically repeated. A create without
a trustworthy returned ID is not rediscovered by name. Unknown network/volume
creation is reported as uncertain. Networks, volumes and private ledgers are
preserved; this adapter contains no deletion, prune or disk-resume capability.

## What is not yet working end to end

The owner guide now explicitly separates current source checks from historical
runtime commands. Its old start/smoke/recovery/harness/Compose-stop examples are
preserved as reference and marked **do not run for this fresh continuation**;
passing source tests does not authorize touching that retained stack.

The real foundation's AUTH/JWKS inputs are deliberately empty, and the concrete
lifecycle rejects them **before issuing any Docker command**. Positive tests use
isolated copied modules with only those three literals replaced by invented
loopback values and a fake Docker model. A container's loopback is not the host
issuer: filling those blanks alone is not a runnable configuration or proof of
identity reachability/trust, schema initialization, readiness or application health.

The separate ordinary production bootstrap image has not been pinned. The
recorded dedicated server image requires its access gates and cannot be used as
an unrestricted bootstrap helper. Do not unset/disable those gates. Bootstrap
still needs its own local identity/TLS, attempted-mutation journal, actual schema,
conversation/statement readback and verified helper shutdown before binding.

The proposed internal isolated bridge and localhost-only publishing are source
configuration, **not observed negative-egress assurance**. Old staging source
warns of an internal-network/host-publishing incompatibility on Colima. Do not
copy its ordinary bridge fallback. Actual host reachability and egress denial
need controlled local canaries. Database volume ownership and server key access
under the selected non-root users also remain unverified at runtime.

Pol.is seed creation can create seed-owner Pass vote rows. The future actual
bootstrap must record that baseline separately from participant vote deltas;
fifteen seed statements do not imply zero vote rows.

## Verification and evidence

- Node26:1,620/1,620 PASS, zero failures/cancellations/skips,16,061.080042ms.
- Node24:1,620/1,620 PASS, zero failures/cancellations/skips,15,916.122167ms.
- PHP:59 PASS across23 identity,23 journal and13 plugin-boundary stub/model checks.
- All 12 known loopback test ports returned ECONNREFUSED after the suites.
- Limited 27-file proof graph still matches 230,564 bytes. This does not include
  every release input and is not full release closure.
- All eight current source/test hashes were independently rechecked; 138 local
  links across the updated guide/report documents resolve. `git diff --check` passes.
- Aggregate continuation evidence (retained local evidence, `evidence/docker-adapter-continuation-2026-09-13.json`; not included in this source snapshot)
  and eight-file source inventory (retained local evidence, `evidence/docker-adapter-source-closure-2026-09-13.json`; not included in this source snapshot).
- [Fresh-only component guide](./fresh-runtime/README.md) and
  [complete integration requirements](./LOCAL-C-FRESH-RUNTIME-PLAN-2026-09-13.md).

The earlier21:21:52 milestone's memory-only official WordPress source download was
not repeated. Earlier native-browser results used model WordPress/Pol.is and an
invented issuer; those journeys were not rerun here and do not establish actual
service integration or selective revocation while another voter stays approved.

No retained configuration, private keys, databases, archives or containers were
read, restarted, stopped or deleted. Tests removed only newly owned synthetic
fixtures. Public Pulse/results/WordPress/fallback surfaces were not changed or
freshly inspected. No external correspondence, submission, commit/push/PR, remote
CI, package installation, image pull/build/scan, retention action, expenditure,
global trust change, participant test or deployment occurred. PR#27 is not GO.

## Next steps — in order

1. **Complete ordinary-bootstrap and local identity source.** Pin a separately
   reviewed ordinary production image and define a container-reachable local
   issuer/JWKS and scoped trust. Add tests without starting old runtimes or
   reading old configuration. C1/C2/C3 selection is not needed for this work.
2. **Prove the network design in a fresh isolated runtime.** First resolve runtime
   availability without implicitly resuming retained resources. Verify the exact
   image subjects/ports, then local reachability, host isolation and negative
   egress. Stop on missing images or incompatible topology; no automatic pull,
   rebuild, context switch or weaker-network fallback.
3. **Bootstrap only new state.** Initialize the new schema, journal before the
   first mutation, obtain actual conversation/15 statement IDs and seed-owner
   baseline, close the bootstrap helper, then atomically prepare the bound
   dedicated configuration. A file update alone does not reconfigure a process.
4. **Join actual services to the native browser journey.** Fresh WordPress
   registration/decision/outbox must feed the actual strict service and actual
   Pol.is provider. Use only two invented identities. Verify forwarded-link
   denial, rightful redemption, selective and terminal warm-session revocation,
   recovery, cancellation and exact owned-resource shutdown.
5. **Keep production decisions separate.** Complete full release evidence,
   persistent identity/state/key custody, delivery and all-inclusive hosting and
   operating costs. C is selected as a direction; C1/C2/C3 remains unselected,
   NOT COSTED, with A$0 authorized spending. Nothing is sent or published without
   Dean's exact approval. The owner decision pack (retained local evidence, `C-PRODUCTION-DECISIONS.md`; outside this repository) retains the choices.

## Official guidance used

The [Pol.is source/Docker instructions](https://github.com/compdemocracy/polis/blob/stable/README.md)
and [configuration guide](https://github.com/compdemocracy/polis/blob/stable/docs/configuration.md)
provide upstream setup, not certification of Barayamal's custom controls. The
quick-start's global certificate installation was not performed.

Docker documents [internal networks](https://docs.docker.com/reference/cli/docker/network/create/)
and [port publishing/gateway modes](https://docs.docker.com/engine/network/port-publishing/).
Engine28 is the minimum because older releases have a documented localhost-port
exposure. An internal bridge still ordinarily allows host-gateway communication;
isolated gateway mode removes the bridge address. These documented properties
must be verified on the exact proposed Colima topology, not inferred from flags.
