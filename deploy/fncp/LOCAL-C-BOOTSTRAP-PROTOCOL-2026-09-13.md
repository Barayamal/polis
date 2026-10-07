# Option C — fresh bootstrap protocol and local issuer

> Portability note — 7 October 2026: workstation paths were removed, and artifacts outside this source snapshot are labelled retained local evidence. Dated results below remain historical; this edit adds no runtime or release claim.

Checkpoint: **2026-09-13T22:21:16+10:00**. **LOCAL_ONLY / KEEP_CLOSED**.

Completed the next source layer using the Pol.is self-hosting guidance and this
fork's authentication, conversation and comment code. The ordinary suite passes
**1,670 tests on each Node24/26**, plus **59 PHP checks**. Fifty new tests are
included in that total: 27 protocol tests and 23 issuer tests.

There is now an actual, short-lived host-loopback HTTPS signing/JWKS service and
a journaled bootstrap protocol with fixed upstream HTTP mappings. The protocol's
Pol.is/helper driver is still injected and modeled: **no Pol.is conversation,
database, Docker helper or actual WordPress/browser integration was created in
this increment**. These are two separately tested components, not a complete
container-ready bootstrap launcher.

## Completed

| Component | Implemented and checked | Limit |
| --- | --- | --- |
| [Bootstrap protocol](./fresh-runtime/bootstrap-protocol.mjs) | New private evidence; one attempt before any callback; fixed seeds; observed IDs/PID; same-conversation readback; closed/gated flags; exact helper closure; no write replay | Trusted injected driver only; ownership/image/network/schema facts are not independently established |
| Fixed HTTP mapper, in that module | Correct POST/GET/PUT routes and bounded fixed request payloads; read seeds before whitelist; no arbitrary origin, credential or redirect | Sends nothing; a future driver must bind the exact owned local helper and one issuer token |
| [Local issuer](./fresh-runtime/bootstrap-issuer.mjs) | Fresh signing key and scoped TLS certificate; unique invented subject; one RS256 token lasting at most 120 seconds; JWKS-only loopback HTTPS; request/lifetime bounds; exact listener closure | Not login, production identity or container-reachable TLS configuration |
| Library interoperability | Actual HTTPS with explicit CA/IP-SAN verification plus installed `express-jwt`8.5.1 / `jwks-rsa`3.2.0; wrong issuer/audience/signature/expiry/algorithm denied | Reconstructs relevant library options; does not import/run Pol.is application middleware or user-mapping database code |

Only aggregate summaries belong in reports. Issuer configuration/token, protocol
callback bodies and returned binding are private handoffs. No caller can select
an issuer URL, arbitrary claims, private key or retained state for the issuer.
The protocol accepts no existing evidence directory or resume manifest. It checks
its exact pinned public seed source and detects private evidence drift.

Review fixed strict helper-ID typing, generic error handling, seed conversation
binding, and unknown-ID cleanup. An invalid or late initial helper inspection
does **not** authorize an identity-less stop. A future runtime owner must retain
its own independent exact-ID ledger. A dispatched uncertain close is not replayed;
after an acknowledged close, failed read-only closure inspection may be retried.
Cancellation denies new work but is not proof of cleanup. An injected driver that
never settles cannot yield successful cleanup evidence.

## Source-derived bootstrap sequence

1. **Journal before authentication.** Even the first authenticated GET may create
   or update Pol.is user/OIDC mapping rows. The new attempt marker precedes the
   first driver callback, not just the conversation POST. Use the same fresh
   invented issuer subject throughout; no simulator password grant is required
   by the RS256 verification contract itself.
2. **Create only inside an isolated ordinary helper.** Temporarily active is
   required for seed insertion and its automatic votes. Request anonymous mode,
   data-open false, strict moderation and disabled topics/treevites/spam/profanity
   filtering. Source hardcodes `is_public:true`; those request flags do not make
   the server private. Verified local isolation must precede actual API work.
3. **Post the fixed fifteen seeds once.** Validate each returned nonnegative
   PostgreSQL integer `tid` and a consistent creator `currentPid`; preserve the
   returned order and reject duplicates. Do not assume IDs0–14 or replay a lost
   response. Raw API responses can contain extra private fields; they are bounded
   and never copied to aggregate evidence.
4. **Read before enabling the whitelist.** Query the exact conversation with
   `moderation=true&include_voting_patterns=true`, without pagination/other
   filters. Check all fifteen IDs, original texts, conversation binding, seed
   flags, active/moderated state and creator PID. Each must have Agree0,
   Disagree0, Pass1 and total1. This proves an accepted **latest-unique** baseline
   of fifteen in the model; it is not a raw vote-history-table count.
5. **Close through PUT and independently read back.** PUT `is_active:false`,
   `use_xid_whitelist:true`, `xid_required:true`, `send_created_email:false`.
   GET the exact conversation and check ownership, ID, closed/gate/privacy/
   moderation flags and disabled optional features. The legacy POST close
   handler is not used because its source neither awaits the update nor sends
   a deterministic success response.
6. **Stop and inspect the exact helper before returning a binding.** HTTP
   conversation closure is not process closure. Later positive synthetic QA
   needs a separate reviewed exact-owned transition to active. Configuration
   binding or strict-service activation alone does not reopen Pol.is.

The HTTP mapper includes the reviewed `X-Forwarded-Proto:https` header needed by
ordinary production routing. It does not claim the API hop used TLS and does not
follow a redirect. The future concrete transport must enforce its exact origin,
ownership, TLS policy, time/output bounds and no-retry mutation contract itself.

## Issuer closure is not cached-token revocation

Actual loopback tests verify certificate trust, IP hostname checks, public-only
JWKS responses, one-time issuance, request budgets and listener shutdown. Expiry
and backwards-clock cases are checked with bounded clock tests; this was not a
120-second live production session exercise.

Closing the issuer prevents further signing/JWKS service, but a token already
validated using cached keys remains cryptographically valid until its expiry,
at most120 seconds after issuer creation. This limitation is tested and recorded
as `cachedTokenRevocationImplemented:false`. Exact helper closure and admission
controls remain necessary. No real mailbox ownership or Indigenous identity is
asserted; the invented email claim is explicitly unverified.

## Verification and retained boundaries

- Node26.8.2:1,670/1,670 PASS;20,096.321541ms; zero failures/cancellations/skips.
- Node24.21.0:1,670/1,670 PASS;20,613.686417ms; zero failures/cancellations/skips.
- PHP:59 PASS across23 identity,23 journal and13 plugin stub/model checks.
- Four new source/test files:79,119 bytes, independently recorded by SHA-256.
- The separate limited27-file /230,564-byte proof graph still matches its pins.
  Neither that graph nor the new four-file inventory is full release closure.
- All twelve known fixed loopback ports returned ECONNREFUSED at22:23:43 AEST;
  ephemeral issuer-port shutdown was separately tested by the issuer suite.
- All four current source/test hashes match;143 local document links resolve;
  `git diff --check` passes.
- Aggregate evidence (retained local evidence, `evidence/bootstrap-protocol-continuation-2026-09-13.json`; not included in this source snapshot)
  and source inventory (retained local evidence, `evidence/bootstrap-protocol-source-closure-2026-09-13.json`; not included in this source snapshot).

The earlier Docker preflight/Colima-off check at21:46:51 AEST was **not repeated**.
There were no Docker calls, VM start, image pull/build/scan, package installation,
native-browser journey, WordPress acquisition/install or actual Pol.is/database
request here. The tests use only new synthetic fixtures, actual host-loopback
issuer listeners and installed libraries. Generated issuer certificate files
and test-owned fixtures/listeners were cleaned up; retained keys, configuration,
archives, stores and resources were not opened or changed.

Public Pulse/results/WordPress/fallback surfaces were not changed or freshly
inspected. No external correspondence, submission, commit/push/PR, remote CI,
retention operation, expenditure, global trust change, participant test or
deployment occurred. Official documentation was read. PR#27 is not GO authority.

## Next steps — in order

1. **Implement the concrete owned helper adapter.** Reuse this protocol and
   issuer; do not duplicate them. Bind a separately reviewed ordinary production
   image, exact new resource IDs and a bounded HTTP/SQL transport. The image is
   still NOT PINNED. Driver-reported booleans are not sufficient runtime evidence.
2. **Complete startup inputs and schema/health checks.** Review container-reachable
   issuer/JWKS and narrowly scoped TLS trust, non-root key/data access, database
   initialization and ordinary Auth0 ManagementClient constructor inputs. Keep
   translation, mail, telemetry and external integration paths disabled.
3. **Resolve runtime availability and prove isolation.** Do not implicitly resume
   retained Colima state or use old start/stop/recovery scripts. Verify exact
   images/ports and controlled local reachability/negative-egress canaries. The
   internal-bridge/published-port topology remains unproved; do not weaken it to
   an unrestricted bridge or disable dedicated gates/TLS to make startup pass.
4. **Run actual bootstrap and join the actual-service browser journey.** Only new
   databases, keys and invented identities; record real returned IDs and baseline,
   close the helper, then separately authorize local active-state transition.
   Exercise real WordPress decisions/outbox, actual Pol.is, rightful redemption,
   forwarded-link denial, selective/terminal warm revocation and recovery.
5. **Keep production approval separate.** C remains selected as a direction.
   C1/C2/C3 remains unselected, totals NOT COSTED and authorized spending A$0.
   Shared local code can continue without that choice. Nothing is sent or
   published without Dean's exact approval; launch remains HOLD.

Use the local owner guide (retained local evidence, `C-SELF-HOSTING-GUIDE.md`; outside this repository)
and [fresh-runtime component guide](./fresh-runtime/README.md). Historical runtime
commands in the owner guide are reference only—not current execution instructions.

Official references: [Pol.is self-hosting/source instructions](https://github.com/compdemocracy/polis/blob/stable/README.md),
[configuration guidance](https://github.com/compdemocracy/polis/blob/stable/docs/configuration.md),
[JWT middleware](https://github.com/compdemocracy/polis/blob/stable/server/src/auth/jwt-middleware.ts)
and [database initialization image](https://github.com/compdemocracy/polis/blob/stable/server/Dockerfile-db).
The upstream quick-start is not certification of Barayamal's custom controls;
its global certificate-installation step was not run.
