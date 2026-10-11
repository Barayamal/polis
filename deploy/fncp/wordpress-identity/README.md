# Fresh WordPress → strict identity → self-hosted Pol.is proof

Local invented-data integration only. Not a deployment package, public registration,
real identity/heritage verification, mail sender or GO authority. Existing WordPress
page 12064 and Jetpack form 12069 are **not used**. No existing registration store
is copied or adopted.

## What this adds

**Fresh-only source boundary:** `pristine-source.mjs` now validates a plain fixed-length, unshared ArrayBuffer against the pinned WordPress7.1 gzip digest and keeps a private defensive copy behind a branded handle. It accepts no path, URL, hash override or environment fallback. `prepareIdentityWordPressFromPristine({ source, eventSecret, challengeSecret, registrationSecret })` is the separate preparation API; an omitted or forged source cannot select the old archive. Preparation generates new local files only, not a running installation. The private archive copy and complete extracted core/configuration tree are checked again before later runtime commands. No source handle certifies where its caller acquired the bytes or grants permission to execute them.

The fresh official7.1 download was independently checked in memory against the pinned digest; it was not saved, extracted or installed. Positive preparation tests use separately copied test modules pinned only to newly generated inert tar fixtures, not real WordPress. See the [fresh-runtime guide](../fresh-runtime/README.md) for the current source-only boundary and remaining actual-service work. The old retained-source `prepareIdentityWordPress` API remains available only for its historical workflows; it is not the new path.

**Earlier continuation:** [closed restored-access restart and source dependency closure](../LOCAL-C-COLD-RESTART-REVIEW-2026-09-13.md)
passed on 13 September 2026. The source-only checker verifies the five PHP files
and five literal dependency edges required by this plugin, including its sibling
journal/contract files. It does not create an archive or install a deployable plugin.
The latest actual journey also passed four-store recovery and 10 closed access-service
HTTP denials; this is not a WordPress application restart or real identity proof.

The earlier [seamless registration and actual four-store recovery](../LOCAL-C-SEAMLESS-RECOVERY-2026-09-13.md)
passed on 13 September 2026. The browser submits only three declarations and the
notice version. A private server bridge performs steps 1–4 below; WordPress cookies,
CSRF, challenges and receipts are not exposed to the browser in this mode. The
participant sees **submitted—not approved**, with no automatic invitation or send.

1. A fresh WordPress guest session has its own HttpOnly/SameSiteStrict cookie and
   independent CSRF token. WordPress issues a signed two-minute challenge.
2. The strict signed-synthetic OIDC browser service checks the live principal,
   mapping, auth capability and current deployment authority. It does not accept
   a caller-selected account, fixture, email or XID.
3. Three explicit self-attestations/consent facts and a fixed notice version are
   bound to a registration-only signed receipt lasting at most 60 seconds.
4. WordPress checks signature, audience, round, browser binding, challenge and
   expiry. One compare-and-swap update consumes the challenge/receipt, inserts
   the immutable registration and rotates the guest cookie/CSRF. Per-round
   account duplicates and replay are denied. The registry is bounded to 20 rows.
5. A local WordPress administrator selects a registered reference. The handler
   resolves its opaque account server-side, checks capability and a WordPress
   nonce, then writes the existing durable event/outbox contract. No arbitrary
   fixture approval endpoint is loaded in this fresh instance.
6. Approval is acknowledged only after the strict local event receiver accepts
   it. Voting still needs current approval, a matching one-use invitation and
   signed deployment authority plus an explicit open round.
7. WordPress revocation closes warm participation and cannot be reversed by a
   later approval. Failed/uncertain delivery stays pending, not falsely completed.

These are Barayamal-specific additions to Pol.is, **not features certified by
upstream installation instructions**. Official starting points:
[Pol.is Docker/source guide](https://github.com/compdemocracy/polis/blob/stable/README.md),
[configuration](https://github.com/compdemocracy/polis/blob/edge/docs/configuration.md).
WordPress explains that its [nonces](https://developer.wordpress.org/apis/security/nonces/)
are not one-use replay or authentication controls; this proof adds its own guest
binding and durable consumption, and retains administrator capability checks.

## Evidence boundaries

- Read [the fixed synthetic notice](consent-notice.md). Self-attestation is not
  proof of Indigenous heritage or mailbox ownership.
- Signed receipts are not encrypted. They include an opaque local fixture, but no
  backend auth/participation token or Pol.is XID. They stay server-side in seamless
  mode; the old manual receipt route is unavailable in that mode.
- A receipt already issued can be consumed until expiry after logout. It confers
  no voting access. The seamless bridge performs the handoff server-to-server,
  caps the current session/principal deadline and refuses uncertain resubmission.
- WordPress/PHP/HTTP approval and outbox can be tested for real locally. The issuer
  remains cryptographically signed but intercepted/invented. Operator cookies
  are provisioned privately by a test helper; that is not real operator login/MFA
  evidence. Separate test-DOM tests and a labelled rendered UI model verify form
  behaviour/layout, not genuine browser identity/operator authentication.
- HTTP loopback cookies are not Secure/TLS production cookies. Keys are local
  test keys, not a production custody/recovery design.
- The standalone [strict recovery validator](../strict-recovery/README.md) is a
  contract/model. The separate [expanded runner](../expanded-recovery/README.md)
  now has an actual four-store restore PASS for the new registry/strict state.
- The new host-side code is not in the previously scanned application images.

## Developer checks

From the prepared clone, with its locked identity dependencies already installed:

```sh
node --test deploy/fncp/wordpress-identity/*.test.mjs deploy/fncp/strict-recovery/*.test.mjs
node --test deploy/fncp/local-browser/*.test.mjs deploy/fncp/expanded-recovery/*.test.mjs
php deploy/fncp/wordpress-identity/tests.php
node deploy/fncp/wordpress-identity/package-check.mjs --check
```

Model/runtime boundary tests do not start Docker or use old databases. One Node
integration test uses and closes a local 8101 receiver; do not run it concurrently
with the actual proof receiver.

For the actual local proof, the isolated `fncp-c-20260913` Colima profile and
existing Pol.is stack must already be running. The preserved **synthetic**
WordPress database alone must be running for read-only pre/post aggregate/hash
checks; its PHP/app server must remain stopped. Ports 8101,8103,33080 must be free.

**Historical commands below—not the fresh-only continuation.** They depend on retained staging configuration and resources. Do not run them for the new fresh-only integration or start the old VM/stack to make them work. The new Docker/bootstrap/native actual-service adapter is not implemented yet.

```sh
FNCP_LOCAL_SYNTHETIC_MODE=fixture-only node deploy/fncp/wordpress-identity/actual-proof.mjs
```

That command preserves the earlier manual-receipt protocol test. For the newer
seamless handoff followed by isolated expanded recovery, use instead:

```sh
FNCP_LOCAL_SYNTHETIC_MODE=fixture-only node deploy/fncp/wordpress-identity/expanded-proof.mjs --synthetic-seamless-expanded
```

Do not run both just to view the form: each actual invocation may add one invented
vote and two terminal identities. A rendering-only model is available via
`node deploy/fncp/local-browser/registration-ui-preview.mjs --ui-model`, loopback8114;
it is labelled as a model and has no authentication/WordPress/Pol.is operations.

The command prepares a fresh WordPress 7.1 instance from the checksum-verified
local archive and a new, cached digest-pinned MySQL container/volume. It never
downloads an image, sends mail, installs a CA or contacts an external issuer.
It allocates at most two new synthetic Pol.is identities and dispatches at most
one invented vote per invocation. It revokes only those identities, closes its
authority and services, and retains its new private stores/volume. Failures are
redacted and retain evidence; do not replay blindly after an uncertain vote.

Aggregate reports are written under `deploy/fncp/evidence/wordpress-identity-*`.
Temporary credentials and mappings are private and must not be printed, sent,
committed or copied into this guide. The separate shared Pol.is/original synthetic
database stacks and VM need explicit shutdown after independent final readback.

## Next implementation work

The participant registration handoff and closed data-only expanded restore are
implemented and tested locally. Next prove real issuer/operator authentication,
full accessibility and post-restore application behaviour in a separately approved
disposable environment. Production recovery still needs offsite custody, files/media,
real identity configuration and a separately authorised new activation.
Production identity/mail/hosting, costs, image integration, release scans and owner
deployment/launch decisions remain separate. No external action follows from a
passing local proof.
