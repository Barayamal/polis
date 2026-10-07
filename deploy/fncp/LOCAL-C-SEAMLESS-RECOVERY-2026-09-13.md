# C — seamless local registration and expanded recovery

13 September 2026 · Local invented-data engineering · Production/launch HOLD.

## Scope and upstream basis

This continues the Barayamal-specific integration around the official [Pol.is
source and Docker guide](https://github.com/compdemocracy/polis/blob/stable/README.md).
It does not make the upstream quick start a production deployment, nor does it
claim that Pol.is supplies Barayamal eligibility verification. WordPress
[nonces](https://developer.wordpress.org/apis/security/nonces/) are not a substitute
for authentication or one-use replay enforcement; the local adapter retains
capability checks and separate atomic guest/receipt consumption.

No external message, public-site change, cloud provisioning, purchase, commit,
push, PR or participant test is authorised or performed by this increment.
Live WordPress page 12064/form 12069, historical retention and the prohibited
repository are outside this work. Public surfaces were not accessed or changed.

## Implemented

- Participant form: three independent unchecked declarations and an explicit
  notice version. Self-attestation is not verified age, mailbox or heritage.
- Private BFF handoff: WordPress guest cookie, CSRF, signed challenge and short-lived
  receipt remain server-side. Browser input cannot choose a fixture, XID or account.
- Clear submitted/not-approved state, separate invitation reveal, bounded single
  submission and an uncertain-outcome latch. No automatic resubmission/adoption.
- Session-expiry clearing of old invitation/callback fields; keyboard focus returns
  to a visible status after logout. The initial invitation fragment is cleared from
  the address bar and never automatically redeemed.
- Terminal-only private test shutdown closes guest and invented operator sessions,
  preserving registration/replay records and acknowledged revocation history.
- Four-store recovery runner: fresh WordPress/MySQL, strict access SQLite, activation
  SQLite and disposable Pol.is/PostgreSQL; encrypted key-continuity component;
  isolated new targets and prior-activation rejection. Actual result below.
- Fixed public evidence projection prevents accidental persistence of a private
  recovery context or arbitrary callback diagnostics. New runtime/backup/key files
  are ignored by Git and excluded from source manifests.

## Verification record

**Completed: 611/611 combined Node tests, 59 PHP checks and 26 actual local journey
stages PASS.** The Node total includes 116 expanded-recovery tests and 44 browser
protocol/test-DOM tests; these are included, not additional counts. PHP is 23 new
registration/quiescence + 23 prior journal + 13 prior adapter checks.

**Actual expanded restore PASS — 2026-09-13T15:27:00.308+10:00 (Australia/Sydney).**
[Final aggregate evidence](evidence/seamless-registration-2026-09-13T05-27-00-308Z.json)
records four restored stores, five independently authenticated encrypted components,
unchanged source counts/hashes and two stopped, retained isolated restore containers.
The actual activation implementation rejected the prior signed grant after assigning
a fresh boot/recovery epoch; no restored service was activated or made reachable.

Final provider aggregate: **0 whitelist rows / 15 fixed seeds / 33 invented vote rows**.
The final fresh WordPress instance contains 2 registrations, 2 acknowledged terminal
revocations, 0 pending events, 0 guest sessions and 0 invented operator sessions.
Across this increment's two separate attempts, exactly 2 verified invented votes and
4 terminal provider records were added. The final successful attempt added one of
those votes. Original access bytes and original WP table counts/journal were unchanged.
CI includes the new tests locally; no remote CI, image rebuild or new image scan is claimed.

The first actual seamless attempt passed 26 WordPress-to-Pol.is stages, accepted
exactly one invented vote, terminally revoked its two identities and left the
provider whitelist at 0. Recovery stopped before copying/restoring because a
preflight check expected signing settings in `credentials.json` instead of the
generated private WordPress configuration. Its failed aggregate-only evidence is
[preserved](evidence/seamless-registration-2026-09-13T05-22-47-966Z.json).
Original access bytes and original synthetic WordPress table counts/journal were
unchanged; the fresh run retained 2 registrations, 2 terminal ACKs and 0 pending events.
The verified synthetic vote count became 32. This was not an uncertain vote retry.

The local browser assets were also checked in a clearly labelled **UI MODEL**,
not a genuine authenticated session. The in-app browser showed three initially
unchecked declarations, submitted-not-approved feedback and focus on the result
heading. At 390px width, DOM document width was 390px and no password field was
visible. No login/callback/invitation credential was entered or admin UI operated.
The temporary model tab and server were closed; viewport override was reset.
This is visual/UI evidence, not real identity/operator login, comprehensive
accessibility certification or rendered end-to-end WordPress/Pol.is evidence.

## Final closed state

At **2026-09-13T15:38:04.916+10:00 (Australia/Sydney)**, the dedicated Colima VM
was verified **Stopped** and all 12 local test ports refused connections. Zero
running containers were observed before stopping the VM. The model browser tab
and temporary server were closed. [Shutdown evidence](evidence/seamless-recovery-shutdown-2026-09-13T05-38-04-916Z.json)
records the exact scope; no public-surface freshness claim is made.

The [closed source/image checkpoint](evidence/local-wip-2026-09-13T05-36-26-947Z/runtime.json)
captures the tested local code and capture-helper update before final documentation
and shutdown links. Every captured container was stopped. Configured published ports
are not active listeners. This is uncommitted local provenance, not a release
attestation or a scan of the new host-side services.

## Reproduce safely

Use the prepared clone, not the live WordPress site or a production database.
Run the ordinary tests before an actual proof; tests that bind port 8101 must not run
alongside its actual receiver. The actual command is explicitly synthetic:

```sh
FNCP_LOCAL_SYNTHETIC_MODE=fixture-only node deploy/fncp/wordpress-identity/expanded-proof.mjs --synthetic-seamless-expanded
```

Prerequisites and detailed restore exclusions are in
[expanded recovery](expanded-recovery/README.md) and
[the WordPress adapter guide](wordpress-identity/README.md).
The existing isolated Colima/Pol.is stack and original synthetic WP database-only
service must already be running. The original WordPress PHP server stays off.
Each invocation creates a new WP/strict test instance and can add one invented
vote and two terminal provider records. Never blindly rerun an uncertain result.
All original stores and evidence are retained. New restored database targets are
tmpfs-backed; stopping them discards only those disposable restored DB contents,
while encrypted archives and protected SQLite work remain for evidence.

For visual-only inspection, use `node deploy/fncp/local-browser/registration-ui-preview.mjs --ui-model`
and `http://127.0.0.1:8114/`. It has no real identity, WordPress, Pol.is, mailbox or
registration store. Stop it after review; it is not a participant-access URL.

## What remains before production

1. Choose the infrastructure/identity target and named operator from the local
   owner decision pack; no provider/account/spending is yet selected or approved.
2. Adapt and test the real issuer, TLS callback, mailbox/recovery and operator MFA
   in a separately authorised isolated environment. Do not remove synthetic guards
   to make these test services public.
3. Package the new host-side services into a reviewed release, select upstream
   revision, verify migrations and distributed failure behaviour, and rerun exact
   source/dependency/image/negative-access checks. No fresh image scan is claimed.
4. Prove complete production recovery, including key custody, offsite copies,
   WordPress files/media, real identity configuration and a separately approved
   recovery/activation decision. A closed data-only local restore is narrower.
5. Approve exact repository submission, infrastructure/deployment and any real
   message/participant test separately. Keep all public surfaces closed until then.

The intended flow is authenticated account → three registration declarations →
WordPress record → separate Barayamal approval → account-bound invitation → fixed
Pol.is voting → immediate denial/reconciliation on revocation. Email delivery is
not implemented/approved by this local proof. October 12–23 remains provisional;
PR #27 is not GO authority.
