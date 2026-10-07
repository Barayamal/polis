# C — closed restart and complete-system review scope

> Portability note — 7 October 2026: workstation paths were removed, and artifacts outside this source snapshot are labelled retained local evidence. Dated results below remain historical; this edit adds no runtime or release claim.

13 September 2026 · Local synthetic engineering · Production and launch HOLD.

## Completed this increment

The actual recovered access service now starts from newly restored SQLite files,
using the current controlled-access and activation implementations. It remains
closed, rejects the genuine old signed activation, checks stale/terminal journal
retries without granting access, and closes its temporary loopback listener.
The negative probe never calls a provider, creates a voter session or votes.

Two offline review tools make the remaining release work inspectable:

- [System inventory](release-review/README.md): 20 components, 55 explicitly listed
  source entries, seven dependency inputs and three npm lockfiles. It separates
  the five Pol.is image artifacts from the newer host-side code, databases,
  WordPress, real identity/mail and operations requirements. It is not a complete
  source closure, SBOM, image measurement or security scan.
- [WordPress dependency check](wordpress-identity/package-check.mjs): verifies the
  five PHP files and five literal dependency edges, including both sibling
  `wordpress-local/journal.php` and `wordpress-local/contract.php`. The in-memory
  source map preserves their relative layout. It does not create an installable
  archive, execute PHP, remove synthetic guards or install a plugin.

Both tools return KEEP_CLOSED. Exit success means the stated offline check
completed, never approval to deploy or activate. Their captured results (retained local evidence, `evidence/c-offline-review-2026-09-13.json`; not included in this source snapshot)
contain source paths, hashes and counts, not private configuration or application data.

The local CI workflow now includes all three existing PHP suites, not only the
new identity suite. Inventory, dependency-closure and cold-restart tests are also
included. No workflow was submitted or run remotely. Earlier documentation that
described completed WordPress/recovery work as outstanding was corrected or labelled
historical. The old RDS scan-scope assumption is not a selected hosting architecture.

## Verification and exact scope

| Check | Observed result |
| --- | --- |
| Combined Node suite, macOS ARM64 Node 24.21.0 | 736/736 PASS; no failures, skipped or cancelled tests |
| Same suite, macOS ARM64 Node 26.8.2 | 736/736 PASS; the same coverage, not another 736 unique tests |
| PHP 8.5.10 suites | 59 PASS: 23 identity + 23 journal + 13 adapter |
| Expanded-recovery subset | 124 PASS, included in 736 |
| Offline inventory subset | 57 PASS, included in 736 |
| WordPress source-closure subset | 49 PASS, included in 736 |
| New actual WordPress-to-Pol.is journey | 26 stages PASS, one verified invented vote |
| Actual four-store restore and cold access restart | PASS, 10 negative HTTP checks, zero provider calls from the restarted service |

The actual run (retained local evidence, `evidence/seamless-registration-2026-09-13T05-51-16-108Z.json`; not included in this source snapshot)
completed at **2026-09-13T15:51:16.108+10:00 (Australia/Sydney)**. This increment
ran one new journey, not a retry of an uncertain vote. Final dedicated provider
aggregate: **0 whitelist entries / 15 fixed statements / 34 invented vote rows**,
a delta of one. Both newly allocated identities were terminally revoked. The
fresh WordPress instance retained two registrations, two acknowledged terminal
subjects, no pending events and no guest/operator sessions after quiescence.

All four stores restored into new targets, five encrypted components authenticated,
and source counts/hashes were independently rechecked. Original access bytes and
the original legacy WordPress all-table counts/journal were unchanged. The latter
is not a claim of byte-identical MySQL storage or complete legacy database equality.
New restore containers were stopped; their tmpfs database contents are ephemeral.
Encrypted archives and protected, unencrypted SQLite work remain local.

The cold probe starts only the restored access/activation implementation. Its
identity verifier deliberately accepts no principal; this is not a real issuer
or signed-in browser test. It verifies absent sessions and consumed invitation
records and rejects invented invalid bearer/invitation canaries. **Original raw
historically valid credentials were not replayed.** The old signed activation
was genuine and was rejected. Full WordPress/BFF/provider application restart,
successful reactivation, actual HTTPS, mail and production disaster recovery remain
separate requirements. The enclosing pre-restore journey tests actual provider
interaction; the cold probe intentionally does not.

Node 24.21.0 was downloaded from the official distribution into a new temporary
directory, with SHA-256 matched to the official HTTPS checksum list before execution:
`bed7eea5325e1108f32ce5228ddd6a5f0f08a499ee42aa7442aea583702f6057`.
This was archive checksum verification, not independent signature verification.
The default Node installation, shell profile and system trust were not changed.
The full suite and actual proof entrypoint ran under that runtime; this does not
claim an Ubuntu CI run or a rebuild of existing Node-based Pol.is images.

## Closed handover

At **2026-09-13T16:00:31.674+10:00 (Australia/Sydney)**, the dedicated Colima
profile was Stopped and all 12 fixed local test ports refused connections.
Zero running containers were observed before stopping the VM. The cold probe's
separate ephemeral listener was independently closed during its proof.
Shutdown evidence (retained local evidence, `evidence/cold-restart-shutdown-2026-09-13T06-00-31-674Z.json`; not included in this source snapshot)
records these aggregate checks. No original store or retained archive was deleted.

The closed source/image capture (retained local evidence, `evidence/local-wip-2026-09-13T05-56-06-653Z/runtime.json`; not included in this source snapshot)
records six stopped stack containers and their image IDs after code verification.
It precedes final documentation/shutdown links, is uncommitted WIP, and is not a
release attestation or a new vulnerability scan. Configured ports in that capture
are not evidence of running listeners.

## Repeat the offline checks

From this prepared clone:

```sh
node deploy/fncp/release-review/inventory.mjs
node deploy/fncp/wordpress-identity/package-check.mjs --check
node --test deploy/fncp/release-review/*.test.mjs deploy/fncp/wordpress-identity/package-check.test.mjs
```

These commands do not start application services or contact external systems.
Do not pipe their output into an activation mechanism. Actual restore execution
has different prerequisites and creates a new invented journey; follow the
[expanded recovery procedure](expanded-recovery/README.md), not an automatic rerun.

## Next steps and approval boundary

1. Review the fixed inventory and WordPress closure result alongside the exact
   local diff. Local tests do not make the fixture-only composition deployable.
2. Dean / Barayamal selects C1, C2 or C3 and the accountable operator using the
   owner decision pack (retained local evidence, `C-PRODUCTION-DECISIONS.md`; outside this repository).
   No hosting variant, identity provider, budget or real account was selected here.
3. Prepare the selected production adapters and complete runtime packaging locally:
   genuine issuer/TLS/cookies, operator MFA, secret custody, durable/distributed
   revocation and whole-round provider closure. Never expose this synthetic harness.
4. Freeze the exact source/configuration and run complete release-bound CI,
   dependency/image checks and full application recovery tests. No new image build,
   scan or production packaging is claimed by this increment.
5. Obtain separate exact approvals before submitting a PR, sending any message,
   provisioning, spending, deploying or testing with real participants. Keep all
   public surfaces closed; PR #27 is not GO authority and October dates remain provisional.

Historical registration retention and live page 12064/form 12069 were not accessed.
Public surfaces were not changed or freshly verified. No external correspondence,
publication, commit, push, PR, cloud resource, participant test or spending occurred.

## Primary technical guidance

- [Official Pol.is self-hosting/source guide](https://github.com/compdemocracy/polis/blob/stable/README.md)
  and [configuration reference](https://github.com/compdemocracy/polis/blob/stable/docs/configuration.md)
  provide the engine and deployment starting point, not Barayamal's eligibility or invitation controls.
- [Pol.is SSL guidance](https://github.com/compdemocracy/polis/blob/stable/docs/ssl.md)
  keeps development certificates separate from production HTTPS requirements.
- [Node release guidance](https://nodejs.org/en/about/previous-releases)
  identifies Node 24 as LTS and recommends supported LTS lines for production.
  [Official checksum list](https://nodejs.org/dist/v24.21.0/SHASUMS256.txt) identifies the checked archive.

The current Pol.is sources were inspected, not merged into this dirty local candidate.
