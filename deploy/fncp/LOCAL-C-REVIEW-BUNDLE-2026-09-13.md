# C — review bundle, startup admission and browser crash assurance

> Portability note — 7 October 2026: workstation paths were removed, and artifacts outside this source snapshot are labelled retained local evidence. Dated results below remain historical; this edit adds no runtime or release claim.

13 September 2026 · Local source and invented test state only · Production HOLD.

## Outcome

Completed provider-independent improvements without selecting a hosting vendor,
starting Docker, changing any retained application store or sending anything.
The complete local Node suite is now **864/864 PASS on each of Node 24.21.0 and
26.8.2**. These are the same tests repeated, not 1,728 unique checks. The existing
three PHP suites also passed **59 checks**. No remote CI, image rebuild or fresh
image scan was run.

## What changed

### 1. Startup checks now run before copying keys or starting services

The Colima rebuild helper previously started services and only then inspected
their source-revision and dedicated-server labels. It now validates all five
assertions first. Inspection failure is rejected even if the command prints a
correct-looking label before failing. A rejected candidate receives neither
certificate/key copies nor a start command.

The **14 mocked-command tests** use new temporary source-shaped fixtures and
intercept every Docker/Git command. They never run the real helper against a VM.
These labels identify asserted baseline provenance, not the complete dirty source
or a cryptographic release attestation. The helper still rebuilds and recreates
containers; **it is not the routine resume procedure** for retained evidence.

The README now separates rebuild from resume and replaces the obsolete routine
volume/configuration purge instructions with explicitly scoped stop-and-preserve
commands. No stored data, key, certificate, archive or material evidence was deleted.

### 2. WordPress source-review ZIP saved locally

- Review ZIP (retained local evidence, `fncp-wordpress-local-review.zip`; outside this repository)
- Inspectable manifest (retained local evidence, `manifest.json`; outside this repository)
- [Generation and inspection guide](wordpress-identity/REVIEW-BUNDLE.md)

The deterministic archive contains exactly **five unchanged PHP source files
plus an embedded review manifest**. It preserves the sibling journal/contract
dependency layout and all existing synthetic-only guards. Its source digest is
pinned to the reviewed closure; source drift cannot quietly produce the same
reviewed artifact. It writes only to an explicitly supplied new directory and
refuses overwrites, hidden state paths and plugin-install paths.

Archive: **50,986 bytes**, SHA-256:
`368a1f3569d459a08cbbf14dac8149e2523c8a07e8289cbeee6ba14ce86ef40a`.

The **90 archive tests** cover determinism, metadata/content tampering, input
hooks, missing dependencies, unsafe paths, existing targets and independent ZIP
parsing. The final saved ZIP passed the separate system `unzip -t` reader. Its
five source members were streamed through `unzip -p` and independently compared
byte-for-byte and by SHA-256 with the fixed current sources; no owner-folder
extraction occurred.

An additional **20 tests** extract the independently validated source map into
fresh test-only temporary directories and load it through actual PHP CLI with
inert WordPress stubs. They verify dependency loading, disabled defaults,
nonlocal/invalid configuration denial, request boundaries and administrator
denial without network/storage calls. Those 20 tests are **included in 864**,
not extra to that count. Temporary test fixtures are removed after the test;
the saved review archive and original stores are preserved.

This is **not a WordPress installer or production plugin release**. No genuine
WordPress installation, database, login, mail transport or participant was used.
Digest equality is not publisher signing, a vulnerability scan or GO authority.
Do not upload this archive to live WordPress or remove its synthetic guards.

### 3. Previously valid browser cookies fail after a process crash

The [new BFF restart proof](local-browser/RESTART-PROOF.md) adds **four tests**:
one denies direct execution of the helper without private IPC, and three obtain
genuinely live visitor/authenticated/participant cookies and CSRF values through
the unchanged browser-facing HTTP service.

Each phase kills the exact first child with SIGKILL, starts a different PID on
the identical loopback origin/port, and replays the previous values. It verifies
**12 denials per phase**, a fresh visitor instead of inherited authority, zero
replacement backend calls and independently closed listeners. No modeled vote
was submitted and no invented credentials were logged or saved.

This is actual HTTP/process behavior with an **in-memory fixture-authentication
and backend model**. It does not prove real OIDC, actual browser rendering,
underlying access-token revocation or full WordPress/Pol.is application recovery.
It does not replay credentials from the original retained stores. It is separate
from the earlier actual four-store recovery and restored access-service proof.

## Verification and closed state

| Scope | Result |
| --- | --- |
| Combined Node suite, macOS ARM64 / Node 24.21.0 | 864 PASS; no failures/skips/cancellations |
| Same suite / Node 26.8.2 | 864 PASS; same coverage repeated |
| Existing PHP suites / PHP 8.5.10 | 59 PASS: 23 identity + 23 journal + 13 adapter |
| New tests within 864 | 90 ZIP + 20 packaged-PHP + 14 startup + 4 crash = 128 |
| Independent saved-archive inspection | Six entries pass CRC; five source files byte-identical |
| Shell/PHP syntax and Git whitespace check | PASS |

At **2026-09-13T16:17:56.685+10:00 (Australia/Sydney)** all 12 fixed test ports
refused connections. The dedicated VM remained **Stopped** throughout this
increment; each test-owned ephemeral listener was closed. The earlier
[actual provider/recovery result](LOCAL-C-COLD-RESTART-REVIEW-2026-09-13.md)
was not rerun. Its 0 allowlist / 15 statements / 34 invented votes is historical
readback, not a fresh database count. No new vote or registration was created
in any retained store.

CI source includes the startup regression and syntax check; existing browser
and WordPress wildcards include the new tests. The workflow has not been submitted
or executed remotely. Aggregate evidence (retained local evidence, `evidence/review-bundle-continuation-2026-09-13.json`; not included in this source snapshot)
records this scope. The earlier 15:56 source/image capture predates these changes.

## Next steps

1. Review the ZIP manifest and local diff; use the owner guide (retained local evidence, `C-SELF-HOSTING-GUIDE.md`; outside this repository) for repeatable commands.
2. Dean / Barayamal chooses the production target and operator using the existing
   C1/C2/C3 decision pack (retained local evidence, `C-PRODUCTION-DECISIONS.md`; outside this repository).
   No variant, budget or account was selected by this continuation.
3. Prepare that target's genuine login, operator MFA, TLS, secret custody, durable
   revocation and complete runtime packaging locally. Price the exact configuration.
4. Review full application recovery and release-bound CI/images before separately
   approving repository submission, deployment or any real participant test.

No external correspondence, public copy change, commit, push, PR, cloud resource,
spending, real identity processing or historical retention action occurred.
Public surfaces were neither changed nor freshly verified. PR #27 is not GO
authority; the October dates remain provisional.

## Official guidance used

- [Pol.is source/self-hosting README](https://github.com/compdemocracy/polis/blob/stable/README.md): source and Docker setup, with production configuration treated separately.
- [Pol.is configuration](https://github.com/compdemocracy/polis/blob/stable/docs/configuration.md) and [SSL guidance](https://github.com/compdemocracy/polis/blob/stable/docs/ssl.md): environment/domain and production TLS requirements, not certification of this custom integration.
- [Docker Compose image inspection](https://docs.docker.com/reference/cli/docker/compose/images/): inspect images associated with created containers before starting them.

Upstream guidance was reviewed, not blindly executed or merged into this dirty
candidate. None of the upstream setup commands supplies Barayamal's missing
production eligibility, invitation or operating approval.
