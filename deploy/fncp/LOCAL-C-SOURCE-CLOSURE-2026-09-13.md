# C — receiver, graceful lifecycle and source-package review

> Portability note — 7 October 2026: workstation paths were removed, and artifacts outside this source snapshot are labelled retained local evidence. Dated results below remain historical; this edit adds no runtime or release claim.

Recorded: 2026-09-13T16:59:44.241+10:00 (Australia/Sydney).

**KEEP CLOSED.** The local work-in-progress passes **1,012/1,012 tests on each of Node 24.21.0 and 26.8.2**, plus **59 separate PHP checks**. These are the same Node checks repeated across two versions, not 2,024 unique checks. This increment adds 94 tests. No production service, hosting choice, deployment, public change, real identity or participant testing is approved or claimed.

## Completed in this increment

1. **Signed WordPress receiver hardening — 25 new tests.** A fixed 32-slot limit is enforced before body collection. Signature freshness is rechecked immediately before ingest; invalid clocks and disconnected/incomplete requests fail closed. If ingest may have applied but its acknowledgement is lost, the response requires retaining and retrying the same event, not creating a replacement. The admission slot remains occupied until ingest settles. See [receiver proof](./local-access/RECEIVER-PROOF.md).
2. **Graceful shutdown — eight tests, plus 12 startup-race tests.** Access, browser and receiver services latch shutdown, stop new admission, drain already admitted work and reject restart of the same instance. Closing during startup now settles the pending listen promise instead of leaving it hanging. Repeated close is idempotent; occupied-port and invalid-port errors do not poison a future valid start. See [lifecycle proof](./local-access/LIFECYCLE-PROOF.md).
3. **Pinned first-party source review — 49 tests.** A manually reviewed graph pins 24 source/dependency-input files: 18 JavaScript modules, four browser assets and two identity dependency inputs. It checks 23 import edges and four asset edges without executing the source or reading private runtime state. Unexpected changes, missing files and unsafe filesystem aliases fail closed. Pins are not automatically refreshed. See [proof source closure](./release-review/PROOF-CLOSURE.md).
4. **CI source and operating notes updated.** The local workflow definition runs the pinned source check, and the existing test globs include the new tests. No remote CI or PR was submitted.

## Important packaging finding

The standalone `local-access/start.mjs` and `local-browser/start.mjs` launchers are **legacy fixture-mode launchers**. They do not wire the strict signed-identity and deployment-bound activation path.

The strict path is composed in `integrated-journey/proof-harness.mjs`, an **in-process synthetic test factory**, not a deployable production service. It shares opaque principal objects and instance-bound verification authority. Serializing those objects or splitting components into Docker services would not preserve that authority. Do not package the legacy launchers as a strict release, remove local-only guards, or imply that the test harness is a production entrypoint.

An approved production design must either preserve a reviewed in-process composition or introduce and verify a separate cross-process authentication protocol. Real callback routing, operator MFA, secrets, durable state, image contents, operational controls and the selected hosting target still need implementation and assurance.

## Evidence and repeatable checks

- Current aggregate evidence (retained local evidence, `evidence/source-closure-continuation-2026-09-13.json`; not included in this source snapshot).
- Saved 24-file graph and hashes (retained local evidence, `evidence/pinned-proof-source-closure-2026-09-13.json`; not included in this source snapshot).
- Source closure SHA-256: `fa7b0d3fc70d583dfc6d037c11e4e4fe50cdec1c34c0a0b48944b30823820255`.
- The separate general inventory still has **56 selected entries**. It is a broader inventory, not the same scope as the 24-file pinned launcher/proof graph. Neither is a complete release, installed-dependency closure, SBOM, publisher signature or security certification.

From the dedicated clone, the read-only source check is:

```sh
node deploy/fncp/release-review/proof-closure.mjs
```

The full Node test suite includes the existing `deploy/fncp/*.test.mjs` and component-directory test globs documented in the owner guide. All 1,012 tests passed without failures, cancellation or skips on both versions. The separate PHP checks comprise 23 identity, 23 journal and 13 WordPress adapter checks; these use pure PHP/stubs, not a live WordPress installation.

At the recorded closure check the dedicated `fncp-c-20260913` VM was **Stopped**. All 12 fixed test ports refused connections: 3000, 5500, 5501, 8088, 8099, 8100, 8101, 8102, 8103, 33079, 33080 and 8114. Test-owned ephemeral listeners were closed.

No VM/container was started. Retained application stores, original keys/configuration, archives and prior evidence were not read or changed. Only fresh test-owned fixtures were cleaned. No image build/scan, external send, provider action, repository submission, remote CI, retention action, spending or public change occurred. Public surfaces were untouched, **not freshly inspected**. Earlier actual Pol.is, 26-stage journey, four-store restore and cold-access evidence remain dated earlier evidence; none was rerun in this increment.

## Next steps in order

1. Review the packaging finding and the updated local owner guide (retained local evidence, `C-SELF-HOSTING-GUIDE.md`; outside this repository). Keep the public round and all launch surfaces closed.
2. Design and test a real strict service composition without substituting the fixture launchers or weakening the authority boundary. Local source design, test cases and review can continue without publishing or provisioning.
3. Use the existing production decision pack (retained local evidence, `C-PRODUCTION-DECISIONS.md`; outside this repository) for Dean's hosting/login choice. C1/C2/C3 remains unselected and NOT COSTED; no cloud account, paid resource or external identity application has been created.
4. After an exact target and cost decision, prepare the whole release candidate: locked source/images and dependencies, real callback/MFA/secret handling, storage and backup/restore controls, deployment-bound activation and synthetic assurance.
5. Request separate exact approval for external submission, provisioning, publication, participant testing and launch. Local test success and PR #27 are not GO authority. Retention remains a separate fresh-confirmation workflow.

## Official technical basis

- [Pol.is stable source and self-hosting README](https://github.com/compdemocracy/polis/blob/stable/README.md).
- [Pol.is configuration guidance](https://github.com/compdemocracy/polis/blob/stable/docs/configuration.md).
- [Pol.is TLS guidance](https://github.com/compdemocracy/polis/blob/stable/docs/ssl.md).
- [Node HTTP server close semantics](https://nodejs.org/api/http.html#serverclosecallback).

These sources inform the Docker/configuration/TLS and server-lifecycle work. They do not certify Barayamal's custom approval, identity or activation integration. No upstream fetch/merge or global certificate-trust change was performed in this increment.
