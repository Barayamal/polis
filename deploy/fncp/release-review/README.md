# Offline Option C release review

**KEEP_CLOSED. Source inventory is not deployment or activation authority.**

This closes an evidence gap: five Pol.is application images are not the entire
Community Pulse system. The fixed inventory names 20 required components and
hashes 56 explicit, observed source entry files, including seven dependency inputs. It
keeps the five image artifacts (server, math, alpha, proxy and migration) distinct
from PostgreSQL, WordPress/PHP/plugins/MySQL, the host-side BFF, access/identity/
activation ledgers, event receiver, recovery code and unresolved external services.
Each component carries a concrete current production gap, not a generic pass box.

The later [pinned host-side proof closure](PROOF-CLOSURE.md) separately checks
27 manually reviewed first-party files and their import/asset relationships.
It distinguishes the two legacy launchers, strict in-process proof factory and
dedicated programmatic strict local composition, plus a separate pure HTTPS
redirect coordinator root. The composition has no runtime test
driver or signer imports; its injected identity/provider adapters are not
independently attested by this graph. The explicitly pinned coordinator is not
a test issuer or proof of real browser/provider readiness. It is not a full release closure, Docker
package, executable production entrypoint or GO authority.

## Run without starting anything

From the clone root with the existing Node runtime:

```sh
node deploy/fncp/release-review/inventory.mjs
node deploy/fncp/release-review/proof-closure.mjs
node --test deploy/fncp/release-review/*.test.mjs
```

The command prints structured JSON only; it writes no report. Exit 0 means the
bounded inventory completed, **not GO**. Errors are fixed, content-free JSON and
exit 1. Both paths always say `KEEP_CLOSED`, `deployable: false` and
`activationAuthority: false`. No production variant is selected and no deployment
configuration, credentials, activation envelope or sender is generated.

Original inventory verification on 13 September 2026: **57/57 tests passed**, including one
actual offline inventory of this clone. The remaining tests use newly generated
source-only temporary fixtures; they never touch application data or runtimes.

No packages are installed, scripts run, runtime services imported or started,
Docker/Git/database/cloud commands invoked, network contacted, historical evidence
read, or current image scan claimed. Do not pipe this inventory into activation.

## Source and dependency scope

- `manifest.mjs` is the exact source allowlist. Missing, duplicated or changed
  critical entries are rejected; callers cannot substitute a different manifest.
- The three npm package/lock pairs are server, alpha and the separately packaged
  identity foundation. `math/deps.edn` is also hashed, but it is a declaration,
  **not a complete transitive runtime lock**. PHP, WordPress core, MySQL and
  PostgreSQL are outside these npm lockfiles.
- Only listed entry files are hashed. This is **not** all imported application
  source, all migration SQL, installed modules, built images, WordPress core
  archive bytes, an SBOM, or a complete deployable source closure.
- Private local runtime (including the WordPress archive), environment files,
  keys/certificates, credentials, databases and evidence directories are not read.
  No whole-repository scan is performed. Only source paths and their byte counts
  and hashes are emitted, never contents or absolute paths.
- Root aliases, symlinks, hard links, nonregular or oversized sources, lexical
  traversal and ordinary concurrent source edits are rejected. Repeated bounded
  reads detect ordinary drift; this is not an atomic filesystem snapshot or a
  hardened sandbox against a malicious concurrent filesystem writer.

The exported `inventoryRepository(root)` exists for unit tests and local callers;
the CLI permits **no arguments** and derives its own repository root. The optional
in-process `artifactClaims` syntax check accepts only either no claims or exactly
the five distinct artifact IDs with digest-form references. Mutable tags, bare
local image IDs and incomplete/duplicate sets are rejected. Even well-formed
assertions are **not independently verified** and cannot change classification.
The CLI accepts no assertion file and reads no image credentials or configuration.

## How this helps the next step

1. Run this offline inventory against the source proposed for review.
2. Read all concrete component gaps. Dean/Barayamal still chooses hosting and
   accountable operation; do not silently default to C1, C2 or C3.
3. After that decision, prepare the production-specific adapters and packaging
   locally, with complete source/dependency closure and real HTTPS/identity tests.
4. Obtain separate approval before repository submission, external test messages,
   cloud provisioning, spending, closed deployment or participant testing.
5. Review fresh release-bound CI, images, scans, recovery and operator assurance.
   Neither this command, historical five-image results nor PR #27 can approve GO.

The [official Pol.is README](https://github.com/compdemocracy/polis/blob/stable/README.md)
provides upstream source and Docker-based setup guidance. Its Dockerfiles are
useful installation references, not certification of these Barayamal-specific
registration, access or activation additions. The exact local files observed here
take precedence for this inventory; fetching or merging upstream is outside it.
