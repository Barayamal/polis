# V3 closed candidate source and image collection

The V3 candidate retains V2's explicit ninth `edge` role and adds a tenth,
credential-free opaque `operator` gateway role. It does not change the
frozen September 14 package or turn a build/scan receipt into deployment approval.
The old `verify-package.mjs` intentionally continues to verify only that older
eight-image delivery and its separately recorded trust anchor.

## Source and build binding

`candidate-source-lock.mjs` exports:

- `await createCandidateSourceLock(canonicalRepositoryRoot)` returns a frozen
  `{version:1,sourceRevision,sourceFingerprint,files}` value without writing files.
- `await validateCandidateSourceLock(root, suppliedLock)` rereads the checkout and
  returns the independently observed matching lock, or rejects.
- `validateCandidateReleaseLock(sourceLock, imageLock, composeVersion)` binds
  source revision/fingerprint to the exact V1 eight-role, V2 nine-role or V3
  ten-role schema.

The fingerprint hashes every tracked file and nonignored added file, including
uncommitted changes and new tooling. It includes executable bits. Only the two
explicit generated filenames `deploy/fncp/selfhost/source-lock.json` and
`deploy/fncp/release-readiness/source-lock.json` are omitted. Keep new evidence and
private material outside the repository. Other lock-like filenames are included.
Ignored files are not source evidence and must not be allowed into build contexts.

The reader rejects ambiguous paths, case aliases, links, missing files and private
material paths; its two complete passes check membership, bytes, file identity,
executable bits and HEAD. The only PEM exceptions are the two existing public
certificate fixtures, whose bytes must parse as certificates without private keys.
Limits are 10,000 source files, 32 MiB per file and 256 MiB total. Use a quiescent
trusted checkout: this is ordinary drift detection, not a hardened filesystem
sandbox against an adversarial concurrent writer. A hash is not a signature.

## Full V3 build and one-feed scan

Run only after everyone editing this source has finished. The socket must identify
an explicitly supplied local `fncp-*` engine; the default/shared engine is refused.
The destination must be new, canonical, absolute and outside the source checkout.

```sh
node deploy/fncp/release-readiness/collect-candidate-release.mjs \
  /absolute/canonical/candidate/repository \
  unix:///absolute/fncp-dedicated-engine/docker.sock \
  /absolute/new/evidence-directory
```

For iterative native rehearsals, build first and scan only after the same source
and image lock have passed the native journey. Each phase needs a new directory:

```sh
node deploy/fncp/release-readiness/collect-candidate-release.mjs build \
  /absolute/canonical/candidate/repository \
  unix:///absolute/fncp-dedicated-engine/docker.sock \
  /absolute/new/build-evidence

node deploy/fncp/release-readiness/collect-candidate-release.mjs scan \
  /absolute/canonical/candidate/repository \
  unix:///absolute/fncp-dedicated-engine/docker.sock \
  /absolute/new/scan-evidence \
  /absolute/new/build-evidence/source-lock.json \
  /absolute/new/build-evidence/image-lock.json
```

The split APIs are `buildCandidateRelease({root,socket,destination})` and
`scanCandidateRelease({root,socket,destination,sourceLock,imageLock})`. Build-only
returns `BUILT_LOCAL_ONLY` with `scanned:false`; it never pulls scanners or collects
advisory results. Scan-only returns `SCANNED_EXISTING_LOCAL_ONLY`; it revalidates the
current checkout against the supplied source lock before accessing the engine,
then checks all ten immutable images and copied source bytes again. It downloads
one fresh advisory feed for that new ten-image scan. Source changes require a new
build; partial runs are never resumed, adopted or overwritten. Reusing a completed
immutable image lock is explicit and is not a release approval.

The exported `collectCandidateRelease({root,socket,destination})` uses the combined
workflow. It builds all ten roles from the fixed `BUILD_RECIPES`, including the
patched MariaDB candidate Dockerfile. Every image receives the exact source
revision, fingerprint and V3 profile labels. Each build checks source before and
after; the final lock accepts only distinct immutable ARM64 Linux image IDs.
Its isolated Docker configuration explicitly discovers installed CLI plugin
directories and checks Buildx before starting; user credentials and context are
not copied. The exported `dockerPluginDirectories(['buildx','compose'])` supports
the installer's separate isolated configuration as well.

Selected copied files are read back from isolated, read-only, networkless image
containers and compared to the source manifest. This includes the full explicit
edge/runtime module closure, PostgreSQL initializer and migrations, participant
modules/assets, copied WordPress code and math sources. Compiled API JavaScript
is not falsely equated with TypeScript input. MariaDB contains no copied project
source; its reviewed recipe and build provenance are recorded separately.

Pinned Syft and Grype container images come from `image-security.lock.json`. The
collector downloads one fresh Grype feed to an owned temporary volume, then scans
all ten exact images offline against that same feed. Syft uses the explicit local
engine socket; no application volumes are mounted. Each SBOM's config/manifest
hashes, source labels, requested image ID and filesystem chain are checked against
the engine observation. Config, platform-manifest and image-index digests are
kept distinct. Raw scanner findings remain intact, zero ignored matches are
required, and no custom ignore rules are installed. The scanner's built-in rules
remain visible in its raw configuration.

Only labelled scanner/source-observer containers and two owned temporary scanner
volumes are removed, after rechecking engine and ownership. Images and evidence
remain. Failure preserves a separate partial attempt; there is no resume, force,
adopt, pruning or overwrite mode. A cleanup failure is an unconfirmed result.

Outputs include source/image/scanner locks, per-command results, per-image source
copy receipts, raw SBOMs and scans, and a final summary. The successful status is
`BUILT_AND_SCANNED_LOCAL_ONLY`. Findings still require assessment. This command
does not produce an image archive, verify complete archive layers, start the
deployment, exercise participants, prove recovery, provision a host or open access.

## Complete release sequence

1. Freeze source; create the V3 build receipt above. Keep unsuccessful attempts.
2. Run the joined fresh installer against these exact ten IDs and source lock.
   Require nine normal services, closed participant/native state, exactly two
   IPv4-loopback operator ports and zero public listeners,
   correct seven durable volumes plus transient socket, and detached installer
   credentials. Source/image changes invalidate the previous build binding.
3. Use invented local identities through the edge for sign-in, registration,
   staff approval, account-bound invitation redemption and native voting. Confirm
   warm-session revocation, quota/replay preservation and immediate closure.
4. Independently observe native vote attribution, persisted math/watermarks and
   private aggregate export. A successful HTTP response alone is insufficient.
5. Cold-backup the complete quiescent deployment, restore to a new owned physical
   namespace, start closed, confirm old capabilities/replays remain denied and
   compare native analysis/export. Exercise whole-stack renewal with fresh closed
   activation binding and both ends of receiver TLS trust changed together.
6. Scan the final unchanged source/image lock against one fresh advisory feed.
   Review exact evidence and residual findings, then prepare the target-specific
   closed-staging approval. A real provider/browser proof, invitations and eventual
   opening remain separately authorised actions.

The historical executed controllers provide reviewed adaptation material under
the September 14 task's `work/production-main-qa/run-owner-b.mjs`,
`work/production-main-b-start.mjs`, and
`outputs/polis-normal-compose-build/evidence/joined-recovery/{rehearse-b2,restore-b3}.mjs`.
They contain old engine/private-input paths and must not be executed unchanged.
Their 270 votes and recovery results are historical evidence, not V2 results.

Dean / Barayamal owns the external staging decision. Existing records preserve
canonical `pulse.barayamal.com.au`, sole operational ownership and A$0 automatic
spend authority. A September 15 AWS Sydney ARM64 recommendation is a proposal,
not an approved account, hostname, identity application, backup destination or
current price. Resolve those concrete fields before requesting exact deployment
approval; do not repeat the settled A/B/C choice or imply that invitations were sent.

The current [Pol.is self-hosting README](https://github.com/compdemocracy/polis/blob/stable/README.md)
continues to describe Docker Compose and production-specific configuration. Its
[configuration](https://github.com/compdemocracy/polis/blob/stable/docs/configuration.md)
and [TLS guidance](https://github.com/compdemocracy/polis/blob/stable/docs/ssl.md)
provide the upstream basis. These nine-role custody, registration, source binding,
activation and joined-recovery controls are Barayamal additions.

Focused source/collector checks:

```sh
node --test deploy/fncp/release-readiness/candidate-source-lock.test.mjs \
  deploy/fncp/release-readiness/collect-candidate-release.test.mjs
```
