# WordPress local source-review archive

This deterministic ZIP is **LOCAL_REVIEW_ONLY_KEEP_CLOSED**, not a production plugin release, installer, activation permission or launch authority. It preserves the five already-reviewed PHP sources byte for byte, including their synthetic-only, fresh-instance, local-environment, loopback and independent-key guards. It provides no real login, Indigenous heritage verification or invitation delivery.

## Contents and preservation

The six ZIP entries are:

```text
fncp-wordpress-local-review/
  wordpress-identity/contract.php
  wordpress-identity/fncp-wordpress-identity.php
  wordpress-identity/registry.php
  wordpress-local/contract.php
  wordpress-local/journal.php
  REVIEW-MANIFEST.json
```

The sibling directories are deliberate: the entrypoint requires `../wordpress-local/journal.php`, which requires the local contract. Do not flatten or rename this layout. The old `wordpress-local/fncp-wordpress-local.php` plugin entrypoint is not part of this bundle and must not be loaded alongside the new plugin.

The source checker’s current five-file/five-edge closure digest is pinned:

```text
e6aea2cff34ec55e365e9189e0ea3cd523302ee474dd7bf8169af8b5db628363
```

Any PHP source drift, even an otherwise harmless comment, rejects packaging until that exact source revision is reviewed and the pin/tests are updated intentionally. A digest is byte-preservation evidence, not PHP security certification or a publisher signature.

The embedded manifest records source hashes, exact paths, source sizes, dependencies, review limits and closed status. The separate `manifest.json` also records the whole-ZIP SHA256 and size. No timestamp, machine path, runtime state, identity, key, configuration, hidden file, dependency installation or WordPress core is included. Source files are not executed while packaging.

ZIP output is bounded to 320 KiB, uses stored (uncompressed) entries, fixed 1980-01-01 metadata and regular-file mode `0644`. There are no explicit directory entries, comments, extra fields, encryption, ZIP64, data descriptors or compression. The validator accepts only this exact six-entry shape, not arbitrary ZIPs.

## Generate a fresh local review copy

From this checkout, choose a new absolute, canonical output directory whose parent already exists:

```sh
node deploy/fncp/wordpress-identity/review-bundle.mjs --output-dir /absolute/existing-parent/fncp-wordpress-review-new
```

Replace the example path before running it. The target directory must **not** exist—even an empty directory or a previous partial result is rejected. Relative paths, `..` aliases, symlink parents, hidden-state paths and WordPress `wp-content`, `plugins` or `mu-plugins` destinations are rejected. On macOS, a `/tmp` alias must be resolved to its canonical location before it can be used.

The command:

1. Reads only the source checker’s exact five PHP files and validates their closure and reviewed digest.
2. Assembles ZIP bytes in memory and independently parses and validates the archive.
3. Creates the one explicitly requested directory with mode `0700`.
4. Creates only `fncp-wordpress-local-review.zip` and `manifest.json`, with mode `0600` and exclusive/no-follow writes.
5. Rereads those files, checks directory/file identity and validates the persisted archive and manifest before printing public metadata.

It does not overwrite, remove, install, extract, activate or send anything. A failed attempt retains any newly created partial output for inspection; do not reuse that directory. The filesystem checks detect ordinary substitutions and drift, not hostile concurrent control of the filesystem. Keep review output in a trusted local directory.

## Review, then extract only if needed

First compare the whole-archive SHA256 with the accompanying manifest. A separate ZIP implementation can inspect the archive without extraction:

```sh
unzip -t /absolute/review-directory/fncp-wordpress-local-review.zip
unzip -l /absolute/review-directory/fncp-wordpress-local-review.zip
```

A successful generic ZIP checksum test does **not** replace this project’s stricter source-pin, metadata and closed-manifest validator. The project validator works in memory and never extracts:

```js
import { readFileSync } from 'node:fs';
import { validateWordPressReviewArchive } from './deploy/fncp/wordpress-identity/review-bundle.mjs';

const { files, manifest } = validateWordPressReviewArchive(
  readFileSync('/absolute/review-directory/fncp-wordpress-local-review.zip'),
);
// files is a fresh Map<string, string> containing only the five original paths.
// manifest contains closed-status metadata and source/archive hashes, not PHP text.
```

If source inspection needs extraction, use only a fresh, empty, non-web-served local scratch directory and preserve the archive root and sibling layout. Do not extract into WordPress, `wp-content`, a web root, a live deployment or an existing tree. Review/extraction is not permission to install or execute the code. This archive is intentionally not a production WordPress upload package.

## APIs and checks

`buildWordPressReviewBundle({ files, manifest })` consumes the existing `assembleWordPressBundle()` result and returns `{ archive: Buffer, manifest }`. It performs no disk I/O and never rewrites source. Exotic input objects, JSON hooks, mismatched manifest claims and changed source hashes are rejected.

`validateWordPressReviewArchive(archive)` independently parses local headers, the central directory and the trailer; checks exact paths/order, offsets, metadata, file attributes, CRC32, source SHA256/closure and canonical embedded manifest; and returns `{ files, manifest }`. It consumes raw Buffer storage without invoking caller-supplied Buffer conversion hooks. Traversal, duplicates, aliases, symlinks, overlapping entries and tampering are rejected.

`writeWordPressReviewBundle(outputDirectory)` performs the explicitly scoped fresh-directory creation described above. Importing the module starts and writes nothing.

Run the local regression suite:

```sh
node --test deploy/fncp/wordpress-identity/review-bundle.test.mjs
```

The focused suite has **90 checks** covering byte determinism, unchanged source/guards, missing dependencies, unsafe inputs, local/central/trailer metadata, traversal/alias/duplicate names, repaired-CRC tampering, no-overwrite behavior, symlink/hardlink destinations, restrictive modes and explicit CLI scope. Test fixtures are invented, created under fresh test directories and removed by their owning test.

The separate [packaged PHP smoke tests](./packaged-plugin-smoke.test.mjs) evaluate the validated five-file map using WordPress-function stubs in a fresh local directory. They are not a real WordPress installation, provider integration or production-runtime test.

## Before any production package

Keep production packaging and installation paused until the identity/hosting target is chosen, real-provider integration and operator security are implemented, all runtime dependencies and release artifacts are included, and production-specific assurance is complete. Do not weaken the synthetic guards or merely rename this archive to call it deployable. Sending, publication, installation and deployment need separate approval.
