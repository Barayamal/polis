# zlib CVE-2026-85091 source remediation

The nine Alpine release roles in V3 retain their distribution `zlib 1.3.2-r0`
package record but replace the runtime `libz.so.1.3.2` bytes with a build from
the upstream zlib 1.3.2 source plus upstream commit
`df84af25dc1942490e1d1c899a07619152a46148`. That commit resets the pending
input state after a stalled non-blocking `gzwrite()` and is the upstream fix
for CVE-2026-85091.

The build downloads the fixed tag archive over HTTPS, verifies its pinned
SHA-256, verifies the locally retained patch, applies it once, checks the two
new state-reset statements, runs the upstream test suite and records the
resulting shared-library digest. Every final image copies the library and
read-only provenance file after package installation, rechecks the digest and
labels the exact upstream commit.

There are three byte-identical copies because the official Pol.is build uses
separate server, math and repository-root Docker contexts. Source tests fail if
they drift. Raw SBOM/scanner output must remain visible: a package-database
scanner can continue matching `zlib 1.3.2-r0` even though its runtime library
was replaced. Release evidence must therefore include the exact image IDs,
in-image provenance/digests, linked-library inspection, upstream tests and a
fresh scan. This is a remediation claim, not an ignore rule or blanket risk
acceptance.

Official inputs:

- <https://github.com/madler/zlib/releases/tag/v1.3.2>
- <https://github.com/madler/zlib/commit/df84af25dc1942490e1d1c899a07619152a46148>

This addition does not authorize deployment or external staging.
