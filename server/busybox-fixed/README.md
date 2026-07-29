# Fixed BusyBox build input

This context rebuilds Alpine `busybox` `1.37.0-r31` with the upstream
`CVE-2025-60876` patch. Source and Alpine aports inputs are pinned and
hash-checked by `build-fixed-busybox.sh`; the final binary is static and its
functional test proves that a carriage return in a URL is rejected.

The final APK database still names `1.37.0-r31`, so version-only scanners may
retain the raw finding. The rebuilt binary hash and rejection test require a
VEX disposition after all images are rebuilt and rescanned.

Direct builder packages are version-pinned. Their transitive APKs still come
from Alpine's mutable `v3.24` repository, so final release evidence must retain
the resulting binary bytes/SBOM or first mirror and hash-pin the full APK
closure. Each final image also proves that `/bin/sh` and `/usr/bin/wget`
continue to resolve to the replacement binary and repeats the malicious URL
test through the `wget` symlink.
