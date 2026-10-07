#!/bin/sh
set -eu
umask 077

archive_url='https://github.com/madler/zlib/archive/refs/tags/v1.3.2.tar.gz'
archive_sha256='b99a0b86c0ba9360ec7e78c4f1e43b1cbdf1e6936c8fa0f6835c0cd694a495a1'
patch_sha256='2e1c40f9ba33c29a2e43c9121970513ef1f70e3a0238e73d724fac56d8af4294'
patch_commit='df84af25dc1942490e1d1c899a07619152a46148'
work='/tmp/fncp-zlib-cve-2026-85091'

mkdir -p "$work" /out/zlib/lib /out/zlib/evidence
curl --fail --location --proto '=https' --tlsv1.2 --silent --show-error \
  "$archive_url" --output "$work/zlib-v1.3.2.tar.gz"
printf '%s  %s\n' "$archive_sha256" "$work/zlib-v1.3.2.tar.gz" | sha256sum -c -
printf '%s  %s\n' "$patch_sha256" /opt/fncp-zlib-fix/df84af25.patch | sha256sum -c -
tar -xzf "$work/zlib-v1.3.2.tar.gz" -C "$work"
patch -d "$work/zlib-1.3.2" -p1 < /opt/fncp-zlib-fix/df84af25.patch
grep -Fq 'state->strm.avail_in = 0;' "$work/zlib-1.3.2/gzwrite.c"
grep -Fq 'state->strm.next_in = state->in;' "$work/zlib-1.3.2/gzwrite.c"

cd "$work/zlib-1.3.2"
CFLAGS='-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2' ./configure --prefix=/opt/fncp-zlib
make -j"$(getconf _NPROCESSORS_ONLN)"
make test
make install
test -f /opt/fncp-zlib/lib/libz.so.1.3.2
cp /opt/fncp-zlib/lib/libz.so.1.3.2 /out/zlib/lib/libz.so.1.3.2
chmod 0555 /out/zlib/lib/libz.so.1.3.2
binary_sha256="$(sha256sum /out/zlib/lib/libz.so.1.3.2 | awk '{print $1}')"
cat > /out/zlib/evidence/provenance.txt <<EOF
profile=FNCP_ZLIB_SOURCE_REMEDIATION_V1
version=1.3.2
archive_sha256=$archive_sha256
patch_commit=$patch_commit
patch_sha256=$patch_sha256
binary_sha256=$binary_sha256
upstream_tests=PASS
EOF
chmod 0444 /out/zlib/evidence/provenance.txt
