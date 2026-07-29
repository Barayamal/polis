#!/bin/sh
set -eu

busybox_version="1.37.0"
busybox_url="https://busybox.net/downloads/busybox-${busybox_version}.tar.bz2"
busybox_sha256="3311dff32e746499f4df0d5df04d7eb396382d7e108bb9250e7b519b837043a4"
aports_commit="c3ef5d10e6ef6528852c51f0564963e2f8c1be19"
aports_url="https://gitlab.alpinelinux.org/api/v4/projects/alpine%2Faports/repository/archive.tar.gz?sha=${aports_commit}&path=main%2Fbusybox"
aports_sha256="0598ff6f34d8067a4e6663548961df3f2088f83f9a45810030b9d210ae53ef97"

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
umask 022
curl --fail --location --silent --show-error --retry 3 --connect-timeout 20 \
  "$busybox_url" --output "$work_dir/busybox.tar.bz2"
printf '%s  %s\n' "$busybox_sha256" "$work_dir/busybox.tar.bz2" | sha256sum -c -
curl --fail --location --silent --show-error --retry 3 --connect-timeout 20 \
  "$aports_url" --output "$work_dir/aports-busybox.tar.gz"
printf '%s  %s\n' "$aports_sha256" "$work_dir/aports-busybox.tar.gz" | sha256sum -c -
mkdir -p "$work_dir/source" "$work_dir/aports"
tar -xjf "$work_dir/busybox.tar.bz2" --strip-components=1 -C "$work_dir/source"
tar -xzf "$work_dir/aports-busybox.tar.gz" -C "$work_dir/aports"
recipe_dir="$(find "$work_dir/aports" -type d -path '*/main/busybox' -print -quit)"
test -n "$recipe_dir"
grep -qx 'pkgver=1.37.0' "$recipe_dir/APKBUILD"
grep -qx 'pkgrel=31' "$recipe_dir/APKBUILD"
patch_names="$(awk '/^source="/ { active=1; next } active && /^"/ { exit } active && /\.patch[[:space:]]*$/ { gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print }' "$recipe_dir/APKBUILD")"
test -n "$patch_names"
printf '%s\n' "$patch_names" | while IFS= read -r patch_name; do
  patch -d "$work_dir/source" -p1 < "$recipe_dir/$patch_name"
done
patch -d "$work_dir/source" -p1 < /opt/fncp-busybox-fix/CVE-2025-60876.patch
mkdir -p "$work_dir/build-static" /out
sed -e 's/.*CONFIG_PIE.*/# CONFIG_PIE is not set/' \
  -e 's/.*CONFIG_STATIC\([A-Z_]*\).*/CONFIG_STATIC\1=y/' \
  -e 's/.*CONFIG_SSL_CLIENT.*/CONFIG_SSL_CLIENT=y/' \
  "$recipe_dir/busyboxconfig" > "$work_dir/build-static/.config"
extra_cflags="$(pkg-config --cflags --static libutmps)"
extra_libs="$(pkg-config --libs --static libutmps)"
make -C "$work_dir/source" O="$work_dir/build-static" silentoldconfig
make -C "$work_dir/source" O="$work_dir/build-static" -j"${BUILD_JOBS:-2}" \
  CONFIG_EXTRA_CFLAGS="$extra_cflags" CONFIG_EXTRA_LDLIBS="$extra_libs"
install -m 0755 "$work_dir/build-static/busybox" /out/busybox
file /out/busybox | grep -Fq 'statically linked'
for applet in ash awk chmod chown cp find grep mkdir readlink rm sed sh test tr wc wget; do
  /out/busybox --list | grep -Fxq "$applet"
done
bad_url="$(printf 'http://127.0.0.1/%b' '\rX-FNCP: injected')"
if /out/busybox wget "$bad_url" >"$work_dir/wget.stdout" 2>"$work_dir/wget.stderr"; then
  exit 1
fi
grep -Fq 'Unencoded control character found in the URL!' "$work_dir/wget.stderr"
sha256sum /out/busybox
