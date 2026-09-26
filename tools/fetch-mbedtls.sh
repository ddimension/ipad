#!/bin/sh
# Fetch the mbedTLS release the bundled build uses into third_party/.
# Release tarball of https://github.com/Mbed-TLS/mbedtls/releases/tag/mbedtls-3.6.7
# (Apache-2.0 OR GPL-2.0-or-later); the SHA-256 is the one the release page
# publishes in mbedtls-3.6.7-sha256sum.txt. A distribution build (the OpenWrt
# package) fetches the same tarball itself and passes -DIPAD_MBEDTLS_DIR.
set -eu
V=3.6.7
SHA=a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6
root=$(cd "$(dirname "$0")/.." && pwd)
dst=$root/third_party
t=$dst/mbedtls-$V.tar.bz2

mkdir -p "$dst"
[ -f "$t" ] || curl -fsSL -o "$t" "https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-$V/mbedtls-$V.tar.bz2"
echo "$SHA  $t" | sha256sum -c - >/dev/null || { echo "fetch-mbedtls: checksum mismatch, $t removed" >&2; rm -f "$t"; exit 1; }
rm -rf "$dst/mbedtls-$V"
tar -xjf "$t" -C "$dst"
echo "mbedTLS $V in $dst/mbedtls-$V"
