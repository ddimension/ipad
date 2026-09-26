#!/bin/sh
# Every ESipa message test_ipa exchanges, both ways, decoded by the eIM's
# ASN.1 types and re-encoded byte-identically. Needs cargo and the eim tree
# (see tools/esipa-check/Cargo.toml).
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
cargo=${CARGO:-$(command -v cargo || echo "$HOME/.cargo/bin/cargo")}
"$cargo" build --quiet --release --manifest-path "$root/tools/esipa-check/Cargo.toml"
dump=$(mktemp)
trap 'rm -f "$dump"' EXIT
IPAD_ESIPA_DUMP=$dump "$root/build/test_ipa" >/dev/null
"$root/tools/esipa-check/target/release/esipa-check" <"$dump" | grep -v '^OK' || true
n=$(wc -l <"$dump")
"$root/tools/esipa-check/target/release/esipa-check" <"$dump" >/dev/null && echo "esipa-check: $n messages decode and re-encode identically"
