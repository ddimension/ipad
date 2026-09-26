#!/bin/sh
# Every suite once more, built at -Os under AddressSanitizer and UBSan. The
# optimizer is part of the point: a use-after-scope in main.c showed at -Os
# only, and only as a provisioning that did not stick.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
b=${1:-$root/build-sanitize}
cmake -S "$root" -B "$b" -DCMAKE_BUILD_TYPE=MinSizeRel \
	-DCMAKE_C_FLAGS="-g -fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer" \
	-DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" >/dev/null
cmake --build "$b" -j"$(nproc)" >/dev/null
cd "$b" && ctest --output-on-failure
