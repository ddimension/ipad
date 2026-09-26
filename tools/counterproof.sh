#!/bin/sh
# Counterproof: remove a guard, rebuild, run a test, restore.
#
#   tools/counterproof.sh <file> <exact text> <replacement> <test> [<test>...]
#
# Exits 0 when the test FAILS without the guard (the guard is proven), 1 when
# it still passes, 2 when the change did not apply or the build broke. The
# build check is the point: a replacement that does not compile leaves the old
# binary in place, and a run of that "proves" nothing (it happened here once,
# with an empty if-body under -Werror).
set -u
f=$1; from=$2; to=$3; shift 3
root=$(cd "$(dirname "$0")/.." && pwd)
bak=$(mktemp)
cp "$root/$f" "$bak"
trap 'cp "$bak" "$root/$f"; rm -f "$bak"; cmake --build "$root/build" >/dev/null 2>&1' EXIT

python3 - "$root/$f" "$from" "$to" <<'PY' || exit 2
import sys
p, a, b = sys.argv[1:4]
s = open(p).read()
if s.count(a) != 1:
    sys.exit("counterproof: text found %d times, need exactly 1" % s.count(a))
open(p, 'w').write(s.replace(a, b, 1))
PY

if ! cmake --build "$root/build" >/dev/null 2>&1; then
	echo "counterproof: build failed with the change, nothing proven" >&2
	exit 2
fi

rc=1
for t in "$@"; do
	if ! "$root/build/test_$t" >/dev/null 2>&1; then
		rc=0
	fi
done
[ $rc = 0 ] && echo "counterproof: a test fails without it (proven)" || echo "counterproof: all tests still pass (NOT proven)"
exit $rc
