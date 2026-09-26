#!/bin/sh
# The ipad binary over the stdio host protocol (tests/hostsim), several runs on
# one card: what a run leaves behind must be there for the next. This is the
# path that broke at -Os with the emulation's state path pointing into a dead
# stack frame — every unit test passed, and provisioning "succeeded" without
# ever writing the state.
#   test_cli.sh <build dir>
set -u
b=$1
w=$(mktemp -d)
trap 'rm -rf "$w"' EXIT
checks=0 failures=0
ok() { checks=$((checks + 1)); if ! eval "$1"; then failures=$((failures + 1)); echo "FAIL: $2"; fi; }

# an EimConfigurationData: 30 { 80 id, 81 fqdn, 83 counter 0 }
printf '\060\041\200\017eim.cli.example\201\013127.0.0.1:9\203\001\000' >"$w/cfg.der"

out=$("$b/hostsim" -- "$b/ipad" -s "$w/s" poll -- "$b/ipad" -s "$w/s" provision "$w/cfg.der" \
	-- "$b/ipad" -s "$w/s" info -- "$b/ipad" -s "$w/s" -i 353290611234567 export "$w/dev.json" 2>&1)

ok 'echo "$out" | grep -q "\"code\":3,\"message\":\"no eIM configured\""' 'poll before provisioning: exit 3, no eIM'
ok 'echo "$out" | grep -q "\"code\":0,\"message\":\"provision\""' 'provision: done'
ok 'echo "$out" | grep -q "\"eims\":\[{\"id\":\"eim.cli.example\""' 'info: the provisioned eIM is there in the next run'
ok 'ls "$w/s"/*.state >/dev/null 2>&1' 'the emulation state was written'
ok 'grep -q "\"format\":\"eim-euicc-import/1\"" "$w/dev.json"' 'export: the import file'
ok 'grep -q "\"device\":{\"imei\":\"353290611234567\"}" "$w/dev.json"' 'export: with the IMEI'

# a second provisioning is refused: one initial eIM (SGP.32 3.5.2)
out=$("$b/hostsim" -- "$b/ipad" -s "$w/s" provision "$w/cfg.der" 2>&1)
ok 'echo "$out" | grep -q "\"code\":1"' 'provision again: refused'

echo "test_cli: $checks checks, $failures failures"
[ "$failures" = 0 ]
