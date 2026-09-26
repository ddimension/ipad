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

# --- the eIM's bundle (eIM decision D-69) and the self-binding -------------
# A stand-in eIM (bind_eim.py) answers the bind with scripted statuses; the
# card is fake22 under the emulation. The bundle carries a real P-256 key.
tests=$(cd "$(dirname "$0")" && pwd)
srv_pid=
trap 'rm -rf "$w"; [ -n "$srv_pid" ] && kill $srv_pid 2>/dev/null' EXIT
eim() {   # eim <statuses>: (re)start the stand-in, sets $port and $url
	[ -n "$srv_pid" ] && kill $srv_pid 2>/dev/null && wait $srv_pid 2>/dev/null
	rm -f "$w"/bind.[0-9]* "$w/port"
	python3 "$tests/bind_eim.py" "$w" "$1" >"$w/port" &
	srv_pid=$!
	i=0
	while [ ! -s "$w/port" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
	port=$(cat "$w/port")
	url=http://127.0.0.1:$port/gsma/rsp2/asn1
}
binds() { ls "$w"/bind.[0-9]* 2>/dev/null | wc -l; }
b64() { base64 -w0 "$1"; }
# bundle <file> <counter> <expires_at> [<key der>]: an eim-ipad-provision/1 file
# with an EimConfigurationData for eim.cli.example at that counter (< 256)
bundle() {
	printf '\060\041\200\017eim.cli.example\201\013127.0.0.1:9\203\001'"\\$(printf '%03o' "$2")" >"$w/bcfg.der"
	k=${4:-$w/bkey.der}
	[ -f "$k" ] || openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -outform DER -out "$k" 2>/dev/null
	printf '{"format":"eim-ipad-provision/1","issuance_id":"0b7e3c52-9a1d-4c1e-8f00-%012d","eim_configuration":"%s","device_key":"%s","counter":%s,"expires_at":"%s"}\n' \
		"$2" "$(b64 "$w/bcfg.der")" "$(b64 "$k")" "$2" "$3" >"$1"
}
future=$(date -u -d '+7 days' +%Y-%m-%dT%H:%M:%SZ)
run() { "$b/hostsim" -- "$b/ipad" "$@" 2>&1; }

bundle "$w/b1.json" 5 "$future"
key64=$(b64 "$w/bkey.der")
spki64=$(openssl pkey -inform DER -in "$w/bkey.der" -pubout -outform DER | base64 -w0)
out=$(run -s "$w/b" provision "$w/b1.json")
ok 'echo "$out" | grep -q "\"code\":0,\"message\":\"provision\""' 'bundle: provisioned'
ok '[ ! -e "$w/b1.json" ]' 'bundle: the file is deleted once stored'
ok '[ "$(stat -c %a "$w/b/device.key")" = 600 ]' 'bundle: device.key is 0600'
ok '[ "$(openssl pkey -inform DER -in "$w/b/device.key" -pubout -outform DER 2>/dev/null | base64 -w0)" = "$spki64" ]' \
	'bundle: the device key is the bundle key'
ok '! echo "$out" | grep -qF "$key64"' 'bundle: the key is not printed'
fp=$(openssl pkey -inform DER -in "$w/bkey.der" -pubout -outform DER | sha256sum | cut -c1-64 | tr a-f A-F)
ok 'echo "$out" | grep -q "host: .*\"event\":\"info\".*\"key_fingerprint\":\"$fp\",\"bind\":\"pending\",\"counter\":5"' \
	'event info after provision: the bundle key, binding pending'
ok 'echo "$out" | grep -q "host: .*\"event\":\"summary\",\"command\":\"provision\",\"code\":0,\"bind\":\"pending\""' \
	'event summary after provision'
out=$(run -s "$w/b" info)
ok 'echo "$out" | grep -q "\"bind\":\"pending\",\"counter\":5"' 'info: binding pending at the start counter'

# 429 then 204: the first poll leaves the binding pending and does not poll
eim 429,204
out=$(run -s "$w/b" -u "$url" poll)
ok 'echo "$out" | grep -q "\"code\":1,\"message\":\"bind\""' 'bind 429: poll ends with 1, no GetEimPackage'
ok '[ -e "$w/b/bind.pending" ]' 'bind 429: still pending'
ok '[ ! -e "$w/b/bind.after" ]' 'bind 429 without Retry-After: the next poll may bind'
# 429 with Retry-After: the next poll leaves the eIM alone until then
eim 429:120
out=$(run -s "$w/b" -u "$url" poll)
ok '[ -e "$w/b/bind.after" ] && [ "$(binds)" = 1 ]' 'bind 429 Retry-After: the time is kept'
out=$(run -s "$w/b" -u "$url" poll)
ok 'echo "$out" | grep -q "\"code\":1,\"message\":\"bind\"" && [ "$(binds)" = 1 ]' \
	'bind 429 Retry-After: the next poll does not ask the eIM'
ok 'echo "$out" | grep -q "\"event\":\"summary\",\"command\":\"poll\",\"code\":1,.*\"error\":\"binding deferred"' 'bind 429 Retry-After: the summary says why'
echo $(( $(date +%s) + 999999 )) >"$w/b/bind.after"
out=$(run -s "$w/b" -u "$url" poll)
ok '[ "$(binds)" = 2 ]' 'bind 429 Retry-After: more than a day ahead (the clock went back) is not obeyed'
echo $(( $(date +%s) - 1 )) >"$w/b/bind.after"
eim 429,204
out=$(run -s "$w/b" -u "$url" poll)
ok '[ "$(binds)" = 1 ] && [ ! -e "$w/b/bind.after" ]' 'bind 429 Retry-After: asked again once the time has passed'
out=$(run -s "$w/b" -u "$url" poll)
ok 'echo "$out" | grep -q "\"code\":0,\"message\":\"poll\""' 'bind 204: then the poll runs'
ok '[ -e "$w/b/bind.done" ] && [ ! -e "$w/b/bind.pending" ]' 'bind 204: bound'
ok '[ "$(binds)" = 2 ]' 'bind: posted once per poll'
ok 'echo "$out" | grep -q "host: .*\"event\":\"info\".*\"bind\":\"pending\",\"counter\":5"' \
	'event info: bind state and counter at the start of the run'
ok 'echo "$out" | grep -q "host: .*\"event\":\"summary\",\"command\":\"poll\",\"code\":0,\"packages\":0,.*\"bind\":\"done\""' \
	'event summary: the outcome of the run for the host'
body=$w/bind.2
ok 'grep -q "^{\"format\":\"eim-euicc-import/1\",\"eid\":\"89049032123451234512345678901235\"" "$body"' \
	'bind body: the import file of the card in hand'
ok 'grep -qF "\"ipa_public_key\":\"$spki64\"" "$body" && grep -q "\"counter\":5," "$body"' \
	'bind body: the bundle key, the bundle counter'
# the proof (eim-domain import.rs): ECDSA P-256 over the text below, r||s
python3 - "$body" "$w" <<'PY'
import json, base64, sys
d = json.load(open(sys.argv[1])); w = sys.argv[2]
open(w + '/proof.txt', 'w').write('eim-euicc-import/1\n%s\n%s\n%d\n' % (d['eid'], d['ipa_public_key'], d['counter']))
sig = base64.b64decode(d['proof'])
def i(b):
    b = b.lstrip(b'\0') or b'\0'
    if b[0] & 0x80: b = b'\0' + b
    return b'\x02' + bytes([len(b)]) + b
s = i(sig[:32]) + i(sig[32:])
open(w + '/proof.der', 'wb').write(b'\x30' + bytes([len(s)]) + s)
open(w + '/pub.der', 'wb').write(base64.b64decode(d['ipa_public_key']))
PY
ok 'openssl dgst -sha256 -verify "$w/pub.der" -keyform DER -signature "$w/proof.der" "$w/proof.txt" >/dev/null 2>&1' \
	'bind body: the proof verifies with the bundle key'
out=$(run -s "$w/b" -u "$url" poll)
ok 'echo "$out" | grep -q "\"code\":0,\"message\":\"poll\"" && [ "$(binds)" = 2 ]' 'bound: the next poll does not bind again'
out=$(run -s "$w/b" info)
ok 'echo "$out" | grep -q "\"bind\":\"done\""' 'info: bound'

# reset: configuration, state, key and binding gone; a second bundle starts over
out=$(run -s "$w/b" reset)
ok 'echo "$out" | grep -q "\"code\":0,\"message\":\"reset\""' 'reset: done'
ok '[ ! -e "$w/b/device.key" ] && [ ! -e "$w/b/bind.done" ] && ! ls "$w/b"/*.state >/dev/null 2>&1' \
	'reset: key, binding and state removed'
out=$(run -s "$w/b" -u "$url" poll)
ok 'echo "$out" | grep -q "\"code\":3"' 'reset: poll says no eIM configured'

# 409: the EID is registered already — counts as bound (D-69)
rm -f "$w/bkey.der"
bundle "$w/b2.json" 0 "$future"
eim 409
out=$(run -s "$w/c" provision "$w/b2.json" -- "$b/ipad" -s "$w/c" -u "$url" poll)
ok 'echo "$out" | grep -q "\"code\":0,\"message\":\"poll\"" && [ -e "$w/c/bind.done" ]' 'bind 409: treated as bound'

# 403: refused; no further poll, not even a bind, until an operator acts
bundle "$w/b3.json" 0 "$future"
eim 403
out=$(run -s "$w/d" provision "$w/b3.json" -- "$b/ipad" -s "$w/d" -u "$url" poll -- "$b/ipad" -s "$w/d" -u "$url" poll)
ok '[ "$(echo "$out" | grep -c "\"code\":4,\"message\":\"bind refused\"")" = 2 ]' 'bind 403: exit 4, and again on the next poll'
ok '[ "$(binds)" = 1 ]' 'bind 403: the eIM is not asked again'
out=$(run -s "$w/d" info)
ok 'echo "$out" | grep -q "\"bind\":\"refused\""' 'info: refused'

# 400: our request was wrong — an error, the binding stays pending
bundle "$w/b4.json" 0 "$future"
eim 400
out=$(run -s "$w/e" provision "$w/b4.json" -- "$b/ipad" -s "$w/e" -u "$url" poll)
ok 'echo "$out" | grep -q "\"code\":1,\"message\":\"bind\"" && [ -e "$w/e/bind.pending" ]' 'bind 400: error, still pending'
ok 'echo "$out" | grep -q "\"event\":\"summary\",\"command\":\"poll\",\"code\":1,\"bind\":\"pending\",\"error\":\"the eIM rejected the binding request (HTTP 400)\""' \
	'event summary: a failed run says why'
out=$(run -s "$w/e" info)
ok 'echo "$out" | grep -q "host: .*\"event\":\"info\".*\"bind\":\"pending\",\"counter\":0"' 'event info: sent for info too'

# an expired bundle and a broken one are refused and left where they are
bundle "$w/b5.json" 0 2024-06-01T00:00:00Z
out=$(run -s "$w/f" provision "$w/b5.json")
ok 'echo "$out" | grep -q "\"code\":1,\"message\":\"provision\"" && [ -e "$w/b5.json" ]' 'expired bundle: refused, file kept'
ok '[ ! -e "$w/f/bind.pending" ] && ! ls "$w/f"/*.state >/dev/null 2>&1' 'expired bundle: nothing stored'
ok '[ "$(openssl pkey -inform DER -in "$w/f/device.key" -pubout -outform DER 2>/dev/null | base64 -w0)" != "$(openssl pkey -inform DER -in "$w/bkey.der" -pubout -outform DER | base64 -w0)" ]' \
	'expired bundle: its key is not stored'
printf '{"format":"eim-ipad-provision/1","issuance_id":"x","device_key":"%s"}' "$key64" >"$w/b6.json"
out=$(run -s "$w/g" provision "$w/b6.json")
ok 'echo "$out" | grep -q "\"code\":1,\"message\":\"provision\""' 'malformed bundle: refused'
ok '! echo "$out" | grep -qF "$key64"' 'malformed bundle: the key is not printed'

echo "test_cli: $checks checks, $failures failures"
[ "$failures" = 0 ]
