#!/bin/sh
# End to end against a real eIM (ddimension eim): the ipad binary over the
# stdio host protocol (tests/hostsim, SGP.22 card simulated), the eIM over
# plain HTTP in its development mode, in a database of its own.
#
#   tools/e2e-eim.sh [<eim checkout>]      (default ../../eim)
#
#   E2E_TLS=1   HTTPS instead: the eIM with a self-signed certificate for
#               localhost, its key pinned in the eIM configuration
#               (trustedPublicKeyDataTls), and a run with a wrong pin that
#               must not get through
#   E2E_KEEP=<dir>  on a failure, copy the work directory (server log,
#               state) there
#   IPAD=...    the ipad command, e.g. "qemu-aarch64-static build-aarch64/ipad"
#               to run a cross-built binary
#
# Needs the eim-postgres container (eim: testenv/db.sh) and cargo. Checks:
# the import file is accepted (proof, key, DER objects); listProfileInfo and
# enable run, are signed with the device key, verified and acknowledged; an
# enable whose connection does not come back is rolled back and reported as
# such; an indirect download is sent as an empty trigger and reaches ES9+',
# after the getRAT the eIM reads first; results signed with another key
# complete no operation (the eIM discards them, and may acknowledge them — SGP.32 5.14.6).
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
eim=$(cd "${1:-$root/../../eim}" && pwd)
cargo=${CARGO:-$(command -v cargo || echo "$HOME/.cargo/bin/cargo")}
w=$(mktemp -d)
port=18080
db=ipad_e2e_$$
url=http://127.0.0.1:$port/gsma/rsp2/asn1
eid=89049032123451234512345678901235
hs=$root/build/hostsim
ipad=${IPAD:-$root/build/ipad}   # word-split on purpose: a wrapper may come first
tls=${E2E_TLS:-0}
pid=

cleanup() {
	[ -n "$pid" ] && kill "$pid" 2>/dev/null || true
	docker exec eim-postgres psql -qU eim -d eim -c "DROP DATABASE IF EXISTS $db" >/dev/null 2>&1 || true
	rm -rf "$w"
}
trap cleanup EXIT
fail() {
	echo "e2e: FAIL: $*"
	[ -n "${E2E_KEEP:-}" ] && cp -r "$w" "$E2E_KEEP"
	[ -f "$w/server.log" ] && sed 's/\x1b\[[0-9;]*m//g' "$w/server.log" | tail -5
	exit 1
}

"$cargo" build --quiet --manifest-path "$eim/Cargo.toml" -p eim-server --bins
B=$eim/target/debug
docker exec eim-postgres psql -qU eim -d eim -c "CREATE DATABASE $db" >/dev/null

# a random passphrase per run: the eIM refuses one shorter than 16 bytes
openssl rand -base64 32 | tr -d '\n' >"$w/pass"
chmod 0400 "$w/pass"   # the eIM warns about a secret others can read
"$B/eim-server" keygen "$w/key.pem" "$w/pass" >/dev/null
"$B/eim-server" keygen "$w/data.pem" "$w/pass" >/dev/null
export DATABASE_URL="postgres://eim:eim@localhost/$db?host=/tmp/eimpg"
# EIM_FQDN is the name the server answers SNI for (a host name); the port
# goes into the configuration the IPA gets
host=127.0.0.1
fqdn=$host:$port
if [ "$tls" = 1 ]; then
	host=localhost
	fqdn=$host:$port
	"$B/eim-server" keygen "$w/tls.pem" "$w/pass" >/dev/null
	openssl req -x509 -key "$w/tls.pem" -passin "file:$w/pass" -days 2 -subj /CN=localhost \
		-addext subjectAltName=DNS:localhost -out "$w/tls.crt" 2>/dev/null
	openssl pkey -in "$w/tls.pem" -passin "file:$w/pass" -pubout -outform DER -out "$w/tls.spki"
	export EIM_TLS_CERT=$w/tls.crt EIM_TLS_KEY=$w/tls.pem
	url=https://$fqdn/gsma/rsp2/asn1
else
	export EIM_INSECURE_HTTP=1
fi
export EIM_LISTEN=127.0.0.1:$port EIM_ID=eim.e2e.example EIM_FQDN=$host
export EIM_KEY_FILE=$w/key.pem EIM_KEY_PASSPHRASE_FILE=$w/pass EIM_DATA_KEY_FILE=$w/data.pem
export EIM_SMDP_TLS_PLATFORM_ROOTS=1
export EIM_TRUSTED_CI=$root/tests/fixtures/prime256v1.cert.der
"$B/eimctl" migrate >/dev/null
"$B/eimctl" eim-config "$w/eim_cfg.ber" --fqdn $fqdn --counter 0 >/dev/null

# trustedPublicKeyDataTls [6] { trustedEimPkTls [0] <SPKI content> } into the
# configuration, in declaration order after eimPublicKeyData [5]; with a
# second, wrong key for the negative run
pin() {
	python3 - "$1" "$2" "$3" <<'PY'
import sys
def tlv(tag, v):
    n = len(v)
    l = bytes([n]) if n < 128 else (bytes([0x81, n]) if n < 256 else bytes([0x82, n >> 8, n & 255]))
    return tag + l + v
def parse(b):
    i, out = 0, []
    while i < len(b):
        t = b[i:i+1]; i += 1
        if t[0] & 0x1f == 0x1f:
            while b[i] & 0x80: t += b[i:i+1]; i += 1
            t += b[i:i+1]; i += 1
        n = b[i]; i += 1
        if n & 0x80:
            k = n & 0x7f; n = int.from_bytes(b[i:i+k], 'big'); i += k
        out.append((t, b[i:i+n])); i += n
    return out
cfg, spki, out = sys.argv[1:4]
(t57, v57), = parse(open(cfg, 'rb').read())
(ta0, va0), = parse(v57)
(t30, v30), = parse(va0)
(_, key), = parse(open(spki, 'rb').read())
items = parse(v30) + [(b'\xa6', tlv(b'\xa0', key))]
body = b''.join(tlv(t, v) for t, v in items)
open(out, 'wb').write(tlv(t57, tlv(ta0, tlv(t30, body))))
PY
}
if [ "$tls" = 1 ]; then
	openssl ecparam -name prime256v1 -genkey -noout -out "$w/other.pem" 2>/dev/null
	openssl pkey -in "$w/other.pem" -pubout -outform DER -out "$w/other.spki"
	pin "$w/eim_cfg.ber" "$w/other.spki" "$w/eim_cfg_wrong.ber"
	pin "$w/eim_cfg.ber" "$w/tls.spki" "$w/eim_cfg_pinned.ber"
	mv "$w/eim_cfg_pinned.ber" "$w/eim_cfg.ber"
fi
"$B/eim-server" >"$w/server.log" 2>&1 &
pid=$!
i=0
until curl -sk -o /dev/null "${url%/gsma*}/"; do
	i=$((i + 1)); [ $i -lt 60 ] || fail "eIM did not start"; sleep 0.5
done

if [ "$tls" = 1 ]; then
	# the wrong pin first, on a card of its own: the TLS handshake completes,
	# the pin check after it refuses (ipad http.c pinned_ok)
	out=$("$hs" -- $ipad -s "$w/wrong" provision "$w/eim_cfg_wrong.ber" -- $ipad -v -s "$w/wrong" poll 2>&1) || true
	echo "$out" | grep -q 'does not match the pinned eIM TLS key' || { echo "$out"; fail "a wrong TLS pin got through"; }
	echo "e2e: TLS with the wrong pinned key refused"
	url_opt=
else
	url_opt="-u $url"
fi

st=$w/state
"$hs" -- $ipad -s "$st" provision "$w/eim_cfg.ber" -- $ipad -s "$st" -i 353290611234567 export "$w/dev.json" |
	grep -q '"message":"export"' || fail "provision/export"
"$B/eimctl" euicc import "$w/dev.json" | grep -q 'ipa_public_key: true' || fail "import refused"
echo "e2e: import file accepted"

"$B/eimctl" op add $eid list_profile_info >/dev/null
"$B/eimctl" op add $eid '{"type":"enable","iccid":"89000123456789012342"}' >/dev/null
"$hs" -- $ipad -s "$st" $url_opt poll | grep -q 'acknowledged=2' || fail "poll"
[ "$("$B/eimctl" op list $eid | grep -c ' done ')" = 2 ] || fail "operations not done"
echo "e2e: listProfileInfo + enable done, verified with the device key"

"$B/eimctl" op add $eid '{"type":"enable","iccid":"89000123456789012343"}' >/dev/null
"$hs" -o -P 98001032547698103224,98001032547698103214,98001032547698103234 -- $ipad -s "$st" $url_opt poll |
	grep -q 'rolled_back=1' || fail "no rollback"
"$B/eimctl" op list $eid | grep -q 'rolled back by the IPA' || fail "rollback not reported"
echo "e2e: offline after enable -> rolled back, reported"

# An indirect download (SGP.32 3.2.3.2) with the activation code kept by the
# eIM: the import file reports eimDownloadDataHandling, so the eIM queues it
# and sends an empty trigger (2.11.1.3). ipad calls InitiateAuthentication
# with the eimTransactionId and no smdpAddress (5.14.1); the eIM takes the
# address from the code and calls ES9+' there. No SM-DP+ listens on it: the
# property is that the eIM matched the call to the operation and tried the
# code's SM-DP+, which it does only for an eimTransactionId it knows.
printf '{"type":"download","activation_code":"1$127.0.0.1:1$E2E-TOKEN"}' |
	"$B/eimctl" op add $eid - >/dev/null || fail "indirect download not queued (capabilities?)"
out=$("$hs" -- $ipad -v -s "$st" $url_opt poll 2>&1) || true
echo "$out" | grep -q 'downloads=[1-9]' || { echo "$out"; fail "no download trigger"; }
sed 's/\x1b\[[0-9;]*m//g' "$w/server.log" | grep -q 'download: ES9+.*function=InitiateAuthentication operation_id=' ||
	{ sed 's/\x1b\[[0-9;]*m//g' "$w/server.log" | tail -20; fail "the eIM did not call ES9+' InitiateAuthentication"; }
"$B/eimctl" op list $eid | grep -Eq 'get_rat +done' || fail "getRAT before the download not done"
echo "e2e: empty trigger -> InitiateAuthentication without smdpAddress, ES9+' tried at the code's SM-DP+"

# before a download the eIM reads the card (getRAT, listProfileInfo): they
# run in the same poll and count as done
done=$("$B/eimctl" op list $eid | grep -c ' done ')
mv "$st/device.key" "$st/device.key.good"
"$B/eimctl" op add $eid list_profile_info >/dev/null
# A result under a key the eIM does not know must never complete an
# operation. It MAY be acknowledged: SGP.32 v1.3 5.14.6 has the eIM discard
# a result with an invalid signature and return the sequence numbers of the
# processed results "including discarded results" (eIM decision D-66) — so
# acknowledged=0 is not the property, and checking for it failed against a
# conforming eIM.
"$hs" -- $ipad -s "$st" $url_opt poll >/dev/null
[ "$("$B/eimctl" op list $eid | grep -c ' done ')" = "$done" ] || fail "a result under another key completed an operation"
grep -q 'result discarded: eUICC signature' "$w/server.log" || fail "eIM did not discard the signature"
echo "e2e: results under another key discarded, no operation completed"
echo "e2e: all passed"
