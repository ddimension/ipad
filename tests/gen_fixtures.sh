#!/bin/sh
# Crypto fixtures made by OpenSSL, an implementation independent of the one
# under test: keys, a certificate and signatures over a fixed message, for
# P-256 and brainpoolP256r1. The signatures are converted from DER
# ECDSA-Sig-Value to the r||s form RSP carries. Re-run to regenerate.
set -e
cd "$(dirname "$0")/fixtures"
printf 'euiccPackageSigned||associationToken' > msg.bin
for c in prime256v1 brainpoolP256r1; do
	openssl ecparam -name $c -genkey -noout -out $c.key.pem
	openssl ec -in $c.key.pem -pubout -outform DER -out $c.spki.der 2>/dev/null
	openssl dgst -sha256 -sign $c.key.pem -out $c.sig.der msg.bin
	# DER SEQUENCE { INTEGER r, INTEGER s } -> 32-octet r || 32-octet s
	openssl asn1parse -inform DER -in $c.sig.der | awk -F: '/INTEGER/ {print $NF}' |
		python3 -c 'import sys; sys.stdout.buffer.write(b"".join(bytes.fromhex(l.strip().rjust(64, "0")) for l in sys.stdin))' > $c.sig.raw
	openssl req -new -x509 -key $c.key.pem -subj "/CN=ipad-test-$c" -days 3650 \
		-outform DER -out $c.cert.der 2>/dev/null
done

# a TLS server identity for the HTTP test: P-256, SAN localhost
openssl req -new -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
	-keyout server.key.pem -out server.cert.pem -subj "/CN=localhost" -days 3650 \
	-addext "subjectAltName=DNS:localhost" 2>/dev/null
openssl x509 -in server.cert.pem -outform DER -out server.cert.der
openssl x509 -in server.cert.pem -pubkey -noout | openssl pkey -pubin -outform DER -out server.spki.der

# identities for an IP-literal URL, same key as the server: only an iPAddress
# SAN names an address (RFC 9525 6.3); a dNSName spelling it, a wildcard and
# a CN without SAN must not
ipcert() {   # ipcert <name> <subject> [<SAN>]
	openssl req -new -x509 -key server.key.pem -out "ip-$1.cert.pem" -subj "$2" -days 3650 \
		${3:+-addext "subjectAltName=$3"} 2>/dev/null
}
ipcert v4 /CN=ipad-test-ip IP:127.0.0.1
ipcert v6 /CN=ipad-test-ip IP:::1
ipcert dns /CN=ipad-test-ip DNS:127.0.0.1
ipcert wild /CN=ipad-test-ip 'DNS:*.0.0.1'
ipcert cn /CN=127.0.0.1
