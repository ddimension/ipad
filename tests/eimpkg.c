/* SPDX-License-Identifier: GPL-2.0-only
 * The eIM side for the tests: EimConfigurationData and eUICC Packages,
 * signed with a real eIM key the way the eIM signs them (2.11). */
#include <string.h>
#include "eimpkg.h"
#include "hex.h"

/* EimConfigurationData { 80 id, 81 fqdn, 83 counter, A5 { A0 <SPKI content> } } */
void eimpkg_cfg_ex(dbuf *b, const char *id, const char *fqdn, int64_t counter, crypto_key *k,
                   bool want_token, crypto_key *tls)
{
	uint8_t spki[128];
	int n = crypto_key_spki(k, spki, sizeof(spki));
	der_tlv s;
	size_t m = der_begin(b, 0x30), a;

	der_put_str(b, 0x80, id);
	if (fqdn)
		der_put_str(b, 0x81, fqdn);
	der_put_int(b, 0x83, counter);
	if (want_token)
		der_put_int(b, 0x84, -1);
	der_parse(spki, (size_t)n, &s);
	a = der_begin(b, 0xA5);
	der_put(b, 0xA0, s.val, s.len);   /* eimPublicKey, implicitly tagged SPKI */
	der_end(b, a);
	if (tls) {
		/* trustedPublicKeyDataTls [6] { trustedEimPkTls [0] } */
		n = crypto_key_spki(tls, spki, sizeof(spki));
		der_parse(spki, (size_t)n, &s);
		a = der_begin(b, 0xA6);
		der_put(b, 0xA0, s.val, s.len);
		der_end(b, a);
	}
	der_end(b, m);
}

void eimpkg_cfg(dbuf *b, const char *id, int64_t counter, crypto_key *k, bool want_token)
{
	eimpkg_cfg_ex(b, id, "eim.test.example:8443", counter, k, want_token, NULL);
}

/* BF51 { 30 {80 id, 5A eid, 81 counter, 82 txid, A0|A1 {ops}}, 5F37 sig } */
void eimpkg_package(dbuf *b, const char *id, const uint8_t *eid, int64_t counter, uint32_t list,
                    const dbuf *ops, crypto_key *signer, int64_t token, bool corrupt)
{
	dbuf sd, in;
	uint8_t sig[64], txid[16];
	size_t m;

	memset(txid, 0x11, sizeof(txid));
	db_init(&sd);
	m = der_begin(&sd, 0x30);
	der_put_str(&sd, 0x80, id);
	der_put(&sd, 0x5A, eid, 16);
	der_put_int(&sd, 0x81, counter);
	der_put(&sd, 0x82, txid, sizeof(txid));
	der_put(&sd, list, ops->d, ops->len);
	der_end(&sd, m);

	db_init(&in);
	db_put(&in, sd.d, sd.len);
	der_put_int(&in, 0x84, token);   /* 84 01 00 without a token (2.11) */
	crypto_sign(signer, in.d, in.len, sig);
	if (corrupt)
		sig[0] ^= 1;

	m = der_begin(b, 0xBF51);
	db_put(b, sd.d, sd.len);
	der_put(b, 0x5F37, sig, sizeof(sig));
	der_end(b, m);
	db_free(&sd);
	db_free(&in);
}

void eimpkg_op(dbuf *ops, uint32_t tag, const char *iccid, bool rollback)
{
	uint8_t ic[10];
	size_t m = der_begin(ops, tag);

	hex_decode(iccid, ic, 10);
	der_put(ops, 0x5A, ic, 10);
	if (rollback)
		der_put_null(ops, 0x05);
	der_end(ops, m);
}

