/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 André Valentin <avalentin@marcant.net>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <mbedtls/pk.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/sha256.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include "crypto.h"

struct crypto_key {
	mbedtls_pk_context pk;
};

static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context drbg;
static int rng_ready;

static int rng(void *ctx, unsigned char *out, size_t len)
{
	(void)ctx;

	if (!rng_ready) {
		mbedtls_entropy_init(&entropy);
		mbedtls_ctr_drbg_init(&drbg);
		if (mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
		                          (const unsigned char *)"ipad", 4) != 0)
			return -1;
		rng_ready = 1;
	}
	return mbedtls_ctr_drbg_random(&drbg, out, len);
}

/* only the two curves RSP uses; anything else is refused rather than trusted */
static int curve_ok(const mbedtls_pk_context *pk)
{
	mbedtls_ecp_group_id g;

	if (!mbedtls_pk_can_do(pk, MBEDTLS_PK_ECKEY))
		return 0;
	g = mbedtls_pk_ec(*pk)->MBEDTLS_PRIVATE(grp).id;
	return g == MBEDTLS_ECP_DP_SECP256R1 || g == MBEDTLS_ECP_DP_BP256R1;
}

static crypto_key *key_new(void)
{
	crypto_key *k = calloc(1, sizeof(*k));

	if (k)
		mbedtls_pk_init(&k->pk);
	return k;
}

void crypto_key_free(crypto_key *k)
{
	if (!k)
		return;
	mbedtls_pk_free(&k->pk);
	free(k);
}

crypto_key *crypto_pub_from_spki(const uint8_t *der, size_t len)
{
	crypto_key *k = key_new();

	if (!k || mbedtls_pk_parse_public_key(&k->pk, der, len) != 0 || !curve_ok(&k->pk)) {
		crypto_key_free(k);
		return NULL;
	}
	return k;
}

crypto_key *crypto_pub_from_cert(const uint8_t *der, size_t len)
{
	mbedtls_x509_crt crt;
	uint8_t spki[256];
	crypto_key *k = NULL;
	int n;

	mbedtls_x509_crt_init(&crt);

	if (mbedtls_x509_crt_parse_der(&crt, der, len) == 0) {
		/* the certificate's key, re-encoded as SPKI and parsed on its own, so
		 * the returned key does not borrow from the certificate */
		n = mbedtls_pk_write_pubkey_der(&crt.pk, spki, sizeof(spki));
		if (n > 0)
			k = crypto_pub_from_spki(spki + sizeof(spki) - n, (size_t)n);
	}

	mbedtls_x509_crt_free(&crt);
	return k;
}

int crypto_cert_spki(const uint8_t *der, size_t len, uint8_t *out, size_t cap, int *is_ca)
{
	mbedtls_x509_crt crt;
	uint8_t spki[512];
	int n = -1;

	mbedtls_x509_crt_init(&crt);
	if (mbedtls_x509_crt_parse_der(&crt, der, len) == 0) {
		n = mbedtls_pk_write_pubkey_der(&crt.pk, spki, sizeof(spki));
		if (n <= 0 || (size_t)n > cap)
			n = -1;
		else
			memcpy(out, spki + sizeof(spki) - n, (size_t)n);
		if (is_ca)
			*is_ca = crt.MBEDTLS_PRIVATE(ca_istrue);
	}
	mbedtls_x509_crt_free(&crt);
	return n;
}

crypto_key *crypto_key_generate(void)
{
	crypto_key *k = key_new();

	if (!k)
		return NULL;

	if (mbedtls_pk_setup(&k->pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) != 0 ||
	    mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(k->pk), rng, NULL) != 0) {
		crypto_key_free(k);
		return NULL;
	}
	return k;
}

crypto_key *crypto_key_load(const char *path)
{
	uint8_t buf[512];
	FILE *f = fopen(path, "rb");
	size_t n;
	crypto_key *k;

	if (!f)
		return NULL;
	n = fread(buf, 1, sizeof(buf), f);
	fclose(f);

	k = key_new();
	if (!k || mbedtls_pk_parse_key(&k->pk, buf, n, NULL, 0, rng, NULL) != 0 || !curve_ok(&k->pk)) {
		crypto_key_free(k);
		k = NULL;
	}
	memset(buf, 0, sizeof(buf));
	return k;
}

/* written to a temporary file created 0600 and renamed over the target, so a
 * crash leaves either the old key or the new one, never half of one, and the
 * key is never readable by others for a moment */
int crypto_key_save(const crypto_key *k, const char *path)
{
	uint8_t buf[512];
	char tmp[4096];
	int n, fd, rc = -1;

	n = mbedtls_pk_write_key_der((mbedtls_pk_context *)&k->pk, buf, sizeof(buf));
	if (n <= 0 || snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp))
		return -1;

	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd >= 0) {
		if (write(fd, buf + sizeof(buf) - n, (size_t)n) == n && fsync(fd) == 0)
			rc = 0;
		close(fd);
		if (rc == 0 && rename(tmp, path) != 0)
			rc = -1;
		if (rc != 0)
			unlink(tmp);
	}
	memset(buf, 0, sizeof(buf));
	return rc;
}

int crypto_key_spki(const crypto_key *k, uint8_t *out, size_t cap)
{
	uint8_t buf[256];
	int n = mbedtls_pk_write_pubkey_der((mbedtls_pk_context *)&k->pk, buf, sizeof(buf));

	if (n <= 0 || (size_t)n > cap)
		return -1;
	memcpy(out, buf + sizeof(buf) - n, (size_t)n);
	return n;
}

void crypto_sha256(const uint8_t *msg, size_t len, uint8_t out[32])
{
	mbedtls_sha256(msg, len, out, 0);
}

int crypto_sign(const crypto_key *k, const uint8_t *msg, size_t len, uint8_t sig[CRYPTO_SIG_LEN])
{
	mbedtls_ecp_keypair *ec = mbedtls_pk_ec(k->pk);
	mbedtls_mpi r, s;
	uint8_t h[32];
	int rc = -1;

	crypto_sha256(msg, len, h);
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	if (mbedtls_ecdsa_sign(&ec->MBEDTLS_PRIVATE(grp), &r, &s, &ec->MBEDTLS_PRIVATE(d),
	                       h, sizeof(h), rng, NULL) == 0 &&
	    mbedtls_mpi_write_binary(&r, sig, 32) == 0 &&
	    mbedtls_mpi_write_binary(&s, sig + 32, 32) == 0)
		rc = 0;

	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	return rc;
}

int crypto_verify(const crypto_key *k, const uint8_t *msg, size_t len, const uint8_t *sig, size_t sig_len)
{
	mbedtls_ecp_keypair *ec;
	mbedtls_mpi r, s;
	uint8_t h[32];
	int rc = -1;

	if (!k || sig_len != CRYPTO_SIG_LEN)
		return -1;

	ec = mbedtls_pk_ec(k->pk);
	crypto_sha256(msg, len, h);
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	if (mbedtls_mpi_read_binary(&r, sig, 32) == 0 &&
	    mbedtls_mpi_read_binary(&s, sig + 32, 32) == 0 &&
	    mbedtls_ecdsa_verify(&ec->MBEDTLS_PRIVATE(grp), h, sizeof(h),
	                         &ec->MBEDTLS_PRIVATE(Q), &r, &s) == 0)
		rc = 0;

	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	return rc;
}
