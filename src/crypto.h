/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 André Valentin <avalentin@marcant.net>
 *
 * The signatures RSP uses: ECDSA with SHA-256 over NIST P-256 or
 * brainpoolP256r1, carried as the plain concatenation r || s (64 octets for
 * these curves), not as a DER ECDSA-Sig-Value. That is the format of
 * eimSignature, euiccSignEPR/EPE and the SGP.22 signatures (SGP.22 v2.7
 * section 2.6.2, BSI TR-03111 plain format); the eIM produces and checks the
 * same (eim-crypto signer.rs sign_raw / verify_raw).
 */
#ifndef IPAD_CRYPTO_H
#define IPAD_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define CRYPTO_SIG_LEN 64

typedef struct crypto_key crypto_key;

/* a public key from a DER SubjectPublicKeyInfo, or from a DER X.509
 * certificate (then its subjectPublicKeyInfo); NULL on anything else,
 * including a curve other than P-256 / brainpoolP256r1 */
crypto_key *crypto_pub_from_spki(const uint8_t *der, size_t len);
crypto_key *crypto_pub_from_cert(const uint8_t *der, size_t len);

/* a new P-256 private key, or one loaded from / saved to a DER file
 * (SEC1 ECPrivateKey; saved with mode 0600, written atomically) */
/* The certificate's SubjectPublicKeyInfo (any algorithm: this is for a TLS
 * pin, not a signature) and whether basicConstraints marks it a CA. Returns
 * the SPKI length, -1 when the certificate does not parse or out is short. */
int crypto_cert_spki(const uint8_t *der, size_t len, uint8_t *out, size_t cap, int *is_ca);

crypto_key *crypto_key_generate(void);
crypto_key *crypto_key_load(const char *path);
/* a private key from DER in memory: SEC1 or PKCS#8 (the eIM's bundle, D-69) */
crypto_key *crypto_key_parse(const uint8_t *der, size_t len);
int crypto_key_save(const crypto_key *k, const char *path);

void crypto_key_free(crypto_key *k);

/* DER SubjectPublicKeyInfo of a key; returns the length, -1 on error */
int crypto_key_spki(const crypto_key *k, uint8_t *out, size_t cap);

/* ECDSA-SHA256 over msg; sig is r || s, 64 octets */
int crypto_sign(const crypto_key *k, const uint8_t *msg, size_t len, uint8_t sig[CRYPTO_SIG_LEN]);
/* 0 when the signature is valid, -1 otherwise (any malformed input included) */
int crypto_verify(const crypto_key *k, const uint8_t *msg, size_t len, const uint8_t *sig, size_t sig_len);

void crypto_sha256(const uint8_t *msg, size_t len, uint8_t out[32]);

#endif
