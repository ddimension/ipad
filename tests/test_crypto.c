/* SPDX-License-Identifier: GPL-2.0-only
 * crypto.c against OpenSSL-made fixtures (tests/gen_fixtures.sh): signatures
 * verify for P-256 and brainpoolP256r1, from SPKI and from a certificate; its
 * own signatures verify; anything altered does not. */
#include <stdlib.h>
#include <unistd.h>
#include "check.h"
#include "crypto.h"

static size_t slurp(const char *name, uint8_t *buf, size_t cap)
{
	char p[512];
	FILE *f;
	size_t n;

	snprintf(p, sizeof(p), "%s/%s", FIXTURES, name);
	f = fopen(p, "rb");
	if (!f)
		return 0;
	n = fread(buf, 1, cap, f);
	fclose(f);
	return n;
}

int main(void)
{
	static const char *curves[] = { "prime256v1", "brainpoolP256r1" };
	uint8_t msg[64], der[1024], sig[64], mine[CRYPTO_SIG_LEN], spki[256];
	size_t mlen = slurp("msg.bin", msg, sizeof(msg));
	char name[64];
	int i;

	OK(mlen > 0, "fixtures: message present");

	for (i = 0; i < 2; i++) {
		size_t n, sl;
		crypto_key *k;

		snprintf(name, sizeof(name), "%s.spki.der", curves[i]);
		n = slurp(name, der, sizeof(der));
		k = crypto_pub_from_spki(der, n);
		OK(k != NULL, curves[i]);

		snprintf(name, sizeof(name), "%s.sig.raw", curves[i]);
		sl = slurp(name, sig, sizeof(sig));
		OK(crypto_verify(k, msg, mlen, sig, sl) == 0, "verify: an OpenSSL signature, r||s");

		msg[0] ^= 1;
		OK(crypto_verify(k, msg, mlen, sig, sl) != 0, "verify: a changed message fails");
		msg[0] ^= 1;
		sig[10] ^= 1;
		OK(crypto_verify(k, msg, mlen, sig, sl) != 0, "verify: a changed signature fails");
		sig[10] ^= 1;
		OK(crypto_verify(k, msg, mlen, sig, 63) != 0, "verify: a short signature fails");
		crypto_key_free(k);

		/* the same key out of a certificate */
		snprintf(name, sizeof(name), "%s.cert.der", curves[i]);
		n = slurp(name, der, sizeof(der));
		k = crypto_pub_from_cert(der, n);
		OK(k != NULL && crypto_verify(k, msg, mlen, sig, sl) == 0, "cert: its key verifies the signature");
		crypto_key_free(k);
	}

	/* a generated key: sign, export SPKI, verify through the export, save/load */
	{
		crypto_key *k = crypto_key_generate(), *pub, *back;
		int n;
		char path[] = "/tmp/ipad-test-key-XXXXXX";
		int fd = mkstemp(path);

		OK(k != NULL, "generate: P-256 key");
		OK(crypto_sign(k, msg, mlen, mine) == 0, "sign");
		n = crypto_key_spki(k, spki, sizeof(spki));
		OK(n == 91, "spki: 91 octets for P-256");
		pub = crypto_pub_from_spki(spki, (size_t)n);
		OK(pub && crypto_verify(pub, msg, mlen, mine, sizeof(mine)) == 0, "own signature verifies via SPKI");

		close(fd);
		OK(crypto_key_save(k, path) == 0, "save");
		back = crypto_key_load(path);
		OK(back && crypto_sign(back, msg, mlen, mine) == 0 &&
		   crypto_verify(pub, msg, mlen, mine, sizeof(mine)) == 0, "load: the same key signs");
		unlink(path);

		crypto_key_free(k);
		crypto_key_free(pub);
		crypto_key_free(back);
	}

	/* a curve RSP does not use is refused, not trusted */
	{
		uint8_t rsa_spki[] = { 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00 };

		OK(crypto_pub_from_spki(rsa_spki, sizeof(rsa_spki)) == NULL, "spki: not an EC key -> NULL");
	}

	DONE("test_crypto");
}
