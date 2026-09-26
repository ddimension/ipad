/* SPDX-License-Identifier: GPL-2.0-only
 * crypto.c against OpenSSL-made fixtures (tests/gen_fixtures.sh): signatures
 * verify for P-256 and brainpoolP256r1, from SPKI and from a certificate; its
 * own signatures verify; anything altered does not. */
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
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

		/* a stale temporary that is a link is removed, not written
		 * through: the key lands in the target, the link's file is
		 * untouched; the key file is 0600 whatever the umask */
		{
			char tmp[64], bait[] = "/tmp/ipad-test-bait-XXXXXX";
			struct stat st;
			mode_t old = umask(0);
			int bfd = mkstemp(bait);

			snprintf(tmp, sizeof(tmp), "%s.tmp", path);
			OK(bfd >= 0 && write(bfd, "bait", 4) == 4, "bait file");
			close(bfd);
			OK(symlink(bait, tmp) == 0, "stale temporary as a link");
			OK(crypto_key_save(k, path) == 0, "save: over a stale linked temporary");
			OK(stat(bait, &st) == 0 && st.st_size == 4, "save: the link's target is untouched");
			OK(lstat(tmp, &st) != 0, "save: no temporary left");
			OK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600, "save: 0600 with umask 0");
			umask(old);
			unlink(path);
			unlink(bait);
		}

		crypto_key_free(k);
		crypto_key_free(pub);
		crypto_key_free(back);
	}

	/* a device key is P-256 and its public point is its own: a brainpool
	 * key, or a SEC1 key carrying another key's point, is refused */
	{
		crypto_key *a = crypto_key_generate(), *b = crypto_key_generate(), *x;
		char pa[] = "/tmp/ipad-test-ka-XXXXXX", pb[] = "/tmp/ipad-test-kb-XXXXXX";
		uint8_t da[256], db[256], pem[1024];
		size_t la = 0, lb = 0, lp;
		FILE *f;

		close(mkstemp(pa));
		close(mkstemp(pb));
		if (crypto_key_save(a, pa) == 0 && (f = fopen(pa, "rb"))) {
			la = fread(da, 1, sizeof(da), f);
			fclose(f);
		}
		if (crypto_key_save(b, pb) == 0 && (f = fopen(pb, "rb"))) {
			lb = fread(db, 1, sizeof(db), f);
			fclose(f);
		}
		unlink(pa);
		unlink(pb);
		OK(la == 121 && lb == 121, "SEC1 P-256 keys with their public point");
		x = crypto_key_parse(da, la);
		OK(x != NULL, "parse: a P-256 key with its own point");
		crypto_key_free(x);
		/* the uncompressed point is the last 65 octets */
		memcpy(da + la - 65, db + lb - 65, 65);
		OK(crypto_key_parse(da, la) == NULL, "parse: another key's public point is refused");

		lp = slurp("brainpoolP256r1.key.pem", pem, sizeof(pem) - 1);
		pem[lp] = 0;
		OK(lp > 0 && crypto_key_parse(pem, lp + 1) == NULL, "parse: a brainpoolP256r1 private key is refused");
		lp = slurp("prime256v1.key.pem", pem, sizeof(pem) - 1);
		pem[lp] = 0;
		x = crypto_key_parse(pem, lp + 1);
		OK(lp > 0 && x != NULL, "parse: a prime256v1 private key (PEM) is taken");
		crypto_key_free(x);
		crypto_key_free(a);
		crypto_key_free(b);
	}

	/* a curve RSP does not use is refused, not trusted */
	{
		uint8_t rsa_spki[] = { 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00 };

		OK(crypto_pub_from_spki(rsa_spki, sizeof(rsa_spki)) == NULL, "spki: not an EC key -> NULL");
	}

	DONE("test_crypto");
}
