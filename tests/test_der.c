/* SPDX-License-Identifier: GPL-2.0-only
 * der.c: the reader/writer against hand-built cases and, round trip, against
 * every byte-exact vector of the eIM (checked against pycrate there). */
#include <stdlib.h>
#include "check.h"
#include "der.h"
#include "hex.h"
#include "vectors.h"

/* re-encode a TLV tree through the writer: constructed values are rebuilt
 * with der_begin/der_end, primitives copied */
static int reencode(dbuf *b, const uint8_t *p, size_t len)
{
	const uint8_t *end = p + len;
	der_tlv t;

	while (p < end) {
		if (der_next(&p, end, &t) < 0)
			return -1;
		if (der_constructed(t.tag)) {
			size_t m = der_begin(b, t.tag);

			if (reencode(b, t.val, t.len) < 0)
				return -1;
			der_end(b, m);
		} else {
			der_put(b, t.tag, t.val, t.len);
		}
	}
	return 0;
}

int main(void)
{
	uint8_t buf[8192];
	dbuf b;
	der_tlv t;
	int64_t v;
	size_t i;

	/* INTEGER minimal encodings (X.690 8.3.2) */
	struct { int64_t v; const char *hex; } ints[] = {
		{ 0, "020100" }, { 127, "02017F" }, { 128, "02020080" }, { 255, "020200FF" },
		{ 256, "02020100" }, { -1, "0201FF" }, { -128, "020180" }, { -129, "0202FF7F" },
		{ 65536, "0203010000" },
	};
	for (i = 0; i < sizeof(ints) / sizeof(ints[0]); i++) {
		int n = hex_decode(ints[i].hex, buf, sizeof(buf));

		db_init(&b);
		der_put_int(&b, 0x02, ints[i].v);
		EQ_HEX(b.d, b.len, buf, (size_t)n, "int: minimal two's complement");
		OK(der_parse(b.d, b.len, &t) == 0 && der_get_int(&t, &v) == 0 && v == ints[i].v,
		   "int: reads back");
		db_free(&b);
	}

	/* long lengths are minimal, and nested constructed values back-patch */
	db_init(&b);
	{
		size_t o = der_begin(&b, 0xBF51), in = der_begin(&b, 0x30);
		uint8_t big[300];

		memset(big, 0xAB, sizeof(big));
		der_put(&b, 0x80, big, 200);
		der_end(&b, in);
		der_put(&b, 0x5F37, big, 300);
		der_end(&b, o);
	}
	/* content: 30 81 CB (80 81 C8 + 200) = 206, 5F 37 82 01 2C + 300 = 305 -> 511 */
	OK(b.len == 5 + 511 && b.d[0] == 0xBF && b.d[1] == 0x51 &&
	   b.d[2] == 0x82 && b.d[3] == 0x01 && b.d[4] == 0xFF && b.d[5] == 0x30 && b.d[6] == 0x81 &&
	   b.d[7] == 0xCB,
	   "lengths: 0x82 form for 511 octets of content, 0x81 form inside");
	OK(der_parse(b.d, b.len, &t) == 0 && t.tag == 0xBF51 && t.len == 511, "lengths: reads back");
	OK(der_find(t.val, t.len, 0x5F37, &t) == 0 && t.len == 300, "find: two-octet tag 5F37");
	db_free(&b);

	/* BIT STRING: trailing zero bits dropped (X.690 11.2.2) */
	{
		uint8_t bits[10] = { 1, 0, 1, 0, 0, 0, 0, 0, 0, 0 };
		uint8_t want[] = { 0x83, 0x02, 0x05, 0xA0 };

		db_init(&b);
		der_put_bits(&b, 0x83, bits, 10);
		EQ_HEX(b.d, b.len, want, sizeof(want), "bits: {0,2} -> 05 A0");
		db_free(&b);
	}

	/* malformed input is refused, not read past */
	{
		uint8_t trunc[] = { 0xBF, 0x51, 0x05, 0x80, 0x01 };
		uint8_t indef[] = { 0x30, 0x80, 0x00, 0x00 };
		uint8_t longtag[] = { 0xBF, 0x81, 0x81, 0x81, 0x01, 0x00 };

		OK(der_parse(trunc, sizeof(trunc), &t) < 0, "malformed: truncated value");
		OK(der_parse(indef, sizeof(indef), &t) < 0, "malformed: indefinite length");
		OK(der_parse(longtag, sizeof(longtag), &t) < 0, "malformed: tag longer than 4 octets");
	}

	/* a length that would wrap len + n is refused, not copied: the chunked
	 * reader once handed db_put a peer's SIZE_MAX-ish chunk size */
	{
		uint8_t x[4] = { 1, 2, 3, 4 };

		db_init(&b);
		db_put(&b, x, sizeof(x));
		db_put(&b, x, SIZE_MAX);
		OK(b.err && b.len == 4, "db_put: len + n wrapping is refused");
		db_put(&b, x, 1);
		OK(b.len == 4, "db_put: the error is sticky");
		db_free(&b);
	}

	/* every eIM vector: parse fully and re-encode to the identical bytes */
	for (i = 0; i < sizeof(VECTORS) / sizeof(VECTORS[0]); i++) {
		int n = hex_decode(VECTORS[i].hex, buf, sizeof(buf));
		char msg[160];

		snprintf(msg, sizeof(msg), "vector %s %s %s: round trip", VECTORS[i].file,
		         VECTORS[i].type, VECTORS[i].label);
		OK(n > 0, "vector decodes as hex");
		db_init(&b);
		OK(reencode(&b, buf, (size_t)n) == 0, msg);
		EQ_HEX(b.d, b.len, buf, (size_t)n, msg);
		db_free(&b);
	}

	DONE("test_der");
}
