/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 André Valentin <avalentin@marcant.net>
 */
#include <stdlib.h>
#include <string.h>
#include "der.h"

static int tag_octets(uint32_t tag)
{
	if (tag > 0xFFFFFF) return 4;
	if (tag > 0xFFFF) return 3;
	if (tag > 0xFF) return 2;
	return 1;
}

bool der_constructed(uint32_t tag)
{
	return (tag >> ((tag_octets(tag) - 1) * 8)) & 0x20;
}

int der_next(const uint8_t **pp, const uint8_t *end, der_tlv *out)
{
	const uint8_t *p = *pp;
	uint32_t tag;
	size_t len;

	if (p >= end)
		return -1;

	tag = *p++;

	/* high tag number form: further octets while bit 8 is set (X.690 8.1.2.4) */
	if ((tag & 0x1F) == 0x1F) {
		int n = 0;

		do {
			if (p >= end || ++n > 3)
				return -1;
			tag = (tag << 8) | *p;
		} while (*p++ & 0x80);
	}

	if (p >= end)
		return -1;

	if (*p < 0x80) {
		len = *p++;
	} else {
		int n = *p++ & 0x7F;

		if (n == 0 || n > 4 || end - p < n)
			return -1;   /* indefinite or oversized */

		for (len = 0; n--; )
			len = (len << 8) | *p++;
	}

	if ((size_t)(end - p) < len)
		return -1;

	out->tag = tag;
	out->val = p;
	out->len = len;
	out->raw = *pp;
	out->raw_len = (size_t)(p - *pp) + len;
	*pp = p + len;
	return 0;
}

int der_parse(const uint8_t *p, size_t len, der_tlv *out)
{
	const uint8_t *q = p;

	if (der_next(&q, p + len, out) < 0 || q != p + len)
		return -1;
	return 0;
}

int der_find(const uint8_t *p, size_t len, uint32_t tag, der_tlv *out)
{
	const uint8_t *end = p + len;

	while (p < end) {
		if (der_next(&p, end, out) < 0)
			return -1;
		if (out->tag == tag)
			return 0;
	}
	return -1;
}

int der_get_int(const der_tlv *t, int64_t *v)
{
	uint64_t u;
	size_t i;

	if (t->len < 1 || t->len > 8)
		return -1;

	u = (t->val[0] & 0x80) ? ~(uint64_t)0 : 0;   /* sign extension */
	for (i = 0; i < t->len; i++)
		u = (u << 8) | t->val[i];
	*v = (int64_t)u;
	return 0;
}

/* --- writer ---------------------------------------------------------------- */

void db_init(dbuf *b)
{
	memset(b, 0, sizeof(*b));
}

void db_free(dbuf *b)
{
	free(b->d);
	db_init(b);
}

static int db_reserve(dbuf *b, size_t n)
{
	if (b->err)
		return -1;

	if (b->len + n > b->cap) {
		size_t cap = b->cap ? b->cap : 256;
		uint8_t *d;

		while (cap < b->len + n)
			cap *= 2;
		d = realloc(b->d, cap);
		if (!d) {
			b->err = 1;
			return -1;
		}
		b->d = d;
		b->cap = cap;
	}
	return 0;
}

void db_put(dbuf *b, const void *p, size_t n)
{
	if (!n || db_reserve(b, n) < 0)
		return;
	memcpy(b->d + b->len, p, n);
	b->len += n;
}

static void put_tag(dbuf *b, uint32_t tag)
{
	uint8_t t[4];
	int n = tag_octets(tag), i;

	for (i = 0; i < n; i++)
		t[i] = (uint8_t)(tag >> ((n - 1 - i) * 8));
	db_put(b, t, (size_t)n);
}

static size_t len_octets(size_t len)
{
	if (len < 0x80) return 1;
	if (len <= 0xFF) return 2;
	if (len <= 0xFFFF) return 3;
	if (len <= 0xFFFFFF) return 4;
	return 5;
}

static void put_len_at(uint8_t *p, size_t len)
{
	size_t n = len_octets(len), i;

	if (n == 1) {
		p[0] = (uint8_t)len;
		return;
	}
	p[0] = (uint8_t)(0x80 | (n - 1));
	for (i = 1; i < n; i++)
		p[i] = (uint8_t)(len >> ((n - 1 - i) * 8));
}

void der_put(dbuf *b, uint32_t tag, const void *val, size_t len)
{
	uint8_t l[5];

	put_tag(b, tag);
	put_len_at(l, len);
	db_put(b, l, len_octets(len));
	db_put(b, val, len);
}

/* The length is not known when a constructed value is opened. One octet is
 * reserved and the content moved up when it turns out to need more: cheaper
 * than a two-pass encoder, and the moves are bounded by the nesting depth. */
size_t der_begin(dbuf *b, uint32_t tag)
{
	uint8_t z = 0;

	put_tag(b, tag);
	db_put(b, &z, 1);
	return b->len;   /* content starts here */
}

void der_end(dbuf *b, size_t mark)
{
	size_t len, n;

	if (b->err || mark > b->len)
		return;

	len = b->len - mark;
	n = len_octets(len);

	if (n > 1) {
		if (db_reserve(b, n - 1) < 0)
			return;
		memmove(b->d + mark + n - 1, b->d + mark, len);
		b->len += n - 1;
	}
	put_len_at(b->d + mark - 1, len);
}

void der_put_int(dbuf *b, uint32_t tag, int64_t v)
{
	uint8_t o[8];
	int i, s = 0;

	for (i = 0; i < 8; i++)
		o[i] = (uint8_t)((uint64_t)v >> ((7 - i) * 8));

	/* minimal two's complement (X.690 8.3.2): drop a leading octet while it
	 * and the next octet's top bit carry the same sign */
	while (s < 7 && ((o[s] == 0x00 && !(o[s + 1] & 0x80)) ||
	                 (o[s] == 0xFF && (o[s + 1] & 0x80))))
		s++;
	der_put(b, tag, o + s, (size_t)(8 - s));
}

void der_put_null(dbuf *b, uint32_t tag)
{
	der_put(b, tag, NULL, 0);
}

void der_put_bool(dbuf *b, uint32_t tag, bool v)
{
	uint8_t o = v ? 0xFF : 0x00;   /* X.690 11.1: DER TRUE is all ones */

	der_put(b, tag, &o, 1);
}

void der_put_str(dbuf *b, uint32_t tag, const char *s)
{
	der_put(b, tag, s, strlen(s));
}

void der_put_bits(dbuf *b, uint32_t tag, const uint8_t *bits, size_t nbits)
{
	uint8_t o[33] = { 0 };
	size_t last = 0, i, nbytes;
	bool any = false;

	if (nbits > 256)
		nbits = 256;

	for (i = 0; i < nbits; i++)
		if (bits[i]) {
			o[1 + i / 8] |= (uint8_t)(0x80 >> (i % 8));
			last = i;
			any = true;
		}

	if (!any) {
		o[0] = 0;
		der_put(b, tag, o, 1);
		return;
	}

	nbytes = last / 8 + 1;
	o[0] = (uint8_t)(7 - last % 8);   /* unused bits in the final octet */
	der_put(b, tag, o, nbytes + 1);
}
