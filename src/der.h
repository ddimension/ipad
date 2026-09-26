/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 André Valentin <avalentin@marcant.net>
 *
 * Compact BER reader / DER writer for the GSMA RSP data objects.
 *
 * Tags are kept as their raw identifier octets packed into a uint32_t, exactly
 * as they appear on the wire and as the specifications write them: 0x80,
 * 0xA0, 0x5A, 0x5F37, 0xBF51. Comparing against the spec's "Tag 'BF51'"
 * comments is then a plain equality, and there is no class/number arithmetic
 * to get wrong.
 *
 * The writer produces canonical DER: minimal length octets, minimal INTEGER
 * content, BIT STRING without trailing zero bits. Signatures are computed over
 * these bytes (SGP.32 v1.3 section 2.11: eimSignature over euiccPackageSigned
 * || associationToken, euiccSignEPR over euiccPackageResultDataSigned ||
 * associationToken), so an encoding that is valid BER but not DER would sign
 * the wrong bytes.
 */
#ifndef IPAD_DER_H
#define IPAD_DER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* one decoded TLV; val points into the input, raw covers tag+length+value */
typedef struct {
	uint32_t tag;
	const uint8_t *val;
	size_t len;
	const uint8_t *raw;
	size_t raw_len;
} der_tlv;

/* true when the tag's first octet has the constructed bit */
bool der_constructed(uint32_t tag);

/* Read the TLV at *pp (not past end) and advance *pp behind it. Returns 0, or
 * -1 on malformed or truncated input (then *pp is unchanged). Accepts tags of
 * up to 4 octets and definite lengths of up to 4 length octets; indefinite
 * lengths are refused (DER has none, and nothing in RSP uses them). */
int der_next(const uint8_t **pp, const uint8_t *end, der_tlv *out);

/* Parse exactly one TLV spanning the whole buffer. */
int der_parse(const uint8_t *p, size_t len, der_tlv *out);

/* First child of a constructed value (val/len) with the given tag, 0 if found,
 * -1 if not found or malformed. */
int der_find(const uint8_t *p, size_t len, uint32_t tag, der_tlv *out);

/* INTEGER content (two's complement, 1..8 octets) to int64_t. */
int der_get_int(const der_tlv *t, int64_t *v);

/* --- writer ---------------------------------------------------------------- */

typedef struct {
	uint8_t *d;
	size_t len;
	size_t cap;
	int err;       /* sticky: set on allocation failure, checked once at the end */
} dbuf;

void db_init(dbuf *b);
void db_free(dbuf *b);
void db_put(dbuf *b, const void *p, size_t n);

/* Open a constructed TLV; returns a mark for der_end(). Nesting is unlimited:
 * the length is back-patched to its minimal form when the TLV is closed. */
size_t der_begin(dbuf *b, uint32_t tag);
void der_end(dbuf *b, size_t mark);

void der_put(dbuf *b, uint32_t tag, const void *val, size_t len);
void der_put_int(dbuf *b, uint32_t tag, int64_t v);
void der_put_null(dbuf *b, uint32_t tag);
void der_put_bool(dbuf *b, uint32_t tag, bool v);
void der_put_str(dbuf *b, uint32_t tag, const char *s);
/* BIT STRING from named bits (bit 0 = most significant bit of the first
 * octet, as ASN.1 numbers them); trailing zero bits dropped as DER requires */
void der_put_bits(dbuf *b, uint32_t tag, const uint8_t *bits, size_t nbits);

#endif
