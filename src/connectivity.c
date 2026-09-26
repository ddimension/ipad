/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 André Valentin <avalentin@marcant.net>
 */
#include <string.h>
#include "connectivity.h"

/* GSM 03.38 default alphabet, the basic table, as the octets a login or a
 * password can realistically contain; everything outside it becomes '?'
 * rather than a byte the modem would be handed unchanged */
static const char gsm7[128] =
	"@\xA3$\xA5\xE8\xE9\xF9\xEC\xF2\xC7\n\xD8\xF8\r\xC5\xE5"
	"?_?????????\x1B\xC6\xE6\xDF\xC9"       /* 0x10 delta, 0x11 '_', 0x12-0x1A greek */
	" !\"#\xA4%&'()*+,-./0123456789:;<=>?"
	"\xA1" "ABCDEFGHIJKLMNOPQRSTUVWXYZ\xC4\xD6\xD1\xDC\xA7"
	"\xBF" "abcdefghijklmnopqrstuvwxyz\xE4\xF6\xF1\xFC\xE0";

static char gsm_char(uint8_t c)
{
	char a = gsm7[c & 0x7F];

	/* only the ASCII part is passed on: credentials go into a config file
	 * and a command line, and a Latin-1 byte there helps nobody */
	return ((unsigned char)a >= 0x20 && (unsigned char)a < 0x7F) ? a : '?';
}

static void put(char *out, size_t cap, size_t *n, char c)
{
	if (*n + 1 < cap)
		out[(*n)++] = c;
	out[*n] = '\0';
}

/* TS 102 223 8.15: data coding scheme octet, then the text */
static int text_string(const uint8_t *p, size_t len, char *out, size_t cap)
{
	size_t n = 0, i;

	out[0] = '\0';
	if (len == 0)
		return 0;   /* a null text string */

	switch (p[0] & 0x0C) {   /* TS 23.038 alphabet bits: 00 7-bit, 04 8-bit, 08 UCS2 */
	case 0x04:
		for (i = 1; i < len; i++)
			put(out, cap, &n, gsm_char(p[i]));
		return 0;

	case 0x08:   /* UCS2 big endian; only the ASCII range is kept */
		for (i = 1; i + 1 < len; i += 2)
			put(out, cap, &n, (p[i] == 0 && p[i + 1] >= 0x20 && p[i + 1] < 0x7F) ? (char)p[i + 1] : '?');
		return 0;

	default: {   /* 7-bit packed: septets, least significant bits first */
		size_t bits = (len - 1) * 8, s;

		for (s = 0; s + 7 <= bits; s += 7) {
			size_t o = 1 + s / 8, sh = s % 8;
			unsigned v = p[o] >> sh;

			if (sh > 1 && o + 1 < len)
				v |= (unsigned)p[o + 1] << (8 - sh);
			put(out, cap, &n, gsm_char((uint8_t)(v & 0x7F)));
		}
		/* a trailing CR fills the last 7 spare bits (TS 23.038 6.1.2.3.1) */
		if (n && out[n - 1] == '\r')
			out[--n] = '\0';
		return 0;
	}
	}
}

/* TS 23.003 9.1: length-prefixed labels, joined with dots */
static int apn_decode(const uint8_t *p, size_t len, char *out, size_t cap)
{
	size_t i = 0, n = 0;

	out[0] = '\0';
	if (len == 0 || len > 100)
		return len == 0 ? 0 : -1;

	while (i < len) {
		size_t l = p[i++];

		if (l == 0 || i + l > len)
			return -1;
		if (n)
			put(out, cap, &n, '.');
		while (l--) {
			uint8_t c = p[i++];

			/* APN labels: letters, digits, hyphen (TS 23.003 9.1) — refuse
			 * anything that would not be one */
			if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			      (c >= '0' && c <= '9') || c == '-'))
				return -1;
			put(out, cap, &n, (char)c);
		}
	}
	return 0;
}

static const char *pdp_24008(uint8_t v)
{
	switch (v) {
	case 0x21: return "ipv4";
	case 0x57: return "ipv6";
	case 0x8D: return "ipv4v6";
	}
	return NULL;
}

static void bearer_decode(const uint8_t *p, size_t len, conn_params *o)
{
	if (len < 1)
		return;

	o->bearer = p[0];

	switch (p[0]) {
	case 0x02:   /* GPRS / UTRAN packet service, 8.52.2: byte 9 = value index 6 */
		if (len >= 7)
			o->pdp_type = (p[6] == 0x02) ? "ipv4" : (p[6] == 0x07) ? "non-ip" : NULL;
		break;

	case 0x09:   /* UTRAN extended / HSDPA / E-UTRAN, 8.52.3: PDP_type is the last byte */
	case 0x0B:   /* E-UTRAN / mapped UTRAN, 8.52.5: byte X+3, the last one */
		if (len >= 2)
			o->pdp_type = pdp_24008(p[len - 1]);
		break;

	case 0x0C: { /* NG-RAN, 8.52.6: byte 4 = value index 1, bits 3..1 */
		static const char *pdu[8] = { "ipv4v6", "ipv4", "ipv6", "ipv4v6",
		                              NULL, NULL, "ipv4v6", "ipv4v6" };

		if (len >= 2)
			o->pdp_type = pdu[p[1] & 7];   /* 4 Unstructured, 5 Ethernet: no IP type */
		break;
	}
	}
}

int conn_parse(const uint8_t *p, size_t len, conn_params *o)
{
	const uint8_t *end = p + len;
	int texts = 0;

	memset(o, 0, sizeof(*o));
	o->bearer = -1;

	/* tolerate the profile-side wrapper 'A1' (Table 2) around the TLVs */
	if (len >= 2 && p[0] == 0xA1) {
		size_t l = p[1], h = 2;

		if (l == 0x81 && len >= 3) {
			l = p[2];
			h = 3;
		}
		if (h + l != len)
			return -1;
		p += h;
	}

	while (p < end) {
		uint8_t tag = p[0] & 0x7F;   /* CR bit is bit 8 (TS 101 220) */
		size_t l, h = 2;

		if (end - p < 2)
			return -1;
		l = p[1];
		if (l == 0x81) {   /* TS 101 220: 128..255 as '81' xx */
			if (end - p < 3)
				return -1;
			l = p[2];
			h = 3;
		} else if (l > 0x7F) {
			return -1;
		}
		if ((size_t)(end - p) < h + l)
			return -1;

		switch (tag) {
		case 0x35:
			bearer_decode(p + h, l, o);
			break;
		case 0x47:
			if (apn_decode(p + h, l, o->apn, sizeof(o->apn)) < 0)
				return -1;
			break;
		case 0x0D:   /* first text string is the login, second the password */
			text_string(p + h, l, texts == 0 ? o->username : o->password,
			            texts == 0 ? sizeof(o->username) : sizeof(o->password));
			texts++;
			break;
		default:
			break;   /* other COMPREHENSION-TLVs: not ours, skipped */
		}
		p += h + l;
	}
	return 0;
}
