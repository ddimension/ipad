/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 André Valentin <avalentin@marcant.net>
 */
#include <string.h>
#include "hex.h"

static int nib(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

int hex_decode(const char *s, uint8_t *out, size_t cap)
{
	size_t n = strlen(s), i;

	if (n % 2 || n / 2 > cap)
		return -1;
	for (i = 0; i < n / 2; i++) {
		int h = nib(s[2 * i]), l = nib(s[2 * i + 1]);

		if (h < 0 || l < 0)
			return -1;
		out[i] = (uint8_t)(h << 4 | l);
	}
	return (int)(n / 2);
}

void hex_encode(const uint8_t *p, size_t n, char *out)
{
	static const char d[] = "0123456789ABCDEF";
	size_t i;

	for (i = 0; i < n; i++) {
		out[2 * i] = d[p[i] >> 4];
		out[2 * i + 1] = d[p[i] & 15];
	}
	out[2 * n] = '\0';
}
