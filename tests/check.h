/* SPDX-License-Identifier: GPL-2.0-only
 * Minimal check helpers, the same verdict line the wwand ucode suites print. */
#ifndef IPAD_CHECK_H
#define IPAD_CHECK_H
#include <stdio.h>
#include <string.h>

static int checks, failures;

#define OK(cond, msg) do { checks++; if (!(cond)) { failures++; \
	fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); } } while (0)

#define EQ_HEX(got, glen, want, wlen, msg) do { checks++; \
	if ((glen) != (wlen) || memcmp(got, want, wlen)) { failures++; \
		fprintf(stderr, "FAIL: %s (%s:%d)\n  got:  ", msg, __FILE__, __LINE__); \
		for (size_t _i = 0; _i < (size_t)(glen); _i++) fprintf(stderr, "%02x", ((const unsigned char *)(got))[_i]); \
		fprintf(stderr, "\n  want: "); \
		for (size_t _i = 0; _i < (size_t)(wlen); _i++) fprintf(stderr, "%02x", ((const unsigned char *)(want))[_i]); \
		fprintf(stderr, "\n"); } } while (0)

#define DONE(name) do { printf("%s: %d checks, %d failures\n", name, checks, failures); \
	return failures ? 1 : 0; } while (0)

#endif
