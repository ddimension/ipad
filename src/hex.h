/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 André Valentin <avalentin@marcant.net>
 */
#ifndef IPAD_HEX_H
#define IPAD_HEX_H
#include <stddef.h>
#include <stdint.h>

/* hex text (either case, no separators) to bytes; returns the byte count, or
 * -1 on an odd length, a non-hex character or an output buffer too small */
int hex_decode(const char *s, uint8_t *out, size_t cap);
/* bytes to upper-case hex; out needs 2*n+1 */
void hex_encode(const uint8_t *p, size_t n, char *out);

#endif
