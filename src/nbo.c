/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 André Valentin <avalentin@marcant.net>
 *
 * The notification backoff (nbo.h). The file is text, so an operator can
 * read it on a router:
 *
 *   ipad-nbo/1 <eIM configurations, 16 hex digits>
 *   <seqNumber> <due, seconds> <delay, seconds> <notification, 16 hex digits>
 *   ...
 */
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "nbo.h"
#include "crypto.h"
#include "hex.h"

#define NBO_MAGIC "ipad-nbo/1"

void nbo_fp(const uint8_t *der, size_t len, uint8_t out[8])
{
	uint8_t h[32];

	crypto_sha256(der, len, h);
	memcpy(out, h, 8);
}

static void save(const nbo *b)
{
	char tmp[600], hx[17];
	FILE *f;
	int i, fd, ok;

	if (!b->path)
		return;
	if (!b->n) {
		remove(b->path);
		return;
	}
	if (snprintf(tmp, sizeof(tmp), "%s.tmp", b->path) >= (int)sizeof(tmp))
		return;
	/* 0600 like the emulation's state, whatever the umask: the records
	 * tell which notifications an eIM refuses, which is nobody else's
	 * business on a shared router. O_NOFOLLOW: a link planted at the
	 * temporary name must not redirect the write; fchmod: a temporary a
	 * crash left behind keeps its old mode under O_TRUNC. */
	fd = open(tmp, O_CREAT | O_TRUNC | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0)
		return;
	if (fchmod(fd, 0600) != 0 || !(f = fdopen(fd, "w"))) {
		close(fd);
		remove(tmp);
		return;
	}
	hex_encode(b->eims, 8, hx);
	fprintf(f, NBO_MAGIC " %s\n", hx);
	for (i = 0; i < b->n; i++) {
		hex_encode(b->r[i].fp, 8, hx);
		fprintf(f, "%" PRId64 " %" PRId64 " %" PRId64 " %s\n", b->r[i].seq, b->r[i].due, b->r[i].delay, hx);
	}
	ok = fflush(f) == 0 && !ferror(f) && fsync(fileno(f)) == 0;
	if (fclose(f) != 0 || !ok || rename(tmp, b->path) != 0)
		remove(tmp);
}

void nbo_load(nbo *b, const char *path)
{
	char line[128], hx[20];
	FILE *f;

	memset(b, 0, sizeof(*b));
	b->path = path;
	if (!path || !(f = fopen(path, "r")))
		return;
	if (fgets(line, sizeof(line), f) && sscanf(line, NBO_MAGIC " %16s", hx) == 1 && strlen(hx) == 16 &&
	    hex_decode(hx, b->eims, 8) == 8) {
		b->has_eims = true;
		while (b->n < NBO_MAX && fgets(line, sizeof(line), f)) {
			nbo_rec *r = &b->r[b->n];

			if (sscanf(line, "%" SCNd64 " %" SCNd64 " %" SCNd64 " %16s", &r->seq, &r->due, &r->delay, hx) == 4 &&
			    strlen(hx) == 16 && hex_decode(hx, r->fp, 8) == 8 && r->delay > 0)
				b->n++;
		}
	}
	fclose(f);
}

void nbo_eims(nbo *b, const uint8_t fp[8])
{
	if (b->has_eims && !memcmp(b->eims, fp, 8))
		return;
	memcpy(b->eims, fp, 8);
	b->has_eims = true;
	if (b->n) {
		b->n = 0;
		save(b);
	}
}

static int find(const nbo *b, int64_t seq)
{
	int i;

	for (i = 0; i < b->n; i++)
		if (b->r[i].seq == seq)
			return i;
	return -1;
}

bool nbo_due(const nbo *b, int64_t seq, const uint8_t fp[8], int64_t now)
{
	int i = find(b, seq);

	return i < 0 || memcmp(b->r[i].fp, fp, 8) || now >= b->r[i].due || b->r[i].due - now > NBO_CAP;
}

int64_t nbo_refused(nbo *b, int64_t seq, const uint8_t fp[8], int64_t now)
{
	int i = find(b, seq);
	int64_t d = i < 0 || memcmp(b->r[i].fp, fp, 8) ? 0 : b->r[i].delay;

	d = d < NBO_FIRST ? NBO_FIRST : d >= NBO_CAP / 2 ? NBO_CAP : 2 * d;
	if (i < 0) {
		if (b->n == NBO_MAX)   /* full: the oldest record goes */
			memmove(b->r, b->r + 1, sizeof(b->r[0]) * (size_t)--b->n);
		i = b->n++;
		b->r[i].seq = seq;
	}
	memcpy(b->r[i].fp, fp, 8);
	b->r[i].delay = d;
	b->r[i].due = now + d;
	save(b);
	return d;
}

void nbo_keep(nbo *b, const int64_t *seqs, int n)
{
	int i, j, k = 0;

	for (i = 0; i < b->n; i++) {
		for (j = 0; j < n && seqs[j] != b->r[i].seq; j++)
			;
		if (j < n)
			b->r[k++] = b->r[i];
	}
	if (k != b->n) {
		b->n = k;
		save(b);
	}
}
